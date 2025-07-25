#!/usr/bin/env -S uv run --prerelease=allow --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "urllib3",
#     "lxml",
#     "packaging",
#     "sigstore-protobuf-specs",
#     "sigstore ~= 3.6",
# ]
# ///

# fetcher: fetch hashes for each Python version

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

import urllib3
from lxml import html
from packaging.version import Version
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm

_VERSIONS = Path(__file__).parent / "versions"
assert _VERSIONS.is_dir()

_SIGNING_IDENTITIES = Path(__file__).parent / "signing-identities.json"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _release_table(release_url: str) -> list[dict]:
    log(f"accessing {release_url}")

    release_html = urllib3.request("GET", release_url).data
    release_doc = html.fromstring(release_html)

    # NOTE: Some older release pages have a docutils <table> element
    # before the artifact table; we skip over it.
    artifact_table = release_doc.xpath("//table[not(contains(@class, 'docutils'))]")[0]
    headers = artifact_table.xpath(".//thead//tr//th//text()")
    artifacts = []
    for row in artifact_table.xpath(".//tbody//tr"):
        col_values = []
        for col in row.xpath(".//td"):
            # If this column is a link, use the href as our value
            # rather than the element's text.
            links = col.xpath(".//a")
            if links:
                col_values.append(links[0].attrib.get("href"))
            else:
                col_values.append(col.text)

        artifacts.append(dict(zip(headers, col_values)))

    return artifacts


def do_release(version: Version, slug: str, force: bool = False) -> None:
    output = _VERSIONS / f"{version}.json"

    # Don't repeat ourselves unless told to.
    if output.is_file() and not force:
        log(f"{output} is cached, not regenerating")
        return

    release_url = f"https://www.python.org/downloads/release/{slug}/"

    artifacts = _release_table(release_url)

    # Now, download each artifact for the version and hash it.
    # Confusingly, each artifact's URL is under the `Version` key,
    # since `Version` in the context of the release's artifacts
    # table is the kind of artifact (e.g. source, installer).
    log(f"fetching {len(artifacts)} artifacts for {version}")
    cleaned_artifacts = []
    for artifact in artifacts:
        artifact_url = artifact["Version"]
        # TODO: Could stream into the hasher instead of buffering here.
        raw_artifact = urllib3.request("GET", artifact_url).data
        artifact_digest = sha256(raw_artifact).hexdigest()
        cleaned_artifacts.append(
            {
                "url": artifact_url,
                "sha256": artifact_digest,
                "release_url": release_url,
                "raw": artifact,
            }
        )

    output.write_text(json.dumps(cleaned_artifacts, indent=4))


def do_sigstore(version: Version) -> None:
    input = _VERSIONS / f"{version}.json"
    artifacts = json.loads(input.read_text())

    for artifact in artifacts:
        if "sigstore" in artifact or "Sigstore" not in artifact["raw"]:
            continue

        sigstore_url = artifact["raw"]["Sigstore"]
        if not sigstore_url:
            # We might have 'null' for the bundle URL if our table
            # entry is for a Windows release manifest; see e.g.
            # https://www.python.org/downloads/release/python-3140b3/
            continue

        if not sigstore_url.endswith(".sigstore"):
            # Some older releases contain only detached materials,
            # not combined bundles. We don't fetch those (yet?).
            continue

        log(f"fetching bundle at {sigstore_url}")
        # Known 404s due to intentionally removed bundles:
        # https://www.python.org/ftp/python/3.10.1/python3101.chm.sigstore
        # https://www.python.org/ftp/python/3.10.11/python31011.chm.sigstore
        resp = urllib3.request("GET", sigstore_url)
        if resp.status != 200:
            continue
        artifact["sigstore"] = resp.json()

    input.write_text(json.dumps(artifacts, indent=4))


def do_sigstore_identities() -> None:
    sigstore_info = urllib3.request(
        "GET", "https://www.python.org/downloads/metadata/sigstore/"
    )
    sigstore_info_doc = html.fromstring(sigstore_info.data)

    sigstore_table = sigstore_info_doc.xpath("//table")[0]
    headers = sigstore_table.xpath(".//thead//tr//th//text()")

    sigstore_identities = []
    for row in sigstore_table.xpath(".//tbody//tr"):
        col_values = row.xpath(".//td//text()")
        sigstore_identities.append(dict(zip(headers, col_values)))

    _SIGNING_IDENTITIES.write_text(json.dumps(sigstore_identities, indent=4))


def do_consistency_check(version_file: Path) -> None:
    log(f"checking consistency of {version_file.stem}")

    versions = json.loads(version_file.read_text())
    if not versions:
        # Some releases are empty due to recall, e.g. 3.9.3.
        log("empty release, skipping consistency check")
        return

    release_url = versions[0]["release_url"]

    artifacts = _release_table(release_url)
    online_sums = {artifact["MD5 Sum"] for artifact in artifacts}
    cached_sums = {version["raw"]["MD5 Sum"] for version in versions}

    if online_sums != cached_sums:
        raise ValueError(
            f"MD5 sums for {version_file} do not match online release page"
        )

    # Also check that the Sigstore bundle is the same, if present.
    for version in versions:
        sigstore_url = version["raw"].get("Sigstore")
        if sigstore_url and sigstore_url.endswith(".sigstore"):
            resp = urllib3.request("GET", sigstore_url)
            if resp.status != 200:
                continue
            online_sigstore = resp.json()

            if version.get("sigstore") != online_sigstore:
                raise ValueError(
                    f"Sigstore for {version_file.stem} does not match online release page"
                )

    log(f"{version_file.stem}: consistency check passed")


def do_verify(verifier: Verifier, idents: list[dict], version_file: Path) -> None:
    log(f"verifying sigstore bundles for {version_file.stem}")

    versions = json.loads(version_file.read_text())
    for version in versions:
        bundle = version.get("sigstore")
        if not bundle:
            continue

        bundle = Bundle.from_json(json.dumps(bundle))

        hashed = Hashed(
            digest=bytes.fromhex(version["sha256"]), algorithm=HashAlgorithm.SHA2_256
        )

        ident_version = ".".join(version_file.stem.split(".")[0:2])
        ident = next(
            (ident for ident in idents if ident["Release"] == ident_version), None
        )

        if not ident:
            raise ValueError(f"no signing identity found for {ident_version}")

        pol = policy.Identity(
            identity=ident["Release manager"], issuer=ident["OIDC Issuer"]
        )

        verifier.verify_artifact(input_=hashed, bundle=bundle, policy=pol)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--mode",
        choices=["fetch", "consistency-check", "verify"],
        default="fetch",
        help="the operation to perform",
    )
    args = parser.parse_args()

    if args.mode == "fetch":
        releases = urllib3.request(
            "GET", "https://www.python.org/api/v2/downloads/release/"
        ).json()

        for release in releases:
            name = release["name"]
            if "install manager" in name:
                # Skip "install manager" releases, which are not actually Python releases.
                continue

            # There's no version in the release JSON, so we infer it
            # from the name (`Python {version}`).
            version = Version(name.split(" ")[1])
            slug = release["slug"]

            do_release(version, slug, force=args.force)
            do_sigstore(version)

        do_sigstore_identities()
    elif args.mode == "consistency-check":
        for version_file in _VERSIONS.glob("*.json"):
            do_consistency_check(version_file)
    elif args.mode == "verify":
        verifier = Verifier.production()
        idents = json.loads(_SIGNING_IDENTITIES.read_text())
        for version_file in _VERSIONS.glob("*.json"):
            do_verify(verifier, idents, version_file)


if __name__ == "__main__":
    main()
