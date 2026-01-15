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
from typing import TypedDict

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


class RawArtifact(TypedDict):
    """
    A "raw" artifact, i.e. a single artifact from a Python release.

    This is "raw" in the sense that all data in it is directly fetched from
    Python's releases, rather than being processed or normalized by us.
    """

    slug: str
    """
    A slug for this release's version.
    """

    url: str
    """
    The download URL for this artifact.
    """

    description: str | None
    """
    A human-readable description of this artifact, if present.
    """

    filesize: int
    """
    The size of this artifact in bytes.
    """

    md5: str | None
    """
    The given MD5 hash of this artifact, if present.
    """

    sha256: str | None
    """
    The given SHA256 hash of this artifact, if present.
    """

    sigstore: dict | None
    """
    The expanded Sigstore bundle for this artifact, if present.
    """


type RawRelease = list[RawArtifact]


class Artifact(TypedDict):
    raw: RawArtifact
    """
    The raw artifact data as fetched from Python's releases.
    """

    sha256: str
    """
    The SHA256 hash of this artifact, as computed by us.
    """


type Release = list[Artifact]


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _get_raw_release(slug: str) -> RawRelease:
    artifacts: RawRelease = []

    # NOTE(ww): Empirically, Python's release API uses the 'os' parameter
    # to filter results by target. We loop over all known OS values to ensure
    # we get all artifacts.
    for os in [1, 2, 3, 4, 5]:
        release_url = f"https://www.python.org/api/v1/downloads/release_file/?os={os}&format=json&release__slug={slug}"
        log(f"accessing {release_url}")

        response = urllib3.request("GET", release_url)
        data = json.loads(response.data)

        for obj in data["objects"]:
            # Fetch the sigstore bundle if present
            sigstore_data = None
            if obj.get("sigstore_bundle_file"):
                bundle_url = obj["sigstore_bundle_file"]
                if bundle_url.endswith(".sigstore"):
                    log(f"fetching bundle at {bundle_url}")
                    bundle_resp = urllib3.request("GET", bundle_url)
                    if bundle_resp.status == 200:
                        sigstore_data = bundle_resp.json()

            artifact: RawArtifact = {
                "slug": slug,
                "url": obj["url"],
                "description": obj.get("description") or None,
                "filesize": obj["filesize"],
                "md5": obj.get("md5_sum") or None,
                "sha256": obj.get("sha256_sum") or None,
                "sigstore": sigstore_data,
            }
            artifacts.append(artifact)

    return artifacts


def do_release(version: Version, slug: str, force: bool = False) -> None:
    output = _VERSIONS / f"{version}.json"

    # Don't repeat ourselves unless told to.
    if output.is_file() and not force:
        log(f"{output} is cached, not regenerating")
        return

    raw_release = _get_raw_release(slug)
    log(f"got {len(raw_release)} artifacts for {version}")

    release: Release = []
    for raw_artifact in raw_release:
        # Sanity check: we should have either md5 or sha256 from the raw artifact.
        if not raw_artifact["md5"] and not raw_artifact["sha256"]:
            raise ValueError(f"artifact {raw_artifact['url']} has no checksums")

        artifact_data = urllib3.request("GET", raw_artifact["url"]).data
        release.append(
            {
                "raw": raw_artifact,
                "sha256": sha256(artifact_data).hexdigest(),
            }
        )

    output.write_text(json.dumps(release, indent=4, sort_keys=True))


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

    input.write_text(json.dumps(artifacts, indent=4, sort_keys=True))


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

    release: Release = json.loads(version_file.read_text())
    if not release:
        # Some releases are empty due to recall, e.g. 3.9.3.
        log("empty release, skipping consistency check")
        return

    release_slug = release[0]["raw"]["slug"]

    online_release = _get_raw_release(release_slug)

    online_sums = set()
    for artifact in online_release:
        if md5 := artifact.get("md5"):
            online_sums.add(f"md5:{md5}")
        if sha256 := artifact.get("sha256"):
            online_sums.add(f"sha256:{sha256}")

    cached_sums = set()
    for artifact in release:
        raw = artifact["raw"]
        if md5 := raw.get("md5"):
            cached_sums.add(f"md5:{md5}")
        if sha256 := raw.get("sha256"):
            cached_sums.add(f"sha256:{sha256}")

    if online_sums != cached_sums:
        raise ValueError(
            f"Checksums sums for {version_file} do not match online release page: {online_sums} != {cached_sums}"
        )

    # # Also check that the Sigstore bundle is the same, if present.
    # for version in release:
    #     sigstore_url = version["raw"].get("Sigstore")
    #     if sigstore_url and sigstore_url.endswith(".sigstore"):
    #         resp = urllib3.request("GET", sigstore_url)
    #         if resp.status != 200:
    #             continue
    #         online_sigstore = resp.json()

    #         if version.get("sigstore") != online_sigstore:
    #             raise ValueError(
    #                 f"Sigstore for {version_file.stem} does not match online release page"
    #             )

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
