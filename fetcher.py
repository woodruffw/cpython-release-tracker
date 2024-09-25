#!/usr/bin/env python

# fetcher: fetch hashes for each Python version

import json
import os
import sys
from hashlib import sha256
from pathlib import Path

import urllib3
from lxml import html
from packaging.version import Version

_FORCE = os.getenv("FORCE") is not None

_VERSIONS = Path(__file__).parent / "versions"
assert _VERSIONS.is_dir()

_SIGNING_IDENTITIES = Path(__file__).parent / "signing-identities.json"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def do_release(version: Version, slug: str) -> None:
    output = _VERSIONS / f"{version}.json"

    # Don't repeat ourselves unless told to.
    if output.is_file() and not _FORCE:
        log(f"{output} is cached, not regenerating")
        return

    release_url = f"https://www.python.org/downloads/release/{slug}/"
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
            {"url": artifact_url, "sha256": artifact_digest, "raw": artifact}
        )

    output.write_text(json.dumps(cleaned_artifacts, indent=4))


def do_sigstore(version: Version) -> None:
    input = _VERSIONS / f"{version}.json"
    artifacts = json.loads(input.read_text())

    for artifact in artifacts:
        if "sigstore" in artifact or "Sigstore" not in artifact["raw"]:
            continue

        sigstore_url = artifact["raw"]["Sigstore"]
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
    sigstore_info = urllib3.request("GET", "https://www.python.org/download/sigstore/")
    sigstore_info_doc = html.fromstring(sigstore_info.data)

    sigstore_table = sigstore_info_doc.xpath("//table")[0]
    headers = sigstore_table.xpath(".//thead//tr//th//text()")

    sigstore_identities = []
    for row in sigstore_table.xpath(".//tbody//tr"):
        col_values = row.xpath(".//td//text()")
        sigstore_identities.append(dict(zip(headers, col_values)))

    _SIGNING_IDENTITIES.write_text(json.dumps(sigstore_identities, indent=4))


releases = urllib3.request(
    "GET", "https://www.python.org/api/v2/downloads/release/"
).json()

for release in releases:
    # There's no version in the release JSON, so we infer it
    # from the name (`Python {version}`).
    version = Version(release["name"].split(" ")[1])
    slug = release["slug"]

    do_release(version, slug)
    do_sigstore(version)

do_sigstore_identities()
