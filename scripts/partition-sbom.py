#!/usr/bin/env python3
"""Separate retained build evidence from installed image packages, without dropping either."""

import copy
import json
from pathlib import Path, PurePosixPath
import sys

# Only directories this repository creates exclusively for build evidence.
# Rust Cargo.lock/dependency manifests intentionally stay in the runtime inventory:
# they describe candidates for static linking, not merely the compiler toolchain.
BUILD_PATHS = (
    "/usr/share/sovereign-stack/nginx",
    "/usr/share/sovereign-stack/base-container/bootstrap-doc",
    "/usr/share/sovereign-stack/python/build-doc",
)


def is_build(location):
    path = str(PurePosixPath("/" + location["path"].lstrip("/")))
    return any(path == prefix or path.startswith(prefix + "/") for prefix in BUILD_PATHS)


def partition(document, build):
    result = copy.deepcopy(document)
    artifacts = []
    removed = set()
    for artifact in result["artifacts"]:
        locations = artifact.get("locations", [])
        # Syft may associate a retained dpkg status record with runtime copyright
        # text. Supporting attribution is not evidence that a package is installed.
        primary = [location for location in locations
                   if location.get("annotations", {}).get("evidence") == "primary"]
        membership = primary or locations
        selected = [location for location in locations if is_build(location) == build]
        # Unknown location is not a reason to omit a runtime dependency.
        if any(is_build(location) == build for location in membership) or (not locations and not build):
            artifact["locations"] = selected
            artifacts.append(artifact)
        else:
            removed.add(artifact["id"])
    result["artifacts"] = artifacts
    files = []
    for file in result.get("files", []):
        if is_build(file["location"]) == build:
            files.append(file)
        else:
            removed.add(file["id"])
    if "files" in result:
        result["files"] = files
    result["artifactRelationships"] = [
        relation for relation in result.get("artifactRelationships", [])
        if relation["parent"] not in removed and relation["child"] not in removed
    ]
    result["sovereignStackInventory"] = {
        "scope": "retained-build-provenance" if build else "runtime",
        "buildEvidencePaths": list(BUILD_PATHS),
        "completeInventory": "sbom.complete.syft.json",
    }
    return result


def main():
    output = Path(sys.argv[1])
    document = json.loads((output / "sbom.complete.syft.json").read_text())
    for build, directory in ((False, output), (True, output / "build-provenance")):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sbom.syft.json").write_text(
            json.dumps(partition(document, build), indent=2) + "\n"
        )


if __name__ == "__main__":
    main()
