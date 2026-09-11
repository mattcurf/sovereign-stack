#!/usr/bin/env python3
"""Separate retained build evidence from installed image packages, without dropping either."""

import copy
import json
from pathlib import Path
import posixpath
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
    path = posixpath.normpath("/" + location.lstrip("/"))
    return any(path == prefix or path.startswith(prefix + "/") for prefix in BUILD_PATHS)


def validate(document):
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2:
        raise TypeError("Expected Trivy native JSON SchemaVersion 2")
    if not isinstance(document.get("Results", []), list):
        raise TypeError("Expected Trivy Results array")
    for result in document.get("Results", []):
        if not isinstance(result, dict) or not isinstance(result.get("Class"), str):
            raise TypeError("Malformed Trivy result")
        for field in ("Packages", "Licenses"):
            records = result.get(field, [])
            if not isinstance(records, list) or any(not isinstance(p, dict) for p in records):
                raise TypeError(f"Malformed Trivy {field} array")
            for record in records:
                if "FilePath" in record and not isinstance(record["FilePath"], str):
                    raise TypeError("Malformed Trivy FilePath")


def record_is_build(record, result):
    path = record.get("FilePath")
    # InstalledFiles and Locations are supporting evidence, not package origin.
    # OS Targets commonly contain an image name with slashes, not a file path.
    if not path and result["Class"] != "os-pkgs":
        target = result.get("Target", "")
        if isinstance(target, str) and "/" in target:
            path = target
    return is_build(path) if path else False


def partition(document, build):
    validate(document)
    result = copy.deepcopy(document)
    retained = []
    for scope in result.get("Results", []):
        for field in ("Packages", "Licenses"):
            if field in scope:
                scope[field] = [record for record in scope[field]
                                if record_is_build(record, scope) == build]
        if scope.get("Packages") or scope.get("Licenses"):
            retained.append(scope)
        elif not any(field in scope for field in ("Packages", "Licenses")):
            if record_is_build({}, scope) == build:
                retained.append(scope)
    result["Results"] = retained
    result["sovereignStackInventory"] = {
        "scope": "retained-build-provenance" if build else "runtime",
        "buildEvidencePaths": list(BUILD_PATHS),
        "completeInventory": "sbom.complete.trivy.json",
    }
    return result


def main():
    output = Path(sys.argv[1])
    document = json.loads((output / "sbom.complete.trivy.json").read_text())
    for build, directory in ((False, output), (True, output / "build-provenance")):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sbom.trivy.json").write_text(
            json.dumps(partition(document, build), indent=2) + "\n"
        )


if __name__ == "__main__":
    main()
