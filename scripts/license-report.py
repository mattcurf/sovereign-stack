#!/usr/bin/env python3
"""Report discovered evidence, never infer that a license obligation is satisfied."""

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import tarfile
from pathlib import Path

MAX_TEXT = 8 * 1024 * 1024


def normalize(path):
    return posixpath.normpath("/" + path.lstrip("/"))


def attribution_path(path):
    name = posixpath.basename(path).lower()
    return bool(
        re.search(r"(?:^|[._-])(copyright|copying|licen[sc]e|notice|authors)([._-].*)?$", name)
    ) or path.startswith("/usr/share/common-licenses/")


def source_texts(root, output):
    """Collect source notices without following symlinks or generated directories."""
    texts, unresolved = {}, []
    excluded = {'.git', '.tools', 'node_modules', 'target', 'evidence', 'build', 'release', '.amp'}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded
                         and Path(directory, d).resolve() != output.resolve())
        for name in sorted(files):
            path = Path(directory, name)
            relative = '/' + str(path.relative_to(root))
            if not attribution_path(relative):
                continue
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TEXT:
                    raise ValueError("symlink, non-regular file, or exceeds 8 MiB evidence limit")
                texts[relative] = path.read_text(encoding='utf-8')
            except (ValueError, UnicodeError, OSError) as error:
                unresolved.append({'path': relative, 'reason': str(error)})
    return texts, unresolved


def archive_texts(archive):
    """Read regular bytes in-place; resolve links inside the archive, never the host."""
    texts, unresolved = {}, []
    with tarfile.open(archive) as tar:
        members = {normalize(m.name): m for m in tar.getmembers()}

        def resolve(path, seen):
            if path in seen or len(seen) > 40:
                raise ValueError("cyclic or excessive archive links")
            seen = seen | {path}
            member = members.get(path)
            if member is None:
                # Debian commonly links the package documentation directory.
                parts = path.strip("/").split("/")
                for i in range(1, len(parts)):
                    prefix = "/" + "/".join(parts[:i])
                    parent = members.get(prefix)
                    if parent and parent.issym():
                        target = normalize(
                            posixpath.join(posixpath.dirname(prefix), parent.linkname)
                        )
                        return resolve(target + "/" + "/".join(parts[i:]), seen)
                raise ValueError("missing archive link target")
            if member.issym() or member.islnk():
                target = member.linkname
                if member.issym() and not target.startswith("/"):
                    target = posixpath.join(posixpath.dirname(path), target)
                return resolve(normalize(target), seen)
            if not member.isfile() or member.size > MAX_TEXT:
                raise ValueError("not a regular file or exceeds 8 MiB evidence limit")
            data = tar.extractfile(member).read(MAX_TEXT + 1)
            if path.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    data = stream.read(MAX_TEXT + 1)
            if len(data) > MAX_TEXT:
                raise ValueError("decompressed evidence exceeds 8 MiB limit")
            return data.decode("utf-8")

        candidates = {p for p in members if attribution_path(p)}
        for path, member in members.items():
            if posixpath.dirname(path) == "/usr/share/doc" and member.issym():
                candidates.add(path + "/copyright")
        for path in sorted(candidates):
            if members.get(path) and members[path].isdir():
                continue
            try:
                texts[path] = resolve(path, set())
            except (ValueError, UnicodeError, OSError, EOFError) as error:
                unresolved.append({"path": path, "reason": str(error)})
    return texts, unresolved


def archive_build_metadata(archive):
    """Keep original retained build declarations separate from license attribution."""
    records, unresolved = [], []
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path = normalize(member.name)
            if not (
                path.startswith("/usr/share/sovereign-stack/")
                and member.isfile()
                and (
                    path.endswith((".json", ".toml", ".lock", ".tsv"))
                    or "version" in posixpath.basename(path).lower()
                )
            ):
                continue
            try:
                if member.size > MAX_TEXT:
                    raise ValueError("build metadata exceeds 8 MiB limit")
                data = tar.extractfile(member).read(MAX_TEXT + 1)
                records.append(
                    {
                        "path": path,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "content": data.decode("utf-8"),
                    }
                )
            except (ValueError, UnicodeError, OSError) as error:
                unresolved.append({"path": path, "reason": str(error)})
    return {"records": records, "unresolved": unresolved}


def report(sbom, texts=None, archive_unresolved=None):
    if (not isinstance(sbom, dict) or sbom.get("SchemaVersion") != 2
            or not isinstance(sbom.get("Results", []), list)):
        raise TypeError("Expected Trivy native JSON SchemaVersion 2 with Results array")
    texts = texts or {}
    attributions, path_index, unresolved, packages = (
        {},
        {},
        list(archive_unresolved or []),
        [],
    )

    def index(text, location):
        key = hashlib.sha256(text.encode()).hexdigest()
        entry = attributions.setdefault(
            key, {"id": key, "text": text, "locations": [], "packages": []}
        )
        if location not in entry["locations"]:
            entry["locations"].append(location)
        path_index[location] = key
        return key

    for path, text in sorted(texts.items()):
        if text.strip():
            index(text, path)
    grouped = {}
    for scope in sbom.get("Results", []):
        if not isinstance(scope, dict) or not isinstance(scope.get("Class"), str):
            raise TypeError("Malformed Trivy result")
        findings = scope.get("Licenses", [])
        if not isinstance(findings, list):
            raise TypeError("Malformed Trivy Licenses array")
        for finding in findings:
            if not isinstance(finding, dict):
                raise TypeError("Malformed Trivy license finding")
            text, path = finding.get("Text"), finding.get("FilePath")
            if isinstance(text, str) and text.strip():
                index(text, normalize(path) if isinstance(path, str) and path
                      else "trivy:license:" + hashlib.sha256(text.encode()).hexdigest())
        records = scope.get("Packages", [])
        if not isinstance(records, list):
            raise TypeError("Malformed Trivy Packages array")
        for package in records:
            if not isinstance(package, dict):
                raise TypeError("Malformed Trivy package")
            identifier = package.get("Identifier") or {}
            if not isinstance(identifier, dict):
                raise TypeError("Malformed Trivy package Identifier")
            kind = {"debian": "deb", "cargo": "rust-crate"}.get(scope.get("Type"), scope.get("Type"))
            key = json.dumps([kind, package.get("ID"), package.get("Name"),
                              package.get("Version"), identifier.get("PURL")])
            grouped.setdefault(key, (kind, identifier.get("PURL"), []))[2].append(package)
    for key, (kind, purl, occurrences) in grouped.items():
        package = occurrences[0]
        # Trivy package IDs are scoped to a result, not globally unique.
        identity = "trivy:" + hashlib.sha256(key.encode()).hexdigest()
        row = {
            "id": identity,
            "name": package.get("Name"),
            "version": package.get("Version"),
            "type": kind,
            "purl": purl,
            "licenses": [],
            "attributions": [],
            "unresolved": [],
        }
        if not isinstance(row["name"], str) or not row["name"]:
            row["unresolved"].append("missing package name")
        licenses = []
        for occurrence in occurrences:
            values = occurrence.get("Licenses")
            if not isinstance(values, list):
                row["unresolved"].append("missing or malformed licenses array")
            else:
                licenses.extend(values)
            paths = occurrence.get("InstalledFiles", [])
            if not isinstance(paths, list):
                row["unresolved"].append("malformed InstalledFiles array")
                paths = []
            for path in paths:
                if isinstance(path, str) and normalize(path) in path_index:
                    row["attributions"].append(path_index[normalize(path)])
            # A package manifest identifies its own directory, not nested dependencies.
            manifest = occurrence.get("FilePath")
            if kind == "node-pkg" and isinstance(manifest, str) and manifest:
                directory = posixpath.dirname(normalize(manifest))
                row["attributions"].extend(
                    value for path, value in path_index.items()
                    if posixpath.dirname(path) == directory
                )
            if kind == "python-pkg" and isinstance(manifest, str) and manifest:
                directory = posixpath.dirname(normalize(manifest))
                if directory.endswith('.dist-info'):
                    row["attributions"].extend(
                        value for path, value in path_index.items()
                        if path.startswith(directory + '/')
                    )
        for lic in licenses:
            if not isinstance(lic, str):
                row["unresolved"].append("malformed license record")
                continue
            value = lic
            if isinstance(value, str) and value.strip():
                row["licenses"].append(value)
                if (
                    value.upper() in {"NOASSERTION", "NONE", "UNKNOWN"}
                    or "LicenseRef-" in value
                ):
                    row["unresolved"].append(f"unresolved license identifier: {value}")
            else:
                row["unresolved"].append("missing or malformed license identifier")
        if row["type"] == "deb" and isinstance(row["name"], str):
            for suffix in ("copyright", "copyright.gz"):
                path = f"/usr/share/doc/{row['name'].split(':')[0]}/{suffix}"
                if path in path_index:
                    row["attributions"].append(path_index[path])
        if row["type"] == "rust-crate":
            prefix = f"/usr/share/sovereign-stack/rust/dependencies/{row['name']}-{row['version']}/"
            row["attributions"].extend(
                key for path, key in path_index.items() if path.startswith(prefix)
            )
        if not row["licenses"]:
            row["unresolved"].append("no discovered license identifier; NOASSERTION")
        row["licenses"] = sorted(set(row["licenses"]))
        row["attributions"] = sorted(set(row["attributions"]))
        if not row["attributions"]:
            row["unresolved"].append(
                "no package-associated attribution/license text discovered"
            )
        for key in row["attributions"]:
            if identity not in attributions[key]["packages"]:
                attributions[key]["packages"].append(identity)
        for reason in row["unresolved"]:
            unresolved.append(
                {"package": identity, "name": row["name"], "reason": reason}
            )
        packages.append(row)
    for entry in attributions.values():
        if not entry["packages"]:
            unresolved.append(
                {
                    "attribution": entry["id"],
                    "locations": entry["locations"],
                    "reason": "text discovered but package association unresolved",
                }
            )
    return {
        "notice": "Discovery only; not legal advice or a license-compliance certification.",
        "packages": packages,
        "attributions": list(attributions.values()),
        "unresolved": unresolved,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path)
    parser.add_argument("output_dir", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--image-tar", type=Path)
    source.add_argument("--source-dir", type=Path)
    args = parser.parse_args()
    texts, issues = archive_texts(args.image_tar) if args.image_tar else ({}, [])
    if args.source_dir:
        texts, issues = source_texts(args.source_dir, args.output_dir.parent)
    metadata = (
        archive_build_metadata(args.image_tar)
        if args.image_tar
        else {"records": [], "unresolved": []}
    )
    issues.extend(metadata["unresolved"])
    result = report(json.loads(args.sbom.read_text()), texts, issues)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.image_tar:
        (args.output_dir / "build-metadata.json").write_text(
            json.dumps(metadata, indent=2) + "\n"
        )
    (args.output_dir / "licenses.json").write_text(json.dumps(result, indent=2) + "\n")
    (args.output_dir / "unresolved.json").write_text(
        json.dumps(result["unresolved"], indent=2) + "\n"
    )
    with (args.output_dir / "licenses.csv").open("w", newline="") as stream:
        fields = [
            "id",
            "name",
            "version",
            "type",
            "purl",
            "licenses",
            "attributions",
            "unresolved",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in result["packages"]:
            writer.writerow(
                {
                    key: json.dumps(value) if isinstance(value, list) else value
                    for key, value in row.items()
                }
            )
    with (args.output_dir / "THIRD_PARTY_NOTICES").open("w") as stream:
        stream.write(result["notice"] + "\n\nPACKAGE INDEX\n")
        for package in result["packages"]:
            stream.write(json.dumps(package) + "\n")
        for entry in result["attributions"]:
            stream.write(
                f"\n=== {entry['id']} ===\nLocations: {json.dumps(entry['locations'])}\n"
            )
            stream.write(
                "Packages: "
                + json.dumps(entry["packages"])
                + "\n"
                + entry["text"]
                + "\n"
            )
        stream.write(
            "\nUNRESOLVED EVIDENCE\n"
            + json.dumps(result["unresolved"], indent=2)
            + "\n"
        )


if __name__ == "__main__":
    main()
