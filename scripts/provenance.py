#!/usr/bin/env python3
"""Tenant-generated SLSA v1 predicate, not independent builder certification."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def repository_materials(root, repo, commit):
    """Record tracked build inputs and explicit immutable image pins, not host secrets."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
        .decode()
        .split("\0")
    )
    records, images = [], set()
    for name in sorted(filter(None, names)):
        path = Path(name)
        if not (
            path.parts[0] in {"base-container", "nginx", "rust", "python"}
            or name in {"tools/lock.json", "docker-bake.hcl", ".github/actions/build-images/action.yml"}
        ):
            continue
        target = root / path
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"Build material is not a regular file: {name}")
        data = target.read_bytes()
        records.append(
            {
                "uri": f"git+{repo}@{commit}#{name}",
                "digest": {"sha256": hashlib.sha256(data).hexdigest()},
            }
        )
        images.update(
            re.findall(
                r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}",
                data.decode("utf-8", errors="replace"),
            )
        )
    for image in sorted(images):
        records.append(
            {"uri": f"oci://{image}", "digest": {"sha256": image.split("@sha256:")[1]}}
        )
    return records


def predicate(image, env, materials):
    if not re.fullmatch(r"(?:[^\s]+@)?sha256:[0-9a-f]{64}", image):
        raise ValueError(
            "IMAGE_DIGEST must be sha256:<64 lowercase hex> or an immutable image reference"
        )
    required = [
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ]
    for key in required:
        if not env.get(key):
            raise ValueError(
                f"Missing {key}; do not fabricate CI identity for local runs"
            )
    for key in ["GITHUB_SHA", "GITHUB_WORKFLOW_SHA"]:
        if not re.fullmatch(r"[0-9a-f]{40}", env[key]):
            raise ValueError(f"Invalid {key}")
    if not isinstance(materials, list):
        raise TypeError("Materials must be a resolvedDependencies JSON array")
    for material in materials:
        if (
            not isinstance(material, dict)
            or not isinstance(material.get("uri"), str)
            or not isinstance(material.get("digest"), dict)
            or not material["digest"]
            or not all(
                isinstance(k, str) and isinstance(v, str) and v
                for k, v in material["digest"].items()
            )
        ):
            raise ValueError("Each material requires uri and nonempty digest mapping")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = f"{server}/{env['GITHUB_REPOSITORY']}"
    workflow = f"{server}/{env['GITHUB_WORKFLOW_REF']}"
    dependencies = [
        {"uri": f"git+{repo}", "digest": {"gitCommit": env["GITHUB_SHA"]}},
        {"uri": workflow, "digest": {"gitCommit": env["GITHUB_WORKFLOW_SHA"]}},
        *materials,
    ]
    return {
        "buildDefinition": {
            "buildType": f"{repo}/blob/main/docs/evidence.md#build-type-v1",
            "externalParameters": {
                "repository": repo,
                "workflow": env["GITHUB_WORKFLOW_REF"],
            },
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {
                "id": f"{repo}/blob/main/docs/evidence.md#self-reported-github-actions-builder"
            },
            "metadata": {
                "invocationId": f"{repo}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/{env['GITHUB_RUN_ATTEMPT']}"
            },
        },
        "sovereign_stack_evidence": {
            "subjectDigest": image.split("@")[-1],
            "assurance": "self-reported by tenant workflow; no independent SLSA certification or level claimed",
            "materialsCompleteness": "best effort; caller must supply resolved image, lockfile and tool materials",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image_digest")
    parser.add_argument("output_file", type=Path)
    parser.add_argument("--materials", type=Path)
    parser.add_argument("--build-metadata", type=Path,
                        help="Originating build job environment, retained across publish-only retries")
    args = parser.parse_args()
    materials = json.loads(args.materials.read_text()) if args.materials else []
    build_env = json.loads(args.build_metadata.read_text()) if args.build_metadata else os.environ
    try:
        result = predicate(args.image_digest, build_env, materials)
        repo = result["buildDefinition"]["externalParameters"]["repository"]
        root = Path(__file__).resolve().parent.parent
        result["buildDefinition"]["resolvedDependencies"].extend(
            repository_materials(root, repo, build_env["GITHUB_SHA"])
        )
    except (ValueError, TypeError) as error:
        parser.error(str(error))
    args.output_file.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
