#!/usr/bin/env python3
"""Maintainer-only: resolve stable releases and verify bytes against published hashes."""

import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path


def fetch(url, path):
    subprocess.run(
        [
            "curl",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            url,
            "-o",
            str(path),
        ],
        check=True,
    )


def main():
    tools = []
    for name, repo in [
        ("cosign", "sigstore/cosign"),
        ("syft", "anchore/syft"),
        ("grype", "anchore/grype"),
        ("helm", "helm/helm"),
        ("actionlint", "rhysd/actionlint"),
        ("docker-buildx", "docker/buildx"),
        ("docker-compose", "docker/compose"),
    ]:
        release = json.loads(
            subprocess.check_output(["gh", "api", f"repos/{repo}/releases/latest"])
        )
        assert not release["prerelease"] and not release["draft"]
        tag = release["tag_name"]
        version = tag.removeprefix("v")
        base = f"https://github.com/{repo}/releases/download/{tag}"
        member = name
        if name == "helm":
            asset = f"helm-{tag}-linux-amd64.tar.gz"
            url = f"https://get.helm.sh/{asset}"
            checksums = url + ".sha256sum"
            member = "linux-amd64/helm"
        elif name == "cosign":
            asset = "cosign-linux-amd64"
            url, checksums = f"{base}/{asset}", f"{base}/cosign_checksums.txt"
        elif name == "docker-buildx":
            asset = f"buildx-{tag}.linux-amd64"
            url, checksums = f"{base}/{asset}", f"{base}/checksums.txt"
        elif name == "docker-compose":
            asset = "docker-compose-linux-x86_64"
            url, checksums = f"{base}/{asset}", f"{base}/checksums.txt"
        else:
            asset = f"{name}_{version}_linux_amd64.tar.gz"
            url, checksums = f"{base}/{asset}", f"{base}/{name}_{version}_checksums.txt"
        with tempfile.TemporaryDirectory() as tmp:
            archive, sums = Path(tmp) / asset, Path(tmp) / "checksums"
            fetch(url, archive)
            fetch(checksums, sums)
            matching = [
                line.split()[0]
                for line in sums.read_text().splitlines()
                if len(line.split()) >= 2 and line.split()[-1].lstrip("*") == asset
            ]
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            assert matching == [digest], (name, matching, digest)
            if asset.endswith(".tar.gz"):
                with tarfile.open(archive) as tar:
                    binary = tar.extractfile(member).read()
            else:
                member = None
                binary = archive.read_bytes()
            tools.append(
                {
                    "name": name,
                    "version": tag,
                    "url": url,
                    "sha256": digest,
                    "checksum_url": checksums,
                    "member": member,
                    "binary_sha256": hashlib.sha256(binary).hexdigest(),
                }
            )
        print(f"Verified {name} {tag}", flush=True)
    # Docker publishes static binaries without checksum sidecars (unlike the tools above).
    # Record this weaker initial trust explicitly; subsequent installs remain hash-pinned.
    release = json.loads(
        subprocess.check_output(["gh", "api", "repos/moby/moby/releases/latest"])
    )
    version = release["tag_name"].removeprefix("docker-v")
    url = f"https://download.docker.com/linux/static/stable/x86_64/docker-{version}.tgz"
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "docker.tgz"
        fetch(url, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        with tarfile.open(archive) as tar:
            for name in (
                "docker",
                "dockerd",
                "containerd",
                "containerd-shim-runc-v2",
                "ctr",
                "runc",
                "docker-init",
                "docker-proxy",
            ):
                member = f"docker/{name}"
                binary = tar.extractfile(member).read()
                tools.append(
                    {
                        "name": name,
                        "version": version,
                        "url": url,
                        "sha256": digest,
                        "checksum_origin": "locally measured official HTTPS artifact; no published checksum",
                        "member": member,
                        "binary_sha256": hashlib.sha256(binary).hexdigest(),
                    }
                )
    print(
        f"Pinned Docker {version} official static archive (no upstream checksum sidecar)",
        flush=True,
    )
    Path(__file__).with_name("lock.json").write_text(
        json.dumps({"platform": "linux/amd64", "tools": tools}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
