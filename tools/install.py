#!/usr/bin/env python3
"""Install only reviewed lockfile bytes. Never resolve versions on the warm path."""

import hashlib
import json
import os
import platform
import subprocess
import tarfile
import tempfile
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Only linux/amd64 is supported")
    root = Path(__file__).resolve().parent.parent
    bindir, cache = root / ".tools/bin", root / ".tools/cache"
    bindir.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    for tool in json.loads((root / "tools/lock.json").read_text())["tools"]:
        target = bindir / tool["name"]
        archive = cache / tool["sha256"]
        if archive.exists() and digest(archive) != tool["sha256"]:
            raise SystemExit(f"Corrupt cached artifact: {archive}")
        if not (
            target.is_file()
            and not target.is_symlink()
            and digest(target) == tool["binary_sha256"]
        ):
            with tempfile.TemporaryDirectory(dir=cache) as tmp:
                if not archive.exists():
                    download = Path(tmp) / "download"
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
                            tool["url"],
                            "-o",
                            str(download),
                        ],
                        check=True,
                    )
                    if digest(download) != tool["sha256"]:
                        raise SystemExit(f"Checksum mismatch: {tool['name']}")
                    download.replace(archive)
                if tool["member"]:
                    with tarfile.open(archive) as tar:
                        member = tar.getmember(tool["member"])
                        if not member.isfile():
                            raise SystemExit("Expected regular binary archive member")
                        binary = tar.extractfile(member).read()
                else:
                    binary = archive.read_bytes()
                if hashlib.sha256(binary).hexdigest() != tool["binary_sha256"]:
                    raise SystemExit(f"Binary checksum mismatch: {tool['name']}")
                staged = Path(tmp) / "binary"
                staged.write_bytes(binary)
                staged.chmod(0o755)
                staged.replace(target)
        target.chmod(0o755)
        if tool["name"] in {"docker-buildx", "docker-compose"}:
            plugins = (
                Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker")))
                / "cli-plugins"
            )
            plugins.mkdir(parents=True, exist_ok=True)
            link = plugins / tool["name"]
            if link.is_symlink() and link.resolve() == target:
                pass
            elif link.exists() or link.is_symlink():
                raise SystemExit(
                    f"Refusing to overwrite existing Docker plugin: {link}"
                )
            else:
                link.symlink_to(target)
        print(f"Verified {tool['name']} {tool['version']}")
    print(f"Add to PATH: {bindir}")


if __name__ == "__main__":
    main()
