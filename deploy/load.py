"""Verify a private inventory snapshot before invoking either deployment engine."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from inventory import read_inventory

HERE = Path(__file__).resolve().parent
PORTS = {"nginx": 8081, "rust": 8082, "python": 8083}


def compose_config(images):
    return {
        "name": "sovereign-stack",
        "services": {
            name: {
                "image": images[name],
                "platform": "linux/amd64",
                "user": "65532:65532",
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"],
                "cpus": 0.5,
                "mem_limit": "128m",
                "pids_limit": 100,
                "ports": [f"127.0.0.1:{port}:8080"],
            }
            for name, port in PORTS.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=("compose", "helm"))
    parser.add_argument("inventory", help="JSON mapping of exactly four GHCR digest refs")
    parser.add_argument("--render", action="store_true", help="verify and render without deploying")
    args = parser.parse_args()
    # Only read the caller-controlled path once. TemporaryDirectory is private (0700).
    images = read_inventory(args.inventory)
    with tempfile.TemporaryDirectory(prefix="sovereign-stack-") as directory:
        snapshot = Path(directory) / "inventory.json"
        snapshot.write_text(json.dumps(images), encoding="utf-8")
        subprocess.run(["bash", str(HERE / "verify-images.sh"), str(snapshot)], check=True)
        config = Path(directory) / "config.json"
        if args.engine == "compose":
            config.write_text(json.dumps(compose_config(images)), encoding="utf-8")
            command = ["docker", "compose", "-p", "sovereign-stack", "-f", str(config)]
            command += ["config"] if args.render else ["up", "-d", "--wait"]
        else:
            config.write_text(json.dumps({"images": images}), encoding="utf-8")
            chart = str(HERE / "helm" / "sovereign-stack")
            command = (["helm", "template", "sovereign-stack", chart] if args.render else
                       ["helm", "upgrade", "--install", "sovereign-stack", chart,
                        "--namespace", "sovereign-stack", "--create-namespace", "--wait", "--timeout", "5m"])
            command += ["--values", str(config)]
        subprocess.run(command, check=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
