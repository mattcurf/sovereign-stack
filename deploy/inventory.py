"""Strict inventory parsing shared by verification and loaders."""
import json
import re

NAMES = ("base-container", "nginx", "rust", "python")
REF = re.compile(r"ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate inventory key: {key}")
        result[key] = value
    return result


def read_inventory(path):
    with open(path, encoding="utf-8") as source:
        images = json.load(source, object_pairs_hook=unique_object)
    if not isinstance(images, dict) or set(images) != set(NAMES):
        raise ValueError("inventory must contain exactly: " + ", ".join(NAMES))
    for name, ref in images.items():
        if not isinstance(ref, str) or not REF.fullmatch(ref):
            raise ValueError(f"invalid GHCR digest reference for {name}")
    return images


if __name__ == "__main__":
    import sys

    try:
        images = read_inventory(sys.argv[1])
        for name in NAMES:
            print(images[name])
    except (ValueError, OSError, IndexError) as error:
        sys.exit(str(error))
