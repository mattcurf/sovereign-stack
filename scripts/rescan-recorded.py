#!/usr/bin/env python3
"""Rescan historical build inputs from an already signature-verified evidence archive."""
import argparse
import json
from pathlib import Path
import subprocess
import tarfile

COMPONENTS = ('base-container', 'nginx', 'rust', 'python')


def read_regular(archive, name):
    # Do not extract archive paths/symlinks onto the runner filesystem.
    entries = [member for member in archive.getmembers() if member.name == name]
    if len(entries) != 1 or not entries[0].isfile():
        raise ValueError(f'Missing, duplicate, or non-regular evidence: {name}')
    return archive.extractfile(entries[0]).read()


def rescan(archive_path, inventory, output, scanner):
    output.mkdir(parents=True, exist_ok=True)
    status = 0
    with tarfile.open(archive_path, 'r:gz') as archive:
        recorded = json.loads(read_regular(archive, 'evidence/inventory.json'))
        if recorded != inventory:
            raise ValueError('Signed evidence archive does not match the selected inventory')
        # Validate every required input before starting scanners.
        inputs = []
        for name in COMPONENTS + tuple(name + '-builder' for name in COMPONENTS) + ('tools',):
            scopes = ('source', 'build-provenance') if name in COMPONENTS else ('runtime', 'source', 'build-provenance')
            if name == 'tools':
                scopes = ('runtime',)
            for scope in scopes:
                path = f'evidence/{name}/' + ('' if scope == 'runtime' else scope + '/') + 'sbom.syft.json'
                data = read_regular(archive, path)
                parsed = json.loads(data)
                if not isinstance(parsed, dict) or not isinstance(parsed.get('artifacts'), list):
                    raise ValueError(f'Invalid Syft inventory: {path}')
                inputs.append((name, scope, data))
        for name, scope, data in inputs:
            directory = output / name / scope
            directory.mkdir(parents=True, exist_ok=True)
            sbom = directory / 'sbom.syft.json'
            sbom.write_bytes(data)
            result = subprocess.run([str(scanner), str(sbom), str(directory)])
            if result.returncode:
                status = 1
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('inventory', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    scanner = Path(__file__).with_name('scan-sbom.sh')
    return rescan(args.archive, json.loads(args.inventory.read_text()), args.output, scanner)


if __name__ == '__main__':
    raise SystemExit(main())
