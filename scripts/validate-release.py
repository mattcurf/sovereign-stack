#!/usr/bin/env python3
"""Bind the signing job to the exact images and evidence accepted by its build job."""
import json
import os
from pathlib import Path
import re
import subprocess

from vulnerability_policy import evaluate, validate_database
from inventory_contract import validate_inventory

COMPONENTS = ('base-container', 'nginx', 'rust', 'python')


def read(path):
    return json.loads(path.read_text())


def validate(evidence, env, inspect):
    build = read(evidence / 'build.json')
    for key in ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_WORKFLOW_REF',
                'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID'):
        if not build.get(key) or build[key] != env.get(key):
            raise ValueError(f'Build evidence belongs to a different {key}')
    if not 1 <= int(build['GITHUB_RUN_ATTEMPT']) <= int(env['GITHUB_RUN_ATTEMPT']):
        raise ValueError('Invalid originating build attempt')
    names = COMPONENTS + tuple(name + '-builder' for name in COMPONENTS) + ('tools',)
    # Check every runtime, build, source, and tool gate before any registry write.
    for name in names:
        scopes = ('',) if name == 'tools' else ('', 'source', 'build-provenance')
        for scope in scopes:
            directory = evidence / name / scope
            status = read(directory / 'scan-status.json')
            report = read(directory / 'trivy.json')
            inventory = read(directory / 'sbom.trivy.json')
            if name != 'tools' and 'sovereignStackTools' in inventory:
                raise ValueError('Tool override identity in a non-tool inventory')
            validate_inventory(read(directory / 'sbom.cyclonedx.json'),
                               inventory, report)
            validate_database(read(directory / 'db-metadata.json'))
            expected_status = evaluate(report, status['scannerExitCode'], inventory)
            if not expected_status['passed'] or status != expected_status:
                raise ValueError(f'Unsuccessful release gate: {name}/{scope}')
    result = {}
    for name in COMPONENTS:
        directory = evidence / name
        inspected = read(directory / 'image-inspect.json')
        if not isinstance(inspected, list) or len(inspected) != 1:
            raise ValueError(f'Ambiguous image evidence: {name}')
        expected = inspected[0]['Id']
        sbom = read(directory / 'sbom.trivy.json')
        if (not re.fullmatch(r'sha256:[a-f0-9]{64}', expected)
                or sbom['Metadata']['ImageID'] != expected
                or inspect(f'sovereign-stack/{name}:local') != expected):
            raise ValueError(f'Loaded image and scanned image differ: {name}')
        # Trivy preserves the Docker config identity in both exchange formats.
        spdx = read(directory / 'sbom.spdx.json')
        if not any(package.get('name') == sbom['ArtifactName']
                   and package.get('primaryPackagePurpose') == 'CONTAINER'
                   and any(annotation.get('comment') == f'ImageID: {expected}'
                           for annotation in package.get('annotations', []))
                   for package in spdx['packages']):
            raise ValueError(f'SPDX predicate describes another image: {name}')
        component = read(directory / 'sbom.cyclonedx.json')['metadata']['component']
        if {'name': 'aquasecurity:trivy:ImageID', 'value': expected} not in component['properties']:
            raise ValueError(f'CycloneDX inventory describes another image: {name}')
        result[name] = expected
    return result


def main():
    root = Path(__file__).resolve().parents[1]

    def inspect(ref):
        return subprocess.check_output(['docker', 'image', 'inspect', ref,
                                        '--format', '{{.Id}}'], text=True).strip()

    validated = validate(root / 'evidence', os.environ, inspect)
    print(json.dumps(validated, indent=2))


if __name__ == '__main__':
    main()
