"""Signing-boundary and registry-authentication regressions (no real credentials)."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/validate-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

MOCK = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args=sys.argv[1:]; tool=pathlib.Path(sys.argv[0]).name
with open(os.environ['CALLS'], 'a') as log: log.write(json.dumps([tool,*args])+'\\n')
if tool=='docker':
    if args[:2]==['image','inspect']: print(json.loads(os.environ['IDS'])[args[2]])
    if args[0]=='login': sys.exit(int(os.environ.get('LOGIN_STATUS','0')))
if tool=='gh':
    if args[0]=='api': print('stack-'+'a'*40+'-1-1')
    else:
        directory=pathlib.Path(args[args.index('--dir')+1])
        (directory/'inventory.json').write_text(json.dumps({n:'ghcr.io/test/'+n+'@sha256:'+'a'*64 for n in ('base-container','nginx','rust','python')}))
'''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        (self.root / 'scripts').mkdir()
        (self.root / '.tools/bin').mkdir(parents=True)
        self.calls = self.root / 'calls'
        self.ids = {f'sovereign-stack/{name}:local': 'sha256:' + digit * 64
                    for name, digit in zip(release.COMPONENTS, '1234')}
        self.build = {'GITHUB_REPOSITORY': 'test/repo', 'GITHUB_SHA': 'a' * 40,
                      'GITHUB_WORKFLOW_SHA': 'a' * 40, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
                      'GITHUB_WORKFLOW_REF': 'test/repo/.github/workflows/publish.yml@refs/heads/main'}
        self.env = {**os.environ, **self.build, 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_ACTOR': 'test',
                    'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main', 'GH_TOKEN': 'not-a-token',
                    'CALLS': str(self.calls), 'IDS': json.dumps(self.ids)}
        self.write('build.json', self.build)
        for name in (*release.COMPONENTS, *(n + '-builder' for n in release.COMPONENTS), 'tools'):
            for scope in ('', 'source') if name != 'tools' else ('',):
                self.write(f'{name}/{scope}/scan-status.json',
                           {'passed': True, 'scannerExitCode': 0, 'matches': 0, 'ignoredMatches': 0})
                self.write(f'{name}/{scope}/grype.json', {'matches': [], 'ignoredMatches': []})
        for name in release.COMPONENTS:
            image = self.ids[f'sovereign-stack/{name}:local']
            self.write(f'{name}/image-inspect.json', [{'Id': image}])
            self.write(f'{name}/sbom.syft.json', {'source': {'name': 'sha256',
                       'metadata': {'imageID': image, 'manifestDigest': 'sha256:' + 'f' * 64}}})
            self.write(f'{name}/sbom.spdx.json', {'packages': [{'name': 'sha256',
                       'versionInfo': image[7:], 'checksums': [{'algorithm': 'SHA256', 'checksumValue': 'f' * 64}]}]})
        for name in ('docker', 'gh', 'cosign'):
            self.executable(self.root / '.tools/bin' / name, MOCK)
        for name in ('publish.sh', 'nightly.sh', 'validate-release.py'):
            shutil.copy(ROOT / 'scripts' / name, self.root / 'scripts')

    def write(self, path, value):
        target = self.evidence / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def executable(self, path, contents):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        path.chmod(0o755)

    def publish_blocked(self):
        result = subprocess.run(['bash', str(self.root / 'scripts/publish.sh')],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(call[:2] in (['docker', 'load'], ['docker', 'image']) for call in calls), calls)

    def test_clean_inputs_return_frozen_ids_and_preserve_build_attempt(self):
        self.assertEqual(release.validate(self.evidence, self.env, self.ids.__getitem__),
                         {name: self.ids[f'sovereign-stack/{name}:local'] for name in release.COMPONENTS})
        output = self.root / 'provenance.json'
        subprocess.run(['python3', str(ROOT / 'scripts/provenance.py'), 'sha256:' + '1' * 64,
                        str(output), '--build-metadata', str(self.evidence / 'build.json')],
                       env=self.env, check=True, capture_output=True)
        self.assertTrue(json.loads(output.read_text())['runDetails']['metadata']['invocationId'].endswith('/attempts/1'))

    def test_changed_tag_cannot_reach_registry_write(self):
        self.ids['sovereign-stack/python:local'] = 'sha256:' + '9' * 64
        self.env['IDS'] = json.dumps(self.ids)
        self.publish_blocked()

    def test_swapped_evidence_cannot_reach_registry_write(self):
        (self.evidence / 'nginx').rename(self.evidence / 'swap')
        (self.evidence / 'rust').rename(self.evidence / 'nginx')
        (self.evidence / 'swap').rename(self.evidence / 'rust')
        self.publish_blocked()

    def test_wrong_spdx_or_unsuccessful_source_gate_cannot_publish(self):
        original = (self.evidence / 'nginx/sbom.spdx.json').read_text()
        shutil.copy(self.evidence / 'rust/sbom.spdx.json', self.evidence / 'nginx/sbom.spdx.json')
        self.publish_blocked()
        (self.evidence / 'nginx/sbom.spdx.json').write_text(original)
        self.write('rust-builder/source/grype.json', {'matches': [{'vulnerability': 'known'}]})
        self.publish_blocked()

    def test_missing_tool_gate_cannot_publish(self):
        (self.evidence / 'tools/scan-status.json').unlink()
        self.publish_blocked()

    def test_nightly_authenticates_before_verification_and_fails_closed(self):
        self.executable(self.root / 'deploy/verify-images.sh', '#!/bin/bash\necho "[\\"verify-images\\"]" >> "$CALLS"\n')
        self.executable(self.root / 'scripts/evidence.sh', '#!/bin/bash\nexit 0\n')
        self.executable(self.root / 'scripts/rescan-recorded.py', 'pass\n')
        command = ['bash', str(self.root / 'scripts/nightly.sh')]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls[0][:2], ['docker', 'login'])
        self.assertIn(['verify-images'], calls)
        self.assertEqual(calls[-1][:2], ['docker', 'logout'])
        self.calls.write_text('')
        result = subprocess.run(command, env={**self.env, 'LOGIN_STATUS': '73'}, capture_output=True)
        self.assertEqual(result.returncode, 73)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
