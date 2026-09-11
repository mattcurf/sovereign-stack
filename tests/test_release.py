"""Signing-boundary and registry-authentication regressions (no real credentials)."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from test_inventory_contract import inventory_pair, invalid_inventory_pairs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/validate-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def report(finding=None, ignored=False):
    return {'SchemaVersion': 2, 'ArtifactName': 'fixture', 'Results': [{
        'Packages': inventory_pair()[1]['Results'][0]['Packages'],
        'Vulnerabilities': [finding] if finding and not ignored else [],
        'ExperimentalModifiedFindings': [{'Type': 'vulnerability', 'Finding': finding}]
        if finding and ignored else []}]}

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
            for scope in ('', 'source', 'build-provenance') if name != 'tools' else ('',):
                self.write(f'{name}/{scope}/scan-status.json',
                           {'passed': True, 'scannerExitCode': 0, 'matches': 0, 'ignoredMatches': 0,
                            'blockingMatches': 0, 'policy': 'fixable-high-critical-v1'})
                cdx, native = inventory_pair(empty=scope == 'build-provenance')
                self.write(f'{name}/{scope}/sbom.cyclonedx.json', cdx)
                self.write(f'{name}/{scope}/sbom.trivy.json', native)
                self.write(f'{name}/{scope}/trivy.json', native)
                now = datetime.now(timezone.utc)
                self.write(f'{name}/{scope}/db-metadata.json', {'Version': 2,
                           'UpdatedAt': (now - timedelta(hours=1)).isoformat(),
                           'NextUpdate': (now + timedelta(hours=12)).isoformat()})
        for name in release.COMPONENTS:
            image = self.ids[f'sovereign-stack/{name}:local']
            self.write(f'{name}/image-inspect.json', [{'Id': image}])
            cdx, native = inventory_pair()
            self.write(f'{name}/sbom.trivy.json', {**native, 'ArtifactName': name,
                       'Metadata': {'ImageID': image}})
            self.write(f'{name}/sbom.spdx.json', {'packages': [{'name': name,
                       'primaryPackagePurpose': 'CONTAINER', 'annotations': [{'comment': f'ImageID: {image}'}]}]})
            cdx['metadata']['component']['properties'].insert(0,
                {'name': 'aquasecurity:trivy:ImageID', 'value': image})
            self.write(f'{name}/sbom.cyclonedx.json', cdx)
        for name in ('docker', 'gh', 'cosign'):
            self.executable(self.root / '.tools/bin' / name, MOCK)
        for name in ('publish.sh', 'nightly.sh', 'validate-release.py', 'vulnerability_policy.py',
                     'inventory_contract.py'):
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

    def test_tool_override_is_recomputed_and_expiry_blocks_publication(self):
        from unittest.mock import patch
        from test_tool_overrides import fixture, policy
        report, native = fixture()
        cdx, _ = inventory_pair(True)
        purl = 'pkg:golang/stdlib@v1.26.1'
        cdx['components'] = [{'name': 'stdlib', 'bom-ref': purl, 'purl': purl, 'type': 'library'}]
        self.write('tools/sbom.trivy.json', native)
        self.write('tools/sbom.cyclonedx.json', cdx)
        self.write('tools/trivy.json', report)
        approved = datetime(2026, 9, 12, tzinfo=timezone.utc)
        self.write('tools/scan-status.json', policy.evaluate(report, 0, native, approved))
        with patch.object(release, 'evaluate', side_effect=lambda r, c, n: policy.evaluate(r, c, n, approved)):
            self.assertEqual(release.validate(self.evidence, self.env, self.ids.__getitem__),
                             {name: self.ids[f'sovereign-stack/{name}:local'] for name in release.COMPONENTS})
        expired = datetime(2026, 10, 11, tzinfo=timezone.utc)
        with patch.object(release, 'evaluate', side_effect=lambda r, c, n: policy.evaluate(r, c, n, expired)):
            with self.assertRaisesRegex(ValueError, 'Unsuccessful release gate: tools'):
                release.validate(self.evidence, self.env, self.ids.__getitem__)

    def test_clean_inputs_return_frozen_ids_and_preserve_build_attempt(self):
        self.assertEqual(release.validate(self.evidence, self.env, self.ids.__getitem__),
                         {name: self.ids[f'sovereign-stack/{name}:local'] for name in release.COMPONENTS})
        output = self.root / 'provenance.json'
        subprocess.run(['python3', str(ROOT / 'scripts/provenance.py'), 'sha256:' + '1' * 64,
                        str(output), '--build-metadata', str(self.evidence / 'build.json')],
                       env=self.env, check=True, capture_output=True)
        self.assertTrue(json.loads(output.read_text())['runDetails']['metadata']['invocationId'].endswith('/attempts/1'))

    def test_malformed_conversion_cannot_reach_registry_write(self):
        # A build-source gate avoids image-identity errors masking the inventory contract.
        for case, cdx, native in invalid_inventory_pairs():
            with self.subTest(case=case):
                self.write('rust-builder/source/sbom.cyclonedx.json', cdx)
                self.write('rust-builder/source/sbom.trivy.json', native)
                with self.assertRaises(ValueError):
                    release.validate(self.evidence, self.env, self.ids.__getitem__)
                self.publish_blocked()

    def test_every_gate_requires_both_inventories_and_matching_scanner_packages(self):
        directories = sorted(path.parent for path in self.evidence.rglob('scan-status.json'))
        self.assertEqual(len(directories), 25)
        for directory in directories:
            for filename in ('sbom.cyclonedx.json', 'sbom.trivy.json'):
                path = directory / filename
                original = path.read_text()
                with self.subTest(scope=directory, missing=filename):
                    path.unlink()
                    with self.assertRaises(FileNotFoundError):
                        release.validate(self.evidence, self.env, self.ids.__getitem__)
                    path.write_text(original)
        for scope in ('nginx', 'rust-builder/source', 'tools'):
            path = self.evidence / scope / 'trivy.json'
            original = path.read_text()
            self.write(f'{scope}/trivy.json', inventory_pair(True)[1])
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'Rescan lost or changed'):
                release.validate(self.evidence, self.env, self.ids.__getitem__)
            self.publish_blocked()
            path.write_text(original)

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
        self.write('rust-builder/source/trivy.json', report({
            'VulnerabilityID': 'CVE-2026-1234', 'Severity': 'HIGH', 'Status': 'fixed', 'FixedVersion': '2.0'}))
        self.publish_blocked()

    def test_missing_tool_gate_cannot_publish(self):
        (self.evidence / 'tools/scan-status.json').unlink()
        self.publish_blocked()

    def test_nonblocking_findings_accepted_but_forged_pass_and_missing_provenance_rejected(self):
        finding = {'VulnerabilityID': 'CVE-2026-1234', 'Severity': 'CRITICAL', 'Status': 'affected'}
        self.write('nginx/trivy.json', report(finding))
        self.write('nginx/scan-status.json', {'passed': True, 'scannerExitCode': 0,
                   'matches': 1, 'ignoredMatches': 0, 'blockingMatches': 0,
                   'policy': 'fixable-high-critical-v1'})
        release.validate(self.evidence, self.env, self.ids.__getitem__)
        # A fixed version is blocking even if the upstream Status still says affected.
        finding['FixedVersion'] = '2.0'
        self.write('nginx/trivy.json', report(finding))
        self.publish_blocked()
        (self.evidence / 'python/build-provenance/scan-status.json').unlink()
        with self.assertRaises(FileNotFoundError):
            # Restore the nginx gate so this specifically exercises missing provenance.
            self.write('nginx/trivy.json', report())
            shutil.copy(self.evidence / 'rust/scan-status.json', self.evidence / 'nginx/scan-status.json')
            release.validate(self.evidence, self.env, self.ids.__getitem__)

    def test_invalid_severity_or_fix_state_cannot_publish(self):
        for severity, state in (('High', 'fixed'), ('HIGH', 'invalid')):
            for ignored in (False, True):
                match = {'VulnerabilityID': 'CVE-2026-1234', 'Severity': severity,
                         'Status': state, 'FixedVersion': '2.0'}
                self.write('nginx/trivy.json', report(match, ignored))
                with self.assertRaisesRegex(ValueError, 'unsupported'):
                    release.validate(self.evidence, self.env, self.ids.__getitem__)

    def test_modified_finding_cannot_be_hidden_by_forged_pass(self):
        self.write('nginx/trivy.json', report({'VulnerabilityID': 'CVE-2026-1234',
                   'Severity': 'HIGH', 'Status': 'will_not_fix', 'FixedVersion': '2.0'}, True))
        self.write('nginx/scan-status.json', {'passed': True, 'scannerExitCode': 0,
                   'matches': 0, 'ignoredMatches': 1, 'blockingMatches': 0,
                   'policy': 'fixable-high-critical-v1'})
        self.publish_blocked()

    def test_exchange_identity_requires_exact_annotation_purpose_and_property(self):
        for file, mutation in (
            ('sbom.spdx.json', lambda doc: doc['packages'][0].update(name='another-image')),
            ('sbom.spdx.json', lambda doc: doc['packages'][0].update(primaryPackagePurpose='LIBRARY')),
            ('sbom.spdx.json', lambda doc: doc['packages'][0]['annotations'][0].update(comment='ImageID: sha256:' + 'f' * 64)),
            ('sbom.cyclonedx.json', lambda doc: doc['metadata']['component']['properties'][0].update(value='sha256:' + 'f' * 64)),
            ('sbom.cyclonedx.json', lambda doc: doc['metadata']['component']['properties'][0].update(name='untrusted:ImageID')),
        ):
            with self.subTest(file=file, mutation=mutation):
                path = self.evidence / 'nginx' / file
                original = path.read_text()
                document = json.loads(original)
                mutation(document)
                self.write(f'nginx/{file}', document)
                self.publish_blocked()
                path.write_text(original)

    def test_database_freshness_required_for_every_scope(self):
        now = datetime.now(timezone.utc)
        for scope in ('nginx', 'rust-builder/source', 'python/build-provenance', 'tools'):
            path = self.evidence / scope / 'db-metadata.json'
            original = path.read_text()
            for update in (
                {'UpdatedAt': (now - timedelta(hours=121)).isoformat()},
                {'UpdatedAt': (now + timedelta(minutes=11)).isoformat()},
                {'NextUpdate': (now - timedelta(seconds=1)).isoformat()}, {'Version': 1},
            ):
                with self.subTest(scope=scope, update=update):
                    self.write(f'{scope}/db-metadata.json', {**json.loads(original), **update})
                    self.publish_blocked()
            path.unlink()
            self.publish_blocked()
            path.write_text(original)

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
