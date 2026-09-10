"""Pin policy and orchestration regression tests; no registry credentials needed."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PinPolicy(unittest.TestCase):
    def test_every_remote_action_is_a_full_commit(self):
        count = 0
        for path in (ROOT / '.github').rglob('*.yml'):
            for action in re.findall(r'uses:\s*(\S+)', path.read_text()):
                if action.startswith('./.github/actions/'):
                    self.assertTrue((ROOT / action / 'action.yml').is_file())
                    continue
                count += 1
                self.assertRegex(action, r'^[\w.-]+/[\w./-]+@[0-9a-f]{40}$', str(path))
        self.assertGreater(count, 0)

    def test_docker_inputs_are_digests_or_local_stages(self):
        paths = list(ROOT.glob('*/Dockerfile'))
        self.assertEqual(len(paths), 4)
        for path in paths:
            text = path.read_text()
            args = dict(re.findall(r'^ARG\s+(\w+)=(\S+)', text, re.MULTILINE))
            stages = {'scratch'}
            for match in re.finditer(r'^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', text, re.MULTILINE | re.IGNORECASE):
                image, stage = match.groups()
                # BASE_IMAGE is built and consumed in the same local build graph.
                if image not in ('$BASE_IMAGE', '${BASE_IMAGE}'):
                    for name, value in args.items():
                        image = image.replace('${' + name + '}', value).replace('$' + name, value)
                    if image not in stages:
                        self.assertRegex(image, r'@sha256:[a-f0-9]{64}$', str(path))
                if stage:
                    stages.add(stage)

    def test_no_security_bypasses_in_workflows(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            text = path.read_text()
            for forbidden in ('pull_request_target', 'continue-on-error: true', 'ubuntu-latest', 'write-all'):
                self.assertNotIn(forbidden, text, str(path))
        self.assertNotIn('id-token: write', (ROOT / '.github/workflows/ci.yml').read_text())
        self.assertNotIn('packages: write', (ROOT / '.github/workflows/ci.yml').read_text())


class Orchestration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()

    def script(self, name, content):
        path = self.root / 'scripts' / name
        path.write_text(content)
        path.chmod(0o755)
        return path

    def test_scan_failure_collects_other_images_and_stays_failed(self):
        shutil.copy(ROOT / 'scripts/scan-images.sh', self.root / 'scripts')
        self.script('tool-evidence.sh', '#!/bin/bash\nexit 0\n')
        self.script('evidence.sh', '#!/bin/bash\necho "$1" >> scanned\n[[ $1 != *nginx* ]]\n')
        result = subprocess.run(['bash', str(self.root / 'scripts/scan-images.sh')], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.root / 'scanned').read_text().splitlines(), [
            f'docker:sovereign-stack/{name}:local' for name in (
                'base-container', 'nginx', 'rust', 'python', 'base-container-builder',
                'nginx-builder', 'rust-builder', 'python-builder')])

    def test_publish_ref_guard_precedes_registry_access(self):
        shutil.copy(ROOT / 'scripts/publish.sh', self.root / 'scripts')
        env = {**os.environ, 'GITHUB_REPOSITORY': 'example/stack', 'GITHUB_SHA': 'a' * 40,
               'GITHUB_ACTOR': 'test', 'GH_TOKEN': 'not-a-token', 'GITHUB_EVENT_NAME': 'pull_request',
               'GITHUB_REF': 'refs/pull/1/merge', 'GITHUB_WORKFLOW_REF': 'example/stack/.github/workflows/publish.yml@refs/heads/main'}
        result = subprocess.run(['bash', str(self.root / 'scripts/publish.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Publishing requires', result.stderr)
        self.assertNotIn('Login', result.stdout)

    def test_cve_job_requires_every_inventory_and_continues_after_failure(self):
        shutil.copy(ROOT / 'scripts/check-cves.sh', self.root / 'scripts')
        self.script('scan-sbom.sh', '#!/bin/bash\necho "$1" >> scanned\n[[ -f $1 ]] || exit 1\necho report > "$2/grype.json"\n')
        available = self.root / 'evidence/python-builder/source'
        available.mkdir(parents=True)
        (available / 'sbom.syft.json').write_text('{}')
        result = subprocess.run(['bash', str(self.root / 'scripts/check-cves.sh')])
        calls = (self.root / 'scanned').read_text().splitlines()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 25)
        self.assertEqual(len(set(calls)), 25)
        self.assertIn('evidence/tools/sbom.syft.json', calls)
        self.assertIn('evidence/python-builder/source/sbom.syft.json', calls)
        self.assertEqual((available / 'grype.json').read_text(), 'report\n')

    def test_runtime_and_build_tools_are_disjoint_and_report_independently(self):
        shutil.copy(ROOT / 'scripts/check-cves.sh', self.root / 'scripts')
        self.script('scan-sbom.sh', '''#!/bin/bash
echo "$1" >> scanned
mkdir -p "$2"
if [[ $1 == evidence/tools/* ]]; then
  echo '{"matches":160,"ignoredMatches":0,"blockingMatches":90,"passed":false}' > "$2/scan-status.json"
  exit 1
fi
echo '{"matches":5,"ignoredMatches":0,"blockingMatches":0,"passed":true}' > "$2/scan-status.json"
''')
        calls = {}
        for scope, expected_exit in (('runtime', 0), ('build-tools', 1), ('all', 1)):
            result = subprocess.run(['bash', str(self.root / 'scripts/check-cves.sh'), scope])
            self.assertEqual(result.returncode, expected_exit)
            calls[scope] = set((self.root / 'scanned').read_text().splitlines())
            (self.root / 'scanned').unlink()
            report = (self.root / f'evidence/cve-{scope}.md').read_text()
            self.assertIn('| 5 | 0 | 0 | PASS |', report)
            if scope == 'runtime':
                self.assertNotIn('FAIL', report)
                self.assertNotIn('build-provenance', report)
            else:
                self.assertIn('| tools | 160 | 0 | 90 | FAIL |', report)
        self.assertEqual(calls['runtime'], {f'evidence/{name}/sbom.syft.json'
                         for name in ('base-container', 'nginx', 'rust', 'python')})
        self.assertEqual(len(calls['build-tools']), 21)
        self.assertFalse(calls['runtime'] & calls['build-tools'])
        self.assertEqual(calls['runtime'] | calls['build-tools'], calls['all'])
        result = subprocess.run(['bash', str(self.root / 'scripts/check-cves.sh'), 'typo'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'scanned').exists())

    def test_cache_and_partial_evidence_guards(self):
        action = (ROOT / '.github/actions/build-images/action.yml').read_text()
        self.assertIn('cache-binary: false', action)
        self.assertNotRegex(action, r'(?m)^\s+version:', 'do not replace verified Buildx')
        scopes = re.findall(r'cache-to=type=gha,version=2,scope=([^,\s]+),mode=max', action)
        self.assertEqual(len(scopes), 8)
        self.assertEqual(len(set(scopes)), 8)
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn("!cancelled() && (needs.sbom.result == 'success' || needs.sbom.result == 'failure')", workflow)
        self.assertIn('fail-fast: false', workflow)

    def test_bake_graph_uses_local_base_and_all_eight_tags(self):
        import json
        result = subprocess.run([str(ROOT / '.tools/bin/docker-buildx'), 'bake', '--print'],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        targets = json.loads(result.stdout)['target']
        self.assertEqual(len(targets), 8)
        for name, target in targets.items():
            self.assertEqual(target['tags'], [f'sovereign-stack/{name}:local'])
            if not name.startswith('base-container'):
                self.assertEqual(target['contexts']['sovereign-stack/base-container:local'],
                                 'target:base-container')


if __name__ == '__main__':
    unittest.main()
