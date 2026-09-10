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
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            for action in re.findall(r'uses:\s*(\S+)', path.read_text()):
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


if __name__ == '__main__':
    unittest.main()
