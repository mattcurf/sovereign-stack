"""Overrides reduce the gate only for the approved binary and time window."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import vulnerability_policy as policy


def fixture():
    package = {'Name': 'stdlib', 'Version': 'v1.26.1',
               'Identifier': {'PURL': 'pkg:golang/stdlib@v1.26.1'}}
    result = {'Target': 'actionlint', 'Class': 'lang-pkgs', 'Type': 'gobinary',
              'Packages': [package], 'Vulnerabilities': [{
                  'VulnerabilityID': 'CVE-2026-39836', 'PkgName': 'stdlib',
                  'InstalledVersion': 'v1.26.1', 'FixedVersion': '1.26.3',
                  'Severity': 'HIGH', 'Status': 'fixed'}]}
    report = {'SchemaVersion': 2, 'ArtifactName': 'tool-inventory', 'Results': [result]}
    native = copy.deepcopy(report)
    native['ArtifactType'] = 'filesystem'
    native['sovereignStackTools'] = {'platform': 'linux/amd64', 'tools': [{
        'name': 'actionlint', 'version': 'v1.7.12',
        'binary_sha256': 'c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4'}]}
    return report, native


class ToolOverrideTests(unittest.TestCase):
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)

    def test_exact_match_retains_raw_finding_and_never_hides_scanner_failure(self):
        report, native = fixture()
        original = copy.deepcopy(report)
        for exit_code in (0, 2):
            status = policy.evaluate(report, exit_code, native, self.now)
            self.assertEqual(status['matches'], 1)
            self.assertEqual(status['originalBlockingMatches'], 1)
            self.assertEqual(status['exceptedMatches'], 1)
            self.assertEqual(status['blockingMatches'], 0)
            self.assertEqual(status['passed'], exit_code == 0)
            self.assertIn('Windows', status['exceptedFindings'][0]['reason'])
        self.assertEqual(report, original)

    def test_every_identity_boundary_must_match(self):
        mutations = [
            lambda r, n: n['sovereignStackTools'].update(platform='windows/amd64'),
            lambda r, n: n['sovereignStackTools']['tools'][0].update(version='v1.7.13'),
            lambda r, n: n['sovereignStackTools']['tools'][0].update(binary_sha256='a'*64),
            lambda r, n: r['Results'][0].update(Target='cosign'),
            lambda r, n: r['Results'][0].update(Type='debian'),
            lambda r, n: r['Results'][0]['Vulnerabilities'][0].update(PkgName='other'),
            lambda r, n: r['Results'][0]['Vulnerabilities'][0].update(InstalledVersion='v1.26.2'),
            lambda r, n: r['Results'][0]['Vulnerabilities'][0].update(VulnerabilityID='CVE-2026-56860'),
        ]
        for mutate in mutations:
            report, native = fixture()
            mutate(report, native)
            status = policy.evaluate(report, 0, native, self.now)
            self.assertFalse(status['passed'])
            self.assertEqual(status['exceptedMatches'], 0)
        report, native = fixture()
        native['ArtifactType'] = 'container_image'
        with self.assertRaises(ValueError):
            policy.evaluate(report, 0, native, self.now)
        self.assertEqual(policy.evaluate(report, 0)['blockingMatches'], 1)

    def test_expiry_and_approval_boundaries(self):
        report, native = fixture()
        for when, expected in [('2026-09-10T23:59:59+00:00', 0),
                               ('2026-09-11T00:00:00+00:00', 1),
                               ('2026-10-10T23:59:59+00:00', 1),
                               ('2026-10-11T00:00:00+00:00', 0)]:
            status = policy.evaluate(report, 0, native, datetime.fromisoformat(when))
            self.assertEqual(status['exceptedMatches'], expected)

    def test_ignored_and_other_findings_remain_blocking(self):
        report, native = fixture()
        row = report['Results'][0]
        row['ExperimentalModifiedFindings'] = [{'Type': 'vulnerability',
                                               'Finding': copy.deepcopy(row['Vulnerabilities'][0])}]
        row['Vulnerabilities'].append({**row['Vulnerabilities'][0], 'VulnerabilityID': 'CVE-2026-56860'})
        status = policy.evaluate(report, 0, native, self.now)
        self.assertEqual(status['originalBlockingMatches'], 3)
        self.assertEqual(status['exceptedMatches'], 1)
        self.assertEqual(status['blockingMatches'], 2)
        self.assertEqual(status['ignoredMatches'], 1)

    def test_missing_evidence_or_unapproved_disposition_fails_closed(self):
        original = json.loads((ROOT / 'tools/cve-overrides.json').read_text())
        report, native = fixture()
        for field, value in [('reason', ''), ('approval', ''), ('evidence', ''),
                             ('disposition', 'candidate'), ('expiresAt', '2027-01-01T00:00:00Z')]:
            overrides = copy.deepcopy(original)
            overrides['overrides'][0][field] = value
            with patch.object(Path, 'read_text', return_value=json.dumps(overrides)):
                with self.assertRaises(ValueError):
                    policy.evaluate(report, 0, native, self.now)

    def test_signing_commands_force_github_token_flow(self):
        commands = [line.strip() for line in (ROOT / 'scripts/publish.sh').read_text().splitlines()
                    if line.strip().startswith(('cosign sign ', 'cosign sign-blob ', 'cosign attest '))]
        self.assertEqual(len(commands), 5)
        for command in commands:
            self.assertIn('--oidc-provider=github-actions', command)
            self.assertIn('--fulcio-auth-flow=token', command)
            self.assertNotIn('--insecure-', command)
            self.assertNotIn('--tlog-upload=false', command)


if __name__ == '__main__':
    unittest.main()
