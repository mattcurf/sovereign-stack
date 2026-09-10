"""Historical scans must use the original signed build inputs, not current main."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('recorded', Path(__file__).resolve().parents[1] / 'scripts/rescan-recorded.py')
recorded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorded)


class RecordedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'evidence.tar.gz'
        self.inventory = {'nginx': 'original-digest'}
        self.members = {'evidence/inventory.json': json.dumps(self.inventory).encode()}
        for name in recorded.COMPONENTS + tuple(n + '-builder' for n in recorded.COMPONENTS) + ('tools',):
            for prefix in ('', 'source/', 'build-provenance/'):
                self.members[f'evidence/{name}/{prefix}sbom.syft.json'] = json.dumps(
                    {'artifacts': [{'name': f'{name}-{prefix}', 'version': 'original'}]}).encode()
        self.scanner = self.root / 'scanner'
        self.scanner.write_text('#!/bin/bash\necho "$1" >> "$(dirname "$0")/calls"\n[[ $1 != *nginx-builder/runtime* ]]\n')
        self.scanner.chmod(0o755)

    def write_archive(self, link=False):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.members.items():
                member = tarfile.TarInfo(name)
                if link and name.endswith('base-container/source/sbom.syft.json'):
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    archive.addfile(member)
                else:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

    def test_mixed_release_evidence_is_rejected_before_scanning(self):
        self.write_archive()
        with self.assertRaisesRegex(ValueError, 'does not match'):
            recorded.rescan(self.archive, {'nginx': 'different-digest'}, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_missing_or_linked_sbom_is_rejected_before_scanning(self):
        self.write_archive(link=True)
        with self.assertRaises(ValueError):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        del self.members['evidence/python-builder/source/sbom.syft.json']
        self.write_archive()
        with self.assertRaises(ValueError):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_all_build_inputs_rescanned_and_failure_retained(self):
        self.write_archive()
        self.assertEqual(recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner), 1)
        calls = (self.root / 'calls').read_text().splitlines()
        self.assertEqual(len(calls), 21)
        self.assertTrue(any('python-builder/source' in call for call in calls))
        self.assertTrue(any('nginx/build-provenance' in call for call in calls))
        for call in calls:
            self.assertEqual(json.loads(Path(call).read_text())['artifacts'][0]['version'], 'original')


if __name__ == '__main__':
    unittest.main()
