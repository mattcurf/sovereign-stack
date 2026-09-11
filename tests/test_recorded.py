"""Historical scans must use the original signed build inputs, not current main."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from test_inventory_contract import inventory_pair, invalid_inventory_pairs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('recorded', ROOT / 'scripts/rescan-recorded.py')
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
                cdx, native = inventory_pair(empty=prefix == 'build-provenance/')
                cdx['metadata']['component']['name'] = f'{name}-{prefix}-original'
                native['ArtifactName'] = f'{name}-{prefix}-original'
                self.members[f'evidence/{name}/{prefix}sbom.cyclonedx.json'] = json.dumps(cdx).encode()
                self.members[f'evidence/{name}/{prefix}sbom.trivy.json'] = json.dumps(native).encode()
        self.scanner = self.root / 'scanner'
        self.scanner.write_text('#!/bin/bash\necho "$1" >> "$(dirname "$0")/calls"\n[[ $1 != *nginx-builder/runtime* ]]\n')
        self.scanner.chmod(0o755)

    def write_archive(self, link=False):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.members.items():
                member = tarfile.TarInfo(name)
                if link and name.endswith('base-container/source/sbom.cyclonedx.json'):
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
        del self.members['evidence/python-builder/source/sbom.cyclonedx.json']
        self.write_archive()
        with self.assertRaises(ValueError):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_legacy_producer_is_rejected_before_any_scan(self):
        path = 'evidence/tools/sbom.cyclonedx.json'
        document = json.loads(self.members[path])
        document['metadata']['tools']['components'] = [{'name': 'syft', 'group': 'anchore'}]
        self.members[path] = json.dumps(document).encode()
        self.write_archive()
        with self.assertRaises(ValueError):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_malformed_or_lost_inventory_is_rejected_before_any_scan(self):
        for case, cdx, native in invalid_inventory_pairs():
            with self.subTest(case=case):
                # Tools is last: preflight must reject this before any earlier scope scans.
                self.members['evidence/tools/sbom.cyclonedx.json'] = json.dumps(cdx).encode()
                self.members['evidence/tools/sbom.trivy.json'] = json.dumps(native).encode()
                self.write_archive()
                with self.assertRaises(ValueError):
                    recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
                self.assertFalse((self.root / 'calls').exists())

    def test_native_inventory_required_in_every_historical_scope(self):
        paths = [path for path in self.members if path.endswith('sbom.trivy.json')
                 and (('-builder/' in path) or ('/source/' in path) or
                      ('/build-provenance/' in path) or path.startswith('evidence/tools/'))
                 and path not in ('evidence/tools/source/sbom.trivy.json',
                                  'evidence/tools/build-provenance/sbom.trivy.json')]
        self.assertEqual(len(paths), 21)
        for path in paths:
            with self.subTest(path=path):
                original = self.members.pop(path)
                self.write_archive()
                with self.assertRaisesRegex(ValueError, 'Missing, duplicate, or non-regular'):
                    recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
                self.assertFalse((self.root / 'calls').exists())
                self.members[path] = original

    def test_linked_native_inventory_is_rejected_before_any_scan(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.members.items():
                member = tarfile.TarInfo(name)
                if name == 'evidence/tools/sbom.trivy.json':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    archive.addfile(member)
                else:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, 'non-regular'):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_duplicate_sbom_is_rejected_before_scanning(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            items = list(self.members.items())
            required = 'evidence/base-container/source/sbom.cyclonedx.json'
            items.append((required, self.members[required]))
            for name, data in items:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        with self.assertRaises(ValueError):
            recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner)
        self.assertFalse((self.root / 'calls').exists())

    def test_unrelated_archive_paths_are_never_extracted(self):
        escaped = self.root / 'outside' / 'NOTICE'
        self.members[str(escaped)] = b'absolute path must not be extracted'
        self.members['../outside/NOTICE'] = b'traversal must not be extracted'
        self.write_archive()
        self.assertEqual(recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner), 1)
        self.assertFalse(escaped.exists())

    def test_all_build_inputs_rescanned_and_failure_retained(self):
        self.write_archive()
        self.assertEqual(recorded.rescan(self.archive, self.inventory, self.root / 'out', self.scanner), 1)
        calls = (self.root / 'calls').read_text().splitlines()
        self.assertEqual(len(calls), 21)
        expected = {f'{name}/{scope}/sbom.cyclonedx.json'
                    for name in recorded.COMPONENTS
                    for scope in ('source', 'build-provenance')}
        expected.update(f'{name}-builder/{scope}/sbom.cyclonedx.json'
                        for name in recorded.COMPONENTS
                        for scope in ('runtime', 'source', 'build-provenance'))
        expected.add('tools/runtime/sbom.cyclonedx.json')
        self.assertEqual({str(Path(call).relative_to(self.root / 'out')) for call in calls}, expected)
        self.assertTrue(any('python-builder/source' in call for call in calls))
        self.assertTrue(any('nginx/build-provenance' in call for call in calls))
        for call in calls:
            path = Path(call)
            name, scope, _ = path.relative_to(self.root / 'out').parts
            prefix = '' if scope == 'runtime' else scope + '/'
            self.assertEqual(path.read_bytes(), self.members[f'evidence/{name}/{prefix}sbom.cyclonedx.json'])
            self.assertEqual((path.parent / 'sbom.trivy.json').read_bytes(),
                             self.members[f'evidence/{name}/{prefix}sbom.trivy.json'])


if __name__ == '__main__':
    unittest.main()
