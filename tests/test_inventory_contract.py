"""Inventory identity must survive conversion and rescanning, including empty scopes."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'inventory_contract', Path(__file__).resolve().parents[1] / 'scripts/inventory_contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def inventory_pair(empty=False):
    """Independent native and exchange fixtures; no production conversion code."""
    purl = 'pkg:cargo/tokio@1.48.0'
    native = {'SchemaVersion': 2, 'ArtifactName': 'fixture', 'Results': [{
        'Class': 'lang-pkgs', 'Type': 'cargo', 'Packages': [] if empty else [
            {'ID': 'fixture@0.1.0', 'Relationship': 'root'},
            {'ID': 'tokio@1.48.0', 'Name': 'tokio', 'Version': '1.48.0',
             'Identifier': {'PURL': purl}}]}]}
    cdx = {'bomFormat': 'CycloneDX', 'metadata': {
        'component': {'name': 'fixture', 'bom-ref': 'fixture-root', 'properties': [
            {'name': 'aquasecurity:trivy:SchemaVersion', 'value': '2'}]},
        'tools': {'components': [{'name': 'trivy', 'group': 'aquasecurity'}]}},
        'components': [] if empty else [
            {'name': 'tokio', 'version': '1.48.0', 'bom-ref': purl, 'type': 'library', 'purl': purl}]}
    return cdx, native


def invalid_inventory_pairs():
    """Each case changes only one property of an otherwise valid nonempty pair."""
    mutations = {
        'missing-components': lambda c, n: c.pop('components'),
        'null-components': lambda c, n: c.update(components=None),
        'missing-root': lambda c, n: c['metadata'].pop('component'),
        'null-root': lambda c, n: c['metadata'].update(component=None),
        'missing-root-name': lambda c, n: c['metadata']['component'].pop('name'),
        'missing-root-ref': lambda c, n: c['metadata']['component'].pop('bom-ref'),
        'missing-schema-property': lambda c, n: c['metadata']['component'].update(properties=[]),
        'wrong-schema-property': lambda c, n: c['metadata']['component']['properties'][0].update(value='1'),
        'null-component': lambda c, n: c.update(components=[None]),
        'missing-library-purl': lambda c, n: c['components'][0].pop('purl'),
        'missing-library-ref': lambda c, n: c['components'][0].pop('bom-ref'),
        'missing-library-name': lambda c, n: c['components'][0].pop('name'),
        'unexpected-component-type': lambda c, n: c['components'][0].update(type='device'),
        'deleted-library': lambda c, n: c.update(components=[]),
        'changed-library-purl': lambda c, n: c['components'][0].update(purl='pkg:cargo/tokio@2.0.0'),
        'lost-native-purl': lambda c, n: n['Results'][0]['Packages'][1]['Identifier'].pop('PURL'),
        'legacy-producer': lambda c, n: c['metadata']['tools']['components'][0].update(name='syft'),
    }
    for name, mutate in mutations.items():
        cdx, native = inventory_pair()
        mutate(cdx, native)
        yield name, cdx, native


class InventoryContractTests(unittest.TestCase):
    def test_debian_lookup_context_survives_conversion_and_rescan(self):
        cdx, native = inventory_pair(True)
        purl = 'pkg:deb/debian/libssl3t64@3.5.7-1?arch=amd64'
        package = {'Name': 'libssl3t64', 'Version': '3.5.7-1',
                   'Identifier': {'PURL': purl}, 'SrcName': 'openssl',
                   'SrcVersion': '3.5.7', 'SrcRelease': '1', 'SrcEpoch': 0}
        native['Metadata'] = {'OS': {'Family': 'debian', 'Name': '13.6'}}
        native['Results'] = [{'Class': 'os-pkgs', 'Type': 'debian', 'Packages': [package]}]
        properties = {'PkgType': 'debian', 'SrcName': 'openssl',
                      'SrcVersion': '3.5.7', 'SrcRelease': '1', 'SrcEpoch': '0'}
        cdx['components'] = [
            {'type': 'operating-system', 'name': 'debian', 'version': '13.6', 'bom-ref': 'os'},
            {'type': 'library', 'name': 'libssl3t64', 'version': '3.5.7-1',
             'bom-ref': purl, 'purl': purl, 'properties': [
                 {'name': 'aquasecurity:trivy:' + k, 'value': v} for k, v in properties.items()]}]
        contract.validate_inventory(cdx, native, copy.deepcopy(native))
        for field in properties:
            for remove in (True, False):
                if field == 'SrcEpoch' and remove:
                    continue  # Omitted zero epoch is equivalent.
                changed = copy.deepcopy(cdx)
                props = changed['components'][1]['properties']
                entry = next(p for p in props if p['name'].endswith(':' + field))
                if remove:
                    props.remove(entry)
                else:
                    entry['value'] = '9' if field == 'SrcEpoch' else 'changed'
                with self.subTest(field=field, remove=remove), self.assertRaises(ValueError):
                    contract.validate_inventory(changed, native)
        for field in ('Name', 'Family'):
            report = copy.deepcopy(native)
            report['Metadata']['OS'][field] = 'different'
            with self.assertRaises(ValueError):
                contract.validate_inventory(cdx, native, report)
        for field in ('SrcName', 'SrcVersion', 'SrcRelease', 'SrcEpoch'):
            report = copy.deepcopy(native)
            report['Results'][0]['Packages'][0][field] = 1 if field == 'SrcEpoch' else 'different'
            with self.assertRaises(ValueError):
                contract.validate_inventory(cdx, native, report)
        for remove in (False, True):
            changed = copy.deepcopy(cdx)
            if remove:
                changed['components'].pop(0)
            else:
                changed['components'][0]['version'] = '12.0'
            with self.assertRaises(ValueError):
                contract.validate_inventory(changed, native)
        empty_cdx, empty_native = inventory_pair(True)
        empty_native['Metadata'] = native['Metadata']
        contract.validate_inventory(empty_cdx, empty_native, copy.deepcopy(empty_native))

    def test_valid_empty_and_populated_pairs_survive_rescanning(self):
        for empty in (False, True):
            cdx, native = inventory_pair(empty)
            contract.validate_inventory(cdx, native, copy.deepcopy(native))
        # Trivy omits Results entirely for some empty provenance documents.
        cdx, _ = inventory_pair(True)
        contract.validate_inventory(cdx, {'SchemaVersion': 2}, {'SchemaVersion': 2})

    def test_grouping_components_and_graph_placeholders_are_not_packages(self):
        cdx, native = inventory_pair()
        cdx['components'].extend([
            {'type': 'application', 'name': 'Cargo.lock', 'bom-ref': 'cargo-lock'},
            {'type': 'operating-system', 'name': 'Debian', 'bom-ref': 'debian'}])
        contract.validate_inventory(cdx, native, native)
        self.assertEqual(contract.native_package_ids(native), {'pkg:cargo/tokio@1.48.0'})

    def test_malformed_or_lost_inventory_is_not_a_clean_empty_scan(self):
        for name, cdx, native in invalid_inventory_pairs():
            with self.subTest(case=name), self.assertRaises(ValueError):
                contract.validate_inventory(cdx, native)

    def test_scanner_cannot_drop_add_or_change_identified_packages(self):
        cdx, native = inventory_pair()
        for result in ({'SchemaVersion': 2}, inventory_pair(True)[1],
                       {'SchemaVersion': 2, 'Results': [{'Packages': [
                           {'Name': 'tokio', 'Version': '2.0.0',
                            'Identifier': {'PURL': 'pkg:cargo/tokio@2.0.0'}}]}]}):
            with self.subTest(report=result), self.assertRaisesRegex(ValueError, 'Rescan lost or changed'):
                contract.validate_inventory(cdx, native, result)
        empty_cdx, empty_native = inventory_pair(True)
        with self.assertRaisesRegex(ValueError, 'Rescan lost or changed'):
            contract.validate_inventory(empty_cdx, empty_native, native)


if __name__ == '__main__':
    unittest.main()
