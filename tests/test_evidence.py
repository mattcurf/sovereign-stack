"""Offline regression tests; live scanner/database checks are separate integration tests."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from test_inventory_contract import inventory_pair, invalid_inventory_pairs

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


licenses = load("licenses", "scripts/license-report.py")
provenance = load("provenance", "scripts/provenance.py")
installer = load("installer", "tools/install.py")
policy = load("policy", "scripts/vulnerability_policy.py")
partitioner = load("partitioner", "scripts/partition-sbom.py")


class InventoryTests(unittest.TestCase):
    def test_empty_native_inventory_omits_results_but_null_is_not_empty(self):
        document = {"SchemaVersion": 2, "ArtifactName": "empty"}
        self.assertEqual(licenses.report(document)["packages"], [])
        self.assertTrue(policy.evaluate(document, 0)["passed"])
        for build in (False, True):
            self.assertEqual(partitioner.partition(document, build)["Results"], [])
            with self.assertRaises(TypeError):
                partitioner.partition({**document, "Results": None}, build)
        with self.assertRaises(TypeError):
            licenses.report({**document, "Results": None})
        with self.assertRaises(ValueError):
            policy.evaluate({**document, "Results": None}, 0)

    def test_build_only_mixed_unknown_and_linked_rust_locations(self):
        build = "/usr/share/sovereign-stack/nginx/npm/package.json"
        runtime = "/usr/local/lib/node_modules/npm/package.json"
        paths = [("build", build), ("mixed", build), ("mixed", runtime),
                 ("runtime", runtime), ("rust", "/usr/share/sovereign-stack/rust/Cargo.lock"),
                 ("neighbor", "/usr/share/sovereign-stack/nginx-other/package.json"),
                 ("unknown", "")]
        document = {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs",
                    "Packages": [{"ID": name, "FilePath": path} for name, path in paths]}]}
        result = partitioner.partition(document, False)
        retained = partitioner.partition(document, True)
        self.assertEqual({p["ID"] for p in result["Results"][0]["Packages"]},
                         {"mixed", "runtime", "rust", "neighbor", "unknown"})
        self.assertEqual({p["ID"] for p in retained["Results"][0]["Packages"]}, {"build", "mixed"})
        self.assertEqual(result["Results"][0]["Packages"][0]["FilePath"], runtime)
        self.assertEqual(len(document["Results"][0]["Packages"]), 7)

    def test_shared_copyright_does_not_make_build_os_an_installed_package(self):
        for primary, supporting, expected_build in (
            ("/usr/share/sovereign-stack/nginx/build-os/var/lib/dpkg/status",
             "/usr/share/doc/libc6/copyright", True),
            ("/var/lib/dpkg/status",
             "/usr/share/sovereign-stack/nginx/build-os/doc/libc6/copyright", False),
        ):
            document = {"SchemaVersion": 2, "Results": [{"Class": "os-pkgs",
                        "Packages": [{"ID": "libc", "FilePath": primary,
                                      "InstalledFiles": [supporting]}]}]}
            for build in (False, True):
                self.assertEqual(len(partitioner.partition(document, build)["Results"]),
                                 int(build == expected_build))


class PolicyTests(unittest.TestCase):
    def test_severity_fix_and_ignored_boundaries(self):
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            for state in ("fixed", "affected", "will_not_fix", "unknown", "not_affected",
                          "under_investigation", "fix_deferred", "end_of_life"):
                for ignored in (False, True):
                    for fixed in ("", "2.0"):
                        with self.subTest(severity=severity, state=state, ignored=ignored, fixed=fixed):
                            match = {"VulnerabilityID": "CVE-2026-1234", "Severity": severity,
                                     "Status": state, "FixedVersion": fixed}
                            report = scan_report(match, ignored)
                            if state == "fixed" and not fixed:
                                with self.assertRaises(ValueError):
                                    policy.evaluate(report, 0)
                                continue
                            expected = severity in ("HIGH", "CRITICAL") and bool(fixed)
                            result = policy.evaluate(report, 0)
                            self.assertEqual(result["blockingMatches"], int(expected))
                            self.assertEqual(result["passed"], not expected)
                            self.assertEqual(result["matches"], int(not ignored))
                            self.assertEqual(result["ignoredMatches"], int(ignored))
                            self.assertFalse(policy.evaluate(report, 2)["passed"])

    def test_malformed_fix_cannot_be_treated_as_unfixed(self):
        for changes in ({"Status": None}, {"Status": "invalid"}, {"Severity": "High"},
                        {"FixedVersion": []}, {"FixedVersion": None},
                        {"Status": "fixed", "FixedVersion": " "}, {"VulnerabilityID": ""}):
            for ignored in (False, True):
                match = {"VulnerabilityID": "CVE-2026-1234", "Severity": "HIGH",
                         "Status": "fixed", "FixedVersion": "2.0", **changes}
                with self.subTest(changes=changes, ignored=ignored), self.assertRaises((ValueError, KeyError)):
                    policy.evaluate(scan_report(match, ignored), 0)
        for field in ("Status", "Severity", "VulnerabilityID"):
            match = {"VulnerabilityID": "CVE-2026-1234", "Severity": "HIGH", "Status": "affected"}
            del match[field]
            with self.assertRaises(KeyError):
                policy.evaluate(scan_report(match), 0)

    def test_database_age_and_schema_boundaries(self):
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        for age, future, version, valid in (
            (120, 1, 2, True), (120.001, 1, 2, False),
            (-1 / 6, 1, 2, True), (-0.167, 1, 2, False),
            (1, 0, 2, False), (1, -1, 2, False), (1, 1, 1, False),
        ):
            metadata = {"Version": version, "UpdatedAt": (now - timedelta(hours=age)).isoformat(),
                        "NextUpdate": (now + timedelta(hours=future)).isoformat()}
            with self.subTest(metadata=metadata):
                if valid:
                    policy.validate_database(metadata, now)
                else:
                    with self.assertRaises(ValueError):
                        policy.validate_database(metadata, now)


def scan_report(finding=None, ignored=False):
    result = {"Target": "test", "Vulnerabilities": [] if ignored or finding is None else [finding],
              "ExperimentalModifiedFindings": [{"Type": "vulnerability", "Finding": finding}] if ignored else []}
    return {"SchemaVersion": 2, "ArtifactName": "test", "Results": [result]}


class LicenseTests(unittest.TestCase):
    def test_missing_malformed_and_unknown_licenses(self):
        for value in (
            None,
            {},
            "MIT",
            [None],
            [42],
            ["NOASSERTION"],
        ):
            with self.subTest(value=value):
                result = licenses.report(
                    {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs", "Packages": [
                        {"ID": "a", "Name": "a", "Licenses": value}]}]}
                )
                self.assertTrue(result["unresolved"])
                self.assertFalse(result["attributions"])

    def test_malformed_document_rejected(self):
        for value in ({}, [], {"SchemaVersion": 2, "Results": {}},
                      {"SchemaVersion": 2, "Results": [None]},
                      {"SchemaVersion": 2, "Results": None}):
            with self.assertRaises(TypeError):
                licenses.report(value)

    def test_plaintext_contents_and_index_deduplication(self):
        packages = [
            {
                "ID": n,
                "Name": n,
                "Licenses": ["MIT"],
                "InstalledFiles": [f"/{n}/LICENSE"],
            }
            for n in ("a", "b")
        ]
        result = licenses.report(
            {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs", "Packages": packages,
             "Licenses": [{"FilePath": f"/{n}/LICENSE", "Text": "Copyright Alice\nMIT text"}
                          for n in ("a", "b")]}]}, {"/LICENSE": "Copyright Alice\nMIT text"}
        )
        self.assertEqual(len(result["attributions"]), 1)
        self.assertEqual(result["attributions"][0]["packages"], [p["id"] for p in result["packages"]])
        self.assertEqual(len(result["attributions"][0]["locations"]), 3)
        self.assertFalse(result["unresolved"])

    def test_malformed_contents_is_unresolved(self):
        result = licenses.report(
            {
                "SchemaVersion": 2, "Results": [{"Class": "lang-pkgs",
                    "Packages": [{"Name": "a", "Licenses": ["MIT"]}],
                    "Licenses": [{"FilePath": "/LICENSE", "Text": [42]}]}]
            }
        )
        self.assertFalse(result["attributions"])
        self.assertIn("no package-associated attribution", str(result["unresolved"]))

    def test_debian_and_rust_associations_do_not_cross_package_boundary(self):
        result = licenses.report(
            {
                "SchemaVersion": 2, "Results": [
                    {"Class": "os-pkgs", "Type": "debian", "Packages": [
                        {"ID": "deb", "Name": "foo", "Licenses": []}]},
                    {"Class": "lang-pkgs", "Type": "cargo", "Packages": [
                        {"ID": "rust", "Name": "bar", "Version": "1", "Licenses": []}]},
                ]
            },
            {
                "/usr/share/doc/foo/copyright": "Debian copyright",
                "/usr/share/sovereign-stack/rust/dependencies/bar-1/LICENSE": "Rust copyright",
                "/usr/share/sovereign-stack/rust/dependencies/bar-10/LICENSE": "Other version",
            },
        )
        self.assertEqual([len(p["attributions"]) for p in result["packages"]], [1, 1])
        self.assertIn("association unresolved", str(result["unresolved"]))

    def test_prefixed_runtime_notices_are_captured_or_explicitly_oversized(self):
        node = "usr/share/sovereign-stack/nginx/NODE-LICENSE"
        rust = "usr/share/sovereign-stack/rust/RUST-COPYRIGHT.html"
        for rust_size in (24, licenses.MAX_TEXT + 1):
            with self.subTest(rust_size=rust_size), tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / "image.tar"
                with tarfile.open(archive, "w") as tar:
                    for path, data in ((node, b"Node attribution"), (rust, b"R" * rust_size)):
                        member = tarfile.TarInfo(path)
                        member.size = len(data)
                        tar.addfile(member, io.BytesIO(data))
                texts, issues = licenses.archive_texts(archive)
                self.assertEqual(texts["/" + node], "Node attribution")
                if rust_size > licenses.MAX_TEXT:
                    self.assertNotIn("/" + rust, texts)
                    self.assertEqual(issues[0]["path"], "/" + rust)
                    self.assertIn("8 MiB", issues[0]["reason"])
                else:
                    self.assertEqual(texts["/" + rust], "R" * rust_size)
                    self.assertEqual(issues, [])

    def test_archive_links_are_resolved_inside_image_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "image.tar"
            with tarfile.open(archive, "w") as tar:
                item = tarfile.TarInfo("usr/share/doc/foo/copyright")
                data = b"Copyright actual author"
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
                for name, target in [
                    ("usr/share/doc/bar", "foo"),
                    ("LICENSE", "/etc/passwd"),
                    ("NOTICE", "NOTICE"),
                ]:
                    item = tarfile.TarInfo(name)
                    item.type, item.linkname = tarfile.SYMTYPE, target
                    tar.addfile(item)
            texts, issues = licenses.archive_texts(archive)
            self.assertEqual(
                texts["/usr/share/doc/bar/copyright"], "Copyright actual author"
            )
            self.assertNotIn("/LICENSE", texts)
            self.assertEqual(len(issues), 2)

    def test_retained_build_metadata_captured_without_attribution_confusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "image.tar"
            with tarfile.open(archive, "w") as tar:
                data = b'{"packages": [{"name": "tokio"}]}'
                item = tarfile.TarInfo(
                    "usr/share/sovereign-stack/rust/cargo-metadata.json"
                )
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            metadata = licenses.archive_build_metadata(archive)
            self.assertEqual(
                metadata["records"][0]["sha256"], hashlib.sha256(data).hexdigest()
            )
            self.assertEqual(licenses.archive_texts(archive), ({}, []))


@unittest.skipUnless(
    (ROOT / ".tools/bin/trivy").exists(),
    "install pinned Trivy with tools/install.sh for real cataloger smoke test",
)
class TrivyIntegrationTests(unittest.TestCase):
    def test_real_rust_lock_cataloger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "trivy.yaml").write_text("{}\n")
            (root / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n[dependencies]\ntokio = "1.48.0"\n')
            (root / "Cargo.lock").write_text("""version = 4
[[package]]
name = "tokio"
version = "1.48.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
""")
            result = subprocess.run(
                [
                    str(ROOT / ".tools/bin/trivy"), "fs", str(root),
                    "--scanners", "license", "--list-all-pkgs", "--include-dev-deps",
                    "--format", "json", "--config", str(root / "trivy.yaml"),
                    "--ignorefile", "/dev/null", "--cache-backend", "memory",
                ],
                capture_output=True,
                text=True,
                check=False,
                env={key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.assertEqual(document["SchemaVersion"], 2)
            self.assertEqual(document["Trivy"]["Version"], "0.74.0")
            self.assertTrue(
                any(
                    scope["Type"] == "cargo" and p.get("Name") == "tokio" and p["Version"] == "1.48.0"
                    for scope in document["Results"] for p in scope.get("Packages", [])
                )
            )


class ProvenanceTests(unittest.TestCase):
    def env(self):
        return {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_WORKFLOW_REF": "test/repo/.github/workflows/publish.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "2",
        }

    def test_v1_and_no_certification_claim(self):
        result = provenance.predicate("sha256:" + "c" * 64, self.env(), [])
        self.assertIn("buildDefinition", result)
        self.assertIn("runDetails", result)
        self.assertNotIn("predicateType", result)
        self.assertIn(
            "no independent SLSA", result["sovereign_stack_evidence"]["assurance"]
        )
        self.assertEqual(len(result["buildDefinition"]["resolvedDependencies"]), 2)

    def test_missing_ci_identity_mutable_digest_and_bad_material_fail(self):
        for image, env, materials in [
            ("latest", self.env(), []),
            ("sha256:" + "c" * 64, {}, []),
            ("sha256:" + "c" * 64, self.env(), [{"uri": "x"}]),
        ]:
            with self.assertRaises(ValueError):
                provenance.predicate(image, env, materials)

    def test_build_input_hashes_and_image_materials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rust").mkdir()
            text = "FROM registry.test/builder@sha256:" + "c" * 64
            text += "\nADD --checksum=sha256:" + "d" * 64 + " https://registry.test/npm.tgz /tmp/npm.tgz\n"
            (root / "rust/Dockerfile").write_text(text)
            with patch.object(
                provenance.subprocess, "check_output", return_value=b"rust/Dockerfile\0"
            ):
                result = provenance.repository_materials(
                    root, "https://github.com/test/repo", "a" * 40
                )
            self.assertEqual(
                result[0]["digest"]["sha256"], hashlib.sha256(text.encode()).hexdigest()
            )
            self.assertEqual(result[1], {"uri": "https://registry.test/npm.tgz",
                                         "digest": {"sha256": "d" * 64}})
            self.assertTrue(result[2]["uri"].startswith("oci://"))


class InstallerTests(unittest.TestCase):
    def test_warm_path_no_download_and_corruption_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            (root / ".tools/bin").mkdir(parents=True)
            (root / ".tools/cache").mkdir()
            binary = b"verified binary"
            digest = hashlib.sha256(binary).hexdigest()
            (root / ".tools/bin/test").write_bytes(binary)
            archive = root / ".tools/cache" / digest
            archive.write_bytes(binary)
            (root / "tools/lock.json").write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "name": "test",
                                "version": "v1",
                                "sha256": digest,
                                "binary_sha256": digest,
                            }
                        ]
                    }
                )
            )
            with (
                patch.object(installer, "__file__", str(root / "tools/install.py")),
                patch.object(installer.subprocess, "run") as run,
            ):
                installer.main()
                run.assert_not_called()
                archive.write_bytes(b"corrupted")
                with self.assertRaisesRegex(SystemExit, "Corrupt cached"):
                    installer.main()


FAKE_TOOLS = r"""#!/usr/bin/env python3
import io,json,os,pathlib,sys,tarfile
from datetime import datetime,timedelta,timezone
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='docker':
    if args[:2]==['image','inspect']:
        assert not args[2].startswith('docker:')
        print(json.dumps([{'Id':'sha256:'+'a'*64}]))
    elif args[0]=='create':
        assert args[-1]=='sha256:'+'a'*64
        print('container-id')
    elif args[0]=='export':
        with tarfile.open(args[args.index('--output')+1],'w') as tar:
            item=tarfile.TarInfo('usr/share/doc/test/copyright')
            data=b'Copyright tester'
            item.size=len(data); tar.addfile(item,io.BytesIO(data))
elif name=='trivy':
    assert not any(k.startswith('TRIVY_') for k in os.environ)
    config=pathlib.Path(args[args.index('--config')+1]).read_text()
    assert pathlib.Path(args[args.index('--ignorefile')+1]).read_text()==''
    mode=os.environ.get('TEST_TRIVY','clean')
    if args[0] in ('image','fs','convert'):
        assert set(config.splitlines()) <= {'{}','disable-telemetry: true','skip-version-check: true'}
        output=pathlib.Path(args[args.index('--output')+1])
        if args[0]=='convert':
            native=json.loads(pathlib.Path(args[1]).read_text())
            assert native['SchemaVersion']==2
            document={'bomFormat':'CycloneDX','metadata':{
                'component':{'name':'test','bom-ref':'root','properties':[
                    {'name':'aquasecurity:trivy:SchemaVersion','value':'2'}]},
                'tools':{'components':[{'name':'trivy','group':'aquasecurity'}]}},
                'components':[{'name':p['Name'],'bom-ref':p['Identifier']['PURL'],
                    'type':'library','purl':p['Identifier']['PURL'], 'properties':[
                        {'name':'aquasecurity:trivy:'+k,'value':v} for k,v in
                        {'PkgType':scope['Type'], **{k:v for k,v in p.items() if k.startswith('Src')}}.items()]}
                    for scope in native['Results'] for p in scope.get('Packages',[])]}
            if any(s.get('Class')=='os-pkgs' and s.get('Packages') for s in native['Results']):
                document['components'].append({'name':'debian','version':'13.6','type':'operating-system','bom-ref':'os'})
            if args[args.index('--format')+1]!='cyclonedx': document={'packages':[]}
        else:
            if args[0]=='image':
                assert args[1]=='sha256:'+'a'*64
                assert '--include-dev-deps' not in args
            else: assert '--include-dev-deps' in args
            assert args[args.index('--scanners')+1]=='license'
            assert '--list-all-pkgs' in args
            document={'SchemaVersion':2,'ArtifactName':'test','Metadata':{'OS':{'Family':'debian','Name':'13.6'}},'Results':[
                {'Class':'os-pkgs','Type':'debian','Packages':[
                    {'ID':'test','Name':'test','Version':'1','SrcName':'test-source','SrcVersion':'1','Identifier':{'PURL':'pkg:deb/debian/test@1'},'Licenses':[]}]},
                {'Class':'lang-pkgs','Type':'npm','Target':'/usr/share/sovereign-stack/nginx/package-lock.json',
                 'Packages':[{'ID':'build','Name':'build','Version':'1','Identifier':{'PURL':'pkg:npm/build@1'},'Licenses':['MIT']}]}]}
        output.write_text(json.dumps(document))
        sys.exit(0)
    assert args[0]=='sbom'
    input_sbom=json.loads(pathlib.Path(args[1]).read_text())
    assert input_sbom['bomFormat']=='CycloneDX'
    packages=[{'Name':c.get('name','unknown'),'Identifier':{'PURL':c['purl']}}
              for c in (input_sbom.get('components') or [])
              if isinstance(c,dict) and c.get('purl')]
    os_packages=[]
    for c in input_sbom.get('components') or []:
        if not isinstance(c,dict): continue
        props={p['name'].removeprefix('aquasecurity:trivy:'):p['value'] for p in c.get('properties',[])}
        if props.get('PkgType')=='debian':
            package=next(p for p in packages if p['Identifier']['PURL']==c['purl'])
            package.update({k:v for k,v in props.items() if k.startswith('Src')})
            packages.remove(package)
            os_packages.append(package)
    if mode=='empty-scan': packages=[]
    for setting in ('scanners: [vuln]', 'severity: [UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL]',
                    'ignore-unfixed: false', 'ignore-status: []', 'vex: []',
                    'skip-db-update: false', 'show-suppressed: true', 'exit-code: 0'):
        assert setting in config, setting
    db=pathlib.Path(args[args.index('--cache-dir')+1])/'db'
    db.mkdir(parents=True,exist_ok=True)
    now=datetime.now(timezone.utc)
    metadata={'Version':2,'UpdatedAt':(now-timedelta(hours=1)).isoformat(),
              'NextUpdate':(now+timedelta(hours=12)).isoformat()}
    if mode=='stale-db': metadata['UpdatedAt']=(now-timedelta(hours=121)).isoformat()
    if mode=='future-db': metadata['UpdatedAt']=(now+timedelta(minutes=11)).isoformat()
    if mode=='expired-db': metadata['NextUpdate']=(now-timedelta(seconds=1)).isoformat()
    if mode=='wrong-db-version': metadata['Version']=1
    if mode!='missing-db': (db/'trivy.db').write_bytes(b'database fixture')
    if mode!='missing-metadata': (db/'metadata.json').write_text(json.dumps(metadata))
    if mode=='malformed': print('{}')
    else:
        match={'VulnerabilityID':'CVE-2026-1234','Severity':'HIGH' if mode in ('block','ignored') else 'UNKNOWN',
               'Status':'fixed' if mode in ('block','ignored') else 'affected',
               'FixedVersion':'2.0' if mode in ('block','ignored') else ''}
        if mode.startswith('invalid-severity'): match['Severity']='High'
        if mode.startswith('invalid-state'): match['Status']='invalid'
        ignored=mode=='ignored' or mode.endswith('-ignored')
        present=mode in ('match','block','ignored') or mode.startswith('invalid-')
        print(json.dumps({'SchemaVersion':2,'ArtifactName':'test','Metadata':{'OS':{'Family':'debian','Name':'13.6'}},'Results':[
            {'Packages':packages,'Vulnerabilities':[match] if present and not ignored else [],
             'ExperimentalModifiedFindings':[{'Type':'vulnerability','Finding':match}] if present and ignored else []},
             {'Class':'os-pkgs','Type':'debian','Packages':[] if mode=='empty-scan' else os_packages}]}))
    sys.exit(2 if mode=='database-failure' else 0)
"""


class PipelineTests(unittest.TestCase):
    def test_scan_helper_rejects_malformed_or_missing_pair_but_accepts_empty(self):
        cases = [('valid', *inventory_pair()), ('valid-empty', *inventory_pair(True)),
                 ('missing-native', inventory_pair()[0], None), *invalid_inventory_pairs()]
        for case, cdx, native in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'scripts').mkdir()
                (root / '.tools/bin').mkdir(parents=True)
                for script in ('scan-sbom.sh', 'vulnerability_policy.py', 'inventory_contract.py'):
                    shutil.copy(ROOT / 'scripts' / script, root / 'scripts' / script)
                scanner = root / '.tools/bin/trivy'
                scanner.write_text(FAKE_TOOLS)
                scanner.chmod(0o755)
                source = root / 'input'
                source.mkdir()
                sbom = source / 'sbom.cyclonedx.json'
                sbom.write_text(json.dumps(cdx))
                if native is not None:
                    (source / 'sbom.trivy.json').write_text(json.dumps(native))
                output = root / 'output'
                output.mkdir()
                # A native file in OUTPUT_DIR cannot substitute for the input's sibling.
                (output / 'sbom.trivy.json').write_text(json.dumps(inventory_pair()[1]))
                result = subprocess.run(['bash', str(root / 'scripts/scan-sbom.sh'), str(sbom), str(output)],
                    env={**os.environ, 'TEST_TRIVY': 'clean'}, capture_output=True, text=True)
                expected = case in ('valid', 'valid-empty')
                self.assertEqual(result.returncode, 0 if expected else 1, result.stderr)
                status = json.loads((output / 'scan-status.json').read_text())
                self.assertEqual(status['passed'], expected)
                # This is inventory rejection, not a fake scanner crash or a CVE blocker.
                self.assertEqual(status['scannerExitCode'], 0)
                self.assertEqual('error' in status, not expected)

    def test_scan_helper_clears_inherited_suppression_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / ".tools/bin").mkdir(parents=True)
            for script in ("scan-sbom.sh", "vulnerability_policy.py", "inventory_contract.py"):
                shutil.copy(ROOT / "scripts" / script, root / "scripts" / script)
            scanner = root / ".tools/bin/trivy"
            scanner.write_text(FAKE_TOOLS)
            scanner.chmod(0o755)
            sbom = root / "input.json"
            cdx, native = inventory_pair()
            sbom.write_text(json.dumps(cdx))
            (root / "sbom.trivy.json").write_text(json.dumps(native))
            (root / ".trivyignore").write_text("CVE-2026-1234\n")
            (root / "trivy.yaml").write_text("ignore-unfixed: true\nseverity: [LOW]\n")
            for mode, expected in (("clean", True), ("ignored", False)):
                result = subprocess.run(["bash", str(root / "scripts/scan-sbom.sh"),
                                         str(sbom), str(root / mode)], cwd=root,
                    env={**os.environ, "TEST_TRIVY": mode, "TRIVY_IGNORE_UNFIXED": "true",
                         "TRIVY_SEVERITY": "LOW", "TRIVY_SKIP_DB_UPDATE": "true",
                         "TRIVY_CONFIG": str(root / "trivy.yaml"),
                         "TRIVY_IGNOREFILE": str(root / ".trivyignore")},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if expected else 1, result.stderr)
                status = json.loads((root / mode / "scan-status.json").read_text())
                self.assertEqual(status["passed"], expected)
                self.assertNotIn("error", status)
                self.assertEqual(status["scannerExitCode"], 0)
                self.assertEqual(status["blockingMatches"], int(not expected))

    def test_gate_blockers_errors_and_all_finding_retention(self):
        for mode in (
            "clean",
            "match",
            "block",
            "ignored",
            "database-failure",
            "stale-db",
            "future-db",
            "expired-db",
            "wrong-db-version",
            "missing-db",
            "missing-metadata",
            "malformed",
            "empty-scan",
            "invalid-severity",
            "invalid-state",
            "invalid-severity-ignored",
            "invalid-state-ignored",
            "no-source",
            "collect-only",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                (root / ".tools/bin").mkdir(parents=True)
                for script in ("evidence.sh", "license-report.py", "scan-sbom.sh",
                               "vulnerability_policy.py", "partition-sbom.py", "inventory_contract.py"):
                    shutil.copy(ROOT / "scripts" / script, root / "scripts" / script)
                for name in ("trivy", "docker"):
                    path = root / ".tools/bin" / name
                    path.write_text(FAKE_TOOLS)
                    path.chmod(0o755)
                for directory in (
                    "rust",
                    "evidence",
                    "build",
                    "release",
                    ".amp",
                    "target",
                ):
                    (root / directory).mkdir()
                    (root / directory / "Cargo.lock").write_text("test lock")
                env = dict(
                    os.environ,
                    TEST_TRIVY="database-failure" if mode == "collect-only" else mode,
                    TRIVY_IGNORE_UNFIXED="true", TRIVY_SEVERITY="LOW",
                    TRIVY_CONFIG="/nonexistent/config", TRIVY_IGNOREFILE="/nonexistent/ignore",
                    TRIVY_SKIP_DB_UPDATE="true", TRIVY_IGNORE_STATUS="fixed",
                    SOURCE_DIR="" if mode == "no-source" else str(root),
                )
                result = subprocess.run(
                    [
                        "bash",
                        str(root / "scripts/evidence.sh"),
                        "docker:test:local",
                        str(root / "out"),
                    ] + (["--collect-only"] if mode == "collect-only" else []),
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                passed = mode in {"clean", "no-source", "match", "collect-only"}
                self.assertEqual(result.returncode, 0 if passed else 1, result.stderr)
                prefixes = [root / "out", root / "out/build-provenance"]
                if mode == "no-source":
                    self.assertFalse((root / "out/source").exists())
                else:
                    prefixes.append(root / "out/source")
                    locks = json.loads((root / "out/source/lockfiles.json").read_text())
                    self.assertEqual(
                        [lock["path"] for lock in locks], ["rust/Cargo.lock"]
                    )
                for prefix in prefixes:
                    self.assertTrue((prefix / "THIRD_PARTY_NOTICES").exists())
                    if mode == "collect-only":
                        self.assertTrue((prefix / "sbom.trivy.json").exists())
                        self.assertTrue((prefix / "sbom.cyclonedx.json").exists())
                        self.assertFalse((prefix / "trivy.json").exists())
                        self.assertFalse((prefix / "scan-status.json").exists())
                        continue
                    self.assertTrue((prefix / "trivy.json").exists())
                    if mode in ("match", "block", "ignored"):
                        report = json.loads((prefix / "trivy.json").read_text())["Results"][0]
                        field = "ExperimentalModifiedFindings" if mode == "ignored" else "Vulnerabilities"
                        self.assertEqual(len(report[field]), 1)
                    if mode in ("clean", "no-source", "match"):
                        metadata = json.loads((prefix / "db-metadata.json").read_text())
                        self.assertEqual(metadata["sha256"], hashlib.sha256(b"database fixture").hexdigest())
                    status = json.loads((prefix / "scan-status.json").read_text())
                    self.assertEqual(status["passed"], passed)
                    self.assertEqual(status["scannerExitCode"], 2 if mode == "database-failure" else 0)
                    if mode in ("clean", "no-source", "match", "block", "ignored", "database-failure"):
                        self.assertNotIn("error", status)
                        self.assertEqual(status["matches"], int(mode in ("match", "block")))
                        self.assertEqual(status["ignoredMatches"], int(mode == "ignored"))
                        self.assertEqual(status["blockingMatches"], int(mode in ("block", "ignored")))
                    else:
                        self.assertIn("error", status)


if __name__ == "__main__":
    unittest.main()
