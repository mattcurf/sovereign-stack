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
from pathlib import Path
from unittest.mock import patch

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
    def test_build_only_mixed_unknown_and_linked_rust_locations(self):
        build = "/usr/share/sovereign-stack/nginx/npm/package.json"
        runtime = "/usr/local/lib/node_modules/npm/package.json"
        paths = {
            "build": [build],
            "mixed": [build, runtime],
            "runtime": [runtime],
            "rust": ["/usr/share/sovereign-stack/rust/Cargo.lock"],
            "neighbor": ["/usr/share/sovereign-stack/nginx-other/package.json"],
            "unknown": [],
        }
        document = {
            "artifacts": [{"id": name, "locations": [{"path": p} for p in locations]}
                          for name, locations in paths.items()],
            "files": [{"id": "bf", "location": {"path": build}},
                      {"id": "rf", "location": {"path": runtime}}],
            "artifactRelationships": [{"parent": "build", "child": "bf"},
                                      {"parent": "runtime", "child": "rf"}],
        }
        result = partitioner.partition(document, False)
        retained = partitioner.partition(document, True)
        self.assertEqual({p["id"] for p in result["artifacts"]},
                         {"mixed", "runtime", "rust", "neighbor", "unknown"})
        self.assertEqual({p["id"] for p in retained["artifacts"]}, {"build", "mixed"})
        self.assertEqual(result["artifacts"][0]["locations"], [{"path": runtime}])
        self.assertEqual(result["artifactRelationships"], [{"parent": "runtime", "child": "rf"}])
        self.assertEqual(len(document["artifacts"]), 6)
        self.assertEqual(len(document["artifacts"][1]["locations"]), 2)

    def test_shared_copyright_does_not_make_build_os_an_installed_package(self):
        for primary, supporting, expected_build in (
            ("/usr/share/sovereign-stack/nginx/build-os/var/lib/dpkg/status",
             "/usr/share/doc/libc6/copyright", True),
            ("/var/lib/dpkg/status",
             "/usr/share/sovereign-stack/nginx/build-os/doc/libc6/copyright", False),
        ):
            document = {"artifacts": [{"id": "libc", "locations": [
                {"path": primary, "annotations": {"evidence": "primary"}},
                {"path": supporting, "annotations": {"evidence": "supporting"}},
            ]}]}
            for build in (False, True):
                self.assertEqual(len(partitioner.partition(document, build)["artifacts"]),
                                 int(build == expected_build))


class PolicyTests(unittest.TestCase):
    def test_severity_fix_and_ignored_boundaries(self):
        for severity in ("Critical", "High", "Medium", "Low", "Negligible", "Unknown"):
            for state in ("fixed", "not-fixed", "wont-fix", "unknown", ""):
                for ignored in (False, True):
                    with self.subTest(severity=severity, state=state, ignored=ignored):
                        match = {"vulnerability": {"severity": severity,
                                 "fix": {"state": state, "versions": ["2.0"] if state == "fixed" else []}}}
                        report = {"matches": [] if ignored else [match],
                                  "ignoredMatches": [match] if ignored else []}
                        expected = severity in ("High", "Critical") and state == "fixed"
                        result = policy.evaluate(report, 0)
                        self.assertEqual(result["blockingMatches"], int(expected))
                        self.assertEqual(result["passed"], not expected)
                        self.assertEqual(result["matches"] + result["ignoredMatches"], 1)
                        self.assertFalse(policy.evaluate(report, 2)["passed"])

    def test_malformed_fix_cannot_be_treated_as_unfixed(self):
        for fix in ({}, {"state": "fixed", "versions": []},
                    {"state": "fixed", "versions": [None]}):
            with self.assertRaises((ValueError, KeyError)):
                policy.evaluate({"matches": [{"vulnerability": {"severity": "High", "fix": fix}}]}, 0)


class LicenseTests(unittest.TestCase):
    def test_missing_malformed_and_unknown_licenses(self):
        for value in (
            None,
            {},
            "MIT",
            [None],
            [{"value": 42}],
            [{"value": "NOASSERTION"}],
        ):
            with self.subTest(value=value):
                result = licenses.report(
                    {"artifacts": [{"id": "a", "name": "a", "licenses": value}]}
                )
                self.assertTrue(result["unresolved"])
                self.assertFalse(result["attributions"])

    def test_malformed_document_rejected(self):
        for value in ({}, [], {"artifacts": {}}, {"artifacts": [None]}):
            with self.assertRaises(TypeError):
                licenses.report(value)

    def test_plaintext_contents_and_index_deduplication(self):
        packages = [
            {
                "id": n,
                "name": n,
                "licenses": [{"value": "MIT", "contents": "Copyright Alice\nMIT text"}],
            }
            for n in ("a", "b")
        ]
        result = licenses.report(
            {"artifacts": packages}, {"/LICENSE": "Copyright Alice\nMIT text"}
        )
        self.assertEqual(len(result["attributions"]), 1)
        self.assertEqual(result["attributions"][0]["packages"], ["a", "b"])
        self.assertEqual(len(result["attributions"][0]["locations"]), 3)
        self.assertFalse(result["unresolved"])

    def test_malformed_contents_is_unresolved(self):
        result = licenses.report(
            {
                "artifacts": [
                    {"name": "a", "licenses": [{"value": "MIT", "contents": [42]}]}
                ]
            }
        )
        self.assertIn("malformed license contents", str(result["unresolved"]))

    def test_debian_and_rust_associations_do_not_cross_package_boundary(self):
        result = licenses.report(
            {
                "artifacts": [
                    {"id": "deb", "name": "foo", "type": "deb", "licenses": []},
                    {
                        "id": "rust",
                        "name": "bar",
                        "version": "1",
                        "type": "rust-crate",
                        "licenses": [],
                    },
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
    (ROOT / ".tools/bin/syft").exists(),
    "install pinned Syft for real cataloger smoke test",
)
class SyftIntegrationTests(unittest.TestCase):
    def test_real_rust_lock_cataloger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text("""version = 4
[[package]]
name = "tokio"
version = "1.48.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
""")
            result = subprocess.run(
                [
                    str(ROOT / ".tools/bin/syft"),
                    "scan",
                    f"dir:{root}",
                    "--select-catalogers",
                    "+rust-cargo-lock-cataloger",
                    "-o",
                    "syft-json",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            artifacts = json.loads(result.stdout)["artifacts"]
            self.assertTrue(
                any(
                    p["name"] == "tokio" and p["type"] == "rust-crate"
                    for p in artifacts
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
            self.assertTrue(result[1]["uri"].startswith("oci://"))


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
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='docker':
    if args[:2]==['image','inspect']:
        assert not args[2].startswith('docker:')
        print(json.dumps([{'Id':'sha256:'+'a'*64}]))
    elif args[0]=='create': print('container-id')
    elif args[0]=='export':
        with tarfile.open(args[args.index('--output')+1],'w') as tar:
            item=tarfile.TarInfo('usr/share/doc/test/copyright')
            data=b'Copyright tester'
            item.size=len(data); tar.addfile(item,io.BytesIO(data))
elif name=='syft':
    for i,arg in enumerate(args):
        if arg=='--exclude':
            assert args[i+1].startswith(('./', '*/', '**/')), 'Syft rejects absolute exclusion globs'
        if arg=='-o':
            fmt,path=args[i+1].split('=',1)
            pathlib.Path(path).write_text(json.dumps({'artifacts':[{'id':'test','name':'test','type':'deb','licenses':[]}]}))
elif name=='grype':
    assert not any(k.startswith('GRYPE_') for k in os.environ)
    mode=os.environ.get('TEST_GRYPE','clean')
    if mode=='malformed': print('{}')
    else:
        match={'vulnerability':{'severity':'High' if mode in ('block','ignored') else 'Unknown',
               'fix':{'state':'fixed' if mode in ('block','ignored') else 'not-fixed',
                      'versions':['2.0'] if mode in ('block','ignored') else []}}}
        if mode.startswith('invalid-severity'): match['vulnerability']['severity']='HIGH'
        if mode.startswith('invalid-state'): match['vulnerability']['fix']['state']='invalid'
        ignored=mode=='ignored' or mode.endswith('-ignored')
        present=mode in ('match','block','ignored') or mode.startswith('invalid-')
        print(json.dumps({'matches': [match] if present and not ignored else [],
                          'ignoredMatches': [match] if present and ignored else []}))
    sys.exit(2 if mode=='database-failure' else 0)
"""


class PipelineTests(unittest.TestCase):
    def test_gate_blockers_errors_and_all_finding_retention(self):
        for mode in (
            "clean",
            "match",
            "block",
            "ignored",
            "database-failure",
            "malformed",
            "invalid-severity",
            "invalid-state",
            "invalid-severity-ignored",
            "invalid-state-ignored",
            "no-source",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                (root / ".tools/bin").mkdir(parents=True)
                for script in ("evidence.sh", "license-report.py", "scan-sbom.sh",
                               "vulnerability_policy.py", "partition-sbom.py"):
                    shutil.copy(ROOT / "scripts" / script, root / "scripts" / script)
                for name in ("syft", "grype", "docker"):
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
                    TEST_GRYPE=mode,
                    GRYPE_ONLY_FIXED="true",
                    SOURCE_DIR="" if mode == "no-source" else str(root),
                )
                result = subprocess.run(
                    [
                        "bash",
                        str(root / "scripts/evidence.sh"),
                        "docker:test:local",
                        str(root / "out"),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                passed = mode in {"clean", "no-source", "match"}
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
                    self.assertTrue((prefix / "grype.json").exists())
                    if mode == "match":
                        self.assertEqual(len(json.loads((prefix / "grype.json").read_text())["matches"]), 1)
                    self.assertEqual(
                        json.loads((prefix / "scan-status.json").read_text())["passed"],
                        passed,
                    )


if __name__ == "__main__":
    unittest.main()
