"""Native Trivy inventory partition and attribution contracts (offline)."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


partitioner = load("partition-sbom")
licenses = load("license-report")
BUILD = "usr/share/sovereign-stack/nginx/npm/node_modules/foo/package.json"
RUNTIME = "usr/local/lib/node_modules/foo/package.json"


def document(*results):
    return {"SchemaVersion": 2, "Metadata": {"ImageID": "sha256:test"}, "Results": list(results)}


def scope(kind, *packages, target="Node.js", cls="lang-pkgs"):
    return {"Class": cls, "Type": kind, "Target": target, "Packages": list(packages)}


def package(name, path=None, version="1"):
    result = {"ID": name, "Name": name, "Version": version, "Licenses": ["MIT"]}
    if path is not None:
        result["FilePath"] = path
    return result


class TrivyInventoryTests(unittest.TestCase):
    def test_primary_paths_override_supporting_and_target_paths(self):
        build = package("build", BUILD)
        build["InstalledFiles"] = [RUNTIME]
        runtime = package("runtime", RUNTIME)
        runtime["Locations"] = [{"FilePath": BUILD}]
        native = document(scope("node-pkg", build, runtime, target=BUILD),
                          scope("cargo", package("rust"), target="usr/share/sovereign-stack/rust/Cargo.lock"),
                          scope("debian", package("os"), target="image/nginx:local (debian 13)", cls="os-pkgs"),
                          scope("node-pkg", package("fallback"), target=BUILD))
        original = copy.deepcopy(native)
        for is_build, expected in ((False, {"runtime", "rust", "os"}), (True, {"build", "fallback"})):
            result = partitioner.partition(native, is_build)
            self.assertEqual({p["Name"] for r in result["Results"] for p in r["Packages"]}, expected)
            self.assertEqual(result["Metadata"], native["Metadata"])
        self.assertEqual(native, original)

    def test_os_without_primary_is_runtime_and_reserved_prefix_is_exact(self):
        os_package = package("os")
        os_package["InstalledFiles"] = [BUILD]
        native = document(scope("debian", os_package, target=BUILD, cls="os-pkgs"),
                          scope("node-pkg", package("neighbor", BUILD.replace("nginx/", "nginx-other/"))))
        self.assertEqual(partitioner.partition(native, True)["Results"], [])

    def test_license_records_follow_actual_paths(self):
        for cls in ("license", "license-file"):
            native = document({"Class": cls, "Target": "License files", "Licenses": [
                {"FilePath": BUILD, "Name": "MIT"}, {"FilePath": RUNTIME, "Name": "BSD"}]})
            for build, name in ((True, "MIT"), (False, "BSD")):
                self.assertEqual(partitioner.partition(native, build)["Results"][0]["Licenses"][0]["Name"], name)

    def test_empty_and_malformed_native_documents(self):
        self.assertEqual(licenses.report(document())["packages"], [])
        self.assertEqual(partitioner.partition(document(), False)["Results"], [])
        empty = {"SchemaVersion": 2, "ArtifactName": "empty-directory"}
        self.assertEqual(licenses.report(empty)["packages"], [])
        self.assertEqual(partitioner.partition(empty, False)["Results"], [])
        for malformed in ({}, [], {"artifacts": []}, {"SchemaVersion": 2, "Results": {}},
                          document(None), document(scope("cargo", None)),
                          document({"Class": "license", "Licenses": [None]})):
            for operation in (licenses.report, lambda value: partitioner.partition(value, False)):
                with self.subTest(value=malformed), self.assertRaises(TypeError):
                    operation(malformed)

    def test_cli_preserves_raw_complete_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = json.dumps(document(scope("node-pkg", package("build", BUILD)))) + "\n"
            (root / "sbom.complete.trivy.json").write_text(raw)
            subprocess.run([sys.executable, str(ROOT / "scripts/partition-sbom.py"), tmp], check=True)
            self.assertEqual((root / "sbom.complete.trivy.json").read_text(), raw)
            for prefix in (root, root / "build-provenance"):
                self.assertEqual(json.loads((prefix / "sbom.trivy.json").read_text())["SchemaVersion"], 2)

    def test_rust_exact_name_and_version_debian_and_dedup(self):
        crate = package("foo", version="1")
        native = document(scope("cargo", crate, package("foo", version="10")),
                          scope("cargo", crate, target="other/Cargo.lock"),
                          scope("debian", package("foo"), cls="os-pkgs"))
        result = licenses.report(native, {
            "/usr/share/sovereign-stack/rust/dependencies/foo-1/LICENSE": "Rust one",
            "/usr/share/sovereign-stack/rust/dependencies/foo-100/LICENSE": "Wrong version",
            "/usr/share/doc/foo/copyright": "Debian copyright"})
        self.assertEqual(len(result["packages"]), 3)
        self.assertEqual(len({p["id"] for p in result["packages"]}), 3)
        self.assertEqual([len(p["attributions"]) for p in result["packages"]], [1, 0, 1])
        self.assertEqual([p["type"] for p in result["packages"]], ["rust-crate", "rust-crate", "deb"])
        self.assertIn("association unresolved", str(result["unresolved"]))

    def test_unavailable_tool_license_is_unresolved(self):
        for value in (None, {}, "MIT", [None], ["UNKNOWN"], []):
            tool = package("trivy")
            tool["Licenses"] = value
            result = licenses.report(document(scope("binary", tool)))
            self.assertTrue(result["unresolved"])
            self.assertFalse(result["attributions"])

    def test_node_attribution_stays_in_package_directory(self):
        native = document(scope("node-pkg", package("foo", RUNTIME)))
        result = licenses.report(native, {
            "/usr/local/lib/node_modules/foo/LICENSE": "Foo notice",
            "/usr/local/lib/node_modules/foo/node_modules/bar/LICENSE": "Bar notice"})
        self.assertEqual(len(result["packages"][0]["attributions"]), 1)
        self.assertIn("association unresolved", str(result["unresolved"]))

    def test_source_notices_exclude_generated_and_linked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'LICENSE').write_text('Original MIT notice')
            (root / 'NOTICE').symlink_to('/etc/passwd')
            for directory in ('evidence', 'custom-output'):
                (root / directory).mkdir()
                (root / directory / 'LICENSE').write_text('Generated notice')
            texts, issues = licenses.source_texts(root, root / 'custom-output')
            self.assertEqual(texts, {'/LICENSE': 'Original MIT notice'})
            self.assertEqual([issue['path'] for issue in issues], ['/NOTICE'])

    def test_python_notice_association_stays_in_exact_distribution(self):
        native = document(scope('python-pkg', package('waitress',
                          'opt/python/waitress-3.0.2.dist-info/METADATA', '3.0.2')))
        result = licenses.report(native, {
            '/opt/python/waitress-3.0.2.dist-info/licenses/LICENSE': 'Correct notice',
            '/opt/python/waitress-3.0.20.dist-info/LICENSE': 'Other version',
            '/opt/python/other-3.0.2.dist-info/LICENSE': 'Other distribution',
        })
        self.assertEqual(len(result['packages'][0]['attributions']), 1)
        associated = [a['text'] for a in result['attributions'] if a['packages']]
        self.assertEqual(associated, ['Correct notice'])


class TrivyBinaryIntegrationTests(unittest.TestCase):
    def test_tool_collector_detects_compiled_dependencies_without_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ('scripts', 'tools', '.tools/bin'):
                (root / directory).mkdir(parents=True)
            for script in ('tool-evidence.sh', 'license-report.py'):
                shutil.copy(ROOT / 'scripts' / script, root / 'scripts' / script)
            shutil.copy(ROOT / '.tools/bin/actionlint', root / '.tools/bin/actionlint')
            (root / '.tools/bin/trivy').symlink_to(ROOT / '.tools/bin/trivy')
            patch = root / 'tools/deps.patch'
            patch.write_bytes(b'reviewed dependency patch fixture\n')
            tool = {
                'name': 'actionlint',
                'binary_sha256': hashlib.sha256((root / '.tools/bin/actionlint').read_bytes()).hexdigest(),
                'source_build': {'patch': 'tools/deps.patch',
                                 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest()},
            }
            (root / 'tools/lock.json').write_text(json.dumps({'tools': [tool]}))
            result = subprocess.run(['bash', str(root / 'scripts/tool-evidence.sh'), '--collect-only'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            native = json.loads((root / 'evidence/tools/sbom.trivy.json').read_text())
            packages = [p for scope in native.get('Results', []) for p in scope.get('Packages', [])]
            self.assertTrue(any(p['Name'] == 'stdlib' for p in packages))
            self.assertTrue(any(p['Name'] == 'github.com/rhysd/actionlint' for p in packages))
            self.assertFalse((root / 'evidence/tools/scan-status.json').exists())
            self.assertEqual((root / 'evidence/tools/source-patches/actionlint.patch').read_bytes(),
                             patch.read_bytes())
            patch.write_bytes(b'unreviewed change\n')
            result = subprocess.run(['bash', str(root / 'scripts/tool-evidence.sh'), '--collect-only'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('does not match reviewed patch', result.stderr)


if __name__ == "__main__":
    unittest.main()
