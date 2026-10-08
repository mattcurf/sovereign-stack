"""Offline installer/updater regressions: python3 -m unittest discover -s tools."""

import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("installer", "install.py")
updater = load("updater", "refresh-lock.py")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "tools").mkdir()
        self.bindir = self.root / ".tools/bin"
        self.bindir.mkdir(parents=True)
        self.binary = b"test trivy binary"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            member = tarfile.TarInfo("trivy")
            member.size = len(self.binary)
            tar.addfile(member, io.BytesIO(self.binary))
        self.archive = stream.getvalue()
        self.tool = {
            "name": "trivy", "version": "v0.74.0", "url": "https://example.test/trivy",
            "sha256": hashlib.sha256(self.archive).hexdigest(), "member": "trivy",
            "binary_sha256": hashlib.sha256(self.binary).hexdigest(),
        }
        self.write_lock()
        self.context = patch.object(installer, "__file__", str(self.root / "tools/install.py"))
        self.context.start()
        self.addCleanup(self.context.stop)

    def write_lock(self):
        (self.root / "tools/lock.json").write_text(json.dumps({"tools": [self.tool]}))

    def download(self, args, **kwargs):
        Path(args[-1]).write_bytes(self.archive)

    def test_cold_warm_and_binary_repair(self):
        with patch.object(installer.subprocess, "run", side_effect=self.download) as run:
            installer.main()
            run.assert_called_once()
        target = self.bindir / "trivy"
        self.assertEqual(target.read_bytes(), self.binary)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        with patch.object(installer.subprocess, "run") as run:
            installer.main()
            target.write_bytes(b"damaged")
            installer.main()
            run.assert_not_called()
        self.assertEqual(target.read_bytes(), self.binary)

    def test_retire_owned_only(self):
        expected = hashlib.sha256(b"legacy").hexdigest()
        for name in ("syft", "grype"):
            (self.bindir / name).write_bytes(b"legacy")
        with patch.object(installer, "RETIRED_BINARIES", dict.fromkeys(("syft", "grype"), expected)):
            with patch.object(installer.subprocess, "run", side_effect=self.download):
                installer.main()
        self.assertEqual([path.name for path in self.bindir.iterdir()], ["trivy"])

    def test_unknown_obsolete_paths_are_preserved(self):
        for kind in ("file", "directory", "symlink", "dangling"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                bindir = Path(tmp)
                syft = bindir / "syft"
                syft.write_bytes(b"owned")
                grype = bindir / "grype"
                if kind == "file":
                    grype.write_bytes(b"unknown")
                elif kind == "directory":
                    grype.mkdir()
                else:
                    grype.symlink_to(syft if kind == "symlink" else bindir / "missing")
                pins = {"syft": hashlib.sha256(b"owned").hexdigest(), "grype": "unknown"}
                with patch.object(installer, "RETIRED_BINARIES", pins):
                    with self.assertRaisesRegex(SystemExit, "Inspect and move"):
                        installer.retire_obsolete_binaries(bindir)
                self.assertTrue(syft.exists())
                self.assertTrue(grype.exists() or grype.is_symlink())

    def test_corrupt_download_is_rejected(self):
        self.tool["sha256"] = "0" * 64
        self.write_lock()
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            with self.assertRaisesRegex(SystemExit, "Checksum mismatch"):
                installer.main()
        self.assertFalse((self.bindir / "trivy").exists())

    def test_corrupt_cached_archive_is_rejected_on_warm_install(self):
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            installer.main()
        (self.root / ".tools/cache" / self.tool["sha256"]).write_bytes(b"bad")
        with self.assertRaisesRegex(SystemExit, "Corrupt cached artifact"):
            installer.main()

    def test_wrong_binary_digest_is_rejected(self):
        self.tool["binary_sha256"] = "0" * 64
        self.write_lock()
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            with self.assertRaisesRegex(SystemExit, "Binary checksum mismatch"):
                installer.main()


class SourceBuildTests(InstallerTests):
    def setUp(self):
        super().setUp()
        self.patch = self.root / "tools/deps.patch"
        self.patch.write_text(
            "--- a/go.mod\n+++ b/go.mod\n@@ -1,2 +1,2 @@\n"
            " module example.test/tool\n-require example.test/dep v1.0.0\n"
            "+require example.test/dep v1.0.1\n"
        )
        self.archives = {}
        for url, name, data in (
            ("https://example.test/source", "project/go.mod",
             b"module example.test/tool\nrequire example.test/dep v1.0.0\n"),
            ("https://example.test/go", "go/bin/go", b"fake compiler"),
        ):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            self.archives[url] = stream.getvalue()
        self.tool.update(
            url="https://example.test/source", member="project",
            sha256=hashlib.sha256(self.archives["https://example.test/source"]).hexdigest(),
            source_build={
                "go": {"url": "https://example.test/go",
                       "sha256": hashlib.sha256(self.archives["https://example.test/go"]).hexdigest()},
                "patch": "tools/deps.patch",
                "patch_sha256": installer.digest(self.patch),
                "package": "./cmd/tool", "ldflags": "-s -w -buildid=",
            },
        )
        self.write_lock()
        self.run = subprocess.run

    def download(self, args, **kwargs):
        if args[0] == "curl":
            Path(args[-1]).write_bytes(self.archives[args[-3]])
        elif args[0] == "git":
            return self.run(args, **kwargs)
        else:
            self.assertIn("-mod=readonly", args)
            self.assertIn("-trimpath", args)
            self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
            self.assertEqual(kwargs["env"]["GOENV"], "off")
            self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
            self.assertIn("v1.0.1", (kwargs["cwd"] / "go.mod").read_text())
            Path(args[args.index("-o") + 1]).write_bytes(self.binary)

    def test_compiler_and_patch_hashes_fail_closed(self):
        for field, message in (("compiler", "Checksum mismatch"),
                               ("patch", "Source patch checksum mismatch")):
            with self.subTest(field=field):
                build = self.tool["source_build"]
                old = build["go"]["sha256"] if field == "compiler" else build["patch_sha256"]
                if field == "compiler":
                    build["go"]["sha256"] = "0" * 64
                else:
                    build["patch_sha256"] = "0" * 64
                self.write_lock()
                with patch.object(installer.subprocess, "run", side_effect=self.download):
                    with self.assertRaisesRegex(SystemExit, message):
                        installer.main()
                self.assertFalse((self.bindir / "trivy").exists())
                if field == "compiler":
                    build["go"]["sha256"] = old
                else:
                    build["patch_sha256"] = old

    def test_source_archive_cannot_escape_temporary_directory(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            member = tarfile.TarInfo("../escape")
            member.size = 6
            tar.addfile(member, io.BytesIO(b"unsafe"))
        self.archives[self.tool["url"]] = stream.getvalue()
        self.tool["sha256"] = hashlib.sha256(stream.getvalue()).hexdigest()
        self.write_lock()
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            with self.assertRaises(tarfile.FilterError):
                installer.main()
        self.assertFalse((self.root / ".tools/cache/escape").exists())
        self.assertFalse((self.bindir / "trivy").exists())

    # The inherited cold/warm, corruption and ownership tests also run through
    # the source-build path. A repaired binary must still match its reviewed hash.
    def test_cold_warm_and_binary_repair(self):
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            installer.main()
        target = self.bindir / "trivy"
        self.assertEqual(target.read_bytes(), self.binary)
        with patch.object(installer.subprocess, "run") as run:
            installer.main()
            run.assert_not_called()
        target.write_bytes(b"damaged")
        with patch.object(installer.subprocess, "run", side_effect=self.download):
            installer.main()
        self.assertEqual(target.read_bytes(), self.binary)


class UpdaterTests(unittest.TestCase):
    def test_updater_cannot_discard_source_remediation(self):
        with patch.object(updater.Path, "read_text", return_value=json.dumps({
            "tools": [{"source_build": {}}]
        })), patch.object(updater.subprocess, "check_output") as release:
            with self.assertRaisesRegex(SystemExit, "reviewed source builds"):
                updater.main()
            release.assert_not_called()

    def test_trivy_asset_case_and_checksum_manifest(self):
        urls = []

        class TrivyReached(Exception):
            pass

        def fetch(url, path):
            urls.append(url)
            if "aquasecurity/trivy" in url:
                if url.endswith("checksums.txt"):
                    raise TrivyReached()
                path.write_bytes(b"archive")
            elif url.endswith("checksums.txt"):
                path.write_text(hashlib.sha256(b"cosign").hexdigest() + "  cosign-linux-amd64\n")
            else:
                path.write_bytes(b"cosign")

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "lock.json").write_text(json.dumps({"tools": []}))
            with patch.object(updater.subprocess, "check_output", return_value=json.dumps({
                "prerelease": False, "draft": False, "tag_name": "v0.74.0"
            }).encode()) as release, patch.object(updater, "fetch", side_effect=fetch), \
                    patch.object(updater, "__file__", str(Path(tmp) / "refresh-lock.py")):
                with self.assertRaises(TrivyReached):
                    updater.main()
        self.assertEqual(release.call_args.args[0][-1], "repos/aquasecurity/trivy/releases/latest")
        base = "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/"
        self.assertEqual(urls[-2:], [base + "trivy_0.74.0_Linux-64bit.tar.gz",
                                     base + "trivy_0.74.0_checksums.txt"])


if __name__ == "__main__":
    unittest.main()
