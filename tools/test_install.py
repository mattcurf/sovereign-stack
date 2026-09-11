"""Offline installer/updater regressions: python3 -m unittest discover -s tools."""

import hashlib
import importlib.util
import io
import json
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


class UpdaterTests(unittest.TestCase):
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

        with patch.object(updater.subprocess, "check_output", return_value=json.dumps({
            "prerelease": False, "draft": False, "tag_name": "v0.74.0"
        }).encode()) as release, patch.object(updater, "fetch", side_effect=fetch):
            with self.assertRaises(TrivyReached):
                updater.main()
        self.assertEqual(release.call_args.args[0][-1], "repos/aquasecurity/trivy/releases/latest")
        base = "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/"
        self.assertEqual(urls[-2:], [base + "trivy_0.74.0_Linux-64bit.tar.gz",
                                     base + "trivy_0.74.0_checksums.txt"])


if __name__ == "__main__":
    unittest.main()
