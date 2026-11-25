import hashlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from release import TARGETS, archive_name, make_archive, version, write_checksums


class ReleaseTests(unittest.TestCase):
    def test_release_tag_must_match_the_manifest(self):
        self.assertEqual(version(f"v{version()}"), version())
        with self.assertRaisesRegex(ValueError, "does not match"):
            version("v999.0.0")

    def test_archives_preserve_the_binary_name_and_unix_execute_bit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "test-executable"
            binary.write_bytes(b"fixture")
            tar_path = make_archive(binary, "aarch64-unknown-linux-musl", version(), root)
            zip_path = make_archive(binary, "x86_64-pc-windows-msvc", version(), root)
            with tarfile.open(tar_path) as archive:
                self.assertEqual(set(archive.getnames()), {"azuifer", "LICENSE-APACHE", "LICENSE-MIT"})
                self.assertEqual(archive.getmember("azuifer").mode, 0o755)
                self.assertEqual(archive.extractfile("azuifer").read(), b"fixture")
            with zipfile.ZipFile(zip_path) as archive:
                self.assertEqual(set(archive.namelist()), {"azuifer.exe", "LICENSE-APACHE", "LICENSE-MIT"})
                self.assertEqual(archive.read("azuifer.exe"), b"fixture")

    def test_incomplete_releases_cannot_emit_a_checksum_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            value = version()
            for target in TARGETS:
                (root / archive_name(value, target)).write_bytes(target.encode("ascii"))
            with self.assertRaisesRegex(ValueError, "missing"):
                write_checksums(value, root)
            self.assertFalse((root / "SHA256SUMS").exists())
            sbom = root / f"azuifer-{value}-cargo.spdx.json"
            sbom.write_bytes(b"{}")
            write_checksums(value, root)
            lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), 7)
            self.assertIn(f"{hashlib.sha256(b'{}').hexdigest()}  {sbom.name}", lines)


if __name__ == "__main__":
    unittest.main()
