import hashlib
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

if __package__:
    from . import release
else:
    import release


def fake_archives(directory, value):
    for target in release.TARGETS:
        (directory / release.archive_name(value, target)).write_bytes(target.encode("ascii"))


class ReleaseTests(unittest.TestCase):
    def test_release_tag_must_match_the_manifest(self):
        self.assertEqual(release.version(f"v{release.version()}"), release.version())
        with self.assertRaisesRegex(ValueError, "does not match"):
            release.version("v999.0.0")

    def test_archives_preserve_the_binary_name_and_unix_execute_bit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "test-executable"
            binary.write_bytes(b"fixture")
            tar_path = release.make_archive(binary, "aarch64-unknown-linux-musl", release.version(), root)
            zip_path = release.make_archive(binary, "x86_64-pc-windows-msvc", release.version(), root)
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
            value = release.version()
            fake_archives(root, value)
            with self.assertRaisesRegex(ValueError, "missing"):
                release.write_checksums(value, root)
            self.assertFalse((root / "SHA256SUMS").exists())

    def test_only_a_complete_cargo_spdx_inventory_can_be_checksummed(self):
        value = release.version()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dist = root / "dist"
            dist.mkdir()
            fake_archives(dist, value)
            (root / "Cargo.lock").write_text(
                'version = 4\n'
                '[[package]]\nname = "serde"\nversion = "1.0.1"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '[[package]]\nname = "serde"\nversion = "1.0.2"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
                encoding="utf-8",
            )
            sbom = dist / f"azuifer-{value}-cargo.spdx.json"
            checksums = dist / "SHA256SUMS"

            def write_sbom(*versions):
                sbom.write_text(json.dumps({
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "packages": [{
                        "name": "serde",
                        "versionInfo": version,
                        "externalRefs": [{
                            "referenceType": "purl",
                            "referenceLocator": f"pkg:cargo/serde@{version}",
                        }],
                    } for version in versions],
                }), encoding="utf-8")

            with patch.object(release, "ROOT", root):
                sbom.write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "SPDX"):
                    release.write_checksums(value, dist)
                self.assertFalse(checksums.exists())

                write_sbom("1.0.1")
                with self.assertRaisesRegex(ValueError, r"missing.*serde@1\.0\.2"):
                    release.write_checksums(value, dist)
                self.assertFalse(checksums.exists())

                write_sbom("1.0.1", "1.0.2")
                release.write_checksums(value, dist)

            lines = checksums.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), len(release.TARGETS) + 1)
            self.assertIn(f"{hashlib.sha256(sbom.read_bytes()).hexdigest()}  {sbom.name}", lines)


if __name__ == "__main__":
    unittest.main()
