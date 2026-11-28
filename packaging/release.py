import argparse
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
)


def version(tag=None):
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        value = tomllib.load(manifest)["package"]["version"]
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9]+)*)?", value):
        raise ValueError(f"unsupported release version: {value!r}")
    if tag is not None and tag != f"v{value}":
        raise ValueError(f"tag {tag!r} does not match Cargo.toml (expected v{value})")
    return value


def archive_name(release_version, target):
    suffix = "zip" if target.endswith("-windows-msvc") else "tar.gz"
    return f"azuifer-{release_version}-{target}.{suffix}"


def make_archive(binary, target, release_version, directory):
    windows = target.endswith("-windows-msvc")
    paths = [
        ("azuifer.exe" if windows else "azuifer", binary, 0o755),
        ("LICENSE-MIT", ROOT / "LICENSE-MIT", 0o644),
        ("LICENSE-APACHE", ROOT / "LICENSE-APACHE", 0o644),
    ]
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / archive_name(release_version, target)
    if windows:
        with zipfile.ZipFile(dest, "x") as archive:
            for name, path, mode in paths:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100000 | mode) << 16
                with path.open("rb") as source, archive.open(info, "w") as member:
                    shutil.copyfileobj(source, member)
    else:
        with dest.open("xb") as file, gzip.GzipFile(filename="", fileobj=file, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name, path, mode in paths:
                    info = tarfile.TarInfo(name)
                    info.mode = mode
                    info.size = path.stat().st_size
                    with path.open("rb") as source:
                        archive.addfile(info, source)
    return dest


def check_cargo_inventory(sbom):
    document = json.loads(sbom.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(document.get("packages"), list)
    ):
        raise ValueError(f"{sbom.name}: expected an SPDX 2.3 package inventory")
    with (ROOT / "Cargo.lock").open("rb") as lockfile:
        expected = {
            f"{package['name']}@{package['version']}"
            for package in tomllib.load(lockfile)["package"]
            if package.get("source", "").startswith("registry+")
        }
    recorded = set()
    for package in document["packages"]:
        if not isinstance(package, dict):
            raise ValueError(f"{sbom.name}: invalid SPDX package")
        references = package.get("externalRefs", [])
        if not isinstance(references, list):
            raise ValueError(f"{sbom.name}: invalid SPDX external references")
        if any(
            isinstance(reference, dict)
            and reference.get("referenceType") == "purl"
            and isinstance(reference.get("referenceLocator"), str)
            and reference["referenceLocator"].startswith("pkg:cargo/")
            for reference in references
        ):
            recorded.add(f"{package.get('name')}@{package.get('versionInfo')}")
    missing = sorted(expected - recorded)
    if missing:
        raise ValueError(f"{sbom.name}: missing {len(missing)} locked Cargo packages: {', '.join(missing[:8])}")


def write_checksums(release_version, directory):
    expected = {archive_name(release_version, target) for target in TARGETS}
    sbom = f"azuifer-{release_version}-cargo.spdx.json"
    expected.add(sbom)
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != expected:
        raise ValueError(f"release asset mismatch: missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}")
    check_cargo_inventory(directory / sbom)
    with (directory / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as checksums:
        for name in sorted(expected):
            with (directory / name).open("rb") as file:
                digest = hashlib.file_digest(file, "sha256").hexdigest()
            checksums.write(f"{digest}  {name}\n")


def main():
    parser = argparse.ArgumentParser(description="Package the Azuifer release binaries.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version").add_argument("--tag")
    archive = commands.add_parser("archive")
    archive.add_argument("--target", choices=TARGETS, required=True)
    archive.add_argument("--binary", type=Path, required=True)
    archive.add_argument("--output", type=Path, required=True)
    checksums = commands.add_parser("checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        release_version = version(getattr(args, "tag", None))
        if args.command == "version":
            print(release_version)
        elif args.command == "archive":
            binary = args.binary.resolve(strict=True)
            reported = subprocess.check_output([str(binary), "--version"], text=True, timeout=30).strip()
            if reported != f"azuifer {release_version}":
                raise ValueError(f"binary does not report azuifer {release_version}")
            print(make_archive(binary, args.target, release_version, args.output))
        elif args.command == "checksums":
            write_checksums(release_version, args.directory)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
