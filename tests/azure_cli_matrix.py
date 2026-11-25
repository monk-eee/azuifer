"""Verify the pinned Azure CLI release window against an Azuifer Docker image."""

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
from pathlib import Path

FIXTURE = Path(__file__).with_name("azure_cli.py").resolve()
PINS = Path(__file__).with_name("azure_cli_versions.json")
SHA256 = r"sha256:[0-9a-f]{64}"
DOCKER_ERRORS = (OSError, RuntimeError, subprocess.TimeoutExpired)


def docker(*args, env=None, timeout=60):
    result = subprocess.run(
        ["docker", *args], env=env, capture_output=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    if result.returncode:
        detail = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"docker {args[0]} exited {result.returncode}: {detail}")
    return result.stdout.strip()


def versions():
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    if not isinstance(pins, dict) or len(pins) != 4 or any(
        not re.fullmatch(r"\d+\.\d+\.\d+", version)
        or not isinstance(digest, str)
        or not re.fullmatch(SHA256, digest)
        for version, digest in pins.items()
    ) or len(set(pins.values())) != 4:
        raise ValueError(f"{PINS.name} must pin four distinct Azure CLI releases by digest")
    return pins


def verify_client(emulator_id, version, client_image):
    result = {"expected_cli_version": version, "client_image": client_image}
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    env = dict(os.environ, AZUIFER_ACCOUNT_KEY=key)
    containers = []
    errors = []
    try:
        emulator = docker(
            "create", "--network", "none", "--read-only",
            "--tmpfs", "/data:rw,mode=0770,uid=65532,gid=65532,size=1g",
            "--env", "AZUIFER_ACCOUNT_KEY", emulator_id,
            "serve", "--location", "/data", "--skip-api-version-check",
            env=env,
        )
        containers.append(emulator)
        docker("start", emulator)
        config = docker(
            "inspect", "--format", "{{.Config.User}} {{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}}",
            emulator,
        )
        if config != "65532:65532 none true":
            raise RuntimeError("expected a non-root emulator with no external network and a read-only root")
        client = docker(
            "create", "--network", f"container:{emulator}", "--env", "AZUIFER_ACCOUNT_KEY",
            "--mount", f"type=bind,source={FIXTURE},target=/tmp/azure_cli.py,readonly",
            "--entrypoint", "python3", client_image,
            "/tmp/azure_cli.py", "--expected-version", version, "--json",
            env=env, timeout=420,
        )
        containers.append(client)
        result["client_image_id"] = docker("inspect", "--format", "{{.Image}}", client)
        evidence = json.loads(docker("start", "--attach", client, timeout=720))
        if evidence["cli_version"] != version:
            raise RuntimeError(f"expected Azure CLI {version}, found {evidence['cli_version']}")
        result.update(evidence)
    except (*DOCKER_ERRORS, ValueError, KeyError) as error:
        errors.append(str(error))
    finally:
        if containers:
            try:
                docker("rm", "--force", *reversed(containers))
            except DOCKER_ERRORS as error:
                errors.append(f"container cleanup failed: {error}")
    if errors:
        result.update(status="failed", error="\n".join(errors).replace(key, "[redacted]"))
        print(f"Azure CLI {version}: FAIL\n{result['error']}", flush=True)
    else:
        result["status"] = "passed"
        print(f"Azure CLI {version}: PASS ({len(result['checks'])} checks, {result['multipart']['bytes']} multipart bytes)", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="azuifer:ci", help="locally built Azuifer image")
    parser.add_argument("--report", type=Path, default=Path("dist/azure-cli-compatibility.json"))
    args = parser.parse_args()
    try:
        pins = versions()
        image_id, platform = docker(
            "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", args.image,
        ).split()
        if not re.fullmatch(SHA256, image_id) or not platform.startswith("linux/"):
            raise ValueError("expected a locally built Linux Azuifer image")
        manifest = json.loads(docker("run", "--rm", "--network", "none", image_id, "conformance", "export"))
        report = {
            "schema_version": 1,
            "emulator_image_id": image_id,
            "platform": platform,
            "blob_api_version": manifest["api_version"],
            "authorization": "SharedKey",
            "newer_version_fallback": True,
            "azure_differential_verified": False,
            "results": [],
        }
        for version, digest in pins.items():
            image = f"mcr.microsoft.com/azure-cli:{version}@{digest}"
            report["results"].append(verify_client(image_id, version, image))
        report["passed"] = all(result["status"] == "passed" for result in report["results"])
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Azure CLI compatibility report: {args.report}")
    except (*DOCKER_ERRORS, ValueError, KeyError) as error:
        parser.exit(1, f"Azure CLI matrix: {error}\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
