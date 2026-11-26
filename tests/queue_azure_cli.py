"""Runs the real `az storage queue` and `az storage message` workflow against Azuifer.

Start Azuifer with --skip-api-version-check (Azure CLI requests newer API versions):

    azuifer serve --services queue --queue-port 10001 --in-memory --skip-api-version-check
    python tests/queue_azure_cli.py --queue-url http://127.0.0.1:10001
"""

import argparse
import json
import shutil
import subprocess
import sys

DEV_ACCOUNT = "devstoreaccount1"
DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-url", default="http://127.0.0.1:10001")
    parser.add_argument("--account", default=DEV_ACCOUNT)
    parser.add_argument("--key", default=DEV_KEY)
    args = parser.parse_args()
    az = shutil.which("az") or shutil.which("az.cmd")
    if not az:
        sys.exit("Azure CLI (az) is not on PATH")
    connection = (
        f"DefaultEndpointsProtocol=http;AccountName={args.account};AccountKey={args.key};"
        f"QueueEndpoint={args.queue_url.rstrip('/')}/{args.account};"
    )

    def run(*command):
        result = subprocess.run(
            [az, "storage", *command, "--connection-string", connection, "-o", "json"],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(f"az storage {' '.join(command)} failed:\n{result.stderr}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    queue = "azcli-queue"
    check(run("queue", "create", "--name", queue)["created"], "create")
    check(run("queue", "exists", "--name", queue)["exists"], "exists")
    check(queue in [q["name"] for q in run("queue", "list")], "list")
    put = run("message", "put", "--queue-name", queue, "--content", "hello from az")
    check(put["id"] and put["popReceipt"], "put")
    peek = run("message", "peek", "--queue-name", queue)
    check([m["content"] for m in peek] == ["hello from az"], "peek")
    got = run("message", "get", "--queue-name", queue, "--visibility-timeout", "600")[0]
    check(got["dequeueCount"] == 1 and got["popReceipt"], "get")
    check(run("message", "get", "--queue-name", queue) == [], "leased message is invisible")
    updated = run("message", "update", "--queue-name", queue, "--id", got["id"],
                  "--pop-receipt", got["popReceipt"], "--content", "updated",
                  "--visibility-timeout", "0")
    check(updated["popReceipt"] != got["popReceipt"], "update")
    again = run("message", "get", "--queue-name", queue)[0]
    check(again["content"] == "updated" and again["dequeueCount"] == 2, "updated content")
    run("message", "delete", "--queue-name", queue, "--id", again["id"],
        "--pop-receipt", again["popReceipt"])
    run("message", "put", "--queue-name", queue, "--content", "two")
    run("message", "clear", "--queue-name", queue)
    check(run("message", "peek", "--queue-name", queue) == [], "clear")
    run("queue", "metadata", "update", "--name", queue, "--metadata", "a=b")
    check(run("queue", "metadata", "show", "--name", queue) == {"a": "b"}, "metadata")
    check(run("queue", "delete", "--name", queue)["deleted"], "delete")
    print(f"Azure CLI queue/message workflow: {checks} checks passed")


if __name__ == "__main__":
    main()
