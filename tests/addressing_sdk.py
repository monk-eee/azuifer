"""Host-style addressing through the official Queue, Table and File Share SDKs.

Usage (from the repository root, after `cargo build`):

    python -m venv .venv
    .venv/bin/pip install azure-storage-queue azure-data-tables azure-storage-file-share
    .venv/bin/python tests/addressing_sdk.py [--binary target/debug/azuifer]

Each client is given `http://testaccount.{service}.localhost:PORT` and an explicit account
name and key. The script also reports whether the SDK can infer the account from such a
host when it is given only a key. It needs `*.localhost` to resolve to the loopback
address, which Windows and macOS do and glibc does when `systemd-resolved` or an
`nss-myhostname` style resolver is active. It is a manual check, not part of `cargo test`.
"""

import argparse
import base64
import os
import subprocess
import sys

from azure.core.credentials import AzureNamedKeyCredential
from azure.data.tables import TableServiceClient
from azure.storage.fileshare import ShareServiceClient
from azure.storage.queue import QueueServiceClient

ACCOUNT = "testaccount"
KEY = base64.b64encode(bytes(range(32))).decode()
CREDENTIAL = {"account_name": ACCOUNT, "account_key": KEY}
PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"{name} failed {detail}")
    PASSED.append(name)
    print(f"ok  {name}")


class Server:
    def __init__(self, binary):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AZUIFER_")}
        env["AZUIFER_ACCOUNT_NAME"] = ACCOUNT
        env["AZUIFER_ACCOUNT_KEY"] = KEY
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--in-memory",
                   "--skip-api-version-check", "--shutdown-on-stdin-eof"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env, text=True)
        self.ports = {}
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("server exited during startup")
            name, _, url = line.strip().partition("_url=")
            self.ports[name] = url.rsplit(":", 1)[1]
            if name == "admin":
                break

    def url(self, service):
        return f"http://{ACCOUNT}.{service}.localhost:{self.ports[service]}"

    def stop(self):
        self.process.stdin.close()
        self.process.wait(timeout=15)


def infers_account(factory):
    """Whether the SDK works out the account from a host-style URL and a bare key."""
    try:
        return factory().account_name == ACCOUNT
    except ValueError:
        return False


def queue_flow(server):
    service = QueueServiceClient(server.url("queue"), credential=CREDENTIAL)
    check("queue client account", service.account_name == ACCOUNT)
    queue = service.create_queue("hostqueue", metadata={"via": "host"})
    queue.send_message("hello host")
    check("queue list", [q.name for q in service.list_queues()] == ["hostqueue"])
    peeked = queue.peek_messages()
    check("queue peek", [m.content for m in peeked] == ["hello host"])
    message = next(iter(queue.receive_messages()))
    check("queue receive", message.content == "hello host")
    queue.delete_message(message)
    check("queue metadata", queue.get_queue_properties().metadata == {"via": "host"})
    service.delete_queue("hostqueue")
    check("queue delete", list(service.list_queues()) == [])
    inferred = infers_account(lambda: QueueServiceClient(server.url("queue"), credential=KEY))
    print(f"info Queue SDK infers the account from the host: {inferred}")


def table_flow(server):
    credential = AzureNamedKeyCredential(ACCOUNT, KEY)
    service = TableServiceClient(endpoint=server.url("table"), credential=credential)
    table = service.create_table("HostTable")
    table.upsert_entity({"PartitionKey": "p", "RowKey": "r", "Value": "v"})
    entity = table.get_entity("p", "r")
    check("table entity", entity["Value"] == "v")
    check("table query", [e["RowKey"] for e in table.query_entities("PartitionKey eq 'p'")] == ["r"])
    check("table list", [t.name for t in service.list_tables()] == ["HostTable"])
    service.delete_table("HostTable")
    check("table delete", list(service.list_tables()) == [])


def file_flow(server):
    service = ShareServiceClient(server.url("file"), credential=CREDENTIAL)
    check("file client account", service.account_name == ACCOUNT)
    share = service.create_share("hostshare")
    directory = share.create_directory("docs")
    file = directory.get_file_client("note.txt")
    file.upload_file(b"hello host")
    check("file download", file.download_file().readall() == b"hello host")
    check("file list", [item.name for item in directory.list_directories_and_files()] == ["note.txt"])
    check("share list", [s.name for s in service.list_shares()] == ["hostshare"])
    service.delete_share("hostshare")
    inferred = infers_account(lambda: ShareServiceClient(server.url("file"), credential=KEY))
    print(f"info File Share SDK infers the account from the host: {inferred}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/azuifer")
    arguments = parser.parse_args()
    server = Server(arguments.binary)
    try:
        queue_flow(server)
        table_flow(server)
        file_flow(server)
    finally:
        server.stop()
    print(f"{len(PASSED)} checks passed")


if __name__ == "__main__":
    sys.exit(main())
