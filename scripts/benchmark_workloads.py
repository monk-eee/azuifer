"""Loopback HTTP workloads shared by both benchmark storage modes."""

import base64
import hashlib
import hmac
import http.client
import itertools
import json
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

ACCOUNT = "benchmark"
API_VERSION = "2023-11-03"
MIB = 1024 * 1024
BLOCK = bytes(range(256)) * 256
SMALL_BLOB = BLOCK[:1024]
DFS_BYTES = BLOCK[:4096]
SERVICES = ("blob", "dfs", "file", "queue", "table")
OPERATIONS = {
    "blob": ("put_small", "get_small", "list", "put_stream", "get_stream"),
    "dfs": ("create", "append", "flush", "rename_directory"),
    "file": ("create", "put_range", "get_range", "list"),
    "queue": ("enqueue", "dequeue", "delete"),
    "table": ("insert", "query", "batch"),
}
STREAM_OPERATIONS = ("blob.put_stream", "blob.get_stream")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def account_sas(key):
    fields = {
        "sp": "rwdlacup",
        "ss": "bfqt",  # DFS shares the Blob service signature.
        "srt": "sco",
        "se": "2100-01-01T00:00:00Z",
        "sv": API_VERSION,
    }
    signed = "\n".join((
        ACCOUNT, fields["sp"], fields["ss"], fields["srt"], "", fields["se"],
        "", "", API_VERSION, "", "",
    ))
    fields["sig"] = base64.b64encode(hmac.digest(key, signed.encode("ascii"), "sha256")).decode("ascii")
    return urlencode(fields)


class Workloads:
    def __init__(self, ports, key, stream_bytes):
        self.ports = ports
        self.connections = {
            service: http.client.HTTPConnection("127.0.0.1", ports[service], timeout=30)
            for service in SERVICES
        }
        self.sas = account_sas(key)
        self.stream_bytes = stream_bytes
        self.blocks = stream_bytes // len(BLOCK)
        digest = hashlib.sha256()
        for block in itertools.repeat(BLOCK, self.blocks):
            digest.update(block)
        self.stream_digest = digest.digest()
        self.samples = {f"{service}.{op}": [] for service in SERVICES for op in OPERATIONS[service]}
        self.measuring = False

    def close(self):
        for connection in self.connections.values():
            connection.close()

    def call(self, service, method, path, status, *, op=None, headers=None, body=None, stream=False):
        label = f"{service}.{op}" if op else f"{service} {method} {path.split('?', 1)[0]}"
        connection = self.connections[service]
        target = f"/{ACCOUNT}{path}{'&' if '?' in path else '?'}{self.sas}"
        headers = {"x-ms-version": API_VERSION, **(headers or {})}
        if stream and method == "PUT":
            headers["Content-Length"] = str(self.stream_bytes)
            body = itertools.repeat(BLOCK, self.blocks)
        started = time.perf_counter_ns()
        connection.request(method, target, body, headers)
        with connection.getresponse() as response:
            if response.status != status:
                code = response.getheader("x-ms-error-code")
                raise ValueError(f"{label}: expected HTTP {status}, got {response.status} ({code or 'no error code'})")
            if stream and method == "GET":
                digest = hashlib.sha256()
                count = 0
                while block := response.read(len(BLOCK)):
                    count += len(block)
                    require(count <= self.stream_bytes, f"{label}: response exceeded expected size")
                    digest.update(block)
                require(count == self.stream_bytes and digest.digest() == self.stream_digest,
                        f"{label}: received incorrect streaming bytes")
                result = b""
            else:
                result = response.read(MIB + 1)
                require(len(result) <= MIB, f"{label}: unexpected large response")
        elapsed = time.perf_counter_ns() - started
        if self.measuring and op is not None:
            self.samples[label].append(elapsed)
        return result

    def setup(self):
        for service, path in (
            ("blob", "/small?restype=container"), ("blob", "/stream?restype=container"),
            ("dfs", "/lake?resource=filesystem"), ("file", "/share?restype=share"),
            ("queue", "/messages"),
        ):
            self.call(service, "PUT", path, 201)
        self.call("table", "POST", "/Tables", 204,
                  headers=TABLE_JSON, body=b'{"TableName":"Benchmark"}')

    def blob(self):
        self.call("blob", "PUT", "/small/data", 201, op="put_small",
                  headers=BLOB_TYPE, body=SMALL_BLOB)
        data = self.call("blob", "GET", "/small/data", 200, op="get_small")
        require(data == SMALL_BLOB, "Blob GET did not round-trip the payload")
        listing = self.call("blob", "GET", "/small?restype=container&comp=list", 200, op="list")
        require(ET.fromstring(listing).findtext("./Blobs/Blob/Name") == "data",
                "Blob list did not contain the stored blob")

    def stream(self):
        self.call("blob", "PUT", "/stream/data", 201, op="put_stream", headers=BLOB_TYPE, stream=True)
        self.call("blob", "GET", "/stream/data", 200, op="get_stream", stream=True)

    def dfs(self):
        self.call("dfs", "PUT", "/lake/before?resource=directory", 201)
        file = "/lake/before/data"
        self.call("dfs", "PUT", f"{file}?resource=file", 201, op="create")
        self.call("dfs", "PATCH", f"{file}?action=append&position=0", 202, op="append", body=DFS_BYTES)
        self.call("dfs", "PATCH", f"{file}?action=flush&position={len(DFS_BYTES)}", 200, op="flush")
        self.call("dfs", "PUT", "/lake/after?resource=directory", 201, op="rename_directory",
                  headers={"x-ms-rename-source": f"/{ACCOUNT}/lake/before"})
        self.call("dfs", "HEAD", file, 404)
        data = self.call("dfs", "GET", "/lake/after/data", 200)
        require(data == DFS_BYTES, "DFS directory rename did not preserve the file")
        self.call("dfs", "DELETE", "/lake/after?recursive=true", 200)

    def file(self):
        file = "/share/data"
        self.call("file", "PUT", file, 201, op="create",
                  headers={"x-ms-type": "file", "x-ms-content-length": str(2 * len(BLOCK))})
        byte_range = {"x-ms-range": f"bytes={len(BLOCK)}-{2 * len(BLOCK) - 1}"}
        self.call("file", "PUT", f"{file}?comp=range", 201, op="put_range",
                  headers={**byte_range, "x-ms-write": "update"}, body=BLOCK)
        data = self.call("file", "GET", file, 206, op="get_range", headers=byte_range)
        require(data == BLOCK, "FileREST range did not round-trip the payload")
        listing = self.call("file", "GET", "/share?restype=directory&comp=list", 200, op="list")
        require(ET.fromstring(listing).findtext("./Entries/File/Name") == "data",
                "FileREST list did not contain the stored file")

    def queue(self):
        messages = "/messages/messages"
        enqueued = self.call(
            "queue", "POST", messages, 201, op="enqueue", headers={"Content-Type": "application/xml"},
            body=b"<QueueMessage><MessageText>benchmark message</MessageText></QueueMessage>",
        )
        retrieved = self.call("queue", "GET", f"{messages}?numofmessages=1", 200, op="dequeue")
        enqueued = ET.fromstring(enqueued).findtext("./QueueMessage/MessageId")
        message = ET.fromstring(retrieved).find("QueueMessage")
        require(message is not None, "Queue did not return an enqueued message")
        receipt = message.findtext("PopReceipt")
        require(enqueued and receipt and message.findtext("MessageId") == enqueued
                and message.findtext("MessageText") == "benchmark message",
                "Queue did not round-trip the enqueued message")
        self.call("queue", "DELETE", f"{messages}/{enqueued}?{urlencode({'popreceipt': receipt})}",
                  204, op="delete")

    def table(self):
        def entity(row):
            return json.dumps({"PartitionKey": "p", "RowKey": row, "Value": row}).encode("ascii")

        def rows(op=None):
            query = urlencode({"$filter": "PartitionKey eq 'p'"})
            data = self.call("table", "GET", f"/Benchmark()?{query}", 200, op=op, headers=TABLE_JSON)
            return {row["RowKey"]: row["Value"] for row in json.loads(data)["value"]}

        self.call("table", "POST", "/Benchmark", 204, op="insert",
                  headers=TABLE_JSON, body=entity("single"))
        require(rows("query") == {"single": "single"}, "Table query did not find the inserted entity")
        batch = [b"--batch\r\nContent-Type: multipart/mixed; boundary=changeset\r\n\r\n"]
        endpoint = f"http://127.0.0.1:{self.ports['table']}/{ACCOUNT}/Benchmark"
        for row in ("left", "right"):
            batch.extend((
                b"--changeset\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n",
                f"POST {endpoint} HTTP/1.1\r\n".encode("ascii"),
                b"Content-Type: application/json\r\nPrefer: return-no-content\r\n\r\n",
                entity(row), b"\r\n",
            ))
        batch.append(b"--changeset--\r\n--batch--\r\n")
        response = self.call("table", "POST", "/$batch", 202, op="batch",
                             headers={"Content-Type": "multipart/mixed; boundary=batch"},
                             body=b"".join(batch))
        statuses = [line.split()[1] for line in response.splitlines() if line.startswith(b"HTTP/1.1 ")]
        expected = {"single": "single", "left": "left", "right": "right"}
        require(statuses == [b"204", b"204"] and rows() == expected,
                "Table changeset did not commit both entities")
        for row in expected:
            self.call("table", "DELETE", f"/Benchmark(PartitionKey='p',RowKey='{row}')", 204,
                      headers={"If-Match": "*"})


BLOB_TYPE = {"x-ms-blob-type": "BlockBlob"}
TABLE_JSON = {"Content-Type": "application/json", "Prefer": "return-no-content"}
