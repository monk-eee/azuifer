#!/usr/bin/env python3
"""Official-SDK checks of TLS and OAuth bearer authentication against Azuifer.

Requires the Azure SDKs and nothing else (no Azure account, no `az login`):

    pip install azure-storage-blob azure-storage-queue azure-data-tables azure-storage-file-share requests
    python tests/tls_auth_sdk.py [--binary target/debug/azuifer]

The script starts the built binary itself, with a generated development certificate
(`--tls-generate`) and reduced-validation bearer tokens (`--oauth basic`). Azure SDKs
refuse bearer tokens over plain HTTP, so every call here runs over TLS with the
generated certificate as the trusted CA (`connection_verify`). The credential is a
hand-built `TokenCredential` that returns an unsigned JWT, the same shape Azurite's
`--oauth basic` mode accepts. The Blob checks include a user-delegation SAS: Get User
Delegation Key with the bearer token, a SAS signed by the SDK with that key, and use
of the SAS without any other credential.

Azure Data Lake's SDK derives its Blob endpoint by rewriting `.dfs.` in the host name,
so it cannot address path-style local endpoints; DFS bearer access is covered by
`cargo test --test tls_auth_http` instead.

The script exits non-zero if any check fails. It is a manual compatibility run, not
part of `cargo test`.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

import requests
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.data.tables import TableServiceClient
from azure.storage.blob import (
    BlobClient,
    BlobSasPermissions,
    BlobServiceClient,
    ContainerClient,
    ContainerSasPermissions,
    generate_blob_sas,
    generate_container_sas,
)
from azure.storage.fileshare import ShareServiceClient
from azure.storage.queue import QueueServiceClient

ACCOUNT = "devstoreaccount1"
STORAGE = "https://storage.azure.com"
ISSUER = "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/"
OID = "11111111-2222-3333-4444-555555555555"
TID = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class UnsignedJwtCredential:
    """A `TokenCredential` that returns a hand-built, unsigned JWT."""

    def __init__(self, lifetime=3600, audience=STORAGE, issuer=ISSUER):
        self.lifetime, self.audience, self.issuer = lifetime, audience, issuer
        self.requests = 0

    def get_token(self, *scopes, **kwargs):
        self.requests += 1
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "nbf": now - 60,
            "exp": now + self.lifetime,
            "oid": OID,
            "tid": TID,
        }
        token = f"{b64(json.dumps({'alg': 'none', 'typ': 'JWT'}))}.{b64(json.dumps(claims))}."
        return AccessToken(token, now + self.lifetime)


class Server:
    def __init__(self, binary, *extra):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("AZUIFER_")}
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--in-memory"]
        command += ["--skip-api-version-check", *extra, "--shutdown-on-stdin-eof"]
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True
        )
        self.urls, self.ca = {}, None
        for line in self.process.stdout:
            name, _, value = line.strip().partition("=")
            if name == "tls_cert":
                self.ca = value
            elif name.endswith("_url"):
                self.urls[name[: -len("_url")]] = value
            if name == "admin_url":
                break
        threading.Thread(target=lambda: [None for _ in self.process.stdout], daemon=True).start()
        if "blob" not in self.urls:
            raise RuntimeError("server did not report its listeners")

    def endpoint(self, service):
        return f"{self.urls[service]}/{ACCOUNT}"

    def stop(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


CHECKS = []


def check(function):
    CHECKS.append(function)
    return function


def code(error):
    return error.response.headers.get("x-ms-error-code")


def blob_service(ctx, credential=None):
    return BlobServiceClient(
        ctx.server.endpoint("blob"),
        credential=credential or ctx.credential,
        connection_verify=ctx.server.ca,
    )


@check
def generated_certificate_is_trusted_and_served_on_every_listener(ctx):
    assert ctx.server.urls["blob"].startswith("https://")
    for service in ("blob", "queue", "table", "file"):
        assert ctx.server.urls[service].startswith("https://"), service
        response = requests.get(ctx.server.urls[service], verify=ctx.server.ca, timeout=10)
        assert response.status_code in (400, 403, 404), (service, response.status_code)
    try:
        requests.get(ctx.server.urls["blob"], timeout=10)
    except requests.exceptions.SSLError:
        pass
    else:
        raise AssertionError("the certificate must not be trusted by default")


@check
def blob_data_plane_with_a_bearer_token(ctx):
    service = blob_service(ctx)
    name = "bearer" + uuid.uuid4().hex[:8]
    container = service.create_container(name)
    blob = container.get_blob_client("hello.txt")
    blob.upload_blob(b"hello from a bearer token", overwrite=True)
    assert blob.download_blob().readall() == b"hello from a bearer token"
    assert [b.name for b in container.list_blobs()] == ["hello.txt"]
    assert name in [c.name for c in service.list_containers()]
    assert ctx.credential.requests >= 1
    container.delete_container()


@check
def user_delegation_sas_signed_with_a_delegation_key(ctx):
    service = blob_service(ctx)
    name = "delegated" + uuid.uuid4().hex[:8]
    container = service.create_container(name)
    container.get_blob_client("a.txt").upload_blob(b"delegated bytes", overwrite=True)
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    expiry = datetime.now(timezone.utc) + timedelta(hours=2)
    key = service.get_user_delegation_key(start, expiry)
    assert key.signed_oid == OID and key.signed_tid == TID and key.signed_service == "b"
    assert len(base64.b64decode(key.value)) == 32

    token = generate_blob_sas(
        account_name=ACCOUNT,
        container_name=name,
        blob_name="a.txt",
        user_delegation_key=key,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    url = f"{ctx.server.endpoint('blob')}/{name}/a.txt?{token}"
    assert requests.get(url, verify=ctx.server.ca, timeout=10).content == b"delegated bytes"
    sas_client = BlobClient.from_blob_url(url, connection_verify=ctx.server.ca)
    assert sas_client.download_blob().readall() == b"delegated bytes"

    try:
        sas_client.upload_blob(b"not allowed", overwrite=True)
    except HttpResponseError as error:
        assert error.status_code == 403 and code(error) == "AuthorizationPermissionMismatch"
    else:
        raise AssertionError("a read-only user-delegation SAS must not write")
    forged = requests.get(url.replace("sp=r", "sp=rw"), verify=ctx.server.ca, timeout=10)
    assert forged.status_code == 403 and forged.headers["x-ms-error-code"] == "AuthenticationFailed"

    container_token = generate_container_sas(
        account_name=ACCOUNT,
        container_name=name,
        user_delegation_key=key,
        permission=ContainerSasPermissions(read=True, list=True, write=True),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    scoped = ContainerClient.from_container_url(
        f"{ctx.server.endpoint('blob')}/{name}?{container_token}", connection_verify=ctx.server.ca
    )
    assert [b.name for b in scoped.list_blobs()] == ["a.txt"]
    scoped.get_blob_client("b.txt").upload_blob(b"written with the SAS")
    container.delete_container()


@check
def queue_data_plane_with_a_bearer_token(ctx):
    service = QueueServiceClient(
        ctx.server.endpoint("queue"), credential=ctx.credential, connection_verify=ctx.server.ca
    )
    name = "bearer" + uuid.uuid4().hex[:8]
    queue = service.create_queue(name)
    queue.send_message("hello queue")
    assert [m.content for m in queue.receive_messages()] == ["hello queue"]
    assert name in [q.name for q in service.list_queues()]
    queue.delete_queue()


@check
def table_data_plane_with_a_bearer_token(ctx):
    service = TableServiceClient(
        ctx.server.endpoint("table"), credential=ctx.credential, connection_verify=ctx.server.ca
    )
    name = "bearer" + uuid.uuid4().hex[:8]
    table = service.create_table(name)
    table.create_entity({"PartitionKey": "p", "RowKey": "r", "value": 7})
    assert table.get_entity("p", "r")["value"] == 7
    assert name in [t.name for t in service.list_tables()]
    service.delete_table(name)


@check
def file_share_data_plane_with_a_bearer_token(ctx):
    service = ShareServiceClient(
        ctx.server.endpoint("file"),
        credential=ctx.credential,
        token_intent="backup",
        connection_verify=ctx.server.ca,
    )
    name = "bearer" + uuid.uuid4().hex[:8]
    share = service.create_share(name)
    file = share.get_file_client("a.txt")
    file.upload_file(b"hello share")
    assert file.download_file().readall() == b"hello share"
    assert name in [s.name for s in service.list_shares()]
    share.delete_share()


@check
def invalid_tokens_fail_with_the_azure_error(ctx):
    bad = {
        "expired": UnsignedJwtCredential(lifetime=-7200),
        "wrong audience": UnsignedJwtCredential(audience="https://other.example"),
        "foreign issuer": UnsignedJwtCredential(issuer="https://issuer.example/tenant/"),
    }
    for name, credential in bad.items():
        try:
            blob_service(ctx, credential).get_service_properties()
        except ClientAuthenticationError as error:
            assert error.status_code == 401, name
            assert code(error) == "InvalidAuthenticationInfo", name
            assert error.response.headers["www-authenticate"].startswith("Bearer "), name
        else:
            raise AssertionError(f"{name} token was accepted")


@check
def sdk_refuses_bearer_tokens_over_plain_http(ctx):
    plain = ctx.server.endpoint("blob").replace("https://", "http://")
    try:
        BlobServiceClient(plain, credential=ctx.credential).get_service_properties()
    except ValueError as error:
        assert "HTTPS" in str(error)
    else:
        raise AssertionError("the SDK sent a bearer token over HTTP")


@check
def bearer_is_rejected_when_oauth_is_off(ctx):
    server = Server(ctx.binary, "--tls-generate")
    try:
        service = BlobServiceClient(
            server.endpoint("blob"), credential=ctx.credential, connection_verify=server.ca
        )
        try:
            service.get_service_properties()
        except ClientAuthenticationError as error:
            assert error.status_code == 401 and code(error) == "InvalidAuthenticationInfo"
        else:
            raise AssertionError("bearer must be rejected when --oauth is off")
    finally:
        server.stop()


class Context:
    def __init__(self, server, binary):
        self.server = server
        self.binary = binary
        self.credential = UnsignedJwtCredential()


def main():
    parser = argparse.ArgumentParser()
    default = os.path.join(os.path.dirname(__file__), "..", "target", "debug", "azuifer")
    parser.add_argument("--binary", default=default + (".exe" if os.name == "nt" else ""))
    args = parser.parse_args()
    server = Server(args.binary, "--tls-generate", "--oauth", "basic")
    ctx = Context(server, args.binary)
    failures = 0
    try:
        for function in CHECKS:
            try:
                function(ctx)
                print(f"PASS {function.__name__}")
            except Exception:
                failures += 1
                print(f"FAIL {function.__name__}")
                traceback.print_exc()
    finally:
        server.stop()
    print(f"{len(CHECKS) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
