"""Drives the official azure-storage-queue SDK against a running Azuifer Queue endpoint.

Usage (start Azuifer with --skip-api-version-check because current SDKs request newer API versions):

    azuifer serve --services queue --queue-port 10001 --in-memory --skip-api-version-check
    pip install azure-storage-queue
    python tests/queue_sdk.py --queue-url http://127.0.0.1:10001

The default account and key are the public devstoreaccount1 development fixture.
"""

import argparse
import base64
import time
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceNotFoundError,
)
from azure.storage.queue import (
    AccessPolicy,
    AccountSasPermissions,
    CorsRule,
    QueueClient,
    QueueSasPermissions,
    QueueServiceClient,
    ResourceTypes,
    RetentionPolicy,
    TextBase64DecodePolicy,
    TextBase64EncodePolicy,
    generate_account_sas,
    generate_queue_sas,
)

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


def expect(error_type, code, action):
    try:
        action()
    except error_type as error:
        check(getattr(error, "error_code", None) == code, f"{code}: got {error!r}")
        return
    raise AssertionError(f"expected {code}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-url", default="http://127.0.0.1:10001")
    parser.add_argument("--account", default=DEV_ACCOUNT)
    parser.add_argument("--key", default=DEV_KEY)
    args = parser.parse_args()
    endpoint = f"{args.queue_url.rstrip('/')}/{args.account}"
    connection = (
        f"DefaultEndpointsProtocol=http;AccountName={args.account};"
        f"AccountKey={args.key};QueueEndpoint={endpoint};"
    )
    suffix = str(int(time.time()))[-6:]
    service = QueueServiceClient.from_connection_string(connection)

    # Queue lifecycle, metadata, and listing.
    name = f"sdk-{suffix}"
    queue = service.create_queue(name, metadata={"Owner": "sdk", "env": "test"})
    props = queue.get_queue_properties()
    check(props.approximate_message_count == 0, "empty queue")
    check(props.metadata.get("owner", props.metadata.get("Owner")) == "sdk", "metadata")
    expect(ResourceExistsError, "QueueAlreadyExists",
           lambda: service.create_queue(name, metadata={"different": "metadata"}))
    try:  # the SDK maps the idempotent 204 to ResourceExistsError
        service.create_queue(name, metadata={"Owner": "sdk", "env": "test"})
        raise AssertionError("expected the SDK to report an existing queue")
    except ResourceExistsError:
        check(True, "idempotent create")
    queue.set_queue_metadata({"updated": "yes"})
    check(list(queue.get_queue_properties().metadata) == ["updated"], "metadata replaced")
    other = service.create_queue(f"sdk-other-{suffix}")
    names = [q.name for q in service.list_queues(name_starts_with="sdk-", include_metadata=True)]
    check(name in names and other.queue_name in names, f"listing {names}")
    paged = list(service.list_queues(name_starts_with="sdk-", results_per_page=1))
    check(len(paged) >= 2, "continuation across pages")

    # Messages: send, receive, peek, update, delete, clear.
    sent = queue.send_message("hello <&> world")
    check(sent.id and sent.pop_receipt, "send response")
    check(sent.expires_on - sent.inserted_on == timedelta(days=7), "default ttl is 7 days")
    peeked = queue.peek_messages(max_messages=5)
    check([m.content for m in peeked] == ["hello <&> world"], "peek content")
    check(peeked[0].dequeue_count == 0, "peek does not dequeue")
    received = list(queue.receive_messages(visibility_timeout=30, max_messages=1))
    check(len(received) == 1 and received[0].dequeue_count == 1, "receive")
    check(not list(queue.receive_messages(max_messages=1)), "invisible while leased")
    updated = queue.update_message(received[0], content="changed", visibility_timeout=0)
    check(updated.pop_receipt != received[0].pop_receipt, "new receipt on update")
    expect(HttpResponseError, "PopReceiptMismatch",
           lambda: queue.delete_message(received[0].id, received[0].pop_receipt))
    again = list(queue.receive_messages(visibility_timeout=30, max_messages=1))
    check(again[0].content == "changed" and again[0].dequeue_count == 2, "updated message")
    queue.delete_message(again[0])
    expect(ResourceNotFoundError, "MessageNotFound", lambda: queue.delete_message(again[0]))
    for n in range(5):
        queue.send_message(f"batch-{n}")
    check(queue.get_queue_properties().approximate_message_count == 5, "count")
    pages = [m.content for m in queue.receive_messages(messages_per_page=2, visibility_timeout=60)]
    check(pages == [f"batch-{n}" for n in range(5)], f"paged receive {pages}")
    queue.clear_messages()
    check(queue.get_queue_properties().approximate_message_count == 0, "cleared")

    # TTL, visibility timeout, and infinite TTL.
    forever = queue.send_message("forever", time_to_live=-1)
    check(forever.expires_on.year == 9999, "infinite ttl")
    queue.clear_messages()
    queue.send_message("delayed", visibility_timeout=1, time_to_live=60)
    check(not queue.peek_messages(), "delayed message invisible")
    time.sleep(1.3)
    check([m.content for m in queue.receive_messages(visibility_timeout=1)] == ["delayed"], "delay")
    queue.clear_messages()
    queue.send_message("short", time_to_live=1)
    time.sleep(2.1)
    check(not queue.peek_messages(), "expired message")
    expect(HttpResponseError, "RequestBodyTooLarge",
           lambda: queue.send_message("x" * (64 * 1024 + 1)))

    # Base64 policies are a client concern; the server stores bytes as sent.
    encoded = QueueClient.from_connection_string(
        connection, name, message_encode_policy=TextBase64EncodePolicy(),
        message_decode_policy=TextBase64DecodePolicy())
    encoded.send_message("päyload ✓")
    raw = queue.peek_messages()[0].content
    check(base64.b64decode(raw).decode() == "päyload ✓", "base64 body stored as sent")
    check(encoded.peek_messages()[0].content == "päyload ✓", "base64 round trip")
    queue.clear_messages()

    # Stored access policies and SAS tokens.
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    queue.set_queue_access_policy({
        "reader": AccessPolicy(
            permission=QueueSasPermissions(read=True),
            start=datetime.now(timezone.utc) - timedelta(minutes=5), expiry=expiry),
    })
    policies = queue.get_queue_access_policy()
    check(list(policies) == ["reader"] and policies["reader"].permission == "r", "acl round trip")
    queue.send_message("for sas")
    service_sas = generate_queue_sas(
        args.account, name, args.key,
        permission=QueueSasPermissions(read=True, add=True, update=True, process=True),
        expiry=expiry)
    sas_queue = QueueClient(endpoint, name, credential=service_sas)
    check([m.content for m in sas_queue.peek_messages()] == ["for sas"], "service SAS peek")
    sas_queue.send_message("added through sas")
    read_only = QueueClient(endpoint, name, credential=generate_queue_sas(
        args.account, name, args.key, permission=QueueSasPermissions(read=True), expiry=expiry))
    expect(HttpResponseError, "AuthorizationPermissionMismatch",
           lambda: read_only.send_message("denied"))
    policy_sas = generate_queue_sas(args.account, name, args.key, policy_id="reader")
    by_policy = QueueClient(endpoint, name, credential=policy_sas)
    check(len(by_policy.peek_messages(max_messages=10)) == 2, "stored policy SAS")
    expired = QueueClient(endpoint, name, credential=generate_queue_sas(
        args.account, name, args.key, permission=QueueSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) - timedelta(hours=1),
        start=datetime.now(timezone.utc) - timedelta(hours=2)))
    expect(HttpResponseError, "AuthenticationFailed", lambda: expired.peek_messages())
    account_sas = generate_account_sas(
        args.account, args.key,
        resource_types=ResourceTypes(service=True, container=True, object=True),
        permission=AccountSasPermissions(read=True, write=True, delete=True, list=True,
                                         add=True, create=True, update=True, process=True),
        expiry=expiry)
    by_account = QueueServiceClient(endpoint, credential=account_sas)
    check(name in [q.name for q in by_account.list_queues()], "account SAS list")
    created = by_account.create_queue(f"sdk-sas-{suffix}")
    created.send_message("account sas")
    by_account.delete_queue(created.queue_name)
    wrong_key = QueueServiceClient(endpoint, credential={"account_name": args.account,
                                                          "account_key": base64.b64encode(b"x" * 32).decode()})
    expect(HttpResponseError, "AuthenticationFailed", lambda: list(wrong_key.list_queues()))

    # Service properties and CORS.
    service.set_service_properties(
        analytics_logging=None,
        hour_metrics=None,
        minute_metrics=None,
        cors=[CorsRule(["http://app.example"], ["GET", "PUT"], allowed_headers=["x-ms-meta-*"],
                       exposed_headers=["x-ms-*"], max_age_in_seconds=60)])
    stored = service.get_service_properties()
    check(len(stored["cors"]) == 1 and stored["cors"][0].max_age_in_seconds == 60, "cors")
    check(stored["hour_metrics"].enabled, "unsent sections unchanged")
    service.set_service_properties(cors=[], hour_metrics=None)
    check(service.get_service_properties()["cors"] == [], "cors cleared")
    check(isinstance(stored["analytics_logging"].retention_policy, RetentionPolicy), "logging")

    # Cleanup and errors against a missing queue.
    service.delete_queue(name)
    service.delete_queue(other.queue_name)
    expect(ResourceNotFoundError, "QueueNotFound", lambda: queue.get_queue_properties())
    expect(ResourceNotFoundError, "QueueNotFound", lambda: queue.send_message("x"))
    print(f"azure-storage-queue SDK: {checks} checks passed")


if __name__ == "__main__":
    main()
