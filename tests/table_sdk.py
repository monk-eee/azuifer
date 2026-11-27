#!/usr/bin/env python3
"""Official-SDK and Azure CLI compatibility checks for the Azuifer Table service.

Requires `pip install azure-data-tables` (and the Azure CLI for the `az` checks).
The script starts the built binary itself:

    python tests/table_sdk.py [--binary target/debug/azuifer] [--skip-az]

It uses the public development account and exits non-zero if any check fails.
This is a manual compatibility run; it is not part of `cargo test`.
"""

import argparse
import datetime
import json
import math
import os
import shutil
import subprocess
import sys
import threading
import traceback
import uuid

from azure.core import MatchConditions
from azure.core.credentials import AzureNamedKeyCredential, AzureSasCredential
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
)
from azure.data.tables import (
    EdmType,
    EntityProperty,
    TableAccessPolicy,
    TableClient,
    TableEntity,
    TableSasPermissions,
    TableServiceClient,
    TableTransactionError,
    UpdateMode,
    generate_account_sas,
    generate_table_sas,
    ResourceTypes,
    AccountSasPermissions,
)

ACCOUNT = "devstoreaccount1"
KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)


class Server:
    def __init__(self, binary, location=None):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("AZUIFER_")}
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--services", "table"]
        command += ["--location", location] if location else ["--in-memory"]
        command.append("--shutdown-on-stdin-eof")
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True
        )
        self.url = None
        for line in self.process.stdout:
            if line.startswith("table_url="):
                self.url = line.strip().split("=", 1)[1]
            if line.startswith("admin_url="):
                break
        threading.Thread(target=lambda: [None for _ in self.process.stdout], daemon=True).start()
        if not self.url:
            raise RuntimeError("server did not report table_url")

    @property
    def endpoint(self):
        return f"{self.url}/{ACCOUNT}"

    @property
    def connection_string(self):
        return (
            f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={KEY};"
            f"TableEndpoint={self.endpoint};"
        )

    def stop(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


CHECKS = []


def code(error):
    """Catalog errors carry their code in the OData envelope, not in a header."""
    header = error.response.headers.get("x-ms-error-code")
    return header if header is not None else json.loads(error.response.text())["odata.error"]["code"]


def check(function):
    CHECKS.append(function)
    return function


def new_table(service, prefix="t"):
    name = prefix + uuid.uuid4().hex[:12]
    return name, service.create_table(name)


@check
def table_lifecycle(ctx):
    service = ctx.service
    name = "life" + uuid.uuid4().hex[:8]
    service.create_table(name)
    try:
        service.create_table(name)
        raise AssertionError("duplicate create should fail")
    except ResourceExistsError as error:
        assert code(error) == "TableAlreadyExists", code(error)
    assert service.create_table_if_not_exists(name).table_name == name
    assert name in [t.name for t in service.list_tables()]
    assert [t.name for t in service.query_tables(f"TableName eq '{name}'")] == [name]
    service.delete_table(name)
    service.delete_table(name)  # the SDK ignores a missing table
    try:
        service.get_table_client(name).create_entity({"PartitionKey": "p", "RowKey": "r"})
        raise AssertionError("writing to a missing table should fail")
    except ResourceNotFoundError as error:
        assert code(error) == "TableNotFound", code(error)
    try:
        service.create_table("bad-name!")
        raise AssertionError("invalid names are rejected")
    except (HttpResponseError, ValueError):
        pass


@check
def table_listing_pages(ctx):
    service = ctx.service
    prefix = "pg" + uuid.uuid4().hex[:6]
    names = [f"{prefix}{i:02d}" for i in range(7)]
    for name in names:
        service.create_table(name)
    listed = [
        t.name
        for page in service.query_tables(f"TableName ge '{prefix}' and TableName lt '{prefix}z'", results_per_page=3).by_page()
        for t in page
    ]
    assert listed == names, listed
    for name in names:
        service.delete_table(name)


@check
def entity_crud_and_etags(ctx):
    name, table = new_table(ctx.service)
    try:
        created = table.create_entity({"PartitionKey": "p", "RowKey": "r", "Name": "one", "Count": 1})
        assert created["etag"], created
        entity = table.get_entity("p", "r")
        assert entity["Name"] == "one" and entity["Count"] == 1
        assert entity.metadata["etag"] == created["etag"]
        assert isinstance(entity["Count"], int)
        try:
            table.create_entity({"PartitionKey": "p", "RowKey": "r"})
            raise AssertionError("duplicate insert should fail")
        except ResourceExistsError as error:
            assert code(error) == "EntityAlreadyExists"
        # Replace removes properties, merge keeps them.
        table.update_entity({"PartitionKey": "p", "RowKey": "r", "Other": "x"}, mode=UpdateMode.MERGE)
        entity = table.get_entity("p", "r")
        assert entity["Name"] == "one" and entity["Other"] == "x"
        table.update_entity({"PartitionKey": "p", "RowKey": "r", "Only": 2}, mode=UpdateMode.REPLACE)
        entity = table.get_entity("p", "r")
        assert "Name" not in entity and entity["Only"] == 2
        # ETag concurrency
        stale = entity.metadata["etag"]
        table.update_entity({"PartitionKey": "p", "RowKey": "r", "Only": 3}, mode=UpdateMode.MERGE)
        try:
            table.update_entity(
                {"PartitionKey": "p", "RowKey": "r", "Only": 4},
                etag=stale,
                match_condition=MatchConditions.IfNotModified,
            )
            raise AssertionError("stale etag should fail")
        except ResourceModifiedError as error:
            assert code(error) == "UpdateConditionNotSatisfied"
        try:
            table.delete_entity("p", "r", etag=stale, match_condition=MatchConditions.IfNotModified)
            raise AssertionError("stale delete should fail")
        except ResourceModifiedError:
            pass
        fresh = table.get_entity("p", "r").metadata["etag"]
        table.delete_entity("p", "r", etag=fresh, match_condition=MatchConditions.IfNotModified)
        try:
            table.get_entity("p", "r")
            raise AssertionError("entity should be gone")
        except ResourceNotFoundError as error:
            assert code(error) == "ResourceNotFound"
        try:
            table.update_entity({"PartitionKey": "p", "RowKey": "r"}, mode=UpdateMode.MERGE)
            raise AssertionError("conditional merge of a missing entity should fail")
        except ResourceNotFoundError:
            pass
        # Upserts create or modify without a condition.
        table.upsert_entity({"PartitionKey": "p", "RowKey": "u", "A": 1}, mode=UpdateMode.MERGE)
        table.upsert_entity({"PartitionKey": "p", "RowKey": "u", "B": 2}, mode=UpdateMode.MERGE)
        entity = table.get_entity("p", "u")
        assert entity["A"] == 1 and entity["B"] == 2
        table.upsert_entity({"PartitionKey": "p", "RowKey": "u", "C": 3}, mode=UpdateMode.REPLACE)
        entity = table.get_entity("p", "u")
        assert "A" not in entity and entity["C"] == 3
        table.delete_entity("p", "u")
        try:
            table.get_entity("p", "u")
            raise AssertionError("deleted")
        except ResourceNotFoundError:
            pass
    finally:
        ctx.service.delete_table(name)


@check
def every_edm_type_round_trips(ctx):
    name, table = new_table(ctx.service)
    try:
        when = datetime.datetime(2013, 8, 22, 1, 12, 6, 260859, tzinfo=datetime.timezone.utc)
        identifier = uuid.uuid4()
        entity = {
            "PartitionKey": "p",
            "RowKey": "types",
            "Text": "héllo 'quoted' wörld",
            "Flag": True,
            "Small": 7,
            "Big": EntityProperty(2**40, EdmType.INT64),
            "Max64": EntityProperty(2**63 - 1, EdmType.INT64),
            "Min64": EntityProperty(-(2**63), EdmType.INT64),
            "Real": 1234.5,
            "Whole": 3.0,
            "NotANumber": float("nan"),
            "Up": float("inf"),
            "Down": float("-inf"),
            "When": when,
            "Id": identifier,
            "Blob": b"\x00\x01\xfe\xff",
            "Empty": "",
            "Int32Min": -(2**31),
            "Int32Max": 2**31 - 1,
        }
        table.create_entity(entity)
        got = table.get_entity("p", "types")
        assert got["Text"] == entity["Text"]
        assert got["Flag"] is True
        assert got["Small"] == 7 and isinstance(got["Small"], int)
        assert got["Big"].value == 2**40 and got["Big"].edm_type == EdmType.INT64
        assert got["Max64"].value == 2**63 - 1 and got["Min64"].value == -(2**63)
        assert got["Real"] == 1234.5 and isinstance(got["Real"], float)
        assert got["Whole"] == 3.0 and isinstance(got["Whole"], float)
        assert math.isnan(got["NotANumber"])
        assert got["Up"] == float("inf") and got["Down"] == float("-inf")
        assert got["When"] == when, (got["When"], when)
        assert got["Id"] == identifier
        assert got["Blob"] == b"\x00\x01\xfe\xff"
        assert got["Empty"] == ""
        assert got["Int32Min"] == -(2**31) and got["Int32Max"] == 2**31 - 1
        assert got.metadata["timestamp"] is not None
    finally:
        ctx.service.delete_table(name)


@check
def queries_filter_select_and_page_across_partitions(ctx):
    name, table = new_table(ctx.service)
    try:
        for part in range(5):
            for row in range(5):
                table.create_entity(
                    {
                        "PartitionKey": f"part{part}",
                        "RowKey": f"row{row:02d}",
                        "N": part * 10 + row,
                        "Even": row % 2 == 0,
                        "Tag": f"t{row}",
                    }
                )
        everything = list(table.list_entities())
        assert len(everything) == 25
        keys = [(e["PartitionKey"], e["RowKey"]) for e in everything]
        assert keys == sorted(keys), "results are ordered by partition then row key"
        paged = [e for page in table.list_entities(results_per_page=4).by_page() for e in page]
        assert [(e["PartitionKey"], e["RowKey"]) for e in paged] == keys
        pages = list(table.list_entities(results_per_page=7).by_page())
        assert [len(list(p)) for p in pages] == [7, 7, 7, 4]
        one = list(table.query_entities("PartitionKey eq 'part2' and N gt 22 and Even eq true"))
        assert [e["N"] for e in one] == [24], one
        ranged = list(table.query_entities("PartitionKey eq 'part1' and RowKey ge 'row02' and RowKey lt 'row04'"))
        assert [e["RowKey"] for e in ranged] == ["row02", "row03"]
        params = list(table.query_entities("N eq @n", parameters={"n": 33}))
        assert [e["PartitionKey"] for e in params] == ["part3"]
        either = list(table.query_entities("(PartitionKey eq 'part0' or PartitionKey eq 'part4') and not (Even eq true)"))
        assert len(either) == 4
        selected = list(table.query_entities("PartitionKey eq 'part0'", select=["Tag", "Missing"]))
        assert len(selected) == 5 and set(selected[0].keys()) == {"Tag", "Missing"}, selected[0]
        assert selected[0]["Missing"] is None
        assert list(table.query_entities("N eq 5L")) == []
        try:
            list(table.query_entities("N eq"))
            raise AssertionError("malformed filters are rejected")
        except HttpResponseError as error:
            assert error.status_code == 400
    finally:
        ctx.service.delete_table(name)


@check
def transactions_are_atomic(ctx):
    name, table = new_table(ctx.service)
    try:
        table.create_entity({"PartitionKey": "p", "RowKey": "exists", "V": 1})
        table.create_entity({"PartitionKey": "p", "RowKey": "gone", "V": 1})
        results = table.submit_transaction(
            [
                ("create", {"PartitionKey": "p", "RowKey": "a", "V": 1}),
                ("upsert", {"PartitionKey": "p", "RowKey": "b", "V": 2}, {"mode": "replace"}),
                ("update", {"PartitionKey": "p", "RowKey": "exists", "V": 9}, {"mode": "merge"}),
                ("delete", {"PartitionKey": "p", "RowKey": "gone"}),
            ]
        )
        assert len(results) == 4
        assert table.get_entity("p", "exists")["V"] == 9
        try:
            table.get_entity("p", "gone")
            raise AssertionError("deleted in the transaction")
        except ResourceNotFoundError:
            pass
        try:
            table.submit_transaction(
                [
                    ("create", {"PartitionKey": "p", "RowKey": "new1"}),
                    ("create", {"PartitionKey": "p", "RowKey": "a"}),
                ]
            )
            raise AssertionError("conflicting transaction must fail")
        except TableTransactionError as error:
            assert error.index == 1, error.index
            assert code(error) == "EntityAlreadyExists", code(error)
        try:
            table.get_entity("p", "new1")
            raise AssertionError("a failed transaction leaves no partial writes")
        except ResourceNotFoundError:
            pass
        try:
            table.submit_transaction(
                [
                    ("create", {"PartitionKey": "p", "RowKey": "x"}),
                    ("create", {"PartitionKey": "q", "RowKey": "y"}),
                ]
            )
            raise AssertionError("cross-partition transaction must fail")
        except (TableTransactionError, HttpResponseError, ValueError):
            pass
        big = [("create", {"PartitionKey": "big", "RowKey": f"r{i:03d}"}) for i in range(100)]
        assert len(table.submit_transaction(big)) == 100
        assert len(list(table.query_entities("PartitionKey eq 'big'"))) == 100
        try:
            table.submit_transaction(big + [("create", {"PartitionKey": "big", "RowKey": "r999"})])
            raise AssertionError("more than 100 operations must fail")
        except (TableTransactionError, HttpResponseError):
            pass
    finally:
        ctx.service.delete_table(name)


@check
def service_sas_and_access_policies(ctx):
    name, table = new_table(ctx.service)
    try:
        table.create_entity({"PartitionKey": "a", "RowKey": "1", "V": 1})
        table.create_entity({"PartitionKey": "b", "RowKey": "1", "V": 2})
        credential = AzureNamedKeyCredential(ACCOUNT, KEY)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        token = generate_table_sas(
            credential,
            name,
            permission=TableSasPermissions(read=True, add=True),
            expiry=expiry,
            start_pk="a",
            end_pk="a",
        )
        client = TableClient(ctx.server.endpoint, name, credential=AzureSasCredential(token))
        assert client.get_entity("a", "1")["V"] == 1
        assert [e["V"] for e in client.list_entities()] == [1], "queries are limited to the signed range"
        client.create_entity({"PartitionKey": "a", "RowKey": "2"})
        for action in (
            lambda: client.get_entity("b", "1"),
            lambda: client.create_entity({"PartitionKey": "b", "RowKey": "9"}),
            lambda: client.delete_entity("a", "2"),
            lambda: client.update_entity({"PartitionKey": "a", "RowKey": "1"}),
        ):
            try:
                action()
                raise AssertionError("SAS should deny this")
            except HttpResponseError as error:
                assert error.status_code == 403, error.status_code
        expired = generate_table_sas(
            credential,
            name,
            permission=TableSasPermissions(read=True),
            expiry=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1),
            start=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1),
        )
        try:
            TableClient(ctx.server.endpoint, name, credential=AzureSasCredential(expired)).get_entity("a", "1")
            raise AssertionError("expired SAS must fail")
        except HttpResponseError as error:
            assert error.status_code == 403
        # Stored access policy
        table.set_table_access_policy(
            {
                "reader": TableAccessPolicy(
                    permission=TableSasPermissions(read=True),
                    expiry=expiry,
                    start=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5),
                )
            }
        )
        policies = table.get_table_access_policy()
        assert list(policies) == ["reader"] and policies["reader"].permission == "r", policies
        policy_token = generate_table_sas(credential, name, policy_id="reader")
        by_policy = TableClient(ctx.server.endpoint, name, credential=AzureSasCredential(policy_token))
        assert by_policy.get_entity("b", "1")["V"] == 2
        try:
            by_policy.create_entity({"PartitionKey": "b", "RowKey": "3"})
            raise AssertionError("policy grants read only")
        except HttpResponseError as error:
            assert error.status_code == 403
        table.set_table_access_policy({})
        try:
            by_policy.get_entity("b", "1")
            raise AssertionError("revoked policy")
        except HttpResponseError as error:
            assert error.status_code == 403
    finally:
        ctx.service.delete_table(name)


@check
def account_sas_and_service_properties(ctx):
    credential = AzureNamedKeyCredential(ACCOUNT, KEY)
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token = generate_account_sas(
        credential,
        resource_types=ResourceTypes(service=True, container=True, object=True),
        permission=AccountSasPermissions(read=True, write=True, delete=True, list=True, add=True, create=True, update=True),
        expiry=expiry,
    )
    service = TableServiceClient(ctx.server.endpoint, credential=AzureSasCredential(token))
    name = "acct" + uuid.uuid4().hex[:8]
    table = service.create_table(name)
    try:
        table.create_entity({"PartitionKey": "p", "RowKey": "r"})
        assert table.get_entity("p", "r")
        assert name in [t.name for t in service.list_tables()]
        properties = service.get_service_properties()
        assert properties["analytics_logging"] is not None
        properties["analytics_logging"].read = True
        properties["hour_metrics"].enabled = False
        service.set_service_properties(
            analytics_logging=properties["analytics_logging"], hour_metrics=properties["hour_metrics"]
        )
        again = ctx.service.get_service_properties()
        assert again["analytics_logging"].read is True
        assert again["hour_metrics"].enabled is False
        assert ctx.service.get_service_stats()["geo_replication"]["status"] == "live"
    finally:
        service.delete_table(name)
    read_only = generate_account_sas(
        credential,
        resource_types=ResourceTypes(object=True),
        permission=AccountSasPermissions(read=True),
        expiry=expiry,
    )
    try:
        TableServiceClient(ctx.server.endpoint, credential=AzureSasCredential(read_only)).create_table("nope" + uuid.uuid4().hex[:6])
        raise AssertionError("a read/object SAS cannot create tables")
    except HttpResponseError as error:
        assert error.status_code == 403


@check
def wrong_key_is_rejected(ctx):
    bad = TableServiceClient(
        ctx.server.endpoint, credential=AzureNamedKeyCredential(ACCOUNT, "AAAA" + KEY[4:])
    )
    try:
        list(bad.list_tables())
        raise AssertionError("a wrong key must fail")
    except HttpResponseError as error:
        assert error.status_code == 403 and code(error) == "AuthenticationFailed"


def az(ctx, *args, expect_ok=True):
    environment = dict(os.environ, AZURE_STORAGE_CONNECTION_STRING=ctx.server.connection_string)
    result = subprocess.run(
        [ctx.az, *args, "--only-show-errors", "-o", "json"],
        capture_output=True,
        text=True,
        env=environment,
        timeout=180,
    )
    if expect_ok and result.returncode != 0:
        raise AssertionError(f"az {' '.join(args)} failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def az_checks(ctx):
    name = "azcli" + uuid.uuid4().hex[:8]
    assert az(ctx, "storage", "table", "create", "-n", name)["created"] is True
    assert az(ctx, "storage", "table", "exists", "-n", name)["exists"] is True
    assert name in [t["name"] for t in az(ctx, "storage", "table", "list")]
    az(ctx, "storage", "entity", "insert", "-t", name, "-e", "PartitionKey=pk", "RowKey=rk", "Name=one", "Count=1")
    shown = az(ctx, "storage", "entity", "show", "-t", name, "--partition-key", "pk", "--row-key", "rk")
    assert shown["Name"] == "one", shown
    az(ctx, "storage", "entity", "merge", "-t", name, "-e", "PartitionKey=pk", "RowKey=rk", "Extra=two")
    az(ctx, "storage", "entity", "replace", "-t", name, "-e", "PartitionKey=pk", "RowKey=r2", "Name=other", expect_ok=False)
    queried = az(ctx, "storage", "entity", "query", "-t", name, "--filter", "PartitionKey eq 'pk'")
    items = queried["items"] if isinstance(queried, dict) else queried
    assert any(item.get("Extra") == "two" and item.get("Name") == "one" for item in items), items
    az(ctx, "storage", "entity", "delete", "-t", name, "--partition-key", "pk", "--row-key", "rk")
    assert az(ctx, "storage", "entity", "query", "-t", name, "--filter", "PartitionKey eq 'pk'")["items"] == []
    az(ctx, "storage", "table", "policy", "create", "-t", name, "-n", "pol", "--permissions", "r", "--expiry", "2099-01-01T00:00Z")
    policies = az(ctx, "storage", "table", "policy", "list", "-t", name)
    assert "pol" in policies, policies
    az(ctx, "storage", "table", "policy", "delete", "-t", name, "-n", "pol")
    assert az(ctx, "storage", "table", "delete", "-n", name)["deleted"] is True
    assert az(ctx, "storage", "table", "exists", "-n", name)["exists"] is False


class Context:
    def __init__(self, server, az_path):
        self.server = server
        self.az = az_path
        self.service = TableServiceClient.from_connection_string(server.connection_string)


def main():
    parser = argparse.ArgumentParser()
    default = os.path.join(os.path.dirname(__file__), "..", "target", "debug", "azuifer")
    parser.add_argument("--binary", default=default + (".exe" if os.name == "nt" else ""))
    parser.add_argument("--skip-az", action="store_true")
    args = parser.parse_args()
    server = Server(args.binary)
    ctx = Context(server, shutil.which("az"))
    failures = 0
    try:
        checks = list(CHECKS)
        if not args.skip_az and ctx.az:
            checks.append(az_checks)
        for function in checks:
            try:
                function(ctx)
                print(f"PASS {function.__name__}")
            except Exception:
                failures += 1
                print(f"FAIL {function.__name__}")
                traceback.print_exc()
    finally:
        server.stop()
    print(f"{len(checks) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
