# ADR-0009: Serve each service on its own listener

- **Status:** Proposed

## Context

Azuifer targets five REST surfaces whose clients derive different endpoints (`blob`, `queue`, `table`, `dfs`, `file`). Their URI forms, error bodies, and authentication rules differ. The runnable Blob slice has one listener, so the process needs a general way to host several services without coupling their request handling.

## Decision and scope

Each enabled service binds its own listener and mounts its own router. `--services` (also `AZUIFER_SERVICES` and the TOML `services` key) selects a comma-separated subset of `blob,queue,table,dfs,file`; the default is all five. Default ports are 10000 through 10004 in that order, with administration on 10005, and each service has an override (`--queue-port`, `--table-port`, `--dfs-port`, `--file-port`). Enabled ports must be distinct, except that port 0 requests an ephemeral port. When the Blob port is 0, unspecified service ports default to 0 so parallel test processes do not collide. `serve` prints `<service>_url=` for each bound service next to `blob_url` and `admin_url`. Each service exposes one router constructor and owns its parser, error mapping, and storage handle; services do not call each other's handlers. Host-style addressing (`{account}.{service}.localhost`) is an additional route into the same routers, not a separate implementation.

This ADR covers process wiring only. It does not decide authentication (ADR-0011), storage layout (ADR-0010), or TLS.

## Alternatives and consequences

One shared port with path or `Host` dispatch matches fewer client configurations and mixes error formats. Separate processes isolate failures but break the one-binary goal and complicate Blob/DFS sharing. Per-service listeners cost extra ports and a port-conflict check, and every service must tolerate being disabled.

## Verification criteria

- Starting with each single service, and with all five, binds exactly the selected listeners and prints their URLs.
- Configuration validation rejects an unknown service, a duplicate name, and two enabled services on one fixed port.
- A request to a disabled service's default port is refused rather than answered by another service.
- Existing Blob HTTP tests pass unchanged against the multi-service build.
