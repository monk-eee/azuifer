# Azure Storage exchange recording plan

## What this covers

The target is the five Azure Storage REST services at **`2023-11-03`**, using the operations and authorization modes in the [conformance manifests](../../specs/conformance/). The audit includes every recognized operation, including endpoints Azuifer cannot replay yet. The manifest operation names and auth sets match public `main` at `e70ff77`; this plan also includes feature paths such as HNS and the special Blob containers.

| Service | Operations | Advertised operation/auth pairs | Unsupported operations | Journey exchanges | Extra grid exchanges | Target |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Blob | 55 | 303 | 1 | 247 | 244 | 491 |
| DFS | 18 | 106 | 0 | 73 | 86 | 159 |
| FileREST | 44 | 188 | 3 | 90 | 147 | 237 |
| Queue | 17 | 72 | 0 | 43 | 53 | 96 |
| Table | 19 | 72 | 1 | 56 | 53 | 109 |
| **Total** | **153** | **741** | **5** | **509** | **583** | **1,092** |

This is a finite coverage target, not a claim that every possible input is covered. It tests each advertised operation/auth pair once and adds separate exchanges for meaningful branches: conditions, checksums and limits, continuations, post-mutation state, failure atomicity, expiry, feature switches, and shared Blob/DFS state. It does not multiply every branch by every credential. Add a row when an API version, profile, or new variant changes contract behavior. Keep newer-version evidence separate until that version is adopted; a client reaching the emulator through version fallback is not evidence for the newer version. SMB and NFS wire exchanges, control-plane APIs, infrastructure performance, and emulator-only fault injection are out of scope.

## How to count and record

- **Exchange:** one HTTP request and its response projected into a fixture. A later read that proves state is a separate exchange. Unrecorded setup, cleanup, waits and local replays do not count. A batch request is one exchange with multiple projected subresponses.
- **Journey:** one ordered row below. Each semicolon separates measured exchanges. An operation in backticks **at the start of a step** covers one advertised operation/auth pair; `service:operation` credits the other service, `@Auth` overrides the row's auth, and `!` marks a recognized unsupported operation. The same pair can only receive one credit, however often it occurs. Plain-text steps are extra branches or read-backs, not additional credits.
- **Grid:** for every pair in the manifests not credited by a journey, record one safe reference exchange using that operation and credential. Use the same synthetic setup as its primary row. The [audit command](../../scripts/audit-azure-recording-plan.py) lists the exact grid remainder with `--grid`. An approved additional grid recording becomes a one-step row and takes that cell out of the remainder without increasing the target. Where Azure declines an advertised pair, preserve the measured result and classify the difference instead of substituting a different credential.
- **Evidence:** `pending` means no approved recording. A fixture link means the row has real Azure evidence and clean offline replay. Azure-only fixtures with a known emulator difference must be marked `gap` with the fixture and the missing behavior; they count as recorded, not matched. A target/RBAC failure is not a service contract. Leave that row pending and record the prerequisite, not the failure, as its status.

**Target = journey exchanges + uncovered grid cells.** Cross-service journey exchanges count under the journey's service; auth credits belong to the operation's service. From the repository root, run `python scripts/audit-azure-recording-plan.py` with Python 3.10 or later to see current progress. The checker verifies counts, credits, fixture provenance and links. At audit start the library held **11 matched Blob cassettes / 60 exchanges**. The first collection batch adds B-12, B-13, B-14, and B-19: **15 cassettes / 87 exchanges** total, leaving **1,005** to record.

```text
manifest pairs + journeys -> select safe target -> record Azure candidate
     -> review projection -> replay Azuifer -> fix or record the gap
     -> independent live drift checks -> credit the row
```

### Recording profiles

| Profile | Required target and boundaries |
| --- | --- |
| `flat` | Existing opt-in flat Blob test account, HTTPS-only with bearer and user-delegation SAS. Only fresh isolated resources; no changes to account settings or IAM. |
| `keys` | Separately approved disposable account with Shared Key enabled for Shared Key, Shared Key Lite, Account SAS, Service SAS and stored access policies. Use synthetic data and keep keys in memory. Never enable keys on the Entra-only account. |
| `hns` | HNS-enabled account with DFS and Blob endpoints and approved Blob data access. Use an identity permitted to manage POSIX ACLs for ACL journeys, on the new filesystem only. |
| `history` | Separate preconfigured versioning and Blob/container soft-delete profiles. Use a short retention period appropriate for the test account; no customer data. A versioning claim does not follow from a snapshot-only test. |
| `config` | Dedicated account approved for settings isolation and restoration, not the current recorder account. Needed for service properties/CORS, public access, website and singleton containers. Tags and governance use separate approved permissions and feature flags. |
| `copy` | Fresh owned source and destination; use a same-account source first, then an explicitly approved separate source for URL/cross-account behavior. Never fetch existing or arbitrary resources. |
| `geo` | Approved read-access geo-redundant account with healthy secondary endpoints and documented replication state. |
| `files` | Approved pre-provisioned disposable share or account-level control where the operation needs it; FileREST backup-intent permissions where required. `files-history`, `files-handles`, and `files-nfs` additionally require retention/snapshot settings, a disposable source of open handles, or an NFS-capable target, respectively. Do not rely on SMB/NFS wire parity. |
| `queue`, `table` | Approved data-plane scopes for fresh synthetic resources, such as Storage Queue Data Contributor and Storage Table Data Contributor on dedicated targets. Account settings and multirole tests use dedicated accounts/identities. |

The current target covers only `flat` and same-account Blob `copy` when its source authorization is supported. It has no Shared Key, anonymous access, HNS, versioning, or soft delete; it lacks the previously checked Queue, Table, and FileREST write permissions. A separate target or approved scope is required for those rows. This ledger never authorizes granting access or changing settings.

## Pathways

### Blob

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| B-01 | flat | Bearer | `Get User Delegation Key` with a bounded window | 1 | [fixture](../../tests/contracts/cassettes/blob-get-user-delegation-key.json) |
| B-02 | flat | Bearer | Key request missing expiry; key request expiry before start; key request malformed start | 3 | [fixture](../../tests/contracts/cassettes/blob-delegation-key-invalid-windows.json) |
| B-03 | flat | UserDelegationSAS | `Get Blob Properties` with read-only SAS; `Get Blob` byte range; denied DELETE; complete read with unchanged ETag | 4 | [fixture](../../tests/contracts/cassettes/blob-user-delegation-sas-read-only.json) |
| B-04 | flat | UserDelegationSAS | `List Blobs` prefix and delimiter with page limit one; continue using marker; traverse nested prefix; deny read with list-only SAS; deny list with read-only SAS; read nested blob | 6 | [fixture](../../tests/contracts/cassettes/blob-user-delegation-sas-list.json) |
| B-05 | flat | UserDelegationSAS | HEAD with signed header overrides; range GET with overrides; GET without overrides showing stored headers | 3 | [fixture](../../tests/contracts/cassettes/blob-user-delegation-sas-overrides.json) |
| B-06 | flat | Bearer | `Put Blob` seed; reject create-only overwrite; `Get Blob` original; overwrite with current ETag; reject stale write; read replacement | 6 | [fixture](../../tests/contracts/cassettes/blob-conditional-overwrite.json) |
| B-07 | flat | Bearer | `Put Block` first; stage second; deny read before commit; `Put Block List` reversed; read assembled bytes; reject unknown block; read unchanged | 7 | [fixture](../../tests/contracts/cassettes/blob-staged-block-commit.json) |
| B-08 | flat | Bearer | Seed blob; `Lease Blob` acquire; reject missing lease ID; reject wrong ID; read original; write with correct ID; read replacement; release; read unlocked | 9 | [fixture](../../tests/contracts/cassettes/blob-lease-guard.json) |
| B-09 | flat | Bearer | Seed; `Snapshot Blob`; overwrite; reject delete without snapshot option; read snapshot; read replacement; restore via conditional PUT; read restored bytes and metadata | 8 | [fixture](../../tests/contracts/cassettes/blob-snapshot-recovery.json) |
| B-10 | flat | Bearer | Create append blob; `Append Block` at current offset; reject stale position; read original; append at next offset; read in order | 6 | [fixture](../../tests/contracts/cassettes/blob-append-position.json) |
| B-11 | flat | Bearer | Create page blob; `Put Page` second page; read sparse holes; reject wrong sequence; read unchanged; clear page; read zeroes | 7 | [fixture](../../tests/contracts/cassettes/blob-sparse-page-writes.json) |
| B-12 | flat | Bearer | Seed; range GET with MD5; x-ms-range overrides Range with CRC64; open-ended tail GET; reject both checksum flags; reject range past EOF; full read unchanged | 7 | [fixture](../../tests/contracts/cassettes/blob-range-checksums.json) |
| B-13 | flat | Bearer | Seed; `Set Blob Metadata` with matching ETag; `Get Blob Metadata` verifies replacement; reject stale metadata; read metadata unchanged; `Set Blob Properties` conditionally; `Get Blob Properties` verifies new headers and length; read same bytes and new metadata | 8 | [fixture](../../tests/contracts/cassettes/blob-metadata-properties.json) |
| B-14 | flat | Bearer | HEAD with current If-None-Match; GET with stale If-Match; GET with If-Modified-Since; GET with stale If-Unmodified-Since; GET with matching ETag plus range; mixed conditions return 304 | 6 | [fixture](../../tests/contracts/cassettes/blob-conditional-reads.json) |
| B-15 | flat | Bearer | `Create Container`; duplicate create; `Set Container Metadata`; `Get Container Metadata`; `Get Container Properties`; `List Containers` with isolated prefix and page limit; continue list; `Delete Container`; read missing container | 9 | pending |
| B-16 | flat | Bearer | `Get Block List` uncommitted; list committed before commit; commit using committed/uncommitted selectors; list all afterward; reject inconsistent ID lengths; confirm content unchanged | 6 | pending |
| B-17 | flat | Bearer | `Get Page Ranges`; list bounded subrange; reject unaligned page write; `Resize Page Blob`; read truncated extent; grow and read zeroes; `Update Sequence Number` via max; sequence update; sequence increment | 9 | pending |
| B-18 | flat | Bearer | Append with max size; reject oversize append; `Seal Append Blob`; reject append after seal; read sealed state and bytes | 5 | pending |
| B-19 | flat | Bearer | `Delete Blob` with current ETag; read missing; repeat delete; conditionally recreate; delete with stale ETag; read unchanged | 6 | [fixture](../../tests/contracts/cassettes/blob-conditional-delete.json) |
| B-20 | flat | Bearer | Acquire finite lease; renew; change ID; reject old ID; break with delay; reject acquire during break; read broken state; reacquire after expiry; release | 9 | pending |
| B-21 | flat | Bearer | `Lease Container` acquire; reject delete without lease; get leased properties; reject wrong-ID renew; renew correctly; release; delete with no active lease | 7 | pending |
| B-22 | copy | Bearer | `Copy Blob`; inspect copy status; read bytes and metadata; reject source condition; reject destination condition; `Abort Copy Blob` while pending on target that reliably queues; verify aborted destination; reject abort of completed copy | 8 | pending |
| B-23 | copy | Bearer | `Put Blob From URL`; read result; `Put Block From URL`; commit staged block; read committed bytes; `Append Block From URL`; read appended result; `Put Page From URL`; read sparse destination; reject invalid source range | 10 | pending |
| B-24 | copy | Bearer | `Incremental Copy Blob` from a page snapshot; check copy state; update source page; take new snapshot; incremental copy again; get destination page ranges; verify bytes | 7 | pending |
| B-25 | history | Bearer | Write first version; overwrite; list versions with current marker; read first version; delete base without deleting history; read retained version; restore by copy; read restored base | 8 | pending |
| B-26 | history | Bearer | Delete blob with snapshots included; list deleted; read missing; `Undelete Blob`; read current; read restored snapshot; delete snapshots only; confirm base survives | 8 | pending |
| B-27 | history | Bearer | Soft-delete container; list retained containers; `Restore Container`; verify restored properties; read original blob; reject stale restore after replacement | 6 | pending |
| B-28 | config | Bearer | `Set Blob Tags`; `Get Blob Tags`; list with tags; `Find Blobs by Tags` matching a synthetic unique tag; nonmatching condition; deny stale tag condition; verify original tags; find next page | 8 | pending |
| B-29 | flat | Bearer | `Set Blob Tier` on a disposable supported tier; read tier headers; reject incompatible tier/blob kind; read unchanged | 4 | pending |
| B-30 | config | Bearer | `Set Blob Immutability Policy` unlocked; reject prohibited mutation; `Delete Blob Immutability Policy`; `Set Blob Legal Hold` on; reject delete while held; unset hold; delete disposable blob | 7 | pending |
| B-31 | hns | Bearer | `Set Blob Expiry` in approved mode; read expiry header; set malformed expiry; verify old expiry; remove expiry; verify cleared | 6 | pending |
| B-32 | flat | Bearer | `Submit Batch` with successes and independent failure; verify deleted object; verify unaffected object; reject malformed multipart | 4 | pending |
| B-33 | flat | Bearer | `Query Blob Contents` CSV with projection and predicate; JSON projection; Avro progress/end; empty result; malformed query; read original unchanged | 6 | pending |
| B-34 | config | Mixed | `Get Account Information@Bearer`; `Get Blob Service Properties@Bearer`; `Set Blob Service Properties@Bearer` isolated CORS rule; `Preflight Blob Request@Anonymous` allowed; denied origin; denied method; restore original properties; verify restored | 8 | pending |
| B-35 | config | Mixed | `Set Container ACL@Bearer` Blob-level public; `Get Container ACL@Bearer`; `Get Blob@Anonymous`; deny anonymous listing; set container-level public; `List Blobs@Anonymous`; revert to private; deny anonymous read | 8 | pending |
| B-36 | config | Bearer | Create test-only root container; put a singleton-path root blob; read via explicit root path; list root; list dedicated logs container by explicit name; reject invalid system container name | 6 | pending |
| B-37 | config | Anonymous | `Static website request` index; configured 404 page; nested asset; unsupported HTTP method | 4 | pending |
| B-38 | geo | Bearer | `Get Blob Service Stats` on readable secondary | 1 | pending |
| B-39 | flat | UserDelegationSAS | Read in-window; deny expired token; deny future start; read with in-window signed start; read after key expiry under controlled short validity | 5 | pending |
| B-40 | flat | Bearer | !`Rename Container` recognized boundary with a synthetic container (not DFS Rename Path) | 1 | pending |

### DFS and Blob/DFS

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| D-01 | hns | Bearer | `Create File System`; duplicate create; `Set File System Properties`; `Get File System Properties`; `List File Systems` filtered first page; continue; `Delete File System`; read missing | 8 | pending |
| D-02 | hns | Bearer | `Create Path` directory; create file; `Append Data` at zero; `Read File` before flush; `Flush Data` contiguous bytes; read flushed bytes; reject wrong offset or gap; verify unchanged length; append retained tail; flush retained tail | 10 | pending |
| D-03 | hns | Bearer | `List Paths` nonrecursive; recursive first page; resume; `Rename Path` with source and destination guards; old path missing; list new tree; reject target collision; verify no partial move | 8 | pending |
| D-04 | hns | Bearer | Reject Delete Path on nonempty directory; `Delete Path` recursively with continuation; resume; confirm old paths missing; confirm siblings intact | 5 | pending |
| D-05 | hns | Bearer | `Get Access Control`; `Set Access Control` owner/group/mode and named entry; read ACL; create child inheriting a default ACL; read ACL; exercise denied access with approved test identity; reject invalid ACL; verify unchanged | 8 | pending |
| D-06 | hns | Bearer | `Set Access Control Recursive` with bounded page; resume; verify descendant ACL; modify recursive entries; remove recursive entry; verify unaffected path | 6 | pending |
| D-07 | hns | Bearer | `Lease Path` acquire; reject append without lease; allow append with lease; reject rename without lease; release; rename; verify data | 7 | pending |
| D-08 | hns | Bearer | Put Blob via Blob endpoint; DFS read same bytes and ETag; DFS append; DFS flush; Blob read identical state; DFS rename to new prefix; `blob:List Blobs` shows moved objects; reject Blob delete of populated directory; reject Blob write on directory collision; list old prefix empty | 10 | pending |
| D-09 | hns | UserDelegationSAS | Read with directory-scoped SAS; `List Paths` within signed directory; deny outside directory on another synthetic object; deny write with read-only SAS; `Read File` signed read-back | 5 | pending |
| D-10 | hns | Bearer | `Set Path Properties`; `Get Path Properties`; stale condition rejection; byte-range read; reject range past EOF; read unchanged | 6 | pending |

### FileREST

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| F-01 | files | Bearer | `Create Share`; duplicate create; `Set Share Metadata`; `Get Share Metadata`; `Set Share Properties`; `Get Share Properties`; `List Shares` filtered page; continue; `Delete Share`; get missing | 10 | pending |
| F-02 | files + keys | SharedKey | `Set Share ACL`; `Get Share ACL`; update with stale guard; verify unchanged; issue access-policy SAS and read only its test file | 5 | pending |
| F-03 | files + config | SharedKey | `Get File Service Properties`; `Set File Service Properties`; verify updated properties; restore settings | 4 | pending |
| F-04 | files | Bearer | `Create Directory`; `Set Directory Metadata`; `Get Directory Metadata`; `Set Directory Properties`; `Get Directory Properties`; `Rename Directory`; reject nonempty delete; `Delete Directory` after emptying | 8 | pending |
| F-05 | files | Bearer | `Create File` sparse; `Put Range`; `Get File` hole and written bytes; `List Ranges`; clear range; read zeros; `Set File Properties` resize; `Get File Properties` length and attributes; reject invalid range; verify unchanged | 10 | pending |
| F-06 | files | Bearer | `Set File Metadata`; `Get File Metadata`; `Rename File`; old path missing; collision rejected; `Delete File`; read missing | 7 | pending |
| F-07 | files | Bearer | `Create Permission`; `Get Permission`; apply key to disposable file; read stored permission key; `Get Share Stats` after known allocation; reject malformed permission | 6 | pending |
| F-08 | files | Bearer | `Lease Share` acquire; reject missing share lease on delete; release share lease; `Lease File` acquire; reject range write without ID; write with ID; change ID; reject stale ID; release; verify data | 10 | pending |
| F-09 | files | Bearer | `List Directories and Files` with prefix and limit; resume; verify directory/file distinction; list empty directory | 4 | pending |
| F-10 | files + copy | Bearer | `Copy File`; check copy progress; read copied bytes; `Put Range From URL`; verify changed range; reject source condition; `Abort Copy File` while pending; verify aborted status; reject abort when copy completed | 9 | pending |
| F-11 | files-history | Bearer | `Snapshot Share`; overwrite primary file; read snapshot contents; list snapshots; delete with snapshot option; list soft-deleted shares; `Restore Share`; read restored file; reject wrong restore generation | 9 | pending |
| F-12 | files-handles | Bearer | `List Handles` first page; resume; `Force Close Handles` single; close recursive; verify no matching handles remain | 5 | pending |
| F-13 | files-nfs | Bearer | !`Create Hard Link` recognized boundary; !`Create Symbolic Link` recognized boundary; !`Get Symbolic Link` recognized boundary | 3 | pending |

### Queue

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| Q-01 | queue | Bearer | `Create Queue`; repeat create; `Set Queue Metadata`; `Get Queue Metadata`; `List Queues` with prefix and page limit; resume; `Delete Queue`; read missing | 8 | pending |
| Q-02 | queue | Bearer | `Put Message`; `Peek Messages` without receipt; `Get Messages` with receipt and dequeue count; peek hides inflight; `Update Message` rotates receipt; reject stale receipt; `Delete Message` with current receipt; get empty | 8 | pending |
| Q-03 | queue | Bearer | Put delayed message; peek before visibility; get after visibility; get after visibility timeout; verify incremented dequeue count; reject pre-redelivery receipt | 6 | pending |
| Q-04 | queue | Bearer | Put short-TTL message; read while live; read after expiry; reject body over limit; reject invalid visibility; `Clear Messages`; verify queue empty | 7 | pending |
| Q-05 | queue + keys | Mixed | `Set Queue ACL@SharedKey`; `Get Queue ACL@SharedKey`; `Put Message@ServiceSAS` with add scope; `Peek Messages@ServiceSAS` with read scope; deny dequeue with read-only scope; delete ACL policy; policy SAS denied | 7 | pending |
| Q-06 | queue + config | Mixed | `Get Queue Service Properties@Bearer`; `Set Queue Service Properties@Bearer`; `Preflight Queue Request@Anonymous` allowed; denied origin; restore settings; verify restored | 6 | pending |
| Q-07 | queue + geo | Bearer | `Get Queue Service Stats` on readable secondary | 1 | pending |

### Table

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| T-01 | table | Bearer | `Create Table`; repeat create; `Query Tables` first filtered page; continue; `Delete Table`; query missing | 6 | pending |
| T-02 | table | Bearer | `Insert Entity` with generated ETag; duplicate insert; `Query Entities` key lookup; `Merge Entity` with current ETag; read merged; reject stale replace; `Update Entity` replace; read omitted property removed; `Delete Entity` with current ETag; read missing | 10 | pending |
| T-03 | table | Bearer | `Insert Or Merge Entity` missing; merge existing; query retained fields; `Insert Or Replace Entity` missing; replace existing; query dropped field; conditional delete rejects stale | 7 | pending |
| T-04 | table | Bearer | Query typed and null values; select projection; filter PartitionKey and RowKey; OData string escaping; query first page; follow continuation headers; empty result; reject unsupported expression | 8 | pending |
| T-05 | table | Bearer | `Entity Group Transactions` atomic success; read first committed entity; read second committed entity; submit batch with stale ETag; confirm rollback of earlier operation; reject mixed partitions; verify untouched | 7 | pending |
| T-06 | table + keys | Mixed | `Set Table ACL@SharedKey`; `Get Table ACL@SharedKey`; `Query Entities@ServiceSAS` within signed key range; deny another synthetic key outside range; revoke test policy; deny read with revoked policy | 6 | pending |
| T-07 | table | Bearer | `Bearer token authorization` read through a scoped reader; reject write by reader; read unchanged; write by approved contributor | 4 | pending |
| T-08 | table + config | Mixed | `Get Table Service Properties@Bearer`; `Set Table Service Properties@Bearer`; `Preflight Table Request@Anonymous` allowed; denied origin; restore settings; verify restored | 6 | pending |
| T-09 | table + geo | Bearer | `Get Table Service Stats` on readable secondary | 1 | pending |
| T-10 | table | Bearer | !`Atom payloads` legacy media boundary at the pinned version | 1 | pending |

## Collection sequence

| Phase | Action | Can copy from | Effort / dependency |
| --- | --- | --- | --- |
| 1 | Finish the remaining `flat` journeys, starting with B-15 (container lifecycle), B-16 (block-list selectors), B-17 (page ranges and sequences) and B-18 (append sealing). Check bytes, metadata and ETag after failed writes. | `Probe::record` and `mutations::observe` in [the Blob recorder](../../tests/contracts/mutations.rs); `sign_sas` in [the harness](../../tests/contracts/mod.rs) | Medium; existing approved target |
| 2 | For each unlocked profile, add its concrete observe function, typed projection and fixture loader. Use the same request construction for Azure and Azuifer. Seed fresh objects and fail loudly on cleanup errors. | `with_fresh_container` in [the harness](../../tests/contracts/mod.rs); `run_live` and `save` in [the live runner](../../tests/contracts/live.rs); [the Blob listing projection](../../tests/contracts/sas_reads/list.rs) for nested XML | High; approved target and role per profile |
| 3 | Fill uncredited grid cells using the same operation template with the advertised credential. Compare API version, status, selected headers/error, and positive state; do not infer acceptance from another auth mode. | [The auth ADR](../adr.d/0011-compose-authentication-from-shared-primitives.md) for mode boundaries, [local HTTP suites](../../tests/) for input and fixture setup | High; phase 2 and target opt-in for each mode |
| 4 | Rerun reviewed scenarios for every Azuifer update on ordinary CI; run independent Azure drift checks when credentials are available and before adopting a new baseline. A capture candidate never updates an approved fixture automatically. | [Recording guide](azure-contracts.md), [ADR-0005](../adr.d/0005-publish-operation-level-conformance.md), [ADR-0021](../adr.d/0021-publish-one-conformance-manifest-per-service.md) | Medium; preserve fixture immutability and scope |
