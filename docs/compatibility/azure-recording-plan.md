# Azure Storage exchange recording plan

## What this covers

The target is the five Azure Storage REST services, using the operations and authorization modes in the [conformance manifests](../../specs/conformance/). The baseline is **`2023-11-03`** for all reviewed fixtures. The plan also tracks pending feature paths, including HNS, the special Blob containers, and FileREST NFS journeys that need their own newer API versions. The audit includes every recognized operation, including endpoints Azuifer cannot replay yet.

| Service | Operations | Advertised operation/auth pairs | Unsupported operations | Journey exchanges | Extra grid exchanges | Target |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Blob | 55 | 303 | 1 | 256 | 244 | 500 |
| DFS | 18 | 106 | 0 | 117 | 86 | 203 |
| FileREST | 44 | 197 | 0 | 169 | 153 | 322 |
| Queue | 17 | 72 | 0 | 49 | 52 | 101 |
| Table | 19 | 72 | 1 | 65 | 52 | 117 |
| **Total** | **153** | **750** | **2** | **656** | **587** | **1,243** |

This is a finite coverage target, not a claim that every possible input is covered. It tests each advertised operation/auth pair once and adds separate exchanges for meaningful branches: conditions, checksums and limits, continuations, post-mutation state, failure atomicity, expiry, feature switches, and shared Blob/DFS state. It does not multiply every branch by every credential. Add a row when an API version, profile, or new variant changes contract behavior. Keep newer-version evidence separate until that version is adopted; a client reaching the emulator through version fallback is not evidence for the newer version. SMB and NFS wire exchanges, control-plane APIs, infrastructure performance, and emulator-only fault injection are out of scope.

## How to count and record

- **Exchange:** one HTTP request and its response projected into a fixture. A later read that proves state is a separate exchange. Unrecorded setup, cleanup, waits and local replays do not count. A batch request is one exchange with multiple projected subresponses.
- **Journey:** one ordered row below. Each semicolon separates measured exchanges. An operation in backticks **at the start of a step** covers one advertised operation/auth pair; `service:operation` credits the other service, `@Auth` overrides the row's auth, and `!` marks a recognized unsupported operation. The same pair can only receive one credit, however often it occurs. Plain-text steps are extra branches or read-backs, not additional credits.
- **Grid:** for every pair in the manifests not credited by a journey, record one safe reference exchange using that operation and credential. Use the same synthetic setup as its primary row. The [audit command](../../scripts/audit-azure-recording-plan.py) lists the exact grid remainder with `--grid`. An approved additional grid recording becomes a one-step row and takes that cell out of the remainder without increasing the target. Where Azure declines an advertised pair, preserve the measured result and classify the difference instead of substituting a different credential.
- **Evidence:** `pending` means no approved recording. A fixture link means the row has real Azure evidence and clean offline replay. Azure-only fixtures with a known emulator difference must be marked `gap` with the fixture and the missing behavior; they count as recorded, not matched. A target/RBAC failure is not a service contract. It blocks a live run; it does not replace existing evidence or count toward a pending row.

**Target = journey exchanges + uncovered grid cells.** Cross-service journey exchanges count under the journey's service; auth credits belong to the operation's service. From the repository root, run `python scripts/audit-azure-recording-plan.py` with Python 3.10 or later to see current progress. The checker verifies counts, credits, fixture provenance and links. The Batch plan now includes tiering and mixed-operation rejection, and Query includes an in-band conversion-error stream as well as invalid SQL.

After changing the plan, cassettes, wire ledger or manifest auth grid, run
`python scripts/audit-azure-recording-plan.py --write-evidence` to refresh the
manifests' `live_azure_evidence`. The default check rejects stale projections.
`azuifer conformance export --format markdown` shows the full target, separate
recorded and matched totals, and explicit matched operation/auth credits by row.
Plain-text steps still count as exchanges but do not grant an operation/auth credit.

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
| `config` | Dedicated account approved for settings isolation and restoration, not the current recorder account. Needed for service properties/CORS changes, public access, website and singleton containers. Tags and governance use separate approved permissions and feature flags. |
| `config-read` | Existing approved recorder with permission to read service properties and a profile with logging, metrics, and retention disabled and no CORS rules. Only read settings and ACLs on fresh empty resources; do not infer Azure defaults or change live settings. |
| `copy` | Fresh owned source and destination; use a same-account source first, then an explicitly approved separate source for URL/cross-account behavior. Never fetch existing or arbitrary resources. |
| `geo` | Approved read-access geo-redundant account with healthy secondary endpoints and documented replication state. |
| `files` | Approved pre-provisioned disposable share or account-level control where the operation needs it; FileREST backup-intent permissions where required. `files-history`, `files-handles`, and `files-nfs` additionally require retention/snapshot settings, a disposable source of open handles, or an NFS-capable target, respectively. Do not rely on SMB/NFS wire parity. |
| `queue`, `table` | Approved data-plane scopes for fresh synthetic resources, such as Storage Queue Data Contributor and Storage Table Data Contributor on dedicated targets. Queue/table lifecycle and request rejection do not establish message/entity permissions. Account settings and multirole tests use dedicated accounts/identities. |

The current target supports `flat`, same-account Blob `copy` with an authorized synthetic source, and the recorded Queue and Table Bearer journeys. Blob tag writes and reads and FileREST backup writes were denied. Shared Key and anonymous Blob access are disabled; HNS, versioning, and both retention policies are off. Blob, Queue, and Table have no CORS rules. Rows requiring those permissions or settings need a separate approved scope or target. This ledger never authorizes granting access or changing settings.

### Reachability on Entra-only targets

Corporate storage controls (for example Secure Future Initiative restrictions)
can disallow Shared Key and public blob access. This affects what an approved
target can record, not Azuifer's advertised scope or the full **1,243-exchange**
target. The `Auth` and `Profile` columns describe separate prerequisites:

| Requirement | What can be recorded |
| --- | --- |
| Bearer or Blob user-delegation SAS | The matched `flat`, same-account `copy`, and Queue/Table data-plane paths are reachable on the current profile. Blob user-delegation SAS does not need Shared Key. Bearer alone does not grant tag access (B-28), FileREST backup permissions, HNS, history, or geo capabilities. Those paths still need suitable permissions or features. |
| Key-backed auth | SharedKey, SharedKeyLite, AccountSAS, and ServiceSAS need a separately approved `keys` target when the recorder disallows Shared Key. Examples include Q-05, T-06, F-02, F-03, F-14, and F-24 through F-27. `Mixed` rows name the credentials at each step or in the journey; one Bearer step does not unlock the whole row. |
| Anonymous access | Public Blob access and static website scenarios need approved configuration (B-35 and B-37). Unauthenticated CORS preflight is a separate operation: Q-10 and T-14 recorded rule-miss and malformed requests without enabling public access. Successful preflights still need configured CORS. |

Use `--grid` on the audit to see uncovered advertised operation/auth cells
separately from pending journeys. Do not remove blocked cells or count a denial
from the wrong profile as a match.

## Pathways

### Blob

Read-only HEAD checks found neither `$root` nor `$logs` on the current target.
B-36 still needs a disposable singleton profile: neither container was created,
populated, or listed. B-46 isolates the invalid-name rejection without accessing
either singleton or changing account settings.

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
| B-15 | flat | Bearer | `Create Container`; duplicate create; `Set Container Metadata`; `Get Container Metadata`; `Get Container Properties`; `List Containers` with isolated prefix and page limit; continue list; `Delete Container`; read missing container | 9 | [fixture](../../tests/contracts/cassettes/blob-container-lifecycle.json) |
| B-16 | flat | Bearer | `Get Block List` uncommitted; list committed before commit; commit using committed/uncommitted selectors; list all afterward; reject inconsistent ID lengths; confirm content unchanged | 6 | [fixture](../../tests/contracts/cassettes/blob-block-list-selectors.json) |
| B-17 | flat | Bearer | `Get Page Ranges`; list bounded subrange; reject unaligned page write; `Resize Page Blob` to shrink; read truncated extent; `Update Sequence Number` via max on the growth request; read zero-filled growth; sequence update; sequence increment | 9 | [fixture](../../tests/contracts/cassettes/blob-page-resize-sequence.json) |
| B-18 | flat | Bearer | Append with max size; reject oversize append; `Seal Append Blob`; reject append after seal; read sealed state and bytes | 5 | [fixture](../../tests/contracts/cassettes/blob-append-sealing.json) |
| B-19 | flat | Bearer | `Delete Blob` with current ETag; read missing; repeat delete; conditionally recreate; delete with stale ETag; read unchanged | 6 | [fixture](../../tests/contracts/cassettes/blob-conditional-delete.json) |
| B-20 | flat | Bearer | Acquire finite lease; renew; change ID; reject old ID; break with delay; reject acquire during break; read broken state; reacquire after the break period; release | 9 | [fixture](../../tests/contracts/cassettes/blob-finite-lease.json) |
| B-21 | flat | Bearer | `Lease Container` acquire; reject delete without lease; get leased properties; reject wrong-ID renew; renew correctly; release; delete with no active lease | 7 | [fixture](../../tests/contracts/cassettes/blob-container-lease.json) |
| B-22 | copy | Bearer | `Copy Blob` completes within the same account; inspect source, progress and copy ID; read bytes and metadata; reject source condition; reject destination condition; `Abort Copy Blob` on a completed copy returns 409; read unchanged destination | 7 | [fixture](../../tests/contracts/cassettes/blob-completed-copy.json) |
| B-23 | copy | Bearer | `Put Blob From URL`; read result; `Put Block From URL`; commit staged block; read committed bytes; `Append Block From URL`; read appended result; `Put Page From URL`; read sparse destination; reject invalid source range | 10 | [fixture](../../tests/contracts/cassettes/blob-write-from-url.json) |
| B-24 | copy | Bearer | `Incremental Copy Blob` from a page snapshot authorized by UserDelegationSAS; check completed properties; reject GET of the base; update source page; take new snapshot; incremental copy again; diff destination snapshots; verify copied snapshot bytes | 8 | [fixture](../../tests/contracts/cassettes/blob-incremental-copy.json) |
| B-25 | history | Bearer | Write first version; overwrite; list versions with current marker; read first version; delete base without deleting history; read retained version; restore by copy; read restored base | 8 | pending |
| B-26 | history | Bearer | Delete blob with snapshots included; list deleted; read missing; `Undelete Blob`; read current; read restored snapshot; delete snapshots only; confirm base survives | 8 | pending |
| B-27 | history | Bearer | Soft-delete container; list retained containers; `Restore Container`; verify restored properties; read original blob; reject stale restore after replacement | 6 | pending |
| B-28 | config | Bearer | `Set Blob Tags`; `Get Blob Tags`; list with tags; `Find Blobs by Tags` matching a synthetic unique tag; nonmatching condition; deny stale tag condition; verify original tags; find next page | 8 | pending |
| B-29 | flat | Bearer | `Set Blob Tier` to Cool; read explicit tier headers; reject a premium tier on a block blob; read unchanged bytes, metadata and ETag | 4 | [fixture](../../tests/contracts/cassettes/blob-tier.json) |
| B-30 | config | Bearer | `Set Blob Immutability Policy` unlocked; reject prohibited mutation; `Delete Blob Immutability Policy`; `Set Blob Legal Hold` on; reject delete while held; unset hold; delete disposable blob | 7 | pending |
| B-31 | hns | Bearer | `Set Blob Expiry` in approved mode; read expiry header; set malformed expiry; verify old expiry; remove expiry; verify cleared | 6 | pending |
| B-32 | flat | Bearer | `Submit Batch` with two deletes and a missing blob; verify first deleted object; verify second deleted object; batch Set Blob Tier with success and missing blob; read new tier and unchanged bytes and ETag; reject mixed operation types; read unaffected object | 7 | [fixture](../../tests/contracts/cassettes/blob-batch-mixed-results.json) |
| B-33 | flat | Bearer | `Query Blob Contents` CSV with projection and predicate; JSON projection; query all rows and verify Avro progress/end; empty result; read Avro conversion errors with byte offsets; reject invalid SQL; read original unchanged | 7 | [fixture](../../tests/contracts/cassettes/blob-query-avro.json) |
| B-34 | config | Mixed | `Set Blob Service Properties@Bearer` isolated CORS rule; `Preflight Blob Request@Anonymous` allowed; denied origin; denied method; restore original properties; verify restored | 6 | pending |
| B-35 | config | Mixed | `Set Container ACL@Bearer` Blob-level public; `Get Container ACL@Bearer`; `Get Blob@Anonymous`; deny anonymous listing; set container-level public; `List Blobs@Anonymous`; revert to private; deny anonymous read | 8 | pending |
| B-36 | config | Bearer | Create test-only root container; put a singleton-path root blob; read via explicit root path; list root; list dedicated logs container by explicit name | 5 | pending |
| B-37 | config | Anonymous | `Static website request` index; configured 404 page; nested asset; unsupported HTTP method | 4 | pending |
| B-38 | geo | Bearer | `Get Blob Service Stats` on readable secondary | 1 | pending |
| B-39 | flat | UserDelegationSAS | Read in-window; deny expired token; deny future start; read with in-window signed start; deny still-unexpired SAS after the short key expires | 5 | [fixture](../../tests/contracts/cassettes/blob-user-delegation-sas-windows.json) |
| B-40 | flat | Bearer | !`Rename Container` rejected with 400 InvalidQueryParameterValue for `comp=rename` on a synthetic flat container (not DFS Rename Path) | 1 | [fixture](../../tests/contracts/cassettes/blob-container-rename-boundary.json) |
| B-41 | flat | Bearer | `Get Account Information` on StorageV2 Standard_LRS with HNS off; `Get Blob Service Properties` with empty CORS and Blob soft delete and website disabled | 2 | [fixture](../../tests/contracts/cassettes/blob-account-read-only.json) |
| B-42 | flat | Bearer | Reject a container-scoped Submit Batch envelope with zero parts, checking the embedded 400 and its request correlation | 1 | [fixture](../../tests/contracts/cassettes/blob-batch-empty-envelope.json) |
| B-43 | flat | Bearer | Reject malformed Query Blob Contents XML before reading blob data, checking status, code, message and request correlation | 1 | [fixture](../../tests/contracts/cassettes/blob-query-malformed-xml.json) |
| B-44 | flat | Bearer | Reject a truncated container-scoped Submit Batch part before executing subrequests, checking status and request correlation | 1 | [fixture](../../tests/contracts/cassettes/blob-batch-truncated-part.json) |
| B-45 | copy | Bearer | Abort a genuinely pending copy on a target that reliably queues; verify the aborted destination | 2 | pending |
| B-46 | flat | Bearer | Reject a container-properties HEAD on a synthetic invalid dollar-prefixed name | 1 | [fixture](../../tests/contracts/cassettes/blob-invalid-system-container-name.json) |

### DFS and Blob/DFS

Rows D-11 through D-14 track the live verification still owed by
[ADR-0030](../adr.d/0030-read-path-range-checksums-and-create-path-expiry.md).
D-15 tracks [ADR-0031](../adr.d/0031-check-search-rights-in-recursive-acl-changes.md):
use a bearer owner without an ACL-bypassing data role and a separate approved
verifier to read the ACLs on unreachable entries.

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
| D-11 | hns | Bearer | Read File with ranged MD5 and verify it against the returned bytes; give conflicting Range and x-ms-range with MD5; request MD5 without a range; request MD5 on a range over 4 MiB; request a bounded range with CRC64; request both checksums; read with If-Modified-Since; read with If-Unmodified-Since | 8 | pending |
| D-12 | hns | Bearer | Create Path on a file with RelativeToNow; append bytes; flush; read the deadline through Blob HEAD; after the deadline check that DFS cannot read the file; check that Blob cannot read it either; create a file with Absolute expiry; verify the deadline; recreate it with NeverExpire; check that the old deadline is cleared | 10 | pending |
| D-13 | hns | Bearer | Send expiry headers on directory creation; check whether the directory exists; try RelativeToCreation on a file; check the resulting file and deadline if present; send a past Absolute time; send a nonnumeric relative time; combine NeverExpire with a time; send an unknown option; send a time without an option; send an option without a time | 10 | pending |
| D-14 | hns | Bearer | Create a file with a future deadline; rename it; check the old name is gone; read the deadline on the new name through Blob HEAD; read the renamed file before the deadline; after the deadline check DFS visibility; check Blob visibility | 7 | pending |
| D-15 | hns | Bearer | Set Access Control Recursive with `forceFlag=false` on a tree with an intermediate directory at mode `0600` and record the first denial; verify an unvisited sibling's ACL; repeat on an equivalent tree with `forceFlag=true` and record failed entries, diagnostics and continuation; verify a blocked child's ACL; verify a reachable sibling's ACL; recursively set an ACL that removes execute on the requested directory of a fresh tree; verify the child ACL from that same call; repeat with the requested directory now not searchable; check the child's ACL after the repeat | 9 | pending |

### FileREST

F-13 uses `2025-05-05` for hard-link creation and `2025-07-05` for symbolic-link
create/read. F-14 through F-23 track the ten items in the
[NFS evidence report](files-nfs-evidence.md#not-verified-against-azure), in order.
Use approved premium NFS and disposable SMB shares with the required data-plane
permissions. Use `2025-07-05` for the NFS comparisons unless a row explicitly
probes another version. Keep those live recordings separate from the
`2023-11-03` baseline; an emulator response obtained through version fallback
is not evidence that the newer Azure version is implemented.

F-24 through F-27 track [ADR-0032](../adr.d/0032-check-copy-source-sas-and-convert-binary-security-descriptors.md).
Use disposable SMB shares in a separate Shared Key-enabled target. Record
the `2024-02-04` copy diagnostics and the versioned permission calls separately
from the baseline.

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
| F-13 | files-nfs | Bearer | `Create Hard Link` to a regular file; `Create Symbolic Link` with synthetic link text; `Read Symbolic Link` and verify the returned text | 3 | pending |
| F-14 | files-nfs + keys | SharedKey | Try Get Share ACL on NFS; try Rename File on NFS; try Create Hard Link on SMB; try Create Symbolic Link on SMB; try Set Share Properties with x-ms-root-squash on SMB; read the SMB share settings afterward | 6 | pending |
| F-15 | files-nfs | Bearer | Get File Properties on NFS at 2023-11-03; read the same file at 2025-05-05; try Create Hard Link at 2023-11-03; try Create Symbolic Link at 2025-05-05; try Read Symbolic Link at 2025-05-05 on a link seeded at 2025-07-05 | 5 | pending |
| F-16 | files-nfs | Bearer | Create a file with SMB-only attribute and permission headers on NFS; read the resulting NFS properties; create a file with POSIX mode and owner headers on SMB; read the resulting SMB properties | 4 | pending |
| F-17 | files-nfs + copy | Bearer | Try Get File on a symbolic link; Put Range on a fresh link; Put Range From URL with a link as source; Put Range From URL with a link as destination; List Ranges on a link; Copy File from a link; Copy File over a fresh link; Create File over a fresh link; resize a fresh link with Set File Properties; try a hard link to a symbolic link; try a hard link to a directory; read back the symbolic-link target of the attempted hard link | 12 | pending |
| F-18 | files-nfs | Bearer | Create a symbolic link without a mode; Get File Properties for default mode and file-type casing; Get Directory Properties for link-count header presence | 3 | pending |
| F-19 | files-nfs | Bearer | Create File under a missing parent and record status/code; Create Directory under a missing parent and record status/code | 2 | pending |
| F-20 | files-nfs + copy | Bearer | Copy a regular file with distinct POSIX properties without either copy-mode header; read destination mode, owner and group | 2 | pending |
| F-21 | files-nfs | Bearer | List a directory containing a symbolic link and check entry type and length against the synthetic link text; read the link's file properties and compare Content-Length | 2 | pending |
| F-22 | files-nfs | Bearer | Get Share Properties for a premium NFS share and record access-tier and quota fields; list the same share and compare the reported fields | 2 | pending |
| F-23 | files-nfs | Bearer | Create File over one name of a nonempty hard-linked file; read the recreated name and its ID, link count and data; read the sibling name and compare its ID, link count and data | 3 | pending |
| F-24 | files + keys + copy | Mixed | Copy File with a read-only source SAS; read copied bytes; Put Range From URL with a read-only source SAS; verify written range; try Copy File with a write-only source SAS; check for a destination; try Put Range From URL with an expired source SAS; verify destination is unchanged; try Copy File with destination SAS and no source SAS; try Put Range From URL with destination SAS and no source SAS | 10 | pending |
| F-25 | files + keys + copy | SharedKey | Try Copy File with a tampered source SAS at `2024-02-04` and check source error headers and body; check for a destination; try Put Range From URL with an expired source SAS at the same version and check source diagnostics; verify destination is unchanged | 4 | pending |
| F-26 | files + keys (SMB) | SharedKey | Create Permission with a known binary descriptor at `2024-11-04`; Get Permission as binary; get as SDDL and compare alias and flag spelling; create equivalent SDDL and compare the returned key; try malformed binary; try a descriptor with a SACL; try an object ACE; try a callback ACE; try an unknown body format; try an unknown Get Permission header format; send valid SDDL with a binary format label at `2023-11-03`; get that permission at `2023-11-03` and check response fields | 12 | pending |
| F-27 | files + keys (SMB) | SharedKey | Create File with a binary permission header at `2025-01-05`; read the stored permission key; Set File Properties with a different binary permission; read the new key; Create Directory with a binary permission; read the stored key; Set Directory Properties with a different binary permission; read the new key; try a valid binary header at the 8 KiB base64 boundary; try one above the boundary; send SDDL with the binary format header at `2024-11-04`; read that permission back | 12 | pending |

### Queue

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| Q-01 | queue | Bearer | `Create Queue`; repeat create with identical metadata; `Set Queue Metadata`; `Get Queue Metadata`; `List Queues` with prefix, metadata and page limit; resume to a queue with empty metadata; `Delete Queue`; read missing | 8 | [fixture](../../tests/contracts/cassettes/queue-lifecycle.json) |
| Q-02 | queue | Bearer | `Put Message`; `Peek Messages` without receipt; `Get Messages` with receipt and dequeue count; peek hides inflight; `Update Message` rotates receipt; peek updated text; reject stale receipt; `Delete Message` with current receipt; get empty | 9 | [fixture](../../tests/contracts/cassettes/queue-message-receipts.json) |
| Q-03 | queue | Bearer | Put delayed message; peek before visibility; get after visibility; get after visibility timeout; peek the redelivered message and verify dequeue count; reject pre-redelivery receipt | 6 | [fixture](../../tests/contracts/cassettes/queue-message-visibility.json) |
| Q-04 | queue | Bearer | Put short-TTL message; read while live; read after expiry; `Clear Messages` after seeding another message; verify queue empty | 5 | [fixture](../../tests/contracts/cassettes/queue-message-expiration.json) |
| Q-05 | queue + keys | Mixed | `Set Queue ACL@SharedKey`; `Get Queue ACL@SharedKey`; `Put Message@ServiceSAS` with add scope; `Peek Messages@ServiceSAS` with read scope; deny dequeue with read-only scope; delete ACL policy; policy SAS denied | 7 | pending |
| Q-06 | queue + config | Mixed | Read original settings; `Set Queue Service Properties@Bearer`; allow the configured origin; deny a mismatched origin with rules enabled; restore settings; verify restored | 6 | pending |
| Q-07 | queue + geo | Bearer | `Get Queue Service Stats` on readable secondary | 1 | pending |
| Q-08 | queue | Bearer | Reject a Put Message visibility timeout of 604801 seconds and verify echoed bounds | 1 | [fixture](../../tests/contracts/cassettes/queue-put-visibility-limit.json) |
| Q-09 | queue | Bearer | Reject Put Message with 65537 UTF-8 bytes of message text and verify the size limit in the error | 1 | [fixture](../../tests/contracts/cassettes/queue-put-message-size-limit.json) |
| Q-10 | queue + config-read | Mixed | `Get Queue Service Properties@Bearer` with CORS off; `Get Queue ACL@Bearer` on a fresh queue; `Preflight Queue Request@Anonymous` without a matching rule; reject missing request method; reject missing origin | 5 | [fixture](../../tests/contracts/cassettes/queue-read-only-settings.json) |

### Table

| ID | Profile | Auth | Ordered exchanges | Count | Evidence |
| --- | --- | --- | --- | ---: | --- |
| T-01 | table | Bearer | `Create Table` with return-no-content; reject duplicate create; `Query Tables` first filtered page; continue with the same filter; `Delete Table`; read missing; reject repeat delete | 7 | [fixture](../../tests/contracts/cassettes/table-lifecycle.json) |
| T-02 | table | Bearer | `Insert Entity` with generated ETag; duplicate insert; `Query Entities` key lookup; `Merge Entity` with current ETag; read merged; reject stale replace; `Update Entity` replace; read omitted property removed; `Delete Entity` with current ETag; read missing | 10 | [fixture](../../tests/contracts/cassettes/table-entity-lifecycle.json) |
| T-03 | table | Bearer | `Insert Or Merge Entity` missing; merge existing; query retained fields; `Insert Or Replace Entity` missing; replace existing; query dropped field; conditional delete rejects stale | 7 | [fixture](../../tests/contracts/cassettes/table-entity-upsert.json) |
| T-04 | table | Bearer | Query typed and null values; select projection; filter PartitionKey and RowKey; OData string escaping; query first page; follow continuation headers; empty result; reject a syntactically valid unsupported filter function | 8 | [fixture](../../tests/contracts/cassettes/table-entity-query.json) |
| T-05 | table | Bearer | `Entity Group Transactions` atomic success; read first committed entity; read second committed entity; submit batch with stale ETag; confirm rollback of earlier operation; reject mixed partitions; verify untouched | 7 | [fixture](../../tests/contracts/cassettes/table-entity-transactions.json) |
| T-06 | table + keys | Mixed | `Set Table ACL@SharedKey`; `Get Table ACL@SharedKey`; `Query Entities@ServiceSAS` within signed key range; deny another synthetic key outside range; revoke test policy; deny read with revoked policy | 6 | pending |
| T-07 | table | Bearer | `Bearer token authorization` read through a scoped reader; reject write by reader; read unchanged; write by approved contributor | 4 | pending |
| T-08 | table + config | Mixed | Read original settings; `Set Table Service Properties@Bearer`; allow the configured origin; deny a mismatched origin with rules enabled; restore settings; verify restored | 6 | pending |
| T-09 | table + geo | Bearer | `Get Table Service Stats` on readable secondary | 1 | pending |
| T-10 | table | Bearer | !`Atom payloads` reject Query Entities with an Atom Accept header and check the OData XML error | 1 | [fixture](../../tests/contracts/cassettes/table-atom-accept.json) |
| T-11 | table | Bearer | Reject an incomplete Query Entities filter and verify the expression position in the OData JSON error | 1 | [fixture](../../tests/contracts/cassettes/table-incomplete-filter.json) |
| T-12 | table | Bearer | Reject an Atom Insert Entity request body with JSON Accept and check the OData JSON error | 1 | [fixture](../../tests/contracts/cassettes/table-atom-content.json) |
| T-13 | table | Bearer | Reject a Query Entities Atom format override despite JSON Accept and check the OData XML error | 1 | [fixture](../../tests/contracts/cassettes/table-atom-format.json) |
| T-14 | table + config-read | Mixed | `Get Table Service Properties@Bearer` with CORS off; `Get Table ACL@Bearer` on a fresh table with XML Accept; `Preflight Table Request@Anonymous` without a matching rule and with XML Accept; reject missing request method; reject missing origin | 5 | [fixture](../../tests/contracts/cassettes/table-read-only-settings.json) |

## Collection sequence

| Phase | Action | Can copy from | Effort / dependency |
| --- | --- | --- | --- |
| 1 | Finish the remaining `flat` journeys and record same-account copies where supported. Check bytes, metadata and ETag after failed writes. | `Probe::record` and `mutations::observe` in [the Blob recorder](../../tests/contracts/mutations.rs); `sign_sas` in [the harness](../../tests/contracts/mod.rs) | Medium; existing target with approved Blob data-plane writes |
| 2 | For each unlocked profile, add its concrete observe function, typed projection and fixture loader. Use the same request construction for Azure and Azuifer. Seed fresh objects and fail loudly on cleanup errors. | `with_fresh_container` in [the harness](../../tests/contracts/mod.rs); `run_live` and `save` in [the live runner](../../tests/contracts/live.rs); [the Blob listing projection](../../tests/contracts/sas_reads/list.rs) for nested XML | High; approved target and role per profile |
| 3 | Fill uncredited grid cells using the same operation template with the advertised credential. Compare API version, status, selected headers/error, and positive state; do not infer acceptance from another auth mode. | [The auth ADR](../adr.d/0011-compose-authentication-from-shared-primitives.md) for mode boundaries, [local HTTP suites](../../tests/) for input and fixture setup | High; phase 2 and target opt-in for each mode |
| 4 | Rerun reviewed scenarios for every Azuifer update on ordinary CI; run independent Azure drift checks when credentials are available and before adopting a new baseline. A capture candidate never updates an approved fixture automatically. | [Recording guide](azure-contracts.md), [ADR-0005](../adr.d/0005-publish-operation-level-conformance.md), [ADR-0021](../adr.d/0021-publish-one-conformance-manifest-per-service.md) | Medium; preserve fixture immutability and scope |
