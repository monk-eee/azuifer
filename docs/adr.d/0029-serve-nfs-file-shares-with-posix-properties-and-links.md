# ADR-0029: Serve NFS file shares: POSIX properties, hard links, and symbolic links

- **Status:** Proposed

## Context

Azure Files has two protocols per share. An SMB share (the only kind Azuifer served) has SMB attributes, security descriptors and timestamps. An NFS share (premium accounts in Azure) has POSIX properties and links instead. The FileREST API reaches NFS shares from API version 2025-05-05: `x-ms-enabled-protocols: NFS` on Create Share (older, 2019-07-07), `x-ms-mode`, `x-ms-owner` and `x-ms-group` on files and directories, `x-ms-link-count`, `x-ms-file-file-type`, Create Hard Link (`restype=hardlink`) and, from 2025-07-05, Create Symbolic Link and Read Symbolic Link (`restype=symboliclink`). The official SDKs expose them: Python `azure-storage-file-share` 12.21 (hard links) and 12.22 (symbolic links), .NET 12.22 and 12.23, JavaScript 12.27 and 12.28, Java 12.26 and 12.27, Go 1.5.1 and 1.5.2.

Azuifer refused NFS shares (`501` on `x-ms-enabled-protocols: NFS`), reported every share as `SMB`, answered `501` for the three link operations, and routed them on `comp=hardlink` and `comp=symboliclink`. Azure uses `restype=`, so that route could never match a real request. It had no POSIX properties, no file type and no way for two names to share one file.

This ADR records the survey of Microsoft Learn that the design rests on, the design, the work and its order, and what is still a guess. Nothing here is recorded from Azure; the unverified points are listed at the end so a live recording can settle them.

### What Azure documents (sources: the Learn REST pages for each operation, `file-service-error-codes`, `version-2025-05-05`, `version-2025-07-05`, `files-nfs-protocol`)

- **Protocol availability.** SMB and NFS both: List Shares, Create/Delete/Get/Set Share Properties, Get/Set Share Metadata, Snapshot Share, Restore Share, Get Share Stats, Lease Share, Create/Get/Set Directory Properties, Delete Directory, Get/Set Directory Metadata, List Directories and Files, Create File, Get File, Get/Set File Properties, Get/Set File Metadata, Delete File, Put Range, List Ranges, Copy File, Abort Copy File. SMB only: Get/Set Share ACL, Create/Get Permission, List/Force Close Handles, Rename Directory, Rename File, Lease File. NFS only: Create Hard Link, Create Symbolic Link, Read Symbolic Link.
- **Share.** `x-ms-enabled-protocols` (`SMB` or `NFS`), `x-ms-root-squash` (`NoRootSquash`, `RootSquash`, `AllSquash`; NFS only) and `x-ms-enable-snapshot-virtual-directory-access` (default true) on Create Share; the last two on Set Share Properties. Get Share Properties returns all three; List Shares returns `EnabledProtocols`, and `RootSquash` and `EnableSnapshotVirtualDirectoryAccess` only for NFS.
- **Files and directories.** Request `x-ms-mode` (octal such as `0644` or symbolic such as `rw-r--r--`), `x-ms-owner` and `x-ms-group` (numeric ids) on Create File and Create Directory (defaults file `0644`, directory `0755`, owner and group `0`) and Set File/Directory Properties (an omitted header keeps the value). `x-ms-file-file-type` on Create File must be `Regular`. Responses carry `x-ms-mode`, `x-ms-owner`, `x-ms-group`, and instead of `x-ms-file-attributes` and `x-ms-file-permission-key`: `x-ms-file-file-type` (`Regular`, `Directory`, `Symlink`/`SymLink`) and for files `x-ms-link-count` (Get File, Get File Properties, Set File Properties, Delete File as the new count, Create Hard Link).
- **Listing.** On NFS `<File>` has `FileId`, `Name` and `Properties/Content-Length`; `<Directory>` has `FileId` and `Name`. No attributes, permission key, timestamps or ETag elements.
- **Leases.** `x-ms-lease-id` is ignored on NFS; Lease File is SMB only. Share leases work.
- **Create Hard Link.** `PUT ?restype=hardlink`, required `x-ms-type: file` and `x-ms-file-target-file` (absolute path from the share root, or a full URI, at most 2 KiB), 201. Errors: 404 `ShareNotFound`, 404 `ParentNotFound`, 404 `ResourceNotFound` (target), 409 `ResourceAlreadyExists`, 400 when the target is not a file, 400 `InvalidQueryParameterValue` on a share snapshot. Owner only.
- **Create Symbolic Link.** `PUT ?restype=symboliclink`, required `x-ms-link-text` (stored as given, percent-encoded, not resolved, target need not exist), optional `x-ms-owner`, `x-ms-group`, metadata and timestamps, no `x-ms-mode`; 201 with `x-ms-file-file-type: SymLink` and no link count. Owner only.
- **Read Symbolic Link.** `GET ?restype=symboliclink`, optional `sharesnapshot`, 200 with `x-ms-link-text`. Owner only.
- **Copy File.** Adds `x-ms-file-mode-copy-mode` and `x-ms-file-owner-copy-mode` (`source` or `override`); `override` needs `x-ms-mode`, or `x-ms-owner` and `x-ms-group`.
- **Errors specific to NFS.** `XNfs4FileTypeUnsupportedException` (400, "The operation isn't supported on the specified NFS file because of its file type") and `XNfs4ShareDeniedException` (403).
- **Not documented anywhere:** what an NFS share answers to an SMB-only operation, what an SMB share answers to an NFS-only operation or header, what an older `x-ms-version` does to an NFS share, whether SMB-only headers are rejected or ignored on NFS, how Get File, Put Range, Copy File and Delete File treat a symbolic link, the default mode of a symbolic link, directory link counts, and the exact link-count arithmetic.

## Decision and scope

### 1. A share has a protocol

`shares` gains `protocol` (`SMB` or `NFS`, default `SMB`), `root_squash` (NULL on SMB) and `snapshot_virtual_directory_access` (default 1). Create Share accepts `x-ms-enabled-protocols` of `SMB` or `NFS` (any case; anything else is `400 InvalidHeaderValue`), `x-ms-root-squash` (valid only with NFS; default `NoRootSquash`) and `x-ms-enable-snapshot-virtual-directory-access`. Set Share Properties accepts the last two on an NFS share. Get Share Properties and List Shares report them as documented. Snapshots copy them. Azure requires a premium account for NFS; Azuifer has no account SKU and accepts NFS on any account. An existing data directory gains the columns when it is opened (`ALTER TABLE ... ADD COLUMN` guarded by `pragma table_info`).

### 2. Nodes carry POSIX properties on NFS shares

`nodes` gains `mode`, `owner`, `grp`, `file_type` and `link_text`. `NodeInfo` gets `nfs: Option<NfsProps>` (`mode`, `owner`, `group`, `kind` of `Regular`, `Directory` or `SymLink`, `link_text`). It is `Some` exactly on NFS-share nodes, so the response builders branch on the node and never ask the share again. `mode` is stored as a number from 0 to 07777, parsed from four-digit octal (leading zeros optional) or nine-character `rwx` with `s`, `S`, `t`, `T`, and rendered as four-digit octal. `owner` and `group` are unsigned 32-bit decimals. Defaults: file `0644`, directory `0755` (and the share root), symbolic link `0777`; owner and group `0`.

On an NFS node the SMB attribute and permission-key headers are not sent, `x-ms-file-file-type` and the POSIX headers are, and the timestamp headers stay (the Learn pages list them). A symbolic link is a node with `file_type = SymLink`, `link_text` set and `length` equal to the byte length of the text.

SMB-only request headers (`x-ms-file-attributes`, `x-ms-file-permission*`, `x-ms-file-change-time`, `x-ms-file-property-semantics`) sent to an NFS share are accepted and ignored, because rejecting what Azure might ignore would break working clients. POSIX headers sent to an SMB share are likewise ignored and the response stays SMB-shaped. `x-ms-file-file-type` other than `Regular` on Create File is `400 InvalidHeaderValue`.

### 3. Hard links share one inode

Every `nodes` row stays the inode and its first name. A new table `links` holds each further name: `(share_id, entry_id, file_id, parent_id, name, key)`, unique on `(share_id, parent_id, key)`, and removed with its inode (`ON DELETE CASCADE`). The one name-lookup function `child` reads `nodes` and then `links`, so every create, copy and link path that already resolves a destination sees both. A looked-up alias returns the inode's `NodeInfo` with its own `parent_id` and `name` and an `entry` marker; `save_node` of an alias updates the inode's properties and never its name or parent. The link count is one plus the number of `links` rows of the inode, computed when the node is read. Deleting a name removes the `links` row; deleting the first name while others exist moves the oldest link's name into the inode row and removes that row, so the content and file id survive; deleting the last name frees the content as today. A directory is empty only if neither `nodes` nor `links` has a child. Listing merges both tables in key order. Share snapshots copy both, with explicit column lists. Quota counts a shared file once because content is keyed by inode.

Rename is SMB only, so NFS names never move and no link rename logic is needed.

### 4. Link operations and their routing

`restype=hardlink` and `restype=symboliclink` route in the `restype` arm (the old `comp` arms are removed). The three operations are no longer "unsupported". They need an NFS share, are owner-only for SAS (the existing `Needs`), and refuse a share snapshot (`400 InvalidQueryParameterValue`, Read Symbolic Link excepted since it documents `sharesnapshot`). Hard links need `x-ms-version` 2025-05-05 or later and symbolic links 2025-07-05; below that the `restype` value is `400 InvalidQueryParameterValue`, as a service that does not know it would answer. The `x-ms-version` that the SAS or header names is the one compared (a SAS request without the header uses `sv`, then the baseline).

- **Create Hard Link:** target resolved within the share (a path, or a URL of this share); `ResourceNotFound`, `ParentNotFound` as documented; target a directory is `400 InvalidHeaderValue`; target a symbolic link is `400 XNfs4FileTypeUnsupportedException`; destination exists is `409 ResourceAlreadyExists`. Reply 201 with ETag, Last-Modified, the three timestamps, `x-ms-file-id`, `x-ms-file-parent-id` (the new name's directory), mode, owner, group, `x-ms-link-count` and `x-ms-file-file-type: Regular`. The link bumps the inode's change time and ETag.
- **Create Symbolic Link:** new node under an existing parent (`ParentNotFound`), `ResourceAlreadyExists`, owner and group from headers, mode `0777`, metadata and timestamps as for a file, link text kept verbatim and bounded to 4096 bytes. Reply 201 with the common headers, POSIX headers and `x-ms-file-file-type: SymLink`.
- **Read Symbolic Link:** `x-ms-link-text`, ETag, Last-Modified; a node that is not a symbolic link is `400 XNfs4FileTypeUnsupportedException`.
- Both link operations answer `x-ms-file-id` (the header every SDK already reads) and not the documented `x-ms-file-file-id`, because the Learn pages disagree with each other and the Python SDK parses `x-ms-file-id`.

### 5. Existing operations on an NFS share

- **Data operations on a symbolic link** (Get File with a body, Put Range, Put Range From URL, List Ranges, Copy File as source or destination, Create File over it, Set File Properties with a new length) are `400 XNfs4FileTypeUnsupportedException`. Get File Properties, Get/Set Metadata, Set File Properties without a length, and Delete File work on the link itself. The Learn pages say nothing about these cases; the error is the documented NFS file-type error and the choice is flagged.
- **Delete File** adds `x-ms-link-count` (the count after the delete) on NFS.
- **Copy File** accepts the two copy-mode headers; omitted means `source` for both. A symbolic-link source is refused as above. Copy produces an independent regular file.
- **Set File Properties** with a new length also sets change and last-write time on NFS, as documented.
- **File leases** do not exist on NFS: `x-ms-lease-id` is ignored and no node-level lease check runs.
- **SMB-only operations on an NFS share** (Get/Set Share ACL, Create/Get Permission, List/Force Close Handles, Rename Directory, Rename File, Lease File) answer `403 XNfs4ShareDeniedException`. The code is the only documented NFS denial; the status and code for this case are unverified.
- **List Directories and Files** on an NFS share renders the NFS shape and ignores `include`.
- **Share leases, snapshots, soft delete, metadata and stats** are unchanged; the protocol rides along.

### 6. Version policy

The baseline stays 2023-11-03. NFS needs a newer `x-ms-version`, so SDKs that speak NFS (they send 2026-10-06 today) need `--skip-api-version-check`, as every current SDK already does. NFS share behavior on file and directory operations does not depend on the version; only the link operations are version-gated (section 4). That departs from Azure, which presumably ignores NFS headers below 2025-05-05, and is accepted to avoid inventing three more behaviors.

### Out of scope

The NFS 4.1 wire protocol, mounting, root squash enforcement (the setting is stored and returned, never applied), the `.snapshot` virtual directory (the setting is stored), POSIX permission enforcement (stored, never evaluated, as SMB permissions already are), `GetFileLinks` and file-id addressing (2026 beta), and anything that needs a premium SKU.

## Work breakdown and estimate

| # | Work | Files | Size | Parity target |
|---|------|-------|------|---------------|
| 1 | Schema, migration, share protocol, Create/Get/Set Share, List Shares, snapshot copy | `store/mod.rs`, `shares.rs`, `ops.rs`, `response.rs`, `model.rs` | M | 6 share operations, `files_http`, migration test |
| 2 | POSIX model: `NfsProps`, mode parser/renderer, node columns, defaults | `model.rs`, `store/mod.rs`, `request.rs` | M | unit tests for mode, defaults |
| 3 | Create/Get/Set directory and file, metadata, list shape, SMB-only rejection, lease skip | `store/nodes.rs`, `ops.rs`, `response.rs`, `request.rs` | L | 14 operations |
| 4 | Link table, `child`, delete/promote, empty check, list merge, snapshot copy, link count | `store/mod.rs`, `store/nodes.rs`, `shares.rs` | L | link semantics tests |
| 5 | Create Hard Link, Create/Read Symbolic Link, routing, version gate, errors | `request.rs`, `ops.rs`, `error.rs`, `store/nodes.rs` | M | 3 operations |
| 6 | Copy File modes, symlink refusals, Delete File link count | `store/nodes.rs`, `ops.rs` | S | 4 operations |
| 7 | Tests: unit, HTTP (`tests/files_nfs_http.rs`), persistence and restart, migration, snapshot, SDK script (`tests/files_nfs_sdk.py`), a second SDK, CI job | `tests/`, workflow | L | evidence below |
| 8 | Manifest, compatibility doc, README, evidence report | `specs/conformance/file.json`, `docs/compatibility/` | S | consistency tests |

Operation coverage after this work: all 46 Files operations are classified for NFS. Of those, 3 are new (the links), 12 change shape on NFS, 6 are rejected on NFS, and the rest are unchanged. Nothing becomes `exact`; every NFS operation is `known-difference` because no recording exists.

## Alternatives and consequences

- **Split `nodes` into inodes and entries.** The textbook model, and the right one if names grow more behaviors. It would rewrite every query in `nodes.rs` and the snapshot copy for a case (hard links) that only NFS shares have, and rename (the operation that makes the split worthwhile) is SMB only. The `links` table adds one extra lookup and leaves all SMB behavior untouched.
- **Copy content on link.** A hard link would diverge on the first write, which is wrong for a read-modify-write client such as a build cache.
- **Reject SMB-only headers on NFS shares.** Truer if Azure rejects them, but a client that sends them (a generic tool) would break where Azure possibly ignores them. Ignoring is the cheaper error to be wrong about.
- **A separate `nfs_shares` table or service.** Protocol is one attribute of a share; two tables would duplicate lease, snapshot and quota logic.
- **Version-gate all NFS behavior.** More faithful if Azure does it, but it invents an older-version behavior with no source. Only the link operations, which document a minimum version, are gated.

The costs: link lookups touch a second table on every path resolution; the unverified error choices are visible to clients; `--skip-api-version-check` is required for NFS clients.

## Verification criteria

- **HTTP protocol tests** (`tests/files_nfs_http.rs`) cover, with a running server: create NFS and SMB shares and read the protocol back from Get Share Properties and List Shares; root squash and snapshot-access settings; defaults and explicit mode, owner and group on files and directories in every accepted mode syntax and every rejected one; SMB headers ignored; the NFS listing shape; hard-link creation, shared content, link count and file id, delete in every order including the first name, directory-empty checks, quota counted once; symbolic-link create, read, delete, text kept verbatim, every refused data operation; copy modes; SMB-only operations refused; share snapshots holding links and symbolic links; restart persistence and an old data directory gaining the columns.
- **SDK script** (`tests/files_nfs_sdk.py`) drives the official Python SDK (12.27, default API version) through the same workflow, and a second SDK scenario (.NET or JavaScript) does the same, both run in CI.
- **Unit tests** cover the mode parser and renderer, defaults, and link-count arithmetic in the store.
- **Evidence report** (`docs/compatibility/files-nfs.md`, produced from the SDK script's wire transcript and the test list) shows, per operation, the request, the response and the test that covers it, and lists the unverified points below.
- **Conformance manifest:** the three link operations leave `unsupported`; NFS notes appear on every changed operation; none is `exact`.
- A differential recording against a real premium NFS share is still needed before any of this is called compatible.

## Unverified points to record against Azure

1. Status and code of an SMB-only operation on an NFS share, and of an NFS-only operation or header on an SMB share.
2. Behavior of the NFS operations at an `x-ms-version` below 2025-05-05.
3. Whether SMB-only headers are rejected or ignored on NFS, and POSIX headers on SMB.
4. Get File, Put Range, Copy File, Create File and Set File Properties (length) on a symbolic link; Create Hard Link to a symbolic link or a directory.
5. Default mode of a symbolic link; `x-ms-link-count` of a directory; file-type casing (`Symlink` or `SymLink`) on Get File Properties.
6. Whether a missing parent on Create File and Create Directory is 404 `ParentNotFound` or the 412 the Learn page names.
7. Default `x-ms-file-mode-copy-mode` and `x-ms-file-owner-copy-mode` when omitted.
8. Listing of symbolic links and whether `Content-Length` is the text length.
9. The access-tier and quota fields Azure returns for a premium NFS share.
