# ADR-0031: Check search rights on the directories of a recursive ACL change

- **Status:** Proposed

## Context

Set Access Control Recursive checked that a bearer caller owns each entry it changes and the POSIX rights on the directory the request names, but not the execute right on the directories between that one and a descendant. [Learn](https://learn.microsoft.com/azure/storage/blobs/data-lake-storage-access-control) says execute on a directory is "required to traverse the child items of a directory", and that a principal needs execute on every folder leading to a file. The [Path - Update](https://learn.microsoft.com/rest/api/storageservices/datalakestoragegen2/path/update) page says only that `forceFlag=false` stops "on encountering user errors (4XX)", `forceFlag=true` carries on, and detailed status of user errors is returned in `failedEntries`. It does not say how an unsearchable directory is reported.

## Decision and scope

For a bearer caller (Shared Key, SAS and data-role tokens have no ACL check, as elsewhere), an entry changes only if the caller owns it **and** can search the directory the request names and every directory between it and the entry. An entry that fails either is one failed entry, with the same `errorMessage` as the ownership failure. With `forceFlag=false` the call stops at the first one; with `forceFlag=true` it records each and continues. The directory the request names is judged like any other for ownership; only its search right gates what is below it.

Search rights are read from the ACLs as the call finds them, before it changes them, so a `set` that removes the caller's execute on a directory does not hide that directory's descendants in the same call. A later call sees the new ACL. Group membership is still not known (the token carries none), as for every other check.

## Alternatives and consequences

Reading rights after each change would let a request lock itself out part way through a batch, and make the result depend on batch size. Treating an unsearchable directory as a 4XX that aborts regardless of `forceFlag` would contradict Learn's description of `forceFlag`. The cost is the choices below, which Learn does not settle.

## Not verified against Azure

- That an unreachable entry is a `failedEntries` item rather than being skipped silently or failing the request, and the `errorMessage` text.
- That the rights are judged before the change within one call.
- Whether the directory the request names needs execute for its own children (Azuifer says yes).

## Verification criteria

- A bearer owner of a tree with one directory at mode `0600`: the directory itself changes, everything below it fails, siblings succeed; without `forceFlag` the call stops at the first unreachable entry.
- A `set` that removes the caller's execute right still changes the whole subtree in that call, and the next call cannot reach it.
- Shared Key passes sealed directories, including paths created through Blob (`tests/dfs_cross_http.rs`, `tests/dfs_sdk.py`).
- A recording against real Azure DFS is needed before any of this is `exact`.
