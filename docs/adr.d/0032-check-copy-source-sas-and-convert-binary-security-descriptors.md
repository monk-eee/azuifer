# ADR-0032: Check a copy source's SAS and convert binary security descriptors

- **Status:** Proposed

## Context

Two FileREST gaps were recorded as known differences.

**Source URL SAS.** Copy File and Put Range From URL read a file on this instance and account. A SAS on the `x-ms-copy-source` URL was ignored, so a token that could not read the file still let a copy through. [Copy File](https://learn.microsoft.com/rest/api/storageservices/copy-file) says a source in the same account may be authorized by Shared Key, while a file in another account or any blob needs a SAS, and that a public source needs none. [Put Range From URL](https://learn.microsoft.com/rest/api/storageservices/put-range-from-url) says the source must be public or authorized by a SAS (`x-ms-copy-source-authorization` is bearer-only). Neither page gives the status for a source whose SAS is bad.

**Binary security descriptors.** [Create Permission](https://learn.microsoft.com/rest/api/storageservices/create-permission) and [Get Permission](https://learn.microsoft.com/rest/api/storageservices/get-permission) take and return `format` (`sddl` or `binary`) from 2024-11-04. The Create/Set File and Directory pages document `x-ms-file-permission-format` from 2025-01-05. `binary` is a base64 self-relative descriptor ([MS-DTYP 2.4.6](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)). Azuifer rejected it with `501`.

## Decision

**Source SAS.** When the source URL carries a `sig`, it is verified by the same `verify_sas` the listener uses for its own requests, as a GET of the source file: signature against the source account's keys, expiry and start, `sv`, the resource (`sr=f` for the file, `sr=s` for its share, or an account SAS for the file service), the stored access policy named by `si`, and read permission. Any failure is `403 CannotVerifyCopySource`. A source URL with no `sig` is read with the request's own credentials, as Learn describes for a same-account source. A source in another account is still refused, so the "no SAS needed" branch for another account never arises. The check runs for Copy File and for Put Range From URL.

**Binary descriptors.** `src/files/sd.rs` converts between the base64 binary form and the SDDL text Azuifer stores, so a descriptor has one stored form and one key whichever way it arrived. Only a descriptor with an owner, a group and a DACL of allow or deny entries converts. A SACL, an object, callback or audit ACE, or a control flag outside the four DACL ones is refused, as is any text that does not decode. A descriptor that fails to decode is `400 FileInvalidPermission`; one that decodes but holds an entry the SDDL form cannot carry is `400 CannotConvertToSddlDueToCustomAce`. SDDL aliases are written for the well-known SIDs and rights masks, and a mask with no alias is `0x` hex, so a conversion back and forth is exact.

- Create Permission and Get Permission honor `format` from 2024-11-04. Below that version the body's `format` and the `x-ms-file-permission-format` request header are ignored and Get Permission answers `{"permission"}` only, as before. From 2024-11-04 it answers `{"format", "permission"}`. An unknown format is `400 InvalidInput` in a body and `400 InvalidHeaderValue` in a header.
- Create/Set File and Directory honor `x-ms-file-permission-format` from 2025-01-05, and ignore it below. `binary` converts the `x-ms-file-permission` value, which may not exceed 8 KiB of base64, as for SDDL.

## Alternatives and consequences

Storing the binary form beside the SDDL would double the permission table and let two keys name one descriptor. Skipping a SAS check when the request itself is owner-authorized would repeat today's gap, since Azure's pages tie the source's authorization to the source URL. Both are rejected. The consequence is that a descriptor with a SACL cannot be stored through the binary path even though Azure may accept it.

## Not verified against Azure

- That a bad source SAS is `403 CannotVerifyCopySource` (the code is documented for copy failures; the status is not given for this case). The optional `CopySourceStatusCode`, `CopySourceErrorCode` and `CopySourceErrorMessage` headers (2024-02-04 and later) are not sent.
- Whether a destination authorized by SAS may name a source with no SAS (Azuifer allows it).
- Which binary descriptors Azure accepts and the error for the rest: SACLs, object and callback entries, and the SDDL it would produce are all unknown. The alias spelling and the order in which SDDL flags are written are Azuifer's, not recorded from Azure.
- Applying the 8 KiB header limit to the base64 text, and the gating of `format` by version.
- That `format` in a Create Permission body is ignored, not rejected, below 2024-11-04.

## Verification criteria

- `tests/files_http.rs`: a read SAS on the source passes for both operations; a write-only, expired, tampered, other-file or account-SAS-without-read source is `403 CannotVerifyCopySource` and creates nothing; no SAS on the source still works. Disabling the check fails the test.
- `src/files/sd.rs` unit tests: a known descriptor converts both ways byte for byte; many entries and flags round-trip; descriptors with a SACL, no DACL, an object ACE, bad base64 or truncation are refused.
- `tests/files_http.rs`: Create and Get Permission by version and format, binary and SDDL forms sharing one key, bad descriptors, and the header on Create File.
- `tests/files_sdk.py`: the Python SDK creates a directory from a binary descriptor at 2025-01-05, copies with a read SAS, and is refused with a write-only one. In `azure-storage-file-share` 12.27 the share-level permission calls do not pass `file_permission_format` through, so only the directory and file calls are driven.
- A recording against real Azure Files is needed before either is `exact`.
