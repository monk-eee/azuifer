//! The operations FileREST routes to, and what each needs from the caller.

use crate::files::auth::{Level, Needs};

/// Every FileREST operation the router recognises, named as in the Microsoft reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    ListShares,
    GetFileServiceProperties,
    SetFileServiceProperties,
    CreateShare,
    GetShareProperties,
    SetShareProperties,
    GetShareMetadata,
    SetShareMetadata,
    DeleteShare,
    GetShareAcl,
    SetShareAcl,
    GetShareStats,
    LeaseShare,
    SnapshotShare,
    RestoreShare,
    CreatePermission,
    GetPermission,
    CreateDirectory,
    GetDirectoryProperties,
    SetDirectoryProperties,
    GetDirectoryMetadata,
    SetDirectoryMetadata,
    DeleteDirectory,
    ListFilesAndDirectories,
    RenameDirectory,
    ListDirectoryHandles,
    ForceCloseDirectoryHandles,
    CreateFile,
    GetFile,
    GetFileProperties,
    SetFileProperties,
    GetFileMetadata,
    SetFileMetadata,
    DeleteFile,
    PutRange,
    PutRangeFromUrl,
    ListRanges,
    CopyFile,
    AbortCopyFile,
    LeaseFile,
    RenameFile,
    ListFileHandles,
    ForceCloseFileHandles,
    CreateHardLink,
    CreateSymbolicLink,
    GetSymbolicLink,
}

impl Operation {
    /// Every recognised operation, for the conformance manifest consistency test.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 46] = [
        Self::ListShares,
        Self::GetFileServiceProperties,
        Self::SetFileServiceProperties,
        Self::CreateShare,
        Self::GetShareProperties,
        Self::SetShareProperties,
        Self::GetShareMetadata,
        Self::SetShareMetadata,
        Self::DeleteShare,
        Self::GetShareAcl,
        Self::SetShareAcl,
        Self::GetShareStats,
        Self::LeaseShare,
        Self::SnapshotShare,
        Self::RestoreShare,
        Self::CreatePermission,
        Self::GetPermission,
        Self::CreateDirectory,
        Self::GetDirectoryProperties,
        Self::SetDirectoryProperties,
        Self::GetDirectoryMetadata,
        Self::SetDirectoryMetadata,
        Self::DeleteDirectory,
        Self::ListFilesAndDirectories,
        Self::RenameDirectory,
        Self::ListDirectoryHandles,
        Self::ForceCloseDirectoryHandles,
        Self::CreateFile,
        Self::GetFile,
        Self::GetFileProperties,
        Self::SetFileProperties,
        Self::GetFileMetadata,
        Self::SetFileMetadata,
        Self::DeleteFile,
        Self::PutRange,
        Self::PutRangeFromUrl,
        Self::ListRanges,
        Self::CopyFile,
        Self::AbortCopyFile,
        Self::LeaseFile,
        Self::RenameFile,
        Self::ListFileHandles,
        Self::ForceCloseFileHandles,
        Self::CreateHardLink,
        Self::CreateSymbolicLink,
        Self::GetSymbolicLink,
    ];

    /// The operation name in the Microsoft REST reference.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ListShares => "List Shares",
            Self::GetFileServiceProperties => "Get File Service Properties",
            Self::SetFileServiceProperties => "Set File Service Properties",
            Self::CreateShare => "Create Share",
            Self::GetShareProperties => "Get Share Properties",
            Self::SetShareProperties => "Set Share Properties",
            Self::GetShareMetadata => "Get Share Metadata",
            Self::SetShareMetadata => "Set Share Metadata",
            Self::DeleteShare => "Delete Share",
            Self::GetShareAcl => "Get Share ACL",
            Self::SetShareAcl => "Set Share ACL",
            Self::GetShareStats => "Get Share Stats",
            Self::LeaseShare => "Lease Share",
            Self::SnapshotShare => "Snapshot Share",
            Self::RestoreShare => "Restore Share",
            Self::CreatePermission => "Create Permission",
            Self::GetPermission => "Get Permission",
            Self::CreateDirectory => "Create Directory",
            Self::GetDirectoryProperties => "Get Directory Properties",
            Self::SetDirectoryProperties => "Set Directory Properties",
            Self::GetDirectoryMetadata => "Get Directory Metadata",
            Self::SetDirectoryMetadata => "Set Directory Metadata",
            Self::DeleteDirectory => "Delete Directory",
            Self::ListFilesAndDirectories => "List Directories and Files",
            Self::RenameDirectory => "Rename Directory",
            Self::ListDirectoryHandles | Self::ListFileHandles => "List Handles",
            Self::ForceCloseDirectoryHandles | Self::ForceCloseFileHandles => "Force Close Handles",
            Self::CreateFile => "Create File",
            Self::GetFile => "Get File",
            Self::GetFileProperties => "Get File Properties",
            Self::SetFileProperties => "Set File Properties",
            Self::GetFileMetadata => "Get File Metadata",
            Self::SetFileMetadata => "Set File Metadata",
            Self::DeleteFile => "Delete File",
            Self::PutRange => "Put Range",
            Self::PutRangeFromUrl => "Put Range From URL",
            Self::ListRanges => "List Ranges",
            Self::CopyFile => "Copy File",
            Self::AbortCopyFile => "Abort Copy File",
            Self::LeaseFile => "Lease File",
            Self::RenameFile => "Rename File",
            Self::CreateHardLink => "Create Hard Link",
            Self::CreateSymbolicLink => "Create Symbolic Link",
            Self::GetSymbolicLink => "Read Symbolic Link",
        }
    }

    /// The SAS scope and permissions the operation requires.
    pub(in crate::files) fn needs(self) -> Needs {
        let (level, types, account, service) = match self {
            Self::ListShares => (Level::Account, "s", "l", ""),
            Self::CreateShare | Self::RestoreShare => (Level::Share, "c", "cw", ""),
            Self::GetShareProperties
            | Self::GetShareMetadata
            | Self::GetShareAcl
            | Self::GetShareStats
            | Self::GetPermission => (Level::Share, "c", "r", ""),
            Self::SetShareProperties
            | Self::SetShareMetadata
            | Self::SetShareAcl
            | Self::LeaseShare
            | Self::CreatePermission => (Level::Share, "c", "w", ""),
            Self::SnapshotShare => (Level::Share, "c", "cw", ""),
            Self::DeleteShare => (Level::Share, "c", "d", ""),
            Self::CreateDirectory => (Level::Directory, "o", "cw", "cw"),
            Self::GetDirectoryProperties
            | Self::GetDirectoryMetadata
            | Self::ListDirectoryHandles => (Level::Directory, "o", "r", "r"),
            Self::SetDirectoryProperties
            | Self::SetDirectoryMetadata
            | Self::RenameDirectory
            | Self::ForceCloseDirectoryHandles => (Level::Directory, "o", "w", "w"),
            Self::DeleteDirectory => (Level::Directory, "o", "d", "d"),
            Self::ListFilesAndDirectories => (Level::Directory, "co", "l", "l"),
            Self::CreateFile | Self::CopyFile => (Level::File, "o", "cw", "cw"),
            Self::GetFile
            | Self::GetFileProperties
            | Self::GetFileMetadata
            | Self::ListRanges
            | Self::ListFileHandles => (Level::File, "o", "r", "r"),
            Self::SetFileProperties
            | Self::SetFileMetadata
            | Self::PutRange
            | Self::PutRangeFromUrl
            | Self::AbortCopyFile
            | Self::LeaseFile
            | Self::RenameFile
            | Self::ForceCloseFileHandles => (Level::File, "o", "w", "w"),
            Self::DeleteFile => (Level::File, "o", "d", "d"),
            Self::GetFileServiceProperties => (Level::Account, "s", "r", ""),
            Self::SetFileServiceProperties => (Level::Account, "s", "w", ""),
            Self::CreateHardLink | Self::CreateSymbolicLink | Self::GetSymbolicLink => {
                (Level::Account, "s", "", "")
            }
        };
        Needs {
            level,
            resource_types: types,
            account_permissions: account,
            service_permissions: service,
        }
    }
}
