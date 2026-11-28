//! Parses an authenticated DFS request into a typed operation, the SAS permission it
//! needs, and the POSIX rights it needs on the paths it touches.

use super::{
    auth::Authenticated,
    error::DfsError,
    headers::{
        acl_entries, boolean, content_update, creation, expiry, lease_use, posix_mode,
        principal_name, properties, read_range,
    },
    params::{directory_parameter, position, rename_source},
    token::Continuation,
};
use crate::{
    auth::{Query, header},
    blob_auth::Target,
    blob_sas::{Need as SasNeed, Public},
    compat::Relax,
    conditions::{self, Conditions, Guard, STANDARD as CONDITION_HEADERS},
    config::Config,
    domain::{
        AccountName, BlobKey, BlobPath, BlobRead, ContainerKey, ContentHeaders, Error, Metadata,
        PageRequest, Result,
    },
    lease::{LeaseAction, LeaseDuration, LeaseId},
    posix::{Form, PathKind, Perms},
    protocol::{self, UploadOptions},
    store::{
        AccessUpdate, AclMode, Caller, CreatePath, Flush, LeaseUse, Need, PropertyUpdate,
        RecursiveAcl, Rename,
    },
};
use axum::http::{HeaderMap, Method, request::Parts};
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// The largest body of one Append Data request.
pub(super) const MAX_APPEND_BYTES: u64 = 100 * 1024 * 1024;
const MAX_RECORDS: usize = 2000;
pub(super) const DELETE_BATCH: usize = 1000;

const CONDITIONS: &[&str] = &[
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
];
const LEASE: &[&str] = &["x-ms-lease-id"];
const DATES: &[&str] = &["if-modified-since", "if-unmodified-since"];
const LEASE_ACTION: &[&str] = &[
    "x-ms-lease-action",
    "x-ms-lease-duration",
    "x-ms-proposed-lease-id",
    "x-ms-lease-break-period",
];
const CONTENT: &[&str] = &[
    "x-ms-cache-control",
    "x-ms-content-type",
    "x-ms-content-encoding",
    "x-ms-content-language",
    "x-ms-content-disposition",
    "cache-control",
    "content-encoding",
    "content-language",
    "content-disposition",
];
const POSIX: &[&str] = &[
    "x-ms-permissions",
    "x-ms-umask",
    "x-ms-owner",
    "x-ms-group",
    "x-ms-acl",
];
const PROPERTIES: &[&str] = &["x-ms-properties"];
const SOURCE: &[&str] = &[
    "x-ms-rename-source",
    "x-ms-source-lease-id",
    "x-ms-source-if-match",
    "x-ms-source-if-none-match",
    "x-ms-source-if-modified-since",
    "x-ms-source-if-unmodified-since",
];

pub(super) struct ListPaths {
    pub(super) key: ContainerKey,
    pub(super) directory: Option<BlobPath>,
    pub(super) recursive: bool,
    pub(super) page: PageRequest,
}

pub(super) struct AppendRequest {
    pub(super) key: BlobKey,
    pub(super) position: u64,
    pub(super) upload: UploadOptions,
    pub(super) guard: Guard,
    pub(super) lease: LeaseUse,
}

/// Which attributes a HEAD returns besides the common properties.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum View {
    Properties,
    AccessControl,
}

pub(super) enum Operation {
    ListFilesystems(AccountName, PageRequest),
    CreateFilesystem(ContainerKey, Metadata),
    SetFilesystemProperties(ContainerKey, Metadata, Guard),
    FilesystemProperties(ContainerKey),
    DeleteFilesystem(ContainerKey, Guard),
    ListPaths(ListPaths),
    CreatePath(Box<CreatePath>),
    RenamePath(Box<Rename>),
    Append(Box<AppendRequest>),
    Flush(Box<Flush>),
    SetProperties(BlobKey, Guard, PropertyUpdate),
    SetAccess(ContainerKey, Option<BlobPath>, AccessUpdate, Guard),
    SetAccessRecursive(Box<RecursiveAcl>),
    ReadPath(BlobKey, BlobRead),
    PathProperties(ContainerKey, Option<BlobPath>, Guard, View),
    DeletePath {
        key: BlobKey,
        guard: Guard,
        recursive: bool,
        continuation: Option<Continuation>,
    },
    LeasePath(BlobKey, LeaseAction, Conditions),
}

/// A POSIX check on one path; `path` is `None` for the filesystem root.
pub(super) struct Access {
    pub(super) key: ContainerKey,
    pub(super) path: Option<BlobPath>,
    pub(super) need: Need,
}

pub(super) struct Parsed {
    pub(super) operation: Operation,
    pub(super) sas: SasNeed,
    pub(super) access: Vec<Access>,
}

const fn sas(service: Option<&'static str>, account: (char, &'static str)) -> SasNeed {
    SasNeed {
        service,
        account: Some(account),
        public: Public::Never,
    }
}

struct Input<'a> {
    method: &'a Method,
    query: &'a Query,
    headers: &'a HeaderMap,
    config: &'a Config,
    caller: &'a Caller,
    relax: Relax<'a>,
}

pub(super) fn parse(
    parts: &Parts,
    auth: &Authenticated,
    config: &Config,
    caller: &Caller,
    request_id: &str,
) -> std::result::Result<Parsed, DfsError> {
    if !config.hns_accounts.contains(auth.target.account()) {
        return Err(DfsError::NamespaceDisabled);
    }
    // The SDKs send empty lease headers when no lease is involved.
    let mut headers = parts.headers.clone();
    for name in [
        "x-ms-lease-id",
        "x-ms-source-lease-id",
        "x-ms-proposed-lease-id",
    ] {
        if headers.get(name).is_some_and(|value| value.is_empty()) {
            headers.remove(name);
        }
    }
    let input = Input {
        method: &parts.method,
        query: &auth.query,
        headers: &headers,
        config,
        caller,
        relax: Relax::new(&config.compat, "dfs", request_id),
    };
    match &auth.target {
        Target::Account(account) => input.account(account.clone()),
        Target::Container(key) => input.container(key.clone()),
        Target::Blob(key) => input.path(key.clone()),
    }
}

impl Input<'_> {
    fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    fn check(&self, params: &[&str], headers: &[&[&str]]) -> Result<()> {
        protocol::check(
            self.query,
            self.headers,
            params,
            headers,
            false,
            &self.relax,
        )
    }

    /// Most operations carry no body.
    fn bodiless(&self) -> Result<()> {
        if header(self.headers, "content-length")?
            .is_some_and(|length| length.parse::<u64>() != Ok(0))
            || self.headers.contains_key("transfer-encoding")
        {
            return Err(Error::InvalidLength);
        }
        Ok(())
    }

    fn account(&self, account: AccountName) -> std::result::Result<Parsed, DfsError> {
        match (self.method, self.param("resource")) {
            (&Method::GET, Some("account")) => {
                self.bodiless()?;
                self.check(&["resource", "prefix", "continuation", "maxresults"], &[])?;
                let page = PageRequest::parse(
                    self.param("prefix"),
                    self.param("continuation"),
                    self.param("maxresults"),
                )?;
                Ok(Parsed {
                    operation: Operation::ListFilesystems(account, page),
                    sas: sas(None, ('s', "l")),
                    access: Vec::new(),
                })
            }
            _ => Err(Error::Unsupported.into()),
        }
    }

    fn filesystem_parsed(&self, operation: Operation, need: SasNeed) -> Parsed {
        Parsed {
            operation,
            sas: need,
            access: Vec::new(),
        }
    }

    fn container(&self, key: ContainerKey) -> std::result::Result<Parsed, DfsError> {
        self.bodiless()?;
        if let Some(action) = self.param("action") {
            return self.root_action(key, action);
        }
        match (self.method, self.param("resource")) {
            (&Method::GET, Some("filesystem")) => {
                self.check(
                    &[
                        "resource",
                        "directory",
                        "recursive",
                        "continuation",
                        "maxresults",
                        "upn",
                    ],
                    &[],
                )?;
                let recursive =
                    boolean(self.param("recursive"))?.ok_or(DfsError::MissingRecursive)?;
                boolean(self.param("upn"))?;
                let directory = directory_parameter(self.query)?;
                let page =
                    PageRequest::parse(None, self.param("continuation"), self.param("maxresults"))?;
                Ok(Parsed {
                    access: vec![Access {
                        key: key.clone(),
                        path: directory.clone(),
                        need: Need::LIST,
                    }],
                    operation: Operation::ListPaths(ListPaths {
                        key,
                        directory,
                        recursive,
                        page,
                    }),
                    sas: sas(Some("l"), ('c', "l")),
                })
            }
            (&Method::PUT, Some("filesystem")) => {
                self.check(&["resource"], &[PROPERTIES])?;
                let metadata = properties(self.headers)?.unwrap_or_default();
                Ok(self.filesystem_parsed(
                    Operation::CreateFilesystem(key, metadata),
                    sas(None, ('c', "wc")),
                ))
            }
            (&Method::PATCH, Some("filesystem")) => {
                self.check(&["resource"], &[PROPERTIES, DATES])?;
                let metadata = properties(self.headers)?.unwrap_or_default();
                let guard = Guard::parse(self.headers)?;
                Ok(self.filesystem_parsed(
                    Operation::SetFilesystemProperties(key, metadata, guard),
                    sas(Some("w"), ('c', "w")),
                ))
            }
            (&Method::HEAD, Some("filesystem")) => {
                self.check(&["resource"], &[])?;
                Ok(self.filesystem_parsed(
                    Operation::FilesystemProperties(key),
                    sas(Some("r"), ('c', "r")),
                ))
            }
            (&Method::DELETE, Some("filesystem")) => {
                self.check(&["resource"], &[DATES])?;
                let guard = Guard::parse(self.headers)?;
                Ok(self.filesystem_parsed(
                    Operation::DeleteFilesystem(key, guard),
                    sas(Some("d"), ('c', "d")),
                ))
            }
            _ => Err(Error::Unsupported.into()),
        }
    }

    /// ACL operations on the filesystem's root directory.
    fn root_action(
        &self,
        key: ContainerKey,
        action: &str,
    ) -> std::result::Result<Parsed, DfsError> {
        match (self.method, action) {
            (&Method::HEAD, "getAccessControl" | "getStatus" | "getProperties") => {
                self.check(&["action", "upn"], &[CONDITIONS, LEASE])?;
                boolean(self.param("upn"))?;
                Ok(Parsed {
                    access: vec![Access {
                        key: key.clone(),
                        path: None,
                        need: Need::TRAVERSE,
                    }],
                    operation: Operation::PathProperties(
                        key,
                        None,
                        Guard::parse(self.headers)?,
                        View::AccessControl,
                    ),
                    sas: sas(Some("er"), ('c', "r")),
                })
            }
            (&Method::PATCH, "setAccessControl") => {
                let (update, guard) = self.access_update()?;
                Ok(Parsed {
                    access: vec![Access {
                        key: key.clone(),
                        path: None,
                        need: Need::TRAVERSE,
                    }],
                    operation: Operation::SetAccess(key, None, update, guard),
                    sas: sas(Some("op"), ('c', "w")),
                })
            }
            (&Method::PATCH, "setAccessControlRecursive") => self.recursive_acl(key, None),
            _ => Err(Error::Unsupported.into()),
        }
    }

    fn access_update(&self) -> Result<(AccessUpdate, Guard)> {
        self.check(&["action", "upn"], &[CONDITIONS, LEASE, POSIX])?;
        let permissions = posix_mode(self.headers, "x-ms-permissions")?;
        let acl = acl_entries(self.headers, Form::Full)?;
        if permissions.is_some() && acl.is_some() {
            return Err(Error::InvalidHeader);
        }
        Ok((
            AccessUpdate {
                owner: principal_name(self.headers, "x-ms-owner")?,
                group: principal_name(self.headers, "x-ms-group")?,
                permissions,
                acl,
            },
            Guard::parse(self.headers)?,
        ))
    }

    fn recursive_acl(
        &self,
        key: ContainerKey,
        path: Option<BlobPath>,
    ) -> std::result::Result<Parsed, DfsError> {
        self.check(
            &[
                "action",
                "mode",
                "forceflag",
                "maxrecords",
                "continuation",
                "upn",
            ],
            &[POSIX],
        )?;
        let (mode, form) = match self.param("mode") {
            Some("set") => (AclMode::Set, Form::Full),
            Some("modify") => (AclMode::Modify, Form::Full),
            Some("remove") => (AclMode::Remove, Form::Removal),
            Some(_) => return Err(Error::InvalidQuery.into()),
            None => return Err(DfsError::MissingParameter("mode")),
        };
        let entries = acl_entries(self.headers, form)?.ok_or(Error::MissingHeader)?;
        let max_records = match self.param("maxrecords") {
            None => MAX_RECORDS,
            Some(value) => match value.parse::<usize>() {
                Ok(count @ 1..=MAX_RECORDS) => count,
                _ => return Err(Error::InvalidQuery.into()),
            },
        };
        let after = self
            .param("continuation")
            .filter(|value| !value.is_empty())
            .map(|value| Continuation::parse(value).map(|token| token.path().to_owned()))
            .transpose()?;
        Ok(Parsed {
            access: vec![Access {
                key: key.clone(),
                path: path.clone(),
                need: Need::TRAVERSE,
            }],
            operation: Operation::SetAccessRecursive(Box::new(RecursiveAcl {
                key,
                path,
                mode,
                entries,
                after,
                max_records,
                force: boolean(self.param("forceflag"))?.unwrap_or(false),
                caller: self.caller.clone(),
            })),
            sas: sas(Some("p"), ('c', "w")),
        })
    }

    fn path(&self, key: BlobKey) -> std::result::Result<Parsed, DfsError> {
        let container = key.container.clone();
        let path = Some(key.path.clone());
        let access = |need| {
            vec![Access {
                key: container.clone(),
                path: path.clone(),
                need,
            }]
        };
        let parsed = |operation, sas, access| Parsed {
            operation,
            sas,
            access,
        };
        match (self.method, self.param("resource"), self.param("action")) {
            (&Method::PUT, resource, None) => {
                self.bodiless()?;
                if self.headers.contains_key("x-ms-rename-source") {
                    return self.rename(key);
                }
                let kind = match resource {
                    Some("file") => PathKind::File,
                    Some("directory") => PathKind::Directory,
                    Some(_) => return Err(Error::InvalidQuery.into()),
                    None => return Err(DfsError::MissingParameter("resource")),
                };
                self.create(key, kind)
            }
            (&Method::PATCH, None, Some("append")) => {
                self.check(
                    &["action", "position"],
                    &[
                        CONDITIONS,
                        LEASE,
                        LEASE_ACTION,
                        &["content-md5", "x-ms-content-crc64"],
                    ],
                )?;
                let upload = protocol::upload_options(self.headers, MAX_APPEND_BYTES)?;
                Ok(parsed(
                    Operation::Append(Box::new(AppendRequest {
                        position: position(self.query)?,
                        upload,
                        guard: Guard::parse(self.headers)?,
                        lease: lease_use(self.headers)?,
                        key,
                    })),
                    sas(Some("w"), ('o', "w")),
                    access(Need::WRITE),
                ))
            }
            (&Method::PATCH, None, Some("flush")) => {
                self.bodiless()?;
                self.check(
                    &["action", "position", "close", "retainuncommitteddata"],
                    &[
                        CONDITIONS,
                        LEASE,
                        LEASE_ACTION,
                        CONTENT,
                        &["x-ms-content-md5"],
                    ],
                )?;
                boolean(self.param("close"))?;
                // AzCopy sends an empty x-ms-content-md5 when it has no hash to offer.
                let md5 = header(self.headers, "x-ms-content-md5")?
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        STANDARD
                            .decode(value)
                            .ok()
                            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                            .ok_or(Error::InvalidHeader)
                    })
                    .transpose()?;
                let mut headers = content_update(self.headers)?;
                headers.properties = None;
                Ok(parsed(
                    Operation::Flush(Box::new(Flush {
                        position: position(self.query)?,
                        retain: boolean(self.param("retainuncommitteddata"))?.unwrap_or(false),
                        headers,
                        md5,
                        guard: Guard::parse(self.headers)?,
                        lease: lease_use(self.headers)?,
                        limit: self.config.max_assembled_blob_bytes,
                        key,
                    })),
                    sas(Some("w"), ('o', "w")),
                    access(Need::WRITE),
                ))
            }
            (&Method::PATCH, None, Some("setProperties")) => {
                self.bodiless()?;
                self.check(
                    &["action"],
                    &[
                        CONDITIONS,
                        LEASE,
                        CONTENT,
                        PROPERTIES,
                        &["x-ms-content-md5"],
                    ],
                )?;
                Ok(parsed(
                    Operation::SetProperties(
                        key,
                        Guard::parse(self.headers)?,
                        content_update(self.headers)?,
                    ),
                    sas(Some("w"), ('o', "w")),
                    access(Need::WRITE),
                ))
            }
            (&Method::PATCH, None, Some("setAccessControl")) => {
                self.bodiless()?;
                let (update, guard) = self.access_update()?;
                let permission = if update.owner.is_some() || update.group.is_some() {
                    "o"
                } else {
                    "p"
                };
                let need = match permission {
                    "o" => sas(Some("o"), ('o', "w")),
                    _ => sas(Some("p"), ('o', "w")),
                };
                Ok(parsed(
                    Operation::SetAccess(container.clone(), path.clone(), update, guard),
                    need,
                    access(Need::TRAVERSE),
                ))
            }
            (&Method::PATCH, None, Some("setAccessControlRecursive")) => {
                self.bodiless()?;
                let mut parsed = self.recursive_acl(container.clone(), path.clone())?;
                parsed.sas = sas(Some("p"), ('o', "w"));
                Ok(parsed)
            }
            (&Method::HEAD, None, action) => {
                self.bodiless()?;
                self.check(&["action", "upn"], &[CONDITIONS, LEASE])?;
                boolean(self.param("upn"))?;
                let view = match action {
                    None | Some("getStatus" | "getProperties") => View::Properties,
                    Some("getAccessControl") => View::AccessControl,
                    Some(_) => return Err(Error::InvalidQuery.into()),
                };
                Ok(parsed(
                    Operation::PathProperties(
                        container.clone(),
                        path.clone(),
                        Guard::parse(self.headers)?,
                        view,
                    ),
                    sas(Some("er"), ('o', "r")),
                    access(Need::TRAVERSE),
                ))
            }
            (&Method::GET, None, None) => {
                self.bodiless()?;
                self.check(
                    &[],
                    &[
                        CONDITIONS,
                        LEASE,
                        &["range", "x-ms-range", "x-ms-range-get-content-md5"],
                    ],
                )?;
                let (range, range_checksum) = read_range(self.headers)?;
                Ok(parsed(
                    Operation::ReadPath(
                        key,
                        BlobRead {
                            guard: Guard::parse(self.headers)?,
                            range,
                            with_body: true,
                            range_checksum,
                        },
                    ),
                    sas(Some("r"), ('o', "r")),
                    access(Need::READ),
                ))
            }
            (&Method::DELETE, None, None) => {
                self.bodiless()?;
                self.check(
                    &["recursive", "continuation", "paginated"],
                    &[CONDITIONS, LEASE],
                )?;
                let recursive = boolean(self.param("recursive"))?.unwrap_or(false);
                boolean(self.param("paginated"))?;
                let continuation = self
                    .param("continuation")
                    .filter(|value| !value.is_empty())
                    .map(Continuation::parse)
                    .transpose()?;
                let need = Need {
                    leaf: if recursive { Perms::ALL } else { Perms::NONE },
                    ..Need::CHANGE_PARENT
                };
                Ok(parsed(
                    Operation::DeletePath {
                        guard: Guard::parse(self.headers)?,
                        key,
                        recursive,
                        continuation,
                    },
                    sas(Some("d"), ('o', "d")),
                    access(need),
                ))
            }
            (&Method::POST, None, None) => {
                self.bodiless()?;
                self.check(&[], &[CONDITIONS, LEASE, LEASE_ACTION])?;
                Ok(parsed(
                    Operation::LeasePath(
                        key,
                        protocol::lease_action(self.headers)?,
                        Conditions::parse(self.headers, &CONDITION_HEADERS)?,
                    ),
                    sas(Some("w"), ('o', "w")),
                    access(Need::WRITE),
                ))
            }
            _ => Err(Error::Unsupported.into()),
        }
    }

    fn create(&self, key: BlobKey, kind: PathKind) -> std::result::Result<Parsed, DfsError> {
        self.check(
            &["resource"],
            &[
                CONDITIONS,
                LEASE,
                LEASE_ACTION,
                CONTENT,
                PROPERTIES,
                POSIX,
                &["x-ms-expiry-option", "x-ms-expiry-time"],
            ],
        )?;
        let expiry = expiry(self.headers, kind)?;
        let update = content_update(self.headers)?;
        let headers = ContentHeaders {
            content_type: update
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into()),
            encoding: update.encoding.unwrap_or_default(),
            language: update.language.unwrap_or_default(),
            disposition: update.disposition.unwrap_or_default(),
            cache_control: update.cache_control.unwrap_or_default(),
        };
        let lease = match header(self.headers, "x-ms-proposed-lease-id")? {
            Some(proposed) => Some((
                LeaseDuration::parse(
                    header(self.headers, "x-ms-lease-duration")?.ok_or(Error::MissingHeader)?,
                )?,
                Some(LeaseId::parse(proposed)?),
            )),
            None => None,
        };
        let access = vec![Access {
            key: key.container.clone(),
            path: Some(key.path.clone()),
            need: Need::REPLACE,
        }];
        Ok(Parsed {
            operation: Operation::CreatePath(Box::new(CreatePath {
                kind,
                guard: Guard::parse(self.headers)?,
                headers,
                properties: update.properties.unwrap_or_default(),
                creation: creation(self.headers)?,
                default_owner: self.caller.oid().map(str::to_owned),
                lease,
                expiry,
                key,
            })),
            sas: sas(Some("wc"), ('o', "wc")),
            access,
        })
    }

    fn rename(&self, key: BlobKey) -> std::result::Result<Parsed, DfsError> {
        self.check(
            &["mode", "continuation", "resource"],
            &[CONDITIONS, LEASE, SOURCE, PROPERTIES, CONTENT, POSIX],
        )?;
        match self.param("mode") {
            None | Some("legacy" | "posix") => (),
            Some(_) => return Err(Error::InvalidQuery.into()),
        }
        let source = rename_source(self.headers, &key.container)?;
        let source_guard = Guard {
            conditions: Conditions::parse(self.headers, &conditions::SOURCE)?,
            lease: conditions::lease_id(self.headers, "x-ms-source-lease-id")?,
        };
        let access = vec![
            Access {
                key: key.container.clone(),
                path: Some(source.path.clone()),
                need: Need::CHANGE_PARENT,
            },
            Access {
                key: key.container.clone(),
                path: Some(key.path.clone()),
                need: Need::REPLACE,
            },
        ];
        Ok(Parsed {
            operation: Operation::RenamePath(Box::new(Rename {
                source,
                destination: key,
                source_guard,
                destination_guard: Guard::parse(self.headers)?,
                properties: properties(self.headers)?,
            })),
            sas: sas(Some("m"), ('o', "wc")),
            access,
        })
    }
}
