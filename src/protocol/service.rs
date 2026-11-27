//! Account and container operations: which request each method and query selects.

use super::headers::{includes, lease_action, metadata, public_access, upload_options};
use super::{
    BatchRequest, CHECKSUMS, ContainerView, DATE_CONDITIONS, LEASE, LEASE_HEADERS, MAX_BATCH_BYTES,
    MAX_XML_BODY_BYTES, Operation, Request,
};
use crate::{
    auth::header,
    blob_batch,
    blob_tags::TagFilter,
    conditions::{Guard, lease_id},
    domain::{AccountName, ContainerCreate, ContainerKey, Error, ListRequest, Result},
};
use axum::http::Method;

impl Request<'_> {
    pub(super) fn account_operation(&self, account: AccountName) -> Result<Operation> {
        let (restype, comp) = (self.param("restype"), self.param("comp"));
        Ok(match (self.method, restype, comp) {
            (&Method::GET, None, Some("list")) => {
                self.check(
                    &["comp", "prefix", "marker", "maxresults", "include"],
                    &[],
                    false,
                )?;
                let (mut metadata, mut deleted) = (false, false);
                for item in self.param("include").unwrap_or_default().split(',') {
                    match item {
                        "" => (),
                        "metadata" => metadata = true,
                        "deleted" => deleted = true,
                        _ => return Err(Error::Unsupported),
                    }
                }
                Operation::ListContainers(account, self.listing()?, metadata, deleted)
            }
            (&Method::GET, Some("service"), Some("properties")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::GetServiceProperties(account)
            }
            (&Method::PUT, Some("service"), Some("properties")) => {
                self.check(&["restype", "comp"], &[CHECKSUMS], false)?;
                Operation::SetServiceProperties(
                    account,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                )
            }
            (&Method::POST, Some("service"), Some("userdelegationkey")) => {
                self.check(&["restype", "comp"], &[CHECKSUMS], false)?;
                Operation::UserDelegationKey(
                    account,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                )
            }
            (&Method::GET, Some("service"), Some("stats")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::ServiceStats
            }
            (&Method::GET | &Method::HEAD, Some("account"), Some("properties")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::AccountInfo
            }
            (&Method::GET, None, Some("blobs")) => {
                self.check(&["comp", "where", "marker", "maxresults"], &[], false)?;
                Operation::FindBlobs(account, None, self.filter()?, self.listing()?)
            }
            // The JS SDK sends a service-level batch with restype=container.
            (&Method::POST, None | Some("container"), Some("batch")) => {
                self.check(&["comp", "restype"], &[], false)?;
                Operation::SubmitBatch(None, self.batch()?)
            }
            _ => return Err(Error::Unsupported),
        })
    }

    pub(super) fn filter(&self) -> Result<TagFilter> {
        TagFilter::parse(self.param("where").ok_or(Error::InvalidQuery)?, true)
    }

    pub(super) fn batch(&self) -> Result<BatchRequest> {
        let content_type = header(self.headers, "content-type")?.ok_or(Error::MissingHeader)?;
        Ok(BatchRequest {
            boundary: blob_batch::boundary(content_type)?,
            upload: upload_options(self.headers, MAX_BATCH_BYTES)?,
        })
    }

    pub(super) fn container_operation(&self, key: ContainerKey) -> Result<Operation> {
        let (restype, comp) = (self.param("restype"), self.param("comp"));
        let reading = matches!(*self.method, Method::GET | Method::HEAD);
        let lease = || lease_id(self.headers, "x-ms-lease-id");
        if let Some(operation) = self.restore_container(&key)? {
            return Ok(Operation::Lifecycle(operation));
        }
        Ok(match (restype, comp) {
            (Some("container"), None) => {
                self.check(
                    &["restype"],
                    &[&["x-ms-blob-public-access"], LEASE, DATE_CONDITIONS],
                    true,
                )?;
                match *self.method {
                    Method::PUT => Operation::CreateContainer(
                        key,
                        ContainerCreate {
                            metadata: metadata(self.headers)?,
                            public_access: public_access(self.headers)?,
                        },
                    ),
                    Method::GET | Method::HEAD => {
                        Operation::ContainerProperties(key, lease()?, ContainerView::Properties)
                    }
                    Method::DELETE => Operation::DeleteContainer(key, Guard::parse(self.headers)?),
                    _ => return Err(Error::Unsupported),
                }
            }
            (Some("container"), Some("metadata")) if reading => {
                self.check(&["restype", "comp"], &[LEASE], false)?;
                Operation::ContainerProperties(key, lease()?, ContainerView::Metadata)
            }
            (Some("container"), Some("metadata")) if *self.method == Method::PUT => {
                self.check(&["restype", "comp"], &[LEASE, DATE_CONDITIONS], true)?;
                Operation::SetContainerMetadata(
                    key,
                    metadata(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("acl")) if reading => {
                self.check(&["restype", "comp"], &[LEASE], false)?;
                Operation::GetContainerAcl(key, lease()?)
            }
            (Some("container"), Some("acl")) if *self.method == Method::PUT => {
                self.check(
                    &["restype", "comp"],
                    &[
                        &["x-ms-blob-public-access"],
                        LEASE,
                        DATE_CONDITIONS,
                        CHECKSUMS,
                    ],
                    false,
                )?;
                Operation::SetContainerAcl(
                    key,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                    public_access(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("lease")) if *self.method == Method::PUT => {
                self.check(
                    &["restype", "comp"],
                    &[LEASE_HEADERS, DATE_CONDITIONS],
                    false,
                )?;
                Operation::LeaseContainer(
                    key,
                    lease_action(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("list")) if *self.method == Method::GET => {
                self.check(
                    &[
                        "comp",
                        "restype",
                        "prefix",
                        "marker",
                        "maxresults",
                        "include",
                        "delimiter",
                    ],
                    &[LEASE],
                    false,
                )?;
                Operation::ListBlobs(
                    key,
                    ListRequest {
                        page: self.listing()?,
                        delimiter: self
                            .param("delimiter")
                            .filter(|delimiter| !delimiter.is_empty())
                            .map(str::to_owned),
                        include: includes(self.param("include"))?,
                    },
                    lease()?,
                )
            }
            (Some("container"), Some("blobs")) if *self.method == Method::GET => {
                self.check(
                    &["restype", "comp", "where", "marker", "maxresults"],
                    &[],
                    false,
                )?;
                // The container is the scope, so `@container` is not a valid term here.
                let filter =
                    TagFilter::parse(self.param("where").ok_or(Error::InvalidQuery)?, false)?;
                let account = key.account.clone();
                Operation::FindBlobs(account, Some(key), filter, self.listing()?)
            }
            (Some("container"), Some("batch")) if *self.method == Method::POST => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::SubmitBatch(Some(key), self.batch()?)
            }
            (Some("account"), Some("properties")) if reading => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::AccountInfo
            }
            _ => return Err(Error::Unsupported),
        })
    }
}
