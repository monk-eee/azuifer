//! Parsing of the path-shaped inputs of DFS requests: positions, directories and rename sources.

use super::error::DfsError;
use crate::{
    auth::{Query, header},
    domain::{BlobKey, BlobPath, ContainerKey, Error, Result},
};
use axum::http::HeaderMap;

pub(super) fn position(query: &Query) -> std::result::Result<u64, DfsError> {
    query
        .get("position")
        .ok_or(DfsError::MissingParameter("position"))?
        .parse()
        .map_err(|_| Error::InvalidQuery.into())
}

pub(super) fn directory_parameter(query: &Query) -> Result<Option<BlobPath>> {
    query
        .get("directory")
        .map(|value| value.trim_matches('/'))
        .filter(|value| !value.is_empty())
        .map(|value| {
            let path = BlobPath::parse(value.to_owned()).map_err(|_| Error::InvalidQuery)?;
            path.check_hns().map_err(|_| Error::InvalidQuery)?;
            Ok(path)
        })
        .transpose()
}

/// `x-ms-rename-source`: a percent-encoded `/{filesystem}/{path}`, optionally with a SAS.
pub(super) fn rename_source(headers: &HeaderMap, target: &ContainerKey) -> Result<BlobKey> {
    let text = header(headers, "x-ms-rename-source")?.ok_or(Error::MissingHeader)?;
    let path_part = text.split('?').next().unwrap_or_default();
    let decoded = percent_encoding::percent_decode_str(path_part)
        .decode_utf8()
        .map_err(|_| Error::InvalidHeader)?;
    // The Go Data Lake client builds the source from the whole URL path, so against a
    // path-style endpoint it names the account too: `/{account}/{filesystem}/{path}`.
    let own = format!("/{}/{}/", target.account.as_str(), target.name.as_str());
    let decoded = match decoded.strip_prefix(&own) {
        Some(rest) => format!("/{}/{rest}", target.name.as_str()),
        None => decoded.into_owned(),
    };
    let (filesystem, path) = decoded
        .strip_prefix('/')
        .and_then(|rest| rest.split_once('/'))
        .ok_or(Error::InvalidHeader)?;
    if filesystem != target.name.as_str() {
        return Err(Error::InvalidInput);
    }
    let path = BlobPath::parse(path.trim_end_matches('/').to_owned())?;
    path.check_hns()?;
    Ok(BlobKey {
        container: target.clone(),
        path,
    })
}
