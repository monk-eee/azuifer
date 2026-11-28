//! Header, query and body parsing shared by the Blob operations, and the checks that refuse
//! what an operation does not implement.

use super::{BLOB_PROPERTIES, MAX_COMMITTED_BLOCKS, UploadOptions};
use crate::{
    auth::{Query, header},
    blob_auth::Target,
    checksum::Checksum,
    compat::Relax,
    conditions::{Guard, lease_id},
    config::Config,
    domain::{
        AccessTier, BlobWrite, BlockId, BlockSelection, BlockSource, ContentHeaders, ContentLength,
        Error, Include, Metadata, PublicAccess, RangeChecksum, Result, xml_safe,
    },
    lease::{LeaseAction, LeaseDuration},
};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use quick_xml::{Reader, events::Event};
use std::collections::HashMap;

pub(super) fn public_access(headers: &HeaderMap) -> Result<PublicAccess> {
    header(headers, "x-ms-blob-public-access")?
        .map(PublicAccess::parse)
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(super) fn includes(value: Option<&str>) -> Result<Vec<Include>> {
    value
        .unwrap_or_default()
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| match item.to_ascii_lowercase().as_str() {
            "metadata" => Ok(Include::Metadata),
            "copy" => Ok(Include::Copy),
            "uncommittedblobs" => Ok(Include::Uncommitted),
            "snapshots" => Ok(Include::Snapshots),
            "versions" => Ok(Include::Versions),
            "deleted" => Ok(Include::Deleted),
            "tags" => Ok(Include::Tags),
            "immutabilitypolicy" => Ok(Include::ImmutabilityPolicy),
            "legalhold" => Ok(Include::LegalHold),
            _ => Err(Error::Unsupported),
        })
        .collect()
}

pub(super) fn range_checksum(headers: &HeaderMap) -> Result<Option<RangeChecksum>> {
    let flag = |name| Ok(header(headers, name)? == Some("true"));
    match (
        flag("x-ms-range-get-content-md5")?,
        flag("x-ms-range-get-content-crc64")?,
    ) {
        (true, true) => Err(Error::ConflictingRangeChecksums),
        (true, false) => Ok(Some(RangeChecksum::Md5)),
        (false, true) => Ok(Some(RangeChecksum::Crc64)),
        (false, false) => Ok(None),
    }
}

pub(crate) fn lease_action(headers: &HeaderMap) -> Result<LeaseAction> {
    let current = || lease_id(headers, "x-ms-lease-id")?.ok_or(Error::MissingHeader);
    match header(headers, "x-ms-lease-action")?.ok_or(Error::MissingHeader)? {
        "acquire" => Ok(LeaseAction::Acquire {
            duration: LeaseDuration::parse(
                header(headers, "x-ms-lease-duration")?.ok_or(Error::MissingHeader)?,
            )?,
            proposed: lease_id(headers, "x-ms-proposed-lease-id")?,
        }),
        "renew" => Ok(LeaseAction::Renew(current()?)),
        "change" => Ok(LeaseAction::Change {
            current: current()?,
            proposed: lease_id(headers, "x-ms-proposed-lease-id")?.ok_or(Error::MissingHeader)?,
        }),
        "release" => Ok(LeaseAction::Release(current()?)),
        "break" => Ok(LeaseAction::Break {
            period: header(headers, "x-ms-lease-break-period")?
                .map(|period| match period.parse::<u32>() {
                    Ok(seconds @ 0..=60) => Ok(seconds),
                    _ => Err(Error::InvalidHeader),
                })
                .transpose()?,
        }),
        _ => Err(Error::InvalidHeader),
    }
}

pub(crate) fn upload_options(headers: &HeaderMap, limit: u64) -> Result<UploadOptions> {
    let length: u64 = header(headers, "content-length")?
        .ok_or(Error::MissingLength)?
        .parse()
        .map_err(|_| Error::InvalidLength)?;
    if length > limit {
        return Err(Error::TooLarge);
    }
    let checksum = declared_checksum(headers, "content-md5", "x-ms-content-crc64")?;
    Ok(UploadOptions {
        length: ContentLength(length),
        checksum,
    })
}

/// The MD5 or CRC64 a request declares in the named headers; naming both is invalid.
fn declared_checksum(headers: &HeaderMap, md5: &str, crc64: &str) -> Result<Option<Checksum>> {
    let md5 = decode_hash(header(headers, md5)?)?;
    let crc64 = decode_hash(header(headers, crc64)?)?;
    match (md5, crc64) {
        (Some(_), Some(_)) => Err(Error::InvalidHeader),
        (Some(md5), None) => Ok(Some(Checksum::Md5(md5))),
        (None, Some(crc64)) => Ok(Some(Checksum::Crc64(u64::from_le_bytes(crc64)))),
        (None, None) => Ok(None),
    }
}

/// The hash of the source bytes a From-URL write declares (`x-ms-source-content-*`).
pub(super) fn source_checksum(headers: &HeaderMap) -> Result<Option<Checksum>> {
    declared_checksum(
        headers,
        "x-ms-source-content-md5",
        "x-ms-source-content-crc64",
    )
}

/// `x-ms-seal-blob` of Copy Blob; `None` leaves the destination unsealed.
pub(super) fn seal_blob(headers: &HeaderMap) -> Result<Option<bool>> {
    header(headers, "x-ms-seal-blob")?
        .map(|value| match value {
            value if value.eq_ignore_ascii_case("true") => Ok(true),
            value if value.eq_ignore_ascii_case("false") => Ok(false),
            _ => Err(Error::InvalidHeader),
        })
        .transpose()
}

pub(super) fn decode_hash<const N: usize>(value: Option<&str>) -> Result<Option<[u8; N]>> {
    value
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| Error::InvalidHeader)?
                .try_into()
                .map_err(|_| Error::InvalidHeader)
        })
        .transpose()
}

/// `x-ms-blob-content-md5`, which AzCopy sends empty when it has no hash to set.
pub(super) fn blob_content_md5(headers: &HeaderMap) -> Result<Option<[u8; 16]>> {
    decode_hash(header(headers, "x-ms-blob-content-md5")?.filter(|value| !value.is_empty()))
}

/// Reads the content headers. The `x-ms-blob-*` form wins over the plain
/// header; `plain` also accepts the plain `Content-Type` of a Put Blob request.
/// The flag reports whether any content property was supplied.
pub(super) fn content_headers(headers: &HeaderMap, plain: bool) -> Result<(ContentHeaders, bool)> {
    let pick = |blob: &str, standard: Option<&str>| -> Result<Option<String>> {
        let value = match header(headers, blob)? {
            Some(value) => Some(value),
            None => match standard {
                Some(name) => header(headers, name)?,
                None => None,
            },
        };
        match value {
            Some(value) if value.len() > 1024 || !xml_safe(value) => Err(Error::InvalidHeader),
            other => Ok(other.map(str::to_owned)),
        }
    };
    let fallback = |name| plain.then_some(name);
    let content_type = pick("x-ms-blob-content-type", fallback("content-type"))?;
    if content_type
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 512)
    {
        return Err(Error::InvalidHeader);
    }
    let encoding = pick("x-ms-blob-content-encoding", fallback("content-encoding"))?;
    let language = pick("x-ms-blob-content-language", fallback("content-language"))?;
    let disposition = pick(
        "x-ms-blob-content-disposition",
        fallback("content-disposition"),
    )?;
    let cache_control = pick("x-ms-blob-cache-control", fallback("cache-control"))?;
    let supplied = BLOB_PROPERTIES
        .iter()
        .any(|name| headers.contains_key(*name));
    Ok((
        ContentHeaders {
            content_type: content_type.unwrap_or_else(|| "application/octet-stream".into()),
            encoding: encoding.unwrap_or_default(),
            language: language.unwrap_or_default(),
            disposition: disposition.unwrap_or_default(),
            cache_control: cache_control.unwrap_or_default(),
        },
        supplied,
    ))
}

pub(super) fn metadata(headers: &HeaderMap) -> Result<Metadata> {
    let mut metadata = Metadata::new();
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-ms-meta-") {
            let mut chars = name.bytes();
            if !chars
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                || !chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::InvalidHeader);
            }
            let value = value.to_str().map_err(|_| Error::InvalidHeader)?;
            if !xml_safe(value) {
                return Err(Error::InvalidHeader);
            }
            metadata.insert(name.to_owned(), value.to_owned());
        }
    }
    if metadata
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum::<usize>()
        > 8192
    {
        return Err(Error::InvalidHeader);
    }
    Ok(metadata)
}

pub(super) fn blob_write(headers: &HeaderMap, plain: bool) -> Result<BlobWrite> {
    Ok(BlobWrite {
        headers: content_headers(headers, plain)?.0,
        metadata: metadata(headers)?,
        guard: Guard::parse(headers)?,
        tier: header(headers, "x-ms-access-tier")?
            .map(AccessTier::parse)
            .transpose()?,
        copy: None,
        md5: blob_content_md5(headers)?,
        tags: header(headers, "x-ms-tags")?
            .map(crate::blob_tags::from_header)
            .transpose()?
            .unwrap_or_default(),
    })
}

pub(crate) fn parse_block_list(body: &[u8]) -> Result<Vec<BlockSelection>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidXml)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let root = match reader.read_event().map_err(|_| Error::InvalidXml)? {
        Event::Decl(_) => reader.read_event().map_err(|_| Error::InvalidXml)?,
        event => event,
    };
    let mut selections = Vec::new();
    let mut sources = HashMap::new();
    match root {
        Event::Empty(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() => {}
        Event::Start(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() =>
        {
            loop {
                match reader.read_event().map_err(|_| Error::InvalidXml)? {
                    Event::End(end) if end.name().as_ref() == "BlockList" => break,
                    Event::Start(tag) if tag.attributes_raw().is_empty() => {
                        if selections.len() == MAX_COMMITTED_BLOCKS {
                            return Err(Error::BlockListTooLong);
                        }
                        let source = match tag.name().as_ref() {
                            "Committed" => BlockSource::Committed,
                            "Uncommitted" => BlockSource::Uncommitted,
                            "Latest" => BlockSource::Latest,
                            _ => return Err(Error::InvalidXml),
                        };
                        let value = reader
                            .read_text(tag.name())
                            .map_err(|_| Error::InvalidXml)?;
                        let id =
                            BlockId::parse(value.trim()).map_err(|_| Error::InvalidBlockList)?;
                        if selections
                            .first()
                            .is_some_and(|first: &BlockSelection| first.id.width != id.width)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        if sources
                            .insert(id.as_str().to_owned(), source)
                            .is_some_and(|prior| prior != source)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        selections.push(BlockSelection { id, source });
                    }
                    _ => return Err(Error::InvalidXml),
                }
            }
        }
        _ => return Err(Error::InvalidXml),
    }
    if !matches!(reader.read_event(), Ok(Event::Eof)) {
        return Err(Error::InvalidXml);
    }
    Ok(selections)
}

/// Rejects query parameters and `x-ms-*` or conditional headers the operation
/// does not implement, instead of silently ignoring them. The one exception is a name
/// the compatibility mode lists (ADR-0038), which `relax` logs and lets through.
pub(crate) fn check(
    query: &Query,
    headers: &HeaderMap,
    allowed_query: &[&str],
    allowed_headers: &[&[&str]],
    metadata: bool,
    relax: &Relax<'_>,
) -> Result<()> {
    if query
        .keys()
        .any(|key| key != "timeout" && !allowed_query.contains(&key.as_str()) && !relax.query(key))
    {
        return Err(Error::Unsupported);
    }
    for key in headers.keys() {
        let key = key.as_str();
        if allowed_headers.iter().any(|list| list.contains(&key))
            || matches!(
                key,
                "x-ms-version"
                    | "x-ms-date"
                    | "x-ms-client-request-id"
                    | "x-ms-return-client-request-id"
            )
            || metadata && key.starts_with("x-ms-meta-")
            || key == "x-ms-if-tags"
                && allowed_headers
                    .iter()
                    .any(|list| list.contains(&"if-match"))
            || key == "x-ms-source-if-tags"
                && allowed_headers
                    .iter()
                    .any(|list| list.contains(&"x-ms-source-if-match"))
        {
            continue;
        }
        if key.starts_with("x-ms-")
            || key.starts_with("if-")
            || matches!(
                key,
                "range"
                    | "content-md5"
                    | "content-encoding"
                    | "content-language"
                    | "cache-control"
                    | "content-disposition"
            )
        {
            if relax.header(key) {
                continue;
            }
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}

pub(crate) fn check_hns_path(target: &Target, config: &Config) -> Result<()> {
    if let Target::Blob(key) = target
        && config.hns_accounts.contains(&key.container.account)
    {
        key.path.check_hns()?;
    }
    Ok(())
}

pub(crate) fn parse_query(query: Option<&str>) -> Result<Query> {
    let mut result = Query::new();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        if query.len() > 16 * 1024 {
            return Err(Error::InvalidQuery);
        }
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(Error::InvalidQuery)?;
            let name = decode(name, true)
                .ok_or(Error::InvalidQuery)?
                .to_ascii_lowercase();
            let value = decode(value, true).ok_or(Error::InvalidQuery)?;
            if name.is_empty()
                || !xml_safe(&name)
                || !xml_safe(&value)
                || result.insert(name, value).is_some()
            {
                return Err(Error::InvalidQuery);
            }
        }
    }
    Ok(result)
}

pub(super) fn decode(value: &str, query: bool) -> Option<String> {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' && !(bytes.next()?.is_ascii_hexdigit() && bytes.next()?.is_ascii_hexdigit())
        {
            return None;
        }
    }
    let prepared = if query && value.contains('+') {
        std::borrow::Cow::Owned(value.replace('+', " "))
    } else {
        std::borrow::Cow::Borrowed(value)
    };
    percent_decode_str(&prepared)
        .decode_utf8()
        .ok()
        .map(|value| value.into_owned())
}
