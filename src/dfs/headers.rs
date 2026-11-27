//! Pure header and query parsing shared by the DFS operations: user-defined properties,
//! content headers, POSIX ownership and ACL headers, lease actions of appends, and the
//! range checksum and expiry headers that Read Path and Create Path share with Blob.

use crate::{
    auth::header,
    blob_expiry::ExpiryOption,
    conditions,
    domain::{ByteRange, Error, Metadata, RangeChecksum, Result, xml_safe},
    lease::LeaseDuration,
    posix::{Creation, Entry, Form, Mode, PathKind, parse_entries},
    store::{LeaseUse, PropertyUpdate},
};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) fn boolean(value: Option<&str>) -> Result<Option<bool>> {
    value
        .map(|value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(Error::InvalidQuery),
        })
        .transpose()
}

/// `x-ms-properties`: `name=base64(value)` pairs, replacing all properties.
pub(super) fn properties(headers: &HeaderMap) -> Result<Option<Metadata>> {
    let Some(text) = header(headers, "x-ms-properties")? else {
        return Ok(None);
    };
    let mut metadata = Metadata::new();
    for pair in text
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
    {
        let (name, value) = pair.split_once('=').ok_or(Error::InvalidHeader)?;
        let mut chars = name.bytes();
        if !chars
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            || !chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::InvalidHeader);
        }
        let value = STANDARD.decode(value).map_err(|_| Error::InvalidHeader)?;
        let value = String::from_utf8(value).map_err(|_| Error::InvalidHeader)?;
        if !xml_safe(&value) || metadata.insert(name.to_owned(), value).is_some() {
            return Err(Error::InvalidHeader);
        }
    }
    if metadata
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>()
        > 8192
    {
        return Err(Error::InvalidHeader);
    }
    Ok(Some(metadata))
}

pub(super) fn content_header(
    headers: &HeaderMap,
    blob: &str,
    plain: Option<&str>,
) -> Result<Option<String>> {
    let value = match header(headers, blob)? {
        Some(value) => Some(value),
        None => plain
            .map(|name| header(headers, name))
            .transpose()?
            .flatten(),
    };
    match value {
        Some(value) if value.len() > 1024 || !xml_safe(value) => Err(Error::InvalidHeader),
        other => Ok(other.map(str::to_owned)),
    }
}

/// The content headers a request sets, `None` for those it leaves alone.
pub(super) fn content_update(headers: &HeaderMap) -> Result<PropertyUpdate> {
    Ok(PropertyUpdate {
        content_type: content_header(headers, "x-ms-content-type", None)?,
        encoding: content_header(headers, "x-ms-content-encoding", Some("content-encoding"))?,
        language: content_header(headers, "x-ms-content-language", Some("content-language"))?,
        disposition: content_header(
            headers,
            "x-ms-content-disposition",
            Some("content-disposition"),
        )?,
        cache_control: content_header(headers, "x-ms-cache-control", Some("cache-control"))?,
        properties: properties(headers)?,
    })
}

pub(super) fn principal_name(headers: &HeaderMap, name: &str) -> Result<Option<String>> {
    match header(headers, name)? {
        Some(value)
            if value.is_empty()
                || value.len() > 256
                || !xml_safe(value)
                || value.contains([':', ',']) =>
        {
            Err(Error::InvalidHeader)
        }
        other => Ok(other.map(str::to_owned)),
    }
}

pub(super) fn posix_mode(headers: &HeaderMap, name: &str) -> Result<Option<Mode>> {
    header(headers, name)?.map(Mode::parse).transpose()
}

pub(super) fn umask(headers: &HeaderMap) -> Result<Option<Mode>> {
    header(headers, "x-ms-umask")?
        .map(|text| {
            if text.len() == 4 {
                Mode::parse(text)
            } else {
                Err(Error::InvalidHeader)
            }
        })
        .transpose()
}

pub(super) fn acl_entries(headers: &HeaderMap, form: Form) -> Result<Option<Vec<Entry>>> {
    header(headers, "x-ms-acl")?
        .map(|text| parse_entries(text, form))
        .transpose()
}

/// Reads the owner, group, permissions, umask and ACL headers of a create or an ACL change.
pub(super) fn creation(headers: &HeaderMap) -> Result<Creation> {
    let permissions = posix_mode(headers, "x-ms-permissions")?;
    let acl = acl_entries(headers, Form::Full)?;
    if permissions.is_some() && acl.is_some() {
        return Err(Error::InvalidHeader);
    }
    Ok(Creation {
        permissions,
        umask: umask(headers)?,
        acl,
        owner: principal_name(headers, "x-ms-owner")?,
        group: principal_name(headers, "x-ms-group")?,
    })
}

/// `x-ms-lease-action` of Append Data and Flush Data.
pub(super) fn lease_use(headers: &HeaderMap) -> Result<LeaseUse> {
    let duration = || {
        LeaseDuration::parse(header(headers, "x-ms-lease-duration")?.ok_or(Error::MissingHeader)?)
    };
    let proposed = || conditions::lease_id(headers, "x-ms-proposed-lease-id");
    Ok(match header(headers, "x-ms-lease-action")? {
        None => LeaseUse::Hold,
        Some("acquire") => LeaseUse::Acquire {
            duration: duration()?,
            proposed: proposed()?,
        },
        Some("auto-renew") => LeaseUse::AutoRenew,
        Some("release") => LeaseUse::Release,
        Some("acquire-release") => LeaseUse::AcquireRelease {
            duration: duration()?,
            proposed: proposed()?,
        },
        Some(_) => return Err(Error::InvalidHeader),
    })
}

/// The range of Read Path and the checksum `x-ms-range-get-content-md5` asks for. Learn
/// documents no CRC64 header for Read Path, so only MD5 exists, and it needs a range.
pub(super) fn read_range(
    headers: &HeaderMap,
) -> Result<(Option<ByteRange>, Option<RangeChecksum>)> {
    let range = header(headers, "x-ms-range")?
        .or(header(headers, "range")?)
        .map(ByteRange::parse)
        .transpose()?;
    let checksum = match header(headers, "x-ms-range-get-content-md5")? {
        Some("true") if range.is_none() => return Err(Error::InvalidHeader),
        Some("true") => Some(RangeChecksum::Md5),
        _ => None,
    };
    Ok((range, checksum))
}

/// `x-ms-expiry-option` and `x-ms-expiry-time` of Create Path (ADR-0030). Learn lists
/// RelativeToNow, Absolute and NeverExpire for files of a hierarchical namespace only.
pub(super) fn expiry(headers: &HeaderMap, kind: PathKind) -> Result<Option<ExpiryOption>> {
    if !headers.contains_key("x-ms-expiry-option") && !headers.contains_key("x-ms-expiry-time") {
        return Ok(None);
    }
    match ExpiryOption::parse(headers)? {
        _ if kind == PathKind::Directory => Err(Error::InvalidHeader),
        ExpiryOption::RelativeToCreation(_) => Err(Error::InvalidHeader),
        option => Ok(Some(option)),
    }
}
