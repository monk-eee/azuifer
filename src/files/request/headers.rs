//! Typed access to request headers: the values handlers receive instead of raw strings.

use crate::auth;
use crate::files::{
    error::{Error, Result},
    lease,
    model::{
        self, Attributes, Conditions, HttpProperties, Metadata, PermissionSpec, Posix,
        SmbProperties, TimeSpec,
    },
    sd,
    store::{CopyBy, NfsCopy},
    time,
};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;

/// The most base64 text of a binary security descriptor a header may carry, like SDDL's 8 KiB.
const MAX_BINARY_PERMISSION: usize = 8 * 1024;

/// Typed access to request headers.
pub(in crate::files) struct Headers<'a>(pub(in crate::files) &'a HeaderMap);

impl Headers<'_> {
    pub(in crate::files) fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    pub(in crate::files) fn get(&self, name: &str) -> Result<Option<&str>> {
        auth::header(self.0, name).map_err(|_| Error::InvalidHeaderValue)
    }

    pub(in crate::files) fn required(&self, name: &str) -> Result<&str> {
        self.get(name)?.ok_or(Error::MissingRequiredHeader)
    }

    pub(in crate::files) fn number(&self, name: &str) -> Result<Option<u64>> {
        self.get(name)?
            .map(|value| value.parse().map_err(|_| Error::InvalidHeaderValue))
            .transpose()
    }

    pub(in crate::files) fn flag(&self, name: &str) -> Result<bool> {
        match self.get(name)? {
            None => Ok(false),
            Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
            Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
            Some(_) => Err(Error::InvalidHeaderValue),
        }
    }

    pub(in crate::files) fn lease_id(&self, name: &str) -> Result<Option<String>> {
        self.get(name)?.map(lease::parse_id).transpose()
    }

    /// `x-ms-meta-*` headers as validated metadata.
    pub(in crate::files) fn metadata(&self) -> Result<Metadata> {
        let mut pairs = Vec::new();
        for (name, value) in self.0 {
            if let Some(key) = name.as_str().strip_prefix("x-ms-meta-") {
                let value = value.to_str().map_err(|_| Error::InvalidMetadata)?;
                pairs.push((key.to_owned(), value.to_owned()));
            }
        }
        model::metadata(pairs)
    }

    pub(in crate::files) fn has_metadata(&self) -> bool {
        self.0
            .keys()
            .any(|name| name.as_str().starts_with("x-ms-meta-"))
    }

    pub(in crate::files) fn md5(&self, name: &str) -> Result<Option<[u8; 16]>> {
        self.get(name)?
            .map(|value| {
                STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                    .ok_or(Error::InvalidMd5)
            })
            .transpose()
    }

    pub(in crate::files) fn crc64(&self, name: &str) -> Result<Option<u64>> {
        self.get(name)?
            .map(|value| {
                STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                    .map(u64::from_le_bytes)
                    .ok_or(Error::InvalidHeaderValue)
            })
            .transpose()
    }

    /// The five HTTP representation headers; `None` when none is present.
    pub(in crate::files) fn http_properties(&self) -> Result<Option<HttpProperties>> {
        let text = |name| self.get(name).map(|value| value.map(str::to_owned));
        let md5 = self
            .md5("x-ms-content-md5")?
            .map(|bytes| STANDARD.encode(bytes));
        let http = HttpProperties {
            content_type: text("x-ms-content-type")?,
            content_encoding: text("x-ms-content-encoding")?,
            content_language: text("x-ms-content-language")?,
            content_disposition: text("x-ms-content-disposition")?,
            cache_control: text("x-ms-cache-control")?,
            md5,
        };
        Ok((!http.is_empty()).then_some(http))
    }

    fn time_spec(&self, name: &str) -> Result<Option<TimeSpec>> {
        self.get(name)?
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "now" => Ok(TimeSpec::Now),
                "preserve" => Ok(TimeSpec::Preserve),
                _ => time::parse_iso_ticks(value)
                    .map(TimeSpec::At)
                    .ok_or(Error::InvalidHeaderValue),
            })
            .transpose()
    }

    /// SMB attributes, timestamps, and permission, defaulting per create or update.
    pub(in crate::files) fn smb(&self, create: bool, version: &str) -> Result<SmbProperties> {
        let mut smb = if create {
            SmbProperties::for_create()
        } else {
            SmbProperties::for_update()
        };
        smb.attributes = match self.get("x-ms-file-attributes")? {
            None | Some("preserve") => None,
            Some(value) => Some(Attributes::parse(value)?),
        };
        if let Some(spec) = self.time_spec("x-ms-file-creation-time")? {
            smb.creation = spec;
        }
        if let Some(spec) = self.time_spec("x-ms-file-last-write-time")? {
            smb.last_write = spec;
        }
        smb.change = self.time_spec("x-ms-file-change-time")?;
        smb.permission = match (
            self.get("x-ms-file-permission")?,
            self.get("x-ms-file-permission-key")?,
        ) {
            (Some(_), Some(_)) => return Err(Error::InvalidHeaderValue),
            (Some("inherit"), None) => PermissionSpec::Inherit,
            (Some("preserve"), None) => PermissionSpec::Preserve,
            (Some(text), None) => {
                // The format header exists from 2025-01-05; before that it is ignored.
                let format = if version >= "2025-01-05" {
                    self.get("x-ms-file-permission-format")?
                } else {
                    None
                };
                match format {
                    None | Some("sddl") => PermissionSpec::Sddl(text.to_owned()),
                    Some("binary") if text.len() <= MAX_BINARY_PERMISSION => {
                        PermissionSpec::Sddl(sd::sddl_from_binary(text)?)
                    }
                    Some("binary") => return Err(Error::FileInvalidPermission),
                    Some(_) => return Err(Error::InvalidHeaderValue),
                }
            }
            (None, Some(key)) => PermissionSpec::Key(key.to_owned()),
            (None, None) if create => PermissionSpec::Inherit,
            (None, None) => PermissionSpec::Preserve,
        };
        Ok(smb)
    }

    /// `x-ms-mode`, `x-ms-owner` and `x-ms-group`; each is optional.
    pub(in crate::files) fn posix(&self) -> Result<Posix> {
        let id = |name: &str| -> Result<Option<u32>> {
            self.get(name)?
                .map(|value| {
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::InvalidHeaderValue);
                    }
                    value.parse().map_err(|_| Error::InvalidHeaderValue)
                })
                .transpose()
        };
        Ok(Posix {
            mode: self.get("x-ms-mode")?.map(model::parse_mode).transpose()?,
            owner: id("x-ms-owner")?,
            group: id("x-ms-group")?,
        })
    }

    /// A header that is a Boolean when present and unset when absent.
    pub(in crate::files) fn optional_flag(&self, name: &str) -> Result<Option<bool>> {
        self.get(name)?
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(Error::InvalidHeaderValue),
            })
            .transpose()
    }

    /// `x-ms-file-mode-copy-mode` and `x-ms-file-owner-copy-mode`, each `source` (the
    /// default) or `override`, which requires the headers that carry the new values.
    pub(in crate::files) fn nfs_copy(&self) -> Result<NfsCopy> {
        let by = |name: &str| -> Result<CopyBy> {
            match self.get(name)? {
                None => Ok(CopyBy::Source),
                Some(value) if value.eq_ignore_ascii_case("source") => Ok(CopyBy::Source),
                Some(value) if value.eq_ignore_ascii_case("override") => Ok(CopyBy::Override),
                Some(_) => Err(Error::InvalidHeaderValue),
            }
        };
        let copy = NfsCopy {
            mode: by("x-ms-file-mode-copy-mode")?,
            owner: by("x-ms-file-owner-copy-mode")?,
            posix: self.posix()?,
        };
        if copy.mode == CopyBy::Override && copy.posix.mode.is_none() {
            return Err(Error::MissingRequiredHeader);
        }
        if copy.owner == CopyBy::Override
            && (copy.posix.owner.is_none() || copy.posix.group.is_none())
        {
            return Err(Error::MissingRequiredHeader);
        }
        Ok(copy)
    }

    /// Standard HTTP preconditions for reads.
    pub(in crate::files) fn conditions(&self) -> Result<Conditions> {
        let date = |name| -> Result<Option<i64>> {
            self.get(name)?
                .map(|value| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(crate::clock::to_millis)
                        .ok_or(Error::InvalidHeaderValue)
                })
                .transpose()
        };
        Ok(Conditions {
            if_match: self.get("if-match")?.map(str::to_owned),
            if_none_match: self.get("if-none-match")?.map(str::to_owned),
            if_modified_since: date("if-modified-since")?,
            if_unmodified_since: date("if-unmodified-since")?,
        })
    }

    /// `x-ms-range` (preferred) or `Range` as `bytes=start-end`.
    pub(in crate::files) fn range(&self) -> Result<Option<ByteRange>> {
        let value = match self.get("x-ms-range")? {
            Some(value) => Some(value),
            None => self.get("range")?,
        };
        value.map(ByteRange::parse).transpose()
    }

    pub(in crate::files) fn content_length(&self) -> Result<u64> {
        self.number("content-length")?
            .ok_or(Error::MissingContentLengthHeader)
    }
}

/// A `bytes=start-end` range with an inclusive, optional end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::files) struct ByteRange {
    pub(in crate::files) start: u64,
    pub(in crate::files) end: Option<u64>,
}

impl ByteRange {
    pub(in crate::files) fn parse(value: &str) -> Result<Self> {
        let (start, end) = value
            .strip_prefix("bytes=")
            .and_then(|range| range.split_once('-'))
            .ok_or(Error::InvalidHeaderValue)?;
        let start = start.parse().map_err(|_| Error::InvalidHeaderValue)?;
        let end = match end {
            "" => None,
            end => Some(end.parse().map_err(|_| Error::InvalidHeaderValue)?),
        };
        if end.is_some_and(|end| end < start) {
            return Err(Error::InvalidHeaderValue);
        }
        Ok(Self { start, end })
    }

    /// For writes: both ends are mandatory; returns `(offset, length)`.
    pub(in crate::files) fn exact(self) -> Result<(u64, u64)> {
        let end = self.end.ok_or(Error::InvalidHeaderValue)?;
        Ok((self.start, end - self.start + 1))
    }
}

/// The `x-ms-content-length` of a new or resized file, within the 4 TiB limit.
pub(in crate::files) fn file_length(headers: &Headers<'_>, name: &str) -> Result<Option<u64>> {
    headers
        .number(name)?
        .map(|length| {
            if length > MAX_FILE_BYTES {
                Err(Error::InvalidHeaderValue)
            } else {
                Ok(length)
            }
        })
        .transpose()
}
