//! Negotiates Table response metadata and validates the request media type.

use super::Format;
use crate::{
    auth::{Query, header},
    table::{
        edm::Metadata,
        error::{Kind, OdataErrorFormat, Result, TableError},
    },
};
use axum::http::HeaderMap;

fn level_from_media(value: &str) -> Option<Metadata> {
    let mut parts = value.split(';').map(str::trim);
    let media = parts.next()?.to_ascii_lowercase();
    if !matches!(media.as_str(), "application/json" | "application/*" | "*/*") {
        return None;
    }
    let level = parts
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("odata"))
        .map(|(_, level)| level.trim().to_ascii_lowercase());
    Some(match level.as_deref() {
        Some("nometadata") => Metadata::None,
        Some("fullmetadata") => Metadata::Full,
        _ => Metadata::Minimal,
    })
}

pub(in crate::table) fn explicit_json_level(accept: &str) -> Option<Metadata> {
    accept
        .split(',')
        .filter(|item| {
            item.split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
        .find_map(level_from_media)
}

fn atom_not_supported(format: OdataErrorFormat) -> TableError {
    TableError::new(Kind::AtomFormatNotSupported).with_odata_format(format)
}

pub(super) fn negotiate(accept: Option<&str>, format: Option<&str>) -> Result<Metadata> {
    if let Some(format) = format {
        return match format.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Metadata::Minimal),
            "atom" | "xml" => Err(atom_not_supported(OdataErrorFormat::Xml)),
            _ => level_from_media(format)
                .ok_or_else(|| TableError::new(Kind::JsonFormatNotSupported)),
        };
    }
    let Some(accept) = accept.filter(|accept| !accept.trim().is_empty()) else {
        return Ok(Metadata::Minimal);
    };
    if let Some(level) = accept.split(',').find_map(level_from_media) {
        return Ok(level);
    }
    let atom = accept.split(',').any(|item| {
        let media = item
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        matches!(media.as_str(), "application/atom+xml" | "application/xml")
    });
    Err(if atom {
        atom_not_supported(OdataErrorFormat::Xml)
    } else {
        TableError::new(Kind::JsonFormatNotSupported)
    })
}

pub(super) fn format(headers: &HeaderMap, query: &Query) -> Result<Format> {
    let level = negotiate(
        header(headers, "accept")?,
        query.get("$format").map(String::as_str),
    )?;
    let return_content = !header(headers, "prefer")?
        .is_some_and(|prefer| prefer.to_ascii_lowercase().contains("return-no-content"));
    Ok(Format {
        level,
        return_content,
    })
}

pub(super) fn require_json(headers: &HeaderMap, level: Metadata) -> Result<()> {
    let content_type = header(headers, "content-type")?.unwrap_or_default();
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "" | "application/json" => Ok(()),
        "application/atom+xml" | "application/xml" => {
            Err(atom_not_supported(OdataErrorFormat::Json(level)))
        }
        _ => Err(TableError::new(Kind::JsonFormatNotSupported)),
    }
}
