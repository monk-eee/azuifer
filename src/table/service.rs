//! XML documents of the Table service: stored access policies, service properties, stats.

use super::{
    datetime::Ticks,
    error::{Kind, Result, TableError},
};
use crate::{sas::parse_time, wire::Xml};
use axum::{http::StatusCode, response::Response};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::SystemTime};

const MAX_POLICIES: usize = 5;
const SERVICE_ELEMENTS: [&str; 4] = ["Logging", "HourMetrics", "MinuteMetrics", "Cors"];

fn xml_error() -> TableError {
    TableError::new(Kind::InvalidXmlDocument)
}

/// A stored access policy of a table (`Set Table ACL`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct AccessPolicy {
    pub(super) id: String,
    pub(super) start: Option<String>,
    pub(super) expiry: Option<String>,
    pub(super) permission: Option<String>,
}

fn element_text(reader: &mut Reader<&[u8]>, name: quick_xml::name::QName) -> Result<String> {
    reader
        .read_text(name)
        .map(|text| text.trim().to_owned())
        .map_err(|_| xml_error())
}

pub(super) fn parse_acl(body: &[u8]) -> Result<Vec<AccessPolicy>> {
    let text = std::str::from_utf8(body).map_err(|_| xml_error())?;
    // An empty body clears every stored policy.
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut event = reader.read_event().map_err(|_| xml_error())?;
    if matches!(event, Event::Decl(_)) {
        event = reader.read_event().map_err(|_| xml_error())?;
    }
    let mut policies: Vec<AccessPolicy> = Vec::new();
    match event {
        Event::Empty(root) if root.name().as_ref() == "SignedIdentifiers" => {}
        Event::Start(root) if root.name().as_ref() == "SignedIdentifiers" => loop {
            match reader.read_event().map_err(|_| xml_error())? {
                Event::End(end) if end.name().as_ref() == "SignedIdentifiers" => break,
                Event::Start(tag) if tag.name().as_ref() == "SignedIdentifier" => {
                    policies.push(parse_identifier(&mut reader)?);
                }
                _ => return Err(xml_error()),
            }
        },
        _ => return Err(xml_error()),
    }
    if !matches!(reader.read_event(), Ok(Event::Eof)) {
        return Err(xml_error());
    }
    if policies.len() > MAX_POLICIES {
        return Err(TableError::with(
            Kind::InvalidXmlDocument,
            "A maximum of 5 access policies may be set on a table.",
        ));
    }
    for (at, policy) in policies.iter().enumerate() {
        if policies[..at].iter().any(|other| other.id == policy.id) {
            return Err(xml_error());
        }
    }
    Ok(policies)
}

fn parse_identifier(reader: &mut Reader<&[u8]>) -> Result<AccessPolicy> {
    let mut policy = AccessPolicy {
        id: String::new(),
        start: None,
        expiry: None,
        permission: None,
    };
    let mut has_id = false;
    loop {
        match reader.read_event().map_err(|_| xml_error())? {
            Event::End(end) if end.name().as_ref() == "SignedIdentifier" => break,
            Event::Start(tag) if tag.name().as_ref() == "Id" => {
                policy.id = element_text(reader, tag.name())?;
                has_id = true;
            }
            Event::Empty(tag) if tag.name().as_ref() == "Id" => has_id = true,
            Event::Empty(tag) if tag.name().as_ref() == "AccessPolicy" => {}
            Event::Start(tag) if tag.name().as_ref() == "AccessPolicy" => loop {
                match reader.read_event().map_err(|_| xml_error())? {
                    Event::End(end) if end.name().as_ref() == "AccessPolicy" => break,
                    Event::Start(field) => {
                        let value = element_text(reader, field.name())?;
                        match field.name().as_ref() {
                            "Start" => policy.start = Some(value),
                            "Expiry" => policy.expiry = Some(value),
                            "Permission" => policy.permission = Some(value),
                            _ => return Err(xml_error()),
                        }
                    }
                    Event::Empty(_) => {}
                    _ => return Err(xml_error()),
                }
            },
            _ => return Err(xml_error()),
        }
    }
    let permission_ok = policy
        .permission
        .as_deref()
        .is_none_or(|p| p.chars().all(|c| matches!(c, 'r' | 'a' | 'u' | 'd')));
    let times_ok = [&policy.start, &policy.expiry]
        .into_iter()
        .flatten()
        .all(|time| parse_time(time).is_ok());
    if !has_id || policy.id.is_empty() || policy.id.len() > 64 || !permission_ok || !times_ok {
        return Err(xml_error());
    }
    // Azure returns policy times in one canonical form that every client can parse.
    for text in [&mut policy.start, &mut policy.expiry]
        .into_iter()
        .flatten()
    {
        let parsed = parse_time(text).map_err(|_| xml_error())?;
        *text = Ticks::from_system(parsed).format();
    }
    Ok(policy)
}

pub(super) fn acl_response(policies: &[AccessPolicy]) -> Response {
    let mut xml = Xml::root("SignedIdentifiers", &[]);
    for policy in policies {
        xml.open("SignedIdentifier");
        xml.element("Id", &policy.id);
        xml.open("AccessPolicy");
        for (tag, value) in [
            ("Start", &policy.start),
            ("Expiry", &policy.expiry),
            ("Permission", &policy.permission),
        ] {
            if let Some(value) = value {
                xml.element(tag, value);
            }
        }
        xml.close("AccessPolicy");
        xml.close("SignedIdentifier");
    }
    xml.finish("SignedIdentifiers", StatusCode::OK)
}

/// Splits a `Set Table Service Properties` body into its top-level elements.
pub(super) fn parse_properties(body: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(body).map_err(|_| xml_error())?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut depth = 0_usize;
    let mut rooted = false;
    let mut start = 0;
    let mut elements = BTreeMap::new();
    loop {
        let before = usize::try_from(reader.buffer_position()).map_err(|_| xml_error())?;
        let event = reader.read_event().map_err(|_| xml_error())?;
        let after = usize::try_from(reader.buffer_position()).map_err(|_| xml_error())?;
        match event {
            Event::Decl(_) | Event::Comment(_) | Event::Text(_) if depth == 0 => {}
            Event::Start(tag) => {
                if depth == 0 {
                    if rooted || tag.name().as_ref() != "StorageServiceProperties" {
                        return Err(xml_error());
                    }
                    rooted = true;
                } else if depth == 1 {
                    start = before;
                }
                depth += 1;
            }
            Event::Empty(tag) => {
                if depth == 0 && !rooted && tag.name().as_ref() == "StorageServiceProperties" {
                    rooted = true;
                } else if depth == 1 {
                    insert_element(&mut elements, tag.name().as_ref(), text.get(before..after))?;
                } else {
                    return Err(xml_error());
                }
            }
            Event::End(tag) => {
                depth = depth.checked_sub(1).ok_or_else(xml_error)?;
                if depth == 1 {
                    insert_element(&mut elements, tag.name().as_ref(), text.get(start..after))?;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 || !rooted || elements.is_empty() {
        return Err(xml_error());
    }
    Ok(elements)
}

fn insert_element(
    elements: &mut BTreeMap<String, String>,
    name: &str,
    raw: Option<&str>,
) -> Result<()> {
    if !SERVICE_ELEMENTS.contains(&name) {
        return Err(xml_error());
    }
    let raw = raw.ok_or_else(xml_error)?;
    if name == "Cors" && super::cors::parse_rules(raw.trim()).is_none() {
        return Err(xml_error());
    }
    if elements
        .insert(name.to_owned(), raw.trim().to_owned())
        .is_some()
    {
        return Err(xml_error());
    }
    Ok(())
}

fn default_element(name: &str) -> &'static str {
    match name {
        "Logging" => {
            "<Logging><Version>1.0</Version><Read>false</Read><Write>false</Write><Delete>false</Delete><RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></Logging>"
        }
        "HourMetrics" => {
            "<HourMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>true</IncludeAPIs><RetentionPolicy><Enabled>true</Enabled><Days>7</Days></RetentionPolicy></HourMetrics>"
        }
        "MinuteMetrics" => {
            "<MinuteMetrics><Version>1.0</Version><Enabled>false</Enabled><RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></MinuteMetrics>"
        }
        _ => "<Cors />",
    }
}

pub(super) fn properties_response(stored: &BTreeMap<String, String>) -> Response {
    let mut document =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><StorageServiceProperties>");
    for name in SERVICE_ELEMENTS {
        document.push_str(
            stored
                .get(name)
                .map_or(default_element(name), String::as_str),
        );
    }
    document.push_str("</StorageServiceProperties>");
    xml_response(document)
}

pub(super) fn stats_response(now: SystemTime) -> Response {
    xml_response(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><StorageServiceStats><GeoReplication><Status>live</Status><LastSyncTime>{}</LastSyncTime></GeoReplication></StorageServiceStats>",
        httpdate::fmt_http_date(now)
    ))
}

fn xml_response(document: String) -> Response {
    let mut response = Response::new(axum::body::Body::from(document));
    response.headers_mut().insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/xml"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<SignedIdentifiers>
  <SignedIdentifier>
    <Id>read-only</Id>
    <AccessPolicy>
      <Start>2020-01-01T00:00:00.0000000Z</Start>
      <Expiry>2099-01-01T00:00:00Z</Expiry>
      <Permission>r</Permission>
    </AccessPolicy>
  </SignedIdentifier>
  <SignedIdentifier><Id>bare</Id></SignedIdentifier>
</SignedIdentifiers>"#;

    #[test]
    fn access_policies_parse_and_validate() {
        let policies = parse_acl(ACL.as_bytes()).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].id, "read-only");
        assert_eq!(policies[0].permission.as_deref(), Some("r"));
        assert_eq!(policies[1].expiry, None);
        assert_eq!(parse_acl(b"<SignedIdentifiers />").unwrap(), vec![]);
        for bad in [
            "<x/>",
            "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>z</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><Id>a</Id></SignedIdentifier><SignedIdentifier><Id>a</Id></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><AccessPolicy/></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Expiry>soon</Expiry></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
            "not xml",
        ] {
            assert!(parse_acl(bad.as_bytes()).is_err(), "{bad}");
        }
        let six: String = (0..6)
            .map(|i| format!("<SignedIdentifier><Id>i{i}</Id></SignedIdentifier>"))
            .collect();
        assert!(
            parse_acl(format!("<SignedIdentifiers>{six}</SignedIdentifiers>").as_bytes()).is_err()
        );
    }

    #[test]
    fn service_property_updates_split_into_top_level_elements() {
        let body = "<?xml version=\"1.0\"?><StorageServiceProperties>\n  <Logging><Version>1.0</Version><Read>true</Read></Logging>\n  <Cors/>\n</StorageServiceProperties>";
        let parsed = parse_properties(body.as_bytes()).unwrap();
        assert_eq!(
            parsed["Logging"],
            "<Logging><Version>1.0</Version><Read>true</Read></Logging>"
        );
        assert_eq!(parsed["Cors"], "<Cors/>");
        assert_eq!(parsed.len(), 2);
        for bad in [
            "<StorageServiceProperties/>",
            "<StorageServiceProperties><Unknown/></StorageServiceProperties>",
            "<Other><Cors/></Other>",
            "<StorageServiceProperties><Cors/><Cors/></StorageServiceProperties>",
            "<StorageServiceProperties><Cors>",
        ] {
            assert!(parse_properties(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
