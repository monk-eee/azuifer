//! User delegation keys and user-delegation SAS signing (ADR-0011).
//!
//! `Get User Delegation Key` hands a bearer-authenticated caller a random 32-byte
//! key. A SAS signed with that key carries `skoid`, `sktid`, `skt`, `ske`, `sks`,
//! and `skv`, and the key is found again from those fields. Keys live in memory,
//! so a restart invalidates every user-delegation SAS (a key is valid for at most
//! seven days anyway).

use crate::{
    domain::{AccountName, Error, Result, xml_safe},
    oauth::Principal,
    sas::{self, Sas},
    wire::{Xml, xml_error_with_details},
    xml_tree,
};
use axum::{http::StatusCode, response::Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::rand::{SecureRandom as _, SystemRandom};
use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_KEYS: usize = 1024;
const ZERO_GUID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Clone)]
pub(crate) struct Issued {
    account: String,
    pub(crate) oid: String,
    pub(crate) tid: String,
    pub(crate) start: SystemTime,
    pub(crate) expiry: SystemTime,
    pub(crate) value: [u8; 32],
}

#[derive(Default)]
pub(crate) struct Keys(Mutex<Vec<Issued>>);

impl Keys {
    pub(crate) fn issue(
        &self,
        account: &AccountName,
        principal: &Principal,
        window: (SystemTime, SystemTime),
        now: SystemTime,
    ) -> Result<Issued> {
        let mut value = [0; 32];
        SystemRandom::new()
            .fill(&mut value)
            .map_err(|_| Error::Internal)?;
        let issued = Issued {
            account: account.as_str().to_owned(),
            oid: principal.oid.clone().unwrap_or_else(|| ZERO_GUID.into()),
            tid: principal.tid.clone().unwrap_or_else(|| ZERO_GUID.into()),
            start: window.0,
            expiry: window.1,
            value,
        };
        let mut keys = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        keys.retain(|key| key.expiry > now);
        if keys.len() >= MAX_KEYS {
            keys.remove(0);
        }
        keys.push(issued.clone());
        Ok(issued)
    }

    /// The signing key a SAS names with `skoid`, `sktid`, `skt`, and `ske`, and its lifetime.
    pub(crate) fn find(
        &self,
        account: &AccountName,
        sas: &Sas,
    ) -> Result<(Vec<u8>, (SystemTime, SystemTime))> {
        let time = |name| sas::parse_time(sas.field(name));
        let window = (time("skt")?, time("ske")?);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|key| {
                key.account == account.as_str()
                    && key.oid == sas.field("skoid")
                    && key.tid == sas.field("sktid")
                    && (key.start, key.expiry) == window
            })
            .map(|key| (key.value.to_vec(), window))
            .ok_or(Error::AuthenticationFailed)
    }
}

/// Parses the `KeyInfo` body, issues a key for the bearer caller, and writes the
/// `UserDelegationKey` document.
pub(crate) fn respond(
    keys: &Keys,
    account: &AccountName,
    principal: &Principal,
    body: &[u8],
    now: SystemTime,
    version: &str,
    request_id: &str,
) -> Result<Response> {
    let root = parse_key_info(body)?;
    let window = match parse_window(&root, now) {
        Ok(window) => window,
        Err(WindowError::NodeValue(field, value)) if xml_safe(value) => {
            let message = format!(
                "The value for one of the XML nodes is not in the correct format.\nRequestId:{request_id}\nTime:{}",
                sas::format_time(now)
            );
            return Ok(xml_error_with_details(
                StatusCode::BAD_REQUEST,
                "InvalidXmlNodeValue",
                &message,
                &[("XmlNodeName", field.name()), ("XmlNodeValue", value)],
            ));
        }
        Err(WindowError::NodeValue(..)) => return Err(Error::InvalidXml),
        Err(WindowError::TooLong) => return Err(Error::InvalidInput),
    };
    let key = keys.issue(account, principal, window, now)?;
    let mut xml = Xml::root("UserDelegationKey", &[]);
    xml.element("SignedOid", &key.oid);
    xml.element("SignedTid", &key.tid);
    xml.element("SignedStart", &sas::format_time(key.start));
    xml.element("SignedExpiry", &sas::format_time(key.expiry));
    xml.element("SignedService", "b");
    xml.element("SignedVersion", version);
    xml.element("Value", &STANDARD.encode(key.value));
    Ok(xml.finish("UserDelegationKey", StatusCode::OK))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowField {
    Start,
    Expiry,
}

impl WindowField {
    fn name(self) -> &'static str {
        match self {
            Self::Start => "Start",
            Self::Expiry => "Expiry",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum WindowError<'a> {
    NodeValue(WindowField, &'a str),
    TooLong,
}

fn parse_key_info(body: &[u8]) -> Result<xml_tree::Node> {
    let root = xml_tree::parse(body)?;
    if root.name == "KeyInfo" {
        Ok(root)
    } else {
        Err(Error::InvalidXml)
    }
}

/// `<KeyInfo><Start/><Expiry/></KeyInfo>`: start defaults to now, expiry is
/// required and at most seven days after the start. Times have whole seconds.
fn parse_window(
    root: &xml_tree::Node,
    now: SystemTime,
) -> std::result::Result<(SystemTime, SystemTime), WindowError<'_>> {
    let whole = |time: SystemTime| {
        let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
    };
    let read = |field: WindowField, default| {
        let text = root.text_of(field.name());
        let time = match text {
            Some(value) => sas::parse_time(value).ok(),
            None => default,
        };
        let value = text.unwrap_or_default();
        time.and_then(whole)
            .map(|time| (time, value))
            .ok_or(WindowError::NodeValue(field, value))
    };
    let (start, start_value) = read(WindowField::Start, Some(now))?;
    let (expiry, expiry_value) = read(WindowField::Expiry, None)?;
    if expiry <= now {
        return Err(WindowError::NodeValue(WindowField::Expiry, expiry_value));
    }
    if expiry <= start {
        return Err(WindowError::NodeValue(WindowField::Start, start_value));
    }
    if expiry
        .duration_since(start)
        .is_ok_and(|span| span > MAX_VALIDITY)
    {
        return Err(WindowError::TooLong);
    }
    Ok((start, expiry))
}

/// String-to-sign of a user-delegation SAS (signed versions 2018-11-09 and later).
/// 2020-02-10 added the snapshot or version time; 2020-12-06 the encryption scope;
/// 2025-07-05 the delegated user's tenant and object id; 2026-04-06 the signed request
/// headers and query parameters. Tokens that use those four optional features are
/// refused before signing is checked.
pub(crate) fn string_to_sign(sas: &Sas, canonical: &str, snapshot: &str) -> String {
    let version = sas.field("sv");
    let mut fields = vec![
        sas.field("sp"),
        sas.field("st"),
        sas.field("se"),
        canonical,
        sas.field("skoid"),
        sas.field("sktid"),
        sas.field("skt"),
        sas.field("ske"),
        sas.field("sks"),
        sas.field("skv"),
        sas.field("saoid"),
        sas.field("suoid"),
        sas.field("scid"),
    ];
    if version >= "2025-07-05" {
        fields.extend([sas.field("skdutid"), sas.field("sduoid")]);
    }
    fields.extend([sas.field("sip"), sas.field("spr"), version, sas.field("sr")]);
    if version >= "2020-02-10" {
        fields.push(snapshot);
    }
    if version >= "2020-12-06" {
        fields.push(sas.field("ses"));
    }
    if version >= "2026-04-06" {
        // The canonicalized signed request headers and query parameters (srh, srq) are always empty here.
        fields.extend(["", ""]);
    }
    fields.extend(["rscc", "rscd", "rsce", "rscl", "rsct"].map(|name| sas.field(name)));
    fields.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Query;

    fn at(text: &str) -> SystemTime {
        sas::parse_time(text).unwrap()
    }

    fn sas_with(version: &str) -> Sas {
        let mut query: Query = [
            ("sp", "racwd"),
            ("st", "2023-05-24T01:13:55Z"),
            ("se", "2023-05-24T09:13:55Z"),
            ("skoid", "oid"),
            ("sktid", "tid"),
            ("skt", "2023-05-24T01:13:55Z"),
            ("ske", "2023-05-25T01:13:55Z"),
            ("sks", "b"),
            ("skv", "2022-11-02"),
            ("saoid", "ao"),
            ("suoid", "uo"),
            ("scid", "cid"),
            ("sip", "198.51.100.10-198.51.100.20"),
            ("spr", "https"),
            ("sr", "b"),
            ("ses", "scope"),
            ("rscc", "cc"),
            ("rscd", "cd"),
            ("rsce", "ce"),
            ("rscl", "cl"),
            ("rsct", "ct"),
            ("sig", "x"),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
        query.insert("sv".into(), version.into());
        Sas::from_query(&query).unwrap().unwrap()
    }

    #[test]
    fn the_string_to_sign_follows_the_documented_layout_for_each_signed_version() {
        let head = "racwd\n2023-05-24T01:13:55Z\n2023-05-24T09:13:55Z\n/blob/acct/c/b\noid\ntid\n2023-05-24T01:13:55Z\n2023-05-25T01:13:55Z\nb\n2022-11-02\nao\nuo\ncid";
        let tail = "198.51.100.10-198.51.100.20\nhttps";
        let sign = |version| string_to_sign(&sas_with(version), "/blob/acct/c/b", "SNAP");
        assert_eq!(
            sign("2023-11-03"),
            format!("{head}\n{tail}\n2023-11-03\nb\nSNAP\nscope\ncc\ncd\nce\ncl\nct")
        );
        assert_eq!(
            sign("2020-12-06"),
            format!("{head}\n{tail}\n2020-12-06\nb\nSNAP\nscope\ncc\ncd\nce\ncl\nct")
        );
        assert_eq!(
            sign("2020-02-10"),
            format!("{head}\n{tail}\n2020-02-10\nb\nSNAP\ncc\ncd\nce\ncl\nct")
        );
        assert_eq!(
            sign("2018-11-09"),
            format!("{head}\n{tail}\n2018-11-09\nb\ncc\ncd\nce\ncl\nct")
        );
        // 2025-07-05 adds the delegated user tenant and object id before the IP range.
        assert_eq!(
            sign("2025-07-05"),
            format!("{head}\n\n\n{tail}\n2025-07-05\nb\nSNAP\nscope\ncc\ncd\nce\ncl\nct")
        );
        // 2026-04-06 adds the (empty) canonicalized request headers and query parameters.
        assert_eq!(
            sign("2026-10-06"),
            format!("{head}\n\n\n{tail}\n2026-10-06\nb\nSNAP\nscope\n\n\ncc\ncd\nce\ncl\nct")
        );
    }

    #[test]
    fn key_info_defaults_the_start_and_bounds_the_lifetime() {
        let now = at("2029-01-01T10:00:00.750Z");
        let parse = |text: &str| parse_key_info(text.as_bytes()).unwrap();
        let default = parse("<KeyInfo><Expiry>2029-01-02T00:00:00Z</Expiry></KeyInfo>");
        let (start, expiry) = parse_window(&default, now).unwrap();
        assert_eq!(sas::format_time(start), "2029-01-01T10:00:00Z");
        assert_eq!(sas::format_time(expiry), "2029-01-02T00:00:00Z");
        let explicit = parse(
            "<KeyInfo><Start>2029-01-01T09:00:00Z</Start><Expiry>2029-01-08T09:00:00Z</Expiry></KeyInfo>",
        );
        assert!(
            parse_window(&explicit, now).is_ok(),
            "exactly seven days is allowed"
        );
        let long = parse(
            "<KeyInfo><Start>2029-01-01T09:00:00Z</Start><Expiry>2029-01-08T09:00:01Z</Expiry></KeyInfo>",
        );
        assert_eq!(parse_window(&long, now).err(), Some(WindowError::TooLong));
        let backwards = parse(
            "<KeyInfo><Start>2029-01-01T11:00:00Z</Start><Expiry>2029-01-01T10:30:00Z</Expiry></KeyInfo>",
        );
        assert_eq!(
            parse_window(&backwards, now).err(),
            Some(WindowError::NodeValue(
                WindowField::Start,
                "2029-01-01T11:00:00Z"
            ))
        );
        let expired = parse(
            "<KeyInfo><Start>2028-01-01T00:00:00Z</Start><Expiry>2028-01-02T00:00:00Z</Expiry></KeyInfo>",
        );
        assert_eq!(
            parse_window(&expired, now).err(),
            Some(WindowError::NodeValue(
                WindowField::Expiry,
                "2028-01-02T00:00:00Z"
            ))
        );
        let missing_expiry = parse("<KeyInfo><Start>2029-01-01T10:00:00Z</Start></KeyInfo>");
        assert_eq!(
            parse_window(&missing_expiry, now).err(),
            Some(WindowError::NodeValue(WindowField::Expiry, ""))
        );
        let invalid_expiry = parse("<KeyInfo><Expiry>tomorrow</Expiry></KeyInfo>");
        assert_eq!(
            parse_window(&invalid_expiry, now).err(),
            Some(WindowError::NodeValue(WindowField::Expiry, "tomorrow"))
        );
        assert_eq!(
            parse_key_info(b"<Other><Expiry>2029-01-02T00:00:00Z</Expiry></Other>").err(),
            Some(Error::InvalidXml)
        );
    }

    #[test]
    fn an_issued_key_is_found_only_by_its_exact_identity_and_expired_keys_are_dropped() {
        let keys = Keys::default();
        let account = AccountName::parse("acct").unwrap();
        let principal = Principal::default();
        let (start, expiry) = (at("2029-01-01T00:00:00Z"), at("2029-01-02T00:00:00Z"));
        let issued = keys
            .issue(&account, &principal, (start, expiry), start)
            .unwrap();
        assert_eq!(
            (issued.oid.as_str(), issued.tid.as_str()),
            (ZERO_GUID, ZERO_GUID)
        );
        let named = |skoid: &str, skt: &str| {
            let query: Query = [
                ("skoid", skoid),
                ("sktid", ZERO_GUID),
                ("skt", skt),
                ("ske", "2029-01-02T00:00:00Z"),
                ("sig", "x"),
            ]
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
            Sas::from_query(&query).unwrap().unwrap()
        };
        let found = keys.find(&account, &named(ZERO_GUID, "2029-01-01T00:00:00Z"));
        assert_eq!(found, Ok((issued.value.to_vec(), (start, expiry))));
        assert!(
            keys.find(&account, &named("other", "2029-01-01T00:00:00Z"))
                .is_err()
        );
        assert!(
            keys.find(&account, &named(ZERO_GUID, "2029-01-01T00:00:01Z"))
                .is_err()
        );
        let other = AccountName::parse("other").unwrap();
        assert!(
            keys.find(&other, &named(ZERO_GUID, "2029-01-01T00:00:00Z"))
                .is_err()
        );
        let second = keys
            .issue(&account, &principal, (start, expiry), start)
            .unwrap();
        assert_ne!(issued.value, second.value, "every key is random");
        keys.issue(&account, &principal, (expiry, expiry), expiry)
            .unwrap();
        assert!(
            keys.find(&account, &named(ZERO_GUID, "2029-01-01T00:00:00Z"))
                .is_err()
        );
    }
}
