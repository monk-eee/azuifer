use crate::domain::{AccountName, Error, Result};
use axum::http::{HeaderMap, Method};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

const SIGNED_HEADERS: [&str; 11] = [
    "content-encoding",
    "content-language",
    "content-length",
    "content-md5",
    "content-type",
    "date",
    "if-modified-since",
    "if-match",
    "if-none-match",
    "if-unmodified-since",
    "range",
];

pub(crate) type Query = BTreeMap<String, String>;

pub(crate) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Error::InvalidHeader);
    }
    first
        .map(|v| v.to_str().map_err(|_| Error::InvalidHeader))
        .transpose()
}

pub(crate) fn verify(
    account: &AccountName,
    keys: &[Vec<u8>],
    method: &Method,
    raw_path: &str,
    query: &Query,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<()> {
    let authorization = header(headers, "authorization")?.ok_or(Error::AuthenticationFailed)?;
    let (scheme, credentials) = authorization
        .split_once(' ')
        .ok_or(Error::AuthenticationFailed)?;
    if scheme != "SharedKey" {
        return Err(Error::Unsupported);
    }
    let (name, signature) = credentials
        .split_once(':')
        .ok_or(Error::AuthenticationFailed)?;
    if name != account.as_str() {
        return Err(Error::AuthenticationFailed);
    }
    let date = header(headers, "x-ms-date")?
        .or(header(headers, "date")?)
        .ok_or(Error::AuthenticationFailed)?;
    check_skew(date, now)?;
    let message = canonical(account, method, raw_path, query, headers)?;
    verify_signature(keys, &message, signature)
}

/// Rejects a request date more than 15 minutes away from `now`.
pub(crate) fn check_skew(date: &str, now: SystemTime) -> Result<()> {
    let date = httpdate::parse_http_date(date).map_err(|_| Error::AuthenticationFailed)?;
    if now
        .duration_since(date)
        .or_else(|_| date.duration_since(now))
        .map_err(|_| Error::AuthenticationFailed)?
        > Duration::from_secs(900)
    {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

/// Checks a Base64 HMAC-SHA256 signature of `message` against any account key
/// in constant time, so either of two rotating keys validates.
pub(crate) fn verify_signature(keys: &[Vec<u8>], message: &str, signature: &str) -> Result<()> {
    let signature = STANDARD
        .decode(signature)
        .map_err(|_| Error::AuthenticationFailed)?;
    let mut valid = false;
    for key in keys {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Internal)?;
        mac.update(message.as_bytes());
        valid |= mac.verify_slice(&signature).is_ok();
    }
    if !valid {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

pub(crate) fn canonical(
    account: &AccountName,
    method: &Method,
    raw_path: &str,
    query: &Query,
    headers: &HeaderMap,
) -> Result<String> {
    let mut text = method.as_str().to_owned();
    for name in SIGNED_HEADERS {
        text.push('\n');
        let value = header(headers, name)?.unwrap_or_default();
        if !(name == "content-length" && value == "0"
            || name == "date" && headers.contains_key("x-ms-date"))
        {
            text.push_str(value);
        }
    }
    text.push('\n');
    text.push_str(&canonical_headers(headers)?);
    text.push('/');
    text.push_str(account.as_str());
    text.push_str(raw_path);
    for (name, value) in query {
        text.push('\n');
        text.push_str(name);
        text.push(':');
        text.push_str(value);
    }
    Ok(text)
}

/// The canonicalized `x-ms-*` header block shared by Shared Key and Shared Key
/// Lite: lowercase names in order, folded values, one line each.
pub(crate) fn canonical_headers(headers: &HeaderMap) -> Result<String> {
    let mut extension_headers = BTreeMap::new();
    for (name, value) in headers {
        let name = name.as_str();
        if name.starts_with("x-ms-") {
            let value = value.to_str().map_err(|_| Error::InvalidHeader)?;
            if extension_headers.insert(name, value).is_some() {
                return Err(Error::InvalidHeader);
            }
        }
    }
    let mut text = String::new();
    for (name, value) in extension_headers {
        text.push_str(name);
        text.push(':');
        text.push_str(&fold_whitespace(value));
        text.push('\n');
    }
    Ok(text)
}

pub(crate) fn fold_whitespace(value: &str) -> String {
    let mut out = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut space = false;
    for ch in value.trim_matches([' ', '\t']).chars() {
        if !quoted && matches!(ch, ' ' | '\t') {
            space = true;
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(ch);
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn canonical_request_preserves_path_and_orders_headers_and_query() {
        let account = AccountName::parse("testaccount").unwrap();
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-ms-version", "2023-11-03"),
            ("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
            ("content-length", "0"),
            ("date", "ignored"),
            ("x-ms-meta-note", "one   \"two  three\""),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let query = Query::from([
            ("restype".into(), "container".into()),
            ("comp".into(), "list".into()),
        ]);
        let actual = canonical(
            &account,
            &Method::GET,
            "/testaccount/container%2Fname",
            &query,
            &headers,
        )
        .unwrap();
        let expected = concat!(
            "GET\n\n\n\n\n\n\n\n\n\n\n\n",
            "x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\n",
            "x-ms-meta-note:one \"two  three\"\n",
            "x-ms-version:2023-11-03\n",
            "/testaccount/testaccount/container%2Fname\ncomp:list\nrestype:container",
        );
        assert_eq!(actual, expected);
    }
}
