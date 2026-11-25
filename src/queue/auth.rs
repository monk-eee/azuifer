use super::{
    App,
    error::{QueueError, Result},
    model::QueueName,
    protocol::Request,
    time,
};
use crate::{
    auth::{self, Query, header},
    domain::AccountName,
    sas::Sas,
};
use axum::http::{HeaderMap, Method, request::Parts};
use std::time::SystemTime;

/// Authenticates a request with Shared Key, Shared Key Lite, an account SAS, or
/// a service SAS; anonymous requests are always rejected for Queue.
pub(super) async fn authorize(app: &App, parts: &Parts, request: &Request) -> Result<()> {
    let keys = app
        .config
        .accounts
        .get(&request.account)
        .ok_or(QueueError::AuthenticationFailed)?;
    let authorization = header(&parts.headers, "authorization")?;
    let now = app.clock.now();
    match (authorization, request.query.contains_key("sig")) {
        (Some(_), true) => Err(QueueError::InvalidAuthenticationInfo),
        (None, false) => Err(QueueError::AuthenticationFailed),
        (Some(value), false) => match value.split_once(' ').map_or(value, |(scheme, _)| scheme) {
            "SharedKey" => Ok(auth::verify(
                &request.account,
                keys,
                &parts.method,
                parts.uri.path(),
                &request.query,
                &parts.headers,
                now,
            )?),
            "SharedKeyLite" => verify_lite(
                &request.account,
                keys,
                &parts.method,
                parts.uri.path(),
                &request.query,
                &parts.headers,
                now,
            ),
            _ => Err(QueueError::InvalidAuthenticationInfo),
        },
        (None, true) => authorize_sas(app, keys, request, now).await,
    }
}

fn verify_lite(
    account: &AccountName,
    keys: &[Vec<u8>],
    method: &Method,
    raw_path: &str,
    query: &Query,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<()> {
    let authorization =
        header(headers, "authorization")?.ok_or(QueueError::AuthenticationFailed)?;
    let (_, credentials) = authorization
        .split_once(' ')
        .ok_or(QueueError::AuthenticationFailed)?;
    let (name, signature) = credentials
        .split_once(':')
        .ok_or(QueueError::AuthenticationFailed)?;
    if name != account.as_str() {
        return Err(QueueError::AuthenticationFailed);
    }
    let date = header(headers, "x-ms-date")?
        .or(header(headers, "date")?)
        .ok_or(QueueError::AuthenticationFailed)?;
    auth::check_skew(date, now)?;
    let message = lite_string(account, method, raw_path, query, headers)?;
    Ok(auth::verify_signature(keys, &message, signature)?)
}

/// `VERB, Content-MD5, Content-Type, Date, CanonicalizedHeaders` followed by a
/// resource that only carries the `comp` query parameter.
fn lite_string(
    account: &AccountName,
    method: &Method,
    raw_path: &str,
    query: &Query,
    headers: &HeaderMap,
) -> Result<String> {
    let value = |name| header(headers, name).map(Option::unwrap_or_default);
    let date = if headers.contains_key("x-ms-date") {
        ""
    } else {
        value("date")?
    };
    let mut text = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        value("content-md5")?,
        value("content-type")?,
        date,
        auth::canonical_headers(headers)?
    );
    text.push('/');
    text.push_str(account.as_str());
    text.push_str(raw_path);
    if let Some(comp) = query.get("comp") {
        text.push_str("?comp=");
        text.push_str(comp);
    }
    Ok(text)
}

async fn authorize_sas(
    app: &App,
    keys: &[Vec<u8>],
    request: &Request,
    now: SystemTime,
) -> Result<()> {
    let grant = request
        .operation
        .grant()
        .ok_or(QueueError::PermissionMismatch)?;
    let query = &request.query;
    if query.contains_key("ss") || query.contains_key("srt") {
        let sas = Sas::from_query(query)?.ok_or(QueueError::AuthenticationFailed)?;
        sas.verify(keys, &account_string(&request.account, &sas))?;
        sas.check_window(now)?;
        check_protocol(&sas)?;
        if !sas.field("ss").contains('q') {
            return Err(QueueError::ServiceMismatch);
        }
        if !sas.field("srt").contains(grant.scope.letter()) {
            return Err(QueueError::ResourceTypeMismatch);
        }
        if !grant
            .account
            .chars()
            .any(|letter| sas.allows(&letter.to_string()))
        {
            return Err(QueueError::PermissionMismatch);
        }
        return Ok(());
    }

    let queue = request
        .operation
        .queue()
        .ok_or(QueueError::PermissionMismatch)?;
    let signed = service_string(query, &request.account, queue);
    let mut effective = query.clone();
    if let Some(identifier) = query.get("si").filter(|id| !id.is_empty()) {
        let policies = app
            .store
            .acl(request.account.clone(), queue.as_str().to_owned())
            .await
            .map_err(|error| match error {
                QueueError::QueueNotFound => QueueError::AuthenticationFailed,
                other => other,
            })?;
        let policy = policies
            .iter()
            .find(|policy| policy.id == *identifier)
            .ok_or(QueueError::AuthenticationFailed)?;
        let stored = [
            ("sp", Some(policy.permission.clone())),
            ("st", policy.start.map(time::iso8601)),
            ("se", policy.expiry.map(time::iso8601)),
        ];
        for (name, value) in stored {
            if let Some(value) = value
                && effective.get(name).is_none_or(String::is_empty)
            {
                effective.insert(name.to_owned(), value);
            }
        }
    }
    let sas = Sas::from_query(&effective)?.ok_or(QueueError::AuthenticationFailed)?;
    sas.verify(keys, &signed)?;
    sas.check_window(now)?;
    check_protocol(&sas)?;
    match grant.service {
        Some(letter) if sas.allows(&letter.to_string()) => Ok(()),
        _ => Err(QueueError::PermissionMismatch),
    }
}

/// The emulator listens on plain HTTP, so a SAS limited to HTTPS can never match.
fn check_protocol(sas: &Sas) -> Result<()> {
    let protocol = sas.field("spr");
    if !protocol.is_empty()
        && protocol
            .split(',')
            .all(|item| item.trim().eq_ignore_ascii_case("https"))
    {
        return Err(QueueError::ProtocolMismatch);
    }
    Ok(())
}

fn account_string(account: &AccountName, sas: &Sas) -> String {
    let mut text = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        account.as_str(),
        sas.field("sp"),
        sas.field("ss"),
        sas.field("srt"),
        sas.field("st"),
        sas.field("se"),
        sas.field("sip"),
        sas.field("spr"),
        sas.field("sv"),
    );
    if sas.field("sv") >= "2020-12-06" {
        text.push_str(sas.field("ses"));
        text.push('\n');
    }
    text
}

/// String-to-sign for a Queue service SAS; later signed versions add the
/// service-prefixed resource (2015-02-21), IP and protocol (2015-04-05).
fn service_string(query: &Query, account: &AccountName, queue: &QueueName) -> String {
    let field = |name: &str| query.get(name).map_or("", String::as_str);
    let version = field("sv");
    let resource = if version >= "2015-02-21" {
        format!("/queue/{}/{}", account.as_str(), queue.as_str())
    } else {
        format!("/{}/{}", account.as_str(), queue.as_str())
    };
    let mut lines = vec![
        field("sp"),
        field("st"),
        field("se"),
        &resource,
        field("si"),
    ];
    if version >= "2015-04-05" {
        lines.push(field("sip"));
        lines.push(field("spr"));
    }
    if version >= "2012-02-12" {
        lines.push(version);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn query(pairs: &[(&str, &str)]) -> Query {
        pairs
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect()
    }

    fn account() -> AccountName {
        AccountName::parse("myaccount").unwrap()
    }

    #[test]
    fn shared_key_lite_matches_the_published_example() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("content-type", "text/plain; charset=UTF-8"),
            ("x-ms-date", "Sun, 20 Sep 2009 20:36:40 GMT"),
            ("x-ms-meta-m1", "v1"),
            ("x-ms-meta-m2", "v2"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let actual = lite_string(
            &AccountName::parse("testaccount1").unwrap(),
            &Method::PUT,
            "/mycontainer/hello.txt",
            &Query::new(),
            &headers,
        )
        .unwrap();
        assert_eq!(
            actual,
            "PUT\n\ntext/plain; charset=UTF-8\n\nx-ms-date:Sun, 20 Sep 2009 20:36:40 GMT\nx-ms-meta-m1:v1\nx-ms-meta-m2:v2\n/testaccount1/mycontainer/hello.txt"
        );
    }

    #[test]
    fn shared_key_lite_signs_only_the_comp_parameter_and_the_date_header_without_x_ms_date() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            HeaderValue::from_static("Sat, 21 Feb 2015 00:48:38 GMT"),
        );
        headers.insert("x-ms-version", HeaderValue::from_static("2023-11-03"));
        let actual = lite_string(
            &account(),
            &Method::GET,
            "/myaccount/q",
            &query(&[("comp", "metadata"), ("timeout", "20")]),
            &headers,
        )
        .unwrap();
        assert_eq!(
            actual,
            "GET\n\n\nSat, 21 Feb 2015 00:48:38 GMT\nx-ms-version:2023-11-03\n/myaccount/myaccount/q?comp=metadata"
        );
    }

    #[test]
    fn service_sas_string_follows_the_signed_version() {
        let queue = QueueName::parse("thumbnails").unwrap();
        let base = [
            ("sp", "raup"),
            ("st", "2024-01-01T00:00:00Z"),
            ("se", "2024-01-02T00:00:00Z"),
            ("si", "policy"),
            ("sip", "10.0.0.1"),
            ("spr", "https,http"),
        ];
        let with = |version: &str| {
            let mut pairs = base.to_vec();
            pairs.push(("sv", version));
            service_string(&query(&pairs), &account(), &queue)
        };
        assert_eq!(
            with("2023-11-03"),
            "raup\n2024-01-01T00:00:00Z\n2024-01-02T00:00:00Z\n/queue/myaccount/thumbnails\npolicy\n10.0.0.1\nhttps,http\n2023-11-03"
        );
        assert_eq!(
            with("2015-02-21"),
            "raup\n2024-01-01T00:00:00Z\n2024-01-02T00:00:00Z\n/queue/myaccount/thumbnails\npolicy\n2015-02-21"
        );
        assert_eq!(
            with("2013-08-15"),
            "raup\n2024-01-01T00:00:00Z\n2024-01-02T00:00:00Z\n/myaccount/thumbnails\npolicy\n2013-08-15"
        );
        let legacy = service_string(&query(&base), &account(), &queue);
        assert_eq!(
            legacy,
            "raup\n2024-01-01T00:00:00Z\n2024-01-02T00:00:00Z\n/myaccount/thumbnails\npolicy"
        );
    }

    #[test]
    fn account_sas_string_adds_the_encryption_scope_from_2020_12_06() {
        let sas = |version: &str| {
            let q = query(&[
                ("sv", version),
                ("ss", "q"),
                ("srt", "sco"),
                ("sp", "rwdlacup"),
                ("se", "2030-01-01T00:00:00Z"),
                ("spr", "https"),
                ("ses", "scope1"),
                ("sig", "x"),
            ]);
            account_string(&account(), &Sas::from_query(&q).unwrap().unwrap())
        };
        assert_eq!(
            sas("2023-11-03"),
            "myaccount\nrwdlacup\nq\nsco\n\n2030-01-01T00:00:00Z\n\nhttps\n2023-11-03\nscope1\n"
        );
        assert_eq!(
            sas("2019-02-02"),
            "myaccount\nrwdlacup\nq\nsco\n\n2030-01-01T00:00:00Z\n\nhttps\n2019-02-02\n"
        );
    }

    #[test]
    fn https_only_sas_is_rejected_on_the_plain_http_listener() {
        let check = |spr: &str| {
            let q = query(&[("se", "2030-01-01"), ("spr", spr), ("sig", "x")]);
            check_protocol(&Sas::from_query(&q).unwrap().unwrap())
        };
        assert_eq!(check("https"), Err(QueueError::ProtocolMismatch));
        assert_eq!(check("https,http"), Ok(()));
        assert_eq!(check(""), Ok(()));
    }
}
