//! Path-style and host-style addressing for every service.
//!
//! `http://127.0.0.1:10000/{account}/{container}/{blob}` names the account in
//! the first path segment. `http://{account}.blob.localhost:10000/{container}/{blob}`
//! (and any `{account}.{service}.{domain}`, with `blob`, `queue`, `table`, `file`
//! or `dfs` as the service) names it in the host. Either way the rest of the
//! code sees the path-style form; Shared Key and SAS verification sign the path
//! exactly as sent, so only the logical path gains the account.

use crate::domain::AccountName;
use axum::http::request::Parts;

/// The authority a client addressed, from `Host` or an HTTP/2 `:authority`.
pub(crate) fn request_host(parts: &Parts) -> Option<&str> {
    parts
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|value| value.to_str().ok())
        })
}

/// The lowercased first label of a host-style authority for `service`, if the
/// authority is `{label}.{service}.{domain}`.
pub(crate) fn host_label(service: &str, host: Option<&str>) -> Option<String> {
    let host = host?;
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        host.split(':').next()?
    };
    let mut labels = name.split('.');
    let label = labels.next()?;
    if !labels.next()?.eq_ignore_ascii_case(service) || labels.next().is_none() {
        return None;
    }
    Some(label.to_ascii_lowercase())
}

/// The account named by a host-style authority for `service`, if it has that form.
pub(crate) fn host_account(service: &str, host: Option<&str>) -> Option<AccountName> {
    AccountName::parse(&host_label(service, host)?).ok()
}

/// The suffix of the read-only secondary endpoint of a geo-redundant account.
pub(crate) const SECONDARY: &str = "-secondary";

/// Like [`host_account`], and also the account of a `{account}-secondary` host.
pub(crate) fn host_account_or_secondary(service: &str, host: Option<&str>) -> Option<AccountName> {
    let label = host_label(service, host)?;
    AccountName::parse(label.strip_suffix(SECONDARY).unwrap_or(&label)).ok()
}

/// The path-style form of a request path, given the account from the host if any.
pub(crate) fn logical_path(host_account: Option<&AccountName>, path: &str) -> String {
    match host_account {
        Some(account) => format!("/{}{path}", account.as_str()),
        None => path.to_owned(),
    }
}

/// The request path in path-style form for `service`, and the host when the
/// request used host-style addressing.
pub(crate) fn resolve<'a>(service: &str, parts: &'a Parts) -> (String, Option<&'a str>) {
    let host = request_host(parts);
    match host_account(service, host) {
        Some(account) => (logical_path(Some(&account), parts.uri.path()), host),
        None => (parts.uri.path().to_owned(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(service: &str, host: &str) -> Option<String> {
        host_account(service, Some(host)).map(|account| account.as_str().to_owned())
    }

    #[test]
    fn host_style_names_the_account_before_the_service_label() {
        assert_eq!(
            account("blob", "devstoreaccount1.blob.localhost:10000").as_deref(),
            Some("devstoreaccount1")
        );
        assert_eq!(
            account("blob", "myacct.blob.core.windows.net").as_deref(),
            Some("myacct")
        );
        for service in ["queue", "table", "file", "dfs"] {
            let host = format!("acct1.{service}.localhost:10001");
            assert_eq!(account(service, &host).as_deref(), Some("acct1"));
            assert_eq!(account("blob", &host), None);
        }
        assert_eq!(account("blob", "127.0.0.1:10000"), None);
        assert_eq!(account("blob", "localhost:10000"), None);
        assert_eq!(account("blob", "acct.queue.localhost"), None);
        assert_eq!(account("blob", "blob.localhost"), None);
        assert_eq!(account("blob", "[::1]:10000"), None);
        assert_eq!(
            account("blob", "UPPER.BLOB.localhost").as_deref(),
            Some("upper")
        );
        assert_eq!(account("blob", "not-an-account.blob.localhost"), None);
        assert!(host_account("blob", None).is_none());
    }

    #[test]
    fn host_labels_keep_the_secondary_suffix() {
        assert_eq!(
            host_label("table", Some("Acct-secondary.table.localhost:1")).as_deref(),
            Some("acct-secondary")
        );
        assert_eq!(
            host_label("queue", Some("acct-secondary.table.localhost")),
            None
        );
    }

    #[test]
    fn logical_paths_prefix_the_account_only_for_host_style() {
        let account = AccountName::parse("acct1").unwrap();
        assert_eq!(logical_path(Some(&account), "/c/b"), "/acct1/c/b");
        assert_eq!(logical_path(Some(&account), "/"), "/acct1/");
        assert_eq!(logical_path(None, "/acct1/c"), "/acct1/c");
    }

    #[test]
    fn resolve_reads_the_host_header_or_the_authority() {
        let parts = |uri: &str, host: Option<&str>| {
            let mut request = axum::http::Request::builder().uri(uri);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            request.body(()).unwrap().into_parts().0
        };
        let styled = parts("/q/messages", Some("acct1.queue.localhost:10001"));
        assert_eq!(
            resolve("queue", &styled),
            (
                "/acct1/q/messages".to_owned(),
                Some("acct1.queue.localhost:10001")
            )
        );
        let styled = parts("http://acct1.queue.localhost:10001/q", None);
        assert_eq!(
            resolve("queue", &styled),
            ("/acct1/q".to_owned(), Some("acct1.queue.localhost:10001"))
        );
        let plain = parts("/acct1/q", Some("127.0.0.1:10001"));
        assert_eq!(resolve("queue", &plain), ("/acct1/q".to_owned(), None));
        let other = parts("/acct1/q", Some("acct1.table.localhost:10001"));
        assert_eq!(resolve("queue", &other), ("/acct1/q".to_owned(), None));
    }
}
