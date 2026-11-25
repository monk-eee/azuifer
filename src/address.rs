//! Path-style and host-style Blob addressing.
//!
//! `http://127.0.0.1:10000/{account}/{container}/{blob}` names the account in
//! the first path segment. `http://{account}.blob.localhost:10000/{container}/{blob}`
//! (and any `{account}.blob.{domain}`) names it in the host. Either way the rest
//! of the code sees the path-style form; only the signing path differs.

use crate::domain::AccountName;

/// The account named by a host-style `Host` header, if the header has that form.
pub(crate) fn host_account(host: Option<&str>) -> Option<AccountName> {
    let host = host?;
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        host.split(':').next()?
    };
    let mut labels = name.split('.');
    let account = labels.next()?;
    if labels.next()? != "blob" || labels.next().is_none() {
        return None;
    }
    AccountName::parse(&account.to_ascii_lowercase()).ok()
}

/// The path-style form of a request path, given the account from the host if any.
pub(crate) fn logical_path(host_account: Option<&AccountName>, path: &str) -> String {
    match host_account {
        Some(account) => format!("/{}{path}", account.as_str()),
        None => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_style_names_the_account_before_the_blob_label() {
        let account = |host| host_account(Some(host)).map(|a| a.as_str().to_owned());
        assert_eq!(
            account("devstoreaccount1.blob.localhost:10000").as_deref(),
            Some("devstoreaccount1")
        );
        assert_eq!(
            account("myacct.blob.core.windows.net").as_deref(),
            Some("myacct")
        );
        assert_eq!(account("127.0.0.1:10000"), None);
        assert_eq!(account("localhost:10000"), None);
        assert_eq!(account("acct.queue.localhost"), None);
        assert_eq!(account("blob.localhost"), None);
        assert_eq!(account("UPPER.blob.localhost").as_deref(), Some("upper"));
        assert_eq!(host_account(None).map(|a| a.as_str().to_owned()), None);
    }

    #[test]
    fn logical_paths_prefix_the_account_only_for_host_style() {
        let account = AccountName::parse("acct1").unwrap();
        assert_eq!(logical_path(Some(&account), "/c/b"), "/acct1/c/b");
        assert_eq!(logical_path(Some(&account), "/"), "/acct1/");
        assert_eq!(logical_path(None, "/acct1/c"), "/acct1/c");
    }
}
