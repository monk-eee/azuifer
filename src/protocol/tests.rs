//! Tests of request parsing: includes, queries, headers, and refused parameters.

use super::{
    headers::{content_headers, includes},
    *,
};
use crate::{compat::Relax, domain::Include, lease::LeaseDuration};

#[test]
fn include_values_are_case_insensitive() {
    // The .NET SDK sends include=Snapshots.
    let parsed = includes(Some("Snapshots,METADATA")).unwrap();
    assert!(matches!(
        parsed[..],
        [Include::Snapshots, Include::Metadata]
    ));
    assert!(includes(Some("nonsense")).is_err());
}
use axum::http::HeaderValue;

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
}

#[test]
fn query_rejects_ambiguous_signature_and_literal_line_breaks() {
    assert_eq!(
        parse_query(Some("COMP=list&comp=list")),
        Err(Error::InvalidQuery)
    );
    assert_eq!(
        parse_query(Some("prefix=%0aNext:value")),
        Err(Error::InvalidQuery)
    );
    assert_eq!(parse_query(Some("prefix=%ff")), Err(Error::InvalidQuery));
    assert_eq!(parse_query(Some("prefix=%2")), Err(Error::InvalidQuery));
    assert_eq!(
        parse_query(Some("PreFix=a+%2B%2Fb"))
            .unwrap()
            .get("prefix")
            .map(String::as_str),
        Some("a +/b")
    );
    assert_eq!(decode("a+%2Fb", false).as_deref(), Some("a+/b"));
}

#[test]
fn blob_headers_prefer_the_blob_specific_form_and_report_whether_any_were_sent() {
    let sent = headers(&[
        ("x-ms-blob-content-type", "text/plain"),
        ("content-type", "ignored/for-properties"),
        ("content-encoding", "gzip"),
        ("x-ms-blob-cache-control", "no-store"),
    ]);
    let (props, supplied) = content_headers(&sent, true).unwrap();
    assert!(supplied);
    assert_eq!(props.content_type, "text/plain");
    assert_eq!(
        (props.encoding.as_str(), props.cache_control.as_str()),
        ("gzip", "no-store")
    );
    let (props, supplied) = content_headers(&sent, false).unwrap();
    assert_eq!((props.encoding.as_str(), supplied), ("", true));
    let (props, supplied) = content_headers(&headers(&[]), true).unwrap();
    assert_eq!(
        (props.content_type.as_str(), supplied),
        ("application/octet-stream", false)
    );
    assert!(content_headers(&headers(&[("x-ms-blob-content-type", "")]), true).is_err());
}

#[test]
fn lease_headers_map_to_actions_and_reject_invalid_values() {
    let id = "00000000-0000-0000-0000-000000000001";
    let other = "00000000-0000-0000-0000-000000000002";
    let acquire = headers(&[
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "-1"),
    ]);
    assert!(matches!(
        lease_action(&acquire),
        Ok(LeaseAction::Acquire {
            duration: LeaseDuration::Infinite,
            proposed: None
        })
    ));
    let change = headers(&[
        ("x-ms-lease-action", "change"),
        ("x-ms-lease-id", id),
        ("x-ms-proposed-lease-id", other),
    ]);
    assert!(matches!(
        lease_action(&change),
        Ok(LeaseAction::Change { .. })
    ));
    let brk = headers(&[
        ("x-ms-lease-action", "break"),
        ("x-ms-lease-break-period", "61"),
    ]);
    assert_eq!(lease_action(&brk).err(), Some(Error::InvalidHeader));
    let renew = headers(&[("x-ms-lease-action", "renew")]);
    assert_eq!(lease_action(&renew).err(), Some(Error::MissingHeader));
    let short = headers(&[
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "5"),
    ]);
    assert_eq!(lease_action(&short).err(), Some(Error::InvalidHeader));
}

#[test]
fn unimplemented_headers_and_parameters_are_refused() {
    let policy = crate::compat::Policy::default();
    let relax = Relax::new(&policy, "blob", "test");
    let query = Query::from([("snapshot".to_owned(), "x".to_owned())]);
    assert_eq!(
        check(&query, &headers(&[]), &[], &[], false, &relax),
        Err(Error::Unsupported)
    );
    let tags = headers(&[("x-ms-tags", "a=b")]);
    assert_eq!(
        check(&Query::new(), &tags, &[], &[], false, &relax),
        Err(Error::Unsupported)
    );
    let browser = headers(&[("x-ms-useragent", "azsdk-js")]);
    assert_eq!(
        check(&Query::new(), &browser, &[], &[], false, &relax),
        Err(Error::Unsupported),
        "strict mode refuses the browser SDK's user-agent header"
    );
    let timeout = Query::from([("timeout".to_owned(), "30".to_owned())]);
    assert_eq!(
        check(
            &timeout,
            &headers(&[("origin", "https://a.test")]),
            &[],
            &[],
            false,
            &relax
        ),
        Ok(())
    );
}

#[test]
fn lenient_mode_ignores_only_the_names_it_lists() {
    let policy = crate::compat::Policy::resolve(
        Some(crate::compat::Mode::Lenient),
        Some("x-ms-trace-hint,cachebust"),
    )
    .unwrap();
    let relax = Relax::new(&policy, "blob", "test");
    let ignored = headers(&[("x-ms-useragent", "azsdk-js"), ("x-ms-trace-hint", "1")]);
    let query = Query::from([("cachebust".to_owned(), "7".to_owned())]);
    assert_eq!(check(&query, &ignored, &[], &[], false, &relax), Ok(()));
    for refused in [
        headers(&[("x-ms-tags", "a=b")]),
        headers(&[("x-ms-encryption-scope", "scope")]),
        headers(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")]),
        headers(&[("if-match", "*")]),
        headers(&[("x-ms-unlisted", "1")]),
    ] {
        assert_eq!(
            check(&Query::new(), &refused, &[], &[], false, &relax),
            Err(Error::Unsupported),
            "{refused:?}"
        );
    }
    let snapshot = Query::from([("snapshot".to_owned(), "x".to_owned())]);
    assert_eq!(
        check(&snapshot, &headers(&[]), &[], &[], false, &relax),
        Err(Error::Unsupported)
    );
}

#[test]
fn listing_includes_name_what_they_support() {
    assert_eq!(
        includes(Some("metadata,copy,uncommittedblobs"))
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        includes(Some("snapshots,versions,deleted,tags"))
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        includes(Some("immutabilitypolicy,legalhold"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        includes(Some("permissions")).err(),
        Some(Error::Unsupported)
    );
    assert!(includes(None).unwrap().is_empty());
}

#[test]
fn hostile_block_lists_and_batch_boundaries_are_answered_without_panic() {
    let seed = "<?xml version=\"1.0\"?><BlockList><Committed>QUFBQQ==</Committed><Uncommitted>QkJCQg==</Uncommitted><Latest>Q0NDQw==</Latest></BlockList>";
    assert_eq!(parse_block_list(seed.as_bytes()).unwrap().len(), 3);
    crate::hostile::sweep(&[seed], ("<Latest>", "</Latest>"), |text| {
        let _ = parse_block_list(text.as_bytes());
    });
    let many = format!(
        "<BlockList>{}</BlockList>",
        "<Latest>QUFBQQ==</Latest>".repeat(100_000)
    );
    assert!(parse_block_list(many.as_bytes()).is_err());
}
