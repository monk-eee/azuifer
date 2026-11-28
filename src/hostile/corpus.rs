use crate::{address, auth, blob_batch, conditions::Guard, domain, protocol, sas, service_props};
use axum::http::{HeaderMap, Request, request::Parts};
use std::{fs, path::Path};

/// Replays a directory of fixed protocol cases in file-name order on a small stack.
pub(crate) fn replay(category: &str, check: impl Fn(&[u8]) -> bool + Send + 'static) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join(category);
    let mut cases: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("read corpus directory entry"))
        .collect();
    assert!(!cases.is_empty(), "{}: empty corpus", dir.display());
    cases.sort_unstable_by_key(fs::DirEntry::file_name);
    super::on_small_stack(move || {
        for entry in cases {
            let path = entry.path();
            let expected = match path.extension().and_then(|ext| ext.to_str()) {
                Some("ok") => true,
                Some("err") => false,
                _ => panic!("{}: expected a .ok or .err case", path.display()),
            };
            assert!(
                entry.file_type().unwrap().is_file() && entry.metadata().unwrap().len() <= 65536,
                "{}: expected a regular file no larger than 64 KiB",
                path.display(),
            );
            let input =
                fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(check(&input), expected, "{}", path.display());
        }
    });
}

fn request_parts(input: &[u8]) -> Option<Parts> {
    let mut lines = std::str::from_utf8(input).ok()?.lines();
    let (method, uri) = lines.next()?.split_once(' ')?;
    let mut request = Request::builder().method(method).uri(uri);
    for line in lines {
        let (name, value) = line.split_once(':')?;
        request = request.header(name, value.trim_start());
    }
    Some(request.body(()).ok()?.into_parts().0)
}

#[test]
fn replay_uri_and_address_corpus() {
    replay("uri_and_address", |input| {
        let Some(parts) = request_parts(input) else {
            return false;
        };
        let (path, _) = address::resolve("blob", &parts);
        protocol::parse_target(&path).is_ok_and(|target| target.account().as_str() == "testaccount")
            && protocol::parse_query(parts.uri.query()).is_ok()
            && Guard::parse(&parts.headers).is_ok()
            && auth::header(&parts.headers, "range").is_ok_and(|value| {
                value.is_none_or(|value| domain::ByteRange::parse(value).is_ok())
            })
    });
}

#[test]
fn replay_blob_xml_and_batch_corpus() {
    replay("xml_bodies/block_list", |input| {
        protocol::parse_block_list(input).is_ok()
    });
    replay("xml_bodies/service_properties", |input| {
        service_props::ServiceProperties::parse(input).is_ok()
    });
    replay("xml_bodies/blob_batch", |input| {
        blob_batch::parse_body(input, "fixture").is_ok()
    });
}

#[test]
fn replay_sas_time_window_corpus() {
    replay("sas_token", |input| {
        let Ok(input) = std::str::from_utf8(input) else {
            return false;
        };
        let dates: Vec<_> = input.lines().map(sas::parse_time).collect();
        let [Ok(start), Ok(expiry), Ok(now)] = dates.as_slice() else {
            return false;
        };
        sas::check_window(Some(*start), Some(*expiry), *now).is_ok()
    });
}

#[test]
fn replay_shared_key_canonicalization_corpus() {
    replay("shared_key", |input| {
        let Some(parts) = request_parts(input) else {
            return false;
        };
        let Ok(query) = protocol::parse_query(parts.uri.query()) else {
            return false;
        };
        let account = domain::AccountName::parse("testaccount").unwrap();
        let canonical =
            |headers| auth::canonical(&account, &parts.method, parts.uri.path(), &query, headers);
        let Ok(message) = canonical(&parts.headers) else {
            return false;
        };
        let fields: Vec<_> = parts.headers.iter().collect();
        let mut reordered = HeaderMap::new();
        for (name, value) in fields.into_iter().rev() {
            reordered.append(name, value.clone());
        }
        assert_eq!(canonical(&reordered).unwrap(), message);
        assert!(
            message
                .lines()
                .any(|line| line == format!("/testaccount{}", parts.uri.path()))
        );
        true
    });
}
