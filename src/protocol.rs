use crate::{
    auth::{self, Query, header},
    config::Config,
    domain::{
        AccountName, ApiVersion, BlobKey, BlobPath, ByteRange, Condition, ContainerKey,
        ContainerName, ContentLength, Error, Metadata, PageRequest, Result, xml_safe,
    },
};
use axum::http::{HeaderMap, Method, request::Parts};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use std::time::SystemTime;

enum Resource {
    Account(AccountName),
    Container(ContainerKey),
    Blob(BlobKey),
}

impl Resource {
    fn account(&self) -> &AccountName {
        match self {
            Self::Account(account) => account,
            Self::Container(key) => &key.account,
            Self::Blob(key) => &key.container.account,
        }
    }

    fn parse(path: &str) -> Result<Self> {
        let mut segments = path
            .strip_prefix('/')
            .ok_or(Error::InvalidName)?
            .splitn(3, '/');
        let account = AccountName::parse(segments.next().ok_or(Error::InvalidName)?)?;
        let label = segments.next();
        let blob = segments.next();
        let resource = match (label, blob) {
            (None | Some(""), None) => Self::Account(account),
            (Some(label), blob) => {
                let key = ContainerKey {
                    account,
                    name: ContainerName::parse(label)?,
                };
                if let Some(path) = blob {
                    if path.is_empty() {
                        return Err(Error::InvalidName);
                    }
                    let value = decode(path, false).ok_or(Error::InvalidName)?;
                    Self::Blob(BlobKey {
                        container: key,
                        path: BlobPath::parse(value)?,
                    })
                } else {
                    Self::Container(key)
                }
            }
            (None, Some(_)) => return Err(Error::InvalidName),
        };
        Ok(resource)
    }
}

pub(crate) enum Operation {
    CreateContainer(ContainerKey),
    ContainerProperties(ContainerKey),
    DeleteContainer(ContainerKey),
    ListContainers(AccountName, PageRequest),
    ListBlobs(ContainerKey, PageRequest, bool),
    PutBlob(BlobKey, UploadOptions),
    ReadBlob(BlobKey, ReadOptions),
    DeleteBlob(BlobKey, Condition),
}

pub(crate) struct UploadOptions {
    pub(crate) length: ContentLength,
    pub(crate) content_type: String,
    pub(crate) checksum: Option<[u8; 16]>,
    pub(crate) metadata: Metadata,
    pub(crate) condition: Condition,
}

pub(crate) struct ReadOptions {
    pub(crate) condition: Condition,
    pub(crate) range: Option<ByteRange>,
    pub(crate) with_body: bool,
}

pub(crate) struct ParsedRequest {
    pub(crate) operation: Operation,
    pub(crate) requested_version: ApiVersion,
}

pub(crate) fn parse(parts: &Parts, config: &Config) -> Result<ParsedRequest> {
    let headers = &parts.headers;
    if headers.len() > 100
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > 32768
    {
        return Err(Error::InvalidHeader);
    }
    let requested_version =
        ApiVersion::parse(header(headers, "x-ms-version")?.ok_or(Error::InvalidVersion)?)?;
    if requested_version != config.api_version
        && (!config.skip_api_version_check || requested_version < config.api_version)
    {
        return Err(Error::InvalidVersion);
    }
    let query = parse_query(parts.uri.query())?;
    if query.contains_key("sig") {
        return Err(Error::Unsupported);
    }
    let resource = Resource::parse(parts.uri.path())?;
    let account = resource.account();
    let keys = config
        .accounts
        .get(account)
        .ok_or(Error::AuthenticationFailed)?;
    auth::verify(
        account,
        keys,
        &parts.method,
        parts.uri.path(),
        &query,
        headers,
        SystemTime::now(),
    )?;
    let param = |name| query.get(name).map(String::as_str);
    let listing = || PageRequest::parse(param("prefix"), param("marker"), param("maxresults"));
    let op = match (resource, &parts.method, param("restype"), param("comp")) {
        (Resource::Account(account), &Method::GET, None, Some("list")) => {
            check(
                &query,
                headers,
                &["comp", "prefix", "marker", "maxresults", "include"],
                &[],
                false,
            )?;
            if param("include").is_some_and(|include| !include.is_empty()) {
                return Err(Error::Unsupported);
            }
            Operation::ListContainers(account, listing()?)
        }
        (Resource::Container(key), &Method::GET, Some("container"), Some("list")) => {
            check(
                &query,
                headers,
                &[
                    "comp",
                    "restype",
                    "prefix",
                    "marker",
                    "maxresults",
                    "include",
                ],
                &[],
                false,
            )?;
            let metadata = match param("include") {
                None => false,
                Some("metadata") => true,
                Some(_) => return Err(Error::Unsupported),
            };
            Operation::ListBlobs(key, listing()?, metadata)
        }
        (Resource::Container(key), method, Some("container"), None) => {
            check(&query, headers, &["restype"], &[], false)?;
            match *method {
                Method::PUT => Operation::CreateContainer(key),
                Method::GET | Method::HEAD => Operation::ContainerProperties(key),
                Method::DELETE => Operation::DeleteContainer(key),
                _ => return Err(Error::Unsupported),
            }
        }
        (Resource::Blob(key), &Method::PUT, None, None) => {
            check(
                &query,
                headers,
                &[],
                &[
                    "if-match",
                    "if-none-match",
                    "x-ms-blob-type",
                    "x-ms-blob-content-type",
                    "content-md5",
                ],
                true,
            )?;
            let options = upload_options(headers, config.max_blob_bytes)?;
            Operation::PutBlob(key, options)
        }
        (Resource::Blob(key), method @ (&Method::GET | &Method::HEAD), None, None) => {
            let with_body = method == Method::GET;
            let fields: &[&str] = if with_body {
                &["if-match", "if-none-match", "range", "x-ms-range"]
            } else {
                &["if-match", "if-none-match"]
            };
            check(&query, headers, &[], fields, false)?;
            let range = header(headers, "x-ms-range")?
                .or(header(headers, "range")?)
                .map(ByteRange::parse)
                .transpose()?;
            Operation::ReadBlob(
                key,
                ReadOptions {
                    condition: condition(headers)?,
                    range,
                    with_body,
                },
            )
        }
        (Resource::Blob(key), &Method::DELETE, None, None) => {
            check(&query, headers, &[], &["if-match", "if-none-match"], false)?;
            Operation::DeleteBlob(key, condition(headers)?)
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(ParsedRequest {
        operation: op,
        requested_version,
    })
}

fn condition(headers: &HeaderMap) -> Result<Condition> {
    Condition::parse(
        header(headers, "if-match")?,
        header(headers, "if-none-match")?,
    )
}

fn upload_options(headers: &HeaderMap, limit: u64) -> Result<UploadOptions> {
    match header(headers, "x-ms-blob-type")? {
        Some("BlockBlob") => (),
        Some("AppendBlob" | "PageBlob") => return Err(Error::Unsupported),
        _ => return Err(Error::InvalidHeader),
    }
    let length: u64 = header(headers, "content-length")?
        .ok_or(Error::MissingLength)?
        .parse()
        .map_err(|_| Error::InvalidLength)?;
    if length > limit {
        return Err(Error::TooLarge);
    }
    let checksum = header(headers, "content-md5")?
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| Error::InvalidHeader)?
                .try_into()
                .map_err(|_| Error::InvalidHeader)
        })
        .transpose()?;
    let content_type = header(headers, "x-ms-blob-content-type")?
        .or(header(headers, "content-type")?)
        .unwrap_or("application/octet-stream");
    if content_type.is_empty() || content_type.len() > 512 || !xml_safe(content_type) {
        return Err(Error::InvalidHeader);
    }
    let mut metadata = Metadata::new();
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-ms-meta-") {
            let mut chars = name.bytes();
            if !chars
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                || !chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::InvalidHeader);
            }
            let value = value.to_str().map_err(|_| Error::InvalidHeader)?;
            if !xml_safe(value) {
                return Err(Error::InvalidHeader);
            }
            metadata.insert(name.to_owned(), value.to_owned());
        }
    }
    if metadata
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum::<usize>()
        > 8192
    {
        return Err(Error::InvalidHeader);
    }
    Ok(UploadOptions {
        length: ContentLength(length),
        content_type: content_type.to_owned(),
        checksum,
        metadata,
        condition: condition(headers)?,
    })
}

fn check(
    query: &Query,
    headers: &HeaderMap,
    allowed_query: &[&str],
    allowed_headers: &[&str],
    metadata: bool,
) -> Result<()> {
    if query
        .keys()
        .any(|key| !allowed_query.contains(&key.as_str()))
    {
        return Err(Error::Unsupported);
    }
    for key in headers.keys() {
        let key = key.as_str();
        if allowed_headers.contains(&key)
            || matches!(key, "x-ms-version" | "x-ms-date" | "x-ms-client-request-id")
            || metadata && key.starts_with("x-ms-meta-")
        {
            continue;
        }
        if key.starts_with("x-ms-")
            || key.starts_with("if-")
            || matches!(
                key,
                "range"
                    | "content-md5"
                    | "content-encoding"
                    | "content-language"
                    | "cache-control"
                    | "content-disposition"
                    | "origin"
            )
        {
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}

fn parse_query(query: Option<&str>) -> Result<Query> {
    let mut result = Query::new();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        if query.len() > 16 * 1024 {
            return Err(Error::InvalidQuery);
        }
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(Error::InvalidQuery)?;
            let name = decode(name, true)
                .ok_or(Error::InvalidQuery)?
                .to_ascii_lowercase();
            let value = decode(value, true).ok_or(Error::InvalidQuery)?;
            if name.is_empty()
                || !xml_safe(&name)
                || !xml_safe(&value)
                || result.insert(name, value).is_some()
            {
                return Err(Error::InvalidQuery);
            }
        }
    }
    Ok(result)
}

fn decode(value: &str, query: bool) -> Option<String> {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' && !(bytes.next()?.is_ascii_hexdigit() && bytes.next()?.is_ascii_hexdigit())
        {
            return None;
        }
    }
    let prepared = if query && value.contains('+') {
        std::borrow::Cow::Owned(value.replace('+', " "))
    } else {
        std::borrow::Cow::Borrowed(value)
    };
    percent_decode_str(&prepared)
        .decode_utf8()
        .ok()
        .map(|value| value.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
