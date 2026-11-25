use crate::{
    auth::{self, Query, header},
    checksum::Checksum,
    config::Config,
    domain::{
        AccountName, ApiVersion, BlobKey, BlobPath, BlobWrite, BlockId, BlockListKind,
        BlockSelection, BlockSource, ByteRange, Condition, ContainerKey, ContainerName,
        ContentLength, Error, Metadata, PageRequest, Result, xml_safe,
    },
};
use axum::http::{HeaderMap, Method, request::Parts};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use quick_xml::{Reader, events::Event};
use std::{collections::HashMap, time::SystemTime};

const MAX_BLOCK_LIST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COMMITTED_BLOCKS: usize = 50_000;

pub(crate) enum Resource {
    Account(AccountName),
    Container(ContainerKey),
    Blob(BlobKey),
}

impl Resource {
    pub(crate) fn account(&self) -> &AccountName {
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
    PutBlob(BlobKey, UploadOptions, BlobWrite),
    PutBlock(BlobKey, BlockId, UploadOptions),
    PutBlockList(BlobKey, UploadOptions, BlobWrite, Option<[u8; 16]>),
    GetBlockList(BlobKey, BlockListKind, Condition),
    ReadBlob(BlobKey, ReadOptions),
    DeleteBlob(BlobKey, Condition),
}

pub(crate) struct UploadOptions {
    pub(crate) length: ContentLength,
    pub(crate) checksum: Option<Checksum>,
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

pub(crate) struct AuthenticatedRequest {
    pub(crate) requested_version: ApiVersion,
    pub(crate) resource: Resource,
    pub(crate) query: Query,
}

pub(crate) fn authenticate(parts: &Parts, config: &Config) -> Result<AuthenticatedRequest> {
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
    Ok(AuthenticatedRequest {
        requested_version,
        resource,
        query,
    })
}

pub(crate) fn parse(parts: &Parts, config: &Config) -> Result<ParsedRequest> {
    let AuthenticatedRequest {
        requested_version,
        resource,
        query,
    } = authenticate(parts, config)?;
    let headers = &parts.headers;
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
        (Resource::Blob(key), &Method::PUT, None, Some("block")) => {
            check(
                &query,
                headers,
                &["comp", "blockid"],
                &["content-md5", "x-ms-content-crc64"],
                false,
            )?;
            let id = BlockId::parse(param("blockid").ok_or(Error::InvalidQuery)?)?;
            Operation::PutBlock(key, id, upload_options(headers, config.max_blob_bytes)?)
        }
        (Resource::Blob(key), &Method::PUT, None, Some("blocklist")) => {
            check(
                &query,
                headers,
                &["comp"],
                &[
                    "if-match",
                    "if-none-match",
                    "x-ms-blob-content-type",
                    "x-ms-blob-content-md5",
                    "content-md5",
                    "x-ms-content-crc64",
                ],
                true,
            )?;
            Operation::PutBlockList(
                key,
                upload_options(headers, MAX_BLOCK_LIST_BYTES)?,
                blob_write(headers, false)?,
                decode_hash(header(headers, "x-ms-blob-content-md5")?)?,
            )
        }
        (Resource::Blob(key), &Method::GET, None, Some("blocklist")) => {
            check(
                &query,
                headers,
                &["comp", "blocklisttype"],
                &["if-match", "if-none-match"],
                false,
            )?;
            let list = match param("blocklisttype") {
                None | Some("committed") => BlockListKind::Committed,
                Some("uncommitted") => BlockListKind::Uncommitted,
                Some("all") => BlockListKind::All,
                _ => return Err(Error::InvalidQuery),
            };
            Operation::GetBlockList(key, list, condition(headers)?)
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
                    "x-ms-content-crc64",
                ],
                true,
            )?;
            match header(headers, "x-ms-blob-type")? {
                Some("BlockBlob") => (),
                Some("AppendBlob" | "PageBlob") => return Err(Error::Unsupported),
                _ => return Err(Error::InvalidHeader),
            }
            Operation::PutBlob(
                key,
                upload_options(headers, config.max_blob_bytes)?,
                blob_write(headers, true)?,
            )
        }
        (Resource::Blob(key), method @ (&Method::GET | &Method::HEAD), None, None) => {
            let with_body = method == Method::GET;
            let fields: &[&str] = if with_body {
                &["if-match", "if-none-match", "range", "x-ms-range"]
            } else {
                &["if-match", "if-none-match"]
            };
            check(&query, headers, &[], fields, false)?;
            Operation::ReadBlob(key, read_options(headers, with_body)?)
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

pub(crate) fn read_options(headers: &HeaderMap, with_body: bool) -> Result<ReadOptions> {
    let range = header(headers, "x-ms-range")?
        .or(header(headers, "range")?)
        .map(ByteRange::parse)
        .transpose()?;
    Ok(ReadOptions {
        condition: condition(headers)?,
        range,
        with_body,
    })
}

fn condition(headers: &HeaderMap) -> Result<Condition> {
    Condition::parse(
        header(headers, "if-match")?,
        header(headers, "if-none-match")?,
    )
}

fn upload_options(headers: &HeaderMap, limit: u64) -> Result<UploadOptions> {
    let length: u64 = header(headers, "content-length")?
        .ok_or(Error::MissingLength)?
        .parse()
        .map_err(|_| Error::InvalidLength)?;
    if length > limit {
        return Err(Error::TooLarge);
    }
    let md5 = decode_hash(header(headers, "content-md5")?)?;
    let crc64 = decode_hash(header(headers, "x-ms-content-crc64")?)?;
    let checksum = match (md5, crc64) {
        (Some(_), Some(_)) => return Err(Error::InvalidHeader),
        (Some(md5), None) => Some(Checksum::Md5(md5)),
        (None, Some(crc64)) => Some(Checksum::Crc64(u64::from_le_bytes(crc64))),
        (None, None) => None,
    };
    Ok(UploadOptions {
        length: ContentLength(length),
        checksum,
    })
}

fn decode_hash<const N: usize>(value: Option<&str>) -> Result<Option<[u8; N]>> {
    value
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| Error::InvalidHeader)?
                .try_into()
                .map_err(|_| Error::InvalidHeader)
        })
        .transpose()
}

fn blob_write(headers: &HeaderMap, request_content_type: bool) -> Result<BlobWrite> {
    let request_content_type = if request_content_type {
        header(headers, "content-type")?
    } else {
        None
    };
    let content_type = header(headers, "x-ms-blob-content-type")?
        .or(request_content_type)
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
    Ok(BlobWrite {
        content_type: content_type.to_owned(),
        metadata,
        condition: condition(headers)?,
    })
}

pub(crate) fn parse_block_list(body: &[u8]) -> Result<Vec<BlockSelection>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidXml)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let root = match reader.read_event().map_err(|_| Error::InvalidXml)? {
        Event::Decl(_) => reader.read_event().map_err(|_| Error::InvalidXml)?,
        event => event,
    };
    let mut selections = Vec::new();
    let mut sources = HashMap::new();
    match root {
        Event::Empty(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() => {}
        Event::Start(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() =>
        {
            loop {
                match reader.read_event().map_err(|_| Error::InvalidXml)? {
                    Event::End(end) if end.name().as_ref() == "BlockList" => break,
                    Event::Start(tag) if tag.attributes_raw().is_empty() => {
                        if selections.len() == MAX_COMMITTED_BLOCKS {
                            return Err(Error::BlockListTooLong);
                        }
                        let source = match tag.name().as_ref() {
                            "Committed" => BlockSource::Committed,
                            "Uncommitted" => BlockSource::Uncommitted,
                            "Latest" => BlockSource::Latest,
                            _ => return Err(Error::InvalidXml),
                        };
                        let value = reader
                            .read_text(tag.name())
                            .map_err(|_| Error::InvalidXml)?;
                        let id =
                            BlockId::parse(value.trim()).map_err(|_| Error::InvalidBlockList)?;
                        if selections
                            .first()
                            .is_some_and(|first: &BlockSelection| first.id.width != id.width)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        if sources
                            .insert(id.as_str().to_owned(), source)
                            .is_some_and(|prior| prior != source)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        selections.push(BlockSelection { id, source });
                    }
                    _ => return Err(Error::InvalidXml),
                }
            }
        }
        _ => return Err(Error::InvalidXml),
    }
    if !matches!(reader.read_event(), Ok(Event::Eof)) {
        return Err(Error::InvalidXml);
    }
    Ok(selections)
}

pub(crate) fn check(
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
