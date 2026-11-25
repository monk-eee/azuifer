//! Parses page and append blob requests: Put Blob for both types, Put Page, Get Page
//! Ranges, Append Block, and Seal. Each returns `None` for requests it does not own,
//! so the block blob operations parse them unchanged.

use super::{
    BLOB_PROPERTIES, CHECKSUMS, CONDITIONS, LEASE, PLAIN_PROPERTIES, Request, SOURCE,
    UploadOptions, blob_write, upload_options,
};
use crate::{
    auth::header,
    blob_page::{
        AppendCondition, AppendWrite, Creation, MAX_APPEND_BLOCK_BYTES, MAX_WRITE_BYTES,
        PageOperation, PageWrite, RangeQuery, SequenceConditions, page_blob_length, page_range,
        sequence_number,
    },
    conditions::Guard,
    domain::{BlobKey, ByteRange, Error, Result},
};
use axum::http::Method;

const CREATE: &[&str] = &["x-ms-blob-type", "x-ms-access-tier"];
const SEQUENCE_CONDITIONS: &[&str] = &[
    "x-ms-if-sequence-number-le",
    "x-ms-if-sequence-number-lt",
    "x-ms-if-sequence-number-eq",
];
const APPEND_CONDITIONS: &[&str] = &[
    "x-ms-blob-condition-maxsize",
    "x-ms-blob-condition-appendpos",
];

impl Request<'_> {
    pub(super) fn page_operation(&self, key: &BlobKey) -> Result<Option<PageOperation>> {
        let from_url = self.headers.contains_key("x-ms-copy-source");
        let key = key.clone();
        Ok(Some(match (self.method, self.param("comp")) {
            (&Method::PUT, None) if !from_url => match header(self.headers, "x-ms-blob-type")? {
                Some("PageBlob") => self.create_page(key)?,
                Some("AppendBlob") => self.create_append(key)?,
                _ => return Ok(None),
            },
            (&Method::PUT, Some("page")) if from_url => self.put_page_from_url(key)?,
            (&Method::PUT, Some("page")) => self.put_page(key)?,
            (&Method::GET, Some("pagelist")) => self.page_ranges(key)?,
            (&Method::PUT, Some("appendblock")) if from_url => self.append_from_url(key)?,
            (&Method::PUT, Some("appendblock")) => self.append_block(key)?,
            (&Method::PUT, Some("seal")) => self.seal(key)?,
            _ => return Ok(None),
        }))
    }

    /// A request that carries no body: its `Content-Length` must be zero.
    fn require_empty_body(&self) -> Result<()> {
        if upload_options(self.headers, u64::MAX)?.length.0 == 0 {
            Ok(())
        } else {
            Err(Error::InvalidHeader)
        }
    }

    fn create_page(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &[],
            &[
                CONDITIONS,
                LEASE,
                BLOB_PROPERTIES,
                PLAIN_PROPERTIES,
                CREATE,
                &["x-ms-blob-content-length", "x-ms-blob-sequence-number"],
            ],
            true,
        )?;
        self.require_empty_body()?;
        let length = page_blob_length(
            header(self.headers, "x-ms-blob-content-length")?.ok_or(Error::MissingHeader)?,
        )?;
        let sequence = header(self.headers, "x-ms-blob-sequence-number")?
            .map(sequence_number)
            .transpose()?
            .unwrap_or_default();
        Ok(PageOperation::Create(
            key,
            blob_write(self.headers, true)?,
            Creation::Page { length, sequence },
        ))
    }

    fn create_append(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &[],
            &[CONDITIONS, LEASE, BLOB_PROPERTIES, PLAIN_PROPERTIES, CREATE],
            true,
        )?;
        self.require_empty_body()?;
        Ok(PageOperation::Create(
            key,
            blob_write(self.headers, true)?,
            Creation::Append,
        ))
    }

    fn page_write(&self) -> Result<PageWrite> {
        let range = header(self.headers, "x-ms-range")?
            .or(header(self.headers, "range")?)
            .ok_or(Error::MissingHeader)?;
        Ok(PageWrite {
            range: page_range(range)?,
            sequence: SequenceConditions::parse(self.headers)?,
            guard: Guard::parse(self.headers)?,
        })
    }

    fn put_page(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp"],
            &[
                CONDITIONS,
                LEASE,
                CHECKSUMS,
                SEQUENCE_CONDITIONS,
                &["x-ms-page-write", "x-ms-range", "range"],
            ],
            false,
        )?;
        let upload: Option<UploadOptions> =
            match header(self.headers, "x-ms-page-write")?.ok_or(Error::MissingHeader)? {
                "update" => Some(upload_options(self.headers, MAX_WRITE_BYTES)?),
                "clear" => {
                    let options = upload_options(self.headers, u64::MAX)?;
                    if options.length.0 != 0 || options.checksum.is_some() {
                        return Err(Error::InvalidHeader);
                    }
                    None
                }
                _ => return Err(Error::InvalidHeader),
            };
        Ok(PageOperation::PutPage(key, self.page_write()?, upload))
    }

    fn put_page_from_url(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp"],
            &[
                SOURCE,
                CONDITIONS,
                LEASE,
                SEQUENCE_CONDITIONS,
                &[
                    "x-ms-range",
                    "range",
                    "x-ms-source-range",
                    "x-ms-page-write",
                ],
            ],
            false,
        )?;
        self.require_empty_body()?;
        if header(self.headers, "x-ms-page-write")?.is_some_and(|action| action != "update") {
            return Err(Error::InvalidHeader);
        }
        let range = header(self.headers, "x-ms-source-range")?
            .map(ByteRange::parse)
            .transpose()?
            .ok_or(Error::MissingHeader)?;
        Ok(PageOperation::PutPageFromUrl(
            key,
            self.page_write()?,
            self.source(Some(range), true)?,
        ))
    }

    fn page_ranges(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp", "marker", "maxresults"],
            &[CONDITIONS, LEASE, &["x-ms-range", "range"]],
            false,
        )?;
        let number = |name: &str| {
            self.param(name)
                .map(|value| value.parse::<u64>().map_err(|_| Error::InvalidQuery))
                .transpose()
        };
        let limit = number("maxresults")?
            .map(|limit| {
                u32::try_from(limit)
                    .ok()
                    .filter(|limit| *limit > 0)
                    .ok_or(Error::InvalidQuery)
            })
            .transpose()?;
        Ok(PageOperation::PageRanges(
            key,
            RangeQuery {
                window: header(self.headers, "x-ms-range")?
                    .or(header(self.headers, "range")?)
                    .map(ByteRange::parse)
                    .transpose()?,
                marker: number("marker")?,
                limit,
                guard: Guard::parse(self.headers)?,
            },
        ))
    }

    fn append_write(&self) -> Result<AppendWrite> {
        Ok(AppendWrite {
            condition: AppendCondition::parse(self.headers)?,
            guard: Guard::parse(self.headers)?,
        })
    }

    fn append_block(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp"],
            &[CONDITIONS, LEASE, CHECKSUMS, APPEND_CONDITIONS],
            false,
        )?;
        let options = upload_options(self.headers, MAX_APPEND_BLOCK_BYTES)?;
        if options.length.0 == 0 {
            return Err(Error::InvalidHeader);
        }
        Ok(PageOperation::AppendBlock(
            key,
            self.append_write()?,
            options,
        ))
    }

    fn append_from_url(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp"],
            &[
                SOURCE,
                CONDITIONS,
                LEASE,
                APPEND_CONDITIONS,
                &["x-ms-source-range"],
            ],
            false,
        )?;
        self.require_empty_body()?;
        let range = header(self.headers, "x-ms-source-range")?
            .map(ByteRange::parse)
            .transpose()?;
        Ok(PageOperation::AppendBlockFromUrl(
            key,
            self.append_write()?,
            self.source(range, true)?,
        ))
    }

    fn seal(&self, key: BlobKey) -> Result<PageOperation> {
        self.check(
            &["comp"],
            &[CONDITIONS, LEASE, &["x-ms-blob-condition-appendpos"]],
            false,
        )?;
        Ok(PageOperation::Seal(key, self.append_write()?))
    }
}
