use super::*;
use std::time::Instant;

const PAGE: usize = 512;
const SIZE: usize = 4 * PAGE;
const PAGE_SOURCE: &str = "source.vhd";
const BACKUP: &str = "backup.vhd";

#[test]
fn rejected_source_bearer_does_not_use_destination_credentials() -> Result<()> {
    with_local(|client, endpoint, bearer| {
        with_fresh_container(client, endpoint, bearer, |container, _| {
            let probe = Probe {
                client,
                bearer,
                endpoint,
                account: ACCOUNT,
                container,
                exchanges: Vec::new(),
            };
            probe.seed_block(BLOB, BLOB_BYTES)?;
            let reply = Reply::receive(
                probe
                    .put("destination")?
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("x-ms-copy-source", probe.url(BLOB)?.as_str())
                    .header("x-ms-copy-source-authorization", "Bearer invalid"),
            )?;
            ensure!(
                reply.status == 403
                    && reply.field("x-ms-error-code") == Some("CannotVerifyCopySource"),
                "expected source authorization failure, observed HTTP {}",
                reply.status
            );
            Probe::setup(
                probe.wire(Method::GET, "destination")?,
                404,
                "verify rejected copy did not create its destination",
            )
        })
    })
}

impl Probe<'_> {
    pub(super) fn from_url(&mut self) -> Result<()> {
        let mut bytes = [b'a'; 2 * PAGE];
        bytes[PAGE..].fill(b'b');
        self.seed_block(BLOB, &bytes)?;
        let source = self.url(BLOB)?;
        let copy = |probe: &Self, target: &str| -> Result<_> {
            Ok(probe
                .put(target)?
                .header("x-ms-copy-source", source.as_str())
                .header(
                    "x-ms-copy-source-authorization",
                    format!("Bearer {}", probe.bearer),
                ))
        };
        let copy_range = |probe: &Self, target: &str| -> Result<_> {
            Ok(copy(probe, target)?.header("x-ms-source-range", "bytes=512-1023"))
        };
        self.write_empty(
            Step::PutBlob,
            copy(self, "whole")?
                .header("x-ms-blob-type", "BlockBlob")
                .header("x-ms-copy-source-blob-properties", "false"),
        )?;
        self.read_blob(
            Step::ReadWhole,
            self.wire(Method::GET, "whole")?,
            &bytes,
            "BlockBlob",
        )?;
        let partial = &bytes[PAGE..];
        self.write_empty(
            Step::StageBlock,
            copy_range(self, "staged?comp=block&blockid=YQ%3D%3D")?,
        )?;
        self.write_empty(
            Step::CommitBlock,
            self.wire(Method::PUT, "staged?comp=blocklist")?
                .header("content-type", "application/xml")
                .body("<BlockList><Latest>YQ==</Latest></BlockList>"),
        )?;
        self.read_blob(
            Step::ReadBlock,
            self.wire(Method::GET, "staged")?,
            partial,
            "BlockBlob",
        )?;
        Self::setup(
            self.put("append")?.header("x-ms-blob-type", "AppendBlob"),
            201,
            "seed append destination",
        )?;
        let append = Reply::receive(
            copy_range(self, "append?comp=appendblock")?
                .header("x-ms-blob-condition-appendpos", "0"),
        )?;
        self.record(
            Step::AppendBlock,
            &append,
            append.empty(),
            Some(Detail::Append {
                offset: append.value("x-ms-blob-append-offset", "0"),
                committed_blocks: append.value("x-ms-blob-committed-block-count", "1"),
            }),
        );
        self.read_blob(
            Step::ReadAppend,
            self.wire(Method::GET, "append")?,
            partial,
            "AppendBlob",
        )?;
        self.create_page("page")?;
        let page_copy = |probe: &Self, range| -> Result<_> {
            Ok(copy(probe, "page?comp=page")?
                .header("x-ms-source-range", range)
                .header("x-ms-range", "bytes=512-1023")
                .header("x-ms-page-write", "update"))
        };
        let page = Reply::receive(page_copy(self, "bytes=512-1023")?)?;
        self.record(
            Step::PutPage,
            &page,
            page.empty(),
            Some(Detail::Page {
                sequence: page.value("x-ms-blob-sequence-number", "0"),
            }),
        );
        let mut bytes = [0; SIZE];
        bytes[PAGE..2 * PAGE].copy_from_slice(partial);
        self.read_blob(
            Step::ReadPage,
            self.wire(Method::GET, "page")?,
            &bytes,
            "PageBlob",
        )?;
        self.write_empty(Step::RejectSourceRange, page_copy(self, "bytes=2048-2559")?)
    }

    fn create_page(&self, name: &str) -> Result<()> {
        Self::setup(
            self.put(name)?
                .header("x-ms-blob-type", "PageBlob")
                .header("x-ms-blob-content-length", SIZE),
            201,
            "seed page destination",
        )
    }

    fn page_write(&self, offset: usize, byte: u8) -> Result<RequestBuilder> {
        Ok(self
            .wire(Method::PUT, &format!("{PAGE_SOURCE}?comp=page"))?
            .header(
                "x-ms-range",
                format!("bytes={offset}-{}", offset + PAGE - 1),
            )
            .header("x-ms-page-write", "update")
            .body(vec![byte; PAGE]))
    }

    fn snapshot(&self) -> Result<Reply> {
        Reply::receive(self.put(&format!("{PAGE_SOURCE}?comp=snapshot"))?)
    }

    fn copy_details(reply: &Reply, expected_id: Option<&str>, copy_status: &str) -> Detail {
        Detail::Copy {
            id: header(&reply.headers, "x-ms-copy-id", |id| {
                expected_id.map_or_else(|| Uuid::parse_str(id).is_ok(), |expected| expected == id)
            }),
            status: reply.value("x-ms-copy-status", copy_status),
            incremental: reply.value("x-ms-incremental-copy", "true"),
            snapshot: header(
                &reply.headers,
                "x-ms-copy-destination-snapshot",
                is_utc_timestamp,
            ),
        }
    }

    fn copy_and_wait(&mut self, step: Step, source: &Url) -> Result<Reply> {
        let started = Reply::receive(
            self.put(&format!("{BACKUP}?comp=incrementalcopy"))?
                .header("x-ms-copy-source", source.as_str()),
        )?;
        self.record(
            step,
            &started,
            started.empty(),
            Some(Self::copy_details(&started, None, "pending")),
        );
        ensure!(
            started.status == 202,
            "incremental copy returned HTTP {}",
            started.status
        );
        let id = started
            .field("x-ms-copy-id")
            .filter(|id| Uuid::parse_str(id).is_ok())
            .context("copy did not return an ID")?;
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let reply = Reply::receive(self.wire(Method::HEAD, BACKUP)?)?;
            ensure!(
                reply.status == 200 && reply.field("x-ms-copy-id") == Some(id),
                "copy properties do not identify accepted copy"
            );
            match reply.field("x-ms-copy-status") {
                Some("success") => return Ok(reply),
                Some("pending") if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(250))
                }
                _ => anyhow::bail!(
                    "incremental copy did not complete successfully within the probe window"
                ),
            }
        }
    }

    pub(super) fn incremental_copy(&mut self) -> Result<()> {
        self.create_page(PAGE_SOURCE)?;
        Self::setup(self.page_write(0, b'x')?, 201, "seed first source page")?;
        let first = self.snapshot()?;
        let expiry = iso(180);
        let key = delegation_key_document(self.client, self.endpoint, self.bearer, &expiry)?;
        let sas = sign_sas(
            &key,
            (self.account, self.container, Some(PAGE_SOURCE)),
            "r",
            &expiry,
        )?;
        let source = |probe: &Self, snapshot: &Reply| -> Result<Url> {
            ensure!(
                snapshot.status == 201,
                "source snapshot returned HTTP {}",
                snapshot.status
            );
            let timestamp = snapshot
                .field("x-ms-snapshot")
                .filter(|time| is_utc_timestamp(time))
                .context("missing source snapshot time")?;
            let mut url = probe.url(PAGE_SOURCE)?;
            url.query_pairs_mut().append_pair("snapshot", timestamp);
            url.set_query(Some(&format!(
                "{}&{sas}",
                url.query().context("missing snapshot query")?
            )));
            Ok(url)
        };
        let first_copy = self.copy_and_wait(Step::StartCopy, &source(self, &first)?)?;
        self.record(
            Step::CopyComplete,
            &first_copy,
            first_copy.empty(),
            Some(Self::copy_details(&first_copy, None, "success")),
        );
        let first_time = first_copy
            .field("x-ms-copy-destination-snapshot")
            .filter(|time| is_utc_timestamp(time))
            .context("first copy has no destination snapshot")?;
        self.write_empty(Step::RejectBaseRead, self.wire(Method::GET, BACKUP)?)?;
        self.write_empty(Step::UpdateSource, self.page_write(2 * PAGE, b'y')?)?;
        let second = self.snapshot()?;
        self.record(
            Step::SnapshotSource,
            &second,
            second.empty(),
            Some(Detail::Snapshot {
                timestamp: header(&second.headers, "x-ms-snapshot", is_utc_timestamp),
            }),
        );
        let second_copy = self.copy_and_wait(Step::CopyAgain, &source(self, &second)?)?;
        let second_time = second_copy
            .field("x-ms-copy-destination-snapshot")
            .filter(|time| is_utc_timestamp(time) && *time != first_time)
            .context("second copy did not make a new destination snapshot")?;
        let diff = Reply::receive(self.wire(Method::GET, BACKUP)?.query(&[
            ("comp", "pagelist"),
            ("snapshot", second_time),
            ("prevsnapshot", first_time),
        ]))?;
        let ranges = if diff.status == 200 {
            Body::Ranges(page_ranges(&diff.headers, &diff.bytes)?)
        } else {
            Body::Other
        };
        self.record(Step::ChangedRanges, &diff, ranges, None);
        let mut bytes = [0; SIZE];
        bytes[..PAGE].fill(b'x');
        bytes[2 * PAGE..3 * PAGE].fill(b'y');
        self.read_blob(
            Step::ReadSnapshot,
            self.wire(Method::GET, BACKUP)?
                .query(&[("snapshot", second_time)]),
            &bytes,
            "PageBlob",
        )
    }
}
