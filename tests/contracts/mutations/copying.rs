use super::{
    Details, ErrorCode, Header, INITIAL, Probe, Response, Step, echoed, header, header_text,
    request,
};
use anyhow::{Context as _, Result};
use reqwest::{Method, header::HeaderMap};
use uuid::Uuid;

const SOURCE_BLOB: &str = "copy-source.txt";
pub(super) const STALE_SOURCE_ETAG: &str = "\"0x000000000000000\"";

pub(super) fn matches_fixture(response: &Response) -> bool {
    use Step::*;
    match response.step {
        StartCopy | ReadCopiedBlob | ReadUnchangedCopy => matches!(
            response.details,
            Some(Details::Copy {
                id: Header::Matches,
                success: Header::Matches,
                ..
            })
        ),
        HeadCopiedBlob => matches!(
            response.details,
            Some(Details::Copy {
                id: Header::Matches,
                success: Header::Matches,
                source: Header::Matches,
                progress: Header::Matches,
                completion_time: Header::Matches,
            })
        ),
        RejectCopySource => {
            response.status == 412 && response.error_header == ErrorCode::SourceConditionNotMet
        }
        RejectCopyDestination => {
            response.status == 409 && response.error_header == ErrorCode::BlobAlreadyExists
        }
        RejectAbortCompletedCopy => {
            response.status == 409 && response.error_header == ErrorCode::NoPendingCopyOperation
        }
        _ => true,
    }
}

impl Probe<'_> {
    pub(super) fn copy_details(
        &mut self,
        step: Step,
        headers: &HeaderMap,
    ) -> Result<Option<Details>> {
        use Step::*;
        if !matches!(
            step,
            StartCopy | HeadCopiedBlob | ReadCopiedBlob | ReadUnchangedCopy
        ) {
            return Ok(None);
        }
        let id = header_text(headers, "x-ms-copy-id");
        let copy_id = if step == StartCopy {
            self.copy_id = id
                .filter(|id| Uuid::parse_str(id).is_ok())
                .map(str::to_owned);
            header(headers, "x-ms-copy-id", |id| Uuid::parse_str(id).is_ok())
        } else {
            echoed(id, self.copy_id.as_deref())
        };
        let source = self.url.join(SOURCE_BLOB)?;
        let size = INITIAL.len();
        Ok(Some(Details::Copy {
            id: copy_id,
            success: header(headers, "x-ms-copy-status", |value| value == "success"),
            source: header(headers, "x-ms-copy-source", |value| {
                value == source.as_str()
            }),
            progress: header(headers, "x-ms-copy-progress", |value| {
                value == format!("{size}/{size}")
            }),
            completion_time: header(headers, "x-ms-copy-completion-time", |value| {
                httpdate::parse_http_date(value).is_ok()
            }),
        }))
    }

    pub(super) fn completed_copy(&mut self) -> Result<()> {
        let source = self.url.join(SOURCE_BLOB)?;
        self.setup(
            request(self.client, Method::PUT, source.clone())
                .bearer_auth(self.bearer)
                .header("x-ms-blob-type", "BlockBlob")
                .header("content-type", "text/plain")
                .header("x-ms-meta-purpose", "initial")
                .body(INITIAL),
            201,
            "seed same-account copy source",
        )?;
        let copy = |probe: &Self| {
            probe
                .request(Method::PUT)
                .header("content-length", "0")
                .header("x-ms-copy-source", source.as_str())
        };
        let etag = self
            .record(Step::StartCopy, copy(self), None)?
            .etag
            .context("copy did not return a usable destination ETag")?;
        let copy_id = self
            .copy_id
            .clone()
            .context("copy did not return a usable ID")?;
        self.record(
            Step::HeadCopiedBlob,
            self.request(Method::HEAD),
            Some(&etag),
        )?;
        self.record(Step::ReadCopiedBlob, self.request(Method::GET), Some(&etag))?;
        self.record(
            Step::RejectCopySource,
            copy(self).header("x-ms-source-if-match", STALE_SOURCE_ETAG),
            Some(&etag),
        )?;
        self.record(
            Step::RejectCopyDestination,
            copy(self).header("if-none-match", "*"),
            Some(&etag),
        )?;
        self.record(
            Step::RejectAbortCompletedCopy,
            self.request(Method::PUT)
                .query(&[("comp", "copy"), ("copyid", copy_id.as_str())])
                .header("content-length", "0")
                .header("x-ms-copy-action", "abort"),
            Some(&etag),
        )?;
        self.record(
            Step::ReadUnchangedCopy,
            self.request(Method::GET),
            Some(&etag),
        )?;
        Ok(())
    }
}
