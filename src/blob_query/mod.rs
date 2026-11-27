//! Query Blob Contents (ADR-0027): a SQL subset over delimited or JSON blobs, answered as the
//! Avro stream the SDKs decode.

mod avro;
mod format;
mod sql;

use crate::{
    blob_exec::{self, Context},
    blob_snapshot::Selector,
    domain::{BlobRead, Error, Result, xml_safe},
    protocol::Operation,
    respond,
    server::App,
    store::PathRead,
    wire::{correlated_error_message, xml_error},
    xml_tree,
};
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{HeaderValue, StatusCode},
    response::Response,
};
use format::Format;
use sql::{Query, Scope, SqlError};

/// Output is split into data records of about this size.
const CHUNK_BYTES: usize = 1 << 20;

struct Request {
    query: Query,
    input: Format,
    output: Format,
}

fn parse_request(
    root: &xml_tree::Node,
    expression: &str,
) -> Result<std::result::Result<Request, SqlError>> {
    if root.name != "QueryRequest" || root.text_of("QueryType").is_some_and(|t| t != "SQL") {
        return Err(Error::InvalidXml);
    }
    let input = format::serialization(root.child("InputSerialization"))?
        .unwrap_or_else(|| Format::Delimited(format::Delimited::default()));
    let output =
        format::serialization(root.child("OutputSerialization"))?.unwrap_or_else(|| match input {
            Format::Delimited(_) => Format::Delimited(format::Delimited::default()),
            Format::Json { .. } => Format::Json {
                record: "\n".to_owned(),
            },
        });
    Ok(Query::parse(expression).map(|query| Request {
        query,
        input,
        output,
    }))
}

struct Output {
    avro: avro::Writer,
    pending: String,
    separator: String,
    wrote_data: bool,
    budget: usize,
}

impl Output {
    fn record(&mut self, columns: &[(String, sql::Value)], format: &Format) {
        self.pending.push_str(&format::write(columns, format));
        self.pending.push_str(&self.separator);
        if self.pending.len() >= CHUNK_BYTES {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.pending.is_empty() || !self.wrote_data {
            self.avro.data(self.pending.as_bytes());
            self.pending.clear();
            self.wrote_data = true;
        }
    }

    fn error(&mut self, fatal: bool, name: &str, message: &str, position: u64) {
        // The SDK starts decoding before installing its error handler.
        self.flush();
        self.avro.error(fatal, name, message, position);
    }

    fn check_size(&self) -> Result<()> {
        if self.avro.encoded_len().saturating_add(self.pending.len()) > self.budget {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

/// Runs the query over the blob text and returns the Avro stream.
fn run(request: &Request, text: &str, total: u64, budget: usize) -> Result<Vec<u8>> {
    let mut out = Output {
        avro: avro::Writer::new(),
        pending: String::new(),
        separator: format::separator(&request.output).to_owned(),
        wrote_data: false,
        budget,
    };
    match format::read(text, &request.input) {
        Err(error) => out.error(true, "InvalidInput", &error.message, error.position),
        Ok(input) => {
            let scope = Scope {
                headers: input.headers.as_deref(),
            };
            scan(request, &input.rows, &scope, &mut out)?;
        }
    }
    out.flush();
    out.avro.progress(total, total);
    out.avro.end(total);
    out.check_size()?;
    Ok(out.avro.finish())
}

fn scan(
    request: &Request,
    rows: &[(u64, sql::Row)],
    scope: &Scope<'_>,
    out: &mut Output,
) -> Result<()> {
    let query = &request.query;
    let aggregate = query.is_aggregate();
    let mut accumulators = query.accumulators();
    let mut emitted = 0u64;
    for (position, row) in rows {
        if !aggregate && query.limit.is_some_and(|limit| emitted >= limit) {
            break;
        }
        let mut evaluate = || {
            if query.matches(row, scope)? {
                if aggregate {
                    query.accumulate(&mut accumulators, row, scope)?;
                } else {
                    let columns = query.project(row, scope)?;
                    out.record(&columns, &request.output);
                    emitted += 1;
                }
            }
            Ok::<_, SqlError>(())
        };
        if let Err(error) = evaluate() {
            let fatal = error.fatal || aggregate;
            out.error(fatal, error.name, &error.message, *position);
            if fatal {
                return out.check_size();
            }
        }
        out.check_size()?;
    }
    if aggregate && query.limit != Some(0) {
        let columns: Vec<_> = query
            .aggregate_names()
            .into_iter()
            .zip(accumulators.into_iter().map(sql::Accumulator::finish))
            .collect();
        out.record(&columns, &request.output);
    }
    Ok(())
}

pub(crate) async fn execute(
    app: &App,
    op: Operation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    let Operation::QueryBlob(key, selector, options, guard) = op else {
        return Err(Error::Unsupported);
    };
    let (bytes, _) = blob_exec::read_bounded(app, body, &options).await?;
    let root = match xml_tree::parse(&bytes) {
        Ok(root) => root,
        Err(Error::InvalidXml) => {
            let message = correlated_error_message(
                "XML specified is not syntactically valid.",
                ctx.request_id,
                app.clock.now(),
            );
            return Ok(xml_error(
                StatusCode::BAD_REQUEST,
                "InvalidXmlDocument",
                &message,
            ));
        }
        Err(error) => return Err(error),
    };
    let expression = root.text_of("Expression").ok_or(Error::InvalidXml)?;
    let request = match parse_request(&root, expression)? {
        Ok(request) => request,
        Err(_) => {
            if !xml_safe(expression) {
                return Err(Error::InvalidXml);
            }
            let message = correlated_error_message(
                &format!("Syntax error in query: {expression}"),
                ctx.request_id,
                app.clock.now(),
            );
            return Ok(xml_error(
                StatusCode::BAD_REQUEST,
                "ErrorProcessingQueryExpression",
                &message,
            ));
        }
    };
    let read = BlobRead {
        guard,
        range: None,
        with_body: true,
        range_checksum: None,
    };
    let download = match selector {
        Some(selector) => {
            let _: Selector = selector;
            app.store.read_selected(key, selector, read).await?.download
        }
        None => match app.store.read_path(key, read).await? {
            PathRead::File(download) => *download,
            PathRead::Directory(..) => return Err(Error::Unsupported),
        },
    };
    let mut response = respond::download_response(download, ctx.credentials.overrides())?;
    let limit = usize::try_from(app.config.max_blob_bytes).unwrap_or(usize::MAX);
    let content = to_bytes(std::mem::take(response.body_mut()), limit)
        .await
        .map_err(|_| Error::InvalidLength)?;
    let text = String::from_utf8_lossy(&content);
    // Keep room for the Avro schema and framing even when the input limit is tiny.
    let stream = run(
        &request,
        &text,
        content.len() as u64,
        limit.max(CHUNK_BYTES),
    )?;
    let headers = response.headers_mut();
    for name in [
        "content-length",
        "content-md5",
        "content-range",
        "x-ms-blob-content-md5",
    ] {
        headers.remove(name);
    }
    headers.insert("content-type", HeaderValue::from_static("avro/binary"));
    *response.body_mut() = Body::from_stream(futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(Bytes::from(stream))
    }));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_errors_cannot_expand_a_small_source_past_the_output_budget() {
        let request = Request {
            query: Query::parse("SELECT CAST(_1 AS INT) FROM BlobStorage").unwrap(),
            input: Format::Delimited(format::Delimited::default()),
            output: Format::Delimited(format::Delimited::default()),
        };
        assert!(run(&request, "x\n", 2, 1024).is_ok());
        let data = "x\n".repeat(32);
        assert_eq!(
            run(&request, &data, data.len() as u64, 1024),
            Err(Error::TooLarge)
        );
    }
}
