//! Query Blob Contents (ADR-0027): a SQL subset over delimited or JSON blobs, answered as the
//! Avro stream the SDKs decode.

mod avro;
mod format;
mod sql;

use crate::{
    blob_exec::{self, Context},
    blob_snapshot::Selector,
    domain::{BlobRead, Error, Result},
    protocol::Operation,
    respond,
    server::App,
    store::PathRead,
    wire::xml_error,
    xml_tree,
};
use axum::{
    body::{Body, to_bytes},
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

fn parse_request(body: &[u8]) -> Result<std::result::Result<Request, SqlError>> {
    let root = xml_tree::parse(body)?;
    if root.name != "QueryRequest" || root.text_of("QueryType").is_some_and(|t| t != "SQL") {
        return Err(Error::InvalidXml);
    }
    let expression = root.text_of("Expression").ok_or(Error::InvalidXml)?;
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
        if !self.pending.is_empty() {
            self.avro.data(self.pending.as_bytes());
            self.pending.clear();
        }
    }
}

/// Runs the query over the blob text and returns the Avro stream.
fn run(request: &Request, text: &str, total: u64) -> Vec<u8> {
    let mut out = Output {
        avro: avro::Writer::new(),
        pending: String::new(),
        separator: format::separator(&request.output).to_owned(),
    };
    // SDKs decode the first record before they install their error handler, so it is never an error.
    out.avro.progress(0, total);
    let fatal = |out: &mut Output, name: &str, message: &str, position: u64| {
        out.flush();
        out.avro.error(true, name, message, position);
    };
    match format::read(text, &request.input) {
        Err(error) => fatal(&mut out, "InvalidInput", &error.message, error.position),
        Ok(input) => {
            let scope = Scope {
                headers: input.headers.as_deref(),
            };
            if let Err((position, error)) = scan(request, &input.rows, &scope, &mut out) {
                fatal(&mut out, error.name, &error.message, position);
            }
        }
    }
    out.flush();
    out.avro.progress(total, total);
    out.avro.end(total);
    out.avro.finish()
}

fn scan(
    request: &Request,
    rows: &[sql::Row],
    scope: &Scope<'_>,
    out: &mut Output,
) -> std::result::Result<(), (u64, SqlError)> {
    let query = &request.query;
    let mut accumulators = query.accumulators();
    let mut emitted = 0u64;
    for (index, row) in rows.iter().enumerate() {
        let position = index as u64;
        if !query
            .matches(row, scope)
            .map_err(|error| (position, error))?
        {
            continue;
        }
        if query.is_aggregate() {
            query
                .accumulate(&mut accumulators, row, scope)
                .map_err(|error| (position, error))?;
            continue;
        }
        if query.limit.is_some_and(|limit| emitted >= limit) {
            break;
        }
        let columns = query
            .project(row, scope)
            .map_err(|error| (position, error))?;
        out.record(&columns, &request.output);
        emitted += 1;
    }
    if query.is_aggregate() && query.limit != Some(0) {
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
    let request = match parse_request(&bytes)? {
        Ok(request) => request,
        Err(error) => {
            return Ok(xml_error(
                StatusCode::BAD_REQUEST,
                error.name,
                &error.message,
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
    let stream = run(&request, &text, content.len() as u64);
    let headers = response.headers_mut();
    for name in ["content-md5", "content-range", "x-ms-blob-content-md5"] {
        headers.remove(name);
    }
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("content-length", HeaderValue::from(stream.len()));
    *response.body_mut() = Body::from(stream);
    Ok(response)
}
