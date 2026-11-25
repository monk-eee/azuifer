//! Executes typed Table operations against the store and shapes the Azure responses.

use super::{
    App,
    auth::Credential,
    batch::{self, Batch},
    datetime::Ticks,
    edm::{self, Metadata, Urls},
    error::{Kind, Result, TableError},
    model::{EntityKey, TableName},
    protocol::{self, Format, Operation, Request},
    service,
    store::{EntityScan, Failure, WriteKind, Written},
};
use crate::domain::AccountName;
use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use serde_json::{Map, Value as Json};
use std::time::SystemTime;

pub(super) struct Context<'a> {
    pub(super) app: &'a App,
    pub(super) account: &'a AccountName,
    pub(super) urls: Urls,
    pub(super) credential: &'a Credential,
    pub(super) request_id: &'a str,
    pub(super) now: SystemTime,
}

pub(super) fn text_header(response: &mut Response, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value).map_err(|_| TableError::new(Kind::Internal))?;
    response
        .headers_mut()
        .insert(HeaderName::from_static(name), value);
    Ok(())
}

fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn json(status: StatusCode, level: Metadata, body: &Map<String, Json>) -> Result<Response> {
    let mut response = Response::new(Body::from(Json::Object(body.clone()).to_string()));
    *response.status_mut() = status;
    text_header(&mut response, "content-type", level.content_type())?;
    Ok(response)
}

/// The error as an Azure JSON response, optionally naming the failed batch operation.
pub(super) fn error_response(
    error: &TableError,
    index: Option<usize>,
    request_id: &str,
    now: SystemTime,
) -> Response {
    let body = error.body(index, request_id, &Ticks::from_system(now).format());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = error.status();
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static(
            "application/json;odata=minimalmetadata;streaming=true;charset=utf-8",
        ),
    );
    headers.insert("x-ms-error-code", HeaderValue::from_static(error.code()));
    response
}

fn table_entry(name: &TableName, level: Metadata, urls: &Urls) -> Map<String, Json> {
    let mut map = Map::new();
    if level == Metadata::Full {
        let path = format!("Tables('{}')", name.as_str());
        map.insert(
            "odata.type".into(),
            Json::String(format!("{}.Tables", urls.account)),
        );
        map.insert(
            "odata.id".into(),
            Json::String(format!("{}/{path}", urls.base)),
        );
        map.insert("odata.editLink".into(), Json::String(path));
    }
    map.insert("TableName".into(), Json::String(name.as_str().to_owned()));
    map
}

fn with_metadata(level: Metadata, link: String, mut body: Map<String, Json>) -> Map<String, Json> {
    if level == Metadata::None {
        return body;
    }
    let mut map = Map::new();
    map.insert("odata.metadata".into(), Json::String(link));
    map.append(&mut body);
    map
}

pub(super) async fn execute(ctx: &Context<'_>, request: Request) -> Result<Response> {
    let store = &ctx.app.store;
    let account = ctx.account.clone();
    let Format {
        level,
        return_content,
    } = request.format;
    match request.operation {
        Operation::GetServiceProperties => Ok(service::properties_response(
            &store.service_properties(account).await?,
        )),
        Operation::SetServiceProperties(updates) => {
            store.update_service_properties(account, updates).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::GetServiceStats => Ok(service::stats_response(ctx.now)),
        Operation::QueryTables(query) => {
            let page = store
                .query_tables(account, query.filter, query.top, query.after)
                .await?;
            let value: Vec<Json> = page
                .names
                .iter()
                .map(|name| Json::Object(table_entry(name, level, &ctx.urls)))
                .collect();
            let mut body = Map::new();
            body.insert("value".into(), Json::Array(value));
            let body = with_metadata(level, edm::metadata_link(&ctx.urls, None, false), body);
            let mut response = json(StatusCode::OK, level, &body)?;
            if let Some(next) = page.next {
                text_header(
                    &mut response,
                    "x-ms-continuation-nexttablename",
                    next.as_str(),
                )?;
            }
            Ok(response)
        }
        Operation::GetTable(name) => {
            let stored = store.table(account, name).await?;
            let body = with_metadata(
                level,
                edm::metadata_link(&ctx.urls, None, true),
                table_entry(&stored, level, &ctx.urls),
            );
            json(StatusCode::OK, level, &body)
        }
        Operation::CreateTable(name) => {
            store.create_table(account, name.clone()).await?;
            let location = format!("{}/Tables('{}')", ctx.urls.base, name.as_str());
            let mut response = if return_content {
                let body = with_metadata(
                    level,
                    edm::metadata_link(&ctx.urls, None, true),
                    table_entry(&name, level, &ctx.urls),
                );
                json(StatusCode::CREATED, level, &body)?
            } else {
                empty(StatusCode::NO_CONTENT)
            };
            text_header(&mut response, "location", &location)?;
            text_header(&mut response, "dataserviceid", &location)?;
            text_header(
                &mut response,
                "preference-applied",
                preference(return_content),
            )?;
            Ok(response)
        }
        Operation::DeleteTable(name) => {
            store.delete_table(account, name).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::GetAcl(table) => Ok(service::acl_response(
            &store.table_acl(account, table).await?,
        )),
        Operation::SetAcl(table, policies) => {
            store.set_table_acl(account, table, policies).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::QueryEntities(table, query) => {
            let scan = EntityScan {
                filter: query.filter,
                top: query.top,
                start: query.start,
                range: ctx.credential.range().cloned(),
            };
            let page = store.query_entities(account, table.clone(), scan).await?;
            let value: Vec<Json> = page
                .entities
                .iter()
                .map(|entity| {
                    Json::Object(edm::entity_json(
                        entity,
                        &table,
                        level,
                        &ctx.urls,
                        query.select.as_ref(),
                    ))
                })
                .collect();
            let mut body = Map::new();
            body.insert("value".into(), Json::Array(value));
            let body = with_metadata(
                level,
                edm::metadata_link(&ctx.urls, Some(&table), false),
                body,
            );
            let mut response = json(StatusCode::OK, level, &body)?;
            if let Some((partition, row)) = page.next {
                text_header(
                    &mut response,
                    "x-ms-continuation-nextpartitionkey",
                    &protocol::encode_token(&partition),
                )?;
                text_header(
                    &mut response,
                    "x-ms-continuation-nextrowkey",
                    &protocol::encode_token(&row),
                )?;
            }
            Ok(response)
        }
        Operation::GetEntity(table, key, select) => {
            let entity = store.entity(account, table.clone(), key).await?;
            let body = with_metadata(
                level,
                edm::metadata_link(&ctx.urls, Some(&table), true),
                edm::entity_json(&entity, &table, level, &ctx.urls, select.as_ref()),
            );
            let mut response = json(StatusCode::OK, level, &body)?;
            text_header(&mut response, "etag", &super::model::etag(entity.timestamp))?;
            Ok(response)
        }
        Operation::Write(table, op) => {
            let kind = op.kind.clone();
            let key = op.key.clone();
            let ticks = Ticks::from_system(ctx.now);
            let written = store
                .apply(account, table.clone(), vec![op], ticks)
                .await
                .map_err(|failure| failure.error)?;
            let written = written
                .into_iter()
                .next()
                .ok_or_else(|| TableError::new(Kind::Internal))?;
            write_response(ctx, &table, &kind, &key, request.format, &written)
        }
        Operation::Batch(batch) => execute_batch(ctx, batch).await,
    }
}

fn preference(return_content: bool) -> &'static str {
    if return_content {
        "return-content"
    } else {
        "return-no-content"
    }
}

/// The response for one applied write; shared by single operations and batch parts.
fn write_response(
    ctx: &Context<'_>,
    table: &TableName,
    kind: &WriteKind,
    key: &EntityKey,
    format: Format,
    written: &Written,
) -> Result<Response> {
    let etag = super::model::etag(written.timestamp);
    let mut response = match (kind, &written.entity) {
        (WriteKind::Insert, Some(entity)) => {
            let location = format!("{}/{}", ctx.urls.base, edm::entity_path(table, key));
            let mut response = if format.return_content {
                let body = with_metadata(
                    format.level,
                    edm::metadata_link(&ctx.urls, Some(table), true),
                    edm::entity_json(entity, table, format.level, &ctx.urls, None),
                );
                json(StatusCode::CREATED, format.level, &body)?
            } else {
                empty(StatusCode::NO_CONTENT)
            };
            text_header(&mut response, "location", &location)?;
            text_header(&mut response, "dataserviceid", &location)?;
            text_header(
                &mut response,
                "preference-applied",
                preference(format.return_content),
            )?;
            response
        }
        (WriteKind::Delete, _) => return Ok(empty(StatusCode::NO_CONTENT)),
        _ => empty(StatusCode::NO_CONTENT),
    };
    text_header(&mut response, "etag", &etag)?;
    Ok(response)
}

async fn execute_batch(ctx: &Context<'_>, batch: Batch) -> Result<Response> {
    if !batch.transaction {
        let mut responses = Vec::new();
        for sub in batch.requests {
            let response = match Box::pin(execute(ctx, sub.request)).await {
                Ok(response) => response,
                Err(error) => error_response(&error, None, ctx.request_id, ctx.now),
            };
            responses.push((sub.content_id, response));
        }
        return batch::assemble(responses, false).await;
    }
    let mut table = None;
    let mut ops = Vec::new();
    let mut meta = Vec::new();
    for sub in batch.requests {
        let Operation::Write(name, op) = sub.request.operation else {
            return Err(TableError::new(Kind::Internal));
        };
        table.get_or_insert(name);
        meta.push((
            sub.content_id,
            sub.request.format,
            op.kind.clone(),
            op.key.clone(),
        ));
        ops.push(op);
    }
    let table = table.ok_or_else(|| TableError::new(Kind::Internal))?;
    let ticks = Ticks::from_system(ctx.now);
    match ctx
        .app
        .store
        .apply(ctx.account.clone(), table.clone(), ops, ticks)
        .await
    {
        Ok(written) => {
            let mut responses = Vec::with_capacity(written.len());
            for ((content_id, format, kind, key), written) in meta.into_iter().zip(&written) {
                responses.push((
                    content_id,
                    write_response(ctx, &table, &kind, &key, format, written)?,
                ));
            }
            batch::assemble(responses, true).await
        }
        Err(Failure { index, error }) => {
            let content_id = meta
                .into_iter()
                .nth(index)
                .map_or_else(|| (index + 1).to_string(), |(id, ..)| id);
            let response = error_response(&error, Some(index), ctx.request_id, ctx.now);
            batch::assemble(vec![(content_id, response)], true).await
        }
    }
}

/// Reports a batch parse failure: a failed change-set operation is a `202` with the
/// failing part, while structural errors fail the whole request.
pub(super) async fn batch_failure(
    error: batch::BatchError,
    request_id: &str,
    now: SystemTime,
) -> Result<Response> {
    match error.index {
        None => Err(error.error),
        Some(index) => {
            let response = error_response(&error.error, Some(index), request_id, now);
            batch::assemble(vec![((index + 1).to_string(), response)], true).await
        }
    }
}
