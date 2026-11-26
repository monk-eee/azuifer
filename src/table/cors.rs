//! CORS for the Table service: the rules stored by Set Table Service Properties are matched
//! for `OPTIONS` preflights and added to responses of requests that carry an `Origin`,
//! with the matching code shared with Blob (ADR-0019).

use super::{
    App,
    error::{Kind, TableError},
    handlers, protocol,
};
use crate::{
    blob_cors,
    service_props::{self, CorsRule},
    xml_tree,
};
use axum::{
    http::{HeaderMap, StatusCode, request::Parts},
    response::Response,
};
use std::time::SystemTime;

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Parses the stored `<Cors>` element; an unreadable one is treated as no rules.
pub(super) fn parse_rules(stored: &str) -> Option<Vec<CorsRule>> {
    let node = xml_tree::parse(stored.as_bytes()).ok()?;
    service_props::parse_cors(&node).ok()
}

async fn rules(app: &App, parts: &Parts) -> Vec<CorsRule> {
    let (path, _) = protocol::logical_path(parts);
    let Ok((account, _, _)) = protocol::parse_path(&path) else {
        return Vec::new();
    };
    let Ok(stored) = app.store.service_properties(account).await else {
        return Vec::new();
    };
    stored
        .get("Cors")
        .and_then(|cors| parse_rules(cors))
        .unwrap_or_default()
}

/// Answers a browser preflight from the account's stored CORS rules.
pub(super) async fn preflight(
    app: &App,
    parts: &Parts,
    request_id: &str,
    now: SystemTime,
) -> Response {
    let headers = &parts.headers;
    let (Some(origin), Some(method)) = (
        header_text(headers, "origin"),
        header_text(headers, "access-control-request-method"),
    ) else {
        return handlers::error_response(
            &TableError::new(Kind::MissingRequiredHeader),
            None,
            request_id,
            now,
        );
    };
    let requested = header_text(headers, "access-control-request-headers");
    let rules = rules(app, parts).await;
    match blob_cors::find(&rules, origin, method, requested) {
        Some(rule) => {
            let mut response = Response::new(axum::body::Body::empty());
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .extend(blob_cors::preflight(rule, origin, method, requested));
            response
        }
        None => handlers::error_response(
            &TableError::new(Kind::CorsPreflightFailure),
            None,
            request_id,
            now,
        ),
    }
}

/// Adds `Access-Control-*` headers when a rule allows the request's origin and method.
pub(super) async fn decorate(app: &App, parts: &Parts, response: &mut Response) {
    let Some(origin) = header_text(&parts.headers, "origin") else {
        return;
    };
    let rules = rules(app, parts).await;
    if let Some(rule) = blob_cors::find(&rules, origin, parts.method.as_str(), None) {
        blob_cors::apply(rule, origin, response.headers_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_rules_are_read_back() {
        let stored = "<Cors><CorsRule><AllowedOrigins>*</AllowedOrigins>\
            <AllowedMethods>GET,POST</AllowedMethods><MaxAgeInSeconds>30</MaxAgeInSeconds>\
            <ExposedHeaders>x-ms-*</ExposedHeaders><AllowedHeaders>*</AllowedHeaders>\
            </CorsRule></Cors>";
        let rules = parse_rules(stored).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].max_age_seconds, 30);
        assert!(parse_rules("<Cors />").unwrap().is_empty());
        assert!(parse_rules("<Cors>").is_none());
    }
}
