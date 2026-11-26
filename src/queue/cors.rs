use super::{
    error::{QueueError, Result},
    model::CorsRule,
    protocol::Preflight,
};
use axum::{
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};

fn list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn origin_allowed(rule: &CorsRule, origin: &str) -> bool {
    list(&rule.allowed_origins)
        .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(origin))
}

fn method_allowed(rule: &CorsRule, method: &str) -> bool {
    list(&rule.allowed_methods).any(|allowed| allowed.eq_ignore_ascii_case(method))
}

/// Header names match exactly or by a trailing-`*` prefix pattern such as `x-ms-meta-*`.
fn header_allowed(rule: &CorsRule, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    list(&rule.allowed_headers).any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => pattern == name,
        }
    })
}

fn rule_header(name: &'static str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    Ok((
        HeaderName::from_static(name),
        HeaderValue::from_str(value).map_err(|_| QueueError::Internal)?,
    ))
}

fn allow_origin<'a>(rule: &'a CorsRule, origin: &'a str) -> (&'a str, bool) {
    if list(&rule.allowed_origins).any(|allowed| allowed == "*") {
        ("*", false)
    } else {
        (origin, true)
    }
}

/// Answers an OPTIONS preflight from the stored rules, or fails like Azure does.
pub(super) fn preflight(rules: &[CorsRule], request: &Preflight) -> Result<Response> {
    let rule = rules
        .iter()
        .find(|rule| {
            origin_allowed(rule, &request.origin)
                && method_allowed(rule, &request.method)
                && request
                    .headers
                    .iter()
                    .all(|name| header_allowed(rule, name))
        })
        .ok_or(QueueError::CorsPreflightFailure)?;
    let (origin, credentials) = allow_origin(rule, &request.origin);
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    let mut add = |name, value: &str| -> Result<()> {
        let (name, value) = rule_header(name, value)?;
        headers.insert(name, value);
        Ok(())
    };
    add("access-control-allow-origin", origin)?;
    add("access-control-allow-methods", &request.method)?;
    add("access-control-max-age", &rule.max_age.to_string())?;
    if !request.headers.is_empty() {
        add("access-control-allow-headers", &request.headers.join(","))?;
    }
    if credentials {
        add("access-control-allow-credentials", "true")?;
        add("vary", "Origin")?;
    }
    Ok(response)
}

/// Adds the CORS response headers of the first rule matching a normal request.
pub(super) fn decorate(
    rules: &[CorsRule],
    request: &HeaderMap,
    method: &str,
    response: &mut Response,
) {
    let Some(origin) = request.get("origin").and_then(|value| value.to_str().ok()) else {
        return;
    };
    let Some(rule) = rules
        .iter()
        .find(|rule| origin_allowed(rule, origin) && method_allowed(rule, method))
    else {
        return;
    };
    let (allowed, credentials) = allow_origin(rule, origin);
    let mut set = |name, value: &str| {
        if let Ok((name, value)) = rule_header(name, value) {
            response.headers_mut().insert(name, value);
        }
    };
    set("access-control-allow-origin", allowed);
    if !rule.exposed_headers.is_empty() {
        set("access-control-expose-headers", &rule.exposed_headers);
    }
    if credentials {
        set("access-control-allow-credentials", "true");
        set("vary", "Origin");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &str, methods: &str, headers: &str) -> CorsRule {
        CorsRule {
            allowed_origins: origins.into(),
            allowed_methods: methods.into(),
            max_age: 60,
            exposed_headers: "x-ms-*".into(),
            allowed_headers: headers.into(),
        }
    }

    fn request(origin: &str, method: &str, headers: &[&str]) -> Preflight {
        Preflight {
            origin: origin.into(),
            method: method.into(),
            headers: headers.iter().map(|h| (*h).into()).collect(),
        }
    }

    #[test]
    fn preflight_matches_origin_method_and_header_patterns() {
        let rules = [rule(
            "http://a.example",
            "GET,PUT",
            "x-ms-meta-*,content-type",
        )];
        let ok = preflight(
            &rules,
            &request(
                "HTTP://A.example",
                "put",
                &["X-MS-META-foo", "Content-Type"],
            ),
        )
        .unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(
            ok.headers()["access-control-allow-origin"],
            "HTTP://A.example"
        );
        assert_eq!(ok.headers()["access-control-max-age"], "60");
        assert_eq!(ok.headers()["access-control-allow-credentials"], "true");
        for bad in [
            request("http://b.example", "GET", &[]),
            request("http://a.example", "DELETE", &[]),
            request("http://a.example", "GET", &["authorization"]),
        ] {
            assert_eq!(
                preflight(&rules, &bad).err(),
                Some(QueueError::CorsPreflightFailure)
            );
        }
        assert_eq!(
            preflight(&[], &request("http://a.example", "GET", &[])).err(),
            Some(QueueError::CorsPreflightFailure)
        );
    }

    #[test]
    fn wildcard_origin_answers_star_without_credentials() {
        let rules = [rule("*", "GET", "")];
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("http://any.example"));
        let mut response = Response::new(axum::body::Body::empty());
        decorate(&rules, &headers, "GET", &mut response);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(
            response.headers()["access-control-expose-headers"],
            "x-ms-*"
        );
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
        let mut untouched = Response::new(axum::body::Body::empty());
        decorate(&rules, &headers, "DELETE", &mut untouched);
        assert!(untouched.headers().is_empty());
    }
}
