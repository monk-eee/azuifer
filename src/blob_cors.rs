//! CORS evaluation at the HTTP edge (ADR-0019). Rules come from the account's
//! stored service properties; a request without an `Origin` header is untouched.

use crate::service_props::CorsRule;
use axum::http::{HeaderMap, HeaderName, HeaderValue};

fn listed(text: &str) -> impl Iterator<Item = &str> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

/// An exact (case-insensitive) match, `*`, or a `prefix*` pattern.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix)),
        None => pattern.eq_ignore_ascii_case(name),
    }
}

/// The first rule that allows `origin` to use `method` with the requested headers.
pub(crate) fn find<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
    requested_headers: Option<&str>,
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        listed(&rule.allowed_origins).any(|allowed| allowed == "*" || allowed == origin)
            && listed(&rule.allowed_methods).any(|allowed| allowed.eq_ignore_ascii_case(method))
            && requested_headers.is_none_or(|requested| {
                listed(requested).all(|name| {
                    listed(&rule.allowed_headers).any(|pattern| pattern_matches(pattern, name))
                })
            })
    })
}

fn allow_origin(rule: &CorsRule, origin: &str) -> (&'static str, String, bool) {
    let wildcard = listed(&rule.allowed_origins).any(|allowed| allowed == "*");
    (
        "access-control-allow-origin",
        if wildcard {
            "*".into()
        } else {
            origin.to_owned()
        },
        !wildcard,
    )
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), value);
    }
}

/// Adds the headers for a non-preflight request that a rule allows.
pub(crate) fn apply(rule: &CorsRule, origin: &str, headers: &mut HeaderMap) {
    let (name, value, specific) = allow_origin(rule, origin);
    insert(headers, name, &value);
    if specific {
        insert(headers, "access-control-allow-credentials", "true");
        headers.append("vary", HeaderValue::from_static("Origin"));
    }
    let exposed: Vec<String> = headers
        .keys()
        .map(|name| name.as_str().to_owned())
        .filter(|name| {
            !name.starts_with("access-control-")
                && listed(&rule.exposed_headers).any(|pattern| pattern_matches(pattern, name))
        })
        .collect();
    if !exposed.is_empty() {
        insert(headers, "access-control-expose-headers", &exposed.join(","));
    }
}

/// The headers of a successful preflight response.
pub(crate) fn preflight(
    rule: &CorsRule,
    origin: &str,
    method: &str,
    requested: Option<&str>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let (name, value, specific) = allow_origin(rule, origin);
    insert(&mut headers, name, &value);
    insert(&mut headers, "access-control-allow-methods", method);
    if let Some(requested) = requested {
        insert(&mut headers, "access-control-allow-headers", requested);
    }
    insert(
        &mut headers,
        "access-control-max-age",
        &rule.max_age_seconds.to_string(),
    );
    if specific {
        insert(&mut headers, "access-control-allow-credentials", "true");
        headers.append("vary", HeaderValue::from_static("Origin"));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &str, methods: &str, allowed: &str, exposed: &str) -> CorsRule {
        CorsRule {
            allowed_origins: origins.into(),
            allowed_methods: methods.into(),
            allowed_headers: allowed.into(),
            exposed_headers: exposed.into(),
            max_age_seconds: 60,
        }
    }

    #[test]
    fn rules_match_origin_method_and_requested_headers() {
        let rules = [rule(
            "https://a.test",
            "GET,PUT",
            "x-ms-meta-*,content-type",
            "x-ms-*",
        )];
        assert!(find(&rules, "https://a.test", "GET", None).is_some());
        assert!(find(&rules, "https://b.test", "GET", None).is_none());
        assert!(find(&rules, "https://a.test", "DELETE", None).is_none());
        assert!(
            find(
                &rules,
                "https://a.test",
                "PUT",
                Some("Content-Type, x-ms-meta-owner")
            )
            .is_some()
        );
        assert!(find(&rules, "https://a.test", "PUT", Some("authorization")).is_none());
        assert!(find(&[rule("*", "GET", "", "")], "https://any.test", "get", None).is_some());
    }

    #[test]
    fn responses_echo_the_origin_unless_the_rule_is_a_wildcard() {
        let specific = rule("https://a.test", "GET", "", "x-ms-meta-*,etag");
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("\"1\""));
        headers.insert("x-ms-meta-a", HeaderValue::from_static("1"));
        headers.insert("x-ms-request-id", HeaderValue::from_static("id"));
        apply(&specific, "https://a.test", &mut headers);
        assert_eq!(headers["access-control-allow-origin"], "https://a.test");
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(headers["vary"], "Origin");
        let exposed = headers["access-control-expose-headers"].to_str().unwrap();
        assert!(
            exposed.contains("etag")
                && exposed.contains("x-ms-meta-a")
                && !exposed.contains("request-id")
        );
        let wildcard = preflight(
            &rule("*", "GET", "*", ""),
            "https://z.test",
            "GET",
            Some("x-any"),
        );
        assert_eq!(wildcard["access-control-allow-origin"], "*");
        assert_eq!(wildcard["access-control-allow-headers"], "x-any");
        assert_eq!(wildcard["access-control-max-age"], "60");
        assert!(!wildcard.contains_key("access-control-allow-credentials"));
    }
}
