//! HTTP preconditions shared by every Blob and container operation.

use crate::{
    auth::header,
    blob_tags::{TagFilter, Tags},
    domain::{ETag, Entity, Error, Result},
    lease::LeaseId,
};
use axum::http::HeaderMap;
use std::time::UNIX_EPOCH;

#[derive(Clone, Debug, Eq, PartialEq)]
enum TagMatch {
    Any,
    Tag(String),
}

impl TagMatch {
    fn parse(value: &str) -> Result<Self> {
        if value == "*" {
            Ok(Self::Any)
        } else {
            Ok(Self::Tag(ETag::parse(value)?.as_str().to_owned()))
        }
    }

    fn matches(&self, current: Option<Entity>) -> bool {
        match (self, current) {
            (Self::Any, Some(_)) => true,
            (Self::Tag(tag), Some(entity)) => entity.etag().as_str() == tag,
            (_, None) => false,
        }
    }
}

/// The four standard conditional headers; both ETag conditions may be combined.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Conditions {
    if_match: Option<TagMatch>,
    if_none_match: Option<TagMatch>,
    if_modified_since: Option<u64>,
    if_unmodified_since: Option<u64>,
    if_tags: Option<TagFilter>,
}

/// Header names for one set of conditions, e.g. the destination or the copy source.
pub(crate) struct ConditionHeaders {
    pub(crate) if_match: &'static str,
    pub(crate) if_none_match: &'static str,
    pub(crate) if_modified_since: &'static str,
    pub(crate) if_unmodified_since: &'static str,
    pub(crate) if_tags: &'static str,
}

pub(crate) const STANDARD: ConditionHeaders = ConditionHeaders {
    if_match: "if-match",
    if_none_match: "if-none-match",
    if_modified_since: "if-modified-since",
    if_unmodified_since: "if-unmodified-since",
    if_tags: "x-ms-if-tags",
};

pub(crate) const SOURCE: ConditionHeaders = ConditionHeaders {
    if_match: "x-ms-source-if-match",
    if_none_match: "x-ms-source-if-none-match",
    if_modified_since: "x-ms-source-if-modified-since",
    if_unmodified_since: "x-ms-source-if-unmodified-since",
    if_tags: "x-ms-source-if-tags",
};

fn http_seconds(value: &str) -> Result<u64> {
    httpdate::parse_http_date(value)
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs())
        .ok_or(Error::InvalidHeader)
}

impl Conditions {
    pub(crate) fn parse(headers: &HeaderMap, names: &ConditionHeaders) -> Result<Self> {
        let tag = |name| header(headers, name)?.map(TagMatch::parse).transpose();
        let date = |name| header(headers, name)?.map(http_seconds).transpose();
        Ok(Self {
            if_match: tag(names.if_match)?,
            if_none_match: tag(names.if_none_match)?,
            if_modified_since: date(names.if_modified_since)?,
            if_unmodified_since: date(names.if_unmodified_since)?,
            if_tags: header(headers, names.if_tags)?
                .map(|text| TagFilter::parse(text, false).map_err(|_| Error::InvalidHeader))
                .transpose()?,
        })
    }

    /// Evaluates `x-ms-if-tags` against the blob's tags; `None` means the blob is absent.
    pub(crate) fn check_tags(&self, tags: Option<&Tags>) -> Result<()> {
        match (&self.if_tags, tags) {
            (None, _) => Ok(()),
            (Some(filter), Some(tags)) if filter.matches(tags) => Ok(()),
            _ => Err(Error::ConditionNotMet),
        }
    }

    /// True for `If-None-Match: *`, which Put Blob answers with `BlobAlreadyExists`.
    pub(crate) fn requires_absence(&self) -> bool {
        self.if_none_match == Some(TagMatch::Any)
    }

    /// Evaluates the conditions against the current resource. A failed
    /// `If-None-Match` or `If-Modified-Since` is `NotModified` for reads and
    /// `ConditionNotMet` for writes; every other failure is `ConditionNotMet`.
    pub(crate) fn check(&self, current: Option<Entity>, reading: bool) -> Result<()> {
        if self
            .if_match
            .as_ref()
            .is_some_and(|condition| !condition.matches(current))
        {
            return Err(Error::ConditionNotMet);
        }
        if let Some(limit) = self.if_unmodified_since
            && current.is_none_or(|entity| entity.modified > limit)
        {
            return Err(Error::ConditionNotMet);
        }
        let tag_failed = self
            .if_none_match
            .as_ref()
            .is_some_and(|condition| condition.matches(current));
        let date_failed = self
            .if_modified_since
            .is_some_and(|limit| current.is_none_or(|entity| entity.modified <= limit));
        if tag_failed || date_failed {
            return Err(if reading {
                Error::NotModified
            } else {
                Error::ConditionNotMet
            });
        }
        Ok(())
    }
}

/// The preconditions of one operation: HTTP conditions plus `x-ms-lease-id`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Guard {
    pub(crate) conditions: Conditions,
    pub(crate) lease: Option<LeaseId>,
}

impl Guard {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        Ok(Self {
            conditions: Conditions::parse(headers, &STANDARD)?,
            lease: lease_id(headers, "x-ms-lease-id")?,
        })
    }
}

pub(crate) fn lease_id(headers: &HeaderMap, name: &str) -> Result<Option<LeaseId>> {
    header(headers, name)?.map(LeaseId::parse).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use uuid::Uuid;

    fn entity(n: u128, modified: u64) -> Entity {
        Entity {
            id: Uuid::from_u128(n),
            tag: Uuid::from_u128(n),
            modified,
            version: None,
        }
    }

    fn conditions(pairs: &[(&'static str, String)]) -> Result<Conditions> {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        Conditions::parse(&headers, &STANDARD)
    }

    const NOON: &str = "Fri, 03 Nov 2023 12:00:00 GMT";
    const NOON_SECONDS: u64 = 1_699_012_800;

    #[test]
    fn etag_conditions_combine_and_distinguish_reads_from_writes() {
        let current = entity(17, 0);
        let tag = current.etag().as_str().to_owned();
        let other = entity(19, 0).etag().as_str().to_owned();
        let both =
            conditions(&[("if-match", tag.clone()), ("if-none-match", other.clone())]).unwrap();
        assert_eq!(both.check(Some(current), false), Ok(()));
        let clash =
            conditions(&[("if-match", tag.clone()), ("if-none-match", tag.clone())]).unwrap();
        assert_eq!(clash.check(Some(current), true), Err(Error::NotModified));
        assert_eq!(
            clash.check(Some(current), false),
            Err(Error::ConditionNotMet)
        );
        let mismatch = conditions(&[("if-match", other)]).unwrap();
        assert_eq!(
            mismatch.check(Some(current), true),
            Err(Error::ConditionNotMet)
        );
        let star = conditions(&[("if-none-match", "*".into())]).unwrap();
        assert!(star.requires_absence());
        assert_eq!(star.check(None, false), Ok(()));
        assert_eq!(
            conditions(&[("if-match", "*".into())])
                .unwrap()
                .check(None, false),
            Err(Error::ConditionNotMet)
        );
        assert_eq!(conditions(&[]).unwrap().check(None, false), Ok(()));
    }

    #[test]
    fn date_conditions_compare_whole_seconds() {
        let at_noon = entity(1, NOON_SECONDS);
        let before = entity(2, NOON_SECONDS - 1);
        let after = entity(3, NOON_SECONDS + 1);
        let since = conditions(&[("if-modified-since", NOON.into())]).unwrap();
        assert_eq!(since.check(Some(after), true), Ok(()));
        assert_eq!(since.check(Some(at_noon), true), Err(Error::NotModified));
        assert_eq!(
            since.check(Some(before), false),
            Err(Error::ConditionNotMet)
        );
        let unmodified = conditions(&[("if-unmodified-since", NOON.into())]).unwrap();
        assert_eq!(unmodified.check(Some(at_noon), false), Ok(()));
        assert_eq!(
            unmodified.check(Some(after), true),
            Err(Error::ConditionNotMet)
        );
        assert!(conditions(&[("if-modified-since", "yesterday".into())]).is_err());
    }

    #[test]
    fn source_headers_use_their_own_names() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-source-if-match", HeaderValue::from_static("*"));
        assert!(
            Conditions::parse(&headers, &STANDARD)
                .unwrap()
                .check(None, false)
                .is_ok()
        );
        assert!(
            Conditions::parse(&headers, &SOURCE)
                .unwrap()
                .check(None, false)
                .is_err()
        );
    }
}
