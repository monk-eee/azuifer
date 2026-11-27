//! Blob index tags (ADR-0019): the tag set, its header and XML forms, and the
//! filter expression behind `x-ms-if-tags` and Find Blobs by Tags.

use crate::{
    blob_batch,
    blob_exec::{self, Context},
    domain::{Error, Result},
    protocol::Operation,
    respond::empty,
    server::App,
    store::TaggedBlob,
    wire::Xml,
    xml_tree,
};
use axum::{body::Body, http::StatusCode, response::Response};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

pub(crate) type Tags = BTreeMap<String, String>;

const MAX_TAGS: usize = 10;
const MAX_KEY: usize = 128;
const MAX_VALUE: usize = 256;
const MAX_FILTER_CHARS: usize = 2000;
const MAX_TERMS: usize = 32;

fn allowed(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '+' | '-' | '.' | '/' | ':' | '=' | '_'))
}

/// Checks the limits Azure applies to a tag set: ten tags, 1 to 128 character
/// keys, 0 to 256 character values, and the permitted characters.
pub(crate) fn validate(tags: &Tags) -> Result<()> {
    if tags.len() > MAX_TAGS {
        return Err(Error::TagsTooLarge);
    }
    for (key, value) in tags {
        let (key_len, value_len) = (key.chars().count(), value.chars().count());
        if key_len > MAX_KEY || value_len > MAX_VALUE {
            return Err(Error::TagsTooLarge);
        }
        if key_len == 0 || !allowed(key) || !allowed(value) {
            return Err(Error::InvalidTag);
        }
    }
    Ok(())
}

fn unescape(text: &str) -> Result<String> {
    percent_decode_str(text)
        .decode_utf8()
        .map(|text| text.into_owned())
        .map_err(|_| Error::InvalidTag)
}

/// Parses the `x-ms-tags` header: URL-encoded `key=value` pairs joined by `&`.
pub(crate) fn from_header(value: &str) -> Result<Tags> {
    let mut tags = Tags::new();
    if value.is_empty() {
        return Ok(tags);
    }
    for pair in value.split('&') {
        let (key, text) = pair.split_once('=').ok_or(Error::InvalidTag)?;
        if tags.insert(unescape(key)?, unescape(text)?).is_some() {
            return Err(Error::InvalidTag);
        }
    }
    validate(&tags)?;
    Ok(tags)
}

/// Parses a Set Blob Tags body: `<Tags><TagSet><Tag><Key/><Value/></Tag>…`.
pub(crate) fn from_xml(body: &[u8]) -> Result<Tags> {
    let root = xml_tree::parse(body)?;
    if root.name != "Tags" {
        return Err(Error::InvalidXml);
    }
    let mut tags = Tags::new();
    if let Some(set) = root.child("TagSet") {
        for tag in set.named("Tag") {
            let key = tag.text_of("Key").ok_or(Error::InvalidXml)?;
            let value = tag.text_of("Value").ok_or(Error::InvalidXml)?;
            if tags.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(Error::InvalidTag);
            }
        }
    }
    validate(&tags)?;
    Ok(tags)
}

pub(crate) fn write_tag_set(xml: &mut Xml, tags: &Tags) {
    xml.open("TagSet");
    for (key, value) in tags {
        xml.open("Tag");
        xml.element("Key", key);
        xml.element("Value", value);
        xml.close("Tag");
    }
    xml.close("TagSet");
}

pub(crate) fn tags_response(tags: &Tags) -> Response {
    let mut xml = Xml::root("Tags", &[]);
    write_tag_set(&mut xml, tags);
    xml.finish("Tags", StatusCode::OK)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
        }
    }

    fn holds(self, left: &str, right: &str) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
            Self::Lt => left < right,
            Self::Le => left <= right,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Term {
    Container(String),
    Tag { key: String, op: Op, value: String },
}

/// A conjunction of tag comparisons, e.g. `"Status" = 'Final' AND "Year" >= '2018'`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TagFilter {
    pub(crate) terms: Vec<Term>,
    /// The expression as the client sent it, echoed in Find Blobs results.
    pub(crate) text: String,
}

#[derive(Debug, PartialEq)]
enum Token {
    Container,
    Name(String),
    Literal(String),
    Op(Op),
    And,
}

fn quoted(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, quote: char) -> Result<String> {
    let mut text = String::new();
    loop {
        match chars.next() {
            Some(c) if c == quote => {
                if chars.peek() == Some(&quote) {
                    chars.next();
                    text.push(quote);
                } else {
                    return Ok(text);
                }
            }
            Some(c) => text.push(c),
            None => return Err(Error::InvalidQuery),
        }
    }
}

fn tokens(text: &str) -> Result<Vec<Token>> {
    let mut chars = text.chars().peekable();
    let mut found = Vec::new();
    while let Some(c) = chars.next() {
        found.push(match c {
            c if c.is_whitespace() => continue,
            '@' => {
                let word: String =
                    std::iter::from_fn(|| chars.next_if(char::is_ascii_alphabetic)).collect();
                if word != "container" {
                    return Err(Error::InvalidQuery);
                }
                Token::Container
            }
            '"' => Token::Name(quoted(&mut chars, '"')?),
            '\'' => Token::Literal(quoted(&mut chars, '\'')?),
            '=' => Token::Op(Op::Eq),
            '>' => Token::Op(if chars.next_if_eq(&'=').is_some() {
                Op::Ge
            } else {
                Op::Gt
            }),
            '<' => Token::Op(if chars.next_if_eq(&'=').is_some() {
                Op::Le
            } else {
                Op::Lt
            }),
            c if c.is_ascii_alphabetic() => {
                let mut word = c.to_string();
                word.extend(std::iter::from_fn(|| {
                    chars.next_if(char::is_ascii_alphabetic)
                }));
                if !word.eq_ignore_ascii_case("and") {
                    return Err(Error::InvalidQuery);
                }
                Token::And
            }
            _ => return Err(Error::InvalidQuery),
        });
    }
    Ok(found)
}

impl TagFilter {
    /// Parses a filter. `@container = 'name'` is accepted only when `containers`
    /// is true (account-level Find Blobs by Tags); conditions never use it.
    pub(crate) fn parse(text: &str, containers: bool) -> Result<Self> {
        if text.chars().count() > MAX_FILTER_CHARS {
            return Err(Error::InvalidQuery);
        }
        let tokens = tokens(text)?;
        let mut terms = Vec::new();
        let mut iter = tokens.into_iter();
        loop {
            let term = match (iter.next(), iter.next(), iter.next()) {
                (Some(Token::Container), Some(Token::Op(Op::Eq)), Some(Token::Literal(name)))
                    if containers =>
                {
                    Term::Container(name)
                }
                (Some(Token::Name(key)), Some(Token::Op(op)), Some(Token::Literal(value)))
                    if !key.is_empty() =>
                {
                    Term::Tag { key, op, value }
                }
                _ => return Err(Error::InvalidQuery),
            };
            terms.push(term);
            match iter.next() {
                None => break,
                Some(Token::And) => (),
                Some(_) => return Err(Error::InvalidQuery),
            }
            if terms.len() >= MAX_TERMS {
                return Err(Error::InvalidQuery);
            }
        }
        Ok(Self {
            terms,
            text: text.to_owned(),
        })
    }

    /// Evaluates the tag terms; container terms are the caller's concern.
    pub(crate) fn matches(&self, tags: &Tags) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Container(_) => true,
            Term::Tag { key, op, value } => {
                tags.get(key).is_some_and(|stored| op.holds(stored, value))
            }
        })
    }
}

fn find_response(
    endpoint: &str,
    filter: &TagFilter,
    items: Vec<(String, TaggedBlob)>,
    next: &str,
) -> Response {
    let mut xml = Xml::root("EnumerationResults", &[("ServiceEndpoint", endpoint)]);
    xml.element("Where", &filter.text);
    xml.open("Blobs");
    for (_, blob) in items {
        xml.open("Blob");
        xml.element("Name", &blob.name);
        xml.element("ContainerName", &blob.container);
        xml.open("Tags");
        write_tag_set(&mut xml, &blob.tags);
        xml.close("Tags");
        xml.close("Blob");
    }
    xml.close("Blobs");
    xml.element("NextMarker", next);
    xml.finish("EnumerationResults", StatusCode::OK)
}

/// Runs the tag operations and forwards Submit Batch.
pub(crate) async fn execute(
    app: &App,
    op: Operation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    match op {
        Operation::SetBlobTags(key, version, options, guard) => {
            let (bytes, _) = blob_exec::read_bounded(app, body, &options).await?;
            let tags = from_xml(&bytes)?;
            app.store.set_blob_tags(key, version, tags, guard).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::GetBlobTags(key, version, guard) => {
            let tags = app.store.blob_tags(key, version, guard).await?;
            Ok(tags_response(&tags))
        }
        Operation::FindBlobs(account, scope, filter, page) => {
            let endpoint = blob_exec::storage_endpoint(app, account.as_str());
            let found = app
                .store
                .find_blobs_by_tags(account, scope, filter.clone(), page)
                .await?;
            Ok(find_response(&endpoint, &filter, found.items, &found.next))
        }
        other => blob_batch::execute(app, other, body, ctx).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> Tags {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn filters_parse_quoted_names_literals_and_operators() {
        let filter = TagFilter::parse(
            r#"@container = 'box' AND "Year" >= '2018' and "it's" < 'a''b'"#,
            true,
        )
        .unwrap();
        assert_eq!(
            filter.terms,
            vec![
                Term::Container("box".into()),
                Term::Tag {
                    key: "Year".into(),
                    op: Op::Ge,
                    value: "2018".into()
                },
                Term::Tag {
                    key: "it's".into(),
                    op: Op::Lt,
                    value: "a'b".into()
                },
            ]
        );
    }

    #[test]
    fn invalid_filters_are_rejected() {
        for bad in [
            "",
            r#""a" = 'b' OR "c" = 'd'"#,
            r#"a = 'b'"#,
            r#""a" = b"#,
            r#""a" = 'b' AND"#,
            r#""a" != 'b'"#,
            r#""a" = 'unterminated"#,
            r#""" = 'x'"#,
            r#"@container > 'x'"#,
            r#"@other = 'x'"#,
            r#"("a" = 'b')"#,
        ] {
            assert_eq!(
                TagFilter::parse(bad, true),
                Err(Error::InvalidQuery),
                "{bad}"
            );
        }
        assert_eq!(
            TagFilter::parse("@container = 'x'", false),
            Err(Error::InvalidQuery)
        );
        let long = format!("\"k\" = '{}'", "v".repeat(2000));
        assert!(TagFilter::parse(&long, false).is_err());
    }

    #[test]
    fn comparisons_are_ordinal_string_comparisons() {
        let blob = tags(&[("Status", "Final"), ("Date", "2018-07-01")]);
        let hit = |text: &str| TagFilter::parse(text, false).unwrap().matches(&blob);
        assert!(hit(r#""Status" = 'Final'"#));
        assert!(!hit(r#""Status" = 'final'"#));
        assert!(hit(r#""Date" >= '2018-06-18' AND "Date" < '2018-07-18'"#));
        assert!(!hit(r#""Date" > '2018-07-01'"#));
        assert!(!hit(r#""Missing" = 'x'"#));
    }

    #[test]
    fn tag_sets_enforce_azure_limits() {
        assert_eq!(from_header("a=1&b=two%20words").unwrap().len(), 2);
        assert_eq!(from_header("").unwrap().len(), 0);
        assert_eq!(from_header("a=1&a=2"), Err(Error::InvalidTag));
        assert_eq!(from_header("novalue"), Err(Error::InvalidTag));
        assert_eq!(from_header("a=%3B"), Err(Error::InvalidTag));
        let eleven: Vec<String> = (0..11).map(|n| format!("k{n}=v")).collect();
        assert_eq!(from_header(&eleven.join("&")), Err(Error::TagsTooLarge));
        assert_eq!(
            from_header(&format!("{}=v", "k".repeat(129))),
            Err(Error::TagsTooLarge)
        );
        assert_eq!(
            from_header(&format!("k={}", "v".repeat(257))),
            Err(Error::TagsTooLarge)
        );
        assert!(from_header(&format!("{}={}", "k".repeat(128), "v".repeat(256))).is_ok());
        assert_eq!(from_header("=v"), Err(Error::InvalidTag));
    }

    #[test]
    fn tag_xml_round_trips() {
        let parsed = from_xml(
            b"<Tags><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value></Value></Tag></TagSet></Tags>",
        )
        .unwrap();
        assert_eq!(parsed, tags(&[("a", "1"), ("b", "")]));
        assert_eq!(from_xml(b"<Tags/>").unwrap().len(), 0);
        assert_eq!(from_xml(b"<Wrong/>"), Err(Error::InvalidXml));
        assert_eq!(
            from_xml(b"<Tags><TagSet><Tag><Key>a</Key></Tag></TagSet></Tags>"),
            Err(Error::InvalidXml)
        );
    }

    #[test]
    fn hostile_tag_text_is_answered_without_panic() {
        crate::hostile::sweep(
            &["\"Status\" = 'Final' AND \"Year\" >= '2018' AND @container = 'a''b'"],
            ("(", ")"),
            |text| {
                let _ = TagFilter::parse(text, true);
                let _ = TagFilter::parse(text, false);
            },
        );
        crate::hostile::sweep(&["a=b&c%20d=e%2Ff&g="], ("&", "="), |text| {
            let _ = from_header(text);
        });
        let seed = "<Tags><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tags>";
        crate::hostile::sweep(&[seed], ("<Tag>", "</Tag>"), |text| {
            let _ = from_xml(text.as_bytes());
        });
        let long = format!("\"k\" = '{}'", "x".repeat(2_000_000));
        assert_eq!(
            TagFilter::parse(&long, true).err(),
            Some(Error::InvalidQuery)
        );
        let many = format!("\"k\" = 'v'{}", " AND \"k\" = 'v'".repeat(100));
        assert_eq!(
            TagFilter::parse(&many, true).err(),
            Some(Error::InvalidQuery)
        );
    }
}
