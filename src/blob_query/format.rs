//! Delimited text and JSON lines: the query request's serialization settings, the input
//! readers, and the output writers.

use super::sql::{Row, Value};
use crate::{
    domain::{Error, Result},
    xml_tree::Node,
};
use serde_json::Value as Json;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Delimited {
    pub(super) column: char,
    pub(super) quote: Option<char>,
    pub(super) escape: Option<char>,
    pub(super) record: String,
    pub(super) headers: bool,
}

impl Default for Delimited {
    fn default() -> Self {
        Self {
            column: ',',
            quote: Some('"'),
            escape: None,
            record: "\n".to_owned(),
            headers: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Format {
    Delimited(Delimited),
    Json { record: String },
}

fn single(text: &str) -> Result<Option<char>> {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (None, _) => Ok(None),
        (Some(c), None) => Ok(Some(c)),
        _ => Err(Error::InvalidXml),
    }
}

fn delimited(node: &Node) -> Result<Delimited> {
    let mut config = Delimited::default();
    if let Some(column) = node.child("ColumnSeparator")
        && let Some(c) = single(&column.raw)?
    {
        config.column = c;
    }
    if let Some(quote) = node.child("FieldQuote") {
        config.quote = single(&quote.raw)?;
    }
    if let Some(escape) = node.child("EscapeChar") {
        config.escape = single(&escape.raw)?;
    }
    if let Some(record) = node.child("RecordSeparator")
        && !record.raw.is_empty()
    {
        config.record.clone_from(&record.raw);
    }
    config.headers = node.flag("HasHeaders")?.unwrap_or(false);
    Ok(config)
}

/// The serialization named by an `InputSerialization` or `OutputSerialization` element.
/// `Ok(None)` is an absent element; `Err(Unsupported)` is Arrow or Parquet.
pub(super) fn serialization(node: Option<&Node>) -> Result<Option<Format>> {
    let Some(node) = node else {
        return Ok(None);
    };
    let format = node.child("Format").ok_or(Error::InvalidXml)?;
    Ok(Some(
        match format.text_of("Type").ok_or(Error::InvalidXml)? {
            "delimited" => Format::Delimited(
                format
                    .child("DelimitedTextConfiguration")
                    .map_or_else(|| Ok(Delimited::default()), delimited)?,
            ),
            "json" => {
                let record = format
                    .child("JsonTextConfiguration")
                    .and_then(|config| config.child("RecordSeparator"))
                    .filter(|record| !record.raw.is_empty())
                    .map_or_else(|| "\n".to_owned(), |record| record.raw.clone());
                Format::Json { record }
            }
            "arrow" | "parquet" => return Err(Error::Unsupported),
            _ => return Err(Error::InvalidXml),
        },
    ))
}

pub(super) struct Input {
    pub(super) headers: Option<Vec<String>>,
    pub(super) rows: Vec<Row>,
}

/// A malformed record: the message and its byte offset.
pub(super) struct ReadError {
    pub(super) message: String,
    pub(super) position: u64,
}

pub(super) fn read(text: &str, format: &Format) -> std::result::Result<Input, ReadError> {
    match format {
        Format::Delimited(config) => Ok(read_delimited(text, config)),
        Format::Json { .. } => read_json(text),
    }
}

fn read_json(text: &str) -> std::result::Result<Input, ReadError> {
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Json>();
    let mut rows = Vec::new();
    loop {
        match stream.next() {
            None => break,
            Some(Ok(value)) => rows.push(Row::Json(value)),
            Some(Err(error)) => {
                return Err(ReadError {
                    message: format!("invalid JSON: {error}"),
                    position: stream.byte_offset() as u64,
                });
            }
        }
    }
    Ok(Input {
        headers: None,
        rows,
    })
}

fn read_delimited(text: &str, config: &Delimited) -> Input {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quote = false;
    let mut quoted = false;
    let chars: Vec<char> = text.chars().collect();
    let separator: Vec<char> = config.record.chars().collect();
    let mut at = 0;
    let mut record_started = false;
    while at < chars.len() {
        let c = chars[at];
        if in_quote {
            if Some(c) == config.escape && config.escape != config.quote && at + 1 < chars.len() {
                field.push(chars[at + 1]);
                at += 2;
            } else if Some(c) == config.quote {
                if chars.get(at + 1) == Some(&c) {
                    field.push(c);
                    at += 2;
                } else {
                    in_quote = false;
                    at += 1;
                }
            } else {
                field.push(c);
                at += 1;
            }
            continue;
        }
        if chars[at..].starts_with(&separator) && !separator.is_empty() {
            if config.record == "\n" && at > 0 && chars[at - 1] == '\r' {
                field.pop();
            }
            fields.push(std::mem::take(&mut field));
            records.push(std::mem::take(&mut fields));
            quoted = false;
            record_started = false;
            at += separator.len();
            continue;
        }
        record_started = true;
        if c == config.column {
            fields.push(std::mem::take(&mut field));
            quoted = false;
        } else if Some(c) == config.quote && field.is_empty() && !quoted {
            in_quote = true;
            quoted = true;
        } else {
            field.push(c);
        }
        at += 1;
    }
    if record_started || !field.is_empty() || !fields.is_empty() {
        fields.push(field);
        records.push(fields);
    }
    let mut records = records.into_iter();
    let headers = if config.headers { records.next() } else { None };
    Input {
        headers,
        rows: records.map(Row::Csv).collect(),
    }
}

/// One output record, without its separator.
pub(super) fn write(columns: &[(String, Value)], format: &Format) -> String {
    match format {
        Format::Delimited(config) => columns
            .iter()
            .map(|(_, value)| quote_field(&value.to_text(), config))
            .collect::<Vec<_>>()
            .join(&config.column.to_string()),
        Format::Json { .. } => {
            let mut out = String::from("{");
            for (index, (name, value)) in columns.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Json::String(name.clone()).to_string());
                out.push(':');
                out.push_str(&value.to_json().to_string());
            }
            out.push('}');
            out
        }
    }
}

pub(super) fn separator(format: &Format) -> &str {
    match format {
        Format::Delimited(config) => &config.record,
        Format::Json { record } => record,
    }
}

fn quote_field(text: &str, config: &Delimited) -> String {
    let Some(quote) = config.quote else {
        return text.to_owned();
    };
    let needs = text.contains(config.column)
        || text.contains(quote)
        || text.contains('\n')
        || text.contains('\r')
        || (!config.record.is_empty() && text.contains(config.record.as_str()));
    if !needs {
        return text.to_owned();
    }
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        if c == quote {
            out.push(config.escape.unwrap_or(quote));
        }
        out.push(c);
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml_tree;

    fn rows(input: &Input) -> Vec<Vec<&str>> {
        input
            .rows
            .iter()
            .map(|row| match row {
                Row::Csv(fields) => fields.iter().map(String::as_str).collect(),
                Row::Json(_) => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn delimited_text_handles_quotes_embedded_separators_and_crlf() {
        let config = Delimited {
            headers: true,
            ..Delimited::default()
        };
        let input = read_delimited("a,b\r\n1,\"x,\"\"y\"\"\nz\"\r\n,\n", &config);
        assert_eq!(input.headers.unwrap(), ["a", "b"]);
        assert_eq!(
            rows(&Input {
                headers: None,
                rows: input.rows
            }),
            [vec!["1", "x,\"y\"\nz"], vec!["", ""]]
        );
        let empty = read_delimited("", &Delimited::default());
        assert!(empty.rows.is_empty());
    }

    #[test]
    fn custom_separators_and_escape_characters_apply() {
        let config = Delimited {
            column: '|',
            record: ";".into(),
            escape: Some('\\'),
            ..Delimited::default()
        };
        let input = read_delimited(r#"a|"b\"c";d|e"#, &config);
        assert_eq!(rows(&input), [vec!["a", "b\"c"], vec!["d", "e"]]);
    }

    #[test]
    fn output_quotes_only_what_needs_it() {
        let config = Delimited::default();
        let columns = [
            ("_1".to_owned(), Value::Str("a,b".into())),
            ("_2".to_owned(), Value::Str("say \"hi\"".into())),
            ("_3".to_owned(), Value::Int(3)),
        ];
        assert_eq!(
            write(&columns, &Format::Delimited(config)),
            r#""a,b","say ""hi""",3"#
        );
        assert_eq!(
            write(
                &columns[2..],
                &Format::Json {
                    record: "\n".into()
                }
            ),
            r#"{"_3":3}"#
        );
    }

    #[test]
    fn json_input_is_separator_agnostic_and_reports_bad_text() {
        let input = read_json("{\"a\":1}\n{\"a\":2} {\"a\":3}").ok().unwrap();
        assert_eq!(input.rows.len(), 3);
        assert!(read_json("{\"a\":1}\n{oops").is_err());
    }

    #[test]
    fn serialization_reads_formats_and_refuses_columnar_ones() {
        let parse = |body: &str| {
            let tree = xml_tree::parse(body.as_bytes()).unwrap();
            serialization(tree.child("InputSerialization"))
        };
        let csv = parse(
            "<Q><InputSerialization><Format><Type>delimited</Type><DelimitedTextConfiguration><ColumnSeparator>\t</ColumnSeparator><RecordSeparator>\n</RecordSeparator><FieldQuote/><HasHeaders>true</HasHeaders></DelimitedTextConfiguration></Format></InputSerialization></Q>",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            csv,
            Format::Delimited(Delimited {
                column: '\t',
                quote: None,
                headers: true,
                ..Delimited::default()
            })
        );
        assert!(parse("<Q/>").unwrap().is_none());
        assert_eq!(
            parse("<Q><InputSerialization><Format><Type>parquet</Type></Format></InputSerialization></Q>")
                .unwrap_err(),
            Error::Unsupported
        );
    }
}
