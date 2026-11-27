//! OData `$filter` parsing and evaluation over typed values (ADR-0014).

use super::{
    datetime::Ticks,
    error::{Kind, Result, TableError},
    model::Value,
};
use std::{borrow::Cow, cmp::Ordering};
use uuid::Uuid;

const MAX_COMPARISONS: usize = 15;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    fn flipped(self) -> Self {
        match self {
            Self::Gt => Self::Lt,
            Self::Ge => Self::Le,
            Self::Lt => Self::Gt,
            Self::Le => Self::Ge,
            other => other,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Expr {
    Compare(String, Op, Value),
    /// A bare Boolean property used as a condition.
    Truthy(String),
    Const(bool),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

fn invalid(detail: &str) -> TableError {
    TableError::with(
        Kind::InvalidInput,
        format!("The filter is invalid: {detail}"),
    )
}

#[derive(Debug, PartialEq)]
enum Token {
    Open,
    Close,
    Word(String),
    Str(String),
    Number(String, Option<char>),
    Typed(String, String),
}

fn lex(text: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match c {
            c if c.is_whitespace() => at += 1,
            '(' => {
                tokens.push(Token::Open);
                at += 1;
            }
            ')' => {
                tokens.push(Token::Close);
                at += 1;
            }
            '\'' => {
                let (value, next) = quoted(&chars, at)?;
                tokens.push(Token::Str(value));
                at = next;
            }
            c if c.is_ascii_digit() || c == '-' => {
                let start = at;
                at += 1;
                if c == '-' && chars.get(at) == Some(&'I') {
                    let word: String = chars[at..].iter().take(3).collect();
                    if word == "INF" {
                        tokens.push(Token::Word("-INF".into()));
                        at += 3;
                        continue;
                    }
                }
                while let Some(&d) = chars.get(at) {
                    let exponent_sign = matches!(d, '+' | '-')
                        && at > start
                        && matches!(chars.get(at - 1), Some('e' | 'E'));
                    if d.is_ascii_digit() || matches!(d, '.' | 'e' | 'E') || exponent_sign {
                        at += 1;
                    } else {
                        break;
                    }
                }
                let digits: String = chars[start..at].iter().collect();
                let suffix = chars
                    .get(at)
                    .copied()
                    .filter(|s| matches!(s, 'L' | 'l' | 'd' | 'D' | 'f' | 'F'));
                if suffix.is_some() {
                    at += 1;
                }
                if chars.get(at).is_some_and(|c| c.is_alphanumeric()) {
                    return Err(invalid("malformed number"));
                }
                tokens.push(Token::Number(digits, suffix));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = at;
                while chars
                    .get(at)
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_')
                {
                    at += 1;
                }
                let word: String = chars[start..at].iter().collect();
                if chars.get(at) == Some(&'\'') {
                    if !matches!(word.as_str(), "datetime" | "guid" | "binary" | "X") {
                        return Err(invalid("unsupported literal prefix"));
                    }
                    let (value, next) = quoted(&chars, at)?;
                    tokens.push(Token::Typed(word, value));
                    at = next;
                } else if chars.get(at) == Some(&'(') {
                    if word == "startswith" {
                        return Err(TableError::new(Kind::NotImplemented));
                    }
                    return Err(invalid("functions are not supported"));
                } else {
                    tokens.push(Token::Word(word));
                }
            }
            _ => return Err(invalid("unexpected character")),
        }
    }
    Ok(tokens)
}

/// Reads a single-quoted literal starting at `start`, where `''` is an escaped quote.
fn quoted(chars: &[char], start: usize) -> Result<(String, usize)> {
    let mut value = String::new();
    let mut at = start + 1;
    loop {
        match chars.get(at) {
            None => return Err(invalid("unterminated string")),
            Some('\'') if chars.get(at + 1) == Some(&'\'') => {
                value.push('\'');
                at += 2;
            }
            Some('\'') => return Ok((value, at + 1)),
            Some(c) => {
                value.push(*c);
                at += 1;
            }
        }
    }
}

enum Operand {
    Property(String),
    Literal(Value),
}

struct Parser<'a> {
    text: &'a str,
    tokens: Vec<Token>,
    at: usize,
    comparisons: usize,
}

/// Parses a `$filter` expression.
pub(super) fn parse(text: &str) -> Result<Expr> {
    let mut parser = Parser {
        text,
        tokens: lex(text)?,
        at: 0,
        comparisons: 0,
    };
    let expr = parser.or(0)?;
    if parser.at != parser.tokens.len() {
        return Err(invalid("unexpected trailing input"));
    }
    Ok(expr)
}

impl Parser<'_> {
    fn peek_word(&self) -> Option<&str> {
        match self.tokens.get(self.at) {
            Some(Token::Word(word)) => Some(word),
            _ => None,
        }
    }

    fn or(&mut self, depth: usize) -> Result<Expr> {
        let mut left = self.and(depth)?;
        while self.peek_word() == Some("or") {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.and(depth)?));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize) -> Result<Expr> {
        let mut left = self.not(depth)?;
        while self.peek_word() == Some("and") {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.not(depth)?));
        }
        Ok(left)
    }

    fn not(&mut self, depth: usize) -> Result<Expr> {
        if depth > MAX_DEPTH {
            return Err(invalid("expression is nested too deeply"));
        }
        if self.peek_word() == Some("not") {
            self.at += 1;
            return Ok(Expr::Not(Box::new(self.not(depth + 1)?)));
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Expr> {
        if self.tokens.get(self.at) == Some(&Token::Open) {
            self.at += 1;
            let inner = self.or(depth + 1)?;
            if self.tokens.get(self.at) != Some(&Token::Close) {
                return Err(invalid("missing closing parenthesis"));
            }
            self.at += 1;
            return Ok(inner);
        }
        let left = self.operand()?;
        self.comparisons += 1;
        if self.comparisons > MAX_COMPARISONS {
            return Err(invalid("more than 15 discrete comparisons"));
        }
        let op = match self.peek_word() {
            Some("eq") => Op::Eq,
            Some("ne") => Op::Ne,
            Some("gt") => Op::Gt,
            Some("ge") => Op::Ge,
            Some("lt") => Op::Lt,
            Some("le") => Op::Le,
            Some("add" | "sub" | "mul" | "div" | "mod") => {
                return Err(invalid("arithmetic is not supported"));
            }
            _ => {
                return match left {
                    Operand::Property(name) => Ok(Expr::Truthy(name)),
                    Operand::Literal(Value::Boolean(flag)) => Ok(Expr::Const(flag)),
                    Operand::Literal(_) => Err(invalid("a condition must be a comparison")),
                };
            }
        };
        self.at += 1;
        match (left, self.operand()?) {
            (Operand::Property(name), Operand::Literal(value)) => {
                Ok(Expr::Compare(name, op, value))
            }
            (Operand::Literal(value), Operand::Property(name)) => {
                Ok(Expr::Compare(name, op.flipped(), value))
            }
            _ => Err(invalid(
                "one side of a comparison must be a property and the other a constant",
            )),
        }
    }

    fn operand(&mut self) -> Result<Operand> {
        let token = self.tokens.get(self.at).ok_or_else(|| {
            let position = self.text.encode_utf16().count();
            TableError::with(
                Kind::InvalidInput,
                format!(
                    "Expression expected at position {position} in '{}'.",
                    self.text
                ),
            )
        })?;
        self.at += 1;
        let literal = match token {
            Token::Str(text) => Value::String(text.clone()),
            Token::Number(text, suffix) => number(text, *suffix)?,
            Token::Typed(prefix, text) => typed(prefix, text)?,
            Token::Word(word) => match word.as_str() {
                "true" => Value::Boolean(true),
                "false" => Value::Boolean(false),
                "NaN" => Value::Double(f64::NAN),
                "INF" => Value::Double(f64::INFINITY),
                "-INF" => Value::Double(f64::NEG_INFINITY),
                "and" | "or" | "not" | "eq" | "ne" | "gt" | "ge" | "lt" | "le" => {
                    return Err(invalid("unexpected operator"));
                }
                _ => return Ok(Operand::Property(word.clone())),
            },
            Token::Open | Token::Close => return Err(invalid("unexpected parenthesis")),
        };
        Ok(Operand::Literal(literal))
    }
}

fn number(text: &str, suffix: Option<char>) -> Result<Value> {
    let bad = || invalid("malformed number");
    let integer = text.strip_prefix('-').unwrap_or(text);
    let is_integer = !integer.is_empty() && integer.bytes().all(|b| b.is_ascii_digit());
    match suffix {
        Some('L' | 'l') if is_integer => Ok(Value::Int64(text.parse().map_err(|_| bad())?)),
        Some('L' | 'l') => Err(bad()),
        Some(_) => Ok(Value::Double(text.parse().map_err(|_| bad())?)),
        None if is_integer => {
            let value: i64 = text.parse().map_err(|_| bad())?;
            Ok(i32::try_from(value).map_or(Value::Int64(value), Value::Int32))
        }
        None => Ok(Value::Double(text.parse().map_err(|_| bad())?)),
    }
}

fn typed(prefix: &str, text: &str) -> Result<Value> {
    let bad = || invalid("malformed literal");
    match prefix {
        "datetime" => Ok(Value::DateTime(Ticks::parse(text).ok_or_else(bad)?)),
        "guid" if text.len() == 36 => Ok(Value::Guid(Uuid::parse_str(text).map_err(|_| bad())?)),
        "X" | "binary" => {
            if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad());
            }
            let bytes = (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(bad)?;
            Ok(Value::Binary(bytes))
        }
        _ => Err(bad()),
    }
}

fn compare(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        (Value::Boolean(a), Value::Boolean(b)) => Some(a.cmp(b)),
        (Value::Int32(a), Value::Int32(b)) => Some(a.cmp(b)),
        (Value::Int64(a), Value::Int64(b)) => Some(a.cmp(b)),
        (Value::Double(a), Value::Double(b)) => a.partial_cmp(b),
        (Value::DateTime(a), Value::DateTime(b)) => Some(a.cmp(b)),
        (Value::Guid(a), Value::Guid(b)) => Some(a.as_bytes().cmp(b.as_bytes())),
        (Value::Binary(a), Value::Binary(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

impl Expr {
    /// Evaluates against an entity through `lookup`. Operands must have the same Edm type;
    /// a missing property or a type mismatch makes every comparison false except `ne`.
    pub(super) fn matches<'a>(&self, lookup: &impl Fn(&str) -> Option<Cow<'a, Value>>) -> bool {
        match self {
            Self::Const(flag) => *flag,
            Self::Truthy(name) => matches!(lookup(name).as_deref(), Some(Value::Boolean(true))),
            Self::And(a, b) => a.matches(lookup) && b.matches(lookup),
            Self::Or(a, b) => a.matches(lookup) || b.matches(lookup),
            Self::Not(inner) => !inner.matches(lookup),
            Self::Compare(name, op, literal) => {
                let ordering = lookup(name).and_then(|value| compare(&value, literal));
                match (ordering, op) {
                    (None, Op::Ne) => true,
                    (None, _) => false,
                    (Some(o), Op::Eq) => o == Ordering::Equal,
                    (Some(o), Op::Ne) => o != Ordering::Equal,
                    (Some(o), Op::Gt) => o == Ordering::Greater,
                    (Some(o), Op::Ge) => o != Ordering::Less,
                    (Some(o), Op::Lt) => o == Ordering::Less,
                    (Some(o), Op::Le) => o != Ordering::Greater,
                }
            }
        }
    }

    /// Inclusive key ranges implied by the top-level `and` conjuncts, used only to
    /// narrow the rows read; the full expression is still evaluated on each candidate.
    pub(super) fn key_bounds(&self) -> KeyBounds {
        let mut bounds = KeyBounds::default();
        self.collect_bounds(&mut bounds);
        if let (Some(min), Some(max)) = (&bounds.partition_min, &bounds.partition_max)
            && min > max
        {
            bounds.empty = true;
        }
        if let (Some(min), Some(max)) = (&bounds.row_min, &bounds.row_max)
            && min > max
        {
            bounds.empty = true;
        }
        bounds
    }

    fn collect_bounds(&self, bounds: &mut KeyBounds) {
        match self {
            Self::And(a, b) => {
                a.collect_bounds(bounds);
                b.collect_bounds(bounds);
            }
            Self::Compare(name, op, Value::String(text)) => {
                let (min, max) = match name.as_str() {
                    "PartitionKey" => (&mut bounds.partition_min, &mut bounds.partition_max),
                    "RowKey" => (&mut bounds.row_min, &mut bounds.row_max),
                    _ => return,
                };
                if matches!(op, Op::Eq | Op::Gt | Op::Ge) && min.as_ref().is_none_or(|m| m < text) {
                    *min = Some(text.clone());
                }
                if matches!(op, Op::Eq | Op::Lt | Op::Le) && max.as_ref().is_none_or(|m| m > text) {
                    *max = Some(text.clone());
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct KeyBounds {
    pub(super) partition_min: Option<String>,
    pub(super) partition_max: Option<String>,
    pub(super) row_min: Option<String>,
    pub(super) row_max: Option<String>,
    /// The conjuncts contradict each other, so nothing can match.
    pub(super) empty: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn eval(filter: &str, row: &[(&str, Value)]) -> bool {
        let map: HashMap<String, Value> = row
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        parse(filter)
            .unwrap()
            .matches(&|name| map.get(name).cloned().map(Cow::Owned))
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    #[test]
    fn comparison_operators_cover_every_edm_type() {
        let row = [
            ("S", s("o'clock")),
            ("I", Value::Int32(30)),
            ("L", Value::Int64(5_000_000_000)),
            ("D", Value::Double(100.25)),
            ("B", Value::Boolean(true)),
            (
                "T",
                Value::DateTime(Ticks::parse("2008-07-10T00:00:00Z").unwrap()),
            ),
            (
                "G",
                Value::Guid(Uuid::parse_str("a455c695-df98-5678-aaaa-81d3367e5a34").unwrap()),
            ),
            ("X", Value::Binary(vec![0xAB, 0x01])),
        ];
        for (filter, expected) in [
            ("S eq 'o''clock'", true),
            ("S ne 'o''clock'", false),
            ("S ge 'a' and S lt 'p'", true),
            ("I gt 29 and I le 30", true),
            ("I lt 30", false),
            ("L eq 5000000000L", true),
            ("L gt 4999999999L", true),
            ("D le 100.25", true),
            ("D gt 1e2", true),
            ("B eq true", true),
            ("B ne true", false),
            ("B", true),
            ("T eq datetime'2008-07-10T00:00:00Z'", true),
            ("T gt datetime'2008-07-09T23:59:59.9999999Z'", true),
            ("G eq guid'a455c695-df98-5678-aaaa-81d3367e5a34'", true),
            ("X eq X'AB01'", true),
            ("X eq binary'ab01'", true),
            ("X gt X'AB00'", true),
            ("30 eq I", true),
            ("10 lt I", true),
        ] {
            assert_eq!(eval(filter, &row), expected, "{filter}");
        }
    }

    #[test]
    fn logical_operators_precedence_and_parentheses() {
        let row = [("A", Value::Int32(1)), ("B", Value::Int32(2))];
        for (filter, expected) in [
            ("A eq 1 or B eq 9 and B eq 9", true),
            ("(A eq 1 or B eq 9) and B eq 9", false),
            ("not (A eq 2)", true),
            ("not A eq 1", false),
            ("not not A eq 1", true),
            ("true", true),
            ("false or A eq 1", true),
        ] {
            assert_eq!(eval(filter, &row), expected, "{filter}");
        }
    }

    #[test]
    fn types_are_strict_and_missing_properties_only_match_ne() {
        let row = [("I", Value::Int32(5)), ("L", Value::Int64(5))];
        assert!(!eval("I eq 5L", &row));
        assert!(!eval("L eq 5", &row));
        assert!(!eval("I eq '5'", &row));
        assert!(eval("I ne '5'", &row));
        assert!(!eval("Missing eq 'x'", &row));
        assert!(!eval("Missing gt 1", &row));
        assert!(eval("Missing ne 'x'", &row));
        assert!(!eval("D eq NaN", &[("D", Value::Double(f64::NAN))]));
        assert!(eval("D eq INF", &[("D", Value::Double(f64::INFINITY))]));
        assert!(eval(
            "D eq -INF",
            &[("D", Value::Double(f64::NEG_INFINITY))]
        ));
    }

    #[test]
    fn malformed_and_unsupported_filters_are_rejected() {
        for bad in [
            "",
            "A eq",
            "A eq 1 and",
            "(A eq 1",
            "A eq 1)",
            "A eq 'unterminated",
            "A eq B",
            "1 eq 1",
            "A EQ 1",
            "A eq 1 foo",
            "A add 1 eq 2",
            "A eq guid'not-a-guid'",
            "A eq datetime'garbage'",
            "A eq X'ABC'",
            "A eq 12L3",
            "A eq 1.5L",
            "A eq time'x'",
            "A eq $",
            "'x'",
        ] {
            let error = parse(bad).unwrap_err();
            assert_eq!(error.kind(), Kind::InvalidInput, "{bad}");
        }
        assert_eq!(
            parse("startswith(A,'x') eq true").unwrap_err().kind(),
            Kind::NotImplemented
        );
    }

    #[test]
    fn at_most_fifteen_comparisons_and_bounded_nesting() {
        let ok = vec!["A eq 1"; 15].join(" or ");
        assert!(parse(&ok).is_ok());
        let too_many = vec!["A eq 1"; 16].join(" or ");
        assert!(parse(&too_many).is_err());
        let deep = format!("{}A eq 1{}", "(".repeat(200), ")".repeat(200));
        assert!(parse(&deep).is_err());
        let nots = format!("{}A eq 1", "not ".repeat(200));
        assert!(parse(&nots).is_err());
    }

    #[test]
    fn key_bounds_come_from_top_level_conjuncts_only() {
        let bounds = parse("PartitionKey eq 'p' and RowKey ge 'a' and RowKey lt 'b' and X eq 1")
            .unwrap()
            .key_bounds();
        assert_eq!(bounds.partition_min.as_deref(), Some("p"));
        assert_eq!(bounds.partition_max.as_deref(), Some("p"));
        assert_eq!(bounds.row_min.as_deref(), Some("a"));
        assert_eq!(bounds.row_max.as_deref(), Some("b"));
        assert!(!bounds.empty);

        let or = parse("PartitionKey eq 'p' or RowKey eq 'r'")
            .unwrap()
            .key_bounds();
        assert_eq!(or, KeyBounds::default());
        let reversed = parse("'p' le PartitionKey").unwrap().key_bounds();
        assert_eq!(reversed.partition_min.as_deref(), Some("p"));
        let conflict = parse("PartitionKey eq 'a' and PartitionKey eq 'b'")
            .unwrap()
            .key_bounds();
        assert!(conflict.empty);
    }
}
