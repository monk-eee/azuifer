//! The SQL subset of Query Blob Contents: `SELECT <items> FROM BlobStorage [alias] [WHERE <expr>]
//! [LIMIT n]` with comparison, boolean, arithmetic, `LIKE`, `BETWEEN`, `IN`, `IS NULL`, `CAST`,
//! a few string functions, and the aggregates COUNT, SUM, AVG, MIN and MAX (ADR-0027).

use serde_json::Value as Json;
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// A JSON object or array, kept whole for output.
    Json(Json),
}

impl Value {
    pub(super) fn from_json(value: &Json) -> Self {
        match value {
            Json::Null => Self::Null,
            Json::Bool(flag) => Self::Bool(*flag),
            Json::Number(number) => number.as_i64().map_or_else(
                || Self::Float(number.as_f64().unwrap_or(f64::NAN)),
                Self::Int,
            ),
            Json::String(text) => Self::Str(text.clone()),
            other => Self::Json(other.clone()),
        }
    }

    pub(super) fn to_json(&self) -> Json {
        match self {
            Self::Null => Json::Null,
            Self::Bool(flag) => Json::Bool(*flag),
            Self::Int(number) => Json::from(*number),
            Self::Float(number) => {
                serde_json::Number::from_f64(*number).map_or(Json::Null, Json::Number)
            }
            Self::Str(text) => Json::String(text.clone()),
            Self::Json(value) => value.clone(),
        }
    }

    /// The text of a value in delimited output.
    pub(super) fn to_text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(flag) => flag.to_string(),
            Self::Int(number) => number.to_string(),
            Self::Float(number) => number.to_string(),
            Self::Str(text) => text.clone(),
            Self::Json(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SqlError {
    pub(super) name: &'static str,
    pub(super) message: String,
}

fn parse_error<T>(message: impl Into<String>) -> Result<T, SqlError> {
    Err(SqlError {
        name: "ParseError",
        message: message.into(),
    })
}

fn runtime_error<T>(name: &'static str, message: impl Into<String>) -> Result<T, SqlError> {
    Err(SqlError {
        name,
        message: message.into(),
    })
}

// ------------------------------------------------------------------ lexer

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(String),
    Quoted(String),
    Number(String),
    Text(String),
    Symbol(&'static str),
}

const SYMBOLS: [&str; 17] = [
    "<>", "!=", "<=", ">=", "||", ",", "(", ")", "*", "+", "-", "/", "%", "=", "<", ">", ".",
];

fn tokens(sql: &str) -> Result<Vec<Token>, SqlError> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        if c.is_whitespace() {
            at += 1;
        } else if c == '\'' || c == '"' {
            let mut text = String::new();
            at += 1;
            loop {
                match chars.get(at) {
                    None => return parse_error("unterminated quoted text"),
                    Some(&q) if q == c => {
                        if chars.get(at + 1) == Some(&c) {
                            text.push(c);
                            at += 2;
                        } else {
                            at += 1;
                            break;
                        }
                    }
                    Some(&other) => {
                        text.push(other);
                        at += 1;
                    }
                }
            }
            out.push(if c == '\'' {
                Token::Text(text)
            } else {
                Token::Quoted(text)
            });
        } else if c.is_ascii_digit() {
            let start = at;
            while chars
                .get(at)
                .is_some_and(|d| d.is_ascii_digit() || *d == '.')
            {
                at += 1;
            }
            if matches!(chars.get(at), Some('e' | 'E')) {
                let mut look = at + 1;
                if matches!(chars.get(look), Some('+' | '-')) {
                    look += 1;
                }
                if chars.get(look).is_some_and(char::is_ascii_digit) {
                    at = look;
                    while chars.get(at).is_some_and(char::is_ascii_digit) {
                        at += 1;
                    }
                }
            }
            out.push(Token::Number(chars[start..at].iter().collect()));
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let start = at;
            while chars
                .get(at)
                .is_some_and(|d| d.is_alphanumeric() || *d == '_' || *d == '$')
            {
                at += 1;
            }
            out.push(Token::Word(chars[start..at].iter().collect()));
        } else if c == '[' || c == ']' {
            out.push(Token::Symbol(if c == '[' { "[" } else { "]" }));
            at += 1;
        } else if c == ';' {
            at += 1;
        } else {
            let rest: String = chars[at..chars.len().min(at + 2)].iter().collect();
            let Some(symbol) = SYMBOLS.iter().find(|symbol| rest.starts_with(**symbol)) else {
                return parse_error(format!("unexpected character '{c}'"));
            };
            out.push(Token::Symbol(symbol));
            at += symbol.len();
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ syntax tree

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Part {
    Key(String),
    Index(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CastType {
    Int,
    Float,
    Bool,
    Text,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Agg {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Literal(Value),
    Column(Vec<Part>),
    Negate(Box<Expr>),
    Not(Box<Expr>),
    Binary(Op, Box<Expr>, Box<Expr>),
    Like(Box<Expr>, Box<Expr>, bool),
    IsNull(Box<Expr>, bool),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    Cast(Box<Expr>, CastType),
    Function(String, Vec<Expr>),
    Aggregate(Agg, Option<Box<Expr>>),
}

#[derive(Debug, PartialEq)]
enum Item {
    Star,
    Expr(Expr, Option<String>),
}

#[derive(Debug)]
pub(super) struct Query {
    items: Vec<Item>,
    alias: Option<String>,
    filter: Option<Expr>,
    pub(super) limit: Option<u64>,
    aggregate: bool,
}

fn contains_aggregate(expr: &Expr) -> bool {
    match expr {
        Expr::Aggregate(..) => true,
        Expr::Literal(_) | Expr::Column(_) => false,
        Expr::Negate(inner) | Expr::Not(inner) | Expr::IsNull(inner, _) | Expr::Cast(inner, _) => {
            contains_aggregate(inner)
        }
        Expr::Binary(_, left, right) | Expr::Like(left, right, _) => {
            contains_aggregate(left) || contains_aggregate(right)
        }
        Expr::Between(a, b, c, _) => [a, b, c].iter().any(|e| contains_aggregate(e)),
        Expr::In(value, list, _) => {
            contains_aggregate(value) || list.iter().any(contains_aggregate)
        }
        Expr::Function(_, args) => args.iter().any(contains_aggregate),
    }
}

// ------------------------------------------------------------------ parser

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

const RESERVED: [&str; 12] = [
    "from", "where", "limit", "and", "or", "not", "as", "like", "between", "in", "is", "select",
];

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(found)) if found.eq_ignore_ascii_case(word))
    }

    fn take_keyword(&mut self, word: &str) -> bool {
        let found = self.keyword(word);
        if found {
            self.at += 1;
        }
        found
    }

    fn expect_keyword(&mut self, word: &str) -> Result<(), SqlError> {
        if self.take_keyword(word) {
            Ok(())
        } else {
            parse_error(format!("expected {}", word.to_ascii_uppercase()))
        }
    }

    fn symbol(&self, symbol: &str) -> bool {
        matches!(self.peek(), Some(Token::Symbol(found)) if *found == symbol)
    }

    fn take_symbol(&mut self, symbol: &str) -> bool {
        let found = self.symbol(symbol);
        if found {
            self.at += 1;
        }
        found
    }

    fn expect_symbol(&mut self, symbol: &str) -> Result<(), SqlError> {
        if self.take_symbol(symbol) {
            Ok(())
        } else {
            parse_error(format!("expected '{symbol}'"))
        }
    }

    fn query(&mut self) -> Result<Query, SqlError> {
        self.expect_keyword("select")?;
        let mut items = Vec::new();
        loop {
            if self.take_symbol("*") {
                items.push(Item::Star);
            } else {
                let expr = self.or()?;
                let alias = if self.take_keyword("as") {
                    Some(self.name()?)
                } else if let Some(Token::Word(word)) = self.peek()
                    && !RESERVED.contains(&word.to_ascii_lowercase().as_str())
                {
                    let alias = word.clone();
                    self.at += 1;
                    Some(alias)
                } else {
                    None
                };
                items.push(Item::Expr(expr, alias));
            }
            if !self.take_symbol(",") {
                break;
            }
        }
        self.expect_keyword("from")?;
        match self.next() {
            Some(Token::Word(table)) if table.eq_ignore_ascii_case("blobstorage") => (),
            _ => return parse_error("the table must be BlobStorage"),
        }
        let alias = if self.take_keyword("as") {
            Some(self.name()?)
        } else if let Some(Token::Word(word)) = self.peek()
            && !RESERVED.contains(&word.to_ascii_lowercase().as_str())
        {
            let alias = word.clone();
            self.at += 1;
            Some(alias)
        } else {
            None
        };
        let filter = if self.take_keyword("where") {
            Some(self.or()?)
        } else {
            None
        };
        let limit = if self.take_keyword("limit") {
            match self.next() {
                Some(Token::Number(text)) => Some(
                    text.parse::<u64>()
                        .or_else(|_| parse_error("LIMIT takes a whole number"))?,
                ),
                _ => return parse_error("LIMIT takes a whole number"),
            }
        } else {
            None
        };
        if self.peek().is_some() {
            return parse_error("unexpected text after the query");
        }
        if filter.as_ref().is_some_and(contains_aggregate) {
            return parse_error("aggregates cannot appear in WHERE");
        }
        let aggregate = items.iter().any(|item| match item {
            Item::Expr(expr, _) => contains_aggregate(expr),
            Item::Star => false,
        });
        if aggregate
            && items
                .iter()
                .any(|item| !matches!(item, Item::Expr(Expr::Aggregate(..), _)))
        {
            return parse_error("aggregates cannot be mixed with other select items");
        }
        Ok(Query {
            items,
            alias,
            filter,
            limit,
            aggregate,
        })
    }

    fn name(&mut self) -> Result<String, SqlError> {
        match self.next() {
            Some(Token::Word(name) | Token::Quoted(name)) => Ok(name),
            _ => parse_error("expected a name"),
        }
    }

    fn or(&mut self) -> Result<Expr, SqlError> {
        let mut left = self.and()?;
        while self.take_keyword("or") {
            left = Expr::Binary(Op::Or, Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, SqlError> {
        let mut left = self.not()?;
        while self.take_keyword("and") {
            left = Expr::Binary(Op::And, Box::new(left), Box::new(self.not()?));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr, SqlError> {
        if self.take_keyword("not") {
            Ok(Expr::Not(Box::new(self.not()?)))
        } else {
            self.predicate()
        }
    }

    fn predicate(&mut self) -> Result<Expr, SqlError> {
        let left = self.concat()?;
        let negated = self.keyword("not")
            && matches!(self.tokens.get(self.at + 1), Some(Token::Word(w))
                if ["like", "between", "in"].contains(&w.to_ascii_lowercase().as_str()));
        if negated {
            self.at += 1;
        }
        if self.take_keyword("like") {
            let pattern = self.concat()?;
            return Ok(Expr::Like(Box::new(left), Box::new(pattern), negated));
        }
        if self.take_keyword("between") {
            let low = self.concat()?;
            self.expect_keyword("and")?;
            let high = self.concat()?;
            return Ok(Expr::Between(
                Box::new(left),
                Box::new(low),
                Box::new(high),
                negated,
            ));
        }
        if self.take_keyword("in") {
            self.expect_symbol("(")?;
            let mut list = vec![self.concat()?];
            while self.take_symbol(",") {
                list.push(self.concat()?);
            }
            self.expect_symbol(")")?;
            return Ok(Expr::In(Box::new(left), list, negated));
        }
        if self.take_keyword("is") {
            let negated = self.take_keyword("not");
            self.expect_keyword("null")?;
            return Ok(Expr::IsNull(Box::new(left), negated));
        }
        for (symbol, op) in [
            ("=", Op::Eq),
            ("<>", Op::Ne),
            ("!=", Op::Ne),
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("<", Op::Lt),
            (">", Op::Gt),
        ] {
            if self.take_symbol(symbol) {
                return Ok(Expr::Binary(op, Box::new(left), Box::new(self.concat()?)));
            }
        }
        Ok(left)
    }

    fn concat(&mut self) -> Result<Expr, SqlError> {
        let mut left = self.additive()?;
        while self.take_symbol("||") {
            left = Expr::Binary(Op::Concat, Box::new(left), Box::new(self.additive()?));
        }
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr, SqlError> {
        let mut left = self.term()?;
        loop {
            let op = if self.take_symbol("+") {
                Op::Add
            } else if self.take_symbol("-") {
                Op::Sub
            } else {
                return Ok(left);
            };
            left = Expr::Binary(op, Box::new(left), Box::new(self.term()?));
        }
    }

    fn term(&mut self) -> Result<Expr, SqlError> {
        let mut left = self.unary()?;
        loop {
            let op = if self.take_symbol("*") {
                Op::Mul
            } else if self.take_symbol("/") {
                Op::Div
            } else if self.take_symbol("%") {
                Op::Rem
            } else {
                return Ok(left);
            };
            left = Expr::Binary(op, Box::new(left), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, SqlError> {
        if self.take_symbol("-") {
            return Ok(Expr::Negate(Box::new(self.unary()?)));
        }
        if self.take_symbol("+") {
            return self.unary();
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, SqlError> {
        match self.next() {
            Some(Token::Number(text)) => Ok(Expr::Literal(if let Ok(int) = text.parse::<i64>() {
                Value::Int(int)
            } else {
                Value::Float(
                    text.parse::<f64>()
                        .or_else(|_| parse_error(format!("bad number {text}")))?,
                )
            })),
            Some(Token::Text(text)) => Ok(Expr::Literal(Value::Str(text))),
            Some(Token::Symbol("(")) => {
                let inner = self.or()?;
                self.expect_symbol(")")?;
                Ok(inner)
            }
            Some(Token::Quoted(name)) => self.path(name),
            Some(Token::Word(word)) => {
                let lower = word.to_ascii_lowercase();
                match lower.as_str() {
                    "null" => return Ok(Expr::Literal(Value::Null)),
                    "true" => return Ok(Expr::Literal(Value::Bool(true))),
                    "false" => return Ok(Expr::Literal(Value::Bool(false))),
                    _ => (),
                }
                if self.symbol("(") {
                    return self.call(&lower);
                }
                if RESERVED.contains(&lower.as_str()) {
                    return parse_error(format!("unexpected {}", word.to_ascii_uppercase()));
                }
                self.path(word)
            }
            _ => parse_error("expected an expression"),
        }
    }

    fn path(&mut self, first: String) -> Result<Expr, SqlError> {
        let mut parts = vec![Part::Key(first)];
        loop {
            if self.take_symbol(".") {
                parts.push(Part::Key(self.name()?));
            } else if self.take_symbol("[") {
                match self.next() {
                    Some(Token::Number(text)) => parts
                        .push(Part::Index(text.parse().or_else(|_| {
                            parse_error("an array index is a whole number")
                        })?)),
                    _ => return parse_error("an array index is a whole number"),
                }
                self.expect_symbol("]")?;
            } else {
                return Ok(Expr::Column(parts));
            }
        }
    }

    fn call(&mut self, name: &str) -> Result<Expr, SqlError> {
        self.expect_symbol("(")?;
        if name == "cast" {
            let value = self.or()?;
            self.expect_keyword("as")?;
            let kind = match self.name()?.to_ascii_lowercase().as_str() {
                "int" | "integer" | "bigint" => CastType::Int,
                "float" | "double" | "decimal" | "numeric" | "real" => CastType::Float,
                "bool" | "boolean" => CastType::Bool,
                "string" | "varchar" | "char" | "text" => CastType::Text,
                other => return parse_error(format!("CAST to {other} is not supported")),
            };
            self.expect_symbol(")")?;
            return Ok(Expr::Cast(Box::new(value), kind));
        }
        let aggregate = match name {
            "count" => Some(Agg::Count),
            "sum" => Some(Agg::Sum),
            "avg" => Some(Agg::Avg),
            "min" => Some(Agg::Min),
            "max" => Some(Agg::Max),
            _ => None,
        };
        if let Some(kind) = aggregate {
            if kind == Agg::Count && self.take_symbol("*") {
                self.expect_symbol(")")?;
                return Ok(Expr::Aggregate(kind, None));
            }
            let value = self.or()?;
            self.expect_symbol(")")?;
            if contains_aggregate(&value) {
                return parse_error("aggregates cannot be nested");
            }
            return Ok(Expr::Aggregate(kind, Some(Box::new(value))));
        }
        let mut args = Vec::new();
        if !self.symbol(")") {
            args.push(self.or()?);
            while self.take_symbol(",") {
                args.push(self.or()?);
            }
        }
        self.expect_symbol(")")?;
        let expected: &[usize] = match name {
            "lower" | "upper" | "trim" | "char_length" | "character_length" => &[1],
            "substring" => &[2, 3],
            "nullif" => &[2],
            "coalesce" => &[1, 2, 3, 4, 5, 6, 7, 8],
            _ => return parse_error(format!("the function {name} is not supported")),
        };
        if !expected.contains(&args.len()) {
            return parse_error(format!("wrong number of arguments for {name}"));
        }
        Ok(Expr::Function(name.to_owned(), args))
    }
}

impl Query {
    pub(super) fn parse(sql: &str) -> Result<Self, SqlError> {
        let mut parser = Parser {
            tokens: tokens(sql)?,
            at: 0,
        };
        parser.query()
    }
}

// ------------------------------------------------------------------ rows and evaluation

/// One input record.
pub(super) enum Row {
    Csv(Vec<String>),
    Json(Json),
}

/// What a query needs to know about its input besides the row.
pub(super) struct Scope<'a> {
    pub(super) headers: Option<&'a [String]>,
}

fn strip_alias<'a>(path: &'a [Part], alias: Option<&str>) -> &'a [Part] {
    if let Some(Part::Key(first)) = path.first()
        && (alias.is_some_and(|alias| first.eq_ignore_ascii_case(alias))
            || first.eq_ignore_ascii_case("blobstorage"))
    {
        return &path[1..];
    }
    path
}

fn lookup(row: &Row, path: &[Part], scope: &Scope<'_>) -> Value {
    match row {
        Row::Csv(fields) => {
            let Some(Part::Key(name)) = path.first() else {
                return Value::Null;
            };
            if path.len() > 1 {
                return Value::Null;
            }
            let positional = name
                .strip_prefix('_')
                .and_then(|digits| digits.parse::<usize>().ok())
                .filter(|index| *index >= 1);
            if let Some(index) = positional {
                return fields
                    .get(index - 1)
                    .map_or(Value::Null, |field| Value::Str(field.clone()));
            }
            let Some(headers) = scope.headers else {
                return Value::Null;
            };
            let position = headers
                .iter()
                .position(|header| header == name)
                .or_else(|| {
                    headers
                        .iter()
                        .position(|header| header.eq_ignore_ascii_case(name))
                });
            position
                .and_then(|index| fields.get(index))
                .map_or(Value::Null, |field| Value::Str(field.clone()))
        }
        Row::Json(root) => {
            let mut current = root;
            for part in path {
                let next = match (part, current) {
                    (Part::Key(key), Json::Object(map)) => map.get(key).or_else(|| {
                        map.iter()
                            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
                            .map(|(_, value)| value)
                    }),
                    (Part::Index(index), Json::Array(items)) => items.get(*index),
                    _ => None,
                };
                match next {
                    Some(value) => current = value,
                    None => return Value::Null,
                }
            }
            Value::from_json(current)
        }
    }
}

#[derive(Clone, Copy)]
enum Number {
    Int(i64),
    Float(f64),
}

fn number(value: &Value) -> Option<Number> {
    match value {
        Value::Int(int) => Some(Number::Int(*int)),
        Value::Float(float) => Some(Number::Float(*float)),
        Value::Str(text) => {
            let text = text.trim();
            text.parse::<i64>().map_or_else(
                |_| text.parse::<f64>().ok().map(Number::Float),
                |int| Some(Number::Int(int)),
            )
        }
        _ => None,
    }
}

fn as_f64(number: Number) -> f64 {
    match number {
        Number::Int(int) => int as f64,
        Number::Float(float) => float,
    }
}

fn compare(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Null, _) | (_, Value::Null) | (Value::Json(_), _) | (_, Value::Json(_)) => None,
        (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
        _ => match (number(left), number(right)) {
            (Some(Number::Int(a)), Some(Number::Int(b))) => Some(a.cmp(&b)),
            (Some(a), Some(b)) => as_f64(a).partial_cmp(&as_f64(b)),
            _ => match (left, right) {
                (Value::Str(a), other) => Some(a.as_str().cmp(other.to_text().as_str())),
                (other, Value::Str(b)) => Some(other.to_text().as_str().cmp(b.as_str())),
                _ => None,
            },
        },
    }
}

fn truth(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::Str(text) if text.eq_ignore_ascii_case("true") => Some(true),
        Value::Str(text) if text.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn like(text: &str, pattern: &str) -> bool {
    let (text, pattern): (Vec<char>, Vec<char>) =
        (text.chars().collect(), pattern.chars().collect());
    let (mut t, mut p) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '_' || pattern[p] == text[t]) && pattern[p] != '%' {
            t += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == '%' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '%' {
        p += 1;
    }
    p == pattern.len()
}

fn arithmetic(op: Op, left: &Value, right: &Value) -> Result<Value, SqlError> {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return Ok(Value::Null);
    }
    let (Some(a), Some(b)) = (number(left), number(right)) else {
        return runtime_error("TypeMismatch", "arithmetic needs numbers");
    };
    if let (Number::Int(a), Number::Int(b)) = (a, b) {
        let result = match op {
            Op::Add => a.checked_add(b),
            Op::Sub => a.checked_sub(b),
            Op::Mul => a.checked_mul(b),
            Op::Div | Op::Rem if b == 0 => {
                return runtime_error("DivisionByZero", "division by zero");
            }
            Op::Div => a.checked_div(b),
            _ => a.checked_rem(b),
        };
        return result
            .map(Value::Int)
            .map_or_else(|| runtime_error("Overflow", "integer overflow"), Ok);
    }
    let (a, b) = (as_f64(a), as_f64(b));
    Ok(Value::Float(match op {
        Op::Add => a + b,
        Op::Sub => a - b,
        Op::Mul => a * b,
        Op::Div => a / b,
        _ => a % b,
    }))
}

fn cast(value: Value, kind: CastType) -> Result<Value, SqlError> {
    if matches!(value, Value::Null) {
        return Ok(Value::Null);
    }
    let failed = |what: &str| {
        runtime_error(
            "CastFailed",
            format!("cannot cast {} to {what}", value.to_text()),
        )
    };
    match kind {
        CastType::Text => Ok(Value::Str(value.to_text())),
        CastType::Int => match number(&value) {
            Some(Number::Int(int)) => Ok(Value::Int(int)),
            Some(Number::Float(float)) if float.is_finite() => Ok(Value::Int(float.trunc() as i64)),
            _ => match value {
                Value::Bool(flag) => Ok(Value::Int(i64::from(flag))),
                _ => failed("INT"),
            },
        },
        CastType::Float => match number(&value) {
            Some(number) => Ok(Value::Float(as_f64(number))),
            None => failed("FLOAT"),
        },
        CastType::Bool => {
            truth(&value).map_or_else(|| failed("BOOL"), |flag| Ok(Value::Bool(flag)))
        }
    }
}

fn function(name: &str, args: &[Value]) -> Result<Value, SqlError> {
    let text = |value: &Value| value.to_text();
    Ok(match name {
        "coalesce" => args
            .iter()
            .find(|value| !matches!(value, Value::Null))
            .cloned()
            .unwrap_or(Value::Null),
        "nullif" => {
            if compare(&args[0], &args[1]) == Some(Ordering::Equal) {
                Value::Null
            } else {
                args[0].clone()
            }
        }
        _ if matches!(args[0], Value::Null) => Value::Null,
        "lower" => Value::Str(text(&args[0]).to_lowercase()),
        "upper" => Value::Str(text(&args[0]).to_uppercase()),
        "trim" => Value::Str(text(&args[0]).trim().to_owned()),
        "char_length" | "character_length" => {
            Value::Int(i64::try_from(text(&args[0]).chars().count()).unwrap_or(i64::MAX))
        }
        _ => {
            let (Some(Number::Int(start)), length) = (number(&args[1]), args.get(2).map(number))
            else {
                return runtime_error("TypeMismatch", "SUBSTRING positions are whole numbers");
            };
            let skip = usize::try_from((start - 1).max(0)).unwrap_or(usize::MAX);
            let source = text(&args[0]);
            let chars = source.chars().skip(skip);
            Value::Str(match length {
                None => chars.collect(),
                Some(Some(Number::Int(count))) => chars
                    .take(usize::try_from(count.max(0)).unwrap_or(0))
                    .collect(),
                Some(_) => {
                    return runtime_error("TypeMismatch", "SUBSTRING positions are whole numbers");
                }
            })
        }
    })
}

struct Eval<'a> {
    row: &'a Row,
    scope: &'a Scope<'a>,
    alias: Option<&'a str>,
}

impl Eval<'_> {
    fn expr(&self, expr: &Expr) -> Result<Value, SqlError> {
        Ok(match expr {
            Expr::Literal(value) => value.clone(),
            Expr::Column(path) => lookup(self.row, strip_alias(path, self.alias), self.scope),
            Expr::Negate(inner) => match number(&self.expr(inner)?) {
                Some(Number::Int(int)) => Value::Int(-int),
                Some(Number::Float(float)) => Value::Float(-float),
                None => Value::Null,
            },
            Expr::Not(inner) => {
                truth(&self.expr(inner)?).map_or(Value::Null, |flag| Value::Bool(!flag))
            }
            Expr::Binary(Op::And, left, right) => {
                let (a, b) = (truth(&self.expr(left)?), truth(&self.expr(right)?));
                match (a, b) {
                    (Some(false), _) | (_, Some(false)) => Value::Bool(false),
                    (Some(true), Some(true)) => Value::Bool(true),
                    _ => Value::Null,
                }
            }
            Expr::Binary(Op::Or, left, right) => {
                let (a, b) = (truth(&self.expr(left)?), truth(&self.expr(right)?));
                match (a, b) {
                    (Some(true), _) | (_, Some(true)) => Value::Bool(true),
                    (Some(false), Some(false)) => Value::Bool(false),
                    _ => Value::Null,
                }
            }
            Expr::Binary(Op::Concat, left, right) => {
                let (a, b) = (self.expr(left)?, self.expr(right)?);
                if matches!(a, Value::Null) || matches!(b, Value::Null) {
                    Value::Null
                } else {
                    Value::Str(a.to_text() + &b.to_text())
                }
            }
            Expr::Binary(op @ (Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Rem), left, right) => {
                arithmetic(*op, &self.expr(left)?, &self.expr(right)?)?
            }
            Expr::Binary(op, left, right) => {
                let ordering = compare(&self.expr(left)?, &self.expr(right)?);
                ordering.map_or(Value::Null, |ordering| {
                    Value::Bool(match op {
                        Op::Eq => ordering == Ordering::Equal,
                        Op::Ne => ordering != Ordering::Equal,
                        Op::Lt => ordering == Ordering::Less,
                        Op::Le => ordering != Ordering::Greater,
                        Op::Gt => ordering == Ordering::Greater,
                        _ => ordering != Ordering::Less,
                    })
                })
            }
            Expr::Like(value, pattern, negated) => {
                let (value, pattern) = (self.expr(value)?, self.expr(pattern)?);
                if matches!(value, Value::Null) || matches!(pattern, Value::Null) {
                    Value::Null
                } else {
                    Value::Bool(like(&value.to_text(), &pattern.to_text()) != *negated)
                }
            }
            Expr::IsNull(value, negated) => {
                Value::Bool(matches!(self.expr(value)?, Value::Null) != *negated)
            }
            Expr::Between(value, low, high, negated) => {
                let value = self.expr(value)?;
                let inside = match (
                    compare(&value, &self.expr(low)?),
                    compare(&value, &self.expr(high)?),
                ) {
                    (Some(a), Some(b)) => Some(a != Ordering::Less && b != Ordering::Greater),
                    _ => None,
                };
                inside.map_or(Value::Null, |inside| Value::Bool(inside != *negated))
            }
            Expr::In(value, list, negated) => {
                let value = self.expr(value)?;
                let mut unknown = matches!(value, Value::Null);
                let mut found = false;
                for item in list {
                    match compare(&value, &self.expr(item)?) {
                        Some(Ordering::Equal) => found = true,
                        None => unknown = true,
                        _ => (),
                    }
                }
                if found {
                    Value::Bool(!negated)
                } else if unknown {
                    Value::Null
                } else {
                    Value::Bool(*negated)
                }
            }
            Expr::Cast(value, kind) => cast(self.expr(value)?, *kind)?,
            Expr::Function(name, args) => {
                let values = args
                    .iter()
                    .map(|arg| self.expr(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                function(name, &values)?
            }
            Expr::Aggregate(..) => return parse_error("an aggregate is not allowed here"),
        })
    }
}

impl Query {
    /// Whether the row passes `WHERE`.
    pub(super) fn matches(&self, row: &Row, scope: &Scope<'_>) -> Result<bool, SqlError> {
        let Some(filter) = &self.filter else {
            return Ok(true);
        };
        let eval = Eval {
            row,
            scope,
            alias: self.alias.as_deref(),
        };
        Ok(truth(&eval.expr(filter)?) == Some(true))
    }

    pub(super) fn is_aggregate(&self) -> bool {
        self.aggregate
    }

    /// The output columns of one row, as `(name, value)`.
    pub(super) fn project(
        &self,
        row: &Row,
        scope: &Scope<'_>,
    ) -> Result<Vec<(String, Value)>, SqlError> {
        let eval = Eval {
            row,
            scope,
            alias: self.alias.as_deref(),
        };
        let mut out = Vec::new();
        for (index, item) in self.items.iter().enumerate() {
            match item {
                Item::Star => match row {
                    Row::Csv(fields) => {
                        for (position, field) in fields.iter().enumerate() {
                            let name = scope
                                .headers
                                .and_then(|headers| headers.get(position))
                                .filter(|header| !header.is_empty())
                                .cloned()
                                .unwrap_or_else(|| format!("_{}", position + 1));
                            out.push((name, Value::Str(field.clone())));
                        }
                    }
                    Row::Json(Json::Object(map)) => {
                        out.extend(
                            map.iter()
                                .map(|(key, value)| (key.clone(), Value::from_json(value))),
                        );
                    }
                    Row::Json(other) => out.push(("_1".to_owned(), Value::from_json(other))),
                },
                Item::Expr(expr, alias) => {
                    let name = alias.clone().unwrap_or_else(|| match expr {
                        Expr::Column(path) => match strip_alias(path, self.alias.as_deref()).last()
                        {
                            Some(Part::Key(key)) => key.clone(),
                            _ => format!("_{}", index + 1),
                        },
                        _ => format!("_{}", index + 1),
                    });
                    out.push((name, eval.expr(expr)?));
                }
            }
        }
        Ok(out)
    }

    pub(super) fn accumulators(&self) -> Vec<Accumulator> {
        self.items
            .iter()
            .filter_map(|item| match item {
                Item::Expr(Expr::Aggregate(kind, _), _) => Some(Accumulator::new(*kind)),
                _ => None,
            })
            .collect()
    }

    /// Feeds one matching row to every aggregate.
    pub(super) fn accumulate(
        &self,
        accumulators: &mut [Accumulator],
        row: &Row,
        scope: &Scope<'_>,
    ) -> Result<(), SqlError> {
        let eval = Eval {
            row,
            scope,
            alias: self.alias.as_deref(),
        };
        for (item, accumulator) in self.items.iter().zip(accumulators) {
            if let Item::Expr(Expr::Aggregate(_, argument), _) = item {
                let value = match argument {
                    Some(argument) => Some(eval.expr(argument)?),
                    None => None,
                };
                accumulator.add(value)?;
            }
        }
        Ok(())
    }

    /// The names of the aggregate output columns.
    pub(super) fn aggregate_names(&self) -> Vec<String> {
        self.items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                Item::Expr(_, Some(alias)) => alias.clone(),
                _ => format!("_{}", index + 1),
            })
            .collect()
    }
}

pub(super) struct Accumulator {
    kind: Agg,
    count: i64,
    int_sum: i64,
    float_sum: f64,
    all_int: bool,
    best: Option<Value>,
}

impl Accumulator {
    fn new(kind: Agg) -> Self {
        Self {
            kind,
            count: 0,
            int_sum: 0,
            float_sum: 0.0,
            all_int: true,
            best: None,
        }
    }

    fn add(&mut self, value: Option<Value>) -> Result<(), SqlError> {
        let Some(value) = value else {
            self.count += 1;
            return Ok(());
        };
        if matches!(value, Value::Null) {
            return Ok(());
        }
        self.count += 1;
        match self.kind {
            Agg::Count => (),
            Agg::Sum | Agg::Avg => match number(&value) {
                Some(Number::Int(int)) => {
                    self.float_sum += int as f64;
                    match self.int_sum.checked_add(int) {
                        Some(sum) => self.int_sum = sum,
                        None => self.all_int = false,
                    }
                }
                Some(Number::Float(float)) => {
                    self.all_int = false;
                    self.float_sum += float;
                }
                None => return runtime_error("TypeMismatch", "SUM and AVG need numbers"),
            },
            Agg::Min | Agg::Max => {
                let better = match &self.best {
                    None => true,
                    Some(best) => {
                        let ordering = compare(&value, best);
                        if self.kind == Agg::Min {
                            ordering == Some(Ordering::Less)
                        } else {
                            ordering == Some(Ordering::Greater)
                        }
                    }
                };
                if better {
                    self.best = Some(value);
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Value {
        match self.kind {
            Agg::Count => Value::Int(self.count),
            Agg::Sum if self.count == 0 => Value::Null,
            Agg::Sum if self.all_int => Value::Int(self.int_sum),
            Agg::Sum => Value::Float(self.float_sum),
            Agg::Avg if self.count == 0 => Value::Null,
            Agg::Avg => Value::Float(self.float_sum / self.count as f64),
            Agg::Min | Agg::Max => self.best.unwrap_or(Value::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csv(fields: &[&str]) -> Row {
        Row::Csv(fields.iter().map(|field| (*field).to_owned()).collect())
    }

    fn select(sql: &str, row: &Row, headers: Option<&[String]>) -> Vec<(String, Value)> {
        let query = Query::parse(sql).unwrap();
        let scope = Scope { headers };
        assert!(query.matches(row, &scope).unwrap(), "{sql}");
        query.project(row, &scope).unwrap()
    }

    fn passes(sql: &str, row: &Row) -> bool {
        Query::parse(sql)
            .unwrap()
            .matches(row, &Scope { headers: None })
            .unwrap()
    }

    #[test]
    fn positional_and_named_columns_project_in_order() {
        let row = csv(&["ann", "31", "NZ"]);
        let headers = ["name".to_owned(), "age".to_owned(), "country".to_owned()];
        let positional = select("SELECT _3, _1 FROM BlobStorage", &row, None);
        assert_eq!(positional[0], ("_3".into(), Value::Str("NZ".into())));
        assert_eq!(positional[1].1, Value::Str("ann".into()));
        let named = select(
            "select s.name as who, AGE from BlobStorage s",
            &row,
            Some(&headers),
        );
        assert_eq!(named[0], ("who".into(), Value::Str("ann".into())));
        assert_eq!(named[1], ("AGE".into(), Value::Str("31".into())));
        assert_eq!(
            select("SELECT * FROM BlobStorage", &row, Some(&headers)).len(),
            3
        );
    }

    #[test]
    fn where_compares_numbers_and_text_with_three_valued_logic() {
        let row = csv(&["ann", "31", ""]);
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE _2 > 30 AND _1 = 'ann'",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE CAST(_2 AS INT) + 1 = 32",
            &row
        ));
        assert!(!passes("SELECT * FROM BlobStorage WHERE _4 = 'x'", &row));
        assert!(!passes(
            "SELECT * FROM BlobStorage WHERE NOT (_4 = 'x')",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE _4 IS NULL OR _2 < 3",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE _1 LIKE 'a_n' AND _1 NOT LIKE 'b%'",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE _2 BETWEEN 30 AND 40 AND _1 IN ('bob', 'ann')",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE UPPER(_1) || '!' = 'ANN!' AND CHAR_LENGTH(_1) = 3",
            &row
        ));
        assert!(passes(
            "SELECT * FROM BlobStorage WHERE SUBSTRING(_1, 2, 2) = 'nn'",
            &row
        ));
    }

    #[test]
    fn json_paths_reach_nested_fields_and_array_items() {
        let row = Row::Json(serde_json::json!({"a": {"b": [10, 20]}, "name": "x"}));
        let query =
            Query::parse("SELECT s.a.b[1] AS second, name FROM BlobStorage s WHERE s.a.b[0] = 10")
                .unwrap();
        let scope = Scope { headers: None };
        assert!(query.matches(&row, &scope).unwrap());
        let out = query.project(&row, &scope).unwrap();
        assert_eq!(out[0], ("second".into(), Value::Int(20)));
        assert_eq!(out[1], ("name".into(), Value::Str("x".into())));
    }

    #[test]
    fn aggregates_fold_matching_rows() {
        let query = Query::parse(
            "SELECT COUNT(*) AS n, SUM(_1), AVG(_1), MIN(_1), MAX(_1) FROM BlobStorage",
        )
        .unwrap();
        assert!(query.is_aggregate());
        let scope = Scope { headers: None };
        let mut accumulators = query.accumulators();
        for value in ["3", "5", "10"] {
            query
                .accumulate(&mut accumulators, &csv(&[value]), &scope)
                .unwrap();
        }
        let results: Vec<Value> = accumulators.into_iter().map(Accumulator::finish).collect();
        assert_eq!(results[0], Value::Int(3));
        assert_eq!(results[1], Value::Int(18));
        assert_eq!(results[2], Value::Float(6.0));
        // Text compares as text: no cast, no numeric order.
        assert_eq!(results[3], Value::Str("10".into()));
        assert_eq!(results[4], Value::Str("5".into()));
        assert_eq!(query.aggregate_names()[0], "n");
    }

    #[test]
    fn bad_sql_is_a_parse_error_and_bad_casts_fail_at_run_time() {
        for sql in [
            "SELECT FROM BlobStorage",
            "SELECT * FROM other",
            "SELECT * FROM BlobStorage WHERE",
            "SELECT * FROM BlobStorage WHERE _1 = 'a",
            "SELECT COUNT(*), _1 FROM BlobStorage",
            "SELECT * FROM BlobStorage WHERE SUM(_1) > 1",
            "SELECT nosuch(_1) FROM BlobStorage",
            "SELECT * FROM BlobStorage LIMIT x",
        ] {
            assert_eq!(Query::parse(sql).unwrap_err().name, "ParseError", "{sql}");
        }
        let query = Query::parse("SELECT CAST(_1 AS INT) FROM BlobStorage").unwrap();
        let error = query
            .project(&csv(&["abc"]), &Scope { headers: None })
            .unwrap_err();
        assert_eq!(error.name, "CastFailed");
        let query = Query::parse("SELECT 1 / 0 FROM BlobStorage").unwrap();
        assert_eq!(
            query
                .project(&csv(&[]), &Scope { headers: None })
                .unwrap_err()
                .name,
            "DivisionByZero"
        );
    }
}
