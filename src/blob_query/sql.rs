//! The SQL subset of Query Blob Contents: `SELECT <items> FROM BlobStorage [alias] [WHERE <expr>]
//! [LIMIT n]` with comparison, boolean, arithmetic, `LIKE`, `BETWEEN`, `IN`, `IS NULL`, `CAST`,
//! a few string functions, and the aggregates COUNT, SUM, AVG, MIN and MAX (ADR-0027).

use serde_json::Value as Json;

mod eval;
mod lexer;
mod parse;
#[cfg(test)]
mod tests;

pub(super) use eval::{Accumulator, Row, Scope};

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
    pub(super) fatal: bool,
}

fn parse_error<T>(message: impl Into<String>) -> Result<T, SqlError> {
    Err(SqlError {
        name: "ParseError",
        message: message.into(),
        fatal: true,
    })
}

fn runtime_error<T>(name: &'static str, message: impl Into<String>) -> Result<T, SqlError> {
    Err(SqlError {
        name,
        message: message.into(),
        fatal: true,
    })
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
