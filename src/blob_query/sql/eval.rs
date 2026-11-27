//! Evaluation of a parsed query against rows: lookups, comparison, functions, projection and aggregates.

use super::{
    Agg, CastType, Expr, Item, Op, Part, Query, SqlError, Value, parse_error, runtime_error,
};
use serde_json::Value as Json;
use std::cmp::Ordering;

// ------------------------------------------------------------------ rows and evaluation

/// One input record.
pub(in crate::blob_query) enum Row {
    Csv(Vec<String>),
    Json(Json),
}

/// What a query needs to know about its input besides the row.
pub(in crate::blob_query) struct Scope<'a> {
    pub(in crate::blob_query) headers: Option<&'a [String]>,
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
    let failed = || {
        Err(SqlError {
            name: "InvalidTypeConversion",
            message: "Invalid type conversion.".into(),
            fatal: false,
        })
    };
    match kind {
        CastType::Text => Ok(Value::Str(value.to_text())),
        CastType::Int => match number(&value) {
            Some(Number::Int(int)) => Ok(Value::Int(int)),
            Some(Number::Float(float)) if float.is_finite() => Ok(Value::Int(float.trunc() as i64)),
            _ => match value {
                Value::Bool(flag) => Ok(Value::Int(i64::from(flag))),
                _ => failed(),
            },
        },
        CastType::Float => match number(&value) {
            Some(number) => Ok(Value::Float(as_f64(number))),
            None => failed(),
        },
        CastType::Bool => truth(&value).map_or_else(failed, |flag| Ok(Value::Bool(flag))),
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
    pub(in crate::blob_query) fn matches(
        &self,
        row: &Row,
        scope: &Scope<'_>,
    ) -> Result<bool, SqlError> {
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

    pub(in crate::blob_query) fn is_aggregate(&self) -> bool {
        self.aggregate
    }

    /// The output columns of one row, as `(name, value)`.
    pub(in crate::blob_query) fn project(
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

    pub(in crate::blob_query) fn accumulators(&self) -> Vec<Accumulator> {
        self.items
            .iter()
            .filter_map(|item| match item {
                Item::Expr(Expr::Aggregate(kind, _), _) => Some(Accumulator::new(*kind)),
                _ => None,
            })
            .collect()
    }

    /// Feeds one matching row to every aggregate.
    pub(in crate::blob_query) fn accumulate(
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
    pub(in crate::blob_query) fn aggregate_names(&self) -> Vec<String> {
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

pub(in crate::blob_query) struct Accumulator {
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

    pub(in crate::blob_query) fn finish(self) -> Value {
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
