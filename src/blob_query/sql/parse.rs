//! Recursive-descent parser from tokens to the syntax tree.

use super::{
    Agg, CastType, Expr, Item, Op, Part, Query, SqlError, Value, contains_aggregate, parse_error,
};

use super::lexer::{Token, tokens};

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
    pub(in crate::blob_query) fn parse(sql: &str) -> Result<Self, SqlError> {
        let mut parser = Parser {
            tokens: tokens(sql)?,
            at: 0,
        };
        parser.query()
    }
}
