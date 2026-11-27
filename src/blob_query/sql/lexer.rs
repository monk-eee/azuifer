//! Splits SQL text into tokens.

use super::{SqlError, parse_error};

// ------------------------------------------------------------------ lexer

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Token {
    Word(String),
    Quoted(String),
    Number(String),
    Text(String),
    Symbol(&'static str),
}

const SYMBOLS: [&str; 17] = [
    "<>", "!=", "<=", ">=", "||", ",", "(", ")", "*", "+", "-", "/", "%", "=", "<", ">", ".",
];

pub(super) fn tokens(sql: &str) -> Result<Vec<Token>, SqlError> {
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
