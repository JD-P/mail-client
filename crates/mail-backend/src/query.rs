use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_QUERY_TOKENS: usize = 512;
const MAX_QUERY_NESTING: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op", content = "args")]
pub enum QueryExpr {
    Term(QueryTerm),
    And(Vec<QueryExpr>),
    Or(Vec<QueryExpr>),
    Not(Box<QueryExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueryTerm {
    pub field: Option<String>,
    pub value: String,
    pub phrase: bool,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueryParseError {
    pub message: String,
    pub start: usize,
    pub end: usize,
}

impl QueryParseError {
    pub(crate) fn new(message: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            message: message.into(),
            start,
            end,
        }
    }
}

impl fmt::Display for QueryParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at bytes {}..{}", self.message, self.start, self.end)
    }
}

impl std::error::Error for QueryParseError {}

#[derive(Clone, Debug)]
enum TokenKind {
    Atom { value: String, phrase: bool },
    And,
    Or,
    Minus,
    Left,
    Right,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

pub fn parse_query(source: &str) -> Result<QueryExpr, QueryParseError> {
    if source.len() > MAX_QUERY_BYTES {
        return Err(QueryParseError::new(
            format!("query exceeds the {MAX_QUERY_BYTES}-byte limit"),
            MAX_QUERY_BYTES,
            source.len(),
        ));
    }
    let tokens = lex(source)?;
    if tokens.is_empty() {
        return Err(QueryParseError::new("empty query", 0, 0));
    }
    let mut parser = Parser {
        source_len: source.len(),
        tokens,
        position: 0,
    };
    let expression = parser.parse_or()?;
    if let Some(token) = parser.peek() {
        return Err(QueryParseError::new(
            "unexpected token",
            token.start,
            token.end,
        ));
    }
    Ok(expression)
}

fn lex(source: &str) -> Result<Vec<Token>, QueryParseError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0;
    let mut nesting = 0usize;
    while position < bytes.len() {
        if bytes[position].is_ascii_whitespace() {
            position += 1;
            continue;
        }
        let start = position;
        match bytes[position] {
            b'(' => {
                position += 1;
                nesting += 1;
                if nesting > MAX_QUERY_NESTING {
                    return Err(QueryParseError::new(
                        format!("query nests deeper than {MAX_QUERY_NESTING} parentheses"),
                        start,
                        position,
                    ));
                }
                tokens.push(Token {
                    kind: TokenKind::Left,
                    start,
                    end: position,
                });
            }
            b')' => {
                position += 1;
                nesting = nesting.saturating_sub(1);
                tokens.push(Token {
                    kind: TokenKind::Right,
                    start,
                    end: position,
                });
            }
            b'-' => {
                position += 1;
                tokens.push(Token {
                    kind: TokenKind::Minus,
                    start,
                    end: position,
                });
            }
            _ => {
                let mut value = String::new();
                let mut quoted = false;
                while position < bytes.len()
                    && !bytes[position].is_ascii_whitespace()
                    && !matches!(bytes[position], b'(' | b')')
                {
                    if bytes[position] == b'"' {
                        quoted = true;
                        position += 1;
                        let quote_start = position - 1;
                        let mut closed = false;
                        while position < bytes.len() {
                            match bytes[position] {
                                b'"' => {
                                    position += 1;
                                    closed = true;
                                    break;
                                }
                                b'\\'
                                    if position + 1 < bytes.len()
                                        && matches!(bytes[position + 1], b'"' | b'\\') =>
                                {
                                    value.push(bytes[position + 1] as char);
                                    position += 2;
                                }
                                _ => {
                                    let ch = source[position..].chars().next().expect("in bounds");
                                    value.push(ch);
                                    position += ch.len_utf8();
                                }
                            }
                        }
                        if !closed {
                            return Err(QueryParseError::new(
                                "unterminated quoted phrase",
                                quote_start,
                                source.len(),
                            ));
                        }
                    } else {
                        let ch = source[position..].chars().next().expect("in bounds");
                        value.push(ch);
                        position += ch.len_utf8();
                    }
                }
                if value.is_empty() {
                    return Err(QueryParseError::new("empty search term", start, position));
                }
                let kind = match value.as_str() {
                    "AND" => TokenKind::And,
                    "OR" => TokenKind::Or,
                    _ => TokenKind::Atom {
                        value,
                        phrase: quoted,
                    },
                };
                tokens.push(Token {
                    kind,
                    start,
                    end: position,
                });
            }
        }
        if tokens.len() > MAX_QUERY_TOKENS {
            return Err(QueryParseError::new(
                format!("query exceeds the {MAX_QUERY_TOKENS}-token limit"),
                start,
                position,
            ));
        }
    }
    Ok(tokens)
}

struct Parser {
    source_len: usize,
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += usize::from(token.is_some());
        token
    }

    fn parse_or(&mut self) -> Result<QueryExpr, QueryParseError> {
        let mut terms = vec![self.parse_and()?];
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Or)) {
            self.take();
            terms.push(self.parse_and()?);
        }
        Ok(collapse(terms, QueryExpr::Or))
    }

    fn parse_and(&mut self) -> Result<QueryExpr, QueryParseError> {
        let mut terms = vec![self.parse_unary()?];
        loop {
            match self.peek().map(|token| &token.kind) {
                Some(TokenKind::And) => {
                    self.take();
                    terms.push(self.parse_unary()?);
                }
                Some(TokenKind::Or | TokenKind::Right) | None => break,
                _ => terms.push(self.parse_unary()?),
            }
        }
        Ok(collapse(terms, QueryExpr::And))
    }

    fn parse_unary(&mut self) -> Result<QueryExpr, QueryParseError> {
        let mut negations = 0usize;
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Minus)) {
            self.take();
            negations += 1;
        }
        let mut expression = self.parse_primary()?;
        for _ in 0..negations {
            expression = QueryExpr::Not(Box::new(expression));
        }
        Ok(expression)
    }

    fn parse_primary(&mut self) -> Result<QueryExpr, QueryParseError> {
        let token = self.take().ok_or_else(|| {
            QueryParseError::new("expected a search term", self.source_len, self.source_len)
        })?;
        match token.kind {
            TokenKind::Atom { value, phrase } => {
                let (field, value) = match value.split_once(':') {
                    Some((field, value)) if !field.is_empty() && !value.is_empty() => {
                        (Some(field.to_ascii_lowercase()), value.to_owned())
                    }
                    Some((_field, _value)) => {
                        return Err(QueryParseError::new(
                            "search operator requires a value",
                            token.start,
                            token.end,
                        ));
                    }
                    None => (None, value),
                };
                Ok(QueryExpr::Term(QueryTerm {
                    field,
                    value,
                    phrase,
                    start: token.start,
                    end: token.end,
                }))
            }
            TokenKind::Left => {
                let expression = self.parse_or()?;
                let close = self.take().ok_or_else(|| {
                    QueryParseError::new("unclosed parenthesis", token.start, self.source_len)
                })?;
                if !matches!(close.kind, TokenKind::Right) {
                    return Err(QueryParseError::new(
                        "expected closing parenthesis",
                        close.start,
                        close.end,
                    ));
                }
                Ok(expression)
            }
            _ => Err(QueryParseError::new(
                "expected a search term",
                token.start,
                token.end,
            )),
        }
    }
}

fn collapse(items: Vec<QueryExpr>, make: impl FnOnce(Vec<QueryExpr>) -> QueryExpr) -> QueryExpr {
    if items.len() == 1 {
        items.into_iter().next().expect("one item")
    } else {
        make(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gmail_shaped_boolean_query() {
        let parsed = parse_query(r#"from:alice subject:"quarterly report" OR -is:read"#).unwrap();
        assert!(matches!(parsed, QueryExpr::Or(_)));
    }

    #[test]
    fn reports_unclosed_quote_span() {
        let error = parse_query("subject:\"nope").unwrap_err();
        assert_eq!(error.start, 8);
        assert_eq!(error.end, 13);
    }

    #[test]
    fn rejects_excessive_parenthesis_nesting() {
        let source = format!("{}term{}", "(".repeat(33), ")".repeat(33));
        let error = parse_query(&source).unwrap_err();
        assert!(error.message.contains("deeper than 32"));
    }
}
