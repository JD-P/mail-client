#![forbid(unsafe_code)]
//! CSS syntax adapter. Every declaration is parsed once; unsupported values are
//! ignored at declaration granularity. No stylesheet or URL loading occurs here.
use crate::{core::*, dom::*};
use cssparser::{Parser, Token};
use serde::Serialize;
#[derive(Clone, Debug, Serialize)]
pub struct Declaration {
    pub name: String,
    pub value: String,
    pub important: bool,
    pub order: u32,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Relation {
    Descendant,
    Child,
    Adjacent,
    Sibling,
}
#[derive(Clone, Debug, Serialize)]
pub enum Test {
    Tag(String),
    Id(String),
    Class(String),
    Attr(String, String, String),
    State(String),
}
#[derive(Clone, Debug, Serialize)]
pub struct Compound {
    pub tests: Vec<Test>,
    pub relation: Relation,
}
#[derive(Clone, Debug, Serialize)]
pub struct Selector {
    pub parts: Vec<Compound>,
    pub specificity: u32,
    pub valid: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    pub selectors: Vec<Selector>,
    pub declarations: Vec<Declaration>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Sheet {
    pub rules: Vec<Rule>,
    pub rejected: Vec<String>,
    pub selector_count: usize,
}

// A bounded scanner for structural delimiters; actual identifier/value escapes
// are interpreted by cssparser when matching/decoding declaration components.
pub fn split_top(s: &str, delimiter: char) -> Vec<&str> {
    let mut v = vec![];
    let (mut start, mut depth, mut quote, mut escape) = (0, 0i32, '\0', false);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if c == '\\' {
            escape = true;
            i += 1;
            continue;
        }
        if quote != '\0' {
            if c == quote {
                quote = '\0';
            }
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = c;
        } else if c == '/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if c == '(' || c == '[' || c == '{' {
            depth += 1;
        } else if c == ')' || c == ']' || c == '}' {
            depth -= 1;
        } else if depth == 0 && c == delimiter {
            v.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    v.push(&s[start..]);
    v
}
pub fn clean(s: &str) -> String {
    let mut p = Parser::new(s);
    let mut out = String::new();
    while let Ok(t) = p.next_including_whitespace_and_comments() {
        match t {
            Token::Comment(_) => out.push(' '),
            _ => {
                use cssparser::ToCss;
                let _ = t.to_css(&mut out);
            }
        }
    }
    out
}
pub fn ident(s: &str) -> Option<String> {
    let mut p = Parser::new(s);
    let v = p.expect_ident_cloned().ok()?.to_ascii_lowercase();
    p.expect_exhausted().ok()?;
    Some(v)
}
pub fn canonical_value(s: &str) -> Option<String> {
    fn tokens(p: &mut Parser<'_>, depth: usize) -> Option<String> {
        if depth > 64 {
            return None;
        }
        use cssparser::{ToCss, TokenSerializationType};
        let mut out = String::new();
        let mut previous = TokenSerializationType::Nothing;
        while let Ok(token) = p.next_including_whitespace_and_comments().cloned() {
            if matches!(token, Token::Comment(_)) {
                continue;
            }
            if matches!(token, Token::BadString(_) | Token::BadUrl(_)) {
                return None;
            }
            let kind = token.serialization_type();
            if previous.needs_separator_when_before(kind) {
                out.push(' ');
            }
            match token {
                Token::WhiteSpace(_) => {
                    if !out.ends_with(' ') {
                        out.push(' ');
                    }
                    previous = kind;
                    continue;
                }
                Token::Function(_)
                | Token::ParenthesisBlock
                | Token::SquareBracketBlock
                | Token::CurlyBracketBlock => {
                    let close = match token {
                        Token::SquareBracketBlock => ']',
                        Token::CurlyBracketBlock => '}',
                        _ => ')',
                    };
                    token.to_css(&mut out).ok()?;
                    let inner = p
                        .parse_nested_block(|p| {
                            tokens(p, depth + 1)
                                .ok_or_else(|| cssparser::ParseError::<()>::custom(()))
                        })
                        .ok()?;
                    out.push_str(&inner);
                    out.push(close);
                    previous = Token::CloseParenthesis.serialization_type();
                }
                _ => {
                    token.to_css(&mut out).ok()?;
                    previous = kind;
                }
            }
        }
        Some(out.trim().to_string())
    }
    let mut p = Parser::new(s);
    tokens(&mut p, 0)
}
pub fn declarations(
    s: &str,
    order: &mut u32,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Vec<Declaration>> {
    if s.len() > limits.css_bytes {
        return Err(Error::Budget("CSS bytes"));
    }
    budget.charge(s.len() as u64)?;
    let mut out = vec![];
    for piece in split_top(s, ';') {
        let halves = split_top(piece, ':');
        if halves.len() < 2 {
            continue;
        }
        let name = match ident(halves[0].trim()) {
            Some(v) => v,
            None => continue,
        };
        let value = piece[halves[0].len() + 1..].trim();
        let lower = value.to_ascii_lowercase();
        let mut important = false;
        let mut end = value.len();
        if let Some(i) = lower.rfind('!') {
            if ident(lower[i + 1..].trim()).as_deref() == Some("important") {
                important = true;
                end = i;
            }
        }
        if *order as usize >= limits.declarations {
            return Err(Error::Budget("declarations"));
        }
        *order += 1;
        out.push(Declaration {
            name,
            value: match canonical_value(value[..end].trim()) {
                Some(v) => v,
                None => continue,
            },
            important,
            order: *order,
        });
    }
    Ok(out)
}
pub fn words(s: &str) -> Vec<String> {
    let mut p = Parser::new(s);
    let mut out = vec![];
    while !p.is_exhausted() {
        let start = p.position();
        if p.next().is_err() {
            break;
        }
        let _ = p.parse_nested_block(|q| {
            while q.next_including_whitespace_and_comments().is_ok() {}
            Ok::<_, cssparser::ParseError<()>>(())
        });
        out.push(p.slice_from(start).trim().to_string());
    }
    out
}

pub fn parse_selector(s: &str, limits: &Limits) -> Selector {
    let mut p = Parser::new(s);
    let mut parts = vec![];
    let mut tests = vec![];
    let mut specificity = 0u32;
    let mut relation = Relation::Descendant;
    let mut valid = true;
    let mut space = false;
    while let Ok(t) = p.next_including_whitespace_and_comments().cloned() {
        match t {
            Token::WhiteSpace(_) => {
                space = true;
                continue;
            }
            Token::Comment(_) => continue,
            Token::Delim(c) if c == '>' || c == '+' || c == '~' => {
                if !tests.is_empty() {
                    parts.push(Compound {
                        tests: std::mem::take(&mut tests),
                        relation,
                    });
                }
                relation = match c {
                    '>' => Relation::Child,
                    '+' => Relation::Adjacent,
                    _ => Relation::Sibling,
                };
                space = false;
                continue;
            }
            _ => {}
        }
        if space && !tests.is_empty() {
            parts.push(Compound {
                tests: std::mem::take(&mut tests),
                relation,
            });
            relation = Relation::Descendant;
        }
        space = false;
        match t {
            Token::Ident(v) => {
                tests.push(Test::Tag(v.to_ascii_lowercase()));
                specificity += 1;
            }
            Token::Delim('*') => {
                tests.push(Test::Tag("*".into()));
            }
            Token::IDHash(v) => {
                tests.push(Test::Id(v.to_string()));
                specificity += 65536;
            }
            Token::Delim('.') => {
                if let Ok(v) = p.expect_ident_cloned() {
                    tests.push(Test::Class(v.to_string()));
                    specificity += 256;
                } else {
                    valid = false;
                    break;
                }
            }
            Token::SquareBracketBlock => {
                let a = p.parse_nested_block(|q| {
                    let name = q.expect_ident_cloned()?.to_ascii_lowercase();
                    let op = match q.next() {
                        Ok(Token::Delim('=')) => "=",
                        Ok(Token::IncludeMatch) => "~=",
                        Ok(Token::DashMatch) => "|=",
                        Ok(Token::PrefixMatch) => "^=",
                        Ok(Token::SuffixMatch) => "$=",
                        Ok(Token::SubstringMatch) => "*=",
                        Err(_) => "",
                        _ => return Err(cssparser::ParseError::<()>::custom(())),
                    };
                    let value = if op.is_empty() {
                        String::new()
                    } else {
                        q.expect_ident_or_string()?.to_string()
                    };
                    let insensitive = if let Ok(v) = q.expect_ident() {
                        v.eq_ignore_ascii_case("i")
                    } else {
                        false
                    };
                    q.expect_exhausted()?;
                    Ok::<_, cssparser::ParseError<()>>((
                        name,
                        format!("{}{}", op, if insensitive { "i" } else { "" }),
                        value,
                    ))
                });
                if let Ok((a, b, c)) = a {
                    tests.push(Test::Attr(a, b, c));
                    specificity += 256;
                } else {
                    valid = false;
                }
            }
            Token::Colon => {
                if let Ok(v) = p.expect_ident_cloned() {
                    let v = v.to_ascii_lowercase();
                    if matches!(
                        v.as_str(),
                        "hover" | "focus" | "focus-visible" | "active" | "link"
                    ) {
                        tests.push(Test::State(v));
                        specificity += 256;
                    } else {
                        valid = false;
                    }
                } else {
                    valid = false;
                }
            }
            _ => {
                valid = false;
                break;
            }
        }
        if parts.len() >= limits.selector_parts {
            valid = false;
            break;
        }
    }
    // Relations belong to the right-hand compound for right-to-left matching.
    parts.push(Compound { tests, relation });
    Selector {
        parts,
        specificity,
        valid,
    }
}
fn compound_matches(c: &Compound, id: NodeId, doc: &Document, states: &[(NodeId, String)]) -> bool {
    let n = &doc.nodes[id];
    if !n.element() || n.disabled {
        return false;
    }
    c.tests.iter().all(|t| match t {
        Test::Tag(v) => v == "*" || &n.tag == v,
        Test::Id(v) => n.attr("id") == Some(v.as_str()),
        Test::Class(v) => n
            .attr("class")
            .is_some_and(|s| s.split_ascii_whitespace().any(|x| x == v)),
        Test::State(v) => {
            if v == "link" {
                n.tag == "a" && n.attr("href").is_some()
            } else {
                n.tag == "a" && states.iter().any(|(i, s)| *i == id && s == v)
            }
        }
        Test::Attr(k, op, value) => {
            let Some(a) = n.attr(k) else {
                return false;
            };
            let (a, v) = if op.ends_with('i') {
                (a.to_ascii_lowercase(), value.to_ascii_lowercase())
            } else {
                (a.to_string(), value.clone())
            };
            match op.trim_end_matches('i') {
                "" => true,
                "=" => a == v,
                "~=" => a.split_ascii_whitespace().any(|x| x == v),
                "|=" => a == v || a.starts_with(&(v + "-")),
                "^=" => !v.is_empty() && a.starts_with(&v),
                "$=" => !v.is_empty() && a.ends_with(&v),
                "*=" => !v.is_empty() && a.contains(&v),
                _ => false,
            }
        }
    })
}
pub fn matches(
    sel: &Selector,
    id: NodeId,
    doc: &Document,
    states: &[(NodeId, String)],
    budget: &mut Budget,
) -> Result<bool> {
    if !sel.valid || sel.parts.is_empty() {
        return Ok(false);
    }
    let mut pending = vec![(id, sel.parts.len() - 1)];
    while let Some((node, part)) = pending.pop() {
        let n = &doc.nodes[node];
        let attr_cost = |key: &str, compare: bool| {
            n.attrs.iter().map(|(k, _)| k.len() + 1).sum::<usize>()
                + if compare {
                    n.attr(key).map(|v| v.len()).unwrap_or(0)
                } else {
                    0
                }
        };
        let work = sel.parts[part]
            .tests
            .iter()
            .map(|t| match t {
                Test::Tag(v) => v.len() + n.tag.len() + 1,
                Test::Id(v) => attr_cost("id", true) + v.len(),
                Test::Class(v) => attr_cost("class", true) + v.len(),
                Test::Attr(k, _, v) => attr_cost(k, true) + v.len(),
                Test::State(v) => attr_cost("href", false) + v.len(),
            })
            .sum::<usize>()
            + 1;
        budget.charge(work as u64)?;
        if !compound_matches(&sel.parts[part], node, doc, states) {
            continue;
        }
        if part == 0 {
            return Ok(true);
        }
        match sel.parts[part].relation {
            Relation::Child => {
                if let Some(p) = doc.nodes[node].parent {
                    pending.push((p, part - 1));
                }
            }
            Relation::Descendant => {
                let mut p = doc.nodes[node].parent;
                while let Some(i) = p {
                    budget.charge(1)?;
                    pending.push((i, part - 1));
                    p = doc.nodes[i].parent;
                }
            }
            Relation::Adjacent => {
                if let Some(p) = doc.previous_element(node) {
                    pending.push((p, part - 1));
                }
            }
            Relation::Sibling => {
                let mut p = doc.previous_element(node);
                while let Some(i) = p {
                    budget.charge(1)?;
                    pending.push((i, part - 1));
                    p = doc.previous_element(i);
                }
            }
        }
    }
    Ok(false)
}

pub fn media_matches(s: &str, width: Au, height: Au) -> bool {
    let _ = height;
    split_top(s, ',').iter().any(|query| {
        let q = query.trim().to_ascii_lowercase();
        let neg = q.starts_with("not ");
        let q = q.strip_prefix("not ").unwrap_or(&q).trim();
        let q = q.strip_prefix("only ").unwrap_or(q);
        let mut ok = true;
        for term in q.split(" and ") {
            let term = term.trim();
            if term == "screen" || term == "all" || term.is_empty() {
                continue;
            }
            if !term.starts_with('(') || !term.ends_with(')') {
                ok = false;
                break;
            }
            let a: Vec<_> = term[1..term.len() - 1].splitn(2, ':').collect();
            if a.len() != 2 {
                ok = false;
                break;
            }
            let value = a[1]
                .trim()
                .strip_suffix("px")
                .and_then(|x| x.trim().parse::<i64>().ok())
                .map(px);
            ok &= match (a[0].trim(), value) {
                ("min-width" | "min-device-width", Some(v)) => width >= v,
                ("max-width" | "max-device-width", Some(v)) => width <= v,
                ("width" | "device-width", Some(v)) => width == v,
                _ => false,
            };
        }
        if neg {
            !ok
        } else {
            ok
        }
    })
}
pub fn stylesheet(
    s: &str,
    width: Au,
    height: Au,
    limits: &Limits,
    budget: &mut Budget,
    order: &mut u32,
) -> Result<Sheet> {
    let mut sheet = Sheet::default();
    parse_rules(s, width, height, limits, budget, order, 0, &mut sheet)?;
    Ok(sheet)
}
fn parse_rules(
    s: &str,
    width: Au,
    height: Au,
    limits: &Limits,
    budget: &mut Budget,
    order: &mut u32,
    depth: usize,
    sheet: &mut Sheet,
) -> Result<()> {
    if depth > limits.media_depth {
        return Err(Error::Budget("media nesting"));
    }
    budget.charge(s.len() as u64)?;
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(b.len());
            continue;
        }
        let start = i;
        let (mut quote, mut parens, mut escape) = ('\0', 0i32, false);
        while i < b.len() {
            let c = b[i] as char;
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if quote != '\0' {
                if c == quote {
                    quote = '\0';
                }
            } else if c == '\'' || c == '"' {
                quote = c;
            } else if c == '(' || c == '[' {
                parens += 1;
            } else if c == ')' || c == ']' {
                parens -= 1;
            } else if parens == 0 && (c == '{' || c == ';') {
                break;
            }
            i += 1;
        }
        if i == b.len() {
            break;
        }
        let prelude = s[start..i].trim();
        if b[i] == b';' {
            if prelude.starts_with('@') {
                sheet.rejected.push(prelude.to_string());
            }
            i += 1;
            continue;
        }
        i += 1;
        let block = i;
        let mut nesting = 1usize;
        quote = '\0';
        escape = false;
        while i < b.len() && nesting > 0 {
            let c = b[i] as char;
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if quote != '\0' {
                if c == quote {
                    quote = '\0';
                }
            } else if c == '\'' || c == '"' {
                quote = c;
            } else if b[i..].starts_with(b"/*") {
                i += 2;
                while i + 1 < b.len() && !b[i..].starts_with(b"*/") {
                    i += 1;
                }
                i = (i + 2).min(b.len());
                continue;
            } else if c == '{' {
                nesting += 1;
            } else if c == '}' {
                nesting -= 1;
                if nesting == 0 {
                    break;
                }
            }
            i += 1;
        }
        let body = &s[block..i];
        i = (i + 1).min(b.len());
        if prelude.starts_with('@') {
            if prelude.to_ascii_lowercase().starts_with("@media ")
                && media_matches(prelude[7..].trim(), width, height)
            {
                parse_rules(body, width, height, limits, budget, order, depth + 1, sheet)?;
            } else {
                sheet.rejected.push(prelude.to_string());
            }
            continue;
        }
        let selectors: Vec<_> = split_top(prelude, ',')
            .into_iter()
            .map(|q| parse_selector(q.trim(), limits))
            .collect();
        if selectors.iter().any(|x| !x.valid) {
            continue;
        }
        if sheet.selector_count + selectors.len() > limits.selectors {
            return Err(Error::Budget("selectors"));
        }
        sheet.selector_count += selectors.len();
        sheet.rules.push(Rule {
            selectors,
            declarations: declarations(body, order, limits, budget)?,
        });
    }
    Ok(())
}
