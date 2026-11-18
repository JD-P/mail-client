use crate::{
    AccountId, AuthenticationMethodEvidence, AuthenticationMethodKind, AuthenticationMethodResult,
    AuthenticationProperty, AuthenticationResultsHeader, AuthenticationResultsHeaderKind,
    AuthenticationResultsParseStatus, AuthenticationResultsTrust, BackendError,
    DeliveryAuthentication, DeliveryAuthenticationObservation, Result,
};
use mail_parser::MessageParser;
use std::collections::HashSet;

const MAX_AUTH_HEADERS: usize = 32;
const MAX_AUTH_HEADER_BYTES: usize = 32 * 1024;
const MAX_TOTAL_AUTH_HEADER_BYTES: usize = 128 * 1024;
const MAX_METHODS: usize = 32;
const MAX_PROPERTIES: usize = 16;
const MAX_PROPERTY_BYTES: usize = 2 * 1024;
const MAX_COMMENT_DEPTH: usize = 8;
const MAX_TRUSTED_AUTHSERV_IDS: usize = 32;
const MAX_AUTHSERV_ID_BYTES: usize = 255;

pub(crate) fn parse(
    raw: &[u8],
    sources: &[(Option<AccountId>, Vec<String>)],
) -> DeliveryAuthentication {
    let (headers, limited) = parse_headers(raw);
    let sources = if sources.is_empty() {
        vec![(None, Vec::new())]
    } else {
        sources.to_vec()
    };
    DeliveryAuthentication {
        observations: sources
            .into_iter()
            .map(|(account_id, trusted_authserv_ids)| {
                let mut observation = DeliveryAuthenticationObservation {
                    account_id,
                    headers: headers.clone(),
                    limited,
                };
                apply_trust(&mut observation, &trusted_authserv_ids);
                observation
            })
            .collect(),
    }
}

pub(crate) fn refresh_trust(
    evidence: &mut DeliveryAuthentication,
    account_id: AccountId,
    trusted_authserv_ids: &[String],
) {
    for observation in &mut evidence.observations {
        if observation.account_id == Some(account_id) {
            apply_trust(observation, trusted_authserv_ids);
        }
    }
}

pub(crate) fn normalize_trusted_authserv_ids(values: Vec<String>) -> Result<Vec<String>> {
    if values.len() > MAX_TRUSTED_AUTHSERV_IDS {
        return Err(BackendError::InvalidInput(format!(
            "at most {MAX_TRUSTED_AUTHSERV_IDS} trusted authserv-ids may be configured"
        )));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = normalize_authserv_id(&value) else {
            return Err(BackendError::InvalidInput(format!(
                "invalid trusted authserv-id {value:?}"
            )));
        };
        normalized.push(value);
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

fn parse_headers(raw: &[u8]) -> (Vec<AuthenticationResultsHeader>, bool) {
    let Some(message) = MessageParser::new().parse_headers(raw) else {
        return (Vec::new(), false);
    };
    let mut values = Vec::new();
    let mut total_bytes = 0usize;
    let mut limited = false;
    for (header_index, header) in message.headers().iter().enumerate() {
        let kind = if header
            .raw_name()
            .eq_ignore_ascii_case("Authentication-Results")
        {
            AuthenticationResultsHeaderKind::AuthenticationResults
        } else if header
            .raw_name()
            .eq_ignore_ascii_case("ARC-Authentication-Results")
        {
            AuthenticationResultsHeaderKind::ArcAuthenticationResults
        } else {
            continue;
        };
        let raw_value = header.raw_value();
        total_bytes = total_bytes.saturating_add(raw_value.len());
        if values.len() >= MAX_AUTH_HEADERS || total_bytes > MAX_TOTAL_AUTH_HEADER_BYTES {
            limited = true;
            continue;
        }
        values.push(parse_header(
            u32::try_from(header_index).unwrap_or(u32::MAX),
            kind,
            raw_value,
        ));
    }
    (values, limited)
}

fn parse_header(
    header_index: u32,
    kind: AuthenticationResultsHeaderKind,
    raw: &[u8],
) -> AuthenticationResultsHeader {
    if raw.len() > MAX_AUTH_HEADER_BYTES {
        return failed_header(
            header_index,
            kind,
            AuthenticationResultsParseStatus::Limited,
            bounded_lossy(raw, MAX_AUTH_HEADER_BYTES),
            format!("authentication-results header exceeds the {MAX_AUTH_HEADER_BYTES}-byte limit"),
        );
    }
    let unfolded = match unfold(raw) {
        Ok(value) => value,
        Err(detail) => {
            return failed_header(
                header_index,
                kind,
                AuthenticationResultsParseStatus::Malformed,
                bounded_lossy(raw, MAX_AUTH_HEADER_BYTES),
                detail,
            );
        }
    };
    let clean = match strip_comments(&unfolded) {
        Ok(value) => value,
        Err(detail) => {
            return failed_header(
                header_index,
                kind,
                AuthenticationResultsParseStatus::Malformed,
                unfolded,
                detail,
            );
        }
    };
    let segments = split_quoted(&clean, b';');
    let mut position = 0usize;
    let arc_instance = if kind == AuthenticationResultsHeaderKind::ArcAuthenticationResults {
        let Some(segment) = segments.get(position) else {
            return failed_header(
                header_index,
                kind,
                AuthenticationResultsParseStatus::Malformed,
                unfolded,
                "ARC-Authentication-Results is missing i=".into(),
            );
        };
        position += 1;
        match parse_arc_instance(segment) {
            Ok(value) => Some(value),
            Err(detail) => {
                return failed_header(
                    header_index,
                    kind,
                    AuthenticationResultsParseStatus::Malformed,
                    unfolded,
                    detail,
                );
            }
        }
    } else {
        None
    };
    let Some(authserv_segment) = segments.get(position) else {
        return failed_header(
            header_index,
            kind,
            AuthenticationResultsParseStatus::Malformed,
            unfolded,
            "authentication-results header is missing its authserv-id".into(),
        );
    };
    position += 1;
    let (authserv_id, authserv_version) = match parse_authserv(authserv_segment) {
        Ok(value) => value,
        Err(detail) => {
            return failed_header(
                header_index,
                kind,
                AuthenticationResultsParseStatus::Malformed,
                unfolded,
                detail,
            );
        }
    };

    let mut methods = Vec::new();
    let mut saw_none = false;
    for segment in &segments[position..] {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if segment.eq_ignore_ascii_case("none") {
            if saw_none || !methods.is_empty() {
                return failed_header_with_identity(
                    header_index,
                    kind,
                    arc_instance,
                    authserv_id,
                    authserv_version,
                    AuthenticationResultsParseStatus::Malformed,
                    unfolded,
                    "the RFC 8601 none result cannot be combined with other methods".into(),
                );
            }
            saw_none = true;
            continue;
        }
        if saw_none {
            return failed_header_with_identity(
                header_index,
                kind,
                arc_instance,
                authserv_id,
                authserv_version,
                AuthenticationResultsParseStatus::Malformed,
                unfolded,
                "the RFC 8601 none result cannot be combined with other methods".into(),
            );
        }
        if methods.len() >= MAX_METHODS {
            return failed_header_with_identity(
                header_index,
                kind,
                arc_instance,
                authserv_id,
                authserv_version,
                AuthenticationResultsParseStatus::Limited,
                unfolded,
                format!("authentication-results exceeds the {MAX_METHODS}-method limit"),
            );
        }
        match parse_method(segment) {
            Ok(method) => methods.push(method),
            Err(ParseFailure::Malformed(detail)) => {
                return failed_header_with_identity(
                    header_index,
                    kind,
                    arc_instance,
                    authserv_id,
                    authserv_version,
                    AuthenticationResultsParseStatus::Malformed,
                    unfolded,
                    detail,
                );
            }
            Err(ParseFailure::Limited(detail)) => {
                return failed_header_with_identity(
                    header_index,
                    kind,
                    arc_instance,
                    authserv_id,
                    authserv_version,
                    AuthenticationResultsParseStatus::Limited,
                    unfolded,
                    detail,
                );
            }
        }
    }
    if !saw_none && methods.is_empty() {
        return failed_header_with_identity(
            header_index,
            kind,
            arc_instance,
            authserv_id,
            authserv_version,
            AuthenticationResultsParseStatus::Malformed,
            unfolded,
            "authentication-results contains neither none nor a method result".into(),
        );
    }

    AuthenticationResultsHeader {
        header_index,
        kind,
        arc_instance,
        authserv_id: Some(authserv_id),
        authserv_version,
        parse_status: AuthenticationResultsParseStatus::Complete,
        trust: AuthenticationResultsTrust::Malformed,
        methods,
        raw_header_value: unfolded,
        detail: None,
    }
}

fn apply_trust(
    observation: &mut DeliveryAuthenticationObservation,
    trusted_authserv_ids: &[String],
) {
    let trusted = trusted_authserv_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    for header in &mut observation.headers {
        let configured_match = header
            .authserv_id
            .as_deref()
            .is_some_and(|value| trusted.contains(value));
        let duplicate = header.kind == AuthenticationResultsHeaderKind::AuthenticationResults
            && configured_match
            && !seen.insert(header.authserv_id.clone().unwrap_or_default());
        header.trust = match header.parse_status {
            AuthenticationResultsParseStatus::Malformed => AuthenticationResultsTrust::Malformed,
            AuthenticationResultsParseStatus::Limited => AuthenticationResultsTrust::Limited,
            AuthenticationResultsParseStatus::Complete
                if header.kind == AuthenticationResultsHeaderKind::ArcAuthenticationResults =>
            {
                AuthenticationResultsTrust::ArcChainUnverified
            }
            AuthenticationResultsParseStatus::Complete if observation.account_id.is_none() => {
                AuthenticationResultsTrust::NoReceivingAccount
            }
            AuthenticationResultsParseStatus::Complete if trusted.is_empty() => {
                AuthenticationResultsTrust::NoTrustedAuthservConfigured
            }
            AuthenticationResultsParseStatus::Complete if !configured_match => {
                AuthenticationResultsTrust::AuthservIdNotTrusted
            }
            AuthenticationResultsParseStatus::Complete if duplicate => {
                AuthenticationResultsTrust::DuplicateTrustedAuthservId
            }
            AuthenticationResultsParseStatus::Complete => AuthenticationResultsTrust::Trusted,
        };
    }
}

fn failed_header(
    header_index: u32,
    kind: AuthenticationResultsHeaderKind,
    status: AuthenticationResultsParseStatus,
    raw_header_value: String,
    detail: String,
) -> AuthenticationResultsHeader {
    failed_header_with_identity(
        header_index,
        kind,
        None,
        String::new(),
        None,
        status,
        raw_header_value,
        detail,
    )
}

#[allow(clippy::too_many_arguments)]
fn failed_header_with_identity(
    header_index: u32,
    kind: AuthenticationResultsHeaderKind,
    arc_instance: Option<u32>,
    authserv_id: String,
    authserv_version: Option<u32>,
    status: AuthenticationResultsParseStatus,
    raw_header_value: String,
    detail: String,
) -> AuthenticationResultsHeader {
    AuthenticationResultsHeader {
        header_index,
        kind,
        arc_instance,
        authserv_id: (!authserv_id.is_empty()).then_some(authserv_id),
        authserv_version,
        parse_status: status,
        trust: match status {
            AuthenticationResultsParseStatus::Limited => AuthenticationResultsTrust::Limited,
            _ => AuthenticationResultsTrust::Malformed,
        },
        methods: Vec::new(),
        raw_header_value,
        detail: Some(detail),
    }
}

fn parse_arc_instance(value: &str) -> std::result::Result<u32, String> {
    let Some((name, value)) = value.trim().split_once('=') else {
        return Err("ARC-Authentication-Results is missing i=".into());
    };
    let instance = value
        .trim()
        .parse::<u32>()
        .map_err(|_| "ARC-Authentication-Results has an invalid i= value".to_owned())?;
    if !name.trim().eq_ignore_ascii_case("i") || !(1..=50).contains(&instance) {
        return Err("ARC-Authentication-Results i= must be between 1 and 50".into());
    }
    Ok(instance)
}

fn parse_authserv(value: &str) -> std::result::Result<(String, Option<u32>), String> {
    let mut cursor = Cursor::new(value);
    cursor.skip_ws();
    let raw_id = cursor
        .value(b'/')
        .ok_or_else(|| "authentication-results has an invalid authserv-id".to_owned())?;
    let id = normalize_authserv_id(&raw_id)
        .ok_or_else(|| "authentication-results has an invalid authserv-id".to_owned())?;
    cursor.skip_ws();
    let version = if cursor.consume(b'/') {
        cursor.skip_ws();
        let value = cursor
            .digits()
            .ok_or_else(|| "authentication-results has an invalid version".to_owned())?;
        Some(
            value
                .parse::<u32>()
                .map_err(|_| "authentication-results version is too large".to_owned())?,
        )
    } else {
        None
    };
    cursor.skip_ws();
    if !cursor.finished() {
        return Err("authentication-results has trailing data after its authserv-id".into());
    }
    Ok((id, version))
}

fn parse_method(value: &str) -> std::result::Result<AuthenticationMethodEvidence, ParseFailure> {
    let mut cursor = Cursor::new(value);
    cursor.skip_ws();
    let method = cursor
        .atom(false)
        .ok_or_else(|| ParseFailure::malformed("method name is missing"))?
        .to_ascii_lowercase();
    let version = if cursor.consume(b'/') {
        let value = cursor
            .digits()
            .ok_or_else(|| ParseFailure::malformed("method version is invalid"))?;
        Some(
            value
                .parse::<u32>()
                .map_err(|_| ParseFailure::malformed("method version is too large"))?,
        )
    } else {
        None
    };
    cursor.skip_ws();
    if !cursor.consume(b'=') {
        return Err(ParseFailure::malformed("method result is missing '='"));
    }
    cursor.skip_ws();
    let raw_result = cursor
        .atom(false)
        .ok_or_else(|| ParseFailure::malformed("method result is missing"))?
        .to_ascii_lowercase();
    let mut reason = None;
    let mut properties = Vec::new();
    while {
        cursor.skip_ws();
        !cursor.finished()
    } {
        if properties.len() >= MAX_PROPERTIES {
            return Err(ParseFailure::limited(format!(
                "method exceeds the {MAX_PROPERTIES}-property limit"
            )));
        }
        let key = cursor
            .atom(true)
            .ok_or_else(|| ParseFailure::malformed("method property name is invalid"))?
            .to_ascii_lowercase();
        cursor.skip_ws();
        if !cursor.consume(b'=') {
            return Err(ParseFailure::malformed("method property is missing '='"));
        }
        cursor.skip_ws();
        let property_value = cursor
            .value(0)
            .ok_or_else(|| ParseFailure::malformed("method property value is missing"))?;
        if property_value.len() > MAX_PROPERTY_BYTES {
            return Err(ParseFailure::limited(format!(
                "method property exceeds the {MAX_PROPERTY_BYTES}-byte limit"
            )));
        }
        if key == "reason" {
            reason = Some(property_value);
            continue;
        }
        let (namespace, name) = key
            .split_once('.')
            .map_or((None, key.as_str()), |(namespace, name)| {
                (Some(namespace.to_owned()), name)
            });
        if name.is_empty() {
            return Err(ParseFailure::malformed("method property name is empty"));
        }
        properties.push(AuthenticationProperty {
            namespace,
            name: name.to_owned(),
            value: property_value,
        });
    }
    Ok(AuthenticationMethodEvidence {
        kind: match method.as_str() {
            "dkim" => AuthenticationMethodKind::Dkim,
            "dmarc" => AuthenticationMethodKind::Dmarc,
            "spf" => AuthenticationMethodKind::Spf,
            "arc" => AuthenticationMethodKind::Arc,
            _ => AuthenticationMethodKind::Other,
        },
        method,
        version,
        result: match raw_result.as_str() {
            "none" => AuthenticationMethodResult::None,
            "pass" => AuthenticationMethodResult::Pass,
            "fail" => AuthenticationMethodResult::Fail,
            "softfail" => AuthenticationMethodResult::SoftFail,
            "neutral" => AuthenticationMethodResult::Neutral,
            "policy" => AuthenticationMethodResult::Policy,
            "temperror" => AuthenticationMethodResult::TemporaryError,
            "permerror" => AuthenticationMethodResult::PermanentError,
            _ => AuthenticationMethodResult::Unknown,
        },
        raw_result,
        reason,
        properties,
    })
}

fn unfold(raw: &[u8]) -> std::result::Result<String, String> {
    let mut output = Vec::with_capacity(raw.len());
    let mut at = 0usize;
    while at < raw.len() {
        match raw[at] {
            b'\r' => {
                if raw.get(at + 1) != Some(&b'\n') {
                    return Err("authentication-results contains a bare carriage return".into());
                }
                at += 2;
                if at == raw.len() {
                    break;
                }
                if !raw[at].is_ascii_whitespace() {
                    return Err("authentication-results contains an injected line break".into());
                }
                while at < raw.len() && matches!(raw[at], b' ' | b'\t') {
                    at += 1;
                }
                if !output.ends_with(b" ") {
                    output.push(b' ');
                }
            }
            b'\n' => {
                at += 1;
                if at == raw.len() {
                    break;
                }
                if !raw[at].is_ascii_whitespace() {
                    return Err("authentication-results contains an injected line break".into());
                }
                while at < raw.len() && matches!(raw[at], b' ' | b'\t') {
                    at += 1;
                }
                if !output.ends_with(b" ") {
                    output.push(b' ');
                }
            }
            value if value == 0 || value.is_ascii_control() && !matches!(value, b'\t') => {
                return Err("authentication-results contains a control character".into());
            }
            value => {
                output.push(value);
                at += 1;
            }
        }
    }
    String::from_utf8(output)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "authentication-results is not valid UTF-8/ASCII".into())
}

fn strip_comments(value: &str) -> std::result::Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    while at < bytes.len() {
        let value = bytes[at];
        if escaped {
            if depth == 0 {
                output.push(value);
            }
            escaped = false;
            at += 1;
            continue;
        }
        if value == b'\\' && (quoted || depth > 0) {
            if depth == 0 {
                output.push(value);
            }
            escaped = true;
            at += 1;
            continue;
        }
        if depth > 0 {
            match value {
                b'(' => {
                    depth += 1;
                    if depth > MAX_COMMENT_DEPTH {
                        return Err("authentication-results comment nesting is too deep".into());
                    }
                }
                b')' => depth -= 1,
                _ => {}
            }
            at += 1;
            continue;
        }
        match value {
            b'"' => {
                quoted = !quoted;
                output.push(value);
            }
            b'(' if !quoted => {
                depth = 1;
                if !output.ends_with(b" ") {
                    output.push(b' ');
                }
            }
            b')' if !quoted => {
                return Err("authentication-results contains an unmatched ')'".into());
            }
            _ => output.push(value),
        }
        at += 1;
    }
    if escaped || quoted || depth > 0 {
        return Err("authentication-results contains an unterminated quote or comment".into());
    }
    String::from_utf8(output).map_err(|_| "authentication-results is not valid UTF-8/ASCII".into())
}

fn split_quoted(value: &str, delimiter: u8) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0usize;
    let mut values = Vec::new();
    for (at, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' && quoted {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == delimiter && !quoted {
            values.push(&value[start..at]);
            start = at + 1;
        }
    }
    values.push(&value[start..]);
    values
}

fn normalize_authserv_id(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty()
        || value.len() > MAX_AUTHSERV_ID_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn bounded_lossy(value: &[u8], maximum: usize) -> String {
    String::from_utf8_lossy(&value[..value.len().min(maximum)])
        .trim()
        .to_owned()
}

enum ParseFailure {
    Malformed(String),
    Limited(String),
}

impl ParseFailure {
    fn malformed(detail: impl Into<String>) -> Self {
        Self::Malformed(detail.into())
    }

    fn limited(detail: impl Into<String>) -> Self {
        Self::Limited(detail.into())
    }
}

struct Cursor<'a> {
    value: &'a str,
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(value: &'a str) -> Self {
        Self { value, at: 0 }
    }

    fn finished(&self) -> bool {
        self.at == self.value.len()
    }

    fn skip_ws(&mut self) {
        while self
            .value
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.at += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.value.as_bytes().get(self.at) == Some(&expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn digits(&mut self) -> Option<&'a str> {
        let start = self.at;
        while self
            .value
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_digit)
        {
            self.at += 1;
        }
        (self.at > start).then(|| &self.value[start..self.at])
    }

    fn atom(&mut self, property: bool) -> Option<&'a str> {
        let start = self.at;
        while self.value.as_bytes().get(self.at).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') || property && *byte == b'.'
        }) {
            self.at += 1;
        }
        (self.at > start).then(|| &self.value[start..self.at])
    }

    fn value(&mut self, stop: u8) -> Option<String> {
        if self.consume(b'"') {
            let mut output = String::new();
            let mut escaped = false;
            while let Some(byte) = self.value.as_bytes().get(self.at).copied() {
                self.at += 1;
                if escaped {
                    output.push(char::from(byte));
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    return Some(output);
                } else if byte.is_ascii_control() {
                    return None;
                } else {
                    output.push(char::from(byte));
                }
            }
            return None;
        }
        let start = self.at;
        while self
            .value
            .as_bytes()
            .get(self.at)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && (stop == 0 || *byte != stop))
        {
            self.at += 1;
        }
        (self.at > start).then(|| self.value[start..self.at].to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_only_first_complete_header_for_a_configured_authserv_id() {
        let account = AccountId::new();
        let evidence = parse(
            concat!(
                "Authentication-Results: mx.provider.example;\r\n",
                " dkim=pass header.d=example.com header.s=mail;\r\n",
                " dmarc=pass header.from=example.com;\r\n",
                " spf=pass smtp.mailfrom=return@example.com; arc=pass\r\n",
                "Authentication-Results: attacker.invalid; dkim=pass header.d=evil.example\r\n",
                "Authentication-Results: mx.provider.example; dkim=fail header.d=example.com\r\n",
                "ARC-Authentication-Results: i=1; forwarder.example; dkim=pass header.d=example.com\r\n",
                "\r\nbody"
            )
            .as_bytes(),
            &[(Some(account), vec!["mx.provider.example".into()])],
        );
        let headers = &evidence.observations[0].headers;
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].trust, AuthenticationResultsTrust::Trusted);
        assert_eq!(headers[0].methods.len(), 4);
        assert_eq!(headers[0].methods[1].kind, AuthenticationMethodKind::Dmarc);
        assert_eq!(headers[0].methods[2].kind, AuthenticationMethodKind::Spf);
        assert_eq!(headers[0].methods[3].kind, AuthenticationMethodKind::Arc);
        assert_eq!(
            headers[1].trust,
            AuthenticationResultsTrust::AuthservIdNotTrusted
        );
        assert_eq!(
            headers[2].trust,
            AuthenticationResultsTrust::DuplicateTrustedAuthservId
        );
        assert_eq!(headers[3].arc_instance, Some(1));
        assert_eq!(
            headers[3].trust,
            AuthenticationResultsTrust::ArcChainUnverified
        );
    }

    #[test]
    fn malformed_and_oversized_headers_fail_closed() {
        let account = AccountId::new();
        let malformed = parse(
            b"Authentication-Results: mx.provider.example; dkim=pass (unterminated\r\n\r\n",
            &[(Some(account), vec!["mx.provider.example".into()])],
        );
        assert_eq!(
            malformed.observations[0].headers[0].trust,
            AuthenticationResultsTrust::Malformed
        );

        let raw = format!(
            "Authentication-Results: mx.provider.example; dkim=pass reason=\"{}\"\r\n\r\n",
            "a".repeat(MAX_AUTH_HEADER_BYTES)
        );
        let limited = parse(
            raw.as_bytes(),
            &[(Some(account), vec!["mx.provider.example".into()])],
        );
        assert_eq!(
            limited.observations[0].headers[0].trust,
            AuthenticationResultsTrust::Limited
        );
    }

    #[test]
    fn authserv_configuration_is_normalized_and_rejects_injection() {
        assert_eq!(
            normalize_trusted_authserv_ids(vec![
                "MX.Provider.Example.".into(),
                "mx.provider.example".into(),
            ])
            .unwrap(),
            vec!["mx.provider.example"]
        );
        assert!(normalize_trusted_authserv_ids(vec!["mx.example; dkim=pass".into()]).is_err());
    }
}
