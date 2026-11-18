use crate::{
    Attachment, BackendError, ContentState, IngestLimits, MessageLink, MessageLinkSource,
    MimeDecodeState, MimeParseState, MimePart, MimePartKind, MimePartRole, Result,
};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};
use linkify::{LinkFinder, LinkKind};
use mail_parser::{AddressList, HeaderForm, MessageParser, PartFlags, PartKind, PartRole};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};
use url::Url;

pub(crate) struct ParsedMessage {
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub sender_addresses: Vec<String>,
    pub reply_to_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub list_id: Option<String>,
    pub rfc_message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub sent_at: Option<i64>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub preview: String,
    pub attachments: Vec<ParsedAttachment>,
    pub resources: Vec<ParsedResource>,
    pub mime_parts: Vec<MimePart>,
    pub mime_state: MimeParseState,
    pub mime_detail: Option<String>,
    pub links: Vec<MessageLink>,
    pub content_state: ContentState,
}

pub(crate) struct ParsedAttachment {
    pub metadata: Attachment,
    pub decode_problems: Vec<String>,
}

pub(crate) struct ParsedResource {
    pub part_id: u32,
    pub bytes: Vec<u8>,
}

pub(crate) struct ParsedThreadHeaders {
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub sender_addresses: Vec<String>,
    pub reply_to_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub rfc_message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
}

/// Parse only the RFC 5322 header block when rebuilding the thread projection.
/// This avoids decoding MIME bodies during a one-time profile upgrade.
pub(crate) fn parse_thread_headers(raw: &[u8]) -> Result<ParsedThreadHeaders> {
    let message = MessageParser::new()
        .parse_headers(raw)
        .ok_or(BackendError::Parse)?;
    let sender = message.from().and_then(|addresses| addresses.first());
    Ok(ParsedThreadHeaders {
        subject: message.subject().map(str::to_owned),
        from_address: sender
            .and_then(|mailbox| mailbox.address())
            .map(normalize_address),
        to_addresses: addresses(message.to()),
        cc_addresses: addresses(message.cc()),
        bcc_addresses: addresses(message.bcc()),
        sender_addresses: addresses(message.sender()),
        reply_to_addresses: addresses(message.reply_to()),
        delivered_to_addresses: delivered_to_addresses(&message),
        rfc_message_id: message.message_id().map(str::to_owned),
        in_reply_to: message
            .in_reply_to()
            .map(|values| values.iter().map(str::to_owned).collect())
            .unwrap_or_default(),
        references: message
            .references()
            .map(|values| values.iter().map(str::to_owned).collect())
            .unwrap_or_default(),
    })
}

pub(crate) fn parse(raw: &[u8], limits: &IngestLimits) -> Result<ParsedMessage> {
    if raw.len() > limits.max_message_bytes {
        return Err(BackendError::MessageTooLarge {
            actual: raw.len(),
            limit: limits.max_message_bytes,
        });
    }
    let Some(message) = MessageParser::new()
        .max_depth(limits.max_mime_depth as usize)
        .max_parts(limits.max_mime_parts)
        .max_encoded_nesting(4)
        .parse(raw)
    else {
        // Preserve exact bytes even when an RFC 5322/MIME interpretation is
        // impossible. Callers can inspect the explicit failed projection and
        // offer raw export without accidentally presenting arbitrary bytes as
        // a successfully parsed message.
        return Ok(ParsedMessage {
            subject: None,
            from_address: None,
            from_name: None,
            to_addresses: Vec::new(),
            cc_addresses: Vec::new(),
            bcc_addresses: Vec::new(),
            sender_addresses: Vec::new(),
            reply_to_addresses: Vec::new(),
            delivered_to_addresses: Vec::new(),
            list_id: None,
            rfc_message_id: None,
            in_reply_to: Vec::new(),
            references: Vec::new(),
            sent_at: None,
            body_text: String::new(),
            body_html: None,
            preview: String::new(),
            attachments: Vec::new(),
            resources: Vec::new(),
            mime_parts: vec![MimePart {
                id: 0,
                parent_id: None,
                child_ids: Vec::new(),
                kind: MimePartKind::Binary,
                role: MimePartRole::Dropped,
                declared_media_type: None,
                name: None,
                content_id: None,
                content_location: None,
                inline: false,
                attachment: false,
                in_plain_body: false,
                in_html_body: false,
                decoded_size: raw.len() as u64,
                decode_state: MimeDecodeState::Failed,
                parse_flags: vec!["parse_failed".into()],
                decode_problems: vec!["input has no RFC 5322 header block or separator".into()],
            }],
            mime_state: MimeParseState::Failed,
            mime_detail: Some("message could not be parsed as RFC 5322/MIME".into()),
            links: Vec::new(),
            content_state: ContentState::Limited,
        });
    };

    let sender = message.from().and_then(|addresses| addresses.first());
    let from_address = sender
        .and_then(|mailbox| mailbox.address())
        .map(normalize_address);
    let from_name = sender.and_then(|mailbox| mailbox.name()).map(str::to_owned);

    let mut limited = message
        .parts()
        .any(|part| part.flags().contains(PartFlags::LIMIT_REACHED));

    let mut body_text = String::new();
    for body in message.text_bodies() {
        append_bounded(&mut body_text, &body, limits.max_text_bytes, &mut limited);
        if body_text.len() >= limits.max_text_bytes {
            break;
        }
        if !body_text.is_empty() {
            append_bounded(&mut body_text, "\n", limits.max_text_bytes, &mut limited);
        }
    }

    let mut html = String::new();
    for part in message.html_body() {
        if matches!(part.kind(), PartKind::Html) {
            if let Some(text) =
                part.text_prefix_bytes(limits.max_html_bytes.saturating_sub(html.len()))
            {
                append_bounded(&mut html, &text, limits.max_html_bytes, &mut limited);
            }
            if html.len() >= limits.max_html_bytes {
                break;
            }
        }
    }

    let mut attachments = Vec::new();
    let mut resources = Vec::new();
    let mut resource_problems = HashMap::new();
    for part in message.parts() {
        if !part.is_attachment() && part.content_id().is_none() {
            continue;
        }
        let (decoded, problems) = part.decoded_checked();
        let problem_names = problems.names().map(str::to_owned).collect::<Vec<_>>();
        let bytes = decoded.into_owned();
        let detected_media_type = detect_media_type(&bytes).map(str::to_owned);
        let decode_state = if part.flags().contains(PartFlags::LIMIT_REACHED) {
            MimeDecodeState::Limited
        } else if !problem_names.is_empty() {
            MimeDecodeState::Problems
        } else {
            MimeDecodeState::Complete
        };
        resource_problems.insert(part.id(), (decode_state, problem_names.clone()));
        resources.push(ParsedResource {
            part_id: part.id(),
            bytes,
        });
        if part.is_attachment() {
            let ordinal = attachments.len() as u32;
            attachments.push(ParsedAttachment {
                metadata: Attachment {
                    id: format!("attachment:{ordinal}"),
                    ordinal,
                    mime_part_id: part.id(),
                    name: part.attachment_name().map(str::to_owned),
                    declared_media_type: declared_media_type(part.content_type()),
                    detected_media_type,
                    decoded_size: part.decoded_len() as u64,
                    inline: part.is_inline(),
                    content_id: part.content_id().map(str::to_owned),
                    decode_state,
                },
                decode_problems: problem_names,
            });
        }
    }
    let mime_parts = message
        .parts()
        .map(|part| {
            let (decode_state, decode_problems) = resource_problems
                .get(&part.id())
                .cloned()
                .unwrap_or_else(|| {
                    if part.flags().contains(PartFlags::LIMIT_REACHED) {
                        (MimeDecodeState::Limited, Vec::new())
                    } else {
                        (MimeDecodeState::Complete, Vec::new())
                    }
                });
            MimePart {
                id: part.id(),
                parent_id: part.parent().map(|parent| parent.id()),
                child_ids: part.children().map(|child| child.id()).collect(),
                kind: match part.kind() {
                    PartKind::Text => MimePartKind::Text,
                    PartKind::Html => MimePartKind::Html,
                    PartKind::Binary => MimePartKind::Binary,
                    PartKind::InlineBinary => MimePartKind::InlineBinary,
                    PartKind::Multipart => MimePartKind::Multipart,
                    PartKind::Message(_) => MimePartKind::Message,
                },
                role: match part.role() {
                    PartRole::Container => MimePartRole::Container,
                    PartRole::TextBody => MimePartRole::TextBody,
                    PartRole::HtmlBody => MimePartRole::HtmlBody,
                    PartRole::CopiedBody => MimePartRole::CopiedBody,
                    PartRole::MediaBody => MimePartRole::MediaBody,
                    PartRole::Attachment => MimePartRole::Attachment,
                    PartRole::Dropped => MimePartRole::Dropped,
                },
                declared_media_type: declared_media_type(part.content_type()),
                name: part.attachment_name().map(str::to_owned),
                content_id: part.content_id().map(str::to_owned),
                content_location: part.content_location().map(str::to_owned),
                inline: part.is_inline(),
                attachment: part.is_attachment(),
                in_plain_body: part.in_text_body(),
                in_html_body: part.in_html_body(),
                decoded_size: part.decoded_len() as u64,
                decode_state,
                parse_flags: part.flags().names().map(str::to_owned).collect(),
                decode_problems,
            }
        })
        .collect::<Vec<_>>();
    let links = extract_links(
        &body_text,
        (!html.is_empty()).then_some(html.as_str()),
        limits,
        &mut limited,
    );

    let delivered_to_addresses = delivered_to_addresses(&message);
    let list_id = message.list_id().and_then(|list| {
        list.first().and_then(|mailbox| {
            mailbox
                .address()
                .or_else(|| mailbox.name())
                .map(str::to_owned)
        })
    });

    let preview = make_preview(&body_text, 240);
    let mime_state = if limited {
        MimeParseState::Limited
    } else {
        MimeParseState::Complete
    };
    Ok(ParsedMessage {
        subject: message.subject().map(str::to_owned),
        from_address,
        from_name,
        to_addresses: addresses(message.to()),
        cc_addresses: addresses(message.cc()),
        bcc_addresses: addresses(message.bcc()),
        sender_addresses: addresses(message.sender()),
        reply_to_addresses: addresses(message.reply_to()),
        delivered_to_addresses,
        list_id,
        rfc_message_id: message.message_id().map(str::to_owned),
        in_reply_to: message
            .in_reply_to()
            .map(|values| values.iter().map(str::to_owned).collect())
            .unwrap_or_default(),
        references: message
            .references()
            .map(|values| values.iter().map(str::to_owned).collect())
            .unwrap_or_default(),
        sent_at: message.date().map(|date| date.to_timestamp()),
        body_text,
        body_html: (!html.is_empty()).then_some(html),
        preview,
        attachments,
        resources,
        mime_parts,
        mime_state,
        mime_detail: limited.then(|| "configured MIME or decoded-content limit reached".into()),
        links,
        content_state: if limited {
            ContentState::Limited
        } else {
            ContentState::Complete
        },
    })
}

fn declared_media_type(media: Option<mail_parser::ContentType<'_>>) -> Option<String> {
    media.map(|media| {
        media
            .subtype()
            .map(|subtype| format!("{}/{}", media.ctype(), subtype))
            .unwrap_or_else(|| media.ctype().to_owned())
    })
}

pub(crate) fn detect_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"%PDF-") {
        Some("application/pdf")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        Some("application/zip")
    } else if bytes.starts_with(b"\x7fELF") {
        Some("application/x-executable")
    } else if bytes.starts_with(b"MZ") {
        Some("application/vnd.microsoft.portable-executable")
    } else if bytes.starts_with(b"{\\rtf") {
        Some("application/rtf")
    } else {
        None
    }
}

fn extract_links(
    body_text: &str,
    body_html: Option<&str>,
    limits: &IngestLimits,
    limited: &mut bool,
) -> Vec<MessageLink> {
    let mut links = Vec::new();
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);
    for link in finder.links(body_text) {
        push_link(
            &mut links,
            link.as_str(),
            MessageLinkSource::PlainText,
            limits,
            limited,
        );
        if links.len() >= limits.max_links {
            *limited = true;
            return links;
        }
    }

    let Some(html) = body_html else {
        return links;
    };
    let sink = HtmlLinkSink {
        hrefs: RefCell::new(Vec::new()),
        tokens: Cell::new(0),
        maximum_tokens: limits.max_html_nodes,
        maximum_links: limits.max_links.saturating_sub(links.len()),
        limited: Cell::new(false),
    };
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    *limited |= tokenizer.sink.limited.get();
    for href in tokenizer.sink.hrefs.into_inner() {
        push_link(&mut links, &href, MessageLinkSource::Html, limits, limited);
    }
    links
}

struct HtmlLinkSink {
    hrefs: RefCell<Vec<String>>,
    tokens: Cell<usize>,
    maximum_tokens: usize,
    maximum_links: usize,
    limited: Cell<bool>,
}

impl TokenSink for HtmlLinkSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        let token_count = self.tokens.get().saturating_add(1);
        self.tokens.set(token_count);
        if token_count > self.maximum_tokens {
            self.limited.set(true);
            return TokenSinkResult::Continue;
        }
        if let TagToken(tag) = token {
            let tag_name: &str = tag.name.as_ref();
            if tag.kind == StartTag && tag_name == "a" {
                let href = tag.attrs.iter().find(|attribute| {
                    let name: &str = attribute.name.local.as_ref();
                    name == "href"
                });
                if let Some(href) = href {
                    let mut hrefs = self.hrefs.borrow_mut();
                    if hrefs.len() < self.maximum_links {
                        hrefs.push(href.value.to_string());
                    } else {
                        self.limited.set(true);
                    }
                }
            }
            if tag.kind == StartTag {
                return match tag_name {
                    "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                    "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                        TokenSinkResult::RawData(RawKind::Rawtext)
                    }
                    "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                    _ => TokenSinkResult::Continue,
                };
            }
        }
        TokenSinkResult::Continue
    }
}

fn push_link(
    links: &mut Vec<MessageLink>,
    destination: &str,
    source: MessageLinkSource,
    limits: &IngestLimits,
    limited: &mut bool,
) {
    if links.len() >= limits.max_links {
        *limited = true;
        return;
    }
    let destination = destination.trim();
    if destination.is_empty() || destination.len() > 8_192 {
        *limited |= destination.len() > 8_192;
        return;
    }
    let Ok(parsed) = Url::parse(destination) else {
        return;
    };
    let ordinal = links.len() as u32;
    let host = parsed.host_str().map(|host| host.to_lowercase());
    let registrable_domain = host.as_deref().and_then(psl::domain_str).map(str::to_owned);
    links.push(MessageLink {
        id: format!("link:{ordinal}"),
        ordinal,
        destination: destination.to_owned(),
        scheme: parsed.scheme().to_lowercase(),
        host,
        registrable_domain,
        source,
    });
}

fn addresses(list: Option<AddressList<'_>>) -> Vec<String> {
    list.into_iter()
        .flat_map(|items| items.mailboxes())
        .filter_map(|mailbox| mailbox.address().map(normalize_address))
        .collect()
}

fn delivered_to_addresses(message: &mail_parser::Message<'_>) -> Vec<String> {
    let mut delivered = Vec::new();
    for header in message.headers().all("Delivered-To") {
        let parsed = header.parse_as(HeaderForm::Addresses);
        if let Some(list) = parsed.value().as_address() {
            delivered.extend(addresses(Some(list)));
        }
    }
    delivered.sort_unstable();
    delivered.dedup();
    delivered
}

fn normalize_address(value: &str) -> String {
    value.trim().to_lowercase()
}

fn append_bounded(target: &mut String, source: &str, limit: usize, limited: &mut bool) {
    let remaining = limit.saturating_sub(target.len());
    if source.len() <= remaining {
        target.push_str(source);
        return;
    }
    let mut end = remaining;
    while end > 0 && !source.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&source[..end]);
    *limited = true;
}

fn make_preview(text: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut was_space = true;
    for character in text.chars() {
        if character.is_whitespace() {
            if !was_space && output.chars().count() < max_chars {
                output.push(' ');
            }
            was_space = true;
        } else if output.chars().count() < max_chars {
            output.push(character);
            was_space = false;
        } else {
            break;
        }
    }
    output.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_security_relevant_html_destinations() {
        let limits = IngestLimits::default();
        let mut limited = false;
        let links = extract_links(
            "",
            Some(
                r#"<a href="https://accounts.example.com@evil.example:8443/login?next=https%3A%2F%2Faccounts.example.com">accounts.example.com</a><script>"<a href='https://not-a-link.example'>"</script><a href="javascript:alert(1)">continue</a>"#,
            ),
            &limits,
            &mut limited,
        );
        assert!(!limited);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].host.as_deref(), Some("evil.example"));
        assert_eq!(links[1].scheme, "javascript");
    }
}
