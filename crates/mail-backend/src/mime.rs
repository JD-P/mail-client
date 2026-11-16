use crate::{
    Attachment, BackendError, ContentState, IngestLimits, MessageLink, MessageLinkSource, Result,
};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};
use linkify::{LinkFinder, LinkKind};
use mail_parser::{AddressList, HeaderForm, MessageParser, PartFlags, PartKind};
use std::cell::{Cell, RefCell};
use url::Url;

pub(crate) struct ParsedMessage {
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub list_id: Option<String>,
    pub rfc_message_id: Option<String>,
    pub sent_at: Option<i64>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub preview: String,
    pub attachments: Vec<Attachment>,
    pub links: Vec<MessageLink>,
    pub content_state: ContentState,
}

pub(crate) fn parse(raw: &[u8], limits: &IngestLimits) -> Result<ParsedMessage> {
    if raw.len() > limits.max_message_bytes {
        return Err(BackendError::MessageTooLarge {
            actual: raw.len(),
            limit: limits.max_message_bytes,
        });
    }
    let message = MessageParser::new()
        .max_depth(limits.max_mime_depth as usize)
        .max_parts(limits.max_mime_parts)
        .max_encoded_nesting(4)
        .parse(raw)
        .ok_or(BackendError::Parse)?;

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

    let attachments = message
        .attachments()
        .enumerate()
        .map(|(ordinal, part)| {
            let declared_media_type = part.content_type().map(|media| {
                media
                    .subtype()
                    .map(|subtype| format!("{}/{}", media.ctype(), subtype))
                    .unwrap_or_else(|| media.ctype().to_owned())
            });
            Attachment {
                id: format!("attachment:{ordinal}"),
                ordinal: ordinal as u32,
                name: part.attachment_name().map(str::to_owned),
                declared_media_type,
                decoded_size: part.decoded_len() as u64,
                inline: part.is_inline(),
                content_id: part.content_id().map(str::to_owned),
            }
        })
        .collect::<Vec<_>>();
    let links = extract_links(
        &body_text,
        (!html.is_empty()).then_some(html.as_str()),
        limits,
        &mut limited,
    );

    let mut delivered_to_addresses = Vec::new();
    for header in message.headers().all("Delivered-To") {
        let parsed = header.parse_as(HeaderForm::Addresses);
        if let Some(list) = parsed.value().as_address() {
            delivered_to_addresses.extend(addresses(Some(list)));
        }
    }
    delivered_to_addresses.sort_unstable();
    delivered_to_addresses.dedup();
    let list_id = message.list_id().and_then(|list| {
        list.first().and_then(|mailbox| {
            mailbox
                .address()
                .or_else(|| mailbox.name())
                .map(str::to_owned)
        })
    });

    let preview = make_preview(&body_text, 240);
    Ok(ParsedMessage {
        subject: message.subject().map(str::to_owned),
        from_address,
        from_name,
        to_addresses: addresses(message.to()),
        cc_addresses: addresses(message.cc()),
        bcc_addresses: addresses(message.bcc()),
        delivered_to_addresses,
        list_id,
        rfc_message_id: message.message_id().map(str::to_owned),
        sent_at: message.date().map(|date| date.to_timestamp()),
        body_text,
        body_html: (!html.is_empty()).then_some(html),
        preview,
        attachments,
        links,
        content_state: if limited {
            ContentState::Limited
        } else {
            ContentState::Complete
        },
    })
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
