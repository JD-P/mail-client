use crate::{Attachment, BackendError, ContentState, IngestLimits, Result};
use mail_parser::{AddressList, HeaderForm, MessageParser, PartFlags, PartKind};

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
                ordinal: ordinal as u32,
                name: part.attachment_name().map(str::to_owned),
                declared_media_type,
                decoded_size: part.decoded_len() as u64,
                inline: part.is_inline(),
                content_id: part.content_id().map(str::to_owned),
            }
        })
        .collect::<Vec<_>>();

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
        content_state: if limited {
            ContentState::Limited
        } else {
            ContentState::Complete
        },
    })
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
