use crate::{BackendError, ImapFetchedHeaders, ImapFetchedMessage, Result};
use async_imap::imap_proto::{BodyContentCommon, BodyStructure};
use async_imap::types::{Fetch, Flag};

pub(crate) struct ImapFetchMetadata {
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
    pub internal_date: Option<i64>,
    pub size: u32,
}

/// Convert a complete response from the vendored `async-imap` client into the
/// transport-neutral value consumed by [`crate::Sync::ingest_imap_batch`].
///
/// The IMAP command must request `UID`, `FLAGS`, `INTERNALDATE`, and a complete
/// `BODY.PEEK[]` (or `RFC822`) payload. `MODSEQ` is retained when the server
/// supports it. Missing UID or body data is rejected instead of silently
/// creating an unstable or partial message.
pub fn imap_fetch_message(fetch: &Fetch) -> Result<ImapFetchedMessage> {
    let uid = fetch
        .uid
        .ok_or_else(|| BackendError::InvalidInput("IMAP FETCH response has no UID".into()))?;
    let raw = fetch.body().ok_or_else(|| {
        BackendError::InvalidInput("IMAP FETCH response has no complete message body".into())
    })?;
    Ok(ImapFetchedMessage {
        uid,
        mod_sequence: fetch.modseq,
        flags: fetch.flags().map(flag_text).collect(),
        internal_date: fetch.internal_date().map(|date| date.timestamp()),
        raw: raw.to_vec(),
    })
}

pub(crate) fn imap_fetch_metadata(fetch: &Fetch) -> Result<ImapFetchMetadata> {
    Ok(ImapFetchMetadata {
        uid: fetch
            .uid
            .ok_or_else(|| BackendError::InvalidInput("IMAP FETCH response has no UID".into()))?,
        mod_sequence: fetch.modseq,
        flags: fetch.flags().map(flag_text).collect(),
        internal_date: fetch.internal_date().map(|date| date.timestamp()),
        size: fetch.size.ok_or_else(|| {
            BackendError::InvalidInput("IMAP FETCH response has no RFC822.SIZE".into())
        })?,
    })
}

pub(crate) fn imap_fetch_headers(fetch: &Fetch) -> Result<ImapFetchedHeaders> {
    let metadata = imap_fetch_metadata(fetch)?;
    let headers = fetch.header().ok_or_else(|| {
        BackendError::InvalidInput("IMAP FETCH response has no requested header fields".into())
    })?;
    let bodystructure = fetch.bodystructure().ok_or_else(|| {
        BackendError::InvalidInput("IMAP FETCH response has no requested BODYSTRUCTURE".into())
    })?;
    Ok(ImapFetchedHeaders {
        uid: metadata.uid,
        mod_sequence: metadata.mod_sequence,
        flags: metadata.flags,
        internal_date: metadata.internal_date,
        size_bytes: metadata.size,
        has_attachment: bodystructure_has_attachment(bodystructure),
        headers: headers.to_vec(),
    })
}

fn bodystructure_has_attachment(body: &BodyStructure<'_>) -> bool {
    match body {
        BodyStructure::Multipart { common, bodies, .. } => {
            common_is_attachment(common) || bodies.iter().any(bodystructure_has_attachment)
        }
        BodyStructure::Basic { common, .. } | BodyStructure::Message { common, .. } => {
            common_is_attachment(common) || !common_is_explicitly_inline(common)
        }
        BodyStructure::Text { common, .. } => common_is_attachment(common),
    }
}

fn common_is_explicitly_inline(common: &BodyContentCommon<'_>) -> bool {
    common
        .disposition
        .as_ref()
        .is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("inline"))
}

fn common_is_attachment(common: &BodyContentCommon<'_>) -> bool {
    common.disposition.as_ref().is_some_and(|disposition| {
        disposition.ty.eq_ignore_ascii_case("attachment")
            || disposition.params.as_ref().is_some_and(|parameters| {
                parameters.iter().any(|(name, _)| {
                    name.eq_ignore_ascii_case("filename") || name.eq_ignore_ascii_case("name")
                })
            })
    }) || common.ty.params.as_ref().is_some_and(|parameters| {
        parameters
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("name"))
    })
}

pub(crate) fn imap_fetch_state(fetch: &Fetch) -> Result<(u32, Option<u64>, Vec<String>)> {
    Ok((
        fetch
            .uid
            .ok_or_else(|| BackendError::InvalidInput("IMAP FETCH response has no UID".into()))?,
        fetch.modseq,
        fetch.flags().map(flag_text).collect(),
    ))
}

pub(crate) fn flag_text(flag: Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\Seen".into(),
        Flag::Answered => "\\Answered".into(),
        Flag::Flagged => "\\Flagged".into(),
        Flag::Deleted => "\\Deleted".into(),
        Flag::Draft => "\\Draft".into(),
        Flag::Recent => "\\Recent".into(),
        Flag::MayCreate => "\\*".into(),
        Flag::Custom(value) => value.into_owned(),
    }
}
