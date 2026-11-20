use crate::{
    archive_worker::{self, ArchiveOperation, ArchiveOutput},
    ArchiveInspection, ArchiveInspectionState, ArchiveIsolationConfig, ArchiveLimits, Backend,
    BackendError, DocumentExtractionLimits, DocumentExtractionRequest, DocumentExtractionResult,
    MessageContentAvailability, MessageId, MimeDecodeState, MimeParseState, MimePart, MimePartKind,
    MimePartRole, MimeStructure, Result,
};
use futures_util::future::BoxFuture;
use std::{path::Path, time::Duration};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// External document conversion boundary. Implementations must cross into a
/// disposable sandbox process; the backend deliberately provides no in-process
/// PDF/office parser.
pub trait SandboxedDocumentExtractor: Send + Sync {
    fn extract<'a>(
        &'a self,
        request: DocumentExtractionRequest,
    ) -> BoxFuture<'a, Result<DocumentExtractionResult>>;
}

#[derive(Clone)]
pub struct Mime(Backend);

impl Mime {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn structure(&self, message_id: MessageId) -> Result<MimeStructure> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT mime_state, mime_detail, content_availability FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| BackendError::NotFound {
            entity: "message",
            id: message_id.to_string(),
        })?;
        let state = parse_parse_state(&row.get::<String>(0)?)?;
        let detail = row.get(1)?;
        let availability = parse_availability(&row.get::<String>(2)?)?;
        if availability != MessageContentAvailability::Complete {
            return Err(BackendError::ContentUnavailable {
                id: message_id.to_string(),
                state: availability_text(availability).into(),
            });
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT part_id, parent_part_id, child_ids_json, kind, role, declared_media_type, name, content_id, content_location, inline, attachment, decoded_size, decode_state, parse_flags_json, decode_problems_json, in_plain_body, in_html_body FROM mime_parts WHERE message_id = ?1 ORDER BY part_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut parts = Vec::new();
        while let Some(row) = rows.next().await? {
            parts.push(MimePart {
                id: database_u32(row.get(0)?, "MIME part ID")?,
                parent_id: row
                    .get::<Option<i64>>(1)?
                    .map(|value| database_u32(value, "MIME parent part ID"))
                    .transpose()?,
                child_ids: serde_json::from_str(&row.get::<String>(2)?)?,
                kind: parse_part_kind(&row.get::<String>(3)?)?,
                role: parse_part_role(&row.get::<String>(4)?)?,
                declared_media_type: row.get(5)?,
                name: row.get(6)?,
                content_id: row.get(7)?,
                content_location: row.get(8)?,
                inline: row.get(9)?,
                attachment: row.get(10)?,
                decoded_size: database_u64(row.get(11)?, "MIME decoded size")?,
                decode_state: parse_decode_state(&row.get::<String>(12)?)?,
                parse_flags: serde_json::from_str(&row.get::<String>(13)?)?,
                decode_problems: serde_json::from_str(&row.get::<String>(14)?)?,
                in_plain_body: row.get(15)?,
                in_html_body: row.get(16)?,
            });
        }
        let root_part_id = parts
            .iter()
            .find(|part| part.parent_id.is_none())
            .map(|part| part.id)
            .ok_or_else(|| {
                BackendError::InvalidInput("message has no materialized MIME root".into())
            })?;
        let plain_body_part_ids = parts
            .iter()
            .filter(|part| part.in_plain_body)
            .map(|part| part.id)
            .collect();
        let html_body_part_ids = parts
            .iter()
            .filter(|part| part.in_html_body)
            .map(|part| part.id)
            .collect();
        Ok(MimeStructure {
            message_id,
            state,
            detail,
            root_part_id,
            parts,
            plain_body_part_ids,
            html_body_part_ids,
        })
    }

    pub async fn stream_attachment<W: AsyncWrite + Unpin>(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        writer: &mut W,
        maximum_bytes: u64,
    ) -> Result<u64> {
        let ordinal = parse_attachment_id(attachment_id)?;
        let hash = self.attachment_blob(message_id, ordinal).await?;
        self.0
            .inner
            .blobs
            .stream_to(&hash, writer, maximum_bytes)
            .await
    }

    /// Resolve a `cid:` URL without giving message HTML network or filesystem
    /// authority. Returns `false` when the content ID is absent.
    pub async fn stream_content_id<W: AsyncWrite + Unpin>(
        &self,
        message_id: MessageId,
        content_id: &str,
        writer: &mut W,
        maximum_bytes: u64,
    ) -> Result<bool> {
        self.ensure_content_complete(message_id).await?;
        let content_id = normalize_content_id(content_id)?;
        let hash = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT blobs.blob_hash FROM mime_parts parts JOIN mime_part_blobs blobs ON blobs.message_id = parts.message_id AND blobs.part_id = parts.part_id WHERE parts.message_id = ?1 AND parts.content_id = ?2 COLLATE NOCASE ORDER BY parts.part_id LIMIT 2",
                    (message_id.to_string(), content_id),
                )
                .await?;
            let first = rows
                .next()
                .await?
                .map(|row| row.get::<String>(0))
                .transpose()?;
            if first.is_some() && rows.next().await?.is_some() {
                return Err(BackendError::Conflict(
                    "message contains duplicate Content-ID resources".into(),
                ));
            }
            first
        };
        let Some(hash) = hash else {
            return Ok(false);
        };
        self.0
            .inner
            .blobs
            .stream_to(&hash, writer, maximum_bytes)
            .await?;
        Ok(true)
    }

    /// Export to a caller-selected path. The untrusted attachment filename is
    /// never used as a path, and an existing destination is never overwritten.
    pub async fn export_attachment(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        destination: &Path,
        maximum_bytes: u64,
    ) -> Result<u64> {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .await
            .map_err(|source| BackendError::Io {
                path: destination.to_owned(),
                source,
            })?;
        let result = self
            .stream_attachment(message_id, attachment_id, &mut file, maximum_bytes)
            .await;
        if result.is_ok() {
            if let Err(source) = file.flush().await {
                drop(file);
                let _ = tokio::fs::remove_file(destination).await;
                return Err(BackendError::Io {
                    path: destination.to_owned(),
                    source,
                });
            }
        }
        if result.is_err() {
            drop(file);
            let _ = tokio::fs::remove_file(destination).await;
        }
        result
    }

    /// Reads ZIP directory metadata under caller budgets without inflating an
    /// entry. Expansion is available only through the separate, explicit
    /// [`Self::read_archive_entry`] operation.
    pub async fn inspect_archive(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        limits: ArchiveLimits,
    ) -> Result<ArchiveInspection> {
        self.inspect_archive_with_isolation(
            message_id,
            attachment_id,
            limits,
            ArchiveIsolationConfig::default(),
        )
        .await
    }

    /// Inspect ZIP metadata in a disposable, fail-closed worker. The explicit
    /// configuration exists for packaged applications and boundary tests; it
    /// does not provide an in-process compatibility path.
    pub async fn inspect_archive_with_isolation(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        limits: ArchiveLimits,
        isolation: ArchiveIsolationConfig,
    ) -> Result<ArchiveInspection> {
        archive_worker::validate_limits(&limits)?;
        if !self
            .attachment_media_type(message_id, attachment_id)
            .await?
            .is_some_and(|value| value.eq_ignore_ascii_case("application/zip"))
        {
            return Ok(ArchiveInspection {
                state: ArchiveInspectionState::Unsupported,
                entries: Vec::new(),
                total_uncompressed_bytes: 0,
                detail: Some("only ZIP archive inspection is currently supported".into()),
            });
        }
        let bytes = self
            .read_attachment(message_id, attachment_id, limits.max_archive_bytes)
            .await?;
        // An IMAP sync worker is already disposable and its seccomp profile
        // forbids nested exec. Reuse that established process boundary rather
        // than weakening it. All ordinary backend callers use the dedicated
        // archive worker below.
        let output = if self.0.inner.search_deferred {
            ArchiveOutput::Inspection(archive_worker::inspect_zip(&bytes, limits)?)
        } else {
            archive_worker::execute(bytes, limits, ArchiveOperation::Inspect, isolation).await?
        };
        match output {
            ArchiveOutput::Inspection(inspection) => Ok(inspection),
            ArchiveOutput::Entry(_) => Err(BackendError::InvalidInput(
                "archive worker returned entry bytes for an inspection".into(),
            )),
        }
    }

    pub async fn read_archive_entry(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        entry_index: u32,
        limits: ArchiveLimits,
    ) -> Result<Vec<u8>> {
        self.read_archive_entry_with_isolation(
            message_id,
            attachment_id,
            entry_index,
            limits,
            ArchiveIsolationConfig::default(),
        )
        .await
    }

    /// Expand exactly one ZIP entry in a disposable worker and validate its
    /// byte count before returning it to the caller.
    pub async fn read_archive_entry_with_isolation(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        entry_index: u32,
        limits: ArchiveLimits,
        isolation: ArchiveIsolationConfig,
    ) -> Result<Vec<u8>> {
        archive_worker::validate_limits(&limits)?;
        if !self
            .attachment_media_type(message_id, attachment_id)
            .await?
            .is_some_and(|value| value.eq_ignore_ascii_case("application/zip"))
        {
            return Err(BackendError::InvalidInput(
                "only ZIP archive expansion is currently supported".into(),
            ));
        }
        let bytes = self
            .read_attachment(message_id, attachment_id, limits.max_archive_bytes)
            .await?;
        let output = if self.0.inner.search_deferred {
            ArchiveOutput::Entry(archive_worker::read_zip_entry(&bytes, entry_index, limits)?)
        } else {
            archive_worker::execute(
                bytes,
                limits,
                ArchiveOperation::ReadEntry { entry_index },
                isolation,
            )
            .await?
        };
        match output {
            ArchiveOutput::Entry(bytes) => Ok(bytes),
            ArchiveOutput::Inspection(_) => Err(BackendError::InvalidInput(
                "archive worker returned metadata for an entry expansion".into(),
            )),
        }
    }

    pub async fn extract_document_text(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        limits: DocumentExtractionLimits,
        extractor: &dyn SandboxedDocumentExtractor,
    ) -> Result<DocumentExtractionResult> {
        if limits.max_input_bytes == 0
            || limits.max_output_bytes == 0
            || limits.timeout_seconds == 0
        {
            return Err(BackendError::InvalidInput(
                "document extraction limits must be positive".into(),
            ));
        }
        let ordinal = parse_attachment_id(attachment_id)?;
        let (hash, declared_media_type, detected_media_type, name, size) =
            self.attachment_record(message_id, ordinal).await?;
        if size > limits.max_input_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: usize::try_from(size).unwrap_or(usize::MAX),
                limit: usize::try_from(limits.max_input_bytes).unwrap_or(usize::MAX),
            });
        }
        let bytes = self.0.inner.blobs.get(&hash).await?;
        if bytes.len() as u64 > limits.max_input_bytes {
            return Err(BackendError::InvalidInput(
                "attachment exceeds document extractor input budget".into(),
            ));
        }
        let result = tokio::time::timeout(
            Duration::from_secs(limits.timeout_seconds),
            extractor.extract(DocumentExtractionRequest {
                declared_media_type,
                detected_media_type,
                name,
                bytes,
                max_output_bytes: limits.max_output_bytes,
            }),
        )
        .await
        .map_err(|_| BackendError::InvalidInput("document extractor timed out".into()))??;
        if result.text.len() > limits.max_output_bytes {
            return Err(BackendError::InvalidInput(
                "document extractor exceeded its output budget".into(),
            ));
        }
        Ok(result)
    }

    async fn attachment_blob(&self, message_id: MessageId, ordinal: u32) -> Result<String> {
        self.attachment_record(message_id, ordinal)
            .await
            .map(|record| record.0)
    }

    async fn attachment_record(
        &self,
        message_id: MessageId,
        ordinal: u32,
    ) -> Result<(String, Option<String>, Option<String>, Option<String>, u64)> {
        self.ensure_content_complete(message_id).await?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT blob_hash, declared_media_type, detected_media_type, name, decoded_size FROM attachments WHERE message_id = ?1 AND ordinal = ?2",
                (message_id.to_string(), i64::from(ordinal)),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| BackendError::NotFound {
            entity: "attachment",
            id: format!("{message_id}:attachment:{ordinal}"),
        })?;
        let hash = row.get::<Option<String>>(0)?.ok_or_else(|| {
            BackendError::Conflict("attachment predates decoded-resource storage".into())
        })?;
        let size = u64::try_from(row.get::<i64>(4)?)
            .map_err(|_| BackendError::InvalidInput("invalid attachment size".into()))?;
        Ok((hash, row.get(1)?, row.get(2)?, row.get(3)?, size))
    }

    async fn ensure_content_complete(&self, message_id: MessageId) -> Result<()> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT content_availability FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| BackendError::NotFound {
            entity: "message",
            id: message_id.to_string(),
        })?;
        let availability = parse_availability(&row.get::<String>(0)?)?;
        if availability != MessageContentAvailability::Complete {
            return Err(BackendError::ContentUnavailable {
                id: message_id.to_string(),
                state: availability_text(availability).into(),
            });
        }
        Ok(())
    }

    async fn read_attachment(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>> {
        let ordinal = parse_attachment_id(attachment_id)?;
        let (hash, _, _, _, size) = self.attachment_record(message_id, ordinal).await?;
        if size > maximum_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: usize::try_from(size).unwrap_or(usize::MAX),
                limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
            });
        }
        let bytes = self.0.inner.blobs.get(&hash).await?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(BackendError::InvalidInput(
                "attachment exceeds configured read budget".into(),
            ));
        }
        Ok(bytes)
    }

    async fn attachment_media_type(
        &self,
        message_id: MessageId,
        attachment_id: &str,
    ) -> Result<Option<String>> {
        let ordinal = parse_attachment_id(attachment_id)?;
        self.attachment_record(message_id, ordinal)
            .await
            .map(|record| record.2.or(record.1))
    }
}

fn parse_attachment_id(value: &str) -> Result<u32> {
    value
        .strip_prefix("attachment:")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| BackendError::InvalidInput("invalid attachment identifier".into()))
}

fn normalize_content_id(value: &str) -> Result<String> {
    let value = value
        .trim()
        .strip_prefix("cid:")
        .unwrap_or(value.trim())
        .trim_start_matches('<')
        .trim_end_matches('>');
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(BackendError::InvalidInput("invalid Content-ID".into()));
    }
    Ok(value.to_owned())
}

fn database_u32(value: i64, name: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {name}")))
}

fn database_u64(value: i64, name: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {name}")))
}

fn parse_parse_state(value: &str) -> Result<MimeParseState> {
    match value {
        "complete" => Ok(MimeParseState::Complete),
        "limited" => Ok(MimeParseState::Limited),
        "failed" => Ok(MimeParseState::Failed),
        _ => Err(BackendError::InvalidInput(
            "invalid MIME parse state".into(),
        )),
    }
}

fn parse_availability(value: &str) -> Result<MessageContentAvailability> {
    match value {
        "headers_only" => Ok(MessageContentAvailability::HeadersOnly),
        "downloading" => Ok(MessageContentAvailability::Downloading),
        "complete" => Ok(MessageContentAvailability::Complete),
        "failed" => Ok(MessageContentAvailability::Failed),
        _ => Err(BackendError::InvalidInput(
            "invalid message content availability".into(),
        )),
    }
}

fn availability_text(value: MessageContentAvailability) -> &'static str {
    match value {
        MessageContentAvailability::HeadersOnly => "headers_only",
        MessageContentAvailability::Downloading => "downloading",
        MessageContentAvailability::Complete => "complete",
        MessageContentAvailability::Failed => "failed",
    }
}

fn parse_decode_state(value: &str) -> Result<MimeDecodeState> {
    match value {
        "complete" => Ok(MimeDecodeState::Complete),
        "problems" => Ok(MimeDecodeState::Problems),
        "limited" => Ok(MimeDecodeState::Limited),
        "failed" => Ok(MimeDecodeState::Failed),
        _ => Err(BackendError::InvalidInput(
            "invalid MIME decode state".into(),
        )),
    }
}

fn parse_part_kind(value: &str) -> Result<MimePartKind> {
    match value {
        "text" => Ok(MimePartKind::Text),
        "html" => Ok(MimePartKind::Html),
        "binary" => Ok(MimePartKind::Binary),
        "inline_binary" => Ok(MimePartKind::InlineBinary),
        "multipart" => Ok(MimePartKind::Multipart),
        "message" => Ok(MimePartKind::Message),
        _ => Err(BackendError::InvalidInput("invalid MIME part kind".into())),
    }
}

fn parse_part_role(value: &str) -> Result<MimePartRole> {
    match value {
        "container" => Ok(MimePartRole::Container),
        "text_body" => Ok(MimePartRole::TextBody),
        "html_body" => Ok(MimePartRole::HtmlBody),
        "copied_body" => Ok(MimePartRole::CopiedBody),
        "media_body" => Ok(MimePartRole::MediaBody),
        "attachment" => Ok(MimePartRole::Attachment),
        "dropped" => Ok(MimePartRole::Dropped),
        _ => Err(BackendError::InvalidInput("invalid MIME part role".into())),
    }
}
