use crate::backend::insert_event;
use crate::{
    AccountId, Backend, BackendError, Draft, DraftAttachment, DraftAttachmentDisposition,
    DraftAttachmentId, DraftContent, DraftId, DraftStatus, IngestMessage, MessageComposition,
    MessageId, NewDraftAttachment, ReplyAudience, Result, SendingLimits, SmtpAccount, SmtpSettings,
    Submission, SubmissionId, SubmissionStatus,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use serde_json::json;
use std::{collections::HashSet, str::FromStr};
use tokio::io::AsyncRead;
use turso::Connection;
use uuid::Uuid;

#[derive(Clone)]
pub struct Sending(Backend);

impl Sending {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn configure_smtp_with_credential(
        &self,
        account_id: AccountId,
        settings: SmtpSettings,
        credential: crate::ImapCredential,
    ) -> Result<SmtpAccount> {
        let reference = self.0.credentials().store(credential).await?;
        let configured = self
            .configure_smtp(account_id, settings, reference.clone())
            .await;
        if configured.is_err() {
            let committed = self
                .smtp_account(account_id)
                .await
                .ok()
                .is_some_and(|account| account.credential_ref == reference);
            if !committed {
                let _ = self.0.credentials().delete(&reference).await;
            }
        }
        configured
    }

    pub async fn configure_smtp(
        &self,
        account_id: AccountId,
        settings: SmtpSettings,
        credential_ref: String,
    ) -> Result<SmtpAccount> {
        validate_smtp_settings(&settings)?;
        require_header_value("credential reference", &credential_ref)?;
        if credential_ref.trim().is_empty() {
            return Err(BackendError::InvalidInput(
                "SMTP credential reference must not be empty".into(),
            ));
        }
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM accounts WHERE id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        if rows.next().await?.is_none() {
            return Err(not_found("account", account_id));
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT credential_ref FROM smtp_accounts WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let previous_reference = rows
            .next()
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?;
        drop(rows);
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO smtp_accounts(account_id, settings_json, credential_ref, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(account_id) DO UPDATE SET settings_json = excluded.settings_json, credential_ref = excluded.credential_ref, updated_at = excluded.updated_at",
                (
                    account_id.to_string(),
                    serde_json::to_string(&settings)?,
                    credential_ref.clone(),
                    now,
                ),
            )
            .await?;
        if previous_reference.as_deref() != Some(credential_ref.as_str()) {
            if let Some(reference) = &previous_reference {
                self.0
                    .queue_managed_credential_cleanup_on(&transaction, reference, now)
                    .await?;
            }
        }
        let event = insert_event(
            &transaction,
            now,
            "smtp_configured",
            account_id.to_string(),
            json!({"account_id": account_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.drain_credential_cleanup(16).await?;
        let _ = self.0.inner.events.send(event);
        Ok(SmtpAccount {
            account_id,
            settings,
            credential_ref,
            updated_at: now,
        })
    }

    pub async fn smtp_account(&self, account_id: AccountId) -> Result<SmtpAccount> {
        let connection = self.0.inner.connection.lock().await;
        load_smtp_account_on(&connection, account_id).await
    }

    pub async fn remove_smtp(&self, account_id: AccountId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT credential_ref FROM smtp_accounts WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let previous_reference = rows
            .next()
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?;
        drop(rows);
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "DELETE FROM smtp_accounts WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        if let Some(reference) = &previous_reference {
            self.0
                .queue_managed_credential_cleanup_on(&transaction, reference, now)
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "smtp_removed",
            account_id.to_string(),
            json!({"account_id": account_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.drain_credential_cleanup(16).await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Drafts(Backend);

impl Drafts {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn create(&self, content: DraftContent) -> Result<Draft> {
        validate_draft_content(&content)?;
        self.0.accounts().get(content.account_id).await?;
        let now = Utc::now().timestamp();
        let draft = Draft {
            id: DraftId::new(),
            revision: 1,
            status: DraftStatus::Editing,
            content,
            attachments: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        insert_draft_on(&transaction, &draft).await?;
        let event = insert_event(
            &transaction,
            now,
            "draft_created",
            draft.id.to_string(),
            json!({"draft_id": draft.id, "revision": draft.revision}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(draft)
    }

    pub async fn create_reply(
        &self,
        account_id: AccountId,
        message_id: MessageId,
        audience: ReplyAudience,
    ) -> Result<Draft> {
        let composition = self.0.threads().reply(message_id, audience).await?;
        self.create_composition(account_id, composition).await
    }

    pub async fn create_forward(
        &self,
        account_id: AccountId,
        message_id: MessageId,
        limits: SendingLimits,
    ) -> Result<Draft> {
        let composition = self.0.threads().forward(message_id).await?;
        let attached = composition.attached_message_id;
        let draft = self.create_composition(account_id, composition).await?;
        if let Some(message_id) = attached {
            let raw = self.0.messages().raw(message_id).await?;
            let mut reader = std::io::Cursor::new(raw);
            self.add_attachment(
                draft.id,
                draft.revision,
                NewDraftAttachment {
                    name: "forwarded-message.eml".into(),
                    media_type: "message/rfc822".into(),
                    disposition: DraftAttachmentDisposition::Attachment,
                    content_id: None,
                },
                &mut reader,
                limits,
            )
            .await
        } else {
            Ok(draft)
        }
    }

    async fn create_composition(
        &self,
        account_id: AccountId,
        composition: MessageComposition,
    ) -> Result<Draft> {
        self.create(DraftContent {
            account_id,
            thread_id: composition.thread_id,
            parent_message_id: composition.parent_message_id,
            to_addresses: composition.to_addresses,
            cc_addresses: composition.cc_addresses,
            bcc_addresses: Vec::new(),
            subject: composition.subject,
            body_text: String::new(),
            body_html: None,
            in_reply_to: composition.in_reply_to,
            references: composition.references,
        })
        .await
    }

    pub async fn get(&self, id: DraftId) -> Result<Draft> {
        let connection = self.0.inner.connection.lock().await;
        load_draft_on(&connection, id).await
    }

    pub async fn list(&self) -> Result<Vec<Draft>> {
        let ids = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query("SELECT id FROM drafts ORDER BY updated_at DESC, id", ())
                .await?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next().await? {
                ids.push(parse_id(row.get::<String>(0)?, "draft")?);
            }
            ids
        };
        let mut drafts = Vec::with_capacity(ids.len());
        for id in ids {
            drafts.push(self.get(id).await?);
        }
        Ok(drafts)
    }

    /// Autosave uses optimistic concurrency. A stale frontend cannot overwrite
    /// edits made by another frontend or agent.
    pub async fn save(
        &self,
        id: DraftId,
        expected_revision: u32,
        content: DraftContent,
    ) -> Result<Draft> {
        validate_draft_content(&content)?;
        self.0.accounts().get(content.account_id).await?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE drafts SET account_id = ?1, revision = revision + 1, thread_id = ?2, parent_message_id = ?3, to_addresses = ?4, cc_addresses = ?5, bcc_addresses = ?6, subject = ?7, body_text = ?8, body_html = ?9, in_reply_to = ?10, references_json = ?11, updated_at = ?12 WHERE id = ?13 AND revision = ?14 AND status = 'editing'",
                turso::params![
                    content.account_id.to_string(),
                    content.thread_id.to_string(),
                    content.parent_message_id.map(|id| id.to_string()),
                    serde_json::to_string(&content.to_addresses)?,
                    serde_json::to_string(&content.cc_addresses)?,
                    serde_json::to_string(&content.bcc_addresses)?,
                    content.subject,
                    content.body_text,
                    content.body_html,
                    content.in_reply_to,
                    serde_json::to_string(&content.references)?,
                    now,
                    id.to_string(),
                    i64::from(expected_revision),
                ],
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "draft changed, was queued, or no longer exists".into(),
            ));
        }
        let revision = expected_revision.saturating_add(1);
        let event = insert_event(
            &transaction,
            now,
            "draft_saved",
            id.to_string(),
            json!({"draft_id": id, "revision": revision}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn add_attachment<R: AsyncRead + Unpin>(
        &self,
        id: DraftId,
        expected_revision: u32,
        mut attachment: NewDraftAttachment,
        reader: &mut R,
        limits: SendingLimits,
    ) -> Result<Draft> {
        validate_sending_limits(&limits)?;
        validate_attachment(&attachment)?;
        if attachment.disposition == DraftAttachmentDisposition::Inline
            && attachment.content_id.is_none()
        {
            attachment.content_id = Some(format!("{}@lizard.local", Uuid::new_v4()));
        }
        let (blob_hash, size_bytes) = self
            .0
            .inner
            .blobs
            .put_reader(reader, limits.max_attachment_bytes)
            .await?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT COALESCE(SUM(size_bytes), 0), COALESCE(MAX(ordinal), -1), COUNT(*) FROM draft_attachments WHERE draft_id = ?1",
                (id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.expect("aggregate query returns one row");
        let total = u64::try_from(row.get::<i64>(0)?)
            .map_err(|_| BackendError::InvalidInput("invalid attachment total".into()))?;
        let ordinal = row.get::<i64>(1)?.saturating_add(1);
        let count = usize::try_from(row.get::<i64>(2)?)
            .map_err(|_| BackendError::InvalidInput("invalid attachment count".into()))?;
        drop(rows);
        if count >= limits.max_attachments {
            transaction.rollback().await?;
            return Err(BackendError::InvalidInput(
                "draft exceeds configured attachment-count limit".into(),
            ));
        }
        if total.saturating_add(size_bytes) > limits.max_total_attachment_bytes {
            transaction.rollback().await?;
            return Err(BackendError::InvalidInput(
                "draft attachments exceed configured total size limit".into(),
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE drafts SET revision = revision + 1, updated_at = ?1 WHERE id = ?2 AND revision = ?3 AND status = 'editing'",
                (now, id.to_string(), i64::from(expected_revision)),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "draft changed, was queued, or no longer exists".into(),
            ));
        }
        let attachment_id = DraftAttachmentId::new();
        transaction
            .execute(
                "INSERT INTO draft_attachments(id, draft_id, ordinal, name, media_type, disposition, content_id, blob_hash, size_bytes, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                turso::params![
                    attachment_id.to_string(),
                    id.to_string(),
                    ordinal,
                    attachment.name,
                    attachment.media_type,
                    disposition_text(attachment.disposition),
                    attachment.content_id,
                    blob_hash,
                    size_bytes as i64,
                    now,
                ],
            )
            .await?;
        let revision = expected_revision.saturating_add(1);
        let event = insert_event(
            &transaction,
            now,
            "draft_attachment_added",
            id.to_string(),
            json!({"draft_id": id, "attachment_id": attachment_id, "revision": revision}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn remove_attachment(
        &self,
        id: DraftId,
        expected_revision: u32,
        attachment_id: DraftAttachmentId,
    ) -> Result<Draft> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE drafts SET revision = revision + 1, updated_at = ?1 WHERE id = ?2 AND revision = ?3 AND status = 'editing'",
                (now, id.to_string(), i64::from(expected_revision)),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "draft changed, was queued, or no longer exists".into(),
            ));
        }
        let removed = transaction
            .execute(
                "DELETE FROM draft_attachments WHERE id = ?1 AND draft_id = ?2",
                (attachment_id.to_string(), id.to_string()),
            )
            .await?;
        if removed != 1 {
            transaction.rollback().await?;
            return Err(not_found("draft attachment", attachment_id));
        }
        let revision = expected_revision.saturating_add(1);
        let event = insert_event(
            &transaction,
            now,
            "draft_attachment_removed",
            id.to_string(),
            json!({"draft_id": id, "attachment_id": attachment_id, "revision": revision}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn delete(&self, id: DraftId, expected_revision: u32) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "DELETE FROM drafts WHERE id = ?1 AND revision = ?2 AND status = 'editing'",
                (id.to_string(), i64::from(expected_revision)),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "only the current revision of an editing draft can be deleted".into(),
            ));
        }
        let event = insert_event(
            &transaction,
            now,
            "draft_deleted",
            id.to_string(),
            json!({"draft_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Outbox(Backend);

impl Outbox {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn enqueue(
        &self,
        draft_id: DraftId,
        expected_revision: u32,
        limits: SendingLimits,
    ) -> Result<Submission> {
        validate_sending_limits(&limits)?;
        let draft = self.0.drafts().get(draft_id).await?;
        if draft.revision != expected_revision || draft.status != DraftStatus::Editing {
            return Err(BackendError::Conflict(
                "draft changed or is no longer editable".into(),
            ));
        }
        if draft.attachments.len() > limits.max_attachments
            || draft
                .attachments
                .iter()
                .any(|attachment| attachment.size_bytes > limits.max_attachment_bytes)
            || draft
                .attachments
                .iter()
                .map(|attachment| attachment.size_bytes)
                .try_fold(0u64, u64::checked_add)
                .is_none_or(|total| total > limits.max_total_attachment_bytes)
        {
            return Err(BackendError::InvalidInput(
                "draft attachments exceed configured sending limits".into(),
            ));
        }
        if draft.content.to_addresses.is_empty()
            && draft.content.cc_addresses.is_empty()
            && draft.content.bcc_addresses.is_empty()
        {
            return Err(BackendError::InvalidInput(
                "a submission requires at least one recipient".into(),
            ));
        }
        let smtp = self
            .0
            .sending()
            .smtp_account(draft.content.account_id)
            .await?;
        let rfc_message_id = make_message_id(&smtp.settings.username)?;
        let raw = build_message(&self.0, &draft, &smtp, &rfc_message_id).await?;
        if raw.len() as u64 > limits.max_message_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: raw.len(),
                limit: usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX),
            });
        }
        let raw_blob_hash = self.0.inner.blobs.put(&raw).await?;
        let recipients = envelope_recipients(&draft.content);
        let now = Utc::now().timestamp();
        let submission = Submission {
            id: SubmissionId::new(),
            draft_id,
            account_id: draft.content.account_id,
            rfc_message_id,
            status: SubmissionStatus::Pending,
            attempts: 0,
            next_attempt_at: Some(now),
            last_error: None,
            smtp_response: None,
            sent_message_id: None,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE drafts SET status = 'queued', updated_at = ?1 WHERE id = ?2 AND revision = ?3 AND status = 'editing'",
                (now, draft_id.to_string(), i64::from(expected_revision)),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "draft changed while its MIME snapshot was being built".into(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO submissions(id, draft_id, account_id, rfc_message_id, envelope_from, recipients_json, raw_blob_hash, raw_size_bytes, status, attempts, next_attempt_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?9, ?9)",
                turso::params![
                    submission.id.to_string(),
                    draft_id.to_string(),
                    submission.account_id.to_string(),
                    submission.rfc_message_id.clone(),
                    smtp.settings.username,
                    serde_json::to_string(&recipients)?,
                    raw_blob_hash,
                    raw.len() as i64,
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "submission_enqueued",
            submission.id.to_string(),
            json!({"submission_id": submission.id, "draft_id": draft_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(submission)
    }

    pub async fn get(&self, id: SubmissionId) -> Result<Submission> {
        let connection = self.0.inner.connection.lock().await;
        load_submission_on(&connection, id).await
    }

    pub async fn list(&self) -> Result<Vec<Submission>> {
        let ids = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT id FROM submissions ORDER BY created_at DESC, id",
                    (),
                )
                .await?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next().await? {
                ids.push(parse_id(row.get::<String>(0)?, "submission")?);
            }
            ids
        };
        let mut values = Vec::with_capacity(ids.len());
        for id in ids {
            values.push(self.get(id).await?);
        }
        Ok(values)
    }

    pub async fn cancel(&self, id: SubmissionId) -> Result<Submission> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE submissions SET status = 'cancelled', next_attempt_at = NULL, updated_at = ?1, completed_at = ?1 WHERE id = ?2 AND status IN ('pending', 'retry_scheduled', 'failed')",
                (now, id.to_string()),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "in-flight, sent, ambiguous, or already-cancelled submission cannot be cancelled"
                    .into(),
            ));
        }
        transaction
            .execute(
                "UPDATE drafts SET status = 'cancelled', updated_at = ?1 WHERE id = (SELECT draft_id FROM submissions WHERE id = ?2)",
                (now, id.to_string()),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "submission_cancelled",
            id.to_string(),
            json!({"submission_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn retry(&self, id: SubmissionId) -> Result<Submission> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE submissions SET status = 'pending', next_attempt_at = ?1, last_error = NULL, updated_at = ?1, completed_at = NULL WHERE id = ?2 AND status = 'failed'",
                (now, id.to_string()),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "only a definite permanent failure can be explicitly retried".into(),
            ));
        }
        let event = insert_event(
            &transaction,
            now,
            "submission_retried",
            id.to_string(),
            json!({"submission_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub(crate) async fn due(&self, limit: usize) -> Result<Vec<SubmissionId>> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id FROM submissions WHERE status IN ('pending', 'retry_scheduled') AND next_attempt_at <= ?1 ORDER BY next_attempt_at, created_at, id LIMIT ?2",
                (now, limit as i64),
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_id(row.get::<String>(0)?, "submission")?);
        }
        Ok(ids)
    }

    pub(crate) async fn begin(
        &self,
        id: SubmissionId,
    ) -> Result<(Submission, Vec<u8>, Vec<String>, String)> {
        let now = Utc::now().timestamp();
        let (hash, recipients, envelope_from, event) = {
            let mut connection = self.0.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            let changed = transaction
                .execute(
                    "UPDATE submissions SET status = 'in_flight', attempts = attempts + 1, next_attempt_at = NULL, updated_at = ?1 WHERE id = ?2 AND status IN ('pending', 'retry_scheduled')",
                    (now, id.to_string()),
                )
                .await?;
            if changed != 1 {
                transaction.rollback().await?;
                return Err(BackendError::Conflict("submission is no longer due".into()));
            }
            let mut rows = transaction
                .query(
                    "SELECT raw_blob_hash, recipients_json, envelope_from FROM submissions WHERE id = ?1",
                    (id.to_string(),),
                )
                .await?;
            let row = rows.next().await?.expect("updated submission exists");
            let values = (
                row.get::<String>(0)?,
                serde_json::from_str(&row.get::<String>(1)?)?,
                row.get::<String>(2)?,
            );
            drop(rows);
            let event = insert_event(
                &transaction,
                now,
                "submission_in_flight",
                id.to_string(),
                json!({"submission_id": id}),
            )
            .await?;
            transaction.commit().await?;
            (values.0, values.1, values.2, event)
        };
        let _ = self.0.inner.events.send(event);
        let raw = match self.0.inner.blobs.get(&hash).await {
            Ok(raw) => raw,
            Err(error) => {
                self.mark_failed(
                    id,
                    SubmissionStatus::Failed,
                    format!("durable outbox payload could not be read: {error}"),
                    None,
                )
                .await?;
                return Err(error);
            }
        };
        Ok((self.get(id).await?, raw, recipients, envelope_from))
    }

    pub(crate) async fn mark_retry(
        &self,
        id: SubmissionId,
        error: String,
        delay_seconds: i64,
        response: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE submissions SET status = 'retry_scheduled', next_attempt_at = ?1, last_error = ?2, smtp_response = ?3, updated_at = ?4 WHERE id = ?5 AND status = 'in_flight'",
                (
                    now.saturating_add(delay_seconds),
                    error,
                    response,
                    now,
                    id.to_string(),
                ),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "in-flight submission changed before retry was recorded".into(),
            ));
        }
        let event = insert_event(
            &transaction,
            now,
            "submission_retry_scheduled",
            id.to_string(),
            json!({"submission_id": id, "next_attempt_at": now.saturating_add(delay_seconds)}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub(crate) async fn mark_failed(
        &self,
        id: SubmissionId,
        status: SubmissionStatus,
        error: String,
        response: Option<String>,
    ) -> Result<()> {
        let status_text = match status {
            SubmissionStatus::Failed => "failed",
            SubmissionStatus::Ambiguous => "ambiguous",
            _ => {
                return Err(BackendError::InvalidInput(
                    "invalid terminal submission status".into(),
                ))
            }
        };
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE submissions SET status = ?1, last_error = ?2, smtp_response = ?3, next_attempt_at = NULL, updated_at = ?4, completed_at = ?4 WHERE id = ?5 AND status = 'in_flight'",
                (status_text, error, response, now, id.to_string()),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "in-flight submission changed before failure was recorded".into(),
            ));
        }
        let event = insert_event(
            &transaction,
            now,
            if status == SubmissionStatus::Ambiguous {
                "submission_ambiguous"
            } else {
                "submission_failed"
            },
            id.to_string(),
            json!({"submission_id": id, "status": status}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub(crate) async fn mark_sent(
        &self,
        id: SubmissionId,
        raw: Vec<u8>,
        response: String,
    ) -> Result<()> {
        let message_id = self.0.ingest(IngestMessage::local(raw)).await?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE submissions SET status = 'sent', smtp_response = ?1, sent_message_id = ?2, last_error = NULL, updated_at = ?3, completed_at = ?3 WHERE id = ?4 AND status = 'in_flight'",
                (response, message_id.to_string(), now, id.to_string()),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "submission changed after SMTP accepted it".into(),
            ));
        }
        transaction
            .execute(
                "UPDATE drafts SET status = 'sent', updated_at = ?1 WHERE id = (SELECT draft_id FROM submissions WHERE id = ?2)",
                (now, id.to_string()),
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO sent_reconciliation(rfc_message_id, blob_hash, message_id, submission_id, account_id) SELECT rfc_message_id, raw_blob_hash, ?1, id, account_id FROM submissions WHERE id = ?2",
                (message_id.to_string(), id.to_string()),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "submission_sent",
            id.to_string(),
            json!({"submission_id": id, "message_id": message_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub(crate) async fn recover_inflight(&self) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query("SELECT id FROM submissions WHERE status = 'in_flight'", ())
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_id::<SubmissionId>(row.get(0)?, "submission")?);
        }
        drop(rows);
        transaction
            .execute(
                "UPDATE submissions SET status = 'ambiguous', last_error = 'application stopped while SMTP delivery was in flight; automatic retry is unsafe', updated_at = ?1, completed_at = ?1 WHERE status = 'in_flight'",
                (now,),
            )
            .await?;
        let mut events = Vec::with_capacity(ids.len());
        for id in ids {
            events.push(
                insert_event(
                    &transaction,
                    now,
                    "submission_ambiguous",
                    id.to_string(),
                    json!({"submission_id": id, "reason": "interrupted"}),
                )
                .await?,
            );
        }
        transaction.commit().await?;
        drop(connection);
        for event in events {
            let _ = self.0.inner.events.send(event);
        }
        Ok(())
    }
}

async fn build_message(
    backend: &Backend,
    draft: &Draft,
    smtp: &SmtpAccount,
    rfc_message_id: &str,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    header(&mut output, "From", &smtp.settings.username)?;
    if !draft.content.to_addresses.is_empty() {
        header(&mut output, "To", &draft.content.to_addresses.join(", "))?;
    }
    if !draft.content.cc_addresses.is_empty() {
        header(&mut output, "Cc", &draft.content.cc_addresses.join(", "))?;
    }
    header(
        &mut output,
        "Subject",
        &encode_unstructured(&draft.content.subject),
    )?;
    header(&mut output, "Date", &Utc::now().to_rfc2822())?;
    header(&mut output, "Message-ID", &format!("<{rfc_message_id}>"))?;
    if let Some(parent) = draft.content.in_reply_to.as_deref() {
        header(&mut output, "In-Reply-To", &format!("<{parent}>"))?;
    }
    if !draft.content.references.is_empty() {
        header(
            &mut output,
            "References",
            &draft
                .content
                .references
                .iter()
                .map(|value| format!("<{value}>"))
                .collect::<Vec<_>>()
                .join(" "),
        )?;
    }
    header(&mut output, "MIME-Version", "1.0")?;

    let inline = draft
        .attachments
        .iter()
        .filter(|item| item.disposition == DraftAttachmentDisposition::Inline)
        .collect::<Vec<_>>();
    let regular = draft
        .attachments
        .iter()
        .filter(|item| item.disposition == DraftAttachmentDisposition::Attachment)
        .collect::<Vec<_>>();
    let mixed_boundary = format!("lizard-mixed-{}", Uuid::new_v4());
    let related_boundary = format!("lizard-related-{}", Uuid::new_v4());
    if !regular.is_empty() {
        header(
            &mut output,
            "Content-Type",
            &format!("multipart/mixed; boundary=\"{mixed_boundary}\""),
        )?;
        output.extend_from_slice(b"\r\n");
        boundary(&mut output, &mixed_boundary, false);
    }
    if !inline.is_empty() {
        header(
            &mut output,
            "Content-Type",
            &format!("multipart/related; boundary=\"{related_boundary}\""),
        )?;
        output.extend_from_slice(b"\r\n");
        boundary(&mut output, &related_boundary, false);
    }
    write_body(
        &mut output,
        &draft.content.body_text,
        draft.content.body_html.as_deref(),
    )?;
    for attachment in inline {
        boundary(&mut output, &related_boundary, false);
        write_attachment(backend, &mut output, attachment).await?;
    }
    if !draft
        .attachments
        .iter()
        .filter(|item| item.disposition == DraftAttachmentDisposition::Inline)
        .collect::<Vec<_>>()
        .is_empty()
    {
        boundary(&mut output, &related_boundary, true);
    }
    for attachment in regular {
        boundary(&mut output, &mixed_boundary, false);
        write_attachment(backend, &mut output, attachment).await?;
    }
    if draft
        .attachments
        .iter()
        .any(|item| item.disposition == DraftAttachmentDisposition::Attachment)
    {
        boundary(&mut output, &mixed_boundary, true);
    }
    Ok(output)
}

fn write_body(output: &mut Vec<u8>, text: &str, html: Option<&str>) -> Result<()> {
    if let Some(html) = html {
        let boundary_value = format!("lizard-alternative-{}", Uuid::new_v4());
        header(
            output,
            "Content-Type",
            &format!("multipart/alternative; boundary=\"{boundary_value}\""),
        )?;
        output.extend_from_slice(b"\r\n");
        boundary(output, &boundary_value, false);
        write_text_part(output, "text/plain; charset=utf-8", text)?;
        boundary(output, &boundary_value, false);
        write_text_part(output, "text/html; charset=utf-8", html)?;
        boundary(output, &boundary_value, true);
    } else {
        write_text_part(output, "text/plain; charset=utf-8", text)?;
    }
    Ok(())
}

fn write_text_part(output: &mut Vec<u8>, media_type: &str, value: &str) -> Result<()> {
    header(output, "Content-Type", media_type)?;
    header(output, "Content-Transfer-Encoding", "base64")?;
    output.extend_from_slice(b"\r\n");
    write_base64(output, value.as_bytes());
    Ok(())
}

async fn write_attachment(
    backend: &Backend,
    output: &mut Vec<u8>,
    attachment: &DraftAttachment,
) -> Result<()> {
    let hash = {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT blob_hash FROM draft_attachments WHERE id = ?1",
                (attachment.id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .ok_or_else(|| not_found("draft attachment", attachment.id))?
            .get::<String>(0)?
    };
    let bytes = backend.inner.blobs.get(&hash).await?;
    header(
        output,
        "Content-Type",
        &format!(
            "{}; name*=UTF-8''{}",
            attachment.media_type,
            percent_encode(&attachment.name)
        ),
    )?;
    header(output, "Content-Transfer-Encoding", "base64")?;
    header(
        output,
        "Content-Disposition",
        &format!(
            "{}; filename*=UTF-8''{}",
            disposition_text(attachment.disposition),
            percent_encode(&attachment.name)
        ),
    )?;
    if let Some(content_id) = attachment.content_id.as_deref() {
        header(output, "Content-ID", &format!("<{content_id}>"))?;
    }
    output.extend_from_slice(b"\r\n");
    write_base64(output, &bytes);
    Ok(())
}

fn write_base64(output: &mut Vec<u8>, bytes: &[u8]) {
    let encoded = STANDARD.encode(bytes);
    for chunk in encoded.as_bytes().chunks(76) {
        output.extend_from_slice(chunk);
        output.extend_from_slice(b"\r\n");
    }
}

fn boundary(output: &mut Vec<u8>, value: &str, close: bool) {
    output.extend_from_slice(b"--");
    output.extend_from_slice(value.as_bytes());
    if close {
        output.extend_from_slice(b"--");
    }
    output.extend_from_slice(b"\r\n");
}

fn header(output: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    require_header_value(name, value)?;
    // RFC 5322's hard limit includes the field name, colon, and separating
    // whitespace. Reject rather than emit an invalid or ambiguously folded
    // attacker-influenced header.
    if name.len().saturating_add(2).saturating_add(value.len()) > 998 {
        return Err(BackendError::InvalidInput(format!(
            "{name} header exceeds the RFC 5322 line limit"
        )));
    }
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
    Ok(())
}

fn encode_unstructured(value: &str) -> String {
    if value.is_ascii() {
        value.to_owned()
    } else {
        format!("=?UTF-8?B?{}?=", STANDARD.encode(value.as_bytes()))
    }
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn envelope_recipients(content: &DraftContent) -> Vec<String> {
    let mut recipients = Vec::new();
    let mut seen = HashSet::new();
    for address in content
        .to_addresses
        .iter()
        .chain(&content.cc_addresses)
        .chain(&content.bcc_addresses)
    {
        if seen.insert(address.to_lowercase()) {
            recipients.push(address.clone());
        }
    }
    recipients
}

fn make_message_id(from: &str) -> Result<String> {
    let domain = from
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| {
            BackendError::InvalidInput("SMTP username must be an email address".into())
        })?;
    Ok(format!(
        "{}@{}",
        Uuid::new_v4(),
        domain.to_ascii_lowercase()
    ))
}

fn validate_draft_content(content: &DraftContent) -> Result<()> {
    for address in content
        .to_addresses
        .iter()
        .chain(&content.cc_addresses)
        .chain(&content.bcc_addresses)
    {
        validate_address(address)?;
    }
    require_header_value("subject", &content.subject)?;
    if content.subject.len() > 998 || content.body_text.len() > 16 * 1024 * 1024 {
        return Err(BackendError::InvalidInput(
            "draft subject or text body exceeds configured structural limit".into(),
        ));
    }
    if content
        .body_html
        .as_ref()
        .is_some_and(|html| html.len() > 16 * 1024 * 1024)
    {
        return Err(BackendError::InvalidInput(
            "draft HTML body exceeds configured structural limit".into(),
        ));
    }
    if let Some(value) = content.in_reply_to.as_deref() {
        validate_message_id(value)?;
    }
    if content.references.len() > 100 {
        return Err(BackendError::InvalidInput(
            "draft References chain exceeds 100 identifiers".into(),
        ));
    }
    for value in &content.references {
        validate_message_id(value)?;
    }
    Ok(())
}

fn validate_attachment(value: &NewDraftAttachment) -> Result<()> {
    require_header_value("attachment name", &value.name)?;
    if value.name.is_empty() || value.name.len() > 255 {
        return Err(BackendError::InvalidInput(
            "attachment name must contain 1 to 255 bytes".into(),
        ));
    }
    validate_media_type(&value.media_type)?;
    if let Some(content_id) = value.content_id.as_deref() {
        validate_message_id(content_id)?;
    }
    Ok(())
}

fn validate_smtp_settings(settings: &SmtpSettings) -> Result<()> {
    if settings.host.trim().is_empty()
        || settings.host.chars().any(char::is_whitespace)
        || settings.port == 0
    {
        return Err(BackendError::InvalidInput(
            "SMTP host and port must be valid".into(),
        ));
    }
    validate_address(&settings.username)
}

fn validate_sending_limits(limits: &SendingLimits) -> Result<()> {
    if limits.max_attachments == 0
        || limits.max_attachments > 10_000
        || limits.max_attachment_bytes == 0
        || limits.max_total_attachment_bytes < limits.max_attachment_bytes
        || limits.max_message_bytes == 0
        || limits.max_attachment_bytes > i64::MAX as u64
        || limits.max_total_attachment_bytes > i64::MAX as u64
        || limits.max_message_bytes > i64::MAX as u64
    {
        return Err(BackendError::InvalidInput(
            "sending limits must be positive and ordered".into(),
        ));
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<()> {
    require_header_value("address", value)?;
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or_else(|| BackendError::InvalidInput(format!("invalid email address {value:?}")))?;
    if local.is_empty()
        || domain.is_empty()
        || value.contains(['<', '>', ',', ' '])
        || value.len() > 320
    {
        return Err(BackendError::InvalidInput(format!(
            "invalid email address {value:?}"
        )));
    }
    Ok(())
}

fn validate_message_id(value: &str) -> Result<()> {
    require_header_value("message identifier", value)?;
    if value.is_empty()
        || value.len() > 512
        || value.contains(['<', '>', ' '])
        || !value.contains('@')
    {
        return Err(BackendError::InvalidInput(
            "invalid RFC message identifier".into(),
        ));
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<()> {
    require_header_value("media type", value)?;
    let (type_, subtype) = value.split_once('/').ok_or_else(|| {
        BackendError::InvalidInput("attachment media type must be type/subtype".into())
    })?;
    if type_.is_empty()
        || subtype.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&byte))
    {
        return Err(BackendError::InvalidInput(
            "attachment media type contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn require_header_value(name: &str, value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        return Err(BackendError::InvalidInput(format!(
            "{name} contains a forbidden control character"
        )));
    }
    Ok(())
}

async fn insert_draft_on(connection: &Connection, draft: &Draft) -> Result<()> {
    connection
        .execute(
            "INSERT INTO drafts(id, account_id, revision, status, thread_id, parent_message_id, to_addresses, cc_addresses, bcc_addresses, subject, body_text, body_html, in_reply_to, references_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            turso::params![
                draft.id.to_string(),
                draft.content.account_id.to_string(),
                i64::from(draft.revision),
                draft_status_text(draft.status),
                draft.content.thread_id.to_string(),
                draft.content.parent_message_id.map(|id| id.to_string()),
                serde_json::to_string(&draft.content.to_addresses)?,
                serde_json::to_string(&draft.content.cc_addresses)?,
                serde_json::to_string(&draft.content.bcc_addresses)?,
                draft.content.subject.clone(),
                draft.content.body_text.clone(),
                draft.content.body_html.clone(),
                draft.content.in_reply_to.clone(),
                serde_json::to_string(&draft.content.references)?,
                draft.created_at,
                draft.updated_at,
            ],
        )
        .await?;
    Ok(())
}

async fn load_draft_on(connection: &Connection, id: DraftId) -> Result<Draft> {
    let mut rows = connection
        .query(
            "SELECT account_id, revision, status, thread_id, parent_message_id, to_addresses, cc_addresses, bcc_addresses, subject, body_text, body_html, in_reply_to, references_json, created_at, updated_at FROM drafts WHERE id = ?1",
            (id.to_string(),),
        )
        .await?;
    let row = rows.next().await?.ok_or_else(|| not_found("draft", id))?;
    let content = DraftContent {
        account_id: parse_id(row.get::<String>(0)?, "account")?,
        thread_id: parse_id(row.get::<String>(3)?, "thread")?,
        parent_message_id: row
            .get::<Option<String>>(4)?
            .map(|value| parse_id(value, "message"))
            .transpose()?,
        to_addresses: serde_json::from_str(&row.get::<String>(5)?)?,
        cc_addresses: serde_json::from_str(&row.get::<String>(6)?)?,
        bcc_addresses: serde_json::from_str(&row.get::<String>(7)?)?,
        subject: row.get(8)?,
        body_text: row.get(9)?,
        body_html: row.get(10)?,
        in_reply_to: row.get(11)?,
        references: serde_json::from_str(&row.get::<String>(12)?)?,
    };
    let revision = u32::try_from(row.get::<i64>(1)?)
        .map_err(|_| BackendError::InvalidInput("invalid draft revision".into()))?;
    let status = parse_draft_status(&row.get::<String>(2)?)?;
    let created_at = row.get(13)?;
    let updated_at = row.get(14)?;
    drop(rows);
    let mut rows = connection
        .query(
            "SELECT id, ordinal, name, media_type, disposition, content_id, size_bytes FROM draft_attachments WHERE draft_id = ?1 ORDER BY ordinal",
            (id.to_string(),),
        )
        .await?;
    let mut attachments = Vec::new();
    while let Some(row) = rows.next().await? {
        attachments.push(DraftAttachment {
            id: parse_id(row.get::<String>(0)?, "draft attachment")?,
            ordinal: u32::try_from(row.get::<i64>(1)?)
                .map_err(|_| BackendError::InvalidInput("invalid attachment ordinal".into()))?,
            name: row.get(2)?,
            media_type: row.get(3)?,
            disposition: parse_disposition(&row.get::<String>(4)?)?,
            content_id: row.get(5)?,
            size_bytes: u64::try_from(row.get::<i64>(6)?)
                .map_err(|_| BackendError::InvalidInput("invalid attachment size".into()))?,
        });
    }
    Ok(Draft {
        id,
        revision,
        status,
        content,
        attachments,
        created_at,
        updated_at,
    })
}

pub(crate) async fn load_smtp_account_on(
    connection: &Connection,
    account_id: AccountId,
) -> Result<SmtpAccount> {
    let mut rows = connection
        .query(
            "SELECT settings_json, credential_ref, updated_at FROM smtp_accounts WHERE account_id = ?1",
            (account_id.to_string(),),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| not_found("SMTP account", account_id))?;
    Ok(SmtpAccount {
        account_id,
        settings: serde_json::from_str(&row.get::<String>(0)?)?,
        credential_ref: row.get(1)?,
        updated_at: row.get(2)?,
    })
}

async fn load_submission_on(connection: &Connection, id: SubmissionId) -> Result<Submission> {
    let mut rows = connection
        .query(
            "SELECT draft_id, account_id, rfc_message_id, status, attempts, next_attempt_at, last_error, smtp_response, sent_message_id, created_at, updated_at, completed_at FROM submissions WHERE id = ?1",
            (id.to_string(),),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| not_found("submission", id))?;
    Ok(Submission {
        id,
        draft_id: parse_id(row.get::<String>(0)?, "draft")?,
        account_id: parse_id(row.get::<String>(1)?, "account")?,
        rfc_message_id: row.get(2)?,
        status: parse_submission_status(&row.get::<String>(3)?)?,
        attempts: u32::try_from(row.get::<i64>(4)?)
            .map_err(|_| BackendError::InvalidInput("invalid submission attempt count".into()))?,
        next_attempt_at: row.get(5)?,
        last_error: row.get(6)?,
        smtp_response: row.get(7)?,
        sent_message_id: row
            .get::<Option<String>>(8)?
            .map(|value| parse_id(value, "message"))
            .transpose()?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        completed_at: row.get(11)?,
    })
}

fn draft_status_text(value: DraftStatus) -> &'static str {
    match value {
        DraftStatus::Editing => "editing",
        DraftStatus::Queued => "queued",
        DraftStatus::Sent => "sent",
        DraftStatus::Cancelled => "cancelled",
    }
}

fn parse_draft_status(value: &str) -> Result<DraftStatus> {
    match value {
        "editing" => Ok(DraftStatus::Editing),
        "queued" => Ok(DraftStatus::Queued),
        "sent" => Ok(DraftStatus::Sent),
        "cancelled" => Ok(DraftStatus::Cancelled),
        _ => Err(BackendError::InvalidInput("invalid draft status".into())),
    }
}

fn parse_submission_status(value: &str) -> Result<SubmissionStatus> {
    match value {
        "pending" => Ok(SubmissionStatus::Pending),
        "in_flight" => Ok(SubmissionStatus::InFlight),
        "retry_scheduled" => Ok(SubmissionStatus::RetryScheduled),
        "sent" => Ok(SubmissionStatus::Sent),
        "failed" => Ok(SubmissionStatus::Failed),
        "ambiguous" => Ok(SubmissionStatus::Ambiguous),
        "cancelled" => Ok(SubmissionStatus::Cancelled),
        _ => Err(BackendError::InvalidInput(
            "invalid submission status".into(),
        )),
    }
}

fn disposition_text(value: DraftAttachmentDisposition) -> &'static str {
    match value {
        DraftAttachmentDisposition::Attachment => "attachment",
        DraftAttachmentDisposition::Inline => "inline",
    }
}

fn parse_disposition(value: &str) -> Result<DraftAttachmentDisposition> {
    match value {
        "attachment" => Ok(DraftAttachmentDisposition::Attachment),
        "inline" => Ok(DraftAttachmentDisposition::Inline),
        _ => Err(BackendError::InvalidInput(
            "invalid draft attachment disposition".into(),
        )),
    }
}

fn parse_id<T: FromStr>(value: String, entity: &'static str) -> Result<T> {
    value.parse().map_err(|_| {
        BackendError::InvalidInput(format!("database contains invalid {entity} identifier"))
    })
}

fn not_found(entity: &'static str, id: impl ToString) -> BackendError {
    BackendError::NotFound {
        entity,
        id: id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountKind, FolderKind, ImapSecurity, ImapSettings, MessageFilter, NewAccount, NewFolder,
        RemoteMessageIdentity, SmtpAuthMethod, SmtpSecurity, ThreadId,
    };

    #[tokio::test]
    async fn reconciles_server_sent_copy_by_protected_message_id() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(crate::BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let account = backend
            .accounts()
            .add(NewAccount {
                name: "Sent reconciliation".into(),
                kind: AccountKind::Imap,
                credential_ref: Some("test-only:imap".into()),
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "sender@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        backend
            .sending()
            .configure_smtp(
                account.id,
                crate::SmtpSettings {
                    host: "smtp.example.test".into(),
                    port: 465,
                    username: "sender@example.test".into(),
                    security: SmtpSecurity::ImplicitTls,
                    auth: SmtpAuthMethod::Password,
                },
                "test-only:smtp".into(),
            )
            .await
            .unwrap();
        let sent_folder = backend
            .folders()
            .add(NewFolder {
                account_id: Some(account.id),
                name: "Sent".into(),
                kind: FolderKind::Remote,
                remote_name: Some("Sent".into()),
            })
            .await
            .unwrap();
        {
            let connection = backend.inner.connection.lock().await;
            connection
                .execute(
                    "INSERT INTO imap_mailbox_state(folder_id, attributes_json) VALUES (?1, ?2)",
                    (sent_folder.id.to_string(), r#"["\\Sent"]"#),
                )
                .await
                .unwrap();
        }
        let draft = backend
            .drafts()
            .create(DraftContent {
                account_id: account.id,
                thread_id: ThreadId::new(),
                parent_message_id: None,
                to_addresses: vec!["reader@example.test".into()],
                cc_addresses: Vec::new(),
                bcc_addresses: Vec::new(),
                subject: "one logical sent message".into(),
                body_text: "body".into(),
                body_html: None,
                in_reply_to: None,
                references: Vec::new(),
            })
            .await
            .unwrap();
        let submission = backend
            .outbox()
            .enqueue(draft.id, draft.revision, SendingLimits::default())
            .await
            .unwrap();
        let (_, raw, _, _) = backend.outbox().begin(submission.id).await.unwrap();
        backend
            .outbox()
            .mark_sent(submission.id, raw.clone(), "250 accepted".into())
            .await
            .unwrap();
        let local_id = backend
            .outbox()
            .get(submission.id)
            .await
            .unwrap()
            .sent_message_id
            .unwrap();

        // A server may add transport headers before placing its copy in Sent,
        // so blob identity alone cannot perform this reconciliation.
        let mut server_copy = b"Received: by fixture.example.test\r\n".to_vec();
        server_copy.extend_from_slice(&raw);
        let reconciled = backend
            .messages()
            .ingest(crate::IngestMessage {
                raw: server_copy,
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: sent_folder.id,
                    uid_validity: 7,
                    uid: 42,
                    mod_sequence: Some(9),
                    flags: vec!["\\Seen".into()],
                }),
                received_at: None,
                user_classification: None,
            })
            .await
            .unwrap();
        assert_eq!(reconciled, local_id);
        let stored = backend.messages().get(local_id).await.unwrap();
        assert_eq!(stored.instances.len(), 1);
        assert_eq!(stored.instances[0].folder_id, sent_folder.id);
        assert_eq!(
            backend
                .messages()
                .list(MessageFilter::default())
                .await
                .unwrap()
                .items
                .len(),
            1
        );

        let interrupted_draft = backend
            .drafts()
            .create(DraftContent {
                account_id: account.id,
                thread_id: ThreadId::new(),
                parent_message_id: None,
                to_addresses: vec!["reader@example.test".into()],
                cc_addresses: Vec::new(),
                bcc_addresses: Vec::new(),
                subject: "interrupted delivery".into(),
                body_text: "body".into(),
                body_html: None,
                in_reply_to: None,
                references: Vec::new(),
            })
            .await
            .unwrap();
        let interrupted = backend
            .outbox()
            .enqueue(
                interrupted_draft.id,
                interrupted_draft.revision,
                SendingLimits::default(),
            )
            .await
            .unwrap();
        backend.outbox().begin(interrupted.id).await.unwrap();
        backend.outbox().recover_inflight().await.unwrap();
        assert_eq!(
            backend.outbox().get(interrupted.id).await.unwrap().status,
            SubmissionStatus::Ambiguous
        );
        assert!(backend.outbox().due(10).await.unwrap().is_empty());
    }
}
