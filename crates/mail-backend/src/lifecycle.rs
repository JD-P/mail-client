use crate::backend::{enqueue_search_on, insert_event};
use crate::{
    AccountBodyPolicy, AccountId, Backend, BackendError, BodyRetentionPolicy, BodyRetentionReport,
    FolderId, IngestMessage, MailExportFormat, MailExportReport, MailImportReport, MailSelection,
    MailTransferLimits, MessageId, OfflineDownloadPolicy, OfflineDownloadProgress,
    ProfileBackupReport, ProfileRestoreReport, Result,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use turso::{params_from_iter, Value};

const EXPORT_MANIFEST: &str = ".lizard-mail-export.json";
const BACKUP_MANIFEST: &str = "profile-backup.json";
const TRANSFER_BATCH: usize = 64;
pub(crate) const MAX_OFFLINE_BATCH: usize = 10_000;

#[derive(Clone)]
pub struct DataLifecycle(Backend);

#[derive(Clone)]
struct ExportRow {
    id: MessageId,
    blob_hash: String,
    received_at: i64,
    is_read: bool,
    is_starred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PortableManifest {
    version: u32,
    format: MailExportFormat,
    entries: Vec<PortableEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PortableEntry {
    file: Option<String>,
    raw_bytes: u64,
    sha256: String,
    received_at: i64,
    is_read: bool,
    is_starred: bool,
}

struct ImportedMessage {
    raw: Vec<u8>,
    received_at: Option<i64>,
    is_read: bool,
    is_starred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProfileManifest {
    version: u32,
    created_at: i64,
    schema_version: i64,
    native_credential_references: u64,
    files: Vec<ProfileFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProfileFile {
    path: String,
    bytes: u64,
    sha256: String,
}

impl DataLifecycle {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn body_policy(&self, account_id: AccountId) -> Result<AccountBodyPolicy> {
        self.0.accounts().get(account_id).await?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT policy_json, updated_at FROM account_body_policies WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(AccountBodyPolicy::local_mirror(account_id));
        };
        let mut policy: AccountBodyPolicy = serde_json::from_str(&row.get::<String>(0)?)?;
        policy.account_id = account_id;
        policy.updated_at = row.get(1)?;
        Ok(policy)
    }

    pub async fn set_body_policy(
        &self,
        mut policy: AccountBodyPolicy,
    ) -> Result<AccountBodyPolicy> {
        self.0.accounts().get(policy.account_id).await?;
        validate_body_policy(&self.0, &policy).await?;
        // A policy that starts requiring an offline copy must serialize with
        // physical body eviction.
        let _blob_guard = self.0.inner.blob_references.read().await;
        let now = Utc::now().timestamp();
        policy.updated_at = now;
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO account_body_policies(account_id, policy_json, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(account_id) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at",
                (
                    policy.account_id.to_string(),
                    serde_json::to_string(&policy)?,
                    now,
                ),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "account_body_policy_changed",
            policy.account_id.to_string(),
            json!({"account_id": policy.account_id, "policy": policy}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(policy)
    }

    pub async fn set_body_pinned(&self, message_id: MessageId, pinned: bool) -> Result<()> {
        self.0.messages().content_status(message_id).await?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if pinned {
            transaction
                .execute(
                    "INSERT INTO message_body_pins(message_id, pinned_at) VALUES (?1, ?2) ON CONFLICT(message_id) DO UPDATE SET pinned_at = excluded.pinned_at",
                    (message_id.to_string(), now),
                )
                .await?;
        } else {
            transaction
                .execute(
                    "DELETE FROM message_body_pins WHERE message_id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "message_body_pin_changed",
            message_id.to_string(),
            json!({"message_id": message_id, "pinned": pinned}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub async fn offline_download_candidates(
        &self,
        account_id: AccountId,
        limit: usize,
    ) -> Result<Vec<MessageId>> {
        if limit == 0 || limit > MAX_OFFLINE_BATCH {
            return Err(BackendError::InvalidInput(format!(
                "offline download batch must contain 1 to {MAX_OFFLINE_BATCH} messages"
            )));
        }
        let policy = self.body_policy(account_id).await?;
        if policy.offline == OfflineDownloadPolicy::OnDemand {
            return Ok(Vec::new());
        }
        let (mut clauses, mut parameters) = offline_policy_scope(account_id, &policy);
        clauses.push("m.content_availability != 'complete'".to_owned());
        parameters.push(Value::Integer(limit as i64));
        let connection = self.0.inner.connection.lock().await;
        let sql = format!(
            "SELECT DISTINCT m.id, m.received_at, m.content_availability FROM messages m JOIN message_instances mi ON mi.message_id = m.id JOIN folders f ON f.id = mi.folder_id LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id WHERE {} ORDER BY CASE WHEN m.content_availability = 'failed' THEN 1 ELSE 0 END, m.received_at DESC, m.id DESC LIMIT ?",
            clauses.join(" AND ")
        );
        let mut rows = connection.query(&sql, params_from_iter(parameters)).await?;
        let mut output = Vec::new();
        while let Some(row) = rows.next().await? {
            output.push(parse_message_id(row.get(0)?)?);
        }
        Ok(output)
    }

    /// Snapshot the account's verified local-mirror progress. The sync engine
    /// takes this SQL snapshot once when hydration begins and then advances
    /// its durable counter after each published message.
    pub async fn offline_download_progress(
        &self,
        account_id: AccountId,
    ) -> Result<OfflineDownloadProgress> {
        let policy = self.body_policy(account_id).await?;
        if policy.offline == OfflineDownloadPolicy::OnDemand {
            return Ok(OfflineDownloadProgress::default());
        }
        let (clauses, parameters) = offline_policy_scope(account_id, &policy);
        let connection = self.0.inner.connection.lock().await;
        let sql = format!(
            "SELECT COUNT(DISTINCT m.id), COUNT(DISTINCT CASE WHEN m.content_availability = 'complete' THEN m.id END) FROM messages m JOIN message_instances mi ON mi.message_id = m.id JOIN folders f ON f.id = mi.folder_id LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id WHERE {}",
            clauses.join(" AND ")
        );
        let mut rows = connection.query(&sql, params_from_iter(parameters)).await?;
        let row = rows.next().await?.ok_or_else(|| {
            BackendError::InvalidInput("offline progress query returned no row".into())
        })?;
        Ok(OfflineDownloadProgress {
            total_messages: u64::try_from(row.get::<i64>(0)?).map_err(|_| {
                BackendError::InvalidInput("database contains an invalid offline total".into())
            })?,
            completed_messages: u64::try_from(row.get::<i64>(1)?).map_err(|_| {
                BackendError::InvalidInput("database contains an invalid offline count".into())
            })?,
        })
    }

    pub async fn apply_retention(
        &self,
        account_id: AccountId,
        limit: usize,
    ) -> Result<BodyRetentionReport> {
        if limit == 0 || limit > MAX_OFFLINE_BATCH {
            return Err(BackendError::InvalidInput(format!(
                "retention batch must contain 1 to {MAX_OFFLINE_BATCH} messages"
            )));
        }
        let policy = self.body_policy(account_id).await?;
        let BodyRetentionPolicy::EvictRemoteAfterDays { days } = policy.retention else {
            return Ok(BodyRetentionReport {
                examined: 0,
                evicted: Vec::new(),
                reclaimed_bytes: 0,
            });
        };
        let threshold = Utc::now()
            .timestamp()
            .saturating_sub(i64::from(days) * 86_400);
        let candidates = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    r#"SELECT DISTINCT m.id, m.received_at, m.is_starred
                    FROM messages m
                    JOIN message_instances mi ON mi.message_id = m.id
                    JOIN folders f ON f.id = mi.folder_id
                    LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                    WHERE mi.account_id = ?1 AND m.content_availability = 'complete'
                        AND m.received_at < ?2 AND f.kind = 'remote'
                        AND COALESCE(ims.remote_present, 1) = 1
                        AND COALESCE(ims.selectable, 1) = 1
                        AND NOT EXISTS (SELECT 1 FROM message_body_pins p WHERE p.message_id = m.id)
                        AND NOT EXISTS (SELECT 1 FROM local_folder_memberships l WHERE l.message_id = m.id)
                    ORDER BY m.received_at, m.id LIMIT ?3"#,
                    (account_id.to_string(), threshold, limit as i64),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push((
                    parse_message_id(row.get(0)?)?,
                    row.get::<i64>(1)?,
                    row.get::<bool>(2)?,
                ));
            }
            values
        };
        let examined = candidates.len() as u64;
        let mut evicted = Vec::new();
        let mut reclaimed_bytes = 0u64;
        for (message_id, _received_at, starred) in candidates {
            if (policy.retain_starred && starred)
                || required_offline_for_any_account(&self.0, message_id).await?
            {
                continue;
            }
            reclaimed_bytes =
                reclaimed_bytes.saturating_add(self.evict_message_body(message_id).await?);
            evicted.push(message_id);
        }
        Ok(BodyRetentionReport {
            examined,
            evicted,
            reclaimed_bytes,
        })
    }

    /// Discard one complete local body only when a live remote instance can
    /// recover it. Local-folder membership and an explicit pin are hard stops.
    pub async fn evict_message_body(&self, message_id: MessageId) -> Result<u64> {
        let _blob_guard = self.0.inner.blob_references.write().await;
        if required_offline_for_any_account(&self.0, message_id).await? {
            return Err(BackendError::Conflict(
                "message body is required by an account's offline-download policy".into(),
            ));
        }
        let (old_hash, expected_bytes, raw) = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    r#"SELECT m.blob_hash, m.size_bytes
                    FROM messages m
                    WHERE m.id = ?1 AND m.content_availability = 'complete'
                        AND NOT EXISTS (SELECT 1 FROM message_body_pins p WHERE p.message_id = m.id)
                        AND NOT EXISTS (SELECT 1 FROM local_folder_memberships l WHERE l.message_id = m.id)
                        AND EXISTS (
                            SELECT 1 FROM message_instances mi
                            JOIN folders f ON f.id = mi.folder_id
                            LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                            WHERE mi.message_id = m.id AND f.kind = 'remote'
                                AND COALESCE(ims.remote_present, 1) = 1
                                AND COALESCE(ims.selectable, 1) = 1
                        )"#,
                    (message_id.to_string(),),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| {
                BackendError::Conflict(
                    "message body is incomplete, pinned, locally retained, or not remotely recoverable"
                        .into(),
                )
            })?;
            let hash = row.get::<String>(0)?;
            let bytes = u64::try_from(row.get::<i64>(1)?)
                .map_err(|_| BackendError::InvalidInput("invalid message size".into()))?;
            drop(rows);
            let raw = self.0.inner.blobs.get(&hash).await?;
            (hash, bytes, raw)
        };
        let header = header_projection(&raw)?;
        let header_hash = self.0.inner.blobs.put(header).await?;
        let not_evaluated = serde_json::to_string(&crate::DkimAuthentication {
            status: crate::DkimAuthenticationStatus::NotEvaluated,
            signatures: Vec::new(),
            evaluated_at: Utc::now().timestamp(),
            detail: Some("complete message content is not cached".into()),
        })?;
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut removable = vec![old_hash.clone()];
        for sql in [
            "SELECT blob_hash FROM attachments WHERE message_id = ?1 AND blob_hash IS NOT NULL",
            "SELECT blob_hash FROM mime_part_blobs WHERE message_id = ?1",
            "SELECT decrypted_blob_hash FROM openpgp_decrypted_messages WHERE message_id = ?1",
        ] {
            let mut rows = transaction.query(sql, (message_id.to_string(),)).await?;
            while let Some(row) = rows.next().await? {
                removable.push(row.get::<String>(0)?);
            }
        }
        let changed = transaction
            .execute(
                r#"UPDATE messages SET blob_hash = ?1, body_text = '', body_html = NULL,
                    preview = '', attachment_names = '', content_state = 'limited',
                    dkim_json = ?2, mime_state = 'limited',
                    mime_detail = 'MIME tree is unavailable because the cached body was evicted',
                    content_availability = 'headers_only', downloaded_bytes = 0,
                    download_error = NULL, download_updated_at = ?3
                WHERE id = ?4 AND blob_hash = ?5 AND content_availability = 'complete'
                    AND NOT EXISTS (SELECT 1 FROM message_body_pins p WHERE p.message_id = messages.id)
                    AND NOT EXISTS (SELECT 1 FROM local_folder_memberships l WHERE l.message_id = messages.id)
                    AND EXISTS (
                        SELECT 1 FROM message_instances mi
                        JOIN folders f ON f.id = mi.folder_id
                        LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                        WHERE mi.message_id = messages.id AND f.kind = 'remote'
                            AND COALESCE(ims.remote_present, 1) = 1
                            AND COALESCE(ims.selectable, 1) = 1
                    )"#,
                (
                    header_hash,
                    not_evaluated,
                    now,
                    message_id.to_string(),
                    old_hash,
                ),
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "message changed while its cached body was being evicted".into(),
            ));
        }
        for table in [
            "attachments",
            "mime_part_blobs",
            "mime_parts",
            "message_links",
            "openpgp_decrypted_messages",
            "openpgp_message_evidence",
        ] {
            transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE message_id = ?1"),
                    (message_id.to_string(),),
                )
                .await?;
        }
        enqueue_search_on(&transaction, message_id).await?;
        let event = insert_event(
            &transaction,
            now,
            "message_body_evicted",
            message_id.to_string(),
            json!({"message_id": message_id, "recoverable_bytes": expected_bytes}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        removable.sort_unstable();
        removable.dedup();
        let mut removed = 0u64;
        for hash in removable {
            if !self.0.blob_is_referenced(&hash).await? {
                if let Ok(metadata) = fs::metadata(
                    self.0
                        .inner
                        .config
                        .profile_dir
                        .join("blobs")
                        .join(&hash[..2])
                        .join(&hash[2..]),
                )
                .await
                {
                    removed = removed.saturating_add(metadata.len());
                }
                self.0.inner.blobs.remove_unreferenced(&hash).await?;
            }
        }
        self.0.inner.storage.measure().await?;
        drop(_search_guard);
        Ok(removed)
    }

    pub async fn export_mail(
        &self,
        selection: MailSelection,
        format: MailExportFormat,
        destination: impl AsRef<Path>,
        limits: MailTransferLimits,
    ) -> Result<MailExportReport> {
        validate_transfer_limits(limits)?;
        let destination = destination.as_ref().to_owned();
        ensure_absent(&destination).await?;
        let _blob_guard = self.0.inner.blob_references.read().await;
        let rows = export_rows(&self.0, selection, limits).await?;
        match format {
            MailExportFormat::EmlDirectory | MailExportFormat::Maildir => {
                self.export_directory(rows, format, destination, limits)
                    .await
            }
            MailExportFormat::Mbox => self.export_mbox(rows, destination, limits).await,
        }
    }

    /// Import standard mail storage without normalizing the RFC bytes. Work is
    /// read and committed in bounded batches; if a later source entry is
    /// invalid, earlier reported backend change events identify the batches
    /// that were already committed and may be removed by the caller.
    pub async fn import_mail(
        &self,
        source: impl AsRef<Path>,
        format: MailExportFormat,
        local_folder_id: Option<FolderId>,
        limits: MailTransferLimits,
    ) -> Result<MailImportReport> {
        validate_transfer_limits(limits)?;
        if let Some(folder_id) = local_folder_id {
            let folder = self.0.folders().get(folder_id).await?;
            if folder.kind != crate::FolderKind::Local {
                return Err(BackendError::InvalidInput(
                    "import destination must be a local folder".into(),
                ));
            }
        }
        let source = source.as_ref();
        let (message_ids, raw_bytes) = match format {
            MailExportFormat::EmlDirectory | MailExportFormat::Maildir => {
                self.import_portable_directory(source, format.clone(), local_folder_id, limits)
                    .await?
            }
            MailExportFormat::Mbox => self.import_mbox(source, local_folder_id, limits).await?,
        };
        Ok(MailImportReport {
            format,
            messages: message_ids,
            raw_bytes,
        })
    }

    pub async fn backup_profile(
        &self,
        destination: impl AsRef<Path>,
    ) -> Result<ProfileBackupReport> {
        let destination = destination.as_ref().to_owned();
        ensure_absent(&destination).await?;
        reject_nested_destination(&self.0.inner.config.profile_dir, &destination)?;
        let _blob_guard = self.0.inner.blob_references.write().await;
        // Creating the final directory is the no-clobber publication point.
        // The manifest is written last, so a crash leaves a recognizably
        // incomplete backup rather than overwriting an older one.
        create_private_dir(&destination).await?;
        let result = self.backup_into(&destination).await;
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                let _ = fs::remove_dir_all(&destination).await;
                return Err(error);
            }
        };
        Ok(ProfileBackupReport {
            destination,
            ..report
        })
    }

    async fn backup_into(&self, destination: &Path) -> Result<ProfileBackupReport> {
        let connection = self.0.inner.connection.lock().await;
        let mut checkpoint = connection
            .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
            .await?;
        while checkpoint.next().await?.is_some() {}
        let schema_version = {
            let mut rows = connection
                .query("SELECT version FROM schema_meta", ())
                .await?;
            rows.next()
                .await?
                .ok_or_else(|| BackendError::InvalidInput("missing schema version".into()))?
                .get::<i64>(0)?
        };
        let native_credential_references = native_credential_reference_count(&connection).await?;
        let source = &self.0.inner.config.profile_dir;
        let files = collect_profile_files(source)?;
        let mut manifest_files = Vec::with_capacity(files.len());
        let mut bytes = 0u64;
        for relative in files {
            let input = source.join(&relative);
            let output = destination.join(&relative);
            let (size, hash) = copy_file_hashed(&input, &output).await?;
            bytes = bytes.saturating_add(size);
            manifest_files.push(ProfileFile {
                path: relative_path_text(&relative)?,
                bytes: size,
                sha256: hash,
            });
        }
        drop(connection);
        let manifest = ProfileManifest {
            version: 1,
            created_at: Utc::now().timestamp(),
            schema_version,
            native_credential_references,
            files: manifest_files,
        };
        let manifest_path = destination.join(BACKUP_MANIFEST);
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
            .await
            .map_err(|source| crate::error::io_error(manifest_path, source))?;
        Ok(ProfileBackupReport {
            destination: destination.to_owned(),
            files: manifest.files.len() as u64,
            bytes,
            native_credential_references,
        })
    }

    async fn export_directory(
        &self,
        rows: Vec<ExportRow>,
        format: MailExportFormat,
        destination: PathBuf,
        limits: MailTransferLimits,
    ) -> Result<MailExportReport> {
        // `create_dir` is atomic and refuses every existing filesystem entry,
        // including a dangling symlink. The manifest is the completion marker.
        create_private_dir(&destination).await?;
        if format == MailExportFormat::Maildir {
            for name in ["cur", "new", "tmp"] {
                if let Err(source) = fs::create_dir(destination.join(name)).await {
                    let _ = fs::remove_dir_all(&destination).await;
                    return Err(crate::error::io_error(destination.join(name), source));
                }
            }
        }
        let result = async {
            let mut entries = Vec::with_capacity(rows.len());
            let mut raw_bytes = 0u64;
            for row in rows {
                let raw = self.0.inner.blobs.get(&row.blob_hash).await?;
                enforce_message_limits(raw.len(), &mut raw_bytes, limits)?;
                let relative = match format {
                    MailExportFormat::EmlDirectory => format!("{}.eml", row.id),
                    MailExportFormat::Maildir if row.is_read || row.is_starred => {
                        let mut flags = String::new();
                        if row.is_starred {
                            flags.push('F');
                        }
                        if row.is_read {
                            flags.push('S');
                        }
                        format!("cur/{}:2,{flags}", row.id)
                    }
                    MailExportFormat::Maildir => format!("new/{}", row.id),
                    MailExportFormat::Mbox => unreachable!(),
                };
                let output = destination.join(&relative);
                fs::write(&output, &raw)
                    .await
                    .map_err(|source| crate::error::io_error(output, source))?;
                entries.push(portable_entry(Some(relative), &raw, &row));
            }
            let manifest = PortableManifest {
                version: 1,
                format: format.clone(),
                entries,
            };
            let manifest_path = destination.join(EXPORT_MANIFEST);
            fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
                .await
                .map_err(|source| crate::error::io_error(manifest_path, source))?;
            Ok::<_, BackendError>(raw_bytes)
        }
        .await;
        let raw_bytes = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&destination).await;
                return Err(error);
            }
        };
        let messages = manifest_count(&destination).await?;
        Ok(MailExportReport {
            format,
            destination,
            messages,
            raw_bytes,
        })
    }

    async fn export_mbox(
        &self,
        rows: Vec<ExportRow>,
        destination: PathBuf,
        limits: MailTransferLimits,
    ) -> Result<MailExportReport> {
        let manifest_destination = mbox_manifest_path(&destination)?;
        ensure_absent(&manifest_destination).await?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(&destination)
            .await
            .map_err(|source| crate::error::io_error(destination.clone(), source))?;
        let mut entries = Vec::with_capacity(rows.len());
        let mut raw_bytes = 0u64;
        let write_result = async {
            for row in &rows {
                let raw = self.0.inner.blobs.get(&row.blob_hash).await?;
                enforce_message_limits(raw.len(), &mut raw_bytes, limits)?;
                file.write_all(format!("From MAILER-DAEMON {}\n", row.received_at).as_bytes())
                    .await
                    .map_err(|source| crate::error::io_error(destination.clone(), source))?;
                file.write_all(&mboxrd_encode(&raw))
                    .await
                    .map_err(|source| crate::error::io_error(destination.clone(), source))?;
                if !raw.ends_with(b"\n") {
                    file.write_all(b"\n")
                        .await
                        .map_err(|source| crate::error::io_error(destination.clone(), source))?;
                }
                file.write_all(b"\n")
                    .await
                    .map_err(|source| crate::error::io_error(destination.clone(), source))?;
                entries.push(portable_entry(None, &raw, row));
            }
            file.sync_all()
                .await
                .map_err(|source| crate::error::io_error(destination.clone(), source))?;
            Ok::<(), BackendError>(())
        }
        .await;
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&destination).await;
            return Err(error);
        }
        let manifest = PortableManifest {
            version: 1,
            format: MailExportFormat::Mbox,
            entries,
        };
        let manifest_bytes = match serde_json::to_vec_pretty(&manifest) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = fs::remove_file(&destination).await;
                return Err(error.into());
            }
        };
        let mut manifest_options = fs::OpenOptions::new();
        manifest_options.create_new(true).write(true);
        #[cfg(unix)]
        {
            manifest_options.mode(0o600);
        }
        let manifest_result = async {
            let mut manifest_file = manifest_options
                .open(&manifest_destination)
                .await
                .map_err(|source| crate::error::io_error(manifest_destination.clone(), source))?;
            manifest_file
                .write_all(&manifest_bytes)
                .await
                .map_err(|source| crate::error::io_error(manifest_destination.clone(), source))?;
            manifest_file
                .sync_all()
                .await
                .map_err(|source| crate::error::io_error(manifest_destination.clone(), source))
        }
        .await;
        if let Err(error) = manifest_result {
            let _ = fs::remove_file(&destination).await;
            let _ = fs::remove_file(&manifest_destination).await;
            return Err(error);
        }
        Ok(MailExportReport {
            format: MailExportFormat::Mbox,
            destination,
            messages: rows.len() as u64,
            raw_bytes,
        })
    }

    async fn import_portable_directory(
        &self,
        source: &Path,
        format: MailExportFormat,
        local_folder_id: Option<FolderId>,
        limits: MailTransferLimits,
    ) -> Result<(Vec<MessageId>, u64)> {
        let manifest = read_portable_manifest(&source.join(EXPORT_MANIFEST)).await?;
        if manifest
            .as_ref()
            .is_some_and(|manifest| manifest.format != format)
        {
            return Err(BackendError::InvalidInput(
                "mail export manifest format does not match the requested import format".into(),
            ));
        }
        let files = portable_files(source, &format).await?;
        if files.len() > limits.max_messages {
            return Err(BackendError::InvalidInput(
                "import exceeds configured message limit".into(),
            ));
        }
        let mut entries = HashMap::new();
        if let Some(manifest) = &manifest {
            if manifest.entries.len() != files.len() {
                return Err(BackendError::InvalidInput(
                    "mail export manifest and directory contain different message counts".into(),
                ));
            }
            for entry in &manifest.entries {
                let file = entry.file.as_deref().ok_or_else(|| {
                    BackendError::InvalidInput(
                        "directory mail export manifest is missing an entry path".into(),
                    )
                })?;
                safe_relative_path(file)?;
                if entries.insert(file.to_owned(), entry).is_some() {
                    return Err(BackendError::InvalidInput(
                        "mail export manifest contains a duplicate entry path".into(),
                    ));
                }
            }
        }

        let mut imported = Vec::with_capacity(TRANSFER_BATCH);
        let mut message_ids = Vec::with_capacity(files.len());
        let mut raw_bytes = 0u64;
        for file in files {
            let raw = read_bounded_file(&file, limits.max_message_bytes).await?;
            enforce_message_limits(raw.len(), &mut raw_bytes, limits)?;
            let relative =
                relative_path_text(file.strip_prefix(source).map_err(|_| {
                    BackendError::InvalidInput("import file escaped its root".into())
                })?)?;
            let entry = entries.get(&relative).copied();
            if manifest.is_some() && entry.is_none() {
                return Err(BackendError::InvalidInput(
                    "mail export manifest does not describe every imported file".into(),
                ));
            }
            if let Some(entry) = entry {
                verify_portable_entry(&raw, entry)?;
            }
            let (flag_read, flag_starred) = if format == MailExportFormat::Maildir {
                parse_maildir_flags(&file)
            } else {
                (false, false)
            };
            imported.push(ImportedMessage {
                raw,
                received_at: entry.map(|entry| entry.received_at),
                is_read: entry.map_or(flag_read, |entry| entry.is_read),
                is_starred: entry.map_or(flag_starred, |entry| entry.is_starred),
            });
            if imported.len() == TRANSFER_BATCH {
                message_ids.extend(
                    self.ingest_imported(std::mem::take(&mut imported), local_folder_id)
                        .await?,
                );
            }
        }
        if !imported.is_empty() {
            message_ids.extend(self.ingest_imported(imported, local_folder_id).await?);
        }
        Ok((message_ids, raw_bytes))
    }

    async fn import_mbox(
        &self,
        source: &Path,
        local_folder_id: Option<FolderId>,
        limits: MailTransferLimits,
    ) -> Result<(Vec<MessageId>, u64)> {
        let manifest_path = mbox_manifest_path(source)?;
        let manifest = read_portable_manifest(&manifest_path).await?;
        if let Some(manifest) = &manifest {
            if manifest.format != MailExportFormat::Mbox
                || manifest.entries.iter().any(|entry| entry.file.is_some())
                || manifest.entries.len() > limits.max_messages
            {
                return Err(BackendError::InvalidInput(
                    "invalid mbox export manifest".into(),
                ));
            }
        }
        let file = fs::File::open(source)
            .await
            .map_err(|error| crate::error::io_error(source.to_owned(), error))?;
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut current = Vec::new();
        let mut imported = Vec::with_capacity(TRANSFER_BATCH);
        let mut message_ids = Vec::new();
        let mut seen_separator = false;
        let mut encoded_bytes = 0u64;
        let mut raw_bytes = 0u64;
        let mut message_index = 0usize;
        loop {
            let read = read_bounded_line(
                &mut reader,
                &mut line,
                usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX),
                source,
            )
            .await?;
            if read == 0 {
                break;
            }
            encoded_bytes = encoded_bytes.saturating_add(read as u64);
            if encoded_bytes > limits.max_total_bytes.saturating_mul(2) {
                return Err(BackendError::InvalidInput(
                    "mbox input exceeds configured encoded-byte limit".into(),
                ));
            }
            if line.starts_with(b"From ") {
                if seen_separator {
                    let entry = finish_mbox_message(
                        std::mem::take(&mut current),
                        message_index,
                        manifest.as_ref(),
                        &mut raw_bytes,
                        limits,
                    )?;
                    imported.push(entry);
                    message_index += 1;
                    if message_index > limits.max_messages {
                        return Err(BackendError::InvalidInput(
                            "mbox exceeds configured message limit".into(),
                        ));
                    }
                    if imported.len() == TRANSFER_BATCH {
                        message_ids.extend(
                            self.ingest_imported(std::mem::take(&mut imported), local_folder_id)
                                .await?,
                        );
                    }
                }
                seen_separator = true;
                continue;
            }
            if !seen_separator {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                return Err(BackendError::InvalidInput(
                    "mbox does not begin with a From_ separator".into(),
                ));
            }
            current.extend_from_slice(mboxrd_unquote(&line));
            if current.len() as u64 > limits.max_message_bytes.saturating_add(2) {
                return Err(BackendError::MessageTooLarge {
                    actual: current.len(),
                    limit: usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX),
                });
            }
        }
        if seen_separator {
            imported.push(finish_mbox_message(
                current,
                message_index,
                manifest.as_ref(),
                &mut raw_bytes,
                limits,
            )?);
            message_index += 1;
            if message_index > limits.max_messages {
                return Err(BackendError::InvalidInput(
                    "mbox exceeds configured message limit".into(),
                ));
            }
        }
        if let Some(manifest) = &manifest {
            if manifest.entries.len() != message_index {
                return Err(BackendError::InvalidInput(
                    "mbox and its lossless manifest contain different message counts".into(),
                ));
            }
        }
        if !imported.is_empty() {
            message_ids.extend(self.ingest_imported(imported, local_folder_id).await?);
        }
        Ok((message_ids, raw_bytes))
    }

    async fn ingest_imported(
        &self,
        imported: Vec<ImportedMessage>,
        local_folder_id: Option<FolderId>,
    ) -> Result<Vec<MessageId>> {
        let mut output = Vec::with_capacity(imported.len());
        let mut imported = imported.into_iter();
        loop {
            let batch = imported.by_ref().take(TRANSFER_BATCH).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            let states = batch
                .iter()
                .map(|item| (item.is_read, item.is_starred))
                .collect::<Vec<_>>();
            let requests = batch
                .into_iter()
                .map(|item| IngestMessage {
                    raw: item.raw,
                    remote: None,
                    received_at: item.received_at,
                    user_classification: None,
                })
                .collect();
            let ids = self.0.messages().ingest_batch(requests).await?;
            let _search_guard = self.0.inner.search_sync.write().await;
            let mut connection = self.0.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (id, (is_read, is_starred)) in ids.iter().zip(states) {
                transaction
                    .execute(
                        "UPDATE messages SET is_read = ?1, is_starred = ?2 WHERE id = ?3",
                        (is_read, is_starred, id.to_string()),
                    )
                    .await?;
                if let Some(folder_id) = local_folder_id {
                    transaction
                        .execute(
                            "INSERT INTO local_folder_memberships(message_id, folder_id, rule_id, created_at) VALUES (?1, ?2, NULL, ?3)",
                            (id.to_string(), folder_id.to_string(), Utc::now().timestamp()),
                        )
                        .await?;
                }
                enqueue_search_on(&transaction, *id).await?;
            }
            transaction.commit().await?;
            drop(connection);
            self.0.flush_search_projection().await?;
            drop(_search_guard);
            output.extend(ids);
        }
        Ok(output)
    }
}

pub async fn restore_profile_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<ProfileRestoreReport> {
    let backup = backup.as_ref();
    let destination = destination.as_ref().to_owned();
    ensure_absent(&destination).await?;
    reject_nested_destination(backup, &destination)?;
    let manifest_path = backup.join(BACKUP_MANIFEST);
    let manifest_bytes = fs::read(&manifest_path)
        .await
        .map_err(|source| crate::error::io_error(manifest_path.clone(), source))?;
    let manifest: ProfileManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.version != 1 || manifest.files.len() > 10_000_000 {
        return Err(BackendError::InvalidInput(
            "unsupported or unreasonably large profile backup manifest".into(),
        ));
    }
    let mut paths = HashSet::new();
    for entry in &manifest.files {
        let relative = safe_relative_path(&entry.path)?;
        if !paths.insert(relative) {
            return Err(BackendError::InvalidInput(
                "profile backup manifest contains a duplicate path".into(),
            ));
        }
        if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BackendError::InvalidInput(
                "profile backup manifest contains an invalid hash".into(),
            ));
        }
    }
    // The destination itself is created with no-clobber semantics; the
    // validated copy is removed on any ordinary failure.
    create_private_dir(&destination).await?;
    let mut total = 0u64;
    let result = async {
        for entry in &manifest.files {
            let relative = safe_relative_path(&entry.path)?;
            let input = backup.join(&relative);
            let output = destination.join(&relative);
            let (bytes, hash) = copy_file_hashed(&input, &output).await?;
            if bytes != entry.bytes || hash != entry.sha256 {
                return Err(BackendError::InvalidInput(format!(
                    "profile backup file failed validation: {}",
                    entry.path
                )));
            }
            total = total.checked_add(bytes).ok_or_else(|| {
                BackendError::InvalidInput("profile backup byte count overflowed".into())
            })?;
        }
        if !destination.join("mail.db").exists() {
            return Err(BackendError::InvalidInput(
                "profile backup does not contain mail.db".into(),
            ));
        }
        Ok::<(), BackendError>(())
    }
    .await;
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&destination).await;
        return Err(error);
    }
    Ok(ProfileRestoreReport {
        destination,
        files: manifest.files.len() as u64,
        bytes: total,
        native_credential_references: manifest.native_credential_references,
    })
}

fn offline_policy_scope(
    account_id: AccountId,
    policy: &AccountBodyPolicy,
) -> (Vec<String>, Vec<Value>) {
    let mut clauses = vec![
        "mi.account_id = ?".to_owned(),
        "f.kind = 'remote'".to_owned(),
        "COALESCE(ims.remote_present, 1) = 1".to_owned(),
        "COALESCE(ims.selectable, 1) = 1".to_owned(),
    ];
    let mut parameters = vec![Value::Text(account_id.to_string())];
    match &policy.offline {
        OfflineDownloadPolicy::OnDemand | OfflineDownloadPolicy::All => {}
        OfflineDownloadPolicy::RecentDays { days } => {
            clauses.push("m.received_at >= ?".into());
            parameters.push(Value::Integer(
                Utc::now()
                    .timestamp()
                    .saturating_sub(i64::from(*days) * 86_400),
            ));
        }
        OfflineDownloadPolicy::SelectedFolders { folder_ids } => {
            let values = folder_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            clauses.push(format!(
                "mi.folder_id IN ({})",
                std::iter::repeat_n("?", values.len())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            parameters.extend(values.into_iter().map(Value::Text));
        }
    }
    (clauses, parameters)
}

async fn validate_body_policy(backend: &Backend, policy: &AccountBodyPolicy) -> Result<()> {
    for days in [
        match policy.offline {
            OfflineDownloadPolicy::RecentDays { days } => Some(days),
            _ => None,
        },
        match policy.retention {
            BodyRetentionPolicy::EvictRemoteAfterDays { days } => Some(days),
            _ => None,
        },
    ]
    .into_iter()
    .flatten()
    {
        if days == 0 || days > 36_500 {
            return Err(BackendError::InvalidInput(
                "body policy day counts must be between 1 and 36500".into(),
            ));
        }
    }
    if let OfflineDownloadPolicy::SelectedFolders { folder_ids } = &policy.offline {
        if folder_ids.is_empty() || folder_ids.len() > 10_000 {
            return Err(BackendError::InvalidInput(
                "selected-folder policy requires 1 to 10000 folders".into(),
            ));
        }
        let mut unique = HashSet::new();
        for folder_id in folder_ids {
            if !unique.insert(*folder_id) {
                return Err(BackendError::InvalidInput(
                    "selected-folder policy contains duplicate folders".into(),
                ));
            }
            let folder = backend.folders().get(*folder_id).await?;
            if folder.account_id != Some(policy.account_id)
                || folder.kind != crate::FolderKind::Remote
            {
                return Err(BackendError::InvalidInput(
                    "offline policy folders must be remote folders of the same account".into(),
                ));
            }
        }
    }
    Ok(())
}

async fn required_offline(
    backend: &Backend,
    account_id: AccountId,
    message_id: MessageId,
    received_at: i64,
    policy: &OfflineDownloadPolicy,
) -> Result<bool> {
    match policy {
        OfflineDownloadPolicy::OnDemand => Ok(false),
        OfflineDownloadPolicy::All => Ok(true),
        OfflineDownloadPolicy::RecentDays { days } => Ok(received_at
            >= Utc::now()
                .timestamp()
                .saturating_sub(i64::from(*days) * 86_400)),
        OfflineDownloadPolicy::SelectedFolders { folder_ids } => {
            let connection = backend.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT folder_id FROM message_instances WHERE message_id = ?1 AND account_id = ?2",
                    (message_id.to_string(), account_id.to_string()),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                let folder: FolderId = row
                    .get::<String>(0)?
                    .parse()
                    .map_err(|_| BackendError::InvalidInput("invalid folder ID".into()))?;
                if folder_ids.contains(&folder) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

async fn required_offline_for_any_account(
    backend: &Backend,
    message_id: MessageId,
) -> Result<bool> {
    let (received_at, account_ids) = {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT received_at FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        let received_at = rows
            .next()
            .await?
            .ok_or_else(|| BackendError::NotFound {
                entity: "message",
                id: message_id.to_string(),
            })?
            .get::<i64>(0)?;
        drop(rows);
        let mut rows = connection
            .query(
                r#"SELECT DISTINCT mi.account_id FROM message_instances mi
                JOIN folders f ON f.id = mi.folder_id
                LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                WHERE mi.message_id = ?1 AND f.kind = 'remote'
                    AND COALESCE(ims.remote_present, 1) = 1
                    AND COALESCE(ims.selectable, 1) = 1"#,
                (message_id.to_string(),),
            )
            .await?;
        let mut account_ids = Vec::new();
        while let Some(row) = rows.next().await? {
            account_ids.push(
                row.get::<String>(0)?
                    .parse::<AccountId>()
                    .map_err(|_| BackendError::InvalidInput("invalid account ID".into()))?,
            );
        }
        (received_at, account_ids)
    };
    for account_id in account_ids {
        let policy = DataLifecycle::new(backend.clone())
            .body_policy(account_id)
            .await?;
        if required_offline(
            backend,
            account_id,
            message_id,
            received_at,
            &policy.offline,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn export_rows(
    backend: &Backend,
    selection: MailSelection,
    limits: MailTransferLimits,
) -> Result<Vec<ExportRow>> {
    let connection = backend.inner.connection.lock().await;
    let mut clauses = Vec::new();
    let mut parameters = Vec::new();
    match selection {
        MailSelection::All => {}
        MailSelection::Account(account_id) => {
            clauses.push("(EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.account_id = ?) OR EXISTS (SELECT 1 FROM sent_reconciliation sr WHERE sr.message_id = m.id AND sr.account_id = ?))".into());
            parameters.push(Value::Text(account_id.to_string()));
            parameters.push(Value::Text(account_id.to_string()));
        }
        MailSelection::Folder(folder_id) => {
            clauses.push("(EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.folder_id = ?) OR EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = ?))".into());
            parameters.push(Value::Text(folder_id.to_string()));
            parameters.push(Value::Text(folder_id.to_string()));
        }
        MailSelection::Messages(ids) => {
            if ids.is_empty() || ids.len() > limits.max_messages {
                return Err(BackendError::InvalidInput(
                    "explicit export selection is empty or exceeds the message limit".into(),
                ));
            }
            clauses.push(format!(
                "m.id IN ({})",
                std::iter::repeat_n("?", ids.len())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            parameters.extend(ids.into_iter().map(|id| Value::Text(id.to_string())));
        }
    }
    let sql = format!(
        "SELECT m.id, m.blob_hash, m.received_at, m.is_read, m.is_starred, m.size_bytes, m.content_availability FROM messages m {} ORDER BY m.received_at, m.id LIMIT ?",
        if clauses.is_empty() { String::new() } else { format!("WHERE {}", clauses.join(" AND ")) }
    );
    parameters.push(Value::Integer(
        i64::try_from(limits.max_messages.saturating_add(1)).unwrap_or(i64::MAX),
    ));
    let mut rows = connection.query(&sql, params_from_iter(parameters)).await?;
    let mut output = Vec::new();
    let mut total = 0u64;
    while let Some(row) = rows.next().await? {
        if output.len() == limits.max_messages {
            return Err(BackendError::InvalidInput(
                "export selection exceeds configured message limit".into(),
            ));
        }
        let size_bytes = u64::try_from(row.get::<i64>(5)?)
            .map_err(|_| BackendError::InvalidInput("invalid message size".into()))?;
        if size_bytes > limits.max_message_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: usize::try_from(size_bytes).unwrap_or(usize::MAX),
                limit: usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX),
            });
        }
        if row.get::<String>(6)? != "complete" {
            return Err(BackendError::Conflict(
                "lossless export requires every selected message body to be downloaded".into(),
            ));
        }
        total = total
            .checked_add(size_bytes)
            .ok_or_else(|| BackendError::InvalidInput("export byte count overflowed".into()))?;
        if total > limits.max_total_bytes {
            return Err(BackendError::InvalidInput(
                "export exceeds configured total-byte limit".into(),
            ));
        }
        output.push(ExportRow {
            id: parse_message_id(row.get(0)?)?,
            blob_hash: row.get(1)?,
            received_at: row.get(2)?,
            is_read: row.get(3)?,
            is_starred: row.get(4)?,
        });
    }
    Ok(output)
}

async fn portable_files(path: &Path, format: &MailExportFormat) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let directory_names: &[&str] = match format {
        MailExportFormat::EmlDirectory => &[""],
        MailExportFormat::Maildir => &["cur", "new"],
        MailExportFormat::Mbox => {
            return Err(BackendError::InvalidInput(
                "mbox is not a directory mail format".into(),
            ))
        }
    };
    for directory_name in directory_names {
        let directory_path = path.join(directory_name);
        let mut directory = fs::read_dir(&directory_path)
            .await
            .map_err(|source| crate::error::io_error(directory_path.clone(), source))?;
        while let Some(entry) = directory
            .next_entry()
            .await
            .map_err(|source| crate::error::io_error(directory_path.clone(), source))?
        {
            let file_type = entry
                .file_type()
                .await
                .map_err(|source| crate::error::io_error(entry.path(), source))?;
            if file_type.is_symlink() {
                return Err(BackendError::InvalidInput(format!(
                    "mail import refuses symbolic link {}",
                    entry.path().display()
                )));
            }
            let eml = entry.path().extension().is_some_and(|value| value == "eml");
            if file_type.is_file() && (*format == MailExportFormat::Maildir || eml) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

async fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .await
        .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
    if !metadata.file_type().is_file() {
        return Err(BackendError::InvalidInput(format!(
            "mail import entry is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(BackendError::MessageTooLarge {
            actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            limit: usize::try_from(maximum).unwrap_or(usize::MAX),
        });
    }
    let file = fs::File::open(path)
        .await
        .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
    let mut limited = file.take(maximum.saturating_add(1));
    let mut raw = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    limited
        .read_to_end(&mut raw)
        .await
        .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
    if raw.len() as u64 > maximum {
        return Err(BackendError::MessageTooLarge {
            actual: raw.len(),
            limit: usize::try_from(maximum).unwrap_or(usize::MAX),
        });
    }
    Ok(raw)
}

async fn read_bounded_line(
    reader: &mut BufReader<fs::File>,
    line: &mut Vec<u8>,
    maximum: usize,
    path: &Path,
) -> Result<usize> {
    line.clear();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
        if available.is_empty() {
            return Ok(line.len());
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |offset| offset + 1);
        if line.len().saturating_add(take) > maximum.saturating_add(2) {
            return Err(BackendError::MessageTooLarge {
                actual: line.len().saturating_add(take),
                limit: maximum,
            });
        }
        line.extend_from_slice(&available[..take]);
        let newline = available[take - 1] == b'\n';
        reader.consume(take);
        if newline {
            return Ok(line.len());
        }
    }
}

fn finish_mbox_message(
    mut raw: Vec<u8>,
    index: usize,
    manifest: Option<&PortableManifest>,
    total: &mut u64,
    limits: MailTransferLimits,
) -> Result<ImportedMessage> {
    let entry = manifest.and_then(|value| value.entries.get(index));
    if manifest.is_some() && entry.is_none() {
        return Err(BackendError::InvalidInput(
            "mbox contains more messages than its lossless manifest".into(),
        ));
    }
    if let Some(entry) = entry {
        let raw_bytes = usize::try_from(entry.raw_bytes)
            .map_err(|_| BackendError::InvalidInput("mbox manifest entry is too large".into()))?;
        if raw.len() < raw_bytes {
            return Err(BackendError::InvalidInput(
                "mbox entry is shorter than its lossless manifest".into(),
            ));
        }
        raw.truncate(raw_bytes);
        verify_portable_entry(&raw, entry)?;
    } else if raw.ends_with(b"\n\n") {
        raw.pop();
    }
    enforce_message_limits(raw.len(), total, limits)?;
    Ok(ImportedMessage {
        raw,
        received_at: entry.map(|entry| entry.received_at),
        is_read: entry.is_some_and(|entry| entry.is_read),
        is_starred: entry.is_some_and(|entry| entry.is_starred),
    })
}

fn header_projection(raw: &[u8]) -> Result<&[u8]> {
    if let Some(offset) = raw.windows(4).position(|value| value == b"\r\n\r\n") {
        return Ok(&raw[..offset + 4]);
    }
    if let Some(offset) = raw.windows(2).position(|value| value == b"\n\n") {
        return Ok(&raw[..offset + 2]);
    }
    Err(BackendError::Parse)
}

fn mboxrd_encode(raw: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(raw.len());
    let mut start = 0;
    while start < raw.len() {
        let end = raw[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(raw.len(), |offset| start + offset + 1);
        let line = &raw[start..end];
        let first_non_quote = line
            .iter()
            .position(|byte| *byte != b'>')
            .unwrap_or(line.len());
        if line[first_non_quote..].starts_with(b"From ") {
            output.push(b'>');
        }
        output.extend_from_slice(line);
        start = end;
    }
    output
}

fn mboxrd_unquote(line: &[u8]) -> &[u8] {
    let quotes = line.iter().take_while(|byte| **byte == b'>').count();
    if quotes > 0 && line[quotes..].starts_with(b"From ") {
        &line[1..]
    } else {
        line
    }
}

fn portable_entry(file: Option<String>, raw: &[u8], row: &ExportRow) -> PortableEntry {
    PortableEntry {
        file,
        raw_bytes: raw.len() as u64,
        sha256: hex::encode(Sha256::digest(raw)),
        received_at: row.received_at,
        is_read: row.is_read,
        is_starred: row.is_starred,
    }
}

fn verify_portable_entry(raw: &[u8], entry: &PortableEntry) -> Result<()> {
    if raw.len() as u64 != entry.raw_bytes || hex::encode(Sha256::digest(raw)) != entry.sha256 {
        return Err(BackendError::InvalidInput(
            "mail export entry failed length or hash validation".into(),
        ));
    }
    Ok(())
}

async fn read_portable_manifest(path: &Path) -> Result<Option<PortableManifest>> {
    match fs::read(path).await {
        Ok(bytes) => {
            let manifest: PortableManifest = serde_json::from_slice(&bytes)?;
            if manifest.version != 1 || manifest.entries.len() > 10_000_000 {
                return Err(BackendError::InvalidInput(
                    "unsupported mail export manifest".into(),
                ));
            }
            if manifest.entries.iter().any(|entry| {
                entry.sha256.len() != 64
                    || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                return Err(BackendError::InvalidInput(
                    "mail export manifest contains an invalid hash".into(),
                ));
            }
            Ok(Some(manifest))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(crate::error::io_error(path.to_owned(), source)),
    }
}

fn parse_maildir_flags(path: &Path) -> (bool, bool) {
    let value = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let flags = value
        .split_once(":2,")
        .map(|(_, flags)| flags)
        .unwrap_or("");
    (flags.contains('S'), flags.contains('F'))
}

fn enforce_message_limits(
    length: usize,
    total: &mut u64,
    limits: MailTransferLimits,
) -> Result<()> {
    if length as u64 > limits.max_message_bytes {
        return Err(BackendError::MessageTooLarge {
            actual: length,
            limit: usize::try_from(limits.max_message_bytes).unwrap_or(usize::MAX),
        });
    }
    *total = total
        .checked_add(length as u64)
        .ok_or_else(|| BackendError::InvalidInput("mail byte count overflowed".into()))?;
    if *total > limits.max_total_bytes {
        return Err(BackendError::InvalidInput(
            "mail transfer exceeds configured total-byte limit".into(),
        ));
    }
    Ok(())
}

fn validate_transfer_limits(limits: MailTransferLimits) -> Result<()> {
    if limits.max_messages == 0
        || limits.max_message_bytes == 0
        || limits.max_total_bytes < limits.max_message_bytes
        || limits.max_messages > 10_000_000
    {
        return Err(BackendError::InvalidInput(
            "mail transfer limits must be positive, ordered, and bounded".into(),
        ));
    }
    Ok(())
}

fn collect_profile_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![PathBuf::new()];
    let mut files = Vec::new();
    while let Some(relative) = pending.pop() {
        let directory = root.join(&relative);
        for entry in std::fs::read_dir(&directory)
            .map_err(|source| crate::error::io_error(directory.clone(), source))?
        {
            let entry =
                entry.map_err(|source| crate::error::io_error(directory.clone(), source))?;
            let child_relative = relative.join(entry.file_name());
            if backup_excluded(&child_relative) {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|source| crate::error::io_error(entry.path(), source))?;
            if file_type.is_symlink() {
                return Err(BackendError::InvalidInput(format!(
                    "profile backup refuses symbolic link {}",
                    child_relative.display()
                )));
            }
            if file_type.is_dir() {
                pending.push(child_relative);
            } else if file_type.is_file() {
                files.push(child_relative);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn backup_excluded(path: &Path) -> bool {
    let first = path.components().next();
    matches!(first, Some(Component::Normal(value)) if value == "search-index" || value == "downloads")
        || path == Path::new("search-index.json")
        || path == Path::new(BACKUP_MANIFEST)
        || path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with("-shm"))
        || path.starts_with(Path::new("blobs/incoming"))
}

async fn copy_file_hashed(source: &Path, destination: &Path) -> Result<(u64, String)> {
    let metadata = fs::symlink_metadata(source)
        .await
        .map_err(|error| crate::error::io_error(source.to_owned(), error))?;
    if !metadata.file_type().is_file() {
        return Err(BackendError::InvalidInput(format!(
            "profile backup entry is not a regular file: {}",
            source.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|source| crate::error::io_error(parent.to_owned(), source))?;
    }
    let mut input = fs::File::open(source)
        .await
        .map_err(|error| crate::error::io_error(source.to_owned(), error))?;
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .await
        .map_err(|error| crate::error::io_error(destination.to_owned(), error))?;
    let mut buffer = vec![0u8; 128 * 1024];
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    loop {
        let read = input
            .read(&mut buffer)
            .await
            .map_err(|error| crate::error::io_error(source.to_owned(), error))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .await
            .map_err(|error| crate::error::io_error(destination.to_owned(), error))?;
        bytes = bytes.saturating_add(read as u64);
    }
    output
        .sync_all()
        .await
        .map_err(|error| crate::error::io_error(destination.to_owned(), error))?;
    Ok((bytes, hex::encode(hash.finalize())))
}

async fn native_credential_reference_count(connection: &turso::Connection) -> Result<u64> {
    let mut rows = connection
        .query(
            r#"SELECT COUNT(DISTINCT reference) FROM (
                SELECT credential_ref AS reference FROM accounts WHERE credential_ref LIKE 'lizard-credential:v1:native:%'
                UNION ALL
                SELECT credential_ref FROM smtp_accounts WHERE credential_ref LIKE 'lizard-credential:v1:native:%'
                UNION ALL
                SELECT credential_ref FROM calendar_accounts WHERE credential_ref LIKE 'lizard-credential:v1:native:%'
                UNION ALL
                SELECT credential_ref FROM openpgp_secret_key_providers WHERE credential_ref LIKE 'lizard-credential:v1:native:%'
            )"#,
            (),
        )
        .await?;
    let value = rows
        .next()
        .await?
        .expect("COUNT returns a row")
        .get::<i64>(0)?;
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput("invalid credential reference count".into()))
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BackendError::InvalidInput(
            "backup manifest contains an unsafe path".into(),
        ));
    }
    Ok(path)
}

fn relative_path_text(path: &Path) -> Result<String> {
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BackendError::InvalidInput(
            "path is not safely relative".into(),
        ));
    }
    path.to_str()
        .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| BackendError::InvalidInput("path is not UTF-8".into()))
}

fn mbox_manifest_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| BackendError::InvalidInput("mbox name is not UTF-8".into()))?;
    Ok(path.with_file_name(format!("{name}.lizard-export.json")))
}

async fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(_) => {
            return Err(BackendError::Conflict(format!(
                "destination already exists: {}",
                path.display()
            )))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(crate::error::io_error(path.to_owned(), source)),
    }
    Ok(())
}

async fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)
        .await
        .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| crate::error::io_error(path.to_owned(), error))?;
    }
    Ok(())
}

fn reject_nested_destination(source: &Path, destination: &Path) -> Result<()> {
    let source = std::fs::canonicalize(source)
        .map_err(|error| crate::error::io_error(source.to_owned(), error))?;
    let parent = destination
        .parent()
        .ok_or_else(|| BackendError::InvalidInput("destination has no parent".into()))?;
    let parent = std::fs::canonicalize(parent)
        .map_err(|error| crate::error::io_error(parent.to_owned(), error))?;
    let candidate = parent.join(
        destination
            .file_name()
            .ok_or_else(|| BackendError::InvalidInput("destination has no file name".into()))?,
    );
    if candidate.starts_with(&source) || source.starts_with(&candidate) {
        return Err(BackendError::InvalidInput(
            "source and destination profiles must not contain one another".into(),
        ));
    }
    Ok(())
}

fn parse_message_id(value: String) -> Result<MessageId> {
    value
        .parse()
        .map_err(|_| BackendError::InvalidInput("invalid message ID".into()))
}

async fn manifest_count(destination: &Path) -> Result<u64> {
    let manifest_path = destination.join(EXPORT_MANIFEST);
    let bytes = fs::read(&manifest_path)
        .await
        .map_err(|source| crate::error::io_error(manifest_path, source))?;
    let manifest: PortableManifest = serde_json::from_slice(&bytes)?;
    Ok(manifest.entries.len() as u64)
}
