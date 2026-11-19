use crate::authentication::DkimVerifier;
use crate::blob::BlobStore;
use crate::event::{ChangeCursor, EventSubscription};
use crate::imap::imap_fetch_headers;
use crate::mime;
use crate::query::parse_query;
use crate::schema;
use crate::search_index::{QueuedSearchDocument, SearchDocument, SearchIndex};
use crate::{
    Account, AccountId, AccountKind, Attachment, BackendConfig, BackendError, BackendEvent,
    Contact, ContactAddress, ContactId, ContentState, Folder, FolderId, FolderKind,
    ImapFetchedHeaders, ImapFetchedMessage, ImapSettings, InboxClass, IngestMessage, Message,
    MessageContentAvailability, MessageContentStatus, MessageFilter, MessageId, MessageInstance,
    MessageLink, MessageLinkSource, MessageSort, MessageSummary, NewAccount, NewContact, NewFolder,
    Page, ProviderSpamAssessment, ProviderSpamEvidence, ProviderSpamEvidenceSource,
    ProviderSpamVerdict, RemoteMessageIdentity, Result, SearchPage, SearchRequest,
    SpamEvidenceVerdict, SyncBatchResult, ThreadMembership, UserClassification,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures_util::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    mem,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, Mutex, RwLock};
use turso::{params_from_iter, Connection, Value};
use uuid::Uuid;

const MAX_INGEST_BATCH_MESSAGES: usize = 1_000;
const MAX_INGEST_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREPARE_CONCURRENCY: usize = 16;
const MAX_IMAP_METADATA_UIDS: usize = 100;
const IMAP_BODY_CHUNK_BYTES: usize = 1024 * 1024;

struct PreparedIngest {
    id: MessageId,
    remote: Option<RemoteMessageIdentity>,
    remote_flags_json: Option<String>,
    attachments: Vec<PreparedAttachment>,
    resources: Vec<PreparedResource>,
    mime_parts: Vec<crate::MimePart>,
    links: Vec<MessageLink>,
    threading: crate::thread::ThreadInput,
    stage: Option<StagedMessage>,
}

struct PreparedAttachment {
    metadata: Attachment,
    blob_hash: String,
    decode_problems_json: String,
}

struct PreparedResource {
    part_id: u32,
    blob_hash: String,
    decoded_size: u64,
}

pub(crate) struct DownloadAttemptGuard {
    backend: Backend,
    message_id: MessageId,
    armed: bool,
}

impl DownloadAttemptGuard {
    pub(crate) fn new(backend: Backend, message_id: MessageId) -> Self {
        Self {
            backend,
            message_id,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DownloadAttemptGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let backend = self.backend.clone();
        let message_id = self.message_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let Ok(status) = backend.messages().content_status(message_id).await else {
                    return;
                };
                if status.availability != MessageContentAvailability::Downloading {
                    return;
                }
                let path = backend.partial_download_path(message_id);
                if let Ok(file) = tokio::fs::OpenOptions::new().write(true).open(&path).await {
                    let _ = file.sync_all().await;
                }
                let downloaded = tokio::fs::metadata(path)
                    .await
                    .map(|metadata| metadata.len())
                    .unwrap_or(status.downloaded_bytes);
                let _ = backend
                    .store_download_failure(
                        message_id,
                        downloaded,
                        "message content download was cancelled; retry will resume",
                    )
                    .await;
            });
        }
    }
}

struct StagedMessage {
    blob_hash: String,
    rfc_message_id: Option<String>,
    subject: Option<String>,
    from_address: Option<String>,
    from_name: Option<String>,
    to_addresses: String,
    cc_addresses: String,
    bcc_addresses: String,
    sender_addresses: String,
    reply_to_addresses: String,
    delivered_to_addresses: String,
    list_id: Option<String>,
    body_text: String,
    body_html: Option<String>,
    preview: String,
    sent_at: Option<i64>,
    received_at: i64,
    size_bytes: i64,
    has_attachment: bool,
    attachment_names: String,
    is_read: bool,
    is_starred: bool,
    user_classification: Option<String>,
    content_state: String,
    search_metadata: String,
    dkim_json: String,
    delivery_auth_json: String,
    mime_state: String,
    mime_detail: Option<String>,
    content_availability: String,
    downloaded_bytes: i64,
    download_error: Option<String>,
    download_updated_at: i64,
    created_at: i64,
}

impl StagedMessage {
    fn staged_bytes(&self) -> usize {
        self.subject.as_ref().map_or(0, String::len)
            + self.from_address.as_ref().map_or(0, String::len)
            + self.from_name.as_ref().map_or(0, String::len)
            + self.to_addresses.len()
            + self.cc_addresses.len()
            + self.bcc_addresses.len()
            + self.sender_addresses.len()
            + self.reply_to_addresses.len()
            + self.delivered_to_addresses.len()
            + self.list_id.as_ref().map_or(0, String::len)
            + self.body_text.len()
            + self.body_html.as_ref().map_or(0, String::len)
            + self.attachment_names.len()
            + self.search_metadata.len()
            + self.dkim_json.len()
            + self.delivery_auth_json.len()
            + self.mime_detail.as_ref().map_or(0, String::len)
            + self.download_error.as_ref().map_or(0, String::len)
    }
}

#[derive(Clone)]
pub struct Backend {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) config: BackendConfig,
    _database: turso::Database,
    pub(crate) connection: Mutex<Connection>,
    pub(crate) search_index: Arc<SearchIndex>,
    /// Sandboxed synchronization workers enqueue search changes but never
    /// contend for the profile's exclusive Tantivy writer.
    pub(crate) search_deferred: bool,
    pub(crate) search_sync: RwLock<()>,
    /// Serializes physical blob collection against the interval between
    /// publishing a content-addressed file and committing its database
    /// reference. Readers are blob publishers; writers may delete or take a
    /// coherent profile snapshot.
    pub(crate) blob_references: RwLock<()>,
    pub(crate) blobs: BlobStore,
    pub(crate) storage: Arc<crate::storage::StorageBudget>,
    pub(crate) credentials: Arc<crate::credential::CredentialManager>,
    dkim_verifier: DkimVerifier,
    pub(crate) events: broadcast::Sender<BackendEvent>,
    download_locks: Mutex<HashMap<MessageId, Weak<Mutex<()>>>>,
    automation_reevaluation: Mutex<()>,
    automation_reevaluation_requested: AtomicBool,
}

impl Backend {
    pub async fn open(config: BackendConfig) -> Result<Self> {
        Self::open_internal(config, None).await
    }

    pub(crate) async fn open_sync_worker(
        config: BackendConfig,
        observed_storage: crate::StorageUsage,
    ) -> Result<Self> {
        Self::open_internal(config, Some(observed_storage)).await
    }

    async fn open_internal(
        config: BackendConfig,
        worker_storage: Option<crate::StorageUsage>,
    ) -> Result<Self> {
        let sync_worker = worker_storage.is_some();
        if !sync_worker {
            tokio::fs::create_dir_all(&config.profile_dir)
                .await
                .map_err(|source| crate::error::io_error(config.profile_dir.clone(), source))?;
            tokio::fs::create_dir_all(config.profile_dir.join("downloads"))
                .await
                .map_err(|source| {
                    crate::error::io_error(config.profile_dir.join("downloads"), source)
                })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(
                    &config.profile_dir,
                    std::fs::Permissions::from_mode(0o700),
                )
                .await
                .map_err(|source| BackendError::Io {
                    path: config.profile_dir.clone(),
                    source,
                })?;
            }
        }
        let database_path = config.profile_dir.join("mail.db");
        let database_path = database_path
            .to_str()
            .ok_or_else(|| BackendError::InvalidInput("profile path is not UTF-8".into()))?;
        let database = turso::Builder::new_local(database_path)
            .experimental_index_method(true)
            .build()
            .await?;
        let mut connection = database.connect()?;
        if !sync_worker {
            schema::migrate(&connection).await?;
            crate::spam::initialize(&mut connection).await?;
            crate::security::initialize(&mut connection).await?;
        }
        let search_index = if sync_worker {
            Arc::new(SearchIndex::create_deferred(&config.profile_dir)?)
        } else {
            prepare_search_index(&config.profile_dir, &mut connection).await?
        };
        let storage = match worker_storage {
            Some(usage) => crate::storage::StorageBudget::from_observed(
                config.profile_dir.clone(),
                config.storage_limits,
                usage,
            ),
            None => {
                crate::storage::StorageBudget::open(
                    config.profile_dir.clone(),
                    config.storage_limits,
                )
                .await?
            }
        };
        let blobs = BlobStore::open(config.profile_dir.join("blobs"), Arc::clone(&storage)).await?;
        let credentials = crate::credential::CredentialManager::new(
            &config.profile_dir,
            config.credential_storage,
        );
        let dkim_verifier = DkimVerifier::new(config.dkim_dns).map_err(|error| {
            BackendError::InvalidInput(format!("could not initialize DKIM resolver: {error}"))
        })?;
        let (events, _) = broadcast::channel(config.event_buffer.max(1));
        let backend = Self {
            inner: Arc::new(Inner {
                config,
                _database: database,
                connection: Mutex::new(connection),
                search_index,
                search_deferred: sync_worker,
                search_sync: RwLock::new(()),
                blob_references: RwLock::new(()),
                blobs,
                storage,
                credentials,
                dkim_verifier,
                events,
                download_locks: Mutex::new(HashMap::new()),
                automation_reevaluation: Mutex::new(()),
                automation_reevaluation_requested: AtomicBool::new(false),
            }),
        };
        if sync_worker {
            // The supervising process owns credential cleanup, search
            // publication and maintenance backfills.  Running them here
            // would widen the worker's authority and race the live backend.
            return Ok(backend);
        }
        backend.drain_credential_cleanup(64).await?;
        backend.recover_interrupted_downloads().await?;
        backend.backfill_sender_projection().await?;
        backend.backfill_delivery_authentication().await?;
        backend.backfill_thread_projection().await?;
        backend.backfill_mime_projection().await?;
        backend.heuristics().refresh_compiled_programs().await?;
        let (_, security_remaining) = backend.heuristics().backfill_builtin(64).await?;
        if security_remaining {
            backend.schedule_security_backfill();
        }
        let initial_spam = backend.spam_classifier().reclassify_pending(256).await?;
        if initial_spam.remaining > 0 {
            backend.schedule_spam_reclassification();
        }
        if backend.automation_backfill_required().await? {
            backend.schedule_automation_reevaluation();
        }
        Ok(backend)
    }

    fn schedule_security_backfill(&self) {
        let backend = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((processed, remaining)) = backend.heuristics().backfill_builtin(64).await
                else {
                    break;
                };
                if processed == 0 || !remaining {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
    }

    /// Version thirteen separates the RFC 5322 Sender field from From. Raw
    /// immutable headers are reparsed in small chunks; `NULL` is used only as
    /// an upgrade marker, while a real message with no Sender stores `[]`.
    async fn backfill_sender_projection(&self) -> Result<()> {
        loop {
            let missing = {
                let connection = self.inner.connection.lock().await;
                let mut rows = connection
                    .query(
                        "SELECT id, blob_hash FROM messages WHERE sender_addresses IS NULL ORDER BY id LIMIT 100",
                        (),
                    )
                    .await?;
                let mut missing = Vec::new();
                while let Some(row) = rows.next().await? {
                    missing.push((
                        parse_id::<MessageId>(row.get(0)?, "message")?,
                        row.get::<String>(1)?,
                    ));
                }
                missing
            };
            if missing.is_empty() {
                return Ok(());
            }
            let mut projected = Vec::with_capacity(missing.len());
            for (message_id, blob_hash) in missing {
                let raw = self.inner.blobs.get(&blob_hash).await?;
                let parsed = mime::parse_thread_headers(&raw)?;
                projected.push((message_id, serde_json::to_string(&parsed.sender_addresses)?));
            }
            let mut connection = self.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (message_id, sender_addresses) in projected {
                transaction
                    .execute(
                        "UPDATE messages SET sender_addresses = ?1 WHERE id = ?2 AND sender_addresses IS NULL",
                        (sender_addresses, message_id.to_string()),
                    )
                    .await?;
            }
            transaction.commit().await?;
        }
    }

    /// Version fourteen materializes every Authentication-Results copy from
    /// immutable bytes. Account policy is applied separately so a header can
    /// never become trusted merely because it exists in the message.
    async fn backfill_delivery_authentication(&self) -> Result<()> {
        loop {
            let missing = {
                let connection = self.inner.connection.lock().await;
                let mut rows = connection
                    .query(
                        "SELECT id, blob_hash FROM messages WHERE delivery_auth_json IS NULL ORDER BY id LIMIT 100",
                        (),
                    )
                    .await?;
                let mut missing = Vec::new();
                while let Some(row) = rows.next().await? {
                    missing.push((
                        parse_id::<MessageId>(row.get(0)?, "message")?,
                        row.get::<String>(1)?,
                    ));
                }
                missing
            };
            if missing.is_empty() {
                return Ok(());
            }
            let mut projected = Vec::with_capacity(missing.len());
            for (message_id, blob_hash) in missing {
                let account_ids = {
                    let connection = self.inner.connection.lock().await;
                    let mut rows = connection
                        .query(
                            "SELECT DISTINCT account_id FROM message_instances WHERE message_id = ?1 ORDER BY account_id",
                            (message_id.to_string(),),
                        )
                        .await?;
                    let mut values = Vec::new();
                    while let Some(row) = rows.next().await? {
                        values.push(parse_id::<AccountId>(row.get(0)?, "account")?);
                    }
                    values
                };
                let raw = self.inner.blobs.get(&blob_hash).await?;
                let evidence = self.delivery_authentication_for(&raw, &account_ids).await?;
                projected.push((message_id, serde_json::to_string(&evidence)?));
            }
            let mut connection = self.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (message_id, evidence) in projected {
                transaction
                    .execute(
                        "UPDATE messages SET delivery_auth_json = ?1 WHERE id = ?2 AND delivery_auth_json IS NULL",
                        (evidence, message_id.to_string()),
                    )
                    .await?;
            }
            transaction.commit().await?;
        }
    }

    async fn delivery_authentication_for(
        &self,
        raw: &[u8],
        account_ids: &[AccountId],
    ) -> Result<crate::DeliveryAuthentication> {
        let mut sources = Vec::with_capacity(account_ids.len());
        if !account_ids.is_empty() {
            let connection = self.inner.connection.lock().await;
            for account_id in account_ids {
                let mut rows = connection
                    .query(
                        "SELECT trusted_authserv_ids_json FROM accounts WHERE id = ?1",
                        (account_id.to_string(),),
                    )
                    .await?;
                let row = rows
                    .next()
                    .await?
                    .ok_or_else(|| not_found("account", account_id))?;
                sources.push((
                    Some(*account_id),
                    serde_json::from_str(&row.get::<String>(0)?)?,
                ));
            }
        }
        Ok(crate::delivery_auth::parse(raw, &sources))
    }

    pub(crate) async fn blob_is_referenced(&self, hash: &str) -> Result<bool> {
        let connection = self.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT
                    EXISTS(SELECT 1 FROM messages WHERE blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM mime_part_blobs WHERE blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM attachments WHERE blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM draft_attachments WHERE blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM submissions WHERE raw_blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM sent_reconciliation WHERE blob_hash = ?1) OR
                    EXISTS(SELECT 1 FROM openpgp_decrypted_messages WHERE decrypted_blob_hash = ?1)"#,
                (hash,),
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .is_some_and(|row| row.get::<bool>(0).unwrap_or(true)))
    }

    fn schedule_spam_reclassification(&self) {
        let backend = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok(batch) = backend.spam_classifier().reclassify_pending(128).await else {
                    break;
                };
                if batch.processed == 0 || batch.remaining == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
    }

    pub(crate) fn schedule_automation_reevaluation(&self) {
        self.inner
            .automation_reevaluation_requested
            .store(true, Ordering::Release);
        let backend = self.clone();
        tokio::spawn(async move {
            let Ok(_guard) = backend.inner.automation_reevaluation.try_lock() else {
                return;
            };
            loop {
                if !backend
                    .inner
                    .automation_reevaluation_requested
                    .swap(false, Ordering::AcqRel)
                {
                    break;
                }
                let Ok(_) = backend.filter_rules().reevaluate_stale(usize::MAX).await else {
                    break;
                };
                let Ok(_) = backend.heuristics().reevaluate_stale(usize::MAX).await else {
                    break;
                };
                tokio::task::yield_now().await;
            }
        });
    }

    pub(crate) fn schedule_heuristic_reevaluation(&self) {
        let backend = self.clone();
        tokio::spawn(async move {
            let _guard = backend.inner.automation_reevaluation.lock().await;
            let _ = backend.heuristics().reevaluate_stale(usize::MAX).await;
        });
    }

    async fn automation_backfill_required(&self) -> Result<bool> {
        let connection = self.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT
                    EXISTS(
                        SELECT 1 FROM heuristic_evaluations
                        WHERE compiler_version != ?1 OR evidence_revision = ''
                    ) OR EXISTS(
                        SELECT 1 FROM messages m
                        JOIN heuristics h ON h.enabled = 1 AND h.deleted_at IS NULL
                        WHERE NOT EXISTS (
                            SELECT 1 FROM heuristic_evaluations e
                            WHERE e.message_id = m.id AND e.heuristic_id = h.id
                                AND e.heuristic_version = h.version
                        ) LIMIT 1
                    ) OR EXISTS(
                        SELECT 1 FROM messages m
                        JOIN filter_rules r ON r.enabled = 1 AND r.deleted_at IS NULL
                        WHERE NOT EXISTS (
                            SELECT 1 FROM filter_rule_evaluations e
                            WHERE e.message_id = m.id AND e.rule_id = r.id
                                AND e.rule_revision = r.revision
                        ) LIMIT 1
                    )"#,
                (i64::from(crate::heuristic::HEURISTIC_COMPILER_VERSION),),
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get::<bool>(0))
            .transpose()?
            .unwrap_or(false))
    }

    async fn recover_interrupted_downloads(&self) -> Result<()> {
        let interrupted = {
            let connection = self.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT id, size_bytes, downloaded_bytes FROM messages WHERE content_availability = 'downloading'",
                    (),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push((
                    parse_id::<MessageId>(row.get(0)?, "message")?,
                    u64::try_from(row.get::<i64>(1)?).map_err(|_| {
                        BackendError::InvalidInput("database contains invalid message size".into())
                    })?,
                    u64::try_from(row.get::<i64>(2)?).map_err(|_| {
                        BackendError::InvalidInput(
                            "database contains invalid downloaded byte count".into(),
                        )
                    })?,
                ));
            }
            values
        };
        for (message_id, expected, recorded) in interrupted {
            let path = self.partial_download_path(message_id);
            let downloaded = tokio::fs::metadata(&path)
                .await
                .map(|metadata| metadata.len().min(expected).min(recorded))
                .unwrap_or(0);
            if let Ok(file) = tokio::fs::OpenOptions::new().write(true).open(&path).await {
                file.set_len(downloaded)
                    .await
                    .map_err(|source| BackendError::Io {
                        path: path.clone(),
                        source,
                    })?;
            }
            self.store_download_failure(
                message_id,
                downloaded,
                "download was interrupted; retry will resume from the durable prefix",
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) fn partial_download_path(&self, message_id: MessageId) -> std::path::PathBuf {
        self.inner
            .config
            .profile_dir
            .join("downloads")
            .join(format!("{message_id}.part"))
    }

    pub fn accounts(&self) -> Accounts {
        Accounts(self.clone())
    }

    pub fn calendar_accounts(&self) -> crate::CalendarAccounts {
        crate::CalendarAccounts::new(self.clone())
    }

    pub fn calendars(&self) -> crate::Calendars {
        crate::Calendars::new(self.clone())
    }

    pub fn caldav_engine(
        &self,
        credentials: Arc<dyn crate::CalDavCredentialProvider>,
        config: crate::CalDavEngineConfig,
    ) -> Result<crate::CalDavEngine> {
        crate::CalDavEngine::new(self.clone(), credentials, config)
    }

    pub fn managed_caldav_engine(
        &self,
        config: crate::CalDavEngineConfig,
    ) -> Result<crate::CalDavEngine> {
        self.caldav_engine(Arc::new(self.credentials()), config)
    }

    pub fn account_identities(&self) -> crate::AccountIdentities {
        crate::AccountIdentities::new(self.clone())
    }

    pub fn data_lifecycle(&self) -> crate::DataLifecycle {
        crate::DataLifecycle::new(self.clone())
    }

    pub fn storage(&self) -> crate::Storage {
        crate::Storage::new(self.clone())
    }

    pub fn openpgp(&self) -> crate::OpenPgp {
        crate::OpenPgp::new(self.clone())
    }

    pub fn credentials(&self) -> crate::Credentials {
        crate::Credentials::new(Arc::clone(&self.inner.credentials))
    }

    /// A ready-to-use provider for the IMAP and SMTP engines. References
    /// belonging to external providers still require their own adapter.
    pub fn credential_provider(&self) -> Arc<dyn crate::CredentialProvider> {
        Arc::new(self.credentials())
    }

    pub(crate) async fn queue_managed_credential_cleanup_on(
        &self,
        connection: &Connection,
        reference: &str,
        now: i64,
    ) -> Result<bool> {
        if !self.inner.credentials.manages(reference)? {
            return Ok(false);
        }
        let mut rows = connection
            .query(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE credential_ref = ?1), EXISTS(SELECT 1 FROM smtp_accounts WHERE credential_ref = ?1), EXISTS(SELECT 1 FROM calendar_accounts WHERE credential_ref = ?1), EXISTS(SELECT 1 FROM openpgp_secret_key_providers WHERE credential_ref = ?1)",
                (reference,),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| {
            BackendError::CredentialStore("could not check credential ownership".into())
        })?;
        let shared = row.get::<bool>(0)?
            || row.get::<bool>(1)?
            || row.get::<bool>(2)?
            || row.get::<bool>(3)?;
        drop(rows);
        if shared {
            return Ok(false);
        }
        connection
            .execute(
                "INSERT INTO credential_cleanup_queue(reference, queued_at, attempts) VALUES (?1, ?2, 0) ON CONFLICT(reference) DO NOTHING",
                (reference, now),
            )
            .await?;
        Ok(true)
    }

    pub(crate) async fn drain_credential_cleanup(&self, limit: usize) -> Result<usize> {
        let limit = i64::try_from(limit).map_err(|_| {
            BackendError::InvalidInput("credential cleanup limit is too large".into())
        })?;
        let references = {
            let connection = self.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT reference FROM credential_cleanup_queue ORDER BY queued_at, reference LIMIT ?1",
                    (limit,),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push(row.get::<String>(0)?);
            }
            values
        };
        for reference in references {
            let result = self.inner.credentials.delete_if_managed(&reference).await;
            let connection = self.inner.connection.lock().await;
            match result {
                Ok(_) => {
                    connection
                        .execute(
                            "DELETE FROM credential_cleanup_queue WHERE reference = ?1",
                            (reference,),
                        )
                        .await?;
                }
                Err(error) => {
                    let detail = error.to_string();
                    let detail = detail.chars().take(1_024).collect::<String>();
                    connection
                        .execute(
                            "UPDATE credential_cleanup_queue SET attempts = attempts + 1, last_error = ?1 WHERE reference = ?2",
                            (detail, reference),
                        )
                        .await?;
                }
            }
        }
        let connection = self.inner.connection.lock().await;
        let mut rows = connection
            .query("SELECT count(*) FROM credential_cleanup_queue", ())
            .await?;
        let remaining = rows
            .next()
            .await?
            .ok_or_else(|| {
                BackendError::CredentialStore("credential cleanup count returned no row".into())
            })?
            .get::<i64>(0)?;
        usize::try_from(remaining).map_err(|_| {
            BackendError::CredentialStore("credential cleanup count is invalid".into())
        })
    }

    pub fn folders(&self) -> Folders {
        Folders(self.clone())
    }

    pub fn messages(&self) -> Messages {
        Messages(self.clone())
    }

    pub fn mime(&self) -> crate::Mime {
        crate::Mime::new(self.clone())
    }

    pub fn threads(&self) -> crate::Threads {
        crate::Threads::new(self.clone())
    }

    pub fn sending(&self) -> crate::Sending {
        crate::Sending::new(self.clone())
    }

    pub fn drafts(&self) -> crate::Drafts {
        crate::Drafts::new(self.clone())
    }

    pub fn outbox(&self) -> crate::Outbox {
        crate::Outbox::new(self.clone())
    }

    pub fn contacts(&self) -> Contacts {
        Contacts(self.clone())
    }

    pub fn onboarding(&self) -> crate::Onboarding {
        crate::Onboarding::new(self.clone())
    }

    pub fn search(&self) -> Search {
        Search(self.clone())
    }

    pub fn saved_searches(&self) -> crate::SavedSearches {
        crate::SavedSearches::new(self.clone())
    }

    pub fn events(&self) -> Events {
        Events(self.clone())
    }

    pub fn filter_rules(&self) -> crate::FilterRules {
        crate::FilterRules::new(self.clone())
    }

    pub fn heuristics(&self) -> crate::Heuristics {
        crate::Heuristics::new(self.clone())
    }

    pub fn spam_classifier(&self) -> crate::SpamClassifier {
        crate::SpamClassifier::new(self.clone())
    }

    /// Explicit user-present pass for encrypted mail. Each message is
    /// decrypted once, then the authenticated in-memory view is shared by all
    /// filters and heuristics. Tantivy is never consulted for correctness.
    pub async fn evaluate_encrypted_automation(
        &self,
        message_ids: &[MessageId],
    ) -> crate::EncryptedAutomationReport {
        // Suppress the background stale worker while the transient plaintext
        // view is in use; otherwise it could race this pass and persist a
        // pending-decryption result after the exact manual result.
        let _reevaluation_guard = self.inner.automation_reevaluation.lock().await;
        let mut report = crate::EncryptedAutomationReport {
            evaluated_messages: Vec::new(),
            filter_applications: 0,
            heuristic_findings: 0,
            failures: Vec::new(),
        };
        let mut seen = HashSet::new();
        for message_id in message_ids.iter().copied() {
            if !seen.insert(message_id) {
                continue;
            }
            let result = async {
                let decrypted = self.openpgp().decrypt_message(message_id).await?;
                let applications = self
                    .filter_rules()
                    .evaluate_message_with_decrypted(message_id, &decrypted)
                    .await?;
                let findings = self
                    .heuristics()
                    .evaluate_message_with_decrypted(message_id, &decrypted)
                    .await?;
                Ok::<_, BackendError>((applications.len(), findings.len()))
            }
            .await;
            match result {
                Ok((applications, findings)) => {
                    report.evaluated_messages.push(message_id);
                    report.filter_applications += applications as u64;
                    report.heuristic_findings += findings as u64;
                }
                Err(error) => report.failures.push(crate::AutomationEvaluationFailure {
                    message_id,
                    detail: error.to_string(),
                }),
            }
        }
        drop(_reevaluation_guard);
        report
    }

    pub fn sync(&self) -> Sync {
        Sync(self.clone())
    }

    pub fn imap_mutations(&self) -> crate::ImapMutations {
        crate::ImapMutations::new(self.clone())
    }

    pub fn imap_account_engine(
        &self,
        credentials: Arc<dyn crate::CredentialProvider>,
        config: crate::ImapAccountEngineConfig,
    ) -> Result<crate::ImapAccountEngine> {
        crate::ImapAccountEngine::new(self.clone(), credentials, config)
    }

    pub fn managed_imap_account_engine(
        &self,
        config: crate::ImapAccountEngineConfig,
    ) -> Result<crate::IsolatedImapAccountEngine> {
        self.isolated_imap_account_engine(
            self.credential_provider(),
            config,
            crate::ImapSyncIsolationConfig::default(),
        )
    }

    pub fn isolated_imap_account_engine(
        &self,
        credentials: Arc<dyn crate::CredentialProvider>,
        config: crate::ImapAccountEngineConfig,
        isolation: crate::ImapSyncIsolationConfig,
    ) -> Result<crate::IsolatedImapAccountEngine> {
        crate::IsolatedImapAccountEngine::new(self.clone(), credentials, config, isolation)
    }

    /// Explicit escape hatch for embedders which cannot launch the fail-closed
    /// worker.  Applications should normally use
    /// [`Backend::managed_imap_account_engine`].
    pub fn managed_imap_account_engine_in_process(
        &self,
        config: crate::ImapAccountEngineConfig,
    ) -> Result<crate::ImapAccountEngine> {
        self.imap_account_engine(self.credential_provider(), config)
    }

    pub async fn smtp_engine(
        &self,
        credentials: Arc<dyn crate::CredentialProvider>,
        config: crate::SmtpEngineConfig,
    ) -> Result<crate::SmtpEngine> {
        crate::SmtpEngine::new(self.clone(), credentials, config).await
    }

    pub async fn managed_smtp_engine(
        &self,
        config: crate::SmtpEngineConfig,
    ) -> Result<crate::SmtpEngine> {
        self.smtp_engine(self.credential_provider(), config).await
    }

    /// Store an exact RFC 5322 message. Protocol adapters should call this
    /// method rather than introducing a second parsing/indexing path.
    pub async fn ingest(&self, request: IngestMessage) -> Result<MessageId> {
        self.ingest_batch(vec![request])
            .await?
            .pop()
            .ok_or_else(|| BackendError::InvalidInput("ingest batch was empty".into()))
    }

    /// Store messages in bounded transactions, then synchronously publish each
    /// committed chunk through the crash-replayable Tantivy outbox. Results
    /// preserve input order. Chunks committed before a later parse failure
    /// remain committed.
    pub async fn ingest_batch(&self, requests: Vec<IngestMessage>) -> Result<Vec<MessageId>> {
        let mut remote_keys = HashSet::new();
        for request in &requests {
            if request.raw.len() > self.inner.config.limits.max_message_bytes {
                return Err(BackendError::MessageTooLarge {
                    actual: request.raw.len(),
                    limit: self.inner.config.limits.max_message_bytes,
                });
            }
            if let Some(remote) = &request.remote {
                if remote.uid == 0 {
                    return Err(BackendError::InvalidInput(
                        "remote message UIDs must be non-zero".into(),
                    ));
                }
                if !remote_keys.insert((remote.folder_id, remote.uid_validity, remote.uid)) {
                    return Err(BackendError::InvalidInput(
                        "an ingest batch cannot contain a duplicate remote UID".into(),
                    ));
                }
            }
        }

        let mut account_growth = HashMap::<AccountId, u64>::new();
        {
            let connection = self.inner.connection.lock().await;
            for request in &requests {
                let Some(remote) = &request.remote else {
                    continue;
                };
                if lookup_remote_on(
                    &connection,
                    remote.folder_id,
                    remote.uid_validity,
                    remote.uid,
                )
                .await?
                .is_some()
                {
                    continue;
                }
                let bytes = u64::try_from(request.raw.len()).unwrap_or(u64::MAX);
                let total = account_growth.entry(remote.account_id).or_default();
                *total = total.saturating_add(bytes);
            }
            for (account_id, requested) in account_growth {
                crate::storage::ensure_account_capacity_on(&connection, account_id, requested)
                    .await?;
            }
        }

        let blob_guard = self.inner.blob_references.read().await;
        let mut message_ids = Vec::with_capacity(requests.len());
        let mut batch = Vec::new();
        let mut staged_bytes = 0usize;
        let mut preparations = stream::iter(
            requests
                .into_iter()
                .map(|request| self.prepare_ingest(request)),
        )
        .buffered(MAX_PREPARE_CONCURRENCY);
        while let Some(prepared) = preparations.next().await {
            let prepared = prepared?;
            let message_bytes = prepared
                .stage
                .as_ref()
                .map_or(0, StagedMessage::staged_bytes);
            if !batch.is_empty()
                && (batch.len() >= MAX_INGEST_BATCH_MESSAGES
                    || staged_bytes.saturating_add(message_bytes) > MAX_INGEST_BATCH_BYTES)
            {
                message_ids.extend(self.commit_prepared_batch(mem::take(&mut batch)).await?);
                staged_bytes = 0;
            }
            staged_bytes = staged_bytes.saturating_add(message_bytes);
            batch.push(prepared);
        }
        if !batch.is_empty() {
            message_ids.extend(self.commit_prepared_batch(batch).await?);
        }
        drop(blob_guard);
        self.openpgp().refresh_messages(&message_ids).await?;
        self.evaluate_automation(&message_ids).await?;
        Ok(message_ids)
    }

    async fn evaluate_automation(&self, message_ids: &[MessageId]) -> Result<()> {
        let mut evaluated = HashSet::new();
        let run_filters = self.filter_rules().has_enabled().await?;
        let run_heuristics = self.heuristics().has_enabled().await?;
        for message_id in message_ids {
            if !evaluated.insert(*message_id) {
                continue;
            }
            if run_filters {
                self.filter_rules().evaluate_message(*message_id).await?;
            }
            if run_heuristics {
                self.heuristics().evaluate_message(*message_id).await?;
            }
        }
        Ok(())
    }

    async fn prepare_ingest(&self, request: IngestMessage) -> Result<PreparedIngest> {
        let size_bytes = request.raw.len() as i64;
        let parsed = mime::parse(&request.raw, &self.inner.config.limits)?;
        let source_accounts = request
            .remote
            .as_ref()
            .map(|remote| vec![remote.account_id])
            .unwrap_or_default();
        let delivery_auth_json = serde_json::to_string(
            &self
                .delivery_authentication_for(&request.raw, &source_accounts)
                .await?,
        )?;
        let blob_hash = self.inner.blobs.put(&request.raw).await?;
        let id = MessageId::new();
        let now = Utc::now().timestamp();
        let dkim_json =
            serde_json::to_string(&self.inner.dkim_verifier.verify(&request.raw, now).await)?;
        let received_at = request.received_at.or(parsed.sent_at).unwrap_or(now);
        let threading = crate::thread::ThreadInput::new(
            parsed.rfc_message_id.as_deref(),
            &parsed.in_reply_to,
            &parsed.references,
            parsed.subject.as_deref(),
            parsed.from_address.as_deref(),
            &parsed.to_addresses,
            &parsed.cc_addresses,
            &parsed.bcc_addresses,
            &parsed.reply_to_addresses,
            &parsed.delivered_to_addresses,
            received_at,
        );
        let attachment_names = parsed
            .attachments
            .iter()
            .filter_map(|attachment| attachment.metadata.name.as_deref())
            .collect::<Vec<_>>()
            .join(" ");
        let has_attachment = !parsed.attachments.is_empty();
        let mut resources = Vec::with_capacity(parsed.resources.len());
        let mut resource_hashes = HashMap::with_capacity(parsed.resources.len());
        for resource in parsed.resources {
            let decoded_size = resource.bytes.len() as u64;
            let blob_hash = self.inner.blobs.put(&resource.bytes).await?;
            resource_hashes.insert(resource.part_id, blob_hash.clone());
            resources.push(PreparedResource {
                part_id: resource.part_id,
                blob_hash,
                decoded_size,
            });
        }
        let attachments = parsed
            .attachments
            .into_iter()
            .map(|attachment| {
                let blob_hash = resource_hashes
                    .get(&attachment.metadata.mime_part_id)
                    .cloned()
                    .ok_or_else(|| {
                        BackendError::InvalidInput(
                            "parsed attachment is missing its decoded resource".into(),
                        )
                    })?;
                Ok(PreparedAttachment {
                    metadata: attachment.metadata,
                    blob_hash,
                    decode_problems_json: serde_json::to_string(&attachment.decode_problems)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut remote = request.remote;
        if let Some(remote) = &mut remote {
            remote.flags = canonical_flags(&remote.flags);
        }
        let remote_flags_json = remote
            .as_ref()
            .map(|remote| serde_json::to_string(&remote.flags))
            .transpose()?;
        let (is_read, is_starred) = remote
            .as_ref()
            .map(|remote| {
                (
                    remote
                        .flags
                        .iter()
                        .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
                    remote
                        .flags
                        .iter()
                        .any(|flag| flag.eq_ignore_ascii_case("\\Flagged")),
                )
            })
            .unwrap_or((false, false));
        let stage = StagedMessage {
            blob_hash,
            rfc_message_id: parsed.rfc_message_id,
            subject: parsed.subject,
            from_address: parsed.from_address,
            from_name: parsed.from_name,
            to_addresses: serde_json::to_string(&parsed.to_addresses)?,
            cc_addresses: serde_json::to_string(&parsed.cc_addresses)?,
            bcc_addresses: serde_json::to_string(&parsed.bcc_addresses)?,
            sender_addresses: serde_json::to_string(&parsed.sender_addresses)?,
            reply_to_addresses: serde_json::to_string(&parsed.reply_to_addresses)?,
            delivered_to_addresses: serde_json::to_string(&parsed.delivered_to_addresses)?,
            list_id: parsed.list_id,
            body_text: parsed.body_text,
            body_html: parsed.body_html,
            preview: parsed.preview,
            sent_at: parsed.sent_at,
            received_at,
            size_bytes,
            has_attachment,
            attachment_names,
            is_read,
            is_starred,
            user_classification: request
                .user_classification
                .map(classification_text)
                .map(str::to_owned),
            content_state: content_state_text(parsed.content_state).to_owned(),
            search_metadata: json!({"received_at": received_at}).to_string(),
            dkim_json,
            delivery_auth_json,
            mime_state: mime_parse_state_text(parsed.mime_state).to_owned(),
            mime_detail: parsed.mime_detail,
            content_availability: content_availability_text(MessageContentAvailability::Complete)
                .to_owned(),
            downloaded_bytes: size_bytes,
            download_error: None,
            download_updated_at: now,
            created_at: now,
        };
        Ok(PreparedIngest {
            id,
            remote,
            remote_flags_json,
            attachments,
            resources,
            mime_parts: parsed.mime_parts,
            links: parsed.links,
            threading,
            stage: Some(stage),
        })
    }

    async fn prepare_imap_headers(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        message: ImapFetchedHeaders,
    ) -> Result<PreparedIngest> {
        if message.headers.len() > self.inner.config.limits.max_header_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: message.headers.len(),
                limit: self.inner.config.limits.max_header_bytes,
            });
        }
        let parsed = mime::parse(&message.headers, &self.inner.config.limits)?;
        let delivery_auth_json = serde_json::to_string(
            &self
                .delivery_authentication_for(&message.headers, &[account_id])
                .await?,
        )?;
        let blob_hash = self.inner.blobs.put(&message.headers).await?;
        let id = MessageId::new();
        let now = Utc::now().timestamp();
        let received_at = message.internal_date.or(parsed.sent_at).unwrap_or(now);
        let threading = crate::thread::ThreadInput::new(
            parsed.rfc_message_id.as_deref(),
            &parsed.in_reply_to,
            &parsed.references,
            parsed.subject.as_deref(),
            parsed.from_address.as_deref(),
            &parsed.to_addresses,
            &parsed.cc_addresses,
            &parsed.bcc_addresses,
            &parsed.reply_to_addresses,
            &parsed.delivered_to_addresses,
            received_at,
        );
        let mut remote = RemoteMessageIdentity {
            account_id,
            folder_id,
            uid_validity,
            uid: message.uid,
            mod_sequence: message.mod_sequence,
            flags: message.flags,
        };
        remote.flags = canonical_flags(&remote.flags);
        let is_read = remote
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"));
        let is_starred = remote
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"));
        let remote_flags_json = serde_json::to_string(&remote.flags)?;
        let dkim_json = serde_json::to_string(&crate::DkimAuthentication {
            status: crate::DkimAuthenticationStatus::NotEvaluated,
            signatures: Vec::new(),
            evaluated_at: now,
            detail: Some("complete message content has not been downloaded".into()),
        })?;
        let size_bytes = i64::from(message.size_bytes);
        let stage = StagedMessage {
            blob_hash,
            rfc_message_id: parsed.rfc_message_id,
            subject: parsed.subject,
            from_address: parsed.from_address,
            from_name: parsed.from_name,
            to_addresses: serde_json::to_string(&parsed.to_addresses)?,
            cc_addresses: serde_json::to_string(&parsed.cc_addresses)?,
            bcc_addresses: serde_json::to_string(&parsed.bcc_addresses)?,
            sender_addresses: serde_json::to_string(&parsed.sender_addresses)?,
            reply_to_addresses: serde_json::to_string(&parsed.reply_to_addresses)?,
            delivered_to_addresses: serde_json::to_string(&parsed.delivered_to_addresses)?,
            list_id: parsed.list_id,
            body_text: String::new(),
            body_html: None,
            preview: String::new(),
            sent_at: parsed.sent_at,
            received_at,
            size_bytes,
            has_attachment: message.has_attachment,
            attachment_names: String::new(),
            is_read,
            is_starred,
            user_classification: None,
            content_state: content_state_text(crate::ContentState::Complete).to_owned(),
            search_metadata: json!({"received_at": received_at}).to_string(),
            dkim_json,
            delivery_auth_json,
            mime_state: mime_parse_state_text(crate::MimeParseState::Limited).to_owned(),
            mime_detail: Some(
                "MIME tree is unavailable until message content is downloaded".into(),
            ),
            content_availability: content_availability_text(
                MessageContentAvailability::HeadersOnly,
            )
            .to_owned(),
            downloaded_bytes: 0,
            download_error: None,
            download_updated_at: now,
            created_at: now,
        };
        Ok(PreparedIngest {
            id,
            remote: Some(remote),
            remote_flags_json: Some(remote_flags_json),
            attachments: Vec::new(),
            resources: Vec::new(),
            mime_parts: Vec::new(),
            links: Vec::new(),
            threading,
            stage: Some(stage),
        })
    }

    async fn download_lock(&self, message_id: MessageId) -> Arc<Mutex<()>> {
        let mut locks = self.inner.download_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&message_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(message_id, Arc::downgrade(&lock));
        lock
    }

    async fn store_download_started(
        &self,
        message_id: MessageId,
        downloaded_bytes: u64,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT downloaded_bytes FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            drop(rows);
            transaction.rollback().await?;
            return Err(not_found("message", message_id));
        };
        let previous_bytes = u64::try_from(row.get::<i64>(0)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid downloaded byte count".into())
        })?;
        drop(rows);
        let growth = downloaded_bytes.saturating_sub(previous_bytes);
        if growth > 0 {
            let mut rows = transaction
                .query(
                    "SELECT DISTINCT account_id FROM message_instances WHERE message_id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
            let mut account_ids = Vec::new();
            while let Some(row) = rows.next().await? {
                account_ids.push(parse_id::<AccountId>(row.get(0)?, "account")?);
            }
            drop(rows);
            for account_id in account_ids {
                crate::storage::ensure_account_capacity_on(&transaction, account_id, growth)
                    .await?;
            }
        }
        let changed = transaction
            .execute(
                "UPDATE messages SET content_availability = 'downloading', downloaded_bytes = ?1, download_error = NULL, download_updated_at = ?2 WHERE id = ?3 AND content_availability != 'complete'",
                (
                    i64::try_from(downloaded_bytes).unwrap_or(i64::MAX),
                    now,
                    message_id.to_string(),
                ),
            )
            .await?;
        if changed == 0 {
            let status = load_content_status_on(&transaction, message_id).await?;
            transaction.rollback().await?;
            if status.availability != MessageContentAvailability::Complete {
                return Err(BackendError::Conflict(
                    "message content state changed before download started".into(),
                ));
            }
            return Ok(());
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn store_download_failure(
        &self,
        message_id: MessageId,
        downloaded_bytes: u64,
        detail: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE messages SET content_availability = 'failed', downloaded_bytes = MIN(size_bytes, ?1), download_error = ?2, download_updated_at = ?3 WHERE id = ?4 AND content_availability != 'complete'",
                (
                    i64::try_from(downloaded_bytes).unwrap_or(i64::MAX),
                    detail.to_owned(),
                    now,
                    message_id.to_string(),
                ),
            )
            .await?;
        if changed == 0 {
            let mut rows = transaction
                .query(
                    "SELECT 1 FROM messages WHERE id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
            if rows.next().await?.is_none() {
                transaction.rollback().await?;
                return Err(not_found("message", message_id));
            }
            transaction.rollback().await?;
            return Ok(());
        }
        let event = insert_event(
            &transaction,
            now,
            "message_download_failed",
            message_id.to_string(),
            json!({
                "message_id": message_id,
                "downloaded_bytes": downloaded_bytes,
                "detail": detail,
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.inner.events.send(event);
        Ok(())
    }

    async fn hydrate_downloaded_message(
        &self,
        message_id: MessageId,
        path: &std::path::Path,
        expected_bytes: u64,
    ) -> Result<MessageContentStatus> {
        if expected_bytes > self.inner.config.limits.max_message_bytes as u64 {
            return Err(BackendError::MessageTooLarge {
                actual: usize::try_from(expected_bytes).unwrap_or(usize::MAX),
                limit: self.inner.config.limits.max_message_bytes,
            });
        }
        let raw = tokio::fs::read(path)
            .await
            .map_err(|source| BackendError::Io {
                path: path.to_owned(),
                source,
            })?;
        if raw.len() as u64 != expected_bytes {
            return Err(BackendError::Conflict(format!(
                "downloaded message contains {} bytes; expected {expected_bytes}",
                raw.len()
            )));
        }
        let (received_at, previous_blob_hash, account_ids) = {
            let connection = self.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT received_at, blob_hash FROM messages WHERE id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
            let row = rows
                .next()
                .await?
                .ok_or_else(|| not_found("message", message_id))?;
            let received_at = row.get::<i64>(0)?;
            let previous_blob_hash = row.get::<String>(1)?;
            drop(rows);
            let mut rows = connection
                .query(
                    "SELECT DISTINCT account_id FROM message_instances WHERE message_id = ?1 ORDER BY account_id",
                    (message_id.to_string(),),
                )
                .await?;
            let mut account_ids = Vec::new();
            while let Some(row) = rows.next().await? {
                account_ids.push(parse_id::<AccountId>(row.get(0)?, "account")?);
            }
            (received_at, previous_blob_hash, account_ids)
        };
        let delivery_auth_json =
            serde_json::to_string(&self.delivery_authentication_for(&raw, &account_ids).await?)?;
        let blob_guard = self.inner.blob_references.read().await;
        let mut prepared = self
            .prepare_ingest(IngestMessage {
                raw,
                remote: None,
                received_at: Some(received_at),
                user_classification: None,
            })
            .await?;
        let stage = prepared
            .stage
            .as_mut()
            .expect("complete projection has staged message data");
        stage.delivery_auth_json = delivery_auth_json;
        let stage = prepared
            .stage
            .take()
            .expect("complete projection has staged message data");
        let _search_guard = self.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                r#"UPDATE messages SET
                    blob_hash = ?1, rfc_message_id = ?2, subject = ?3,
                    from_address = ?4, from_name = ?5, to_addresses = ?6,
                    cc_addresses = ?7, bcc_addresses = ?8,
                    sender_addresses = ?9, reply_to_addresses = ?10,
                    delivered_to_addresses = ?11, list_id = ?12,
                    body_text = ?13, body_html = ?14, preview = ?15,
                    sent_at = ?16, has_attachment = ?17,
                    attachment_names = ?18, content_state = ?19,
                    search_metadata = ?20, dkim_json = ?21,
                    delivery_auth_json = ?22, mime_state = ?23,
                    mime_detail = ?24, content_availability = 'complete',
                    downloaded_bytes = size_bytes, download_error = NULL,
                    download_updated_at = ?25
                WHERE id = ?26 AND content_availability != 'complete' AND size_bytes = ?27"#,
                turso::params![
                    stage.blob_hash,
                    stage.rfc_message_id,
                    stage.subject,
                    stage.from_address,
                    stage.from_name,
                    stage.to_addresses,
                    stage.cc_addresses,
                    stage.bcc_addresses,
                    stage.sender_addresses,
                    stage.reply_to_addresses,
                    stage.delivered_to_addresses,
                    stage.list_id,
                    stage.body_text,
                    stage.body_html,
                    stage.preview,
                    stage.sent_at,
                    stage.has_attachment,
                    stage.attachment_names,
                    stage.content_state,
                    stage.search_metadata,
                    stage.dkim_json,
                    stage.delivery_auth_json,
                    stage.mime_state,
                    stage.mime_detail,
                    now,
                    message_id.to_string(),
                    i64::try_from(expected_bytes).unwrap_or(i64::MAX),
                ],
            )
            .await?;
        if changed == 0 {
            let status = load_content_status_on(&transaction, message_id).await?;
            transaction.rollback().await?;
            if status.availability == MessageContentAvailability::Complete {
                return Ok(status);
            }
            return Err(BackendError::Conflict(
                "message changed while downloaded content was being materialized".into(),
            ));
        }
        transaction
            .execute(
                "DELETE FROM attachments WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM mime_parts WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM message_links WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        for attachment in &prepared.attachments {
            let metadata = &attachment.metadata;
            transaction
                .execute(
                    r#"INSERT INTO attachments (
                        message_id, ordinal, part_id, name, declared_media_type,
                        detected_media_type, decoded_size, inline, content_id,
                        blob_hash, decode_state, decode_problems_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
                    turso::params![
                        message_id.to_string(),
                        i64::from(metadata.ordinal),
                        i64::from(metadata.mime_part_id),
                        metadata.name.clone(),
                        metadata.declared_media_type.clone(),
                        metadata.detected_media_type.clone(),
                        metadata.decoded_size as i64,
                        metadata.inline,
                        metadata.content_id.clone(),
                        attachment.blob_hash.clone(),
                        mime_decode_state_text(metadata.decode_state),
                        attachment.decode_problems_json.clone(),
                    ],
                )
                .await?;
        }
        for part in &prepared.mime_parts {
            transaction
                .execute(
                    r#"INSERT INTO mime_parts (
                        message_id, part_id, parent_part_id, child_ids_json,
                        kind, role, declared_media_type, name, content_id,
                        content_location, inline, attachment, decoded_size,
                        decode_state, parse_flags_json, decode_problems_json,
                        in_plain_body, in_html_body
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                        ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"#,
                    turso::params![
                        message_id.to_string(),
                        i64::from(part.id),
                        part.parent_id.map(i64::from),
                        serde_json::to_string(&part.child_ids)?,
                        mime_part_kind_text(part.kind),
                        mime_part_role_text(part.role),
                        part.declared_media_type.clone(),
                        part.name.clone(),
                        part.content_id.clone(),
                        part.content_location.clone(),
                        part.inline,
                        part.attachment,
                        part.decoded_size as i64,
                        mime_decode_state_text(part.decode_state),
                        serde_json::to_string(&part.parse_flags)?,
                        serde_json::to_string(&part.decode_problems)?,
                        part.in_plain_body,
                        part.in_html_body,
                    ],
                )
                .await?;
        }
        for resource in &prepared.resources {
            transaction
                .execute(
                    "INSERT INTO mime_part_blobs(message_id, part_id, blob_hash, decoded_size) VALUES (?1, ?2, ?3, ?4)",
                    (
                        message_id.to_string(),
                        i64::from(resource.part_id),
                        resource.blob_hash.clone(),
                        resource.decoded_size as i64,
                    ),
                )
                .await?;
        }
        for link in &prepared.links {
            transaction
                .execute(
                    "INSERT INTO message_links(message_id, ordinal, destination, scheme, host, registrable_domain, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    turso::params![
                        message_id.to_string(),
                        i64::from(link.ordinal),
                        link.destination.clone(),
                        link.scheme.clone(),
                        link.host.clone(),
                        link.registrable_domain.clone(),
                        match link.source {
                            MessageLinkSource::PlainText => "plain_text",
                            MessageLinkSource::Html => "html",
                        },
                    ],
                )
                .await?;
        }
        let spam_model_changed =
            crate::spam::refresh_training_and_classification_on(&transaction, message_id, now)
                .await?;
        enqueue_search_on(&transaction, message_id).await?;
        let event = insert_event(
            &transaction,
            now,
            "message_content_downloaded",
            message_id.to_string(),
            json!({"message_id": message_id, "size_bytes": expected_bytes}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        drop(blob_guard);
        let removed_projection = {
            let _blob_guard = self.inner.blob_references.write().await;
            if self.blob_is_referenced(&previous_blob_hash).await? {
                false
            } else {
                self.inner
                    .blobs
                    .remove_unreferenced(&previous_blob_hash)
                    .await?
            }
        };
        if removed_projection {
            self.inner.storage.measure().await?;
        }
        self.openpgp().refresh_message_evidence(message_id).await?;
        self.flush_search_projection().await?;
        let _ = self.inner.events.send(event);
        self.evaluate_automation(&[message_id]).await?;
        drop(_search_guard);
        if spam_model_changed {
            self.spam_classifier().reclassify_pending(64).await?;
            self.schedule_spam_reclassification();
        }
        let connection = self.inner.connection.lock().await;
        load_content_status_on(&connection, message_id).await
    }

    async fn commit_prepared_batch(
        &self,
        mut prepared: Vec<PreparedIngest>,
    ) -> Result<Vec<MessageId>> {
        let _search_guard = self.inner.search_sync.write().await;
        let batch_id = Uuid::new_v4().to_string();
        let mut connection = self.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut existing_ids = vec![None; prepared.len()];
        let mut reconciled_sent = vec![false; prepared.len()];
        for (position, message) in prepared.iter().enumerate() {
            if let Some(remote) = &message.remote {
                existing_ids[position] = lookup_remote_on(
                    &transaction,
                    remote.folder_id,
                    remote.uid_validity,
                    remote.uid,
                )
                .await?;
                if existing_ids[position].is_none() {
                    if let Some(stage) = message.stage.as_ref() {
                        existing_ids[position] = lookup_sent_reconciliation_on(
                            &transaction,
                            remote.account_id,
                            remote.folder_id,
                            stage.rfc_message_id.as_deref(),
                            stage.from_address.as_deref(),
                        )
                        .await?;
                        reconciled_sent[position] = existing_ids[position].is_some();
                    }
                }
            }
        }

        let mut account_growth = HashMap::<AccountId, u64>::new();
        for (position, message) in prepared.iter().enumerate() {
            if let Some(existing) = existing_ids[position] {
                if reconciled_sent[position] {
                    let remote = message
                        .remote
                        .as_ref()
                        .expect("sent reconciliation has remote identity");
                    let mut rows = transaction
                        .query(
                            "SELECT EXISTS(SELECT 1 FROM message_instances WHERE message_id = ?1 AND account_id = ?2)",
                            (existing.to_string(), remote.account_id.to_string()),
                        )
                        .await?;
                    let already_counted = rows
                        .next()
                        .await?
                        .expect("EXISTS query returns one row")
                        .get::<bool>(0)?;
                    drop(rows);
                    if !already_counted {
                        let downloaded = message
                            .stage
                            .as_ref()
                            .map(|stage| stage.downloaded_bytes)
                            .unwrap_or_default();
                        let downloaded = u64::try_from(downloaded).map_err(|_| {
                            BackendError::InvalidInput(
                                "prepared message has invalid downloaded bytes".into(),
                            )
                        })?;
                        let total = account_growth.entry(remote.account_id).or_default();
                        *total = total.saturating_add(downloaded);
                    }
                }
                continue;
            }
            let (Some(remote), Some(stage)) = (&message.remote, &message.stage) else {
                continue;
            };
            let downloaded = u64::try_from(stage.downloaded_bytes).map_err(|_| {
                BackendError::InvalidInput("prepared message has invalid downloaded bytes".into())
            })?;
            let total = account_growth.entry(remote.account_id).or_default();
            *total = total.saturating_add(downloaded);
        }
        for (account_id, requested) in account_growth {
            crate::storage::ensure_account_capacity_on(&transaction, account_id, requested).await?;
        }

        let mut staged_any = false;
        for (position, message) in prepared.iter_mut().enumerate() {
            if existing_ids[position].is_some() {
                message.stage = None;
                continue;
            }
            let stage = message
                .stage
                .take()
                .expect("prepared message has stage data");
            transaction
                .execute(
                    r#"INSERT INTO ingest_message_stage (
                        batch_id, position, id, blob_hash, rfc_message_id, subject,
                        from_address, from_name, to_addresses, cc_addresses,
                        bcc_addresses, sender_addresses, reply_to_addresses,
                        delivered_to_addresses, list_id, body_text, body_html,
                        preview, sent_at, received_at, size_bytes,
                        has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json,
                        delivery_auth_json, mime_state, mime_detail, content_availability,
                        downloaded_bytes, download_error, download_updated_at,
                        created_at
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                        ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32,
                        ?33, ?34, ?35, ?36, ?37
                    )"#,
                    turso::params![
                        batch_id.clone(),
                        position as i64,
                        message.id.to_string(),
                        stage.blob_hash,
                        stage.rfc_message_id,
                        stage.subject,
                        stage.from_address,
                        stage.from_name,
                        stage.to_addresses,
                        stage.cc_addresses,
                        stage.bcc_addresses,
                        stage.sender_addresses,
                        stage.reply_to_addresses,
                        stage.delivered_to_addresses,
                        stage.list_id,
                        stage.body_text,
                        stage.body_html,
                        stage.preview,
                        stage.sent_at,
                        stage.received_at,
                        stage.size_bytes,
                        stage.has_attachment,
                        stage.attachment_names,
                        stage.is_read,
                        stage.is_starred,
                        stage.user_classification,
                        stage.content_state,
                        stage.search_metadata,
                        stage.dkim_json,
                        stage.delivery_auth_json,
                        stage.mime_state,
                        stage.mime_detail,
                        stage.content_availability,
                        stage.downloaded_bytes,
                        stage.download_error,
                        stage.download_updated_at,
                        stage.created_at,
                    ],
                )
                .await?;
            staged_any = true;
        }
        if staged_any {
            transaction
                .execute(
                    r#"INSERT INTO messages (
                        id, blob_hash, rfc_message_id, subject, from_address, from_name,
                        to_addresses, cc_addresses, bcc_addresses, sender_addresses,
                        reply_to_addresses, delivered_to_addresses, list_id,
                        body_text, body_html, preview, sent_at, received_at,
                        size_bytes, has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json,
                        delivery_auth_json, mime_state, mime_detail, content_availability,
                        downloaded_bytes, download_error, download_updated_at,
                        created_at
                    )
                    SELECT id, blob_hash, rfc_message_id, subject, from_address, from_name,
                        to_addresses, cc_addresses, bcc_addresses, sender_addresses,
                        reply_to_addresses, delivered_to_addresses, list_id,
                        body_text, body_html, preview, sent_at, received_at,
                        size_bytes, has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json,
                        delivery_auth_json, mime_state, mime_detail, content_availability,
                        downloaded_bytes, download_error, download_updated_at,
                        created_at
                    FROM ingest_message_stage
                    WHERE batch_id = ?1
                    ORDER BY position"#,
                    (batch_id.clone(),),
                )
                .await?;
            transaction
                .execute(
                    "INSERT OR IGNORE INTO search_index_queue(message_id, revision) SELECT id, 1 FROM ingest_message_stage WHERE batch_id = ?1",
                    (batch_id.clone(),),
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM ingest_message_stage WHERE batch_id = ?1",
                    (batch_id,),
                )
                .await?;
        }

        let mut message_ids = Vec::with_capacity(prepared.len());
        let mut events = Vec::with_capacity(prepared.len());
        for (position, message) in prepared.iter().enumerate() {
            if let Some(existing) = existing_ids[position] {
                if reconciled_sent[position] {
                    let remote = message
                        .remote
                        .as_ref()
                        .expect("sent reconciliation has remote identity");
                    transaction
                        .execute(
                            "INSERT INTO message_instances(message_id, account_id, folder_id, uid_validity, imap_uid, mod_sequence, flags_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            turso::params![
                                existing.to_string(),
                                remote.account_id.to_string(),
                                remote.folder_id.to_string(),
                                i64::from(remote.uid_validity),
                                i64::from(remote.uid),
                                remote.mod_sequence.map(|value| value as i64),
                                message.remote_flags_json.clone().expect("remote flags"),
                            ],
                        )
                        .await?;
                    refresh_provider_spam_evidence_in_transaction(&transaction, existing, remote)
                        .await?;
                    enqueue_search_on(&transaction, existing).await?;
                    let is_read = remote
                        .flags
                        .iter()
                        .any(|flag| flag.eq_ignore_ascii_case("\\Seen"));
                    let is_starred = remote
                        .flags
                        .iter()
                        .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"));
                    transaction
                        .execute(
                            "UPDATE messages SET is_read = ?1, is_starred = ?2 WHERE id = ?3",
                            (is_read, is_starred, existing.to_string()),
                        )
                        .await?;
                    transaction
                        .execute(
                            "UPDATE sent_reconciliation SET reconciled_at = ?1 WHERE message_id = ?2 AND account_id = ?3",
                            (
                                Utc::now().timestamp(),
                                existing.to_string(),
                                remote.account_id.to_string(),
                            ),
                        )
                        .await?;
                    events.push(
                        insert_event(
                            &transaction,
                            Utc::now().timestamp(),
                            "sent_message_reconciled",
                            existing.to_string(),
                            json!({"message_id": existing, "folder_id": remote.folder_id, "uid": remote.uid}),
                        )
                        .await?,
                    );
                    message_ids.push(existing);
                    continue;
                }
                if let Some(event) = refresh_remote_in_transaction(
                    &transaction,
                    existing,
                    message
                        .remote
                        .as_ref()
                        .expect("existing remote has identity"),
                )
                .await?
                {
                    events.push(event);
                }
                message_ids.push(existing);
                continue;
            }
            let membership =
                crate::thread::assign_message_on(&transaction, message.id, &message.threading)
                    .await?;
            for attachment in &message.attachments {
                let metadata = &attachment.metadata;
                transaction
                    .execute(
                        r#"INSERT INTO attachments (
                            message_id, ordinal, part_id, name, declared_media_type,
                            detected_media_type, decoded_size, inline, content_id,
                            blob_hash, decode_state, decode_problems_json
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
                        turso::params![
                            message.id.to_string(),
                            metadata.ordinal as i64,
                            metadata.mime_part_id as i64,
                            metadata.name.clone(),
                            metadata.declared_media_type.clone(),
                            metadata.detected_media_type.clone(),
                            metadata.decoded_size as i64,
                            metadata.inline,
                            metadata.content_id.clone(),
                            attachment.blob_hash.clone(),
                            mime_decode_state_text(metadata.decode_state),
                            attachment.decode_problems_json.clone(),
                        ],
                    )
                    .await?;
            }
            for part in &message.mime_parts {
                transaction
                    .execute(
                        r#"INSERT INTO mime_parts (
                            message_id, part_id, parent_part_id, child_ids_json,
                            kind, role, declared_media_type, name, content_id,
                            content_location, inline, attachment, decoded_size,
                            decode_state, parse_flags_json, decode_problems_json,
                            in_plain_body, in_html_body
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                            ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"#,
                        turso::params![
                            message.id.to_string(),
                            i64::from(part.id),
                            part.parent_id.map(i64::from),
                            serde_json::to_string(&part.child_ids)?,
                            mime_part_kind_text(part.kind),
                            mime_part_role_text(part.role),
                            part.declared_media_type.clone(),
                            part.name.clone(),
                            part.content_id.clone(),
                            part.content_location.clone(),
                            part.inline,
                            part.attachment,
                            part.decoded_size as i64,
                            mime_decode_state_text(part.decode_state),
                            serde_json::to_string(&part.parse_flags)?,
                            serde_json::to_string(&part.decode_problems)?,
                            part.in_plain_body,
                            part.in_html_body,
                        ],
                    )
                    .await?;
            }
            for resource in &message.resources {
                transaction
                    .execute(
                        "INSERT INTO mime_part_blobs(message_id, part_id, blob_hash, decoded_size) VALUES (?1, ?2, ?3, ?4)",
                        (
                            message.id.to_string(),
                            i64::from(resource.part_id),
                            resource.blob_hash.clone(),
                            resource.decoded_size as i64,
                        ),
                    )
                    .await?;
            }
            for link in &message.links {
                transaction
                    .execute(
                        "INSERT INTO message_links(message_id, ordinal, destination, scheme, host, registrable_domain, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        turso::params![
                            message.id.to_string(),
                            i64::from(link.ordinal),
                            link.destination.clone(),
                            link.scheme.clone(),
                            link.host.clone(),
                            link.registrable_domain.clone(),
                            match link.source {
                                MessageLinkSource::PlainText => "plain_text",
                                MessageLinkSource::Html => "html",
                            },
                        ],
                    )
                    .await?;
            }
            if let Some(remote) = &message.remote {
                transaction
                    .execute(
                        r#"INSERT INTO message_instances (
                            message_id, account_id, folder_id, uid_validity, imap_uid,
                            mod_sequence, flags_json
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                        turso::params![
                            message.id.to_string(),
                            remote.account_id.to_string(),
                            remote.folder_id.to_string(),
                            remote.uid_validity as i64,
                            remote.uid as i64,
                            remote.mod_sequence.map(|value| value as i64),
                            message
                                .remote_flags_json
                                .clone()
                                .expect("remote message has serialized flags"),
                        ],
                    )
                    .await?;
                refresh_provider_spam_evidence_in_transaction(&transaction, message.id, remote)
                    .await?;
            }
            crate::spam::classify_message_on(&transaction, message.id, Utc::now().timestamp())
                .await?;
            events.push(
                insert_event(
                    &transaction,
                    Utc::now().timestamp(),
                    "message_ingested",
                    message.id.to_string(),
                    json!({"message_id": message.id, "thread_id": membership.thread_id}),
                )
                .await?,
            );
            message_ids.push(message.id);
        }
        transaction.commit().await?;
        drop(connection);
        self.flush_search_projection().await?;
        for event in events {
            let _ = self.inner.events.send(event);
        }
        Ok(message_ids)
    }

    /// Version-eight adds durable thread metadata. Reparse only messages that
    /// predate that projection, in bounded chunks, and make each chunk atomic.
    async fn backfill_thread_projection(&self) -> Result<()> {
        loop {
            let missing = {
                let connection = self.inner.connection.lock().await;
                let mut rows = connection
                    .query(
                        "SELECT id, blob_hash, received_at FROM messages WHERE thread_id IS NULL AND content_availability = 'complete' ORDER BY received_at, id LIMIT 100",
                        (),
                    )
                    .await?;
                let mut missing = Vec::new();
                while let Some(row) = rows.next().await? {
                    missing.push((
                        parse_id::<MessageId>(row.get(0)?, "message")?,
                        row.get::<String>(1)?,
                        row.get::<i64>(2)?,
                    ));
                }
                missing
            };
            if missing.is_empty() {
                return Ok(());
            }
            let mut projected = Vec::with_capacity(missing.len());
            for (message_id, blob_hash, received_at) in missing {
                let raw = self.inner.blobs.get(&blob_hash).await?;
                let parsed = mime::parse_thread_headers(&raw)?;
                let threading = crate::thread::ThreadInput::new(
                    parsed.rfc_message_id.as_deref(),
                    &parsed.in_reply_to,
                    &parsed.references,
                    parsed.subject.as_deref(),
                    parsed.from_address.as_deref(),
                    &parsed.to_addresses,
                    &parsed.cc_addresses,
                    &parsed.bcc_addresses,
                    &parsed.reply_to_addresses,
                    &parsed.delivered_to_addresses,
                    received_at,
                );
                projected.push((
                    message_id,
                    threading,
                    serde_json::to_string(&parsed.reply_to_addresses)?,
                ));
            }
            let mut connection = self.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (message_id, threading, reply_to_addresses) in projected {
                transaction
                    .execute(
                        "UPDATE messages SET reply_to_addresses = ?1 WHERE id = ?2 AND thread_id IS NULL",
                        (reply_to_addresses, message_id.to_string()),
                    )
                    .await?;
                crate::thread::assign_message_on(&transaction, message_id, &threading).await?;
            }
            transaction.commit().await?;
        }
    }

    /// Materialize the version-nine MIME tree and decoded attachment/resource
    /// blobs for messages stored by earlier versions. Work is bounded per
    /// transaction and resumes after interruption.
    async fn backfill_mime_projection(&self) -> Result<()> {
        loop {
            let missing = {
                let connection = self.inner.connection.lock().await;
                let mut rows = connection
                    .query(
                        "SELECT id, blob_hash FROM messages m WHERE m.content_availability = 'complete' AND NOT EXISTS (SELECT 1 FROM mime_parts p WHERE p.message_id = m.id) ORDER BY id LIMIT 20",
                        (),
                    )
                    .await?;
                let mut missing = Vec::new();
                while let Some(row) = rows.next().await? {
                    missing.push((
                        parse_id::<MessageId>(row.get(0)?, "message")?,
                        row.get::<String>(1)?,
                    ));
                }
                missing
            };
            if missing.is_empty() {
                return Ok(());
            }
            let _blob_guard = self.inner.blob_references.read().await;
            let mut projected = Vec::with_capacity(missing.len());
            for (message_id, blob_hash) in missing {
                let raw = self.inner.blobs.get(&blob_hash).await?;
                let parsed = mime::parse(&raw, &self.inner.config.limits)?;
                let mut resources = Vec::new();
                let mut hashes = HashMap::new();
                for resource in parsed.resources {
                    let size = resource.bytes.len() as u64;
                    let hash = self.inner.blobs.put(&resource.bytes).await?;
                    hashes.insert(resource.part_id, hash.clone());
                    resources.push(PreparedResource {
                        part_id: resource.part_id,
                        blob_hash: hash,
                        decoded_size: size,
                    });
                }
                let attachments = parsed
                    .attachments
                    .into_iter()
                    .map(|attachment| {
                        Ok(PreparedAttachment {
                            blob_hash: hashes
                                .get(&attachment.metadata.mime_part_id)
                                .cloned()
                                .ok_or_else(|| {
                                    BackendError::InvalidInput(
                                        "attachment resource missing during MIME backfill".into(),
                                    )
                                })?,
                            decode_problems_json: serde_json::to_string(
                                &attachment.decode_problems,
                            )?,
                            metadata: attachment.metadata,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                projected.push((
                    message_id,
                    parsed.mime_parts,
                    attachments,
                    resources,
                    parsed.mime_state,
                    parsed.mime_detail,
                ));
            }
            let mut connection = self.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (message_id, parts, attachments, resources, state, detail) in projected {
                transaction
                    .execute(
                        "UPDATE messages SET mime_state = ?1, mime_detail = ?2 WHERE id = ?3",
                        (mime_parse_state_text(state), detail, message_id.to_string()),
                    )
                    .await?;
                for part in parts {
                    transaction
                        .execute(
                            "INSERT INTO mime_parts(message_id, part_id, parent_part_id, child_ids_json, kind, role, declared_media_type, name, content_id, content_location, inline, attachment, decoded_size, decode_state, parse_flags_json, decode_problems_json, in_plain_body, in_html_body) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                            turso::params![
                                message_id.to_string(),
                                i64::from(part.id),
                                part.parent_id.map(i64::from),
                                serde_json::to_string(&part.child_ids)?,
                                mime_part_kind_text(part.kind),
                                mime_part_role_text(part.role),
                                part.declared_media_type,
                                part.name,
                                part.content_id,
                                part.content_location,
                                part.inline,
                                part.attachment,
                                part.decoded_size as i64,
                                mime_decode_state_text(part.decode_state),
                                serde_json::to_string(&part.parse_flags)?,
                                serde_json::to_string(&part.decode_problems)?,
                                part.in_plain_body,
                                part.in_html_body,
                            ],
                        )
                        .await?;
                }
                for resource in resources {
                    transaction
                        .execute(
                            "INSERT INTO mime_part_blobs(message_id, part_id, blob_hash, decoded_size) VALUES (?1, ?2, ?3, ?4)",
                            (
                                message_id.to_string(),
                                i64::from(resource.part_id),
                                resource.blob_hash,
                                resource.decoded_size as i64,
                            ),
                        )
                        .await?;
                }
                for attachment in attachments {
                    let metadata = attachment.metadata;
                    transaction
                        .execute(
                            "UPDATE attachments SET part_id = ?1, detected_media_type = ?2, blob_hash = ?3, decode_state = ?4, decode_problems_json = ?5 WHERE message_id = ?6 AND ordinal = ?7",
                            turso::params![
                                i64::from(metadata.mime_part_id),
                                metadata.detected_media_type,
                                attachment.blob_hash,
                                mime_decode_state_text(metadata.decode_state),
                                attachment.decode_problems_json,
                                message_id.to_string(),
                                i64::from(metadata.ordinal),
                            ],
                        )
                        .await?;
                }
            }
            transaction.commit().await?;
        }
    }

    pub(crate) async fn flush_search_projection(&self) -> Result<()> {
        if self.inner.search_deferred {
            return Ok(());
        }
        loop {
            let deleted = {
                let connection = self.inner.connection.lock().await;
                let mut rows = connection
                    .query(
                        "SELECT message_id FROM search_index_delete_queue ORDER BY message_id LIMIT ?1",
                        (MAX_INGEST_BATCH_MESSAGES as i64,),
                    )
                    .await?;
                let mut deleted = Vec::new();
                while let Some(row) = rows.next().await? {
                    deleted.push(row.get::<String>(0)?);
                }
                deleted
            };
            if !deleted.is_empty() {
                let search_index = Arc::clone(&self.inner.search_index);
                let index_ids = deleted.clone();
                tokio::task::spawn_blocking(move || search_index.delete_documents(index_ids))
                    .await
                    .map_err(|error| {
                        BackendError::SearchIndex(format!("search deletion task failed: {error}"))
                    })??;
                let mut connection = self.inner.connection.lock().await;
                let transaction = connection.transaction().await?;
                for id in deleted {
                    transaction
                        .execute(
                            "DELETE FROM search_index_delete_queue WHERE message_id = ?1",
                            (id,),
                        )
                        .await?;
                }
                transaction.commit().await?;
                continue;
            }
            let queued = {
                let connection = self.inner.connection.lock().await;
                load_queued_search_documents(&connection, MAX_INGEST_BATCH_MESSAGES).await?
            };
            if queued.is_empty() {
                return Ok(());
            }
            let revisions = queued
                .iter()
                .map(|queued| (queued.document.id.clone(), queued.revision))
                .collect::<Vec<_>>();
            let documents = queued
                .into_iter()
                .map(|queued| queued.document)
                .collect::<Vec<_>>();
            let search_index = Arc::clone(&self.inner.search_index);
            tokio::task::spawn_blocking(move || search_index.replace_documents(documents))
                .await
                .map_err(|error| {
                    BackendError::SearchIndex(format!("search indexing task failed: {error}"))
                })??;

            let mut connection = self.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            for (id, revision) in revisions {
                transaction
                    .execute(
                        "DELETE FROM search_index_queue WHERE message_id = ?1 AND revision = ?2",
                        (id, revision),
                    )
                    .await?;
            }
            transaction.commit().await?;
        }
    }

    pub(crate) async fn current_change_cursor(&self) -> Result<ChangeCursor> {
        let connection = self.inner.connection.lock().await;
        let mut rows = connection
            .query("SELECT COALESCE(max(sequence), 0) FROM changes", ())
            .await?;
        let sequence = rows
            .next()
            .await?
            .ok_or_else(|| {
                BackendError::InvalidInput("change cursor query returned no row".into())
            })?
            .get::<i64>(0)?;
        Ok(ChangeCursor(u64::try_from(sequence).map_err(|_| {
            BackendError::InvalidInput("database contains an invalid change sequence".into())
        })?))
    }

    /// Publish durable side effects committed by an isolated synchronization
    /// worker into this process's Tantivy writer and broadcast channel.
    pub(crate) async fn publish_worker_changes(&self, mut cursor: ChangeCursor) -> Result<()> {
        self.flush_search_projection().await?;
        loop {
            let events = self.events().changes_since(cursor, 500).await?;
            if events.is_empty() {
                return Ok(());
            }
            for event in events {
                cursor = ChangeCursor(event.sequence);
                let _ = self.inner.events.send(event);
            }
        }
    }
}

#[derive(Clone)]
pub struct Accounts(Backend);

impl Accounts {
    pub async fn add_with_credential(
        &self,
        mut account: NewAccount,
        credential: crate::ImapCredential,
    ) -> Result<Account> {
        if account.credential_ref.is_some() {
            return Err(BackendError::InvalidInput(
                "add_with_credential requires an empty credential reference".into(),
            ));
        }
        let reference = self.0.credentials().store(credential).await?;
        account.credential_ref = Some(reference.clone());
        match self.add(account).await {
            Ok(account) => Ok(account),
            Err(error) => {
                let _ = self.0.credentials().delete(&reference).await;
                Err(error)
            }
        }
    }

    pub async fn set_credential(
        &self,
        id: AccountId,
        credential: crate::ImapCredential,
    ) -> Result<Account> {
        let existing = self.get(id).await?;
        let reference = self.0.credentials().store(credential).await?;
        let updated = self
            .update(
                id,
                NewAccount {
                    name: existing.name,
                    kind: existing.kind,
                    credential_ref: Some(reference.clone()),
                    imap: existing.imap,
                },
            )
            .await;
        if updated.is_err() {
            let committed = self
                .get(id)
                .await
                .ok()
                .and_then(|account| account.credential_ref)
                .is_some_and(|stored| stored == reference);
            if !committed {
                let _ = self.0.credentials().delete(&reference).await;
            }
        }
        updated
    }

    pub async fn add(&self, account: NewAccount) -> Result<Account> {
        require_nonempty("account name", &account.name)?;
        if account
            .credential_ref
            .as_deref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(BackendError::InvalidInput(
                "credential reference cannot be empty".into(),
            ));
        }
        match (account.kind, &account.imap) {
            (AccountKind::Imap, Some(settings)) => validate_imap_settings(settings)?,
            (AccountKind::Imap, None) => {
                return Err(BackendError::InvalidInput(
                    "IMAP accounts require connection settings".into(),
                ));
            }
            (AccountKind::Local, Some(_)) => {
                return Err(BackendError::InvalidInput(
                    "local accounts cannot have IMAP settings".into(),
                ));
            }
            (AccountKind::Local, None) => {}
        }
        let value = Account {
            id: AccountId::new(),
            name: account.name,
            kind: account.kind,
            credential_ref: account.credential_ref,
            imap: account.imap,
            trusted_authserv_ids: Vec::new(),
            created_at: Utc::now().timestamp(),
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO accounts(id, name, kind, credential_ref, settings_json, trusted_authserv_ids_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                turso::params![
                    value.id.to_string(),
                    value.name.clone(),
                    account_kind_text(value.kind),
                    value.credential_ref.clone(),
                    value.imap.as_ref().map(serde_json::to_string).transpose()?,
                    serde_json::to_string(&value.trusted_authserv_ids)?,
                    value.created_at,
                ],
            )
            .await?;
        if let Some(settings) = &value.imap {
            crate::identity::ensure_default_identity_on(
                &transaction,
                value.id,
                &value.name,
                &settings.username,
                value.created_at,
            )
            .await?;
        }
        let event = insert_event(
            &transaction,
            value.created_at,
            "account_added",
            value.id.to_string(),
            json!({"account_id": value.id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(value)
    }

    pub async fn list(&self) -> Result<Vec<Account>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, kind, credential_ref, settings_json, trusted_authserv_ids_json, created_at FROM accounts ORDER BY created_at, id",
                (),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(Account {
                id: parse_id(row.get::<String>(0)?, "account")?,
                name: row.get(1)?,
                kind: parse_account_kind(&row.get::<String>(2)?)?,
                credential_ref: row.get(3)?,
                imap: row
                    .get::<Option<String>>(4)?
                    .map(|value| serde_json::from_str(&value))
                    .transpose()?,
                trusted_authserv_ids: serde_json::from_str(&row.get::<String>(5)?)?,
                created_at: row.get(6)?,
            });
        }
        Ok(values)
    }

    pub async fn get(&self, id: AccountId) -> Result<Account> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, kind, credential_ref, settings_json, trusted_authserv_ids_json, created_at FROM accounts WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(not_found("account", id));
        };
        Ok(Account {
            id: parse_id(row.get::<String>(0)?, "account")?,
            name: row.get(1)?,
            kind: parse_account_kind(&row.get::<String>(2)?)?,
            credential_ref: row.get(3)?,
            imap: row
                .get::<Option<String>>(4)?
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
            trusted_authserv_ids: serde_json::from_str(&row.get::<String>(5)?)?,
            created_at: row.get(6)?,
        })
    }

    pub async fn update(&self, id: AccountId, account: NewAccount) -> Result<Account> {
        require_nonempty("account name", &account.name)?;
        if account
            .credential_ref
            .as_deref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(BackendError::InvalidInput(
                "credential reference cannot be empty".into(),
            ));
        }
        let existing = self.get(id).await?;
        if account.kind != existing.kind {
            return Err(BackendError::InvalidInput(
                "an account kind cannot be changed after creation".into(),
            ));
        }
        match (account.kind, &account.imap) {
            (AccountKind::Imap, Some(settings)) => validate_imap_settings(settings)?,
            (AccountKind::Imap, None) => {
                return Err(BackendError::InvalidInput(
                    "IMAP accounts require connection settings".into(),
                ))
            }
            (AccountKind::Local, Some(_)) => {
                return Err(BackendError::InvalidInput(
                    "local accounts cannot have IMAP settings".into(),
                ))
            }
            (AccountKind::Local, None) => {}
        }
        let next_credential_ref = account.credential_ref.clone();
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT credential_ref FROM accounts WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            drop(rows);
            transaction.rollback().await?;
            return Err(not_found("account", id));
        };
        let previous_credential_ref = row.get::<Option<String>>(0)?;
        drop(rows);
        if transaction
            .execute(
                "UPDATE accounts SET name = ?1, credential_ref = ?2, settings_json = ?3 WHERE id = ?4",
                turso::params![
                    account.name,
                    account.credential_ref,
                    account.imap.as_ref().map(serde_json::to_string).transpose()?,
                    id.to_string(),
                ],
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("account", id));
        }
        if previous_credential_ref != next_credential_ref {
            if let Some(reference) = &previous_credential_ref {
                self.0
                    .queue_managed_credential_cleanup_on(&transaction, reference, now)
                    .await?;
            }
        }
        let event = insert_event(
            &transaction,
            now,
            "account_updated",
            id.to_string(),
            json!({"account_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.drain_credential_cleanup(16).await?;
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn remove(&self, id: AccountId) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                r#"SELECT credential_ref FROM accounts
                    WHERE id = ?1 AND credential_ref IS NOT NULL
                    UNION SELECT credential_ref FROM smtp_accounts WHERE account_id = ?1
                    UNION SELECT credential_ref FROM openpgp_secret_key_providers
                    WHERE account_id = ?1 AND credential_ref IS NOT NULL"#,
                (id.to_string(),),
            )
            .await?;
        let mut references = HashSet::new();
        while let Some(row) = rows.next().await? {
            references.insert(row.get::<String>(0)?);
        }
        drop(rows);
        let mut rows = transaction
            .query(
                "SELECT DISTINCT m.id, m.thread_id FROM messages m WHERE EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.account_id = ?1) OR EXISTS (SELECT 1 FROM local_folder_memberships lm JOIN folders f ON f.id = lm.folder_id WHERE lm.message_id = m.id AND f.account_id = ?1)",
                (id.to_string(),),
            )
            .await?;
        let mut affected = Vec::new();
        while let Some(row) = rows.next().await? {
            affected.push((
                parse_id::<MessageId>(row.get(0)?, "message")?,
                row.get::<Option<String>>(1)?,
            ));
        }
        drop(rows);
        if transaction
            .execute("DELETE FROM accounts WHERE id = ?1", (id.to_string(),))
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("account", id));
        }
        for reference in &references {
            self.0
                .queue_managed_credential_cleanup_on(&transaction, reference, now)
                .await?;
        }
        let mut removed_messages = Vec::new();
        let mut touched_threads = HashSet::new();
        for (message_id, thread_id) in affected {
            let mut rows = transaction
                .query(
                    "SELECT EXISTS(SELECT 1 FROM message_instances WHERE message_id = ?1), EXISTS(SELECT 1 FROM local_folder_memberships WHERE message_id = ?1)",
                    (message_id.to_string(),),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| {
                BackendError::InvalidInput("database failed to evaluate message ownership".into())
            })?;
            let retained = row.get::<bool>(0)? || row.get::<bool>(1)?;
            drop(rows);
            if retained {
                enqueue_search_on(&transaction, message_id).await?;
            } else {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO search_index_delete_queue(message_id) VALUES (?1)",
                        (message_id.to_string(),),
                    )
                    .await?;
                transaction
                    .execute(
                        "DELETE FROM messages WHERE id = ?1",
                        (message_id.to_string(),),
                    )
                    .await?;
                removed_messages.push(message_id);
            }
            if let Some(thread_id) = thread_id {
                touched_threads.insert(thread_id);
            }
        }
        for thread_id in touched_threads {
            transaction
                .execute(
                    "UPDATE threads SET updated_at = (SELECT MAX(received_at) FROM messages WHERE thread_id = ?1) WHERE id = ?1 AND EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                    (thread_id.clone(),),
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM threads WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                    (thread_id,),
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "account_removed",
            id.to_string(),
            json!({"account_id": id, "removed_message_count": removed_messages.len()}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.drain_credential_cleanup(16).await?;
        for message_id in removed_messages {
            let _ = tokio::fs::remove_file(self.0.partial_download_path(message_id)).await;
        }
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    /// Replaces the exact RFC 8601 authserv-id allowlist for one receiving
    /// account. Merely observing the same string in a message never adds it.
    pub async fn set_trusted_authserv_ids(
        &self,
        id: AccountId,
        values: Vec<String>,
    ) -> Result<Account> {
        if self.get(id).await?.kind != AccountKind::Imap {
            return Err(BackendError::InvalidInput(
                "trusted authserv-ids may only be configured for receiving IMAP accounts".into(),
            ));
        }
        let values = crate::delivery_auth::normalize_trusted_authserv_ids(values)?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "UPDATE accounts SET trusted_authserv_ids_json = ?1 WHERE id = ?2",
                (serde_json::to_string(&values)?, id.to_string()),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("account", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "account_authentication_policy_updated",
            id.to_string(),
            json!({"account_id": id, "trusted_authserv_ids": values}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        self.get(id).await
    }
}

#[derive(Clone)]
pub struct Folders(Backend);

impl Folders {
    pub async fn add(&self, folder: NewFolder) -> Result<Folder> {
        require_nonempty("folder name", &folder.name)?;
        match folder.kind {
            FolderKind::Remote => {
                if folder.account_id.is_none() || folder.remote_name.as_deref().is_none() {
                    return Err(BackendError::InvalidInput(
                        "remote folders require an account and remote name".into(),
                    ));
                }
                validate_mailbox_name(folder.remote_name.as_deref().unwrap())?;
            }
            FolderKind::Local if folder.remote_name.is_some() => {
                return Err(BackendError::InvalidInput(
                    "local folders cannot have a remote name".into(),
                ));
            }
            FolderKind::Local => {}
        }
        let value = Folder {
            id: FolderId::new(),
            account_id: folder.account_id,
            name: folder.name,
            kind: folder.kind,
            remote_name: folder.remote_name,
            created_at: Utc::now().timestamp(),
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO folders(id, account_id, name, kind, remote_name, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                turso::params![
                    value.id.to_string(),
                    value.account_id.map(|id| id.to_string()),
                    value.name.clone(),
                    folder_kind_text(value.kind),
                    value.remote_name.clone(),
                    value.created_at,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            value.created_at,
            "folder_added",
            value.id.to_string(),
            json!({"folder_id": value.id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(value)
    }

    pub async fn list(&self, account_id: Option<AccountId>) -> Result<Vec<Folder>> {
        let connection = self.0.inner.connection.lock().await;
        let (sql, parameters) = if let Some(account_id) = account_id {
            (
                "SELECT id, account_id, name, kind, remote_name, created_at FROM folders WHERE account_id = ?1 ORDER BY name, id",
                vec![Value::Text(account_id.to_string())],
            )
        } else {
            (
                "SELECT id, account_id, name, kind, remote_name, created_at FROM folders ORDER BY name, id",
                Vec::new(),
            )
        };
        let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(Folder {
                id: parse_id(row.get::<String>(0)?, "folder")?,
                account_id: row
                    .get::<Option<String>>(1)?
                    .map(|id| parse_id(id, "account"))
                    .transpose()?,
                name: row.get(2)?,
                kind: parse_folder_kind(&row.get::<String>(3)?)?,
                remote_name: row.get(4)?,
                created_at: row.get(5)?,
            });
        }
        Ok(values)
    }

    pub async fn get(&self, id: FolderId) -> Result<Folder> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, account_id, name, kind, remote_name, created_at FROM folders WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| folder_from_row(&row))
            .transpose()?
            .ok_or_else(|| not_found("folder", id))
    }

    pub async fn update(&self, id: FolderId, folder: NewFolder) -> Result<Folder> {
        require_nonempty("folder name", &folder.name)?;
        let existing = self.get(id).await?;
        if folder.kind != existing.kind || folder.account_id != existing.account_id {
            return Err(BackendError::InvalidInput(
                "folder kind and account cannot be changed".into(),
            ));
        }
        match existing.kind {
            FolderKind::Local if folder.remote_name.is_some() => {
                return Err(BackendError::InvalidInput(
                    "local folders cannot have a remote name".into(),
                ));
            }
            FolderKind::Remote if folder.remote_name != existing.remote_name => {
                return Err(BackendError::InvalidInput(
                    "use rename_remote to change an IMAP mailbox name".into(),
                ));
            }
            _ => {}
        }
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "UPDATE folders SET name = ?1 WHERE id = ?2",
                (folder.name, id.to_string()),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("folder", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "folder_updated",
            id.to_string(),
            json!({"folder_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn remove(&self, id: FolderId) -> Result<()> {
        let folder = self.get(id).await?;
        if folder.kind == FolderKind::Remote {
            return Err(BackendError::InvalidInput(
                "use delete_remote with an authenticated IMAP session".into(),
            ));
        }
        self.remove_local_state(id, "folder_removed").await
    }

    pub async fn create_remote<T>(
        &self,
        session: &mut async_imap::Session<T>,
        account_id: AccountId,
        remote_name: String,
    ) -> Result<Folder>
    where
        T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
    {
        validate_mailbox_name(&remote_name)?;
        if self.0.accounts().get(account_id).await?.kind != AccountKind::Imap {
            return Err(BackendError::InvalidInput(
                "remote mailboxes require an IMAP account".into(),
            ));
        }
        {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT 1 FROM folders WHERE account_id = ?1 AND remote_name = ?2 LIMIT 1",
                    (account_id.to_string(), remote_name.clone()),
                )
                .await?;
            if rows.next().await?.is_some() {
                return Err(BackendError::Conflict(
                    "the remote mailbox already exists in local account state".into(),
                ));
            }
        }
        session.create(&remote_name).await.map_err(imap_error)?;
        let folder = self
            .add(NewFolder {
                account_id: Some(account_id),
                name: remote_name.clone(),
                kind: FolderKind::Remote,
                remote_name: Some(remote_name),
            })
            .await?;
        let connection = self.0.inner.connection.lock().await;
        connection
            .execute(
                "INSERT OR IGNORE INTO imap_mailbox_state(folder_id, attributes_json, selectable, remote_present, sync_status, completeness) VALUES (?1, '[]', 1, 1, 'not_started', 'not_started')",
                (folder.id.to_string(),),
            )
            .await?;
        Ok(folder)
    }

    pub async fn rename_remote<T>(
        &self,
        session: &mut async_imap::Session<T>,
        id: FolderId,
        new_remote_name: String,
    ) -> Result<Folder>
    where
        T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
    {
        validate_mailbox_name(&new_remote_name)?;
        let folder = self.get(id).await?;
        if folder.kind != FolderKind::Remote {
            return Err(BackendError::InvalidInput(
                "only remote folders can be renamed through IMAP".into(),
            ));
        }
        let old_name = folder.remote_name.ok_or_else(|| {
            BackendError::InvalidInput("remote folder has no server mailbox name".into())
        })?;
        {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT 1 FROM folders WHERE account_id = ?1 AND remote_name = ?2 AND id != ?3 LIMIT 1",
                    (
                        folder.account_id.map(|value| value.to_string()),
                        new_remote_name.clone(),
                        id.to_string(),
                    ),
                )
                .await?;
            if rows.next().await?.is_some() {
                return Err(BackendError::Conflict(
                    "another local folder already uses the destination mailbox name".into(),
                ));
            }
        }
        session
            .rename(&old_name, &new_remote_name)
            .await
            .map_err(imap_error)?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE folders SET name = ?1, remote_name = ?1 WHERE id = ?2",
                (new_remote_name.clone(), id.to_string()),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "remote_mailbox_renamed",
            id.to_string(),
            json!({"folder_id": id, "old_remote_name": old_name, "new_remote_name": new_remote_name}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn delete_remote<T>(
        &self,
        session: &mut async_imap::Session<T>,
        id: FolderId,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
    {
        let folder = self.get(id).await?;
        if folder.kind != FolderKind::Remote {
            return Err(BackendError::InvalidInput(
                "only remote folders can be deleted through IMAP".into(),
            ));
        }
        let remote_name = folder.remote_name.ok_or_else(|| {
            BackendError::InvalidInput("remote folder has no server mailbox name".into())
        })?;
        {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT 1 FROM imap_mutations WHERE source_folder_id = ?1 AND status IN ('pending', 'in_flight', 'conflict') LIMIT 1",
                    (id.to_string(),),
                )
                .await?;
            if rows.next().await?.is_some() {
                return Err(BackendError::Conflict(
                    "remote mailbox has an unfinished message mutation".into(),
                ));
            }
        }
        session.delete(&remote_name).await.map_err(imap_error)?;
        self.remove_local_state(id, "remote_mailbox_deleted").await
    }

    async fn remove_local_state(&self, id: FolderId, event_kind: &'static str) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT DISTINCT m.id, m.thread_id FROM messages m LEFT JOIN message_instances mi ON mi.message_id = m.id LEFT JOIN local_folder_memberships lm ON lm.message_id = m.id WHERE mi.folder_id = ?1 OR lm.folder_id = ?1",
                (id.to_string(),),
            )
            .await?;
        let mut affected = Vec::new();
        while let Some(row) = rows.next().await? {
            affected.push((
                parse_id::<MessageId>(row.get(0)?, "message")?,
                row.get::<Option<String>>(1)?,
            ));
        }
        drop(rows);
        if transaction
            .execute("DELETE FROM folders WHERE id = ?1", (id.to_string(),))
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("folder", id));
        }
        let mut removed = Vec::new();
        let mut threads = HashSet::new();
        for (message_id, thread_id) in affected {
            let mut rows = transaction
                .query(
                    "SELECT EXISTS(SELECT 1 FROM message_instances WHERE message_id = ?1), EXISTS(SELECT 1 FROM local_folder_memberships WHERE message_id = ?1)",
                    (message_id.to_string(),),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| {
                BackendError::InvalidInput("database failed to evaluate message ownership".into())
            })?;
            let retained = row.get::<bool>(0)? || row.get::<bool>(1)?;
            drop(rows);
            if retained {
                enqueue_search_on(&transaction, message_id).await?;
            } else {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO search_index_delete_queue(message_id) VALUES (?1)",
                        (message_id.to_string(),),
                    )
                    .await?;
                transaction
                    .execute(
                        "DELETE FROM messages WHERE id = ?1",
                        (message_id.to_string(),),
                    )
                    .await?;
                removed.push(message_id);
            }
            if let Some(thread_id) = thread_id {
                threads.insert(thread_id);
            }
        }
        for thread_id in threads {
            transaction
                .execute(
                    "UPDATE threads SET updated_at = (SELECT MAX(received_at) FROM messages WHERE thread_id = ?1) WHERE id = ?1 AND EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                    (thread_id.clone(),),
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM threads WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                    (thread_id,),
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            event_kind,
            id.to_string(),
            json!({"folder_id": id, "removed_message_count": removed.len()}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        for message_id in removed {
            let _ = tokio::fs::remove_file(self.0.partial_download_path(message_id)).await;
        }
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Messages(Backend);

impl Messages {
    pub async fn ingest(&self, request: IngestMessage) -> Result<MessageId> {
        self.0.ingest(request).await
    }

    pub async fn ingest_batch(&self, requests: Vec<IngestMessage>) -> Result<Vec<MessageId>> {
        self.0.ingest_batch(requests).await
    }

    pub async fn get(&self, id: MessageId) -> Result<Message> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                &format!(
                    "SELECT {}, rfc_message_id, to_addresses, cc_addresses, bcc_addresses, sender_addresses, delivered_to_addresses, list_id, body_text, body_html, dkim_json, delivery_auth_json, in_reply_to_json, references_json, reply_to_addresses, parent_message_id, threading_source, sender_trust, user_classification FROM messages m WHERE m.id = ?1",
                    SUMMARY_COLUMNS
                ),
                (id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| not_found("message", id))?;
        let summary = summary_from_row(&row)?;
        let rfc_message_id = row.get(SUMMARY_COLUMN_COUNT)?;
        let to_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 1)?)?;
        let cc_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 2)?)?;
        let bcc_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 3)?)?;
        let sender_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 4)?)?;
        let delivered_to_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 5)?)?;
        let list_id = row.get(SUMMARY_COLUMN_COUNT + 6)?;
        let body_text = row.get(SUMMARY_COLUMN_COUNT + 7)?;
        let mut body_html = row.get(SUMMARY_COLUMN_COUNT + 8)?;
        let dkim = serde_json::from_str(&row.get::<String>(SUMMARY_COLUMN_COUNT + 9)?)?;
        let mut delivery_authentication =
            serde_json::from_str(&row.get::<String>(SUMMARY_COLUMN_COUNT + 10)?)?;
        let in_reply_to = serde_json::from_str(&row.get::<String>(SUMMARY_COLUMN_COUNT + 11)?)?;
        let references = serde_json::from_str(&row.get::<String>(SUMMARY_COLUMN_COUNT + 12)?)?;
        let reply_to_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 13)?)?;
        let parent_message_id = row
            .get::<Option<String>>(SUMMARY_COLUMN_COUNT + 14)?
            .map(|value| parse_id(value, "message"))
            .transpose()?;
        let source = crate::thread::parse_source(&row.get::<String>(SUMMARY_COLUMN_COUNT + 15)?)?;
        let sender_trust =
            crate::thread::parse_sender_trust(&row.get::<String>(SUMMARY_COLUMN_COUNT + 16)?)?;
        let user_classification = row
            .get::<Option<String>>(SUMMARY_COLUMN_COUNT + 17)?
            .map(|value| parse_user_classification(&value))
            .transpose()?;
        drop(rows);
        refresh_delivery_auth_trust_on(&connection, &mut delivery_authentication).await?;

        let mut rows = connection
            .query(
                "SELECT ordinal, part_id, name, declared_media_type, detected_media_type, decoded_size, inline, content_id, decode_state FROM attachments WHERE message_id = ?1 ORDER BY ordinal",
                (id.to_string(),),
            )
            .await?;
        let mut attachments = Vec::new();
        while let Some(row) = rows.next().await? {
            let ordinal = row.get::<i64>(0)? as u32;
            attachments.push(Attachment {
                id: format!("attachment:{ordinal}"),
                ordinal,
                mime_part_id: u32::try_from(row.get::<i64>(1)?).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid MIME part ID".into())
                })?,
                name: row.get(2)?,
                declared_media_type: row.get(3)?,
                detected_media_type: row.get(4)?,
                decoded_size: u64::try_from(row.get::<i64>(5)?).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid attachment size".into())
                })?,
                inline: row.get(6)?,
                content_id: row.get(7)?,
                decode_state: parse_mime_decode_state(&row.get::<String>(8)?)?,
            });
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT ordinal, destination, scheme, host, registrable_domain, source FROM message_links WHERE message_id = ?1 ORDER BY ordinal",
                (id.to_string(),),
            )
            .await?;
        let mut links = Vec::new();
        while let Some(row) = rows.next().await? {
            let ordinal = u32::try_from(row.get::<i64>(0)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid link ordinal".into())
            })?;
            links.push(MessageLink {
                id: format!("link:{ordinal}"),
                ordinal,
                destination: row.get(1)?,
                scheme: row.get(2)?,
                host: row.get(3)?,
                registrable_domain: row.get(4)?,
                source: match row.get::<String>(5)?.as_str() {
                    "plain_text" => MessageLinkSource::PlainText,
                    "html" => MessageLinkSource::Html,
                    _ => {
                        return Err(BackendError::InvalidInput(
                            "database contains invalid link source".into(),
                        ))
                    }
                },
            });
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT account_id, folder_id, uid_validity, imap_uid, mod_sequence, flags_json FROM message_instances WHERE message_id = ?1 ORDER BY account_id, folder_id, uid_validity, imap_uid",
                (id.to_string(),),
            )
            .await?;
        let mut instances = Vec::new();
        while let Some(row) = rows.next().await? {
            instances.push(MessageInstance {
                account_id: parse_id(row.get::<String>(0)?, "account")?,
                folder_id: parse_id(row.get::<String>(1)?, "folder")?,
                uid_validity: row.get::<i64>(2)? as u32,
                uid: row.get::<i64>(3)? as u32,
                mod_sequence: row.get::<Option<i64>>(4)?.map(|value| value as u64),
                flags: serde_json::from_str(&row.get::<String>(5)?)?,
            });
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT folder_id FROM local_folder_memberships WHERE message_id = ?1 ORDER BY folder_id",
                (id.to_string(),),
            )
            .await?;
        let mut local_folder_ids = Vec::new();
        while let Some(row) = rows.next().await? {
            local_folder_ids.push(parse_id(row.get::<String>(0)?, "folder")?);
        }
        drop(rows);
        let provider_spam = load_provider_spam_assessment_on(&connection, id).await?;
        let local_spam = crate::spam::load_assessment_on(&connection, id).await?;
        let mut rows = connection
            .query(
                "SELECT hf.id, hf.message_id, hf.heuristic_id, hf.heuristic_version, hf.code, hf.presentation, hf.severity, hf.target_kind, hf.target_id, hf.text, hf.evidence_json, hf.source_kind, hf.created_at, responses.dismissed_at FROM heuristic_findings hf JOIN heuristics h ON h.id = hf.heuristic_id AND h.version = hf.heuristic_version AND h.enabled = 1 AND h.deleted_at IS NULL LEFT JOIN heuristic_finding_responses responses ON responses.finding_id = hf.id WHERE hf.message_id = ?1 ORDER BY CASE hf.severity WHEN 'danger' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, hf.presentation, hf.id",
                (id.to_string(),),
            )
            .await?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next().await? {
            findings.push(crate::HeuristicFinding {
                id: parse_id(row.get::<String>(0)?, "heuristic finding")?,
                message_id: parse_id(row.get::<String>(1)?, "message")?,
                heuristic_id: parse_id(row.get::<String>(2)?, "heuristic")?,
                heuristic_version: u32::try_from(row.get::<i64>(3)?).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid heuristic version".into())
                })?,
                code: row.get(4)?,
                presentation: crate::automation::parse_presentation(&row.get::<String>(5)?)?,
                severity: crate::automation::parse_severity(&row.get::<String>(6)?)?,
                target_kind: crate::automation::parse_target_kind(&row.get::<String>(7)?)?,
                target_id: row.get(8)?,
                text: row.get(9)?,
                evidence: serde_json::from_str(&row.get::<String>(10)?)?,
                source_kind: crate::automation::parse_source_kind(&row.get::<String>(11)?)?,
                created_at: row.get(12)?,
                dismissed_at: row.get(13)?,
            });
        }
        drop(rows);
        let openpgp = crate::openpgp::load_evidence_on(&connection, id)
            .await?
            .unwrap_or_default();
        if openpgp.encryption != crate::OpenPgpEncryptionStatus::NotEncrypted
            || !openpgp.signatures.is_empty()
        {
            // OpenPGP mail is deliberately text-only at the backend boundary.
            // This prevents every frontend from having to independently
            // remember the EFAIL remote-content/HTML rendering rule.
            body_html = None;
        }
        let thread_id = summary.thread_id;
        Ok(Message {
            summary,
            rfc_message_id,
            in_reply_to,
            references,
            sender_addresses,
            reply_to_addresses,
            threading: ThreadMembership {
                thread_id,
                parent_message_id,
                source,
                sender_trust,
            },
            to_addresses,
            cc_addresses,
            bcc_addresses,
            delivered_to_addresses,
            list_id,
            body_text,
            body_html,
            attachments,
            links,
            instances,
            local_folder_ids,
            user_classification,
            provider_spam,
            local_spam,
            dkim,
            delivery_authentication,
            openpgp,
            findings,
        })
    }

    pub async fn raw(&self, id: MessageId) -> Result<Vec<u8>> {
        let hash = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT blob_hash, content_availability FROM messages WHERE id = ?1",
                    (id.to_string(),),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| not_found("message", id))?;
            let availability = parse_content_availability(&row.get::<String>(1)?)?;
            if availability != MessageContentAvailability::Complete {
                return Err(content_unavailable(id, availability));
            }
            row.get::<String>(0)?
        };
        self.0.inner.blobs.get(&hash).await
    }

    pub async fn content_status(&self, id: MessageId) -> Result<MessageContentStatus> {
        let connection = self.0.inner.connection.lock().await;
        load_content_status_on(&connection, id).await
    }

    pub async fn list(&self, filter: MessageFilter) -> Result<Page<MessageSummary>> {
        let mut clauses = Vec::new();
        let mut parameters = Vec::new();
        if let Some(account_id) = filter.account_id {
            clauses.push("EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.account_id = ?)".into());
            parameters.push(Value::Text(account_id.to_string()));
        }
        if let Some(folder_id) = filter.folder_id {
            clauses.push("(EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.folder_id = ?) OR EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = ?))".into());
            parameters.push(Value::Text(folder_id.to_string()));
            parameters.push(Value::Text(folder_id.to_string()));
        }
        if let Some(class) = filter.inbox_class {
            clauses.push(
                match class {
                    InboxClass::Warm => WARM_PREDICATE,
                    InboxClass::Cold => COLD_PREDICATE,
                    InboxClass::Spam => SPAM_PREDICATE,
                }
                .into(),
            );
        }
        if let Some(snoozed) = filter.snoozed {
            if snoozed {
                clauses.push("m.snoozed_until > ?".into());
            } else {
                clauses.push("(m.snoozed_until IS NULL OR m.snoozed_until <= ?)".into());
            }
            parameters.push(Value::Integer(Utc::now().timestamp()));
        }
        if let Some(muted) = filter.muted {
            clauses.push("m.muted = ?".into());
            parameters.push(Value::Integer(i64::from(muted)));
        }
        if let Some(priority) = filter.priority {
            clauses.push("m.priority = ?".into());
            parameters.push(Value::Text(message_priority_text(priority).into()));
        }
        apply_cursor(
            &mut clauses,
            &mut parameters,
            filter.cursor.as_deref(),
            filter.sort,
        )?;
        self.query_page(clauses, parameters, filter.page_size, filter.sort)
            .await
    }

    pub async fn classify(
        &self,
        id: MessageId,
        classification: Option<UserClassification>,
    ) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE messages SET user_classification = ?1 WHERE id = ?2",
                (classification.map(classification_text), id.to_string()),
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("message", id));
        }
        let model_changed =
            crate::spam::sync_user_training_on(&transaction, id, classification, now).await?;
        crate::spam::classify_message_on(&transaction, id, now).await?;
        let event = insert_event(
            &transaction,
            now,
            "message_classified",
            id.to_string(),
            json!({"message_id": id, "classification": classification}),
        )
        .await?;
        enqueue_search_on(&transaction, id).await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        drop(_search_guard);
        if model_changed {
            // Keep feedback latency bounded while making immediate progress on
            // the durable reclassification queue. Hosts can drain the rest
            // through `SpamClassifier::reclassify_pending` while idle.
            self.0.spam_classifier().reclassify_pending(64).await?;
            self.0.schedule_spam_reclassification();
        }
        self.0.heuristics().evaluate_message(id).await?;
        Ok(())
    }

    pub async fn set_snoozed_until(&self, id: MessageId, until: Option<i64>) -> Result<()> {
        if until.is_some_and(|value| value <= 0) {
            return Err(BackendError::InvalidInput(
                "snooze timestamps must be positive Unix seconds".into(),
            ));
        }
        self.set_organization_state(
            id,
            "snoozed_until",
            until.map(Value::Integer).unwrap_or(Value::Null),
            "message_snooze_changed",
            json!({"message_id": id, "snoozed_until": until}),
        )
        .await
    }

    pub async fn set_muted(&self, id: MessageId, muted: bool) -> Result<()> {
        self.set_organization_state(
            id,
            "muted",
            Value::Integer(i64::from(muted)),
            "message_mute_changed",
            json!({"message_id": id, "muted": muted}),
        )
        .await
    }

    pub async fn set_priority(
        &self,
        id: MessageId,
        priority: crate::MessagePriority,
    ) -> Result<()> {
        self.set_organization_state(
            id,
            "priority",
            Value::Text(message_priority_text(priority).into()),
            "message_priority_changed",
            json!({"message_id": id, "priority": priority}),
        )
        .await
    }

    async fn set_organization_state(
        &self,
        id: MessageId,
        column: &'static str,
        value: Value,
        event_kind: &'static str,
        payload: serde_json::Value,
    ) -> Result<()> {
        debug_assert!(matches!(column, "snoozed_until" | "muted" | "priority"));
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let sql = format!("UPDATE messages SET {column} = ?1 WHERE id = ?2");
        if transaction
            .execute(&sql, turso::params![value, id.to_string()])
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("message", id));
        }
        let event = insert_event(&transaction, now, event_kind, id.to_string(), payload).await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub async fn add_to_local_folder(&self, id: MessageId, folder_id: FolderId) -> Result<()> {
        self.set_local_folder_membership(id, folder_id, true).await
    }

    pub async fn remove_from_local_folder(&self, id: MessageId, folder_id: FolderId) -> Result<()> {
        self.set_local_folder_membership(id, folder_id, false).await
    }

    async fn set_local_folder_membership(
        &self,
        id: MessageId,
        folder_id: FolderId,
        present: bool,
    ) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT kind FROM folders WHERE id = ?1",
                (folder_id.to_string(),),
            )
            .await?;
        let kind = rows
            .next()
            .await?
            .ok_or_else(|| not_found("folder", folder_id))?
            .get::<String>(0)?;
        if parse_folder_kind(&kind)? != FolderKind::Local {
            return Err(BackendError::InvalidInput(
                "local membership can only target a local folder".into(),
            ));
        }
        drop(rows);
        let mut rows = connection
            .query("SELECT 1 FROM messages WHERE id = ?1", (id.to_string(),))
            .await?;
        if rows.next().await?.is_none() {
            return Err(not_found("message", id));
        }
        drop(rows);
        let transaction = connection.transaction().await?;
        let changed = if present {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO local_folder_memberships(message_id, folder_id, created_at) VALUES (?1, ?2, ?3)",
                    (id.to_string(), folder_id.to_string(), now),
                )
                .await?
        } else {
            transaction
                .execute(
                    "DELETE FROM local_folder_memberships WHERE message_id = ?1 AND folder_id = ?2",
                    (id.to_string(), folder_id.to_string()),
                )
                .await?
        };
        if changed == 0 {
            transaction.commit().await?;
            return Ok(());
        }
        let kind = if present {
            "local_folder_added"
        } else {
            "local_folder_removed"
        };
        let event = insert_event(
            &transaction,
            now,
            kind,
            id.to_string(),
            json!({"message_id": id, "folder_id": folder_id}),
        )
        .await?;
        enqueue_search_on(&transaction, id).await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    async fn query_page(
        &self,
        clauses: Vec<String>,
        parameters: Vec<Value>,
        requested_size: usize,
        sort: MessageSort,
    ) -> Result<Page<MessageSummary>> {
        query_page_on(&self.0, clauses, parameters, requested_size, sort).await
    }
}

#[derive(Clone)]
pub struct Search(Backend);

impl Search {
    pub async fn search(&self, request: SearchRequest) -> Result<SearchPage> {
        let expression = parse_query(&request.query)?;
        let requires_complete_content = query_requires_complete_content(&expression);
        let _search_guard = self.0.inner.search_sync.read().await;
        let page_size = bounded_page_size(request.page_size);
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        if let Some(cursor) = &cursor {
            if cursor.sort != MessageSort::ReceivedNewest
                || MessageId::from_str(&cursor.id).is_err()
            {
                return Err(BackendError::InvalidInput(
                    "invalid newest-first page cursor".into(),
                ));
            }
        }
        let cursor = cursor.map(|cursor| (cursor.received_at, cursor.id));
        let search_index = Arc::clone(&self.0.inner.search_index);
        let ids = tokio::task::spawn_blocking(move || {
            search_index.search(
                &expression,
                cursor
                    .as_ref()
                    .map(|(received_at, id)| (*received_at, id.as_str())),
                page_size + 1,
                Utc::now().timestamp(),
            )
        })
        .await
        .map_err(|error| {
            BackendError::SearchIndex(format!("search query task failed: {error}"))
        })??;
        let connection = self.0.inner.connection.lock().await;
        let mut items = summaries_by_ids_on(&connection, &ids).await?;
        let next_cursor = if items.len() > page_size {
            items.truncate(page_size);
            items
                .last()
                .map(|message| encode_cursor(message, MessageSort::ReceivedNewest))
                .transpose()?
        } else {
            None
        };
        let content_results_complete = if requires_complete_content {
            let mut rows = connection
                .query(
                    r#"SELECT 1 FROM messages m
                    WHERE m.content_availability IN ('headers_only', 'downloading', 'failed')
                       OR (EXISTS (
                            SELECT 1 FROM openpgp_message_evidence e
                            WHERE e.message_id = m.id
                              AND json_extract(e.evidence_json, '$.encryption') != 'not_encrypted'
                        ) AND NOT EXISTS (
                            SELECT 1 FROM openpgp_decrypted_messages d
                            WHERE d.message_id = m.id
                        ))
                    LIMIT 1"#,
                    (),
                )
                .await?;
            rows.next().await?.is_none()
        } else {
            true
        };
        Ok(SearchPage {
            items,
            next_cursor,
            content_results_complete,
        })
    }
}

#[derive(Clone)]
pub struct Contacts(Backend);

impl Contacts {
    pub async fn add(&self, contact: NewContact) -> Result<Contact> {
        self.add_with_provenance(contact, crate::ContactProvenance::manual())
            .await
    }

    pub(crate) async fn add_with_provenance(
        &self,
        contact: NewContact,
        provenance: crate::ContactProvenance,
    ) -> Result<Contact> {
        require_nonempty("contact name", &contact.display_name)?;
        if contact.addresses.is_empty() {
            return Err(BackendError::InvalidInput(
                "a contact requires at least one address".into(),
            ));
        }
        let addresses = contact
            .addresses
            .into_iter()
            .map(|address| {
                Ok(ContactAddress {
                    address: normalize_address(&address.address)?,
                    accepted_name: address.accepted_name,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut unique = HashSet::new();
        if addresses
            .iter()
            .any(|address| !unique.insert(address.address.clone()))
        {
            return Err(BackendError::InvalidInput(
                "a contact cannot contain the same address more than once".into(),
            ));
        }
        let now = Utc::now().timestamp();
        let value = Contact {
            id: ContactId::new(),
            display_name: contact.display_name,
            addresses,
            provenance,
            created_at: now,
            updated_at: now,
        };
        let _search_guard = self.0.inner.search_sync.write().await;
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO contacts(id, display_name, provenance_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                turso::params![
                    value.id.to_string(),
                    value.display_name.clone(),
                    serde_json::to_string(&value.provenance)?,
                    value.created_at,
                    value.updated_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO contact_relationships(contact_id, kind, warm_route, may_create_obligations, notify, remote_content, updated_at) VALUES (?1, 'person', 'action', 1, 1, 'ask', ?2)",
                (value.id.to_string(), value.created_at),
            )
            .await?;
        for address in &value.addresses {
            transaction
                .execute(
                    "INSERT INTO contact_addresses(contact_id, address, accepted_name) VALUES (?1, ?2, ?3)",
                    (
                        value.id.to_string(),
                        address.address.clone(),
                        address.accepted_name.clone(),
                    ),
                )
                .await?;
        }
        let mut affected = HashSet::new();
        for address in &value.addresses {
            let mut rows = transaction
                .query(
                    "SELECT id FROM messages WHERE from_address = ?1 COLLATE NOCASE",
                    (address.address.clone(),),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                affected.insert(parse_id(row.get::<String>(0)?, "message")?);
            }
        }
        for id in affected {
            enqueue_search_on(&transaction, id).await?;
        }
        let event = insert_event(
            &transaction,
            value.created_at,
            "contact_added",
            value.id.to_string(),
            json!({"contact_id": value.id, "addresses": value.addresses}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        Ok(value)
    }

    pub async fn list(&self) -> Result<Vec<Contact>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, display_name, provenance_json, created_at, updated_at FROM contacts ORDER BY display_name, id",
                (),
            )
            .await?;
        let mut contacts = Vec::new();
        while let Some(row) = rows.next().await? {
            contacts.push(Contact {
                id: parse_id(row.get::<String>(0)?, "contact")?,
                display_name: row.get(1)?,
                addresses: Vec::new(),
                provenance: serde_json::from_str(&row.get::<String>(2)?)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            });
        }
        drop(rows);
        for contact in &mut contacts {
            let mut rows = connection
                .query(
                    "SELECT address, accepted_name FROM contact_addresses WHERE contact_id = ?1 ORDER BY address",
                    (contact.id.to_string(),),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                contact.addresses.push(ContactAddress {
                    address: row.get(0)?,
                    accepted_name: row.get(1)?,
                });
            }
        }
        Ok(contacts)
    }

    pub async fn get(&self, id: ContactId) -> Result<Contact> {
        self.list()
            .await?
            .into_iter()
            .find(|contact| contact.id == id)
            .ok_or_else(|| not_found("contact", id))
    }

    pub async fn relationship(&self, id: ContactId) -> Result<crate::ContactRelationship> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT kind, warm_route, may_create_obligations, notify, remote_content, updated_at FROM contact_relationships WHERE contact_id = ?1",
                (id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| not_found("contact", id))?;
        Ok(crate::ContactRelationship {
            contact_id: id,
            kind: parse_relationship_kind(&row.get::<String>(0)?)?,
            warm_route: parse_warm_route(&row.get::<String>(1)?)?,
            may_create_obligations: row.get(2)?,
            notify: row.get(3)?,
            remote_content: parse_remote_content_policy(&row.get::<String>(4)?)?,
            updated_at: row.get(5)?,
        })
    }

    pub async fn set_relationship(
        &self,
        id: ContactId,
        relationship: crate::ContactRelationship,
    ) -> Result<crate::ContactRelationship> {
        if relationship.contact_id != id {
            return Err(BackendError::InvalidInput(
                "relationship contact identifier does not match target".into(),
            ));
        }
        let route_is_action = relationship.warm_route == crate::WarmRoute::Action;
        if route_is_action != relationship.may_create_obligations {
            return Err(BackendError::InvalidInput(
                "Warm Action routing and obligation permission must change together".into(),
            ));
        }
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                r#"UPDATE contact_relationships
                SET kind = ?1, warm_route = ?2, may_create_obligations = ?3,
                    notify = ?4, remote_content = ?5, updated_at = ?6
                WHERE contact_id = ?7"#,
                turso::params![
                    relationship_kind_text(relationship.kind),
                    warm_route_text(relationship.warm_route),
                    relationship.may_create_obligations,
                    relationship.notify,
                    remote_content_policy_text(relationship.remote_content),
                    now,
                    id.to_string(),
                ],
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("contact", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "contact_relationship_changed",
            id.to_string(),
            json!({
                "contact_id": id,
                "kind": relationship.kind,
                "warm_route": relationship.warm_route,
                "may_create_obligations": relationship.may_create_obligations,
                "notify": relationship.notify,
                "remote_content": relationship.remote_content,
            }),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.relationship(id).await
    }

    pub async fn update(&self, id: ContactId, contact: NewContact) -> Result<Contact> {
        require_nonempty("contact name", &contact.display_name)?;
        if contact.addresses.is_empty() {
            return Err(BackendError::InvalidInput(
                "a contact requires at least one address".into(),
            ));
        }
        let addresses = contact
            .addresses
            .into_iter()
            .map(|address| {
                Ok(ContactAddress {
                    address: normalize_address(&address.address)?,
                    accepted_name: address.accepted_name,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut unique = HashSet::new();
        if addresses
            .iter()
            .any(|address| !unique.insert(address.address.clone()))
        {
            return Err(BackendError::InvalidInput(
                "a contact cannot contain the same address more than once".into(),
            ));
        }
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut affected = HashSet::new();
        let mut rows = transaction
            .query(
                "SELECT m.id FROM messages m JOIN contact_addresses ca ON ca.address = m.from_address COLLATE NOCASE WHERE ca.contact_id = ?1",
                (id.to_string(),),
            )
            .await?;
        while let Some(row) = rows.next().await? {
            affected.insert(parse_id::<MessageId>(row.get(0)?, "message")?);
        }
        drop(rows);
        if transaction
            .execute(
                "UPDATE contacts SET display_name = ?1, updated_at = ?2 WHERE id = ?3",
                (contact.display_name, now, id.to_string()),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("contact", id));
        }
        transaction
            .execute(
                "DELETE FROM contact_addresses WHERE contact_id = ?1",
                (id.to_string(),),
            )
            .await?;
        for address in &addresses {
            transaction
                .execute(
                    "INSERT INTO contact_addresses(contact_id, address, accepted_name) VALUES (?1, ?2, ?3)",
                    (
                        id.to_string(),
                        address.address.clone(),
                        address.accepted_name.clone(),
                    ),
                )
                .await?;
            let mut rows = transaction
                .query(
                    "SELECT id FROM messages WHERE from_address = ?1 COLLATE NOCASE",
                    (address.address.clone(),),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                affected.insert(parse_id::<MessageId>(row.get(0)?, "message")?);
            }
        }
        for message_id in affected {
            enqueue_search_on(&transaction, message_id).await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "contact_updated",
            id.to_string(),
            json!({"contact_id": id, "addresses": addresses}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        self.get(id).await
    }

    pub async fn import_vcards(
        &self,
        bytes: &[u8],
        source_label: Option<String>,
    ) -> Result<crate::ContactImportResult> {
        let contacts = parse_vcards(bytes)?;
        let source_label = source_label
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if source_label
            .as_ref()
            .is_some_and(|value| value.len() > 1024)
        {
            return Err(BackendError::InvalidInput(
                "contact import source label is too long".into(),
            ));
        }
        let mut result = crate::ContactImportResult::default();
        for contact in contacts {
            let duplicate = {
                let connection = self.0.inner.connection.lock().await;
                let mut duplicate = false;
                for address in &contact.addresses {
                    let normalized = normalize_address(&address.address)?;
                    let mut rows = connection
                        .query(
                            "SELECT 1 FROM contact_addresses WHERE address = ?1 COLLATE NOCASE LIMIT 1",
                            (normalized,),
                        )
                        .await?;
                    duplicate |= rows.next().await?.is_some();
                }
                duplicate
            };
            if duplicate {
                result.skipped_duplicate_contacts += 1;
                continue;
            }
            let imported_at = Utc::now().timestamp();
            let value = self
                .add_with_provenance(
                    contact,
                    crate::ContactProvenance {
                        kind: crate::ContactProvenanceKind::VcardImport,
                        source_label: source_label.clone(),
                        imported_at: Some(imported_at),
                    },
                )
                .await?;
            result.imported.push(value.id);
        }
        Ok(result)
    }

    pub async fn export_vcards(&self) -> Result<Vec<u8>> {
        let mut output = String::new();
        for contact in self.list().await? {
            output.push_str("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:");
            output.push_str(&escape_vcard(&contact.display_name));
            output.push_str("\r\n");
            for address in contact.addresses {
                output.push_str("EMAIL:");
                output.push_str(&escape_vcard(&address.address));
                output.push_str("\r\n");
                if let Some(accepted_name) = address.accepted_name {
                    output.push_str("X-LIZARD-ACCEPTED-NAME:");
                    output.push_str(&escape_vcard(&accepted_name));
                    output.push_str("\r\n");
                }
            }
            output.push_str("END:VCARD\r\n");
        }
        Ok(output.into_bytes())
    }

    pub async fn remove(&self, id: ContactId) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                r#"SELECT m.id
                FROM messages m
                JOIN contact_addresses ca
                    ON ca.address = m.from_address COLLATE NOCASE
                WHERE ca.contact_id = ?1"#,
                (id.to_string(),),
            )
            .await?;
        let mut affected = Vec::new();
        while let Some(row) = rows.next().await? {
            affected.push(parse_id(row.get::<String>(0)?, "message")?);
        }
        drop(rows);
        let changed = transaction
            .execute("DELETE FROM contacts WHERE id = ?1", (id.to_string(),))
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("contact", id));
        }
        for message_id in affected {
            enqueue_search_on(&transaction, message_id).await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "contact_removed",
            id.to_string(),
            json!({"contact_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        Ok(())
    }
}

#[derive(Clone)]
pub struct Events(Backend);

impl Events {
    pub fn subscribe(&self) -> EventSubscription {
        EventSubscription {
            receiver: self.0.inner.events.subscribe(),
        }
    }

    pub async fn changes_since(
        &self,
        cursor: ChangeCursor,
        limit: usize,
    ) -> Result<Vec<BackendEvent>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT sequence, occurred_at, kind, entity_id, payload_json FROM changes WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
                (cursor.0 as i64, bounded_page_size(limit) as i64),
            )
            .await?;
        let mut events = Vec::new();
        while let Some(row) = rows.next().await? {
            events.push(BackendEvent {
                sequence: row.get::<i64>(0)? as u64,
                occurred_at: row.get(1)?,
                kind: row.get(2)?,
                entity_id: row.get(3)?,
                payload: serde_json::from_str(&row.get::<String>(4)?)?,
            });
        }
        Ok(events)
    }
}

/// Boundary used by IMAP transport code for cheap header discovery and later
/// on-demand, resumable body hydration.
#[derive(Clone)]
pub struct Sync(Backend);

impl Sync {
    /// Pull messages not seen by an earlier successful sync from a selected
    /// remote folder.
    ///
    /// `session` must already be authenticated over a transport which matches
    /// the account's TLS policy. Keeping connection establishment and secret
    /// lookup outside this method prevents the backend from accepting plaintext
    /// passwords or silently weakening TLS. Initial sync requests only the
    /// header fields needed for listing, search, and threading plus
    /// `BODYSTRUCTURE`; complete bodies are downloaded separately on demand.
    ///
    /// The folder cursor is advanced only after every fetched message has been
    /// durably ingested. If the operation fails partway through, retrying is
    /// safe because remote identity is keyed by folder, UIDVALIDITY, and UID.
    pub async fn pull_imap_folder<T>(
        &self,
        session: &mut async_imap::Session<T>,
        account_id: AccountId,
        folder_id: FolderId,
    ) -> Result<SyncBatchResult>
    where
        T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
    {
        let target = self.imap_sync_target(account_id, folder_id).await?;
        let mailbox = session
            .examine(&target.remote_name)
            .await
            .map_err(imap_error)?;
        let uid_validity = mailbox.uid_validity.ok_or_else(|| {
            BackendError::Imap("selected mailbox did not report UIDVALIDITY".into())
        })?;

        let same_epoch = target.uid_validity == Some(uid_validity);
        let first_uid = if same_epoch {
            target.uid_next.unwrap_or(1)
        } else {
            1
        };
        let mut uids: Vec<u32> = session
            .uid_search(format!("UID {first_uid}:{}", u32::MAX))
            .await
            .map_err(imap_error)?
            .into_iter()
            .filter(|uid| *uid >= first_uid)
            .collect();
        uids.sort_unstable();

        let mut message_ids = Vec::with_capacity(uids.len());
        let mut pending = Vec::new();
        let mut pending_bytes = 0usize;

        for uid_chunk in uids.chunks(MAX_IMAP_METADATA_UIDS) {
            let uid_set = uid_chunk
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let fetches = session
                .uid_fetch(
                    uid_set,
                    "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (DATE FROM SENDER TO CC BCC REPLY-TO DELIVERED-TO LIST-ID MESSAGE-ID IN-REPLY-TO REFERENCES SUBJECT CONTENT-TYPE MIME-VERSION AUTHENTICATION-RESULTS ARC-AUTHENTICATION-RESULTS)])",
                )
                .await
                .map_err(imap_error)?;
            let requested: HashSet<u32> = uid_chunk.iter().copied().collect();
            let fetches = crate::imap_engine::collect_requested_fetches(fetches, &requested)
                .await
                .map_err(imap_error)?;
            let mut metadata = Vec::with_capacity(uid_chunk.len());
            for fetch in fetches {
                let item = imap_fetch_headers(&fetch)?;
                metadata.push(item);
            }
            metadata.sort_unstable_by_key(|item| item.uid);
            metadata.dedup_by_key(|item| item.uid);

            for item in metadata {
                if !pending.is_empty()
                    && (pending.len() >= MAX_INGEST_BATCH_MESSAGES
                        || pending_bytes.saturating_add(item.headers.len())
                            > MAX_INGEST_BATCH_BYTES)
                {
                    let ingested = self
                        .ingest_imap_header_batch(
                            account_id,
                            folder_id,
                            uid_validity,
                            mem::take(&mut pending),
                        )
                        .await?;
                    message_ids.extend(ingested.message_ids);
                    pending_bytes = 0;
                }

                pending_bytes = pending_bytes.saturating_add(item.headers.len());
                pending.push(item);
            }
        }

        if !pending.is_empty() {
            let ingested = self
                .ingest_imap_header_batch(account_id, folder_id, uid_validity, pending)
                .await?;
            message_ids.extend(ingested.message_ids);
        }

        let observed_uid_next = uids.last().and_then(|uid| uid.checked_add(1));
        let mut uid_next = mailbox.uid_next.into_iter().chain(observed_uid_next).max();
        if same_epoch {
            uid_next = uid_next.into_iter().chain(target.uid_next).max();
        }
        self.store_imap_cursor(account_id, folder_id, uid_validity, uid_next)
            .await?;

        Ok(SyncBatchResult { message_ids })
    }

    pub async fn ingest_imap_header_batch(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        fetched: Vec<ImapFetchedHeaders>,
    ) -> Result<SyncBatchResult> {
        let blob_guard = self.0.inner.blob_references.read().await;
        let mut prepared = Vec::with_capacity(fetched.len());
        for message in fetched {
            if message.uid == 0 {
                return Err(BackendError::InvalidInput(
                    "IMAP UIDs must be non-zero".into(),
                ));
            }
            prepared.push(
                self.0
                    .prepare_imap_headers(account_id, folder_id, uid_validity, message)
                    .await?,
            );
        }
        let message_ids = self.0.commit_prepared_batch(prepared).await?;
        drop(blob_guard);
        self.0.evaluate_automation(&message_ids).await?;
        Ok(SyncBatchResult { message_ids })
    }

    /// Download and materialize one header-only message. A durable partial
    /// file is resumed on retry, and the message remains visibly incomplete
    /// until its exact byte count, MIME projection, DKIM evidence, search
    /// document, and automation results have committed atomically.
    pub async fn fetch_imap_message_content<T>(
        &self,
        session: &mut async_imap::Session<T>,
        account_id: AccountId,
        message_id: MessageId,
    ) -> Result<MessageContentStatus>
    where
        T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
    {
        let lock = self.0.download_lock(message_id).await;
        let _guard = lock.lock().await;
        let target = self.download_target(account_id, message_id).await?;
        if target.availability == MessageContentAvailability::Complete {
            return self.0.messages().content_status(message_id).await;
        }
        let path = self.0.partial_download_path(message_id);
        let downloaded = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(source) => return Err(crate::error::io_error(path, source)),
        };
        if downloaded > target.expected_bytes || downloaded > u64::from(u32::MAX) {
            let error = BackendError::Conflict(
                "durable partial message is larger than the server message".into(),
            );
            self.0
                .store_download_failure(message_id, downloaded, &error.to_string())
                .await?;
            return Err(error);
        }
        let limit = self.0.inner.config.limits.max_message_bytes;
        if target.expected_bytes > limit as u64 {
            let error = BackendError::MessageTooLarge {
                actual: usize::try_from(target.expected_bytes).unwrap_or(usize::MAX),
                limit,
            };
            self.0
                .store_download_failure(message_id, downloaded, &error.to_string())
                .await?;
            return Err(error);
        }
        let remaining_bytes = target.expected_bytes.saturating_sub(downloaded);
        self.0
            .storage()
            .ensure_account_capacity(account_id, remaining_bytes)
            .await?;
        let mut storage_reservation = self.0.inner.storage.start_reservation().await?;
        storage_reservation.grow(remaining_bytes)?;
        let mailbox = match session.examine(&target.remote_name).await {
            Ok(mailbox) => mailbox,
            Err(source) => {
                let error = imap_error(source);
                self.0
                    .store_download_failure(message_id, downloaded, &error.to_string())
                    .await?;
                return Err(error);
            }
        };
        if mailbox.uid_validity != Some(target.uid_validity) {
            let error = BackendError::Conflict(
                "message UIDVALIDITY changed before its content was downloaded".into(),
            );
            self.0
                .store_download_failure(message_id, downloaded, &error.to_string())
                .await?;
            return Err(error);
        }
        self.0
            .store_download_started(message_id, downloaded)
            .await?;
        let mut attempt = DownloadAttemptGuard::new(self.0.clone(), message_id);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|source| crate::error::io_error(path.clone(), source))?;
        let remote_size = match session.uid_fetch_body_size(target.uid).await {
            Ok(size) => u64::from(size),
            Err(source) => {
                let error = imap_error(source);
                self.0
                    .store_download_failure(message_id, downloaded, &error.to_string())
                    .await?;
                return Err(error);
            }
        };
        if remote_size != target.expected_bytes {
            let error = BackendError::Conflict(format!(
                "IMAP RFC822.SIZE changed from {} to {remote_size}",
                target.expected_bytes
            ));
            let current = file
                .metadata()
                .await
                .map(|value| value.len())
                .unwrap_or(downloaded);
            self.0
                .store_download_failure(message_id, current, &error.to_string())
                .await?;
            return Err(error);
        }
        let mut offset = downloaded;
        while offset < remote_size {
            let requested =
                usize::try_from((remote_size - offset).min(IMAP_BODY_CHUNK_BYTES as u64))
                    .expect("bounded IMAP chunk fits usize");
            if let Err(source) = session
                .uid_fetch_body_range_to(target.uid, &mut file, offset as u32, requested)
                .await
            {
                let _ = file.sync_data().await;
                let current = file
                    .metadata()
                    .await
                    .map(|value| value.len())
                    .unwrap_or(offset);
                let error = imap_error(source);
                self.0
                    .store_download_failure(message_id, current, &error.to_string())
                    .await?;
                return Err(error);
            }
            offset += requested as u64;
            storage_reservation.materialized(requested as u64)?;
            if let Err(source) = file.sync_data().await {
                let error = crate::error::io_error(path.clone(), source);
                self.0
                    .store_download_failure(message_id, offset, &error.to_string())
                    .await?;
                return Err(error);
            }
            self.0.store_download_started(message_id, offset).await?;
        }
        if let Err(source) = file.sync_all().await {
            let error = crate::error::io_error(path.clone(), source);
            self.0
                .store_download_failure(message_id, offset, &error.to_string())
                .await?;
            return Err(error);
        }
        drop(file);
        drop(storage_reservation);
        let result = self
            .0
            .hydrate_downloaded_message(message_id, &path, target.expected_bytes)
            .await;
        match result {
            Ok(status) => {
                attempt.disarm();
                // Publication already committed. Cleanup failure must not make
                // the caller retry an operation that is now complete.
                let _ = tokio::fs::remove_file(&path).await;
                Ok(status)
            }
            Err(error) => {
                let current = tokio::fs::metadata(&path)
                    .await
                    .map(|value| value.len())
                    .unwrap_or(target.expected_bytes);
                self.0
                    .store_download_failure(message_id, current, &error.to_string())
                    .await?;
                Err(error)
            }
        }
    }

    pub async fn ingest_imap_batch(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        fetched: Vec<ImapFetchedMessage>,
    ) -> Result<SyncBatchResult> {
        let mut requests = Vec::with_capacity(fetched.len());
        for message in fetched {
            if message.uid == 0 {
                return Err(BackendError::InvalidInput(
                    "IMAP UIDs must be non-zero".into(),
                ));
            }
            requests.push(IngestMessage {
                raw: message.raw,
                remote: Some(RemoteMessageIdentity {
                    account_id,
                    folder_id,
                    uid_validity,
                    uid: message.uid,
                    mod_sequence: message.mod_sequence,
                    flags: message.flags,
                }),
                received_at: message.internal_date,
                user_classification: None,
            });
        }
        let message_ids = self.0.ingest_batch(requests).await?;
        Ok(SyncBatchResult { message_ids })
    }

    async fn imap_sync_target(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
    ) -> Result<ImapSyncTarget> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT f.account_id, f.kind, f.remote_name, f.uid_validity, f.uid_next, a.kind FROM folders f LEFT JOIN accounts a ON a.id = f.account_id WHERE f.id = ?1",
                (folder_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(not_found("folder", folder_id));
        };
        let stored_account = row
            .get::<Option<String>>(0)?
            .map(|id| parse_id(id, "account"))
            .transpose()?;
        let folder_kind = parse_folder_kind(&row.get::<String>(1)?)?;
        let remote_name = row.get::<Option<String>>(2)?;
        let uid_validity = optional_database_u32(row.get(3)?, "folders.uid_validity")?;
        let uid_next = optional_database_u32(row.get(4)?, "folders.uid_next")?;
        let account_kind = row
            .get::<Option<String>>(5)?
            .map(|kind| parse_account_kind(&kind))
            .transpose()?;

        if stored_account != Some(account_id)
            || folder_kind != FolderKind::Remote
            || account_kind != Some(AccountKind::Imap)
        {
            return Err(BackendError::InvalidInput(
                "folder is not a remote IMAP folder belonging to the account".into(),
            ));
        }
        let remote_name = remote_name.filter(|name| !name.is_empty()).ok_or_else(|| {
            BackendError::InvalidInput("remote IMAP folder has no remote name".into())
        })?;
        Ok(ImapSyncTarget {
            remote_name,
            uid_validity,
            uid_next,
        })
    }

    async fn download_target(
        &self,
        account_id: AccountId,
        message_id: MessageId,
    ) -> Result<ImapDownloadTarget> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT mi.folder_id, f.remote_name, mi.uid_validity, mi.imap_uid,
                    m.size_bytes, m.content_availability
                FROM messages m
                JOIN message_instances mi ON mi.message_id = m.id
                JOIN folders f ON f.id = mi.folder_id
                LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                WHERE m.id = ?1 AND mi.account_id = ?2 AND f.kind = 'remote'
                    AND f.remote_name IS NOT NULL
                    AND COALESCE(ims.remote_present, 1) = 1
                    AND COALESCE(ims.selectable, 1) = 1
                ORDER BY mi.folder_id, mi.imap_uid
                LIMIT 1"#,
                (message_id.to_string(), account_id.to_string()),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            let mut existing = connection
                .query(
                    "SELECT 1 FROM messages WHERE id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
            if existing.next().await?.is_none() {
                return Err(not_found("message", message_id));
            }
            return Err(BackendError::InvalidInput(
                "message has no downloadable instance for this IMAP account".into(),
            ));
        };
        Ok(ImapDownloadTarget {
            remote_name: row.get::<String>(1)?,
            uid_validity: u32::try_from(row.get::<i64>(2)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid UIDVALIDITY".into())
            })?,
            uid: u32::try_from(row.get::<i64>(3)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid IMAP UID".into())
            })?,
            expected_bytes: u64::try_from(row.get::<i64>(4)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid message size".into())
            })?,
            availability: parse_content_availability(&row.get::<String>(5)?)?,
        })
    }

    async fn store_imap_cursor(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        uid_next: Option<u32>,
    ) -> Result<()> {
        let connection = self.0.inner.connection.lock().await;
        let changed = connection
            .execute(
                "UPDATE folders SET uid_validity = ?1, uid_next = ?2 WHERE id = ?3 AND account_id = ?4",
                turso::params![
                    i64::from(uid_validity),
                    uid_next.map(i64::from),
                    folder_id.to_string(),
                    account_id.to_string(),
                ],
            )
            .await?;
        if changed != 1 {
            return Err(BackendError::Conflict(
                "remote folder changed while IMAP sync was running".into(),
            ));
        }
        Ok(())
    }
}

struct ImapSyncTarget {
    remote_name: String,
    uid_validity: Option<u32>,
    uid_next: Option<u32>,
}

struct ImapDownloadTarget {
    remote_name: String,
    uid_validity: u32,
    uid: u32,
    expected_bytes: u64,
    availability: MessageContentAvailability,
}

fn imap_error(error: async_imap::error::Error) -> BackendError {
    let detail = error.to_string();
    if crate::error::is_storage_full_message(&detail) {
        crate::error::storage_full_unknown()
    } else {
        BackendError::Imap(detail)
    }
}

fn optional_database_u32(value: Option<i64>, field: &str) -> Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|_| {
                BackendError::InvalidInput(format!("database contains invalid {field}"))
            })
        })
        .transpose()
}

pub(crate) const WARM_PREDICATE: &str = "NOT (COALESCE(m.user_classification = 'spam', 0) OR (m.user_classification IS NULL AND ((EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'spam') AND NOT EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'not_spam')) OR EXISTS (SELECT 1 FROM local_spam_assessments lsa WHERE lsa.message_id = m.id AND lsa.verdict = 'spam')))) AND m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE)";
pub(crate) const COLD_PREDICATE: &str = "NOT (COALESCE(m.user_classification = 'spam', 0) OR (m.user_classification IS NULL AND ((EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'spam') AND NOT EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'not_spam')) OR EXISTS (SELECT 1 FROM local_spam_assessments lsa WHERE lsa.message_id = m.id AND lsa.verdict = 'spam')))) AND (m.from_address IS NULL OR NOT EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE))";
pub(crate) const SPAM_PREDICATE: &str = "(COALESCE(m.user_classification = 'spam', 0) OR (m.user_classification IS NULL AND ((EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'spam') AND NOT EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'not_spam')) OR EXISTS (SELECT 1 FROM local_spam_assessments lsa WHERE lsa.message_id = m.id AND lsa.verdict = 'spam'))))";
const SUMMARY_COLUMNS: &str = "m.id, m.subject, m.from_address, m.from_name, m.preview, m.sent_at, m.received_at, m.size_bytes, m.has_attachment, m.is_read, m.is_starred, m.snoozed_until, m.muted, m.priority, CASE WHEN (COALESCE(m.user_classification = 'spam', 0) OR (m.user_classification IS NULL AND ((EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'spam') AND NOT EXISTS (SELECT 1 FROM provider_spam_evidence pse WHERE pse.message_id = m.id AND pse.verdict = 'not_spam')) OR EXISTS (SELECT 1 FROM local_spam_assessments lsa WHERE lsa.message_id = m.id AND lsa.verdict = 'spam')))) THEN 'spam' WHEN m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE) THEN 'warm' ELSE 'cold' END, m.content_state, m.thread_id, m.content_availability";
const SUMMARY_COLUMN_COUNT: usize = 18;

async fn query_page_on(
    backend: &Backend,
    clauses: Vec<String>,
    parameters: Vec<Value>,
    requested_size: usize,
    sort: MessageSort,
) -> Result<Page<MessageSummary>> {
    let page_size = bounded_page_size(requested_size);
    let connection = backend.inner.connection.lock().await;
    let mut items =
        query_summaries_on(&connection, clauses, parameters, page_size + 1, sort).await?;
    let next_cursor = if items.len() > page_size {
        items.truncate(page_size);
        items
            .last()
            .map(|message| encode_cursor(message, sort))
            .transpose()?
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

async fn query_summaries_on(
    connection: &Connection,
    clauses: Vec<String>,
    mut parameters: Vec<Value>,
    limit: usize,
    sort: MessageSort,
) -> Result<Vec<MessageSummary>> {
    let mut sql = format!("SELECT {SUMMARY_COLUMNS} FROM messages m");
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(match sort {
        MessageSort::ReceivedNewest => " ORDER BY m.received_at DESC, m.id DESC LIMIT ?",
        MessageSort::ReceivedOldest => " ORDER BY m.received_at ASC, m.id ASC LIMIT ?",
    });
    parameters.push(Value::Integer(limit as i64));
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().await? {
        items.push(summary_from_row(&row)?);
    }
    Ok(items)
}

async fn summaries_by_ids_on(
    connection: &Connection,
    ids: &[String],
) -> Result<Vec<MessageSummary>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {SUMMARY_COLUMNS} FROM messages m WHERE m.id IN ({placeholders})");
    let parameters = ids.iter().cloned().map(Value::Text).collect::<Vec<_>>();
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    let mut by_id = HashMap::with_capacity(ids.len());
    while let Some(row) = rows.next().await? {
        let summary = summary_from_row(&row)?;
        by_id.insert(summary.id.to_string(), summary);
    }
    let mut summaries = Vec::with_capacity(ids.len());
    for id in ids {
        summaries.push(by_id.remove(id).ok_or_else(|| {
            BackendError::SearchIndex(format!("search index references missing message {id}"))
        })?);
    }
    Ok(summaries)
}

async fn prepare_search_index(
    profile_dir: &std::path::Path,
    connection: &mut Connection,
) -> Result<Arc<SearchIndex>> {
    let generation = search_generation_on(connection).await?;
    if let Ok(index) = SearchIndex::open(profile_dir, &generation) {
        let index = Arc::new(index);
        flush_search_projection_on(connection, Arc::clone(&index)).await?;
        if index.num_docs() == message_count_on(connection).await? {
            return Ok(index);
        }
        drop(index);
    }

    let transaction = connection.transaction().await?;
    transaction
        .execute("DELETE FROM search_index_queue", ())
        .await?;
    transaction
        .execute(
            "INSERT INTO search_index_queue(message_id, revision) SELECT id, 1 FROM messages",
            (),
        )
        .await?;
    transaction.commit().await?;

    let index = Arc::new(SearchIndex::create(profile_dir)?);
    flush_search_projection_on(connection, Arc::clone(&index)).await?;
    let expected = message_count_on(connection).await?;
    if index.num_docs() != expected {
        return Err(BackendError::SearchIndex(format!(
            "rebuilt search index contains {} documents but database contains {expected}",
            index.num_docs()
        )));
    }
    index.write_manifest(&generation)?;
    Ok(index)
}

async fn flush_search_projection_on(
    connection: &mut Connection,
    search_index: Arc<SearchIndex>,
) -> Result<()> {
    loop {
        let queued = load_queued_search_documents(connection, MAX_INGEST_BATCH_MESSAGES).await?;
        if queued.is_empty() {
            return Ok(());
        }
        let revisions = queued
            .iter()
            .map(|queued| (queued.document.id.clone(), queued.revision))
            .collect::<Vec<_>>();
        let documents = queued
            .into_iter()
            .map(|queued| queued.document)
            .collect::<Vec<_>>();
        let index = Arc::clone(&search_index);
        tokio::task::spawn_blocking(move || index.replace_documents(documents))
            .await
            .map_err(|error| {
                BackendError::SearchIndex(format!("search indexing task failed: {error}"))
            })??;
        let transaction = connection.transaction().await?;
        for (id, revision) in revisions {
            transaction
                .execute(
                    "DELETE FROM search_index_queue WHERE message_id = ?1 AND revision = ?2",
                    (id, revision),
                )
                .await?;
        }
        transaction.commit().await?;
    }
}

async fn load_queued_search_documents(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<QueuedSearchDocument>> {
    let mut rows = connection
        .query(
            r#"SELECT q.revision, m.id,
                COALESCE(d.subject, m.subject), COALESCE(d.body_text, m.body_text),
                COALESCE(d.from_address, m.from_address),
                m.to_addresses, m.cc_addresses, m.bcc_addresses,
                m.delivered_to_addresses, m.list_id,
                COALESCE(d.attachment_names, m.attachment_names),
                m.rfc_message_id, m.received_at, m.size_bytes,
                CASE WHEN d.message_id IS NOT NULL THEN d.has_attachment ELSE m.has_attachment END,
                m.is_read, m.is_starred,
                CASE
                    WHEN (m.user_classification = 'spam' OR (
                        m.user_classification IS NULL
                        AND (
                            (EXISTS (
                                SELECT 1 FROM provider_spam_evidence pse
                                WHERE pse.message_id = m.id AND pse.verdict = 'spam'
                            ) AND NOT EXISTS (
                                SELECT 1 FROM provider_spam_evidence pse
                                WHERE pse.message_id = m.id AND pse.verdict = 'not_spam'
                            ))
                            OR EXISTS (
                                SELECT 1 FROM local_spam_assessments lsa
                                WHERE lsa.message_id = m.id AND lsa.verdict = 'spam'
                            )
                        )
                    )) THEN 'spam'
                    WHEN m.from_address IS NOT NULL AND EXISTS (
                        SELECT 1 FROM contact_addresses ca
                        WHERE ca.address = m.from_address COLLATE NOCASE
                    ) THEN 'warm'
                    ELSE 'cold'
                END
            FROM search_index_queue q
            JOIN messages m ON m.id = q.message_id
            LEFT JOIN openpgp_decrypted_messages d ON d.message_id = m.id
            ORDER BY q.message_id
            LIMIT ?1"#,
            (limit as i64,),
        )
        .await?;
    let mut queued = Vec::new();
    while let Some(row) = rows.next().await? {
        queued.push(QueuedSearchDocument {
            revision: row.get(0)?,
            document: SearchDocument {
                id: row.get(1)?,
                subject: row.get(2)?,
                body_text: row.get(3)?,
                from_address: row.get(4)?,
                to_addresses: json_addresses(row.get(5)?)?,
                cc_addresses: json_addresses(row.get(6)?)?,
                bcc_addresses: json_addresses(row.get(7)?)?,
                delivered_to_addresses: json_addresses(row.get(8)?)?,
                list_id: row.get(9)?,
                attachment_names: row.get(10)?,
                rfc_message_id: row.get(11)?,
                received_at: row.get(12)?,
                size_bytes: row.get(13)?,
                has_attachment: row.get(14)?,
                is_read: row.get(15)?,
                is_starred: row.get(16)?,
                inbox_class: row.get(17)?,
                folder_lookups: Vec::new(),
                account_lookups: Vec::new(),
            },
        });
    }
    drop(rows);
    if queued.is_empty() {
        return Ok(queued);
    }

    let mut positions = HashMap::with_capacity(queued.len());
    for (position, item) in queued.iter().enumerate() {
        positions.insert(item.document.id.clone(), position);
    }
    let placeholders = std::iter::repeat_n("?", queued.len())
        .collect::<Vec<_>>()
        .join(", ");
    let parameters = queued
        .iter()
        .map(|item| Value::Text(item.document.id.clone()))
        .collect::<Vec<_>>();
    let mut rows = connection
        .query(
            format!(
                r#"SELECT mi.message_id, a.id, a.name, f.id, f.name, f.remote_name
                FROM message_instances mi
                JOIN accounts a ON a.id = mi.account_id
                JOIN folders f ON f.id = mi.folder_id
                WHERE mi.message_id IN ({placeholders})"#
            ),
            params_from_iter(parameters.clone()),
        )
        .await?;
    while let Some(row) = rows.next().await? {
        let id: String = row.get(0)?;
        if let Some(position) = positions.get(&id).copied() {
            let document = &mut queued[position].document;
            document.account_lookups.push(row.get(1)?);
            document.account_lookups.push(row.get(2)?);
            document.folder_lookups.push(row.get(3)?);
            document.folder_lookups.push(row.get(4)?);
            if let Some(remote_name) = row.get::<Option<String>>(5)? {
                document.folder_lookups.push(remote_name);
            }
        }
    }
    drop(rows);
    let mut rows = connection
        .query(
            format!(
                r#"SELECT lm.message_id, f.id, f.name, f.remote_name
                FROM local_folder_memberships lm
                JOIN folders f ON f.id = lm.folder_id
                WHERE lm.message_id IN ({placeholders})"#
            ),
            params_from_iter(parameters),
        )
        .await?;
    while let Some(row) = rows.next().await? {
        let id: String = row.get(0)?;
        if let Some(position) = positions.get(&id).copied() {
            let document = &mut queued[position].document;
            document.folder_lookups.push(row.get(1)?);
            document.folder_lookups.push(row.get(2)?);
            if let Some(remote_name) = row.get::<Option<String>>(3)? {
                document.folder_lookups.push(remote_name);
            }
        }
    }
    for item in &mut queued {
        item.document.folder_lookups.sort_unstable();
        item.document.folder_lookups.dedup();
        item.document.account_lookups.sort_unstable();
        item.document.account_lookups.dedup();
    }
    Ok(queued)
}

pub(crate) async fn enqueue_search_on(connection: &Connection, id: MessageId) -> Result<()> {
    connection
        .execute(
            r#"INSERT INTO search_index_queue(message_id, revision) VALUES (?1, 1)
            ON CONFLICT(message_id) DO UPDATE
            SET revision = search_index_queue.revision + 1"#,
            (id.to_string(),),
        )
        .await?;
    Ok(())
}

async fn search_generation_on(connection: &Connection) -> Result<String> {
    let mut rows = connection
        .query(
            "SELECT generation FROM search_index_meta WHERE singleton = 1",
            (),
        )
        .await?;
    rows.next()
        .await?
        .ok_or_else(|| BackendError::SearchIndex("database has no search generation".into()))?
        .get(0)
        .map_err(Into::into)
}

async fn message_count_on(connection: &Connection) -> Result<u64> {
    let mut rows = connection
        .query("SELECT count(*) FROM messages", ())
        .await?;
    let count = rows
        .next()
        .await?
        .ok_or_else(|| BackendError::SearchIndex("message count query returned no row".into()))?
        .get::<i64>(0)?;
    Ok(count as u64)
}

fn summary_from_row(row: &turso::Row) -> Result<MessageSummary> {
    Ok(MessageSummary {
        id: parse_id(row.get::<String>(0)?, "message")?,
        thread_id: parse_id(row.get::<String>(16)?, "thread")?,
        subject: row.get(1)?,
        from_address: row.get(2)?,
        from_name: row.get(3)?,
        preview: row.get(4)?,
        sent_at: row.get(5)?,
        received_at: row.get(6)?,
        size_bytes: row.get::<i64>(7)? as u64,
        has_attachment: row.get(8)?,
        is_read: row.get(9)?,
        is_starred: row.get(10)?,
        snoozed_until: row.get(11)?,
        muted: row.get(12)?,
        priority: parse_message_priority(&row.get::<String>(13)?)?,
        inbox_class: parse_inbox_class(&row.get::<String>(14)?)?,
        content_state: parse_content_state(&row.get::<String>(15)?)?,
        content_availability: parse_content_availability(&row.get::<String>(17)?)?,
    })
}

async fn refresh_delivery_auth_trust_on(
    connection: &Connection,
    evidence: &mut crate::DeliveryAuthentication,
) -> Result<()> {
    let account_ids = evidence
        .observations
        .iter()
        .filter_map(|observation| observation.account_id)
        .collect::<HashSet<_>>();
    for account_id in account_ids {
        let mut rows = connection
            .query(
                "SELECT trusted_authserv_ids_json FROM accounts WHERE id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let trusted_authserv_ids = match rows.next().await? {
            Some(row) => serde_json::from_str::<Vec<String>>(&row.get::<String>(0)?)?,
            None => Vec::new(),
        };
        drop(rows);
        crate::delivery_auth::refresh_trust(evidence, account_id, &trusted_authserv_ids);
    }
    Ok(())
}

async fn lookup_remote_on(
    connection: &Connection,
    folder_id: FolderId,
    uid_validity: u32,
    uid: u32,
) -> Result<Option<MessageId>> {
    let mut rows = connection
        .query(
            "SELECT message_id FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
            (folder_id.to_string(), uid_validity as i64, uid as i64),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| parse_id(row.get::<String>(0)?, "message"))
        .transpose()
}

async fn load_content_status_on(
    connection: &Connection,
    message_id: MessageId,
) -> Result<MessageContentStatus> {
    let mut rows = connection
        .query(
            "SELECT content_availability, size_bytes, downloaded_bytes, download_error, download_updated_at FROM messages WHERE id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| not_found("message", message_id))?;
    Ok(MessageContentStatus {
        message_id,
        availability: parse_content_availability(&row.get::<String>(0)?)?,
        expected_bytes: u64::try_from(row.get::<i64>(1)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid message size".into())
        })?,
        downloaded_bytes: u64::try_from(row.get::<i64>(2)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid downloaded byte count".into())
        })?,
        last_error: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

async fn load_provider_spam_assessment_on(
    connection: &Connection,
    message_id: MessageId,
) -> Result<ProviderSpamAssessment> {
    let mut rows = connection
        .query(
            "SELECT account_id, folder_id, uid_validity, imap_uid, source, verdict, observed_at FROM provider_spam_evidence WHERE message_id = ?1 ORDER BY account_id, folder_id, uid_validity, imap_uid, source",
            (message_id.to_string(),),
        )
        .await?;
    let mut evidence = Vec::new();
    let mut has_spam = false;
    let mut has_not_spam = false;
    while let Some(row) = rows.next().await? {
        let verdict = parse_spam_evidence_verdict(&row.get::<String>(5)?)?;
        has_spam |= verdict == SpamEvidenceVerdict::Spam;
        has_not_spam |= verdict == SpamEvidenceVerdict::NotSpam;
        evidence.push(ProviderSpamEvidence {
            account_id: parse_id(row.get::<String>(0)?, "account")?,
            folder_id: parse_id(row.get::<String>(1)?, "folder")?,
            uid_validity: u32::try_from(row.get::<i64>(2)?).map_err(|_| {
                BackendError::InvalidInput(
                    "database contains invalid provider-evidence UIDVALIDITY".into(),
                )
            })?,
            uid: u32::try_from(row.get::<i64>(3)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid provider-evidence UID".into())
            })?,
            source: parse_provider_spam_source(&row.get::<String>(4)?)?,
            verdict,
            observed_at: row.get(6)?,
        });
    }
    let verdict = match (has_spam, has_not_spam) {
        (false, false) => ProviderSpamVerdict::Unknown,
        (true, false) => ProviderSpamVerdict::Spam,
        (false, true) => ProviderSpamVerdict::NotSpam,
        (true, true) => ProviderSpamVerdict::Conflicting,
    };
    Ok(ProviderSpamAssessment { verdict, evidence })
}

async fn lookup_sent_reconciliation_on(
    connection: &Connection,
    account_id: AccountId,
    folder_id: FolderId,
    rfc_message_id: Option<&str>,
    from_address: Option<&str>,
) -> Result<Option<MessageId>> {
    let (Some(rfc_message_id), Some(from_address)) = (rfc_message_id, from_address) else {
        return Ok(None);
    };
    let mut rows = connection
        .query(
            "SELECT attributes_json FROM imap_mailbox_state WHERE folder_id = ?1 AND remote_present = 1",
            (folder_id.to_string(),),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let attributes: Vec<String> = serde_json::from_str(&row.get::<String>(0)?)?;
    if !attributes
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("\\Sent"))
    {
        return Ok(None);
    }
    drop(rows);
    let mut rows = connection
        .query(
            "SELECT reconciliation.message_id FROM sent_reconciliation reconciliation JOIN messages ON messages.id = reconciliation.message_id WHERE reconciliation.rfc_message_id = ?1 AND reconciliation.account_id = ?2 AND messages.from_address = ?3 COLLATE NOCASE LIMIT 2",
            (rfc_message_id, account_id.to_string(), from_address),
        )
        .await?;
    let first = rows
        .next()
        .await?
        .map(|row| parse_id(row.get::<String>(0)?, "message"))
        .transpose()?;
    if first.is_some() && rows.next().await?.is_some() {
        return Err(BackendError::Conflict(
            "multiple sent messages share one protected Message-ID".into(),
        ));
    }
    Ok(first)
}

pub(crate) async fn refresh_provider_spam_evidence_in_transaction(
    connection: &Connection,
    message_id: MessageId,
    remote: &RemoteMessageIdentity,
) -> Result<()> {
    connection
        .execute(
            "DELETE FROM provider_spam_evidence WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
            (
                remote.folder_id.to_string(),
                i64::from(remote.uid_validity),
                i64::from(remote.uid),
            ),
        )
        .await?;

    let mut rows = connection
        .query(
            "SELECT attributes_json FROM imap_mailbox_state WHERE folder_id = ?1",
            (remote.folder_id.to_string(),),
        )
        .await?;
    let junk_mailbox = if let Some(row) = rows.next().await? {
        let attributes: Vec<String> = serde_json::from_str(&row.get::<String>(0)?)?;
        attributes
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("\\Junk"))
    } else {
        false
    };
    drop(rows);

    let mut observations = Vec::with_capacity(3);
    if junk_mailbox {
        observations.push(("imap_junk_mailbox", "spam"));
    }
    if remote
        .flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("$Junk"))
    {
        observations.push(("imap_junk_keyword", "spam"));
    }
    if remote
        .flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("$NotJunk"))
    {
        observations.push(("imap_not_junk_keyword", "not_spam"));
    }
    let now = Utc::now().timestamp();
    for (source, verdict) in observations {
        connection
            .execute(
                "INSERT INTO provider_spam_evidence(message_id, account_id, folder_id, uid_validity, imap_uid, source, verdict, observed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                turso::params![
                    message_id.to_string(),
                    remote.account_id.to_string(),
                    remote.folder_id.to_string(),
                    i64::from(remote.uid_validity),
                    i64::from(remote.uid),
                    source,
                    verdict,
                    now,
                ],
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn refresh_junk_mailbox_evidence_in_transaction(
    connection: &Connection,
    folder_id: FolderId,
    is_junk: bool,
    observed_at: i64,
) -> Result<Vec<MessageId>> {
    let mut rows = connection
        .query(
            "SELECT DISTINCT message_id FROM message_instances WHERE folder_id = ?1 ORDER BY message_id",
            (folder_id.to_string(),),
        )
        .await?;
    let mut message_ids = Vec::new();
    while let Some(row) = rows.next().await? {
        message_ids.push(parse_id(row.get::<String>(0)?, "message")?);
    }
    drop(rows);
    connection
        .execute(
            "DELETE FROM provider_spam_evidence WHERE folder_id = ?1 AND source = 'imap_junk_mailbox'",
            (folder_id.to_string(),),
        )
        .await?;
    if is_junk {
        connection
            .execute(
                r#"INSERT INTO provider_spam_evidence (
                    message_id, account_id, folder_id, uid_validity, imap_uid,
                    source, verdict, observed_at
                )
                SELECT message_id, account_id, folder_id, uid_validity, imap_uid,
                    'imap_junk_mailbox', 'spam', ?1
                FROM message_instances WHERE folder_id = ?2"#,
                (observed_at, folder_id.to_string()),
            )
            .await?;
    }
    for message_id in &message_ids {
        enqueue_search_on(connection, *message_id).await?;
    }
    Ok(message_ids)
}

pub(crate) async fn refresh_remote_in_transaction(
    connection: &Connection,
    id: MessageId,
    remote: &RemoteMessageIdentity,
) -> Result<Option<BackendEvent>> {
    let flags = canonical_flags(&remote.flags);
    let flags_json = serde_json::to_string(&flags)?;
    let mut rows = connection
        .query(
            "SELECT mod_sequence, flags_json FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
            (
                remote.folder_id.to_string(),
                remote.uid_validity as i64,
                remote.uid as i64,
            ),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| not_found("remote message instance", id))?;
    let existing_mod_sequence = row.get::<Option<i64>>(0)?.map(|value| value as u64);
    let existing_flags = row.get::<String>(1)?;
    drop(rows);
    if existing_mod_sequence == remote.mod_sequence && existing_flags == flags_json {
        return Ok(None);
    }

    let is_read = flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen"));
    let is_starred = flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"));
    let now = Utc::now().timestamp();
    connection
        .execute(
            "UPDATE message_instances SET mod_sequence = ?1, flags_json = ?2 WHERE folder_id = ?3 AND uid_validity = ?4 AND imap_uid = ?5",
            turso::params![
                remote.mod_sequence.map(|value| value as i64),
                flags_json,
                remote.folder_id.to_string(),
                remote.uid_validity as i64,
                remote.uid as i64,
            ],
        )
        .await?;
    connection
        .execute(
            "UPDATE messages SET is_read = ?1, is_starred = ?2 WHERE id = ?3",
            (is_read, is_starred, id.to_string()),
        )
        .await?;
    refresh_provider_spam_evidence_in_transaction(connection, id, remote).await?;
    enqueue_search_on(connection, id).await?;
    let event = insert_event(
        connection,
        now,
        "message_remote_state_changed",
        id.to_string(),
        json!({
            "message_id": id,
            "folder_id": remote.folder_id,
            "uid_validity": remote.uid_validity,
            "uid": remote.uid,
            "mod_sequence": remote.mod_sequence,
            "flags": flags,
        }),
    )
    .await?;
    Ok(Some(event))
}

pub(crate) async fn insert_event(
    connection: &Connection,
    occurred_at: i64,
    kind: &str,
    entity_id: String,
    payload: serde_json::Value,
) -> Result<BackendEvent> {
    let payload_json = serde_json::to_string(&payload)?;
    connection
        .execute(
            "INSERT INTO changes(occurred_at, kind, entity_id, payload_json) VALUES (?1, ?2, ?3, ?4)",
            (occurred_at, kind, entity_id.clone(), payload_json),
        )
        .await?;
    Ok(BackendEvent {
        sequence: connection.last_insert_rowid() as u64,
        occurred_at,
        kind: kind.to_owned(),
        entity_id,
        payload,
    })
}

#[derive(Serialize, Deserialize)]
struct PageCursor {
    received_at: i64,
    id: String,
    sort: MessageSort,
}

fn encode_cursor(message: &MessageSummary, sort: MessageSort) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&PageCursor {
        received_at: message.received_at,
        id: message.id.to_string(),
        sort,
    })?))
}

fn decode_cursor(value: &str) -> Result<PageCursor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BackendError::InvalidInput("invalid page cursor".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| BackendError::InvalidInput("invalid page cursor".into()))
}

fn apply_cursor(
    clauses: &mut Vec<String>,
    parameters: &mut Vec<Value>,
    cursor: Option<&str>,
    sort: MessageSort,
) -> Result<()> {
    if let Some(cursor) = cursor {
        let cursor = decode_cursor(cursor)?;
        if cursor.sort != sort {
            return Err(BackendError::InvalidInput(
                "page cursor belongs to a different sort order".into(),
            ));
        }
        MessageId::from_str(&cursor.id)
            .map_err(|_| BackendError::InvalidInput("invalid page cursor".into()))?;
        clauses.push(
            match sort {
                MessageSort::ReceivedNewest => {
                    "(m.received_at < ? OR (m.received_at = ? AND m.id < ?))"
                }
                MessageSort::ReceivedOldest => {
                    "(m.received_at > ? OR (m.received_at = ? AND m.id > ?))"
                }
            }
            .into(),
        );
        parameters.push(Value::Integer(cursor.received_at));
        parameters.push(Value::Integer(cursor.received_at));
        parameters.push(Value::Text(cursor.id));
    }
    Ok(())
}

fn bounded_page_size(requested: usize) -> usize {
    requested.clamp(1, 200)
}

fn json_addresses(value: String) -> Result<Vec<String>> {
    serde_json::from_str(&value).map_err(Into::into)
}

const MAX_CONTACT_IMPORT_BYTES: usize = 10 * 1024 * 1024;
const MAX_CONTACT_IMPORT_COUNT: usize = 10_000;

fn parse_vcards(bytes: &[u8]) -> Result<Vec<NewContact>> {
    if bytes.len() > MAX_CONTACT_IMPORT_BYTES {
        return Err(BackendError::InvalidInput(format!(
            "vCard import exceeds the {MAX_CONTACT_IMPORT_BYTES}-byte limit"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| BackendError::InvalidInput("vCard import is not UTF-8".into()))?;
    if text.contains('\0') {
        return Err(BackendError::InvalidInput(
            "vCard import contains a NUL byte".into(),
        ));
    }
    let mut unfolded = Vec::<String>::new();
    for raw in text.replace("\r\n", "\n").replace('\r', "\n").lines() {
        if raw.starts_with([' ', '\t']) {
            let Some(previous) = unfolded.last_mut() else {
                return Err(BackendError::InvalidInput(
                    "vCard import begins with a folded line".into(),
                ));
            };
            previous.push_str(&raw[1..]);
        } else {
            unfolded.push(raw.to_owned());
        }
    }
    let mut contacts = Vec::new();
    let mut current_name = None;
    let mut current_addresses = Vec::new();
    let mut inside = false;
    for line in unfolded {
        if line.eq_ignore_ascii_case("BEGIN:VCARD") {
            if inside {
                return Err(BackendError::InvalidInput(
                    "nested vCard records are invalid".into(),
                ));
            }
            inside = true;
            current_name = None;
            current_addresses.clear();
            continue;
        }
        if line.eq_ignore_ascii_case("END:VCARD") {
            if !inside {
                return Err(BackendError::InvalidInput(
                    "vCard END appears without BEGIN".into(),
                ));
            }
            let display_name = current_name.take().ok_or_else(|| {
                BackendError::InvalidInput("vCard contact has no FN field".into())
            })?;
            if current_addresses.is_empty() {
                return Err(BackendError::InvalidInput(
                    "vCard contact has no EMAIL field".into(),
                ));
            }
            contacts.push(NewContact {
                display_name,
                addresses: mem::take(&mut current_addresses),
            });
            if contacts.len() > MAX_CONTACT_IMPORT_COUNT {
                return Err(BackendError::InvalidInput(format!(
                    "vCard import exceeds the {MAX_CONTACT_IMPORT_COUNT}-contact limit"
                )));
            }
            inside = false;
            continue;
        }
        if !inside {
            if !line.trim().is_empty() {
                return Err(BackendError::InvalidInput(
                    "data outside a vCard record is invalid".into(),
                ));
            }
            continue;
        }
        let Some((name_and_parameters, value)) = line.split_once(':') else {
            continue;
        };
        let name = name_and_parameters
            .split(';')
            .next()
            .unwrap_or_default()
            .rsplit_once('.')
            .map_or(
                name_and_parameters.split(';').next().unwrap_or_default(),
                |(_, name)| name,
            );
        if name.eq_ignore_ascii_case("FN") {
            current_name = Some(unescape_vcard(value)?);
        } else if name.eq_ignore_ascii_case("EMAIL") {
            current_addresses.push(ContactAddress {
                address: unescape_vcard(value)?,
                accepted_name: None,
            });
        } else if name.eq_ignore_ascii_case("X-LIZARD-ACCEPTED-NAME") {
            let Some(address) = current_addresses.last_mut() else {
                return Err(BackendError::InvalidInput(
                    "vCard accepted-name extension appears before EMAIL".into(),
                ));
            };
            address.accepted_name = Some(unescape_vcard(value)?);
        }
    }
    if inside {
        return Err(BackendError::InvalidInput(
            "vCard record is missing END:VCARD".into(),
        ));
    }
    Ok(contacts)
}

fn unescape_vcard(value: &str) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = characters
            .next()
            .ok_or_else(|| BackendError::InvalidInput("vCard value ends with an escape".into()))?;
        match escaped {
            'n' | 'N' => output.push('\n'),
            '\\' | ',' | ';' => output.push(escaped),
            _ => {
                return Err(BackendError::InvalidInput(
                    "vCard value contains an unsupported escape".into(),
                ))
            }
        }
    }
    Ok(output)
}

fn escape_vcard(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "")
        .replace(',', "\\,")
        .replace(';', "\\;")
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(BackendError::InvalidInput(format!(
            "{label} cannot be empty"
        )))
    } else {
        Ok(())
    }
}

fn normalize_address(value: &str) -> Result<String> {
    let value = value.trim().to_lowercase();
    if value.is_empty() || !value.contains('@') || value.chars().any(char::is_whitespace) {
        Err(BackendError::InvalidInput("invalid email address".into()))
    } else {
        Ok(value)
    }
}

fn validate_imap_settings(settings: &ImapSettings) -> Result<()> {
    if settings.host.trim().is_empty()
        || settings.host.chars().any(char::is_whitespace)
        || settings.host.chars().any(char::is_control)
        || settings.username.trim().is_empty()
        || settings.username.chars().any(char::is_control)
        || settings.port == 0
    {
        Err(BackendError::InvalidInput(
            "invalid IMAP connection settings".into(),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn parse_id<T: FromStr>(value: String, entity: &'static str) -> Result<T> {
    value
        .parse()
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {entity} ID")))
}

pub(crate) fn not_found(entity: &'static str, id: impl ToString) -> BackendError {
    BackendError::NotFound {
        entity,
        id: id.to_string(),
    }
}

fn account_kind_text(kind: AccountKind) -> &'static str {
    match kind {
        AccountKind::Imap => "imap",
        AccountKind::Local => "local",
    }
}

fn parse_account_kind(value: &str) -> Result<AccountKind> {
    match value {
        "imap" => Ok(AccountKind::Imap),
        "local" => Ok(AccountKind::Local),
        _ => Err(BackendError::InvalidInput(
            "invalid account kind in database".into(),
        )),
    }
}

fn folder_kind_text(kind: FolderKind) -> &'static str {
    match kind {
        FolderKind::Remote => "remote",
        FolderKind::Local => "local",
    }
}

fn folder_from_row(row: &turso::Row) -> Result<Folder> {
    Ok(Folder {
        id: parse_id(row.get::<String>(0)?, "folder")?,
        account_id: row
            .get::<Option<String>>(1)?
            .map(|id| parse_id(id, "account"))
            .transpose()?,
        name: row.get(2)?,
        kind: parse_folder_kind(&row.get::<String>(3)?)?,
        remote_name: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn validate_mailbox_name(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value.chars().any(|character| character.is_control())
    {
        return Err(BackendError::InvalidInput(
            "IMAP mailbox name is empty, too long, or contains a control character".into(),
        ));
    }
    Ok(())
}

fn parse_folder_kind(value: &str) -> Result<FolderKind> {
    match value {
        "remote" => Ok(FolderKind::Remote),
        "local" => Ok(FolderKind::Local),
        _ => Err(BackendError::InvalidInput(
            "invalid folder kind in database".into(),
        )),
    }
}

fn classification_text(classification: UserClassification) -> &'static str {
    match classification {
        UserClassification::Spam => "spam",
        UserClassification::NotSpam => "not_spam",
    }
}

fn relationship_kind_text(value: crate::RelationshipKind) -> &'static str {
    match value {
        crate::RelationshipKind::Person => "person",
        crate::RelationshipKind::Organization => "organization",
        crate::RelationshipKind::Merchant => "merchant",
        crate::RelationshipKind::Newsletter => "newsletter",
        crate::RelationshipKind::AutomatedService => "automated_service",
        crate::RelationshipKind::Other => "other",
    }
}

fn parse_relationship_kind(value: &str) -> Result<crate::RelationshipKind> {
    match value {
        "person" => Ok(crate::RelationshipKind::Person),
        "organization" => Ok(crate::RelationshipKind::Organization),
        "merchant" => Ok(crate::RelationshipKind::Merchant),
        "newsletter" => Ok(crate::RelationshipKind::Newsletter),
        "automated_service" => Ok(crate::RelationshipKind::AutomatedService),
        "other" => Ok(crate::RelationshipKind::Other),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid relationship kind".into(),
        )),
    }
}

fn warm_route_text(value: crate::WarmRoute) -> &'static str {
    match value {
        crate::WarmRoute::Action => "action",
        crate::WarmRoute::Fyi => "fyi",
    }
}

fn parse_warm_route(value: &str) -> Result<crate::WarmRoute> {
    match value {
        "action" => Ok(crate::WarmRoute::Action),
        "fyi" => Ok(crate::WarmRoute::Fyi),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid Warm route".into(),
        )),
    }
}

fn remote_content_policy_text(value: crate::RemoteContentPolicy) -> &'static str {
    match value {
        crate::RemoteContentPolicy::Ask => "ask",
        crate::RemoteContentPolicy::Allow => "allow",
        crate::RemoteContentPolicy::Block => "block",
    }
}

fn parse_remote_content_policy(value: &str) -> Result<crate::RemoteContentPolicy> {
    match value {
        "ask" => Ok(crate::RemoteContentPolicy::Ask),
        "allow" => Ok(crate::RemoteContentPolicy::Allow),
        "block" => Ok(crate::RemoteContentPolicy::Block),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid remote-content policy".into(),
        )),
    }
}

fn parse_user_classification(value: &str) -> Result<UserClassification> {
    match value {
        "spam" => Ok(UserClassification::Spam),
        "not_spam" => Ok(UserClassification::NotSpam),
        _ => Err(BackendError::InvalidInput(
            "invalid user classification in database".into(),
        )),
    }
}

fn parse_provider_spam_source(value: &str) -> Result<ProviderSpamEvidenceSource> {
    match value {
        "imap_junk_mailbox" => Ok(ProviderSpamEvidenceSource::ImapJunkMailbox),
        "imap_junk_keyword" => Ok(ProviderSpamEvidenceSource::ImapJunkKeyword),
        "imap_not_junk_keyword" => Ok(ProviderSpamEvidenceSource::ImapNotJunkKeyword),
        _ => Err(BackendError::InvalidInput(
            "invalid provider spam evidence source in database".into(),
        )),
    }
}

fn parse_spam_evidence_verdict(value: &str) -> Result<SpamEvidenceVerdict> {
    match value {
        "spam" => Ok(SpamEvidenceVerdict::Spam),
        "not_spam" => Ok(SpamEvidenceVerdict::NotSpam),
        _ => Err(BackendError::InvalidInput(
            "invalid provider spam evidence verdict in database".into(),
        )),
    }
}

pub(crate) fn canonical_flags(flags: &[String]) -> Vec<String> {
    let mut flags = flags.to_vec();
    flags.sort_unstable();
    flags.dedup();
    flags
}

fn content_state_text(state: ContentState) -> &'static str {
    match state {
        ContentState::Complete => "complete",
        ContentState::Limited => "limited",
    }
}

fn content_availability_text(state: MessageContentAvailability) -> &'static str {
    match state {
        MessageContentAvailability::HeadersOnly => "headers_only",
        MessageContentAvailability::Downloading => "downloading",
        MessageContentAvailability::Complete => "complete",
        MessageContentAvailability::Failed => "failed",
    }
}

fn parse_content_availability(value: &str) -> Result<MessageContentAvailability> {
    match value {
        "headers_only" => Ok(MessageContentAvailability::HeadersOnly),
        "downloading" => Ok(MessageContentAvailability::Downloading),
        "complete" => Ok(MessageContentAvailability::Complete),
        "failed" => Ok(MessageContentAvailability::Failed),
        _ => Err(BackendError::InvalidInput(
            "invalid message content availability in database".into(),
        )),
    }
}

fn content_unavailable(id: MessageId, availability: MessageContentAvailability) -> BackendError {
    BackendError::ContentUnavailable {
        id: id.to_string(),
        state: content_availability_text(availability).into(),
    }
}

fn query_requires_complete_content(expression: &crate::QueryExpr) -> bool {
    match expression {
        crate::QueryExpr::Term(term) => term
            .field
            .as_deref()
            .is_none_or(|field| field.eq_ignore_ascii_case("filename")),
        crate::QueryExpr::And(items) | crate::QueryExpr::Or(items) => {
            items.iter().any(query_requires_complete_content)
        }
        crate::QueryExpr::Not(item) => query_requires_complete_content(item),
    }
}

fn mime_parse_state_text(value: crate::MimeParseState) -> &'static str {
    match value {
        crate::MimeParseState::Complete => "complete",
        crate::MimeParseState::Limited => "limited",
        crate::MimeParseState::Failed => "failed",
    }
}

fn mime_decode_state_text(value: crate::MimeDecodeState) -> &'static str {
    match value {
        crate::MimeDecodeState::Complete => "complete",
        crate::MimeDecodeState::Problems => "problems",
        crate::MimeDecodeState::Limited => "limited",
        crate::MimeDecodeState::Failed => "failed",
    }
}

fn parse_mime_decode_state(value: &str) -> Result<crate::MimeDecodeState> {
    match value {
        "complete" => Ok(crate::MimeDecodeState::Complete),
        "problems" => Ok(crate::MimeDecodeState::Problems),
        "limited" => Ok(crate::MimeDecodeState::Limited),
        "failed" => Ok(crate::MimeDecodeState::Failed),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid MIME decode state".into(),
        )),
    }
}

fn mime_part_kind_text(value: crate::MimePartKind) -> &'static str {
    match value {
        crate::MimePartKind::Text => "text",
        crate::MimePartKind::Html => "html",
        crate::MimePartKind::Binary => "binary",
        crate::MimePartKind::InlineBinary => "inline_binary",
        crate::MimePartKind::Multipart => "multipart",
        crate::MimePartKind::Message => "message",
    }
}

fn mime_part_role_text(value: crate::MimePartRole) -> &'static str {
    match value {
        crate::MimePartRole::Container => "container",
        crate::MimePartRole::TextBody => "text_body",
        crate::MimePartRole::HtmlBody => "html_body",
        crate::MimePartRole::CopiedBody => "copied_body",
        crate::MimePartRole::MediaBody => "media_body",
        crate::MimePartRole::Attachment => "attachment",
        crate::MimePartRole::Dropped => "dropped",
    }
}

fn parse_content_state(value: &str) -> Result<ContentState> {
    match value {
        "complete" => Ok(ContentState::Complete),
        "limited" => Ok(ContentState::Limited),
        _ => Err(BackendError::InvalidInput(
            "invalid content state in database".into(),
        )),
    }
}

fn parse_inbox_class(value: &str) -> Result<InboxClass> {
    match value {
        "warm" => Ok(InboxClass::Warm),
        "cold" => Ok(InboxClass::Cold),
        "spam" => Ok(InboxClass::Spam),
        _ => Err(BackendError::InvalidInput(
            "invalid inbox class in database".into(),
        )),
    }
}

fn message_priority_text(value: crate::MessagePriority) -> &'static str {
    match value {
        crate::MessagePriority::Low => "low",
        crate::MessagePriority::Normal => "normal",
        crate::MessagePriority::High => "high",
    }
}

fn parse_message_priority(value: &str) -> Result<crate::MessagePriority> {
    match value {
        "low" => Ok(crate::MessagePriority::Low),
        "normal" => Ok(crate::MessagePriority::Normal),
        "high" => Ok(crate::MessagePriority::High),
        _ => Err(BackendError::InvalidInput(
            "invalid message priority in database".into(),
        )),
    }
}
