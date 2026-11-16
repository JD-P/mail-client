use crate::authentication::DkimVerifier;
use crate::blob::BlobStore;
use crate::event::{ChangeCursor, EventSubscription};
use crate::imap::imap_fetch_metadata;
use crate::mime;
use crate::query::parse_query;
use crate::schema;
use crate::search_index::{QueuedSearchDocument, SearchDocument, SearchIndex};
use crate::{
    Account, AccountId, AccountKind, Attachment, BackendConfig, BackendError, BackendEvent,
    Contact, ContactAddress, ContactId, ContentState, Folder, FolderId, FolderKind,
    ImapFetchedMessage, ImapSettings, InboxClass, IngestMessage, Message, MessageFilter, MessageId,
    MessageInstance, MessageLink, MessageLinkSource, MessageSort, MessageSummary, NewAccount,
    NewContact, NewFolder, Page, RemoteMessageIdentity, Result, SearchRequest, SyncBatchResult,
    UserClassification,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures_util::{stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    mem,
    str::FromStr,
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, Mutex, RwLock};
use turso::{params_from_iter, Connection, Value};
use uuid::Uuid;

const MAX_INGEST_BATCH_MESSAGES: usize = 1_000;
const MAX_INGEST_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREPARE_CONCURRENCY: usize = 16;
const MAX_IMAP_METADATA_UIDS: usize = 500;
const IMAP_BODY_CHUNK_BYTES: usize = 1024 * 1024;

struct PreparedIngest {
    id: MessageId,
    remote: Option<RemoteMessageIdentity>,
    remote_flags_json: Option<String>,
    attachments: Vec<Attachment>,
    links: Vec<MessageLink>,
    stage: Option<StagedMessage>,
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
            + self.delivered_to_addresses.len()
            + self.list_id.as_ref().map_or(0, String::len)
            + self.body_text.len()
            + self.body_html.as_ref().map_or(0, String::len)
            + self.attachment_names.len()
            + self.search_metadata.len()
            + self.dkim_json.len()
    }
}

#[derive(Clone)]
pub struct Backend {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    config: BackendConfig,
    _database: turso::Database,
    pub(crate) connection: Mutex<Connection>,
    search_index: Arc<SearchIndex>,
    pub(crate) search_sync: RwLock<()>,
    blobs: BlobStore,
    dkim_verifier: DkimVerifier,
    pub(crate) events: broadcast::Sender<BackendEvent>,
}

impl Backend {
    pub async fn open(config: BackendConfig) -> Result<Self> {
        tokio::fs::create_dir_all(&config.profile_dir)
            .await
            .map_err(|source| BackendError::Io {
                path: config.profile_dir.clone(),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&config.profile_dir, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|source| BackendError::Io {
                    path: config.profile_dir.clone(),
                    source,
                })?;
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
        schema::migrate(&connection).await?;
        let search_index = prepare_search_index(&config.profile_dir, &mut connection).await?;
        let blobs = BlobStore::open(config.profile_dir.join("blobs")).await?;
        let dkim_verifier = DkimVerifier::new(config.dkim_dns).map_err(|error| {
            BackendError::InvalidInput(format!("could not initialize DKIM resolver: {error}"))
        })?;
        let (events, _) = broadcast::channel(config.event_buffer.max(1));
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                _database: database,
                connection: Mutex::new(connection),
                search_index,
                search_sync: RwLock::new(()),
                blobs,
                dkim_verifier,
                events,
            }),
        })
    }

    pub fn accounts(&self) -> Accounts {
        Accounts(self.clone())
    }

    pub fn folders(&self) -> Folders {
        Folders(self.clone())
    }

    pub fn messages(&self) -> Messages {
        Messages(self.clone())
    }

    pub fn contacts(&self) -> Contacts {
        Contacts(self.clone())
    }

    pub fn search(&self) -> Search {
        Search(self.clone())
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

    pub fn sync(&self) -> Sync {
        Sync(self.clone())
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
        let mut evaluated = HashSet::new();
        let run_filters = self.filter_rules().has_enabled().await?;
        let run_heuristics = self.heuristics().has_enabled().await?;
        for message_id in &message_ids {
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
        Ok(message_ids)
    }

    async fn prepare_ingest(&self, request: IngestMessage) -> Result<PreparedIngest> {
        let size_bytes = request.raw.len() as i64;
        let parsed = mime::parse(&request.raw, &self.inner.config.limits)?;
        let blob_hash = self.inner.blobs.put(&request.raw).await?;
        let id = MessageId::new();
        let now = Utc::now().timestamp();
        let dkim_json =
            serde_json::to_string(&self.inner.dkim_verifier.verify(&request.raw, now).await)?;
        let received_at = request.received_at.or(parsed.sent_at).unwrap_or(now);
        let attachment_names = parsed
            .attachments
            .iter()
            .filter_map(|attachment| attachment.name.as_deref())
            .collect::<Vec<_>>()
            .join(" ");
        let has_attachment = !parsed.attachments.is_empty();
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
            created_at: now,
        };
        Ok(PreparedIngest {
            id,
            remote,
            remote_flags_json,
            attachments: parsed.attachments,
            links: parsed.links,
            stage: Some(stage),
        })
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
        for (position, message) in prepared.iter().enumerate() {
            if let Some(remote) = &message.remote {
                existing_ids[position] = lookup_remote_on(
                    &transaction,
                    remote.folder_id,
                    remote.uid_validity,
                    remote.uid,
                )
                .await?;
            }
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
                        bcc_addresses, delivered_to_addresses, list_id, body_text,
                        body_html, preview, sent_at, received_at, size_bytes,
                        has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json, created_at
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                        ?23, ?24, ?25, ?26, ?27, ?28
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
                        to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses,
                        list_id, body_text, body_html, preview, sent_at, received_at,
                        size_bytes, has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json, created_at
                    )
                    SELECT id, blob_hash, rfc_message_id, subject, from_address, from_name,
                        to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses,
                        list_id, body_text, body_html, preview, sent_at, received_at,
                        size_bytes, has_attachment, attachment_names, is_read, is_starred,
                        user_classification, content_state, search_metadata, dkim_json, created_at
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
            for attachment in &message.attachments {
                transaction
                    .execute(
                        r#"INSERT INTO attachments (
                            message_id, ordinal, name, declared_media_type, decoded_size,
                            inline, content_id
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                        turso::params![
                            message.id.to_string(),
                            attachment.ordinal as i64,
                            attachment.name.clone(),
                            attachment.declared_media_type.clone(),
                            attachment.decoded_size as i64,
                            attachment.inline,
                            attachment.content_id.clone(),
                        ],
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
            }
            events.push(
                insert_event(
                    &transaction,
                    Utc::now().timestamp(),
                    "message_ingested",
                    message.id.to_string(),
                    json!({"message_id": message.id}),
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

    pub(crate) async fn flush_search_projection(&self) -> Result<()> {
        loop {
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
}

#[derive(Clone)]
pub struct Accounts(Backend);

impl Accounts {
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
            created_at: Utc::now().timestamp(),
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO accounts(id, name, kind, credential_ref, settings_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                turso::params![
                    value.id.to_string(),
                    value.name.clone(),
                    account_kind_text(value.kind),
                    value.credential_ref.clone(),
                    value.imap.as_ref().map(serde_json::to_string).transpose()?,
                    value.created_at,
                ],
            )
            .await?;
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
                "SELECT id, name, kind, credential_ref, settings_json, created_at FROM accounts ORDER BY created_at, id",
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
                created_at: row.get(5)?,
            });
        }
        Ok(values)
    }
}

#[derive(Clone)]
pub struct Folders(Backend);

impl Folders {
    pub async fn add(&self, folder: NewFolder) -> Result<Folder> {
        require_nonempty("folder name", &folder.name)?;
        if folder.kind == FolderKind::Remote && folder.account_id.is_none() {
            return Err(BackendError::InvalidInput(
                "remote folders require an account".into(),
            ));
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
                    "SELECT {}, rfc_message_id, to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses, list_id, body_text, body_html, dkim_json FROM messages m WHERE m.id = ?1",
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
        let delivered_to_addresses = json_addresses(row.get(SUMMARY_COLUMN_COUNT + 4)?)?;
        let list_id = row.get(SUMMARY_COLUMN_COUNT + 5)?;
        let body_text = row.get(SUMMARY_COLUMN_COUNT + 6)?;
        let body_html = row.get(SUMMARY_COLUMN_COUNT + 7)?;
        let dkim = serde_json::from_str(&row.get::<String>(SUMMARY_COLUMN_COUNT + 8)?)?;
        drop(rows);

        let mut rows = connection
            .query(
                "SELECT ordinal, name, declared_media_type, decoded_size, inline, content_id FROM attachments WHERE message_id = ?1 ORDER BY ordinal",
                (id.to_string(),),
            )
            .await?;
        let mut attachments = Vec::new();
        while let Some(row) = rows.next().await? {
            let ordinal = row.get::<i64>(0)? as u32;
            attachments.push(Attachment {
                id: format!("attachment:{ordinal}"),
                ordinal,
                name: row.get(1)?,
                declared_media_type: row.get(2)?,
                decoded_size: row.get::<i64>(3)? as u64,
                inline: row.get(4)?,
                content_id: row.get(5)?,
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
        Ok(Message {
            summary,
            rfc_message_id,
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
            dkim,
            findings,
        })
    }

    pub async fn raw(&self, id: MessageId) -> Result<Vec<u8>> {
        let hash = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT blob_hash FROM messages WHERE id = ?1",
                    (id.to_string(),),
                )
                .await?;
            rows.next()
                .await?
                .ok_or_else(|| not_found("message", id))?
                .get::<String>(0)?
        };
        self.0.inner.blobs.get(&hash).await
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
    pub async fn search(&self, request: SearchRequest) -> Result<Page<MessageSummary>> {
        let expression = parse_query(&request.query)?;
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
        Ok(Page { items, next_cursor })
    }
}

#[derive(Clone)]
pub struct Contacts(Backend);

impl Contacts {
    pub async fn add(&self, contact: NewContact) -> Result<Contact> {
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
        let value = Contact {
            id: ContactId::new(),
            display_name: contact.display_name,
            addresses,
            created_at: Utc::now().timestamp(),
        };
        let _search_guard = self.0.inner.search_sync.write().await;
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO contacts(id, display_name, created_at) VALUES (?1, ?2, ?3)",
                (
                    value.id.to_string(),
                    value.display_name.clone(),
                    value.created_at,
                ),
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
        Ok(value)
    }

    pub async fn list(&self) -> Result<Vec<Contact>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, display_name, created_at FROM contacts ORDER BY display_name, id",
                (),
            )
            .await?;
        let mut contacts = Vec::new();
        while let Some(row) = rows.next().await? {
            contacts.push(Contact {
                id: parse_id(row.get::<String>(0)?, "contact")?,
                display_name: row.get(1)?,
                addresses: Vec::new(),
                created_at: row.get(2)?,
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

/// Boundary used by IMAP transport code after it has fetched complete
/// `BODY.PEEK[]` payloads. All messages still pass through [`Backend::ingest`].
#[derive(Clone)]
pub struct Sync(Backend);

impl Sync {
    /// Pull messages not seen by an earlier successful sync from a selected
    /// remote folder.
    ///
    /// `session` must already be authenticated over a transport which matches
    /// the account's TLS policy. Keeping connection establishment and secret
    /// lookup outside this method prevents the backend from accepting plaintext
    /// passwords or silently weakening TLS. Message bodies are requested with
    /// `BODY.PEEK[]` in bounded chunks, so a sync never marks mail as read.
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
                .uid_fetch(uid_set, "(UID FLAGS INTERNALDATE RFC822.SIZE)")
                .await
                .map_err(imap_error)?
                .try_collect::<Vec<_>>()
                .await
                .map_err(imap_error)?;
            let requested: HashSet<u32> = uid_chunk.iter().copied().collect();
            let mut metadata = fetches
                .iter()
                .map(imap_fetch_metadata)
                .collect::<Result<Vec<_>>>()?;
            metadata.retain(|item| requested.contains(&item.uid));
            metadata.sort_unstable_by_key(|item| item.uid);
            metadata.dedup_by_key(|item| item.uid);

            for item in metadata {
                let size = usize::try_from(item.size).map_err(|_| {
                    BackendError::InvalidInput("IMAP message size does not fit in memory".into())
                })?;
                let limit = self.0.inner.config.limits.max_message_bytes;
                if size > limit {
                    return Err(BackendError::MessageTooLarge {
                        actual: size,
                        limit,
                    });
                }

                if !pending.is_empty()
                    && (pending.len() >= MAX_INGEST_BATCH_MESSAGES
                        || pending_bytes.saturating_add(size) > MAX_INGEST_BATCH_BYTES)
                {
                    let ingested = self
                        .ingest_imap_batch(
                            account_id,
                            folder_id,
                            uid_validity,
                            mem::take(&mut pending),
                        )
                        .await?;
                    message_ids.extend(ingested.message_ids);
                    pending_bytes = 0;
                }

                let mut raw = Vec::with_capacity(size);
                let downloaded = session
                    .uid_fetch_body_to(item.uid, &mut raw, IMAP_BODY_CHUNK_BYTES)
                    .await
                    .map_err(imap_error)?;
                if downloaded != item.size || raw.len() != size {
                    return Err(BackendError::Imap(format!(
                        "UID {} changed size while it was being fetched",
                        item.uid
                    )));
                }
                pending_bytes = pending_bytes.saturating_add(raw.len());
                pending.push(ImapFetchedMessage {
                    uid: item.uid,
                    mod_sequence: item.mod_sequence,
                    flags: item.flags,
                    internal_date: item.internal_date,
                    raw,
                });
            }
        }

        if !pending.is_empty() {
            let ingested = self
                .ingest_imap_batch(account_id, folder_id, uid_validity, pending)
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

fn imap_error(error: async_imap::error::Error) -> BackendError {
    BackendError::Imap(error.to_string())
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

const WARM_PREDICATE: &str = "m.user_classification IS NOT 'spam' AND m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE)";
const COLD_PREDICATE: &str = "m.user_classification IS NOT 'spam' AND (m.from_address IS NULL OR NOT EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE))";
const SPAM_PREDICATE: &str = "COALESCE(m.user_classification = 'spam', 0)";
const SUMMARY_COLUMNS: &str = "m.id, m.subject, m.from_address, m.from_name, m.preview, m.sent_at, m.received_at, m.size_bytes, m.has_attachment, m.is_read, m.is_starred, CASE WHEN m.user_classification = 'spam' THEN 'spam' WHEN m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE) THEN 'warm' ELSE 'cold' END, m.content_state";
const SUMMARY_COLUMN_COUNT: usize = 13;

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
            r#"SELECT q.revision, m.id, m.subject, m.body_text, m.from_address,
                m.to_addresses, m.cc_addresses, m.bcc_addresses,
                m.delivered_to_addresses, m.list_id, m.attachment_names,
                m.rfc_message_id, m.received_at, m.size_bytes, m.has_attachment,
                m.is_read, m.is_starred,
                CASE
                    WHEN m.user_classification = 'spam' THEN 'spam'
                    WHEN m.from_address IS NOT NULL AND EXISTS (
                        SELECT 1 FROM contact_addresses ca
                        WHERE ca.address = m.from_address COLLATE NOCASE
                    ) THEN 'warm'
                    ELSE 'cold'
                END
            FROM search_index_queue q
            JOIN messages m ON m.id = q.message_id
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
        inbox_class: parse_inbox_class(&row.get::<String>(11)?)?,
        content_state: parse_content_state(&row.get::<String>(12)?)?,
    })
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

async fn refresh_remote_in_transaction(
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
        || settings.username.trim().is_empty()
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

fn canonical_flags(flags: &[String]) -> Vec<String> {
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
