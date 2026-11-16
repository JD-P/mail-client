use crate::blob::BlobStore;
use crate::event::{ChangeCursor, EventSubscription};
use crate::mime;
use crate::query::{parse_query, QueryExpr, QueryParseError, QueryTerm};
use crate::schema;
use crate::{
    Account, AccountId, AccountKind, Attachment, BackendConfig, BackendError, BackendEvent,
    Contact, ContactAddress, ContactId, ContentState, Folder, FolderId, FolderKind,
    ImapFetchedMessage, ImapSettings, InboxClass, IngestMessage, Message, MessageFilter, MessageId,
    MessageInstance, MessageSort, MessageSummary, NewAccount, NewContact, NewFolder, Page,
    RemoteMessageIdentity, Result, SearchRequest, SyncBatchResult, UserClassification,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{str::FromStr, sync::Arc};
use tokio::sync::{broadcast, Mutex};
use turso::{params_from_iter, Connection, Value};

#[derive(Clone)]
pub struct Backend {
    inner: Arc<Inner>,
}

struct Inner {
    config: BackendConfig,
    _database: turso::Database,
    connection: Mutex<Connection>,
    blobs: BlobStore,
    events: broadcast::Sender<BackendEvent>,
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
        let connection = database.connect()?;
        schema::migrate(&connection).await?;
        let blobs = BlobStore::open(config.profile_dir.join("blobs")).await?;
        let (events, _) = broadcast::channel(config.event_buffer.max(1));
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                _database: database,
                connection: Mutex::new(connection),
                blobs,
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

    pub fn sync(&self) -> Sync {
        Sync(self.clone())
    }

    /// Store an exact RFC 5322 message. Protocol adapters should call this
    /// method rather than introducing a second parsing/indexing path.
    pub async fn ingest(&self, request: IngestMessage) -> Result<MessageId> {
        if request.raw.len() > self.inner.config.limits.max_message_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: request.raw.len(),
                limit: self.inner.config.limits.max_message_bytes,
            });
        }
        if let Some(remote) = &request.remote {
            if let Some(id) = self.refresh_existing_remote(remote).await? {
                return Ok(id);
            }
        }

        let parsed = mime::parse(&request.raw, &self.inner.config.limits)?;
        let blob_hash = self.inner.blobs.put(&request.raw).await?;
        let id = MessageId::new();
        let now = Utc::now().timestamp();
        let received_at = request.received_at.or(parsed.sent_at).unwrap_or(now);
        let to_json = serde_json::to_string(&parsed.to_addresses)?;
        let cc_json = serde_json::to_string(&parsed.cc_addresses)?;
        let bcc_json = serde_json::to_string(&parsed.bcc_addresses)?;
        let delivered_to_json = serde_json::to_string(&parsed.delivered_to_addresses)?;
        let attachment_names = parsed
            .attachments
            .iter()
            .filter_map(|attachment| attachment.name.as_deref())
            .collect::<Vec<_>>()
            .join(" ");
        let classification = request.user_classification.map(classification_text);
        let remote_flags = request
            .remote
            .as_ref()
            .map(|remote| canonical_flags(&remote.flags));
        let (is_read, is_starred) = request
            .remote
            .as_ref()
            .zip(remote_flags.as_ref())
            .map(|(_remote, flags)| {
                (
                    flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
                    flags
                        .iter()
                        .any(|flag| flag.eq_ignore_ascii_case("\\Flagged")),
                )
            })
            .unwrap_or((false, false));

        let mut connection = self.inner.connection.lock().await;
        if let Some(remote) = &request.remote {
            if let Some(existing) = lookup_remote_on(
                &connection,
                remote.folder_id,
                remote.uid_validity,
                remote.uid,
            )
            .await?
            {
                let event = refresh_remote_on(&mut connection, existing, remote).await?;
                drop(connection);
                if let Some(event) = event {
                    let _ = self.inner.events.send(event);
                }
                return Ok(existing);
            }
        }
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                r#"INSERT INTO messages (
                    id, blob_hash, rfc_message_id, subject, from_address, from_name,
                    to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses,
                    list_id, body_text, body_html, preview, sent_at, received_at, size_bytes, has_attachment,
                    attachment_names, is_read, is_starred, user_classification,
                    content_state, created_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                    ?24
                )"#,
                turso::params![
                    id.to_string(),
                    blob_hash,
                    parsed.rfc_message_id,
                    parsed.subject,
                    parsed.from_address,
                    parsed.from_name,
                    to_json,
                    cc_json,
                    bcc_json,
                    delivered_to_json,
                    parsed.list_id,
                    parsed.body_text,
                    parsed.body_html,
                    parsed.preview,
                    parsed.sent_at,
                    received_at,
                    request.raw.len() as i64,
                    !parsed.attachments.is_empty(),
                    attachment_names,
                    is_read,
                    is_starred,
                    classification,
                    content_state_text(parsed.content_state),
                    now,
                ],
            )
            .await?;
        for attachment in &parsed.attachments {
            transaction
                .execute(
                    r#"INSERT INTO attachments (
                        message_id, ordinal, name, declared_media_type, decoded_size,
                        inline, content_id
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                    turso::params![
                        id.to_string(),
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
        if let Some(remote) = &request.remote {
            transaction
                .execute(
                    r#"INSERT INTO message_instances (
                        message_id, account_id, folder_id, uid_validity, imap_uid,
                        mod_sequence, flags_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                    turso::params![
                        id.to_string(),
                        remote.account_id.to_string(),
                        remote.folder_id.to_string(),
                        remote.uid_validity as i64,
                        remote.uid as i64,
                        remote.mod_sequence.map(|value| value as i64),
                        serde_json::to_string(remote_flags.as_deref().unwrap_or_default())?,
                    ],
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "message_ingested",
            id.to_string(),
            json!({"message_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.inner.events.send(event);
        Ok(id)
    }

    async fn refresh_existing_remote(
        &self,
        remote: &RemoteMessageIdentity,
    ) -> Result<Option<MessageId>> {
        let mut connection = self.inner.connection.lock().await;
        let Some(id) = lookup_remote_on(
            &connection,
            remote.folder_id,
            remote.uid_validity,
            remote.uid,
        )
        .await?
        else {
            return Ok(None);
        };
        let event = refresh_remote_on(&mut connection, id, remote).await?;
        drop(connection);
        if let Some(event) = event {
            let _ = self.inner.events.send(event);
        }
        Ok(Some(id))
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

    pub async fn get(&self, id: MessageId) -> Result<Message> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                &format!(
                    "SELECT {}, rfc_message_id, to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses, list_id, body_text, body_html FROM messages m WHERE m.id = ?1",
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
        drop(rows);

        let mut rows = connection
            .query(
                "SELECT ordinal, name, declared_media_type, decoded_size, inline, content_id FROM attachments WHERE message_id = ?1 ORDER BY ordinal",
                (id.to_string(),),
            )
            .await?;
        let mut attachments = Vec::new();
        while let Some(row) = rows.next().await? {
            attachments.push(Attachment {
                ordinal: row.get::<i64>(0)? as u32,
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
            instances,
            local_folder_ids,
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
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    async fn query_page(
        &self,
        clauses: Vec<String>,
        mut parameters: Vec<Value>,
        requested_size: usize,
        sort: MessageSort,
    ) -> Result<Page<MessageSummary>> {
        query_page_on(&self.0, clauses, &mut parameters, requested_size, sort).await
    }
}

#[derive(Clone)]
pub struct Search(Backend);

impl Search {
    pub async fn search(&self, request: SearchRequest) -> Result<Page<MessageSummary>> {
        let expression = parse_query(&request.query)?;
        let now = Utc::now();
        let mut parameters = Vec::new();
        let predicate = compile_query(&expression, &mut parameters, now)?;
        let mut clauses = vec![predicate];
        apply_cursor(
            &mut clauses,
            &mut parameters,
            request.cursor.as_deref(),
            MessageSort::ReceivedNewest,
        )?;
        query_page_on(
            &self.0,
            clauses,
            &mut parameters,
            request.page_size,
            MessageSort::ReceivedNewest,
        )
        .await
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
        let event = insert_event(
            &transaction,
            value.created_at,
            "contact_added",
            value.id.to_string(),
            json!({"contact_id": value.id, "addresses": value.addresses}),
        )
        .await?;
        transaction.commit().await?;
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
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute("DELETE FROM contacts WHERE id = ?1", (id.to_string(),))
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("contact", id));
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
    pub async fn ingest_imap_batch(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        fetched: Vec<ImapFetchedMessage>,
    ) -> Result<SyncBatchResult> {
        let mut message_ids = Vec::with_capacity(fetched.len());
        for message in fetched {
            if message.uid == 0 {
                return Err(BackendError::InvalidInput(
                    "IMAP UIDs must be non-zero".into(),
                ));
            }
            message_ids.push(
                self.0
                    .ingest(IngestMessage {
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
                    })
                    .await?,
            );
        }
        Ok(SyncBatchResult { message_ids })
    }
}

const WARM_PREDICATE: &str = "m.user_classification IS NOT 'spam' AND m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE)";
const COLD_PREDICATE: &str = "m.user_classification IS NOT 'spam' AND (m.from_address IS NULL OR NOT EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE))";
const SPAM_PREDICATE: &str = "COALESCE(m.user_classification = 'spam', 0)";
const SUMMARY_COLUMNS: &str = "m.id, m.subject, m.from_address, m.from_name, m.preview, m.sent_at, m.received_at, m.size_bytes, m.has_attachment, m.is_read, m.is_starred, CASE WHEN m.user_classification = 'spam' THEN 'spam' WHEN m.from_address IS NOT NULL AND EXISTS (SELECT 1 FROM contact_addresses ca WHERE ca.address = m.from_address COLLATE NOCASE) THEN 'warm' ELSE 'cold' END, m.content_state";
const SUMMARY_COLUMN_COUNT: usize = 13;

async fn query_page_on(
    backend: &Backend,
    clauses: Vec<String>,
    parameters: &mut Vec<Value>,
    requested_size: usize,
    sort: MessageSort,
) -> Result<Page<MessageSummary>> {
    let page_size = bounded_page_size(requested_size);
    let mut sql = format!("SELECT {SUMMARY_COLUMNS} FROM messages m");
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(match sort {
        MessageSort::ReceivedNewest => " ORDER BY m.received_at DESC, m.id DESC LIMIT ?",
        MessageSort::ReceivedOldest => " ORDER BY m.received_at ASC, m.id ASC LIMIT ?",
    });
    parameters.push(Value::Integer(page_size as i64 + 1));
    let connection = backend.inner.connection.lock().await;
    let mut rows = connection
        .query(sql, params_from_iter(parameters.clone()))
        .await?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().await? {
        items.push(summary_from_row(&row)?);
    }
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

async fn refresh_remote_on(
    connection: &mut Connection,
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
    let transaction = connection.transaction().await?;
    transaction
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
    transaction
        .execute(
            "UPDATE messages SET is_read = ?1, is_starred = ?2 WHERE id = ?3",
            (is_read, is_starred, id.to_string()),
        )
        .await?;
    let event = insert_event(
        &transaction,
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
    transaction.commit().await?;
    Ok(Some(event))
}

async fn insert_event(
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

fn compile_query(
    expression: &QueryExpr,
    parameters: &mut Vec<Value>,
    now: DateTime<Utc>,
) -> Result<String> {
    compile_query_with_mode(expression, parameters, now, false)
}

fn compile_query_with_mode(
    expression: &QueryExpr,
    parameters: &mut Vec<Value>,
    now: DateTime<Utc>,
    isolate_fts: bool,
) -> Result<String> {
    if let Some(query) = compile_full_text_query(expression) {
        parameters.push(Value::Text(query));
        return Ok(if isolate_fts {
            "m.id IN (SELECT ft.id FROM messages ft WHERE (ft.subject, ft.body_text, ft.from_address, ft.from_name, ft.to_addresses, ft.cc_addresses, ft.bcc_addresses, ft.delivered_to_addresses, ft.list_id, ft.attachment_names) MATCH ?)".into()
        } else {
            "(m.subject, m.body_text, m.from_address, m.from_name, m.to_addresses, m.cc_addresses, m.bcc_addresses, m.delivered_to_addresses, m.list_id, m.attachment_names) MATCH ?".into()
        });
    }
    match expression {
        QueryExpr::Term(term) => compile_term(term, parameters, now),
        QueryExpr::And(items) => compile_group(items, " AND ", parameters, now, isolate_fts),
        // MATCH is only legal as an index-driving constraint in Turso. Under
        // a mixed SQL OR/NOT, isolate text matches in an ID subquery.
        QueryExpr::Or(items) => compile_group(items, " OR ", parameters, now, true),
        QueryExpr::Not(item) => Ok(format!(
            "NOT ({})",
            compile_query_with_mode(item, parameters, now, true)?
        )),
    }
}

fn compile_group(
    items: &[QueryExpr],
    separator: &str,
    parameters: &mut Vec<Value>,
    now: DateTime<Utc>,
    isolate_fts: bool,
) -> Result<String> {
    let parts = items
        .iter()
        .map(|item| compile_query_with_mode(item, parameters, now, isolate_fts))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("({})", parts.join(separator)))
}

fn compile_term(
    term: &QueryTerm,
    parameters: &mut Vec<Value>,
    now: DateTime<Utc>,
) -> Result<String> {
    let field = term.field.as_deref();
    let fts = |column: &'static str, parameters: &mut Vec<Value>| {
        parameters.push(Value::Text(fts_literal(&term.value)));
        format!("m.{column} MATCH ?")
    };
    match field {
        None => Ok(fts("body_text", parameters)),
        Some("subject") => Ok(fts("subject", parameters)),
        Some("from") => Ok(fts("from_address", parameters)),
        Some("to") => Ok(fts("to_addresses", parameters)),
        Some("deliveredto") => Ok(fts("delivered_to_addresses", parameters)),
        Some("cc") => {
            parameters.push(Value::Text(format!("%{}%", escape_like(&term.value))));
            Ok("m.cc_addresses LIKE ? ESCAPE '\\'".into())
        }
        Some("bcc") => {
            parameters.push(Value::Text(format!("%{}%", escape_like(&term.value))));
            Ok("m.bcc_addresses LIKE ? ESCAPE '\\'".into())
        }
        Some("filename") => Ok(fts("attachment_names", parameters)),
        Some("list") => Ok(fts("list_id", parameters)),
        Some("has") if term.value.eq_ignore_ascii_case("attachment") => {
            Ok("m.has_attachment = 1".into())
        }
        Some("has") => Err(query_error(term, "unknown has: predicate")),
        Some("is") => match term.value.to_ascii_lowercase().as_str() {
            "read" => Ok("m.is_read = 1".into()),
            "unread" => Ok("m.is_read = 0".into()),
            "starred" => Ok("m.is_starred = 1".into()),
            "warm" => Ok(WARM_PREDICATE.into()),
            "cold" => Ok(COLD_PREDICATE.into()),
            "spam" => Ok(SPAM_PREDICATE.into()),
            _ => Err(query_error(term, "unknown is: predicate")),
        },
        Some("after" | "newer" | "before" | "older") => {
            let timestamp = parse_date(&term.value)
                .ok_or_else(|| query_error(term, "date must use YYYY-MM-DD"))?;
            parameters.push(Value::Integer(timestamp));
            if matches!(field, Some("after" | "newer")) {
                Ok("m.received_at >= ?".into())
            } else {
                Ok("m.received_at < ?".into())
            }
        }
        Some("older_than" | "newer_than") => {
            let duration = parse_age(&term.value)
                .ok_or_else(|| query_error(term, "age must look like 7d, 2w, 3m, or 1y"))?;
            parameters.push(Value::Integer((now - duration).timestamp()));
            if field == Some("older_than") {
                Ok("m.received_at < ?".into())
            } else {
                Ok("m.received_at >= ?".into())
            }
        }
        Some("larger" | "smaller" | "size") => {
            let size =
                parse_size(&term.value).ok_or_else(|| query_error(term, "invalid byte size"))?;
            parameters.push(Value::Integer(size));
            match field {
                Some("larger") => Ok("m.size_bytes > ?".into()),
                Some("smaller") => Ok("m.size_bytes < ?".into()),
                _ => Ok("m.size_bytes = ?".into()),
            }
        }
        Some("in" | "label") => {
            parameters.push(Value::Text(term.value.clone()));
            parameters.push(Value::Text(term.value.clone()));
            parameters.push(Value::Text(term.value.clone()));
            Ok("EXISTS (SELECT 1 FROM folders f WHERE (f.id = ? OR f.name = ? COLLATE NOCASE OR f.remote_name = ? COLLATE NOCASE) AND (EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.folder_id = f.id) OR EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = f.id)))".into())
        }
        Some("account") => {
            parameters.push(Value::Text(term.value.clone()));
            parameters.push(Value::Text(term.value.clone()));
            Ok("EXISTS (SELECT 1 FROM message_instances mi JOIN accounts a ON a.id = mi.account_id WHERE mi.message_id = m.id AND (a.id = ? OR a.name = ? COLLATE NOCASE))".into())
        }
        Some("rfc822msgid" | "message-id") => {
            parameters.push(Value::Text(term.value.trim_matches(['<', '>']).to_owned()));
            Ok("m.rfc_message_id = ?".into())
        }
        Some(other) => Err(query_error(
            term,
            format!("unknown search operator {other}:"),
        )),
    }
}

/// Lower a wholly full-text subtree into one Tantivy query. Turso currently
/// requires MATCH to be an index-driving constraint, and rejects multiple
/// independent MATCH expressions under SQL Boolean operators.
fn compile_full_text_query(expression: &QueryExpr) -> Option<String> {
    match expression {
        QueryExpr::Term(term) => {
            let field = match term.field.as_deref() {
                None => None,
                Some("subject") => Some("subject"),
                Some("from") => Some("from_address"),
                Some("to") => Some("to_addresses"),
                Some("deliveredto") => Some("delivered_to_addresses"),
                Some("cc") => Some("cc_addresses"),
                Some("bcc") => Some("bcc_addresses"),
                Some("filename") => Some("attachment_names"),
                Some("list") => Some("list_id"),
                _ => return None,
            };
            let literal = fts_literal(&term.value);
            Some(match field {
                Some(field) => format!("{field}:{literal}"),
                None => literal,
            })
        }
        QueryExpr::And(items) => compile_full_text_group(items, " AND "),
        QueryExpr::Or(items) => compile_full_text_group(items, " OR "),
        // Tantivy rejects an all-negative query. Lower negation through SQL
        // around a positive FTS ID subquery instead.
        QueryExpr::Not(_) => None,
    }
}

fn compile_full_text_group(items: &[QueryExpr], separator: &str) -> Option<String> {
    let items = items
        .iter()
        .map(compile_full_text_query)
        .collect::<Option<Vec<_>>>()?;
    Some(format!("({})", items.join(separator)))
}

fn fts_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn parse_date(value: &str) -> Option<i64> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)
        .map(|date| date.and_utc().timestamp())
}

fn parse_age(value: &str) -> Option<Duration> {
    let (amount, unit) = value.split_at(value.len().checked_sub(1)?);
    let amount = amount.parse::<i64>().ok()?;
    let days = match unit.to_ascii_lowercase().as_str() {
        "d" => amount,
        "w" => amount.checked_mul(7)?,
        "m" => amount.checked_mul(30)?,
        "y" => amount.checked_mul(365)?,
        _ => return None,
    };
    Duration::try_days(days)
}

fn parse_size(value: &str) -> Option<i64> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split].parse::<i64>().ok()?;
    let multiplier = match value[split..].to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn query_error(term: &QueryTerm, message: impl Into<String>) -> BackendError {
    QueryParseError::new(message, term.start, term.end).into()
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

fn parse_id<T: FromStr>(value: String, entity: &'static str) -> Result<T> {
    value
        .parse()
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {entity} ID")))
}

fn not_found(entity: &'static str, id: impl ToString) -> BackendError {
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
