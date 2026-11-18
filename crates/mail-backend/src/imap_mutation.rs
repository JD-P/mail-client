use crate::backend::{
    enqueue_search_on, insert_event, refresh_provider_spam_evidence_in_transaction,
    refresh_remote_in_transaction,
};
use crate::{
    AccountId, Backend, BackendError, FolderId, ImapMutation, ImapMutationConflict,
    ImapMutationConflictId, ImapMutationConflictKind, ImapMutationId, ImapMutationOperation,
    ImapMutationStatus, MessageId, RemoteMessageIdentity, Result,
};
use chrono::Utc;
use serde_json::json;
use std::str::FromStr;
use turso::{params_from_iter, Value};

const ACTIVE_MUTATION_SQL: &str = "status IN ('pending', 'in_flight')";

enum QueueRequest {
    Exact(ImapMutationOperation),
    PatchSystemFlag { flag: &'static str, present: bool },
}

#[derive(Clone)]
pub struct ImapMutations(Backend);

impl ImapMutations {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn set_flags(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        flags: Vec<String>,
    ) -> Result<ImapMutation> {
        let flags = normalize_mutable_flags(flags)?;
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::Exact(ImapMutationOperation::SetFlags { flags }),
        )
        .await
    }

    pub async fn set_read(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        read: bool,
    ) -> Result<ImapMutation> {
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::PatchSystemFlag {
                flag: "\\Seen",
                present: read,
            },
        )
        .await
    }

    pub async fn set_starred(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        starred: bool,
    ) -> Result<ImapMutation> {
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::PatchSystemFlag {
                flag: "\\Flagged",
                present: starred,
            },
        )
        .await
    }

    pub async fn copy(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        destination_folder_id: FolderId,
    ) -> Result<ImapMutation> {
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::Exact(ImapMutationOperation::Copy {
                destination_folder_id,
            }),
        )
        .await
    }

    pub async fn move_to(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        destination_folder_id: FolderId,
    ) -> Result<ImapMutation> {
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::Exact(ImapMutationOperation::Move {
                destination_folder_id,
            }),
        )
        .await
    }

    /// Queue a move to the account's uniquely advertised `\\Trash` mailbox.
    pub async fn trash(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
    ) -> Result<ImapMutation> {
        let source = self.load_instance(message_id, source_folder_id).await?;
        let destination = self.trash_folder(source.account_id).await?;
        self.move_to(message_id, source_folder_id, destination)
            .await
    }

    /// Permanently delete one exact UID. Execution requires UIDPLUS so no
    /// unrelated message carrying `\\Deleted` can be expunged.
    pub async fn delete(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
    ) -> Result<ImapMutation> {
        self.queue(
            message_id,
            source_folder_id,
            QueueRequest::Exact(ImapMutationOperation::Delete),
        )
        .await
    }

    pub async fn get(&self, id: ImapMutationId) -> Result<ImapMutation> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                &format!("{} WHERE id = ?1", mutation_select_sql()),
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| mutation_from_row(&row))
            .transpose()?
            .ok_or_else(|| BackendError::NotFound {
                entity: "IMAP mutation",
                id: id.to_string(),
            })
    }

    pub async fn list(&self, account_id: Option<AccountId>) -> Result<Vec<ImapMutation>> {
        let connection = self.0.inner.connection.lock().await;
        let (sql, parameters) = if let Some(account_id) = account_id {
            (
                format!(
                    "{} WHERE account_id = ?1 ORDER BY created_at, id",
                    mutation_select_sql()
                ),
                vec![Value::Text(account_id.to_string())],
            )
        } else {
            (
                format!("{} ORDER BY created_at, id", mutation_select_sql()),
                Vec::new(),
            )
        };
        let mut rows = connection.query(&sql, params_from_iter(parameters)).await?;
        let mut mutations = Vec::new();
        while let Some(row) = rows.next().await? {
            mutations.push(mutation_from_row(&row)?);
        }
        Ok(mutations)
    }

    pub async fn conflicts(
        &self,
        mutation_id: Option<ImapMutationId>,
    ) -> Result<Vec<ImapMutationConflict>> {
        let connection = self.0.inner.connection.lock().await;
        let (sql, parameters) = if let Some(mutation_id) = mutation_id {
            (
                "SELECT id, mutation_id, kind, expected_json, observed_json, detail, created_at, resolved_at FROM imap_mutation_conflicts WHERE mutation_id = ?1 ORDER BY created_at, id",
                vec![Value::Text(mutation_id.to_string())],
            )
        } else {
            (
                "SELECT id, mutation_id, kind, expected_json, observed_json, detail, created_at, resolved_at FROM imap_mutation_conflicts ORDER BY created_at, id",
                Vec::new(),
            )
        };
        let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
        let mut conflicts = Vec::new();
        while let Some(row) = rows.next().await? {
            conflicts.push(conflict_from_row(&row)?);
        }
        Ok(conflicts)
    }

    pub async fn cancel(&self, id: ImapMutationId) -> Result<ImapMutation> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mutation = self.get_without_lock(&connection, id).await?;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE imap_mutations SET status = 'cancelled', updated_at = ?1, completed_at = ?1 WHERE id = ?2 AND status IN ('pending', 'conflict')",
                (now, id.to_string()),
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            let mutation = self.get_without_lock(&connection, id).await?;
            return if mutation.status == ImapMutationStatus::InFlight {
                Err(BackendError::Conflict(
                    "an in-flight IMAP mutation cannot be cancelled safely".into(),
                ))
            } else {
                Ok(mutation)
            };
        }
        transaction
            .execute(
                "UPDATE imap_mutation_conflicts SET resolved_at = ?1 WHERE mutation_id = ?2 AND resolved_at IS NULL",
                (now, id.to_string()),
            )
            .await?;
        let mut events = Vec::new();
        if matches!(mutation.status, ImapMutationStatus::Pending)
            && matches!(&mutation.operation, ImapMutationOperation::SetFlags { .. })
        {
            if let Some(event) =
                refresh_remote_in_transaction(&transaction, mutation.message_id, &mutation.source)
                    .await?
            {
                events.push(event);
            }
        }
        events.push(
            insert_event(
                &transaction,
                now,
                "imap_mutation_cancelled",
                id.to_string(),
                json!({"mutation_id": id}),
            )
            .await?,
        );
        transaction.commit().await?;
        drop(connection);
        if matches!(&mutation.operation, ImapMutationOperation::SetFlags { .. }) {
            self.0.flush_search_projection().await?;
        }
        for event in events {
            let _ = self.0.inner.events.send(event);
        }
        self.get(id).await
    }

    async fn queue(
        &self,
        message_id: MessageId,
        source_folder_id: FolderId,
        request: QueueRequest,
    ) -> Result<ImapMutation> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let source = load_instance_on(&transaction, message_id, source_folder_id).await?;
        let operation = match request {
            QueueRequest::Exact(operation) => operation,
            QueueRequest::PatchSystemFlag { flag, present } => {
                let mut flags = source.flags.clone();
                flags.retain(|candidate| !candidate.eq_ignore_ascii_case(flag));
                if present {
                    flags.push(flag.to_owned());
                }
                ImapMutationOperation::SetFlags {
                    flags: normalize_mutable_flags(flags)?,
                }
            }
        };
        validate_destination_on(&transaction, &source, &operation).await?;

        let mut rows = transaction
            .query(
                &format!(
                    "SELECT id, operation_json, status FROM imap_mutations WHERE message_id = ?1 AND source_folder_id = ?2 AND source_uid_validity = ?3 AND source_uid = ?4 AND {ACTIVE_MUTATION_SQL} ORDER BY created_at LIMIT 1"
                ),
                (
                    message_id.to_string(),
                    source_folder_id.to_string(),
                    i64::from(source.uid_validity),
                    i64::from(source.uid),
                ),
            )
            .await?;
        let active = rows
            .next()
            .await?
            .map(|row| {
                Ok::<_, BackendError>((
                    parse_mutation_id(row.get::<String>(0)?)?,
                    serde_json::from_str::<ImapMutationOperation>(&row.get::<String>(1)?)?,
                    parse_mutation_status(&row.get::<String>(2)?)?,
                ))
            })
            .transpose()?;
        drop(rows);

        let mut events = Vec::new();
        let id = if let Some((id, existing, status)) = active {
            match (&existing, &operation, status) {
                (
                    ImapMutationOperation::SetFlags { .. },
                    ImapMutationOperation::SetFlags { flags },
                    ImapMutationStatus::Pending,
                ) => {
                    transaction
                        .execute(
                            "UPDATE imap_mutations SET operation_json = ?1, status = 'pending', last_error = NULL, updated_at = ?2 WHERE id = ?3",
                            (serde_json::to_string(&operation)?, now, id.to_string()),
                        )
                        .await?;
                    let optimistic = RemoteMessageIdentity {
                        flags: flags.clone(),
                        ..source.clone()
                    };
                    if let Some(event) =
                        refresh_remote_in_transaction(&transaction, message_id, &optimistic).await?
                    {
                        events.push(event);
                    }
                    events.push(
                        insert_event(
                            &transaction,
                            now,
                            "imap_mutation_updated",
                            id.to_string(),
                            json!({"mutation_id": id, "operation": operation}),
                        )
                        .await?,
                    );
                    id
                }
                _ => {
                    transaction.rollback().await?;
                    return Err(BackendError::Conflict(
                        "another server mutation already targets this remote instance".into(),
                    ));
                }
            }
        } else {
            let id = ImapMutationId::new();
            transaction
                .execute(
                    "INSERT INTO imap_mutations(id, account_id, message_id, source_folder_id, source_uid_validity, source_uid, source_modseq, source_flags_json, operation_json, status, attempts, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', 0, ?10, ?10)",
                    turso::params![
                        id.to_string(),
                        source.account_id.to_string(),
                        message_id.to_string(),
                        source.folder_id.to_string(),
                        i64::from(source.uid_validity),
                        i64::from(source.uid),
                        source.mod_sequence.map(|value| value as i64),
                        serde_json::to_string(&source.flags)?,
                        serde_json::to_string(&operation)?,
                        now,
                    ],
                )
                .await?;
            if let ImapMutationOperation::SetFlags { flags } = &operation {
                let optimistic = RemoteMessageIdentity {
                    flags: flags.clone(),
                    ..source.clone()
                };
                if let Some(event) =
                    refresh_remote_in_transaction(&transaction, message_id, &optimistic).await?
                {
                    events.push(event);
                }
            }
            events.push(
                insert_event(
                    &transaction,
                    now,
                    "imap_mutation_queued",
                    id.to_string(),
                    json!({
                        "mutation_id": id,
                        "message_id": message_id,
                        "source": source,
                        "operation": operation,
                    }),
                )
                .await?,
            );
            id
        };
        transaction.commit().await?;
        drop(connection);
        if matches!(operation, ImapMutationOperation::SetFlags { .. }) {
            self.0.flush_search_projection().await?;
        }
        for event in events {
            let _ = self.0.inner.events.send(event);
        }
        self.get(id).await
    }

    async fn load_instance(
        &self,
        message_id: MessageId,
        folder_id: FolderId,
    ) -> Result<RemoteMessageIdentity> {
        let connection = self.0.inner.connection.lock().await;
        load_instance_on(&connection, message_id, folder_id).await
    }

    async fn trash_folder(&self, account_id: AccountId) -> Result<FolderId> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT f.id, s.attributes_json FROM folders f JOIN imap_mailbox_state s ON s.folder_id = f.id WHERE f.account_id = ?1 AND f.kind = 'remote' AND s.remote_present = 1 AND s.selectable = 1 ORDER BY f.id",
                (account_id.to_string(),),
            )
            .await?;
        let mut matches = Vec::new();
        while let Some(row) = rows.next().await? {
            let attributes: Vec<String> = serde_json::from_str(&row.get::<String>(1)?)?;
            if attributes
                .iter()
                .any(|attribute| attribute.eq_ignore_ascii_case("\\Trash"))
            {
                matches.push(parse_folder_id(row.get::<String>(0)?)?);
            }
        }
        match matches.as_slice() {
            [folder] => Ok(*folder),
            [] => Err(BackendError::Conflict(
                "the account does not advertise a unique Trash mailbox".into(),
            )),
            _ => Err(BackendError::Conflict(
                "the account advertises more than one Trash mailbox".into(),
            )),
        }
    }

    async fn get_without_lock(
        &self,
        connection: &turso::Connection,
        id: ImapMutationId,
    ) -> Result<ImapMutation> {
        let mut rows = connection
            .query(
                &format!("{} WHERE id = ?1", mutation_select_sql()),
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| mutation_from_row(&row))
            .transpose()?
            .ok_or_else(|| BackendError::NotFound {
                entity: "IMAP mutation",
                id: id.to_string(),
            })
    }

    pub(crate) async fn due(
        &self,
        account_id: AccountId,
        limit: usize,
    ) -> Result<Vec<ImapMutation>> {
        let limit = i64::try_from(limit).map_err(|_| {
            BackendError::InvalidInput("IMAP mutation batch limit is too large".into())
        })?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                &format!(
                    "{} WHERE account_id = ?1 AND status IN ('pending', 'in_flight') ORDER BY created_at, id LIMIT ?2",
                    mutation_select_sql()
                ),
                (account_id.to_string(), limit),
            )
            .await?;
        let mut mutations = Vec::new();
        while let Some(row) = rows.next().await? {
            mutations.push(mutation_from_row(&row)?);
        }
        Ok(mutations)
    }

    pub(crate) async fn has_blocking_conflict(&self, account_id: AccountId) -> Result<bool> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT EXISTS(SELECT 1 FROM imap_mutation_conflicts c JOIN imap_mutations m ON m.id = c.mutation_id WHERE m.account_id = ?1 AND m.status = 'conflict' AND c.resolved_at IS NULL AND c.kind IN ('ambiguous_outcome', 'missing_server_mapping'))",
                (account_id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .ok_or_else(|| {
                BackendError::InvalidInput(
                    "database did not return IMAP mutation conflict state".into(),
                )
            })?
            .get(0)
            .map_err(Into::into)
    }

    pub(crate) async fn begin(&self, id: ImapMutationId) -> Result<ImapMutation> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        let changed = connection
            .execute(
                "UPDATE imap_mutations SET status = 'in_flight', attempts = attempts + 1, updated_at = ?1, last_error = NULL WHERE id = ?2 AND status = 'pending'",
                (now, id.to_string()),
            )
            .await?;
        if changed == 0 {
            return Err(BackendError::Conflict(
                "IMAP mutation is no longer ready to execute".into(),
            ));
        }
        self.get_without_lock(&connection, id).await
    }

    pub(crate) async fn resume_attempt(&self, id: ImapMutationId) -> Result<ImapMutation> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        let changed = connection
            .execute(
                "UPDATE imap_mutations SET attempts = attempts + 1, updated_at = ?1, last_error = NULL WHERE id = ?2 AND status = 'in_flight'",
                (now, id.to_string()),
            )
            .await?;
        if changed == 0 {
            return Err(BackendError::Conflict(
                "IMAP mutation is no longer in flight".into(),
            ));
        }
        self.get_without_lock(&connection, id).await
    }

    pub(crate) async fn applied(
        &self,
        mutation: &ImapMutation,
        observed: Option<&RemoteMessageIdentity>,
        destination: Option<(FolderId, u32, u32, Vec<String>)>,
    ) -> Result<()> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut events = Vec::new();
        if let Some(observed) = observed {
            if let Some(event) =
                refresh_remote_in_transaction(&transaction, mutation.message_id, observed).await?
            {
                events.push(event);
            }
        }
        if let Some((folder_id, uid_validity, uid, flags)) = &destination {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO message_instances(message_id, account_id, folder_id, uid_validity, imap_uid, mod_sequence, flags_json) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                    (
                        mutation.message_id.to_string(),
                        mutation.account_id.to_string(),
                        folder_id.to_string(),
                        i64::from(*uid_validity),
                        i64::from(*uid),
                        serde_json::to_string(flags)?,
                    ),
                )
                .await?;
            let mut rows = transaction
                .query(
                    "SELECT message_id FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
                    (
                        folder_id.to_string(),
                        i64::from(*uid_validity),
                        i64::from(*uid),
                    ),
                )
                .await?;
            let owner = rows.next().await?.ok_or_else(|| {
                BackendError::Conflict("server copy mapping was not persisted".into())
            })?;
            let owner = parse_message_id(owner.get::<String>(0)?)?;
            if owner != mutation.message_id {
                transaction.rollback().await?;
                return Err(BackendError::Conflict(
                    "server copy mapping collides with another local message".into(),
                ));
            }
            drop(rows);
            refresh_provider_spam_evidence_in_transaction(
                &transaction,
                mutation.message_id,
                &RemoteMessageIdentity {
                    account_id: mutation.account_id,
                    folder_id: *folder_id,
                    uid_validity: *uid_validity,
                    uid: *uid,
                    mod_sequence: None,
                    flags: flags.clone(),
                },
            )
            .await?;
            enqueue_search_on(&transaction, mutation.message_id).await?;
        }
        transaction
            .execute(
                "UPDATE imap_mutations SET status = 'applied', updated_at = ?1, completed_at = ?1, last_error = NULL WHERE id = ?2 AND status = 'in_flight'",
                (now, mutation.id.to_string()),
            )
            .await?;
        events.push(
            insert_event(
                &transaction,
                now,
                "imap_mutation_applied",
                mutation.id.to_string(),
                json!({
                    "mutation_id": mutation.id,
                    "message_id": mutation.message_id,
                    "operation": mutation.operation,
                    "destination": destination.as_ref().map(|(folder_id, uid_validity, uid, _)| json!({
                        "folder_id": folder_id,
                        "uid_validity": uid_validity,
                        "uid": uid,
                    })),
                }),
            )
            .await?,
        );
        transaction.commit().await?;
        drop(connection);
        if observed.is_some() || destination.is_some() {
            self.0.flush_search_projection().await?;
        }
        for event in events {
            let _ = self.0.inner.events.send(event);
        }
        Ok(())
    }

    pub(crate) async fn note_in_flight_error(
        &self,
        mutation: &ImapMutation,
        error: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE imap_mutations SET updated_at = ?1, last_error = ?2 WHERE id = ?3 AND status = 'in_flight'",
                (now, error.to_owned(), mutation.id.to_string()),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn conflict(
        &self,
        mutation: &ImapMutation,
        kind: ImapMutationConflictKind,
        expected: serde_json::Value,
        observed: serde_json::Value,
        detail: impl Into<String>,
    ) -> Result<()> {
        let detail = detail.into();
        let now = Utc::now().timestamp();
        let conflict_id = ImapMutationConflictId::new();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE imap_mutations SET status = 'conflict', updated_at = ?1, completed_at = ?1, last_error = ?2 WHERE id = ?3",
                (now, detail.clone(), mutation.id.to_string()),
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO imap_mutation_conflicts(id, mutation_id, kind, expected_json, observed_json, detail, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    conflict_id.to_string(),
                    mutation.id.to_string(),
                    conflict_kind_text(kind),
                    serde_json::to_string(&expected)?,
                    serde_json::to_string(&observed)?,
                    detail.clone(),
                    now,
                ),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "imap_mutation_conflict",
            mutation.id.to_string(),
            json!({
                "mutation_id": mutation.id,
                "conflict_id": conflict_id,
                "kind": kind,
                "expected": expected,
                "observed": observed,
                "detail": detail,
            }),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }
}

async fn load_instance_on(
    connection: &turso::Connection,
    message_id: MessageId,
    folder_id: FolderId,
) -> Result<RemoteMessageIdentity> {
    let mut rows = connection
        .query(
            "SELECT mi.account_id, mi.uid_validity, mi.imap_uid, mi.mod_sequence, mi.flags_json FROM message_instances mi JOIN folders f ON f.id = mi.folder_id WHERE mi.message_id = ?1 AND mi.folder_id = ?2 AND f.kind = 'remote' ORDER BY mi.uid_validity DESC, mi.imap_uid DESC",
            (message_id.to_string(), folder_id.to_string()),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Err(BackendError::NotFound {
            entity: "remote message instance",
            id: format!("{message_id}@{folder_id}"),
        });
    };
    let identity = RemoteMessageIdentity {
        account_id: parse_account_id(row.get::<String>(0)?)?,
        folder_id,
        uid_validity: database_u32(row.get::<i64>(1)?, "UIDVALIDITY")?,
        uid: database_u32(row.get::<i64>(2)?, "UID")?,
        mod_sequence: row
            .get::<Option<i64>>(3)?
            .map(|value| database_u64(value, "MODSEQ"))
            .transpose()?,
        flags: serde_json::from_str(&row.get::<String>(4)?)?,
    };
    if rows.next().await?.is_some() {
        return Err(BackendError::Conflict(
            "message has more than one instance in the source mailbox".into(),
        ));
    }
    Ok(identity)
}

async fn validate_destination_on(
    connection: &turso::Connection,
    source: &RemoteMessageIdentity,
    operation: &ImapMutationOperation,
) -> Result<()> {
    let destination = match operation {
        ImapMutationOperation::Copy {
            destination_folder_id,
        }
        | ImapMutationOperation::Move {
            destination_folder_id,
        } => *destination_folder_id,
        ImapMutationOperation::SetFlags { .. } | ImapMutationOperation::Delete => return Ok(()),
    };
    if destination == source.folder_id {
        return Err(BackendError::InvalidInput(
            "source and destination IMAP folders must differ".into(),
        ));
    }
    let mut rows = connection
        .query(
            "SELECT f.account_id, f.kind, f.remote_name, s.selectable, s.remote_present FROM folders f LEFT JOIN imap_mailbox_state s ON s.folder_id = f.id WHERE f.id = ?1",
            (destination.to_string(),),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Err(BackendError::NotFound {
            entity: "destination folder",
            id: destination.to_string(),
        });
    };
    let account_id = row
        .get::<Option<String>>(0)?
        .ok_or_else(|| BackendError::InvalidInput("destination is not remote".into()))?;
    if parse_account_id(account_id)? != source.account_id
        || row.get::<String>(1)? != "remote"
        || row.get::<Option<String>>(2)?.is_none()
        || !row.get::<Option<bool>>(3)?.unwrap_or(false)
        || !row.get::<Option<bool>>(4)?.unwrap_or(false)
    {
        return Err(BackendError::InvalidInput(
            "destination must be a present, selectable remote mailbox on the same account".into(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_mutable_flags(flags: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(flags.len());
    for flag in flags {
        let value = match flag.to_ascii_lowercase().as_str() {
            "\\seen" => "\\Seen".to_owned(),
            "\\answered" => "\\Answered".to_owned(),
            "\\flagged" => "\\Flagged".to_owned(),
            "\\deleted" => "\\Deleted".to_owned(),
            "\\draft" => "\\Draft".to_owned(),
            "\\recent" => continue,
            "\\*" => {
                return Err(BackendError::InvalidInput(format!(
                    "IMAP flag {flag:?} cannot be changed"
                )));
            }
            _ if flag.strip_prefix('\\').is_some_and(valid_keyword) => flag,
            _ if valid_keyword(&flag) => flag,
            _ => {
                return Err(BackendError::InvalidInput(format!(
                    "invalid IMAP flag {flag:?}"
                )));
            }
        };
        normalized.push(value);
    }
    normalized.sort_by_key(|flag| flag.to_ascii_lowercase());
    normalized.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(normalized)
}

fn valid_keyword(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.starts_with('\\')
        && value.bytes().all(|byte| {
            byte > b' '
                && byte != 0x7f
                && !matches!(byte, b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b']')
        })
}

fn mutation_select_sql() -> &'static str {
    "SELECT id, account_id, message_id, source_folder_id, source_uid_validity, source_uid, source_modseq, source_flags_json, operation_json, status, attempts, last_error, created_at, updated_at, completed_at FROM imap_mutations"
}

fn mutation_from_row(row: &turso::Row) -> Result<ImapMutation> {
    let account_id = parse_account_id(row.get::<String>(1)?)?;
    let folder_id = parse_folder_id(row.get::<String>(3)?)?;
    Ok(ImapMutation {
        id: parse_mutation_id(row.get::<String>(0)?)?,
        account_id,
        message_id: parse_message_id(row.get::<String>(2)?)?,
        source: RemoteMessageIdentity {
            account_id,
            folder_id,
            uid_validity: database_u32(row.get::<i64>(4)?, "UIDVALIDITY")?,
            uid: database_u32(row.get::<i64>(5)?, "UID")?,
            mod_sequence: row
                .get::<Option<i64>>(6)?
                .map(|value| database_u64(value, "MODSEQ"))
                .transpose()?,
            flags: serde_json::from_str(&row.get::<String>(7)?)?,
        },
        operation: serde_json::from_str(&row.get::<String>(8)?)?,
        status: parse_mutation_status(&row.get::<String>(9)?)?,
        attempts: u32::try_from(row.get::<i64>(10)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid mutation attempt count".into())
        })?,
        last_error: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        completed_at: row.get(14)?,
    })
}

fn conflict_from_row(row: &turso::Row) -> Result<ImapMutationConflict> {
    Ok(ImapMutationConflict {
        id: ImapMutationConflictId::from_str(&row.get::<String>(0)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid IMAP conflict ID".into())
        })?,
        mutation_id: parse_mutation_id(row.get::<String>(1)?)?,
        kind: parse_conflict_kind(&row.get::<String>(2)?)?,
        expected: serde_json::from_str(&row.get::<String>(3)?)?,
        observed: serde_json::from_str(&row.get::<String>(4)?)?,
        detail: row.get(5)?,
        created_at: row.get(6)?,
        resolved_at: row.get(7)?,
    })
}

fn parse_mutation_status(value: &str) -> Result<ImapMutationStatus> {
    match value {
        "pending" => Ok(ImapMutationStatus::Pending),
        "in_flight" => Ok(ImapMutationStatus::InFlight),
        "applied" => Ok(ImapMutationStatus::Applied),
        "conflict" => Ok(ImapMutationStatus::Conflict),
        "cancelled" => Ok(ImapMutationStatus::Cancelled),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid IMAP mutation status".into(),
        )),
    }
}

fn conflict_kind_text(kind: ImapMutationConflictKind) -> &'static str {
    match kind {
        ImapMutationConflictKind::UidValidityChanged => "uid_validity_changed",
        ImapMutationConflictKind::SourceMissing => "source_missing",
        ImapMutationConflictKind::ServerStateChanged => "server_state_changed",
        ImapMutationConflictKind::DestinationUnavailable => "destination_unavailable",
        ImapMutationConflictKind::CapabilityUnavailable => "capability_unavailable",
        ImapMutationConflictKind::AmbiguousOutcome => "ambiguous_outcome",
        ImapMutationConflictKind::MissingServerMapping => "missing_server_mapping",
    }
}

fn parse_conflict_kind(value: &str) -> Result<ImapMutationConflictKind> {
    match value {
        "uid_validity_changed" => Ok(ImapMutationConflictKind::UidValidityChanged),
        "source_missing" => Ok(ImapMutationConflictKind::SourceMissing),
        "server_state_changed" => Ok(ImapMutationConflictKind::ServerStateChanged),
        "destination_unavailable" => Ok(ImapMutationConflictKind::DestinationUnavailable),
        "capability_unavailable" => Ok(ImapMutationConflictKind::CapabilityUnavailable),
        "ambiguous_outcome" => Ok(ImapMutationConflictKind::AmbiguousOutcome),
        "missing_server_mapping" => Ok(ImapMutationConflictKind::MissingServerMapping),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid IMAP mutation conflict kind".into(),
        )),
    }
}

fn parse_account_id(value: String) -> Result<AccountId> {
    AccountId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid account ID".into()))
}

fn parse_folder_id(value: String) -> Result<FolderId> {
    FolderId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid folder ID".into()))
}

fn parse_message_id(value: String) -> Result<MessageId> {
    MessageId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid message ID".into()))
}

fn parse_mutation_id(value: String) -> Result<ImapMutationId> {
    ImapMutationId::from_str(&value).map_err(|_| {
        BackendError::InvalidInput("database contains invalid IMAP mutation ID".into())
    })
}

fn database_u32(value: i64, field: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {field}")))
}

fn database_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountKind, BackendConfig, FolderKind, ImapSecurity, ImapSettings, IngestMessage,
        NewAccount, NewFolder,
    };

    #[test]
    fn mutable_flags_are_canonical_and_injection_safe() {
        assert_eq!(
            normalize_mutable_flags(vec![
                "\\seen".into(),
                "$Label1".into(),
                "\\Seen".into(),
                "\\Junk".into(),
            ])
            .unwrap(),
            vec!["$Label1", "\\Junk", "\\Seen"]
        );
        assert!(normalize_mutable_flags(vec!["bad flag".into()]).is_err());
        assert!(normalize_mutable_flags(vec!["x) UID EXPUNGE 1".into()]).is_err());
        assert!(normalize_mutable_flags(vec!["\\Recent".into()])
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn cancelling_ambiguity_releases_account_synchronization() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let account = backend
            .accounts()
            .add(NewAccount {
                name: "Ambiguity test".into(),
                kind: AccountKind::Imap,
                credential_ref: Some("test:ambiguity".into()),
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        let inbox = backend
            .folders()
            .add(NewFolder {
                account_id: Some(account.id),
                name: "Inbox".into(),
                kind: FolderKind::Remote,
                remote_name: Some("INBOX".into()),
            })
            .await
            .unwrap();
        let message_id = backend
            .messages()
            .ingest(IngestMessage {
                raw: b"From: a@example.test\r\nTo: b@example.test\r\n\r\nbody".to_vec(),
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: inbox.id,
                    uid_validity: 1,
                    uid: 1,
                    mod_sequence: None,
                    flags: Vec::new(),
                }),
                received_at: None,
                user_classification: None,
            })
            .await
            .unwrap();
        let mutations = backend.imap_mutations();
        let mutation = mutations.delete(message_id, inbox.id).await.unwrap();
        {
            let connection = backend.inner.connection.lock().await;
            connection
                .execute(
                    "UPDATE imap_mutations SET status = 'conflict' WHERE id = ?1",
                    (mutation.id.to_string(),),
                )
                .await
                .unwrap();
            connection
                .execute(
                    "INSERT INTO imap_mutation_conflicts(id, mutation_id, kind, expected_json, observed_json, detail, created_at) VALUES (?1, ?2, 'ambiguous_outcome', '{}', '{}', 'unknown result', 1)",
                    (ImapMutationConflictId::new().to_string(), mutation.id.to_string()),
                )
                .await
                .unwrap();
        }
        assert!(mutations.has_blocking_conflict(account.id).await.unwrap());
        mutations.cancel(mutation.id).await.unwrap();
        assert!(!mutations.has_blocking_conflict(account.id).await.unwrap());
    }
}
