use crate::backend::{insert_event, COLD_PREDICATE, SPAM_PREDICATE, WARM_PREDICATE};
use crate::{
    Backend, BackendError, CompositionKind, InboxClass, MessageComposition, MessageId, MessageSort,
    Page, ReplyAudience, Result, Thread, ThreadFilter, ThreadId, ThreadMembership,
    ThreadSenderTrust, ThreadSummary, ThreadWorkState, ThreadWorkStatus, ThreadingSource,
    WorkflowView,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mail_parser::thread_name;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use turso::{params_from_iter, Connection, Value};
use uuid::Uuid;

const MAX_THREAD_IDENTIFIERS: usize = 100;
const MAX_IN_REPLY_TO_IDENTIFIERS: usize = 16;
const MAX_IDENTIFIER_BYTES: usize = 512;
const SUBJECT_FALLBACK_SECONDS: i64 = 30 * 24 * 60 * 60;
const THREAD_NAMESPACE: Uuid = Uuid::from_u128(0x3d679c71_a4a2_5efd_a7d7_32bcd97802d6);

#[derive(Clone, Debug)]
pub(crate) struct ThreadInput {
    pub rfc_message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub subject: Option<String>,
    pub normalized_subject: Option<String>,
    pub from_address: Option<String>,
    pub participants: Vec<String>,
    pub received_at: i64,
}

impl ThreadInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rfc_message_id: Option<&str>,
        in_reply_to: &[String],
        references: &[String],
        subject: Option<&str>,
        from_address: Option<&str>,
        to_addresses: &[String],
        cc_addresses: &[String],
        bcc_addresses: &[String],
        reply_to_addresses: &[String],
        delivered_to_addresses: &[String],
        received_at: i64,
    ) -> Self {
        let mut participants = Vec::new();
        if let Some(from) = from_address {
            participants.push(from.to_owned());
        }
        for addresses in [
            to_addresses,
            cc_addresses,
            bcc_addresses,
            reply_to_addresses,
            delivered_to_addresses,
        ] {
            participants.extend(addresses.iter().cloned());
        }
        canonicalize_addresses(&mut participants);
        Self {
            rfc_message_id: rfc_message_id.and_then(canonical_message_id),
            in_reply_to: bounded_message_ids(in_reply_to, MAX_IN_REPLY_TO_IDENTIFIERS),
            references: bounded_message_ids(references, MAX_THREAD_IDENTIFIERS),
            subject: subject.and_then(display_subject),
            normalized_subject: subject.and_then(normalized_subject),
            from_address: from_address.map(normalize_address),
            participants,
            received_at,
        }
    }
}

#[derive(Clone)]
pub struct Threads(Backend);

impl Threads {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn get(&self, id: ThreadId) -> Result<Thread> {
        let (summary, message_ids) = {
            let connection = self.0.inner.connection.lock().await;
            let summary = load_summary_on(&connection, id).await?;
            let mut rows = connection
                .query(
                    "SELECT id FROM messages WHERE thread_id = ?1 ORDER BY received_at, id",
                    (id.to_string(),),
                )
                .await?;
            let mut message_ids = Vec::new();
            while let Some(row) = rows.next().await? {
                message_ids.push(parse_message_id(row.get(0)?)?);
            }
            (summary, message_ids)
        };
        let mut messages = Vec::with_capacity(message_ids.len());
        for message_id in message_ids {
            messages.push(self.0.messages().get(message_id).await?);
        }
        Ok(Thread { summary, messages })
    }

    pub async fn list(&self, filter: ThreadFilter) -> Result<Page<ThreadSummary>> {
        let page_size = filter.page_size.clamp(1, 200);
        let cursor = filter.cursor.as_deref().map(decode_cursor).transpose()?;
        let connection = self.0.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE thread_work_state SET status = 'active', snoozed_until = NULL, updated_at = unixepoch() WHERE status = 'snoozed' AND snoozed_until <= unixepoch()",
                (),
            )
            .await?;
        let mut clauses = vec!["m.thread_id IS NOT NULL".to_owned()];
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
        if let Some(workflow) = filter.workflow {
            clauses.push(workflow_predicate(workflow).into());
        } else if let Some(class) = filter.inbox_class {
            clauses.push(
                match class {
                    InboxClass::Warm => WARM_PREDICATE,
                    InboxClass::Cold => COLD_PREDICATE,
                    InboxClass::Spam => SPAM_PREDICATE,
                }
                .into(),
            );
        }
        let mut sql = format!(
            "SELECT m.thread_id, MAX(m.received_at) AS latest FROM messages m WHERE {} GROUP BY m.thread_id",
            clauses.join(" AND ")
        );
        if let Some(cursor) = cursor {
            match filter.sort {
                MessageSort::ReceivedNewest => {
                    sql.push_str(" HAVING latest < ? OR (latest = ? AND m.thread_id < ?)");
                }
                MessageSort::ReceivedOldest => {
                    sql.push_str(" HAVING latest > ? OR (latest = ? AND m.thread_id > ?)");
                }
            }
            parameters.push(Value::Integer(cursor.latest_received_at));
            parameters.push(Value::Integer(cursor.latest_received_at));
            parameters.push(Value::Text(cursor.thread_id.to_string()));
        }
        sql.push_str(match filter.sort {
            MessageSort::ReceivedNewest => " ORDER BY latest DESC, m.thread_id DESC LIMIT ?",
            MessageSort::ReceivedOldest => " ORDER BY latest ASC, m.thread_id ASC LIMIT ?",
        });
        parameters.push(Value::Integer((page_size + 1) as i64));
        let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push((parse_thread_id(row.get(0)?)?, row.get::<i64>(1)?));
        }
        let has_more = ids.len() > page_size;
        ids.truncate(page_size);
        let mut items = Vec::with_capacity(ids.len());
        for (id, _) in &ids {
            items.push(load_summary_on(&connection, *id).await?);
        }
        let next_cursor = if has_more {
            ids.last()
                .map(|(id, latest)| encode_cursor(*id, *latest))
                .transpose()?
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    pub async fn work_state(&self, id: ThreadId) -> Result<ThreadWorkState> {
        let connection = self.0.inner.connection.lock().await;
        let mut thread_rows = connection
            .query("SELECT 1 FROM threads WHERE id = ?1", (id.to_string(),))
            .await?;
        if thread_rows.next().await?.is_none() {
            return Err(BackendError::NotFound {
                entity: "thread",
                id: id.to_string(),
            });
        }
        drop(thread_rows);
        load_work_state_on(&connection, id).await
    }

    pub async fn set_work_state(
        &self,
        id: ThreadId,
        status: ThreadWorkStatus,
        snoozed_until: Option<i64>,
    ) -> Result<ThreadWorkState> {
        if status == ThreadWorkStatus::Snoozed {
            if snoozed_until.is_none_or(|value| value <= chrono::Utc::now().timestamp()) {
                return Err(BackendError::InvalidInput(
                    "a snoozed conversation requires a future Unix timestamp".into(),
                ));
            }
        } else if snoozed_until.is_some() {
            return Err(BackendError::InvalidInput(
                "only a snoozed conversation may have a wake timestamp".into(),
            ));
        }
        let now = chrono::Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query("SELECT 1 FROM threads WHERE id = ?1", (id.to_string(),))
            .await?;
        if rows.next().await?.is_none() {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "thread",
                id: id.to_string(),
            });
        }
        drop(rows);
        transaction
            .execute(
                r#"INSERT INTO thread_work_state(
                    thread_id, status, snoozed_until, actionable_once, updated_at
                ) VALUES (?1, ?2, ?3, 0, ?4)
                ON CONFLICT(thread_id) DO UPDATE SET
                    status = excluded.status,
                    snoozed_until = excluded.snoozed_until,
                    updated_at = excluded.updated_at"#,
                turso::params![id.to_string(), work_status_text(status), snoozed_until, now,],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "thread_work_state_changed",
            id.to_string(),
            serde_json::json!({
                "thread_id": id,
                "status": status,
                "snoozed_until": snoozed_until,
            }),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.work_state(id).await
    }

    pub async fn set_actionable_once(
        &self,
        id: ThreadId,
        actionable: bool,
    ) -> Result<ThreadWorkState> {
        let now = chrono::Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query("SELECT 1 FROM threads WHERE id = ?1", (id.to_string(),))
            .await?;
        if rows.next().await?.is_none() {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "thread",
                id: id.to_string(),
            });
        }
        drop(rows);
        transaction
            .execute(
                r#"INSERT INTO thread_work_state(
                    thread_id, status, snoozed_until, actionable_once, updated_at
                ) VALUES (?1, 'active', NULL, ?2, ?3)
                ON CONFLICT(thread_id) DO UPDATE SET
                    status = 'active', snoozed_until = NULL,
                    actionable_once = excluded.actionable_once,
                    updated_at = excluded.updated_at"#,
                (id.to_string(), actionable, now),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "thread_actionable_once_changed",
            id.to_string(),
            serde_json::json!({"thread_id": id, "actionable_once": actionable}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.work_state(id).await
    }

    pub async fn reply(
        &self,
        message_id: MessageId,
        audience: ReplyAudience,
    ) -> Result<MessageComposition> {
        let message = self.0.messages().get(message_id).await?;
        let own_addresses = self.own_addresses().await?;
        let mut primary = if !message.reply_to_addresses.is_empty() {
            message.reply_to_addresses.clone()
        } else {
            message
                .summary
                .from_address
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        if !primary.is_empty()
            && primary
                .iter()
                .all(|address| own_addresses.contains(&normalize_address(address)))
        {
            primary = message.to_addresses.clone();
        }
        canonicalize_addresses(&mut primary);
        primary.retain(|address| !own_addresses.contains(address));

        let mut cc = Vec::new();
        if audience == ReplyAudience::All {
            cc.extend(message.to_addresses.iter().cloned());
            cc.extend(message.cc_addresses.iter().cloned());
            canonicalize_addresses(&mut cc);
            let primary_set = primary.iter().cloned().collect::<HashSet<_>>();
            cc.retain(|address| !own_addresses.contains(address) && !primary_set.contains(address));
        }

        let mut references = if message.references.is_empty() {
            message.in_reply_to.clone()
        } else {
            message.references.clone()
        };
        let parent_rfc_message_id = message
            .rfc_message_id
            .as_deref()
            .and_then(canonical_message_id);
        if let Some(message_id) = parent_rfc_message_id.as_deref() {
            if !references.iter().any(|value| value == message_id) {
                references.push(message_id.to_owned());
            }
        }
        references = bound_outgoing_references(references);
        let subject = prefixed_subject("Re", message.summary.subject.as_deref());
        Ok(MessageComposition {
            kind: CompositionKind::Reply,
            thread_id: message.threading.thread_id,
            source_message_id: message.summary.id,
            parent_message_id: Some(message.summary.id),
            to_addresses: primary,
            cc_addresses: cc,
            subject,
            in_reply_to: parent_rfc_message_id,
            references,
            attached_message_id: None,
            attached_media_type: None,
        })
    }

    pub async fn forward(&self, message_id: MessageId) -> Result<MessageComposition> {
        let message = self.0.messages().get(message_id).await?;
        Ok(MessageComposition {
            kind: CompositionKind::Forward,
            thread_id: ThreadId::new(),
            source_message_id: message.summary.id,
            parent_message_id: None,
            to_addresses: Vec::new(),
            cc_addresses: Vec::new(),
            subject: prefixed_subject("Fwd", message.summary.subject.as_deref()),
            in_reply_to: None,
            references: Vec::new(),
            attached_message_id: Some(message.summary.id),
            attached_media_type: Some("message/rfc822".into()),
        })
    }

    async fn own_addresses(&self) -> Result<HashSet<String>> {
        let connection = self.0.inner.connection.lock().await;
        own_addresses_on(&connection).await
    }
}

pub(crate) async fn assign_message_on(
    connection: &Connection,
    message_id: MessageId,
    input: &ThreadInput,
) -> Result<ThreadMembership> {
    let sender_trust = sender_trust_on(connection, input.from_address.as_deref()).await?;
    let trust_text = trust_text(sender_trust);
    let mut selected = None;

    for (source, identifiers) in [
        (ThreadingSource::References, &input.references),
        (ThreadingSource::InReplyTo, &input.in_reply_to),
    ] {
        for identifier in identifiers.iter().rev() {
            if let Some((thread_id, parent)) =
                unique_header_target_on(connection, identifier, sender_trust).await?
            {
                selected = Some((thread_id, parent, source));
                break;
            }
        }
        if selected.is_some() {
            break;
        }
    }

    if selected.is_none() && input.references.is_empty() && input.in_reply_to.is_empty() {
        if let Some(normalized) = input.normalized_subject.as_deref() {
            if let Some(thread_id) = unique_subject_target_on(
                connection,
                normalized,
                sender_trust,
                input.from_address.as_deref(),
                input.received_at,
            )
            .await?
            {
                selected = Some((thread_id, None, ThreadingSource::NormalizedSubject));
            }
        }
    }

    let (thread_id, parent_message_id, source) = selected.unwrap_or_else(|| {
        let (source, anchor) = if let Some(anchor) = input.references.first() {
            (ThreadingSource::References, format!("message-id:{anchor}"))
        } else if let Some(anchor) = input.in_reply_to.first() {
            (ThreadingSource::InReplyTo, format!("message-id:{anchor}"))
        } else if let Some(anchor) = input.rfc_message_id.as_deref() {
            (ThreadingSource::Root, format!("message-id:{anchor}"))
        } else {
            (ThreadingSource::Root, format!("local-message:{message_id}"))
        };
        (stable_thread_id(sender_trust, &anchor), None, source)
    });
    let now = input.received_at;
    connection
        .execute(
            "INSERT OR IGNORE INTO threads(id, subject, normalized_subject, sender_trust, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            turso::params![
                thread_id.to_string(),
                input.subject.clone(),
                input.normalized_subject.clone(),
                trust_text,
                now,
                now,
            ],
        )
        .await?;
    connection
        .execute(
            "UPDATE threads SET subject = COALESCE(subject, ?1), normalized_subject = COALESCE(normalized_subject, ?2), updated_at = CASE WHEN updated_at < ?3 THEN ?3 ELSE updated_at END WHERE id = ?4",
            turso::params![
                input.subject.clone(),
                input.normalized_subject.clone(),
                now,
                thread_id.to_string(),
            ],
        )
        .await?;
    let changed = connection
        .execute(
            "UPDATE messages SET thread_message_id = ?1, thread_id = ?2, parent_message_id = ?3, threading_source = ?4, sender_trust = ?5, normalized_subject = ?6, in_reply_to_json = ?7, references_json = ?8 WHERE id = ?9",
            turso::params![
                input.rfc_message_id.clone(),
                thread_id.to_string(),
                parent_message_id.map(|id| id.to_string()),
                source_text(source),
                trust_text,
                input.normalized_subject.clone(),
                serde_json::to_string(&input.in_reply_to)?,
                serde_json::to_string(&input.references)?,
                message_id.to_string(),
            ],
        )
        .await?;
    if changed != 1 {
        return Err(BackendError::NotFound {
            entity: "message",
            id: message_id.to_string(),
        });
    }
    if input
        .from_address
        .as_deref()
        .is_some_and(|address| !address.trim().is_empty())
    {
        connection
            .execute(
                r#"UPDATE thread_work_state
                SET status = 'active', snoozed_until = NULL, updated_at = ?1
                WHERE thread_id = ?2 AND status IN ('done', 'waiting')
                  AND NOT EXISTS (
                    SELECT 1 FROM account_identities ai
                    WHERE ai.email_address = ?3 COLLATE NOCASE
                  )"#,
                turso::params![now, thread_id.to_string(), input.from_address.clone(),],
            )
            .await?;
    }
    for address in &input.participants {
        connection
            .execute(
                "INSERT OR IGNORE INTO thread_participants(message_id, thread_id, address) VALUES (?1, ?2, ?3)",
                (message_id.to_string(), thread_id.to_string(), address.clone()),
            )
            .await?;
    }
    Ok(ThreadMembership {
        thread_id,
        parent_message_id,
        source,
        sender_trust,
    })
}

async fn unique_header_target_on(
    connection: &Connection,
    identifier: &str,
    sender_trust: ThreadSenderTrust,
) -> Result<Option<(ThreadId, Option<MessageId>)>> {
    let trust_clause = match sender_trust {
        ThreadSenderTrust::Known => "",
        ThreadSenderTrust::Unknown => " AND t.sender_trust = 'unknown'",
    };
    let mut rows = connection
        .query(
            format!(
                "SELECT m.thread_id, m.id FROM messages m JOIN threads t ON t.id = m.thread_id WHERE m.thread_message_id = ?1 AND m.thread_id IS NOT NULL{trust_clause} ORDER BY m.id LIMIT 3"
            ),
            (identifier,),
        )
        .await?;
    let mut thread_id = None;
    let mut parent = None;
    let mut parent_ambiguous = false;
    while let Some(row) = rows.next().await? {
        let candidate_thread = parse_thread_id(row.get(0)?)?;
        if thread_id.is_some_and(|current| current != candidate_thread) {
            return Ok(None);
        }
        thread_id = Some(candidate_thread);
        let candidate_parent = parse_message_id(row.get(1)?)?;
        if parent.is_some() {
            parent_ambiguous = true;
        } else {
            parent = Some(candidate_parent);
        }
    }
    Ok(thread_id.map(|id| (id, (!parent_ambiguous).then_some(parent).flatten())))
}

async fn unique_subject_target_on(
    connection: &Connection,
    normalized_subject: &str,
    sender_trust: ThreadSenderTrust,
    from_address: Option<&str>,
    received_at: i64,
) -> Result<Option<ThreadId>> {
    let Some(from_address) = from_address else {
        return Ok(None);
    };
    let trust_clause = match sender_trust {
        ThreadSenderTrust::Known => "",
        ThreadSenderTrust::Unknown => " AND t.sender_trust = 'unknown'",
    };
    let sql = format!(
        "SELECT DISTINCT t.id FROM threads t JOIN thread_participants p ON p.thread_id = t.id WHERE t.normalized_subject = ?{trust_clause} AND t.updated_at >= ? AND t.updated_at <= ? AND p.address = ? COLLATE NOCASE ORDER BY t.updated_at DESC, t.id LIMIT 2"
    );
    let parameters = vec![
        Value::Text(normalized_subject.to_owned()),
        Value::Integer(received_at.saturating_sub(SUBJECT_FALLBACK_SECONDS)),
        Value::Integer(received_at.saturating_add(SUBJECT_FALLBACK_SECONDS)),
        Value::Text(normalize_address(from_address)),
    ];
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    let first = rows
        .next()
        .await?
        .map(|row| parse_thread_id(row.get(0)?))
        .transpose()?;
    if first.is_some() && rows.next().await?.is_some() {
        return Ok(None);
    }
    Ok(first)
}

async fn sender_trust_on(
    connection: &Connection,
    from_address: Option<&str>,
) -> Result<ThreadSenderTrust> {
    let Some(from_address) = from_address else {
        return Ok(ThreadSenderTrust::Unknown);
    };
    let mut rows = connection
        .query(
            "SELECT 1 FROM contact_addresses WHERE address = ?1 COLLATE NOCASE LIMIT 1",
            (from_address,),
        )
        .await?;
    if rows.next().await?.is_some() {
        return Ok(ThreadSenderTrust::Known);
    }
    drop(rows);
    if own_addresses_on(connection)
        .await?
        .contains(&normalize_address(from_address))
    {
        Ok(ThreadSenderTrust::Known)
    } else {
        Ok(ThreadSenderTrust::Unknown)
    }
}

async fn own_addresses_on(connection: &Connection) -> Result<HashSet<String>> {
    let mut rows = connection
        .query("SELECT email_address FROM account_identities", ())
        .await?;
    let mut addresses = HashSet::new();
    while let Some(row) = rows.next().await? {
        addresses.insert(normalize_address(&row.get::<String>(0)?));
    }
    Ok(addresses)
}

async fn load_summary_on(connection: &Connection, id: ThreadId) -> Result<ThreadSummary> {
    let mut rows = connection
        .query(
            "SELECT t.subject, t.normalized_subject, t.sender_trust, COUNT(m.id), COALESCE(SUM(CASE WHEN m.is_read = 0 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN m.is_starred = 1 THEN 1 ELSE 0 END), 0), t.openpgp_encryption_required FROM threads t JOIN messages m ON m.thread_id = t.id WHERE t.id = ?1 GROUP BY t.id",
            (id.to_string(),),
        )
        .await?;
    let row = rows.next().await?.ok_or_else(|| BackendError::NotFound {
        entity: "thread",
        id: id.to_string(),
    })?;
    let subject = row.get(0)?;
    let normalized_subject = row.get(1)?;
    let sender_trust = parse_trust(&row.get::<String>(2)?)?;
    let message_count = row.get::<i64>(3)? as u64;
    let unread_count = row.get::<i64>(4)? as u64;
    let starred_count = row.get::<i64>(5)? as u64;
    let openpgp_encryption_required = row.get::<bool>(6)?;
    drop(rows);

    let mut rows = connection
        .query(
            "SELECT id, received_at, preview FROM messages WHERE thread_id = ?1 ORDER BY received_at DESC, id DESC LIMIT 1",
            (id.to_string(),),
        )
        .await?;
    let latest = rows.next().await?.ok_or_else(|| BackendError::NotFound {
        entity: "thread",
        id: id.to_string(),
    })?;
    let latest_message_id = parse_message_id(latest.get(0)?)?;
    let latest_received_at = latest.get(1)?;
    let latest_preview = latest.get(2)?;
    drop(rows);

    let mut rows = connection
        .query(
            "SELECT DISTINCT address FROM thread_participants WHERE thread_id = ?1 ORDER BY address",
            (id.to_string(),),
        )
        .await?;
    let mut participants = Vec::new();
    while let Some(row) = rows.next().await? {
        participants.push(row.get(0)?);
    }
    let work_state = load_work_state_on(connection, id).await?;
    Ok(ThreadSummary {
        id,
        subject,
        normalized_subject,
        participants,
        message_count,
        unread_count,
        starred_count,
        latest_message_id,
        latest_received_at,
        latest_preview,
        sender_trust,
        openpgp_encryption_required,
        work_state,
    })
}

async fn load_work_state_on(connection: &Connection, id: ThreadId) -> Result<ThreadWorkState> {
    let mut rows = connection
        .query(
            "SELECT status, snoozed_until, actionable_once, updated_at FROM thread_work_state WHERE thread_id = ?1",
            (id.to_string(),),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(ThreadWorkState::default());
    };
    Ok(ThreadWorkState {
        status: parse_work_status(&row.get::<String>(0)?)?,
        snoozed_until: row.get(1)?,
        actionable_once: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn workflow_predicate(view: WorkflowView) -> String {
    const ACTIVE: &str = "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'active'";
    const HAS_INBOUND: &str = "EXISTS (SELECT 1 FROM messages inbound WHERE inbound.thread_id = m.thread_id AND inbound.from_address IS NOT NULL AND trim(inbound.from_address) != '' AND NOT EXISTS (SELECT 1 FROM account_identities own_identity WHERE own_identity.email_address = inbound.from_address COLLATE NOCASE))";
    match view {
        WorkflowView::WarmAction => format!(
            "({WARM_PREDICATE} OR COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 1) AND {ACTIVE} AND {HAS_INBOUND} AND (COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 1 OR EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 1))"
        ),
        WorkflowView::WarmFyi => format!(
            "{WARM_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND} AND COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 0 AND EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 0) AND NOT EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 1)"
        ),
        WorkflowView::ColdReview => format!(
            "{COLD_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND} AND COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 0"
        ),
        WorkflowView::SpamQuarantine => {
            format!("{SPAM_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND}")
        }
        WorkflowView::Waiting => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'waiting'".into(),
        WorkflowView::Snoozed => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'snoozed' AND (SELECT tws.snoozed_until FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) > unixepoch()".into(),
        WorkflowView::Done => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'done'".into(),
    }
}

fn work_status_text(value: ThreadWorkStatus) -> &'static str {
    match value {
        ThreadWorkStatus::Active => "active",
        ThreadWorkStatus::Waiting => "waiting",
        ThreadWorkStatus::Snoozed => "snoozed",
        ThreadWorkStatus::Done => "done",
    }
}

fn parse_work_status(value: &str) -> Result<ThreadWorkStatus> {
    match value {
        "active" => Ok(ThreadWorkStatus::Active),
        "waiting" => Ok(ThreadWorkStatus::Waiting),
        "snoozed" => Ok(ThreadWorkStatus::Snoozed),
        "done" => Ok(ThreadWorkStatus::Done),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid thread work state".into(),
        )),
    }
}

fn stable_thread_id(trust: ThreadSenderTrust, anchor: &str) -> ThreadId {
    ThreadId::from_uuid(Uuid::new_v5(
        &THREAD_NAMESPACE,
        format!("{}\0{anchor}", trust_text(trust)).as_bytes(),
    ))
}

fn canonical_message_id(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('<').trim_end_matches('>');
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return None;
    }
    if let Some((local, domain)) = value.rsplit_once('@') {
        if local.is_empty() || domain.is_empty() {
            return None;
        }
        Some(format!("{local}@{}", domain.to_ascii_lowercase()))
    } else {
        Some(value.to_owned())
    }
}

fn bounded_message_ids(values: &[String], maximum: usize) -> Vec<String> {
    let mut values = values
        .iter()
        .filter_map(|value| canonical_message_id(value))
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
    if values.len() > maximum {
        let tail = values.split_off(values.len() - (maximum - 1));
        values.truncate(1);
        values.extend(tail);
    }
    values
}

fn bound_outgoing_references(mut values: Vec<String>) -> Vec<String> {
    values = bounded_message_ids(&values, 50);
    while values.iter().map(|value| value.len() + 3).sum::<usize>() > 4096 && values.len() > 2 {
        values.remove(1);
    }
    values
}

fn display_subject(subject: &str) -> Option<String> {
    let value = thread_name(subject);
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    (!value.is_empty()).then_some(value)
}

fn normalized_subject(subject: &str) -> Option<String> {
    display_subject(subject).map(|value| value.to_lowercase())
}

fn prefixed_subject(prefix: &str, subject: Option<&str>) -> String {
    match subject.and_then(display_subject) {
        Some(subject) => format!("{prefix}: {subject}"),
        None => format!("{prefix}:"),
    }
}

fn normalize_address(address: &str) -> String {
    address.trim().to_lowercase()
}

fn canonicalize_addresses(addresses: &mut Vec<String>) {
    let mut seen = HashSet::new();
    addresses.iter_mut().for_each(|value| {
        *value = normalize_address(value);
    });
    addresses.retain(|value| !value.is_empty() && seen.insert(value.clone()));
    addresses.truncate(100);
}

fn trust_text(value: ThreadSenderTrust) -> &'static str {
    match value {
        ThreadSenderTrust::Known => "known",
        ThreadSenderTrust::Unknown => "unknown",
    }
}

fn parse_trust(value: &str) -> Result<ThreadSenderTrust> {
    match value {
        "known" => Ok(ThreadSenderTrust::Known),
        "unknown" => Ok(ThreadSenderTrust::Unknown),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid thread sender trust".into(),
        )),
    }
}

fn source_text(value: ThreadingSource) -> &'static str {
    match value {
        ThreadingSource::Root => "root",
        ThreadingSource::References => "references",
        ThreadingSource::InReplyTo => "in_reply_to",
        ThreadingSource::NormalizedSubject => "normalized_subject",
    }
}

pub(crate) fn parse_source(value: &str) -> Result<ThreadingSource> {
    match value {
        "root" => Ok(ThreadingSource::Root),
        "references" => Ok(ThreadingSource::References),
        "in_reply_to" => Ok(ThreadingSource::InReplyTo),
        "normalized_subject" => Ok(ThreadingSource::NormalizedSubject),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid threading source".into(),
        )),
    }
}

pub(crate) fn parse_sender_trust(value: &str) -> Result<ThreadSenderTrust> {
    parse_trust(value)
}

fn parse_thread_id(value: String) -> Result<ThreadId> {
    value.parse().map_err(|_| {
        BackendError::InvalidInput("database contains invalid thread identifier".into())
    })
}

fn parse_message_id(value: String) -> Result<MessageId> {
    value.parse().map_err(|_| {
        BackendError::InvalidInput("database contains invalid message identifier".into())
    })
}

#[derive(Serialize, Deserialize)]
struct ThreadCursor {
    latest_received_at: i64,
    thread_id: ThreadId,
}

fn encode_cursor(thread_id: ThreadId, latest_received_at: i64) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&ThreadCursor {
        latest_received_at,
        thread_id,
    })?))
}

fn decode_cursor(value: &str) -> Result<ThreadCursor> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BackendError::InvalidInput("invalid thread cursor".into()))?;
    serde_json::from_slice(&decoded)
        .map_err(|_| BackendError::InvalidInput("invalid thread cursor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_subjects_and_bounded_reference_chains() {
        assert_eq!(
            normalized_subject(" Re[2]: [list]  Lunch   Friday ").as_deref(),
            Some("lunch friday")
        );
        let values = (0..120)
            .map(|value| format!("id-{value}@EXAMPLE.COM"))
            .collect::<Vec<_>>();
        let bounded = bounded_message_ids(&values, 100);
        assert_eq!(bounded.len(), 100);
        assert_eq!(bounded.first().unwrap(), "id-0@example.com");
        assert_eq!(bounded.last().unwrap(), "id-119@example.com");
    }

    #[test]
    fn trust_partition_is_part_of_stable_identity() {
        let known = stable_thread_id(ThreadSenderTrust::Known, "message-id:a@example.com");
        let unknown = stable_thread_id(ThreadSenderTrust::Unknown, "message-id:a@example.com");
        assert_ne!(known, unknown);
        assert_eq!(
            known,
            stable_thread_id(ThreadSenderTrust::Known, "message-id:a@example.com")
        );
    }
}
