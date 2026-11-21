use crate::backend::{insert_event, COLD_PREDICATE, SPAM_PREDICATE, WARM_PREDICATE};
use crate::{
    Backend, BackendError, CompositionKind, InboxClass, MessageComposition, MessageId, MessageSort,
    Page, ReplyAudience, Result, RouteOverrideSource, SimilarityRuleId, Thread, ThreadFilter,
    ThreadId, ThreadMembership, ThreadSenderTrust, ThreadSummary, ThreadWorkState,
    ThreadWorkStatus, ThreadingSource, WarmRoute, WorkflowView,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lizard_verified_kernel::{thread_candidate_allowed, TrustState};
use mail_parser::thread_name;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
        let messages = self.0.messages().get_many(&message_ids).await?;
        Ok(Thread { summary, messages })
    }

    /// Load the conversation summary and its newest message only.
    ///
    /// Frontends use this latency-sensitive snapshot for the first reader
    /// frame. It has a dedicated WAL read connection so background database
    /// work cannot monopolize the in-process connection mutex. Call
    /// [`Self::get`]
    /// when the complete conversation history is actually needed.
    pub async fn get_latest(&self, id: ThreadId) -> Result<Thread> {
        let mut connection = self.0.inner.interactive_connection.lock().await;
        let transaction = connection.transaction().await?;
        let summary = load_summary_on(&transaction, id).await?;
        let latest_message_id = summary.latest_message_id;
        let mut messages =
            crate::backend::load_messages_on(&transaction, &[latest_message_id]).await?;
        let message = messages.pop().ok_or_else(|| {
            BackendError::InvalidInput("conversation has no newest message".into())
        })?;
        transaction.commit().await?;
        Ok(Thread {
            summary,
            messages: vec![message],
        })
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
            clauses.push(workflow_predicate(workflow));
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
        let items = load_summaries_on(&connection, &ids).await?;
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
                    thread_id, status, snoozed_until, actionable_once,
                    route_override, route_override_source, route_override_rule_id,
                    updated_at
                ) VALUES (?1, 'active', NULL, ?2, ?4, ?5, NULL, ?3)
                ON CONFLICT(thread_id) DO UPDATE SET
                    status = 'active', snoozed_until = NULL,
                    actionable_once = excluded.actionable_once,
                    route_override = excluded.route_override,
                    route_override_source = excluded.route_override_source,
                    route_override_rule_id = NULL,
                    updated_at = excluded.updated_at"#,
                turso::params![
                    id.to_string(),
                    actionable,
                    now,
                    actionable.then_some("action"),
                    actionable.then_some("manual"),
                ],
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

    /// Set or clear the explicit Action/FYI route for one conversation. This
    /// is a user-owned correction and therefore outranks similarity rules.
    pub async fn set_route_override(
        &self,
        id: ThreadId,
        route: Option<WarmRoute>,
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
        if route == Some(WarmRoute::Fyi) {
            let mut known_rows = transaction
                .query(
                    r#"SELECT 1
                    FROM messages m
                    JOIN contact_addresses ca
                        ON ca.address = m.from_address COLLATE NOCASE
                    WHERE m.thread_id = ?1
                    LIMIT 1"#,
                    (id.to_string(),),
                )
                .await?;
            if known_rows.next().await?.is_none() {
                drop(known_rows);
                transaction.rollback().await?;
                return Err(BackendError::InvalidInput(
                    "FYI routing requires a known contact; Cold mail can instead be made actionable once or its sender can be added to contacts"
                        .into(),
                ));
            }
        }
        transaction
            .execute(
                r#"INSERT INTO thread_work_state(
                    thread_id, status, snoozed_until, actionable_once,
                    route_override, route_override_source, route_override_rule_id,
                    updated_at
                ) VALUES (?1, 'active', NULL, 0, ?2, ?3, NULL, ?4)
                ON CONFLICT(thread_id) DO UPDATE SET
                    actionable_once = 0,
                    route_override = excluded.route_override,
                    route_override_source = excluded.route_override_source,
                    route_override_rule_id = NULL,
                    updated_at = excluded.updated_at"#,
                turso::params![
                    id.to_string(),
                    route.map(warm_route_text),
                    route.map(|_| "manual"),
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "thread_route_override_changed",
            id.to_string(),
            serde_json::json!({"thread_id": id, "route_override": route}),
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
                "SELECT m.thread_id, m.id, t.sender_trust FROM messages m JOIN threads t ON t.id = m.thread_id WHERE m.thread_message_id = ?1 AND m.thread_id IS NOT NULL{trust_clause} ORDER BY m.id LIMIT 3"
            ),
            (identifier,),
        )
        .await?;
    let mut thread_id = None;
    let mut parent = None;
    let mut parent_ambiguous = false;
    while let Some(row) = rows.next().await? {
        let candidate_trust = parse_sender_trust(&row.get::<String>(2)?)?;
        if !thread_candidate_allowed(
            verified_trust(sender_trust),
            verified_trust(candidate_trust),
        ) {
            continue;
        }
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
        "SELECT DISTINCT t.id, t.sender_trust FROM threads t JOIN thread_participants p ON p.thread_id = t.id WHERE t.normalized_subject = ?{trust_clause} AND t.updated_at >= ? AND t.updated_at <= ? AND p.address = ? COLLATE NOCASE ORDER BY t.updated_at DESC, t.id LIMIT 2"
    );
    let parameters = vec![
        Value::Text(normalized_subject.to_owned()),
        Value::Integer(received_at.saturating_sub(SUBJECT_FALLBACK_SECONDS)),
        Value::Integer(received_at.saturating_add(SUBJECT_FALLBACK_SECONDS)),
        Value::Text(normalize_address(from_address)),
    ];
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    let mut first = None;
    while let Some(row) = rows.next().await? {
        let candidate_trust = parse_sender_trust(&row.get::<String>(1)?)?;
        if !thread_candidate_allowed(
            verified_trust(sender_trust),
            verified_trust(candidate_trust),
        ) {
            continue;
        }
        let candidate = parse_thread_id(row.get(0)?)?;
        if first.replace(candidate).is_some() {
            return Ok(None);
        }
    }
    Ok(first)
}

fn verified_trust(value: ThreadSenderTrust) -> TrustState {
    match value {
        ThreadSenderTrust::Known => TrustState::Known,
        ThreadSenderTrust::Unknown => TrustState::Unknown,
    }
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
    load_summaries_on(connection, &[(id, 0)])
        .await?
        .pop()
        .ok_or_else(|| BackendError::NotFound {
            entity: "thread",
            id: id.to_string(),
        })
}

/// Load a bounded page of thread summaries in two queries rather than issuing
/// four queries for every thread. `Threads::list` caps the input at 200 IDs;
/// the single-item `Threads::get` path uses the same loader so their summary
/// semantics cannot drift.
async fn load_summaries_on(
    connection: &Connection,
    ids: &[(ThreadId, i64)],
) -> Result<Vec<ThreadSummary>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let selected_values = std::iter::repeat_n("(?, ?)", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        r#"WITH selected(thread_id, ordinal) AS (VALUES {selected_values}),
        message_rollup AS (
            SELECT m.thread_id, m.id, m.received_at, m.preview,
                m.from_address, m.from_name,
                COUNT(*) OVER (PARTITION BY m.thread_id) AS message_count,
                SUM(CASE WHEN m.is_read = 0 THEN 1 ELSE 0 END)
                    OVER (PARTITION BY m.thread_id) AS unread_count,
                SUM(CASE WHEN m.is_starred = 1 THEN 1 ELSE 0 END)
                    OVER (PARTITION BY m.thread_id) AS starred_count,
                ROW_NUMBER() OVER (
                    PARTITION BY m.thread_id
                    ORDER BY m.received_at DESC, m.id DESC
                ) AS newest
            FROM messages m
            JOIN selected s ON s.thread_id = m.thread_id
        )
        SELECT s.thread_id, t.subject, t.normalized_subject, t.sender_trust,
            mr.message_count, mr.unread_count, mr.starred_count,
            t.openpgp_encryption_required,
            mr.id, mr.received_at, mr.preview, mr.from_address, mr.from_name,
            COALESCE(tws.status, 'active'), tws.snoozed_until,
            COALESCE(tws.actionable_once, 0), tws.route_override,
            tws.route_override_source, tws.route_override_rule_id,
            COALESCE(tws.updated_at, 0)
        FROM selected s
        JOIN threads t ON t.id = s.thread_id
        JOIN message_rollup mr ON mr.thread_id = s.thread_id AND mr.newest = 1
        LEFT JOIN thread_work_state tws ON tws.thread_id = s.thread_id
        ORDER BY s.ordinal"#
    );
    let mut parameters = Vec::with_capacity(ids.len() * 2);
    for (ordinal, (id, _)) in ids.iter().enumerate() {
        parameters.push(Value::Text(id.to_string()));
        parameters.push(Value::Integer(ordinal as i64));
    }
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    let mut summaries = Vec::with_capacity(ids.len());
    while let Some(row) = rows.next().await? {
        let id = parse_thread_id(row.get(0)?)?;
        summaries.push(ThreadSummary {
            id,
            subject: row.get(1)?,
            normalized_subject: row.get(2)?,
            sender_trust: parse_trust(&row.get::<String>(3)?)?,
            message_count: nonnegative_u64(row.get(4)?, "thread message count")?,
            unread_count: nonnegative_u64(row.get(5)?, "thread unread count")?,
            starred_count: nonnegative_u64(row.get(6)?, "thread starred count")?,
            openpgp_encryption_required: row.get(7)?,
            latest_message_id: parse_message_id(row.get(8)?)?,
            latest_received_at: row.get(9)?,
            latest_preview: row.get(10)?,
            latest_from_address: row.get(11)?,
            latest_from_name: row.get(12)?,
            participants: Vec::new(),
            work_state: ThreadWorkState {
                status: parse_work_status(&row.get::<String>(13)?)?,
                snoozed_until: row.get(14)?,
                actionable_once: row.get(15)?,
                route_override: row
                    .get::<Option<String>>(16)?
                    .map(|value| parse_warm_route(&value))
                    .transpose()?,
                route_override_source: row
                    .get::<Option<String>>(17)?
                    .map(|value| parse_route_source(&value))
                    .transpose()?,
                route_override_rule_id: row
                    .get::<Option<String>>(18)?
                    .map(|value| parse_similarity_rule_id(&value))
                    .transpose()?,
                updated_at: row.get(19)?,
            },
        });
    }
    drop(rows);
    if summaries.len() != ids.len() {
        let returned = summaries
            .iter()
            .map(|summary| summary.id)
            .collect::<HashSet<_>>();
        let missing = ids
            .iter()
            .map(|(id, _)| *id)
            .find(|id| !returned.contains(id))
            .unwrap_or(ids[0].0);
        return Err(BackendError::NotFound {
            entity: "thread",
            id: missing.to_string(),
        });
    }

    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let mut participant_rows = connection
        .query(
            format!(
                "SELECT thread_id, address FROM thread_participants WHERE thread_id IN ({placeholders}) GROUP BY thread_id, address ORDER BY thread_id, address"
            ),
            params_from_iter(
                ids.iter()
                    .map(|(id, _)| Value::Text(id.to_string()))
                    .collect::<Vec<_>>(),
            ),
        )
        .await?;
    let positions = summaries
        .iter()
        .enumerate()
        .map(|(index, summary)| (summary.id, index))
        .collect::<HashMap<_, _>>();
    while let Some(row) = participant_rows.next().await? {
        let id = parse_thread_id(row.get(0)?)?;
        let Some(index) = positions.get(&id).copied() else {
            return Err(BackendError::InvalidInput(
                "database returned a participant for an unrequested thread".into(),
            ));
        };
        summaries[index].participants.push(row.get(1)?);
    }
    Ok(summaries)
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {label}")))
}

async fn load_work_state_on(connection: &Connection, id: ThreadId) -> Result<ThreadWorkState> {
    let mut rows = connection
        .query(
            "SELECT status, snoozed_until, actionable_once, route_override, route_override_source, route_override_rule_id, updated_at FROM thread_work_state WHERE thread_id = ?1",
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
        route_override: row
            .get::<Option<String>>(3)?
            .map(|value| parse_warm_route(&value))
            .transpose()?,
        route_override_source: row
            .get::<Option<String>>(4)?
            .map(|value| parse_route_source(&value))
            .transpose()?,
        route_override_rule_id: row
            .get::<Option<String>>(5)?
            .map(|value| parse_similarity_rule_id(&value))
            .transpose()?,
        updated_at: row.get(6)?,
    })
}

fn workflow_predicate(view: WorkflowView) -> String {
    const ACTIVE: &str = "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'active'";
    const HAS_INBOUND: &str = "EXISTS (SELECT 1 FROM messages inbound WHERE inbound.thread_id = m.thread_id AND inbound.from_address IS NOT NULL AND trim(inbound.from_address) != '' AND NOT EXISTS (SELECT 1 FROM account_identities own_identity WHERE own_identity.email_address = inbound.from_address COLLATE NOCASE))";
    match view {
        WorkflowView::WarmAction => format!(
            "NOT ({SPAM_PREDICATE}) AND ({WARM_PREDICATE} OR COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 1 OR (SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) = 'action') AND {ACTIVE} AND {HAS_INBOUND} AND (COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 1 OR (SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) = 'action' OR ((SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) IS NULL AND EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 1)))"
        ),
        WorkflowView::WarmFyi => format!(
            "{WARM_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND} AND COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 0 AND ((SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) = 'fyi' OR ((SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) IS NULL AND EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 0) AND NOT EXISTS (SELECT 1 FROM messages tm JOIN contact_addresses ca ON ca.address = tm.from_address COLLATE NOCASE JOIN contact_relationships cr ON cr.contact_id = ca.contact_id WHERE tm.thread_id = m.thread_id AND cr.may_create_obligations = 1)))"
        ),
        WorkflowView::ColdReview => format!(
            "{COLD_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND} AND COALESCE((SELECT tws.actionable_once FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 0) = 0 AND COALESCE((SELECT tws.route_override FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), '') != 'action'"
        ),
        WorkflowView::SpamQuarantine => {
            format!("{SPAM_PREDICATE} AND {ACTIVE} AND {HAS_INBOUND}")
        }
        WorkflowView::Waiting => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'waiting'".into(),
        WorkflowView::Snoozed => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'snoozed' AND (SELECT tws.snoozed_until FROM thread_work_state tws WHERE tws.thread_id = m.thread_id) > unixepoch()".into(),
        WorkflowView::Done => "COALESCE((SELECT tws.status FROM thread_work_state tws WHERE tws.thread_id = m.thread_id), 'active') = 'done'".into(),
    }
}

fn warm_route_text(value: WarmRoute) -> &'static str {
    match value {
        WarmRoute::Action => "action",
        WarmRoute::Fyi => "fyi",
    }
}

fn parse_warm_route(value: &str) -> Result<WarmRoute> {
    match value {
        "action" => Ok(WarmRoute::Action),
        "fyi" => Ok(WarmRoute::Fyi),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid thread route override".into(),
        )),
    }
}

fn parse_route_source(value: &str) -> Result<RouteOverrideSource> {
    match value {
        "manual" => Ok(RouteOverrideSource::Manual),
        "similarity_rule" => Ok(RouteOverrideSource::SimilarityRule),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid thread route source".into(),
        )),
    }
}

fn parse_similarity_rule_id(value: &str) -> Result<SimilarityRuleId> {
    value.parse().map_err(|_| {
        BackendError::InvalidInput("database contains invalid similarity rule ID".into())
    })
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

    #[tokio::test]
    async fn latest_snapshot_reads_while_general_connection_is_writing() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(crate::BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let message_id = backend
            .ingest(crate::IngestMessage::local(
                b"From: sender@example.test\r\nTo: reader@example.test\r\nMessage-ID: <interactive-read@example.test>\r\nSubject: Interactive read\r\n\r\nBody\r\n"
                    .to_vec(),
            ))
            .await
            .unwrap();
        let thread_id = backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .summary
            .thread_id;

        let mut general = backend.inner.connection.lock().await;
        let transaction = general.transaction().await.unwrap();
        transaction
            .execute(
                "UPDATE messages SET preview = preview WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await
            .unwrap();

        let snapshot = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            backend.threads().get_latest(thread_id),
        )
        .await
        .expect("interactive WAL reader must not wait for the general connection mutex")
        .unwrap();
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].summary.id, message_id);
        transaction.commit().await.unwrap();
    }

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
