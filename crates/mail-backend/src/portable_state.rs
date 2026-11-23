//! Versioned, private IMAP keyword projection for user-authored organization.
//!
//! These keywords are deliberately incapable of establishing sender trust,
//! changing Warm/Cold/Spam classification, or granting Actionable Once.

use crate::backend::insert_event;
use crate::{
    AccountId, Backend, BackendError, FolderId, MessageId, RemoteMessageIdentity, Result, ThreadId,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::str::FromStr;
use turso::Connection;

pub(crate) const PREFIX: &str = "$LizardV1";
const DONE: &str = "$LizardV1Done";
const WAITING: &str = "$LizardV1Waiting";
const MUTE: &str = "$LizardV1Mute";
const PRIORITY_LOW: &str = "$LizardV1PriorityLow";
const PRIORITY_HIGH: &str = "$LizardV1PriorityHigh";
const ROUTE_ACTION: &str = "$LizardV1RouteAction";
const ROUTE_FYI: &str = "$LizardV1RouteFyi";
const THREAD_SNOOZE_PREFIX: &str = "$LizardV1Snooze";
const MESSAGE_SNOOZE_PREFIX: &str = "$LizardV1MessageSnooze";

pub(crate) fn is_portable_keyword(value: &str) -> bool {
    value
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
}

fn canonical_keywords(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .filter(|value| is_portable_keyword(value))
        .collect::<Vec<_>>();
    values.sort_by_key(|value| value.to_ascii_lowercase());
    values.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    values
}

fn has_keyword(values: &HashSet<String>, keyword: &str) -> bool {
    values
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(keyword))
}

fn encoded_timestamp(prefix: &str, value: i64) -> String {
    format!("{prefix}{value}")
}

fn parse_timestamp(value: &str, prefix: &str) -> Option<i64> {
    value
        .get(prefix.len()..)
        .filter(|_| {
            value
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })?
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
}

pub(crate) async fn stage_thread_on(
    connection: &Connection,
    thread_id: ThreadId,
    now: i64,
) -> Result<()> {
    let mut state_rows = connection
        .query(
            "SELECT status, snoozed_until, route_override, route_override_source, actionable_once FROM thread_work_state WHERE thread_id = ?1",
            (thread_id.to_string(),),
        )
        .await?;
    let state = state_rows
        .next()
        .await?
        .map(|row| {
            Ok::<_, BackendError>((
                row.get::<String>(0)?,
                row.get::<Option<i64>>(1)?,
                row.get::<Option<String>>(2)?,
                row.get::<Option<String>>(3)?,
                row.get::<bool>(4)?,
            ))
        })
        .transpose()?
        .unwrap_or_else(|| ("active".into(), None, None, None, false));
    drop(state_rows);

    let mut rows = connection
        .query(
            r#"SELECT m.id, m.snoozed_until, m.muted, m.priority,
                m.from_address IS NOT NULL AND trim(m.from_address) != '' AND NOT EXISTS (
                    SELECT 1 FROM account_identities ai
                    WHERE ai.email_address = m.from_address COLLATE NOCASE
                )
            FROM messages m WHERE m.thread_id = ?1 ORDER BY m.received_at, m.id"#,
            (thread_id.to_string(),),
        )
        .await?;
    let mut messages = Vec::new();
    while let Some(row) = rows.next().await? {
        messages.push((
            parse_message_id(row.get(0)?)?,
            row.get::<Option<i64>>(1)?,
            row.get::<bool>(2)?,
            row.get::<String>(3)?,
            row.get::<bool>(4)?,
        ));
    }
    drop(rows);
    for (message_id, message_snooze, muted, priority, inbound) in messages {
        let mut desired = Vec::new();
        if inbound {
            match state.0.as_str() {
                "done" => desired.push(DONE.to_owned()),
                "waiting" => desired.push(WAITING.to_owned()),
                "snoozed" => {
                    if let Some(until) = state.1 {
                        desired.push(encoded_timestamp(THREAD_SNOOZE_PREFIX, until));
                    }
                }
                _ => {}
            }
            if !state.4 && state.3.as_deref() == Some("manual") {
                match state.2.as_deref() {
                    Some("action") => desired.push(ROUTE_ACTION.to_owned()),
                    Some("fyi") => desired.push(ROUTE_FYI.to_owned()),
                    _ => {}
                }
            }
        }
        if let Some(until) = message_snooze {
            desired.push(encoded_timestamp(MESSAGE_SNOOZE_PREFIX, until));
        }
        if muted {
            desired.push(MUTE.to_owned());
        }
        match priority.as_str() {
            "low" => desired.push(PRIORITY_LOW.to_owned()),
            "high" => desired.push(PRIORITY_HIGH.to_owned()),
            _ => {}
        }
        stage_message_instances_on(connection, message_id, canonical_keywords(desired), now)
            .await?;
    }
    Ok(())
}

pub(crate) async fn stage_message_on(
    connection: &Connection,
    message_id: MessageId,
    now: i64,
) -> Result<()> {
    let mut rows = connection
        .query(
            "SELECT thread_id FROM messages WHERE id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let thread_id = rows
        .next()
        .await?
        .map(|row| row.get::<Option<String>>(0))
        .transpose()?
        .flatten()
        .map(parse_thread_id)
        .transpose()?;
    drop(rows);
    if let Some(thread_id) = thread_id {
        stage_thread_on(connection, thread_id, now).await?;
    }
    Ok(())
}

async fn stage_message_instances_on(
    connection: &Connection,
    message_id: MessageId,
    desired: Vec<String>,
    now: i64,
) -> Result<()> {
    let mut rows = connection
        .query(
            r#"SELECT mi.folder_id, mi.uid_validity, mi.imap_uid,
                ims.custom_keywords_supported
            FROM message_instances mi
            JOIN imap_mailbox_state ims ON ims.folder_id = mi.folder_id
            WHERE mi.message_id = ?1
            ORDER BY mi.folder_id, mi.uid_validity, mi.imap_uid"#,
            (message_id.to_string(),),
        )
        .await?;
    let mut instances = Vec::new();
    while let Some(row) = rows.next().await? {
        instances.push((
            parse_folder_id(row.get(0)?)?,
            row.get::<i64>(1)?,
            row.get::<i64>(2)?,
            row.get::<Option<bool>>(3)?,
        ));
    }
    drop(rows);
    let desired_json = serde_json::to_string(&desired)?;
    for (folder_id, uid_validity, uid, supported) in instances {
        if supported == Some(false) {
            connection
                .execute(
                    "DELETE FROM portable_keyword_projection WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
                    (folder_id.to_string(), uid_validity, uid),
                )
                .await?;
            continue;
        }
        connection
            .execute(
                r#"INSERT INTO portable_keyword_projection(
                    message_id, folder_id, uid_validity, imap_uid,
                    desired_keywords_json, mutation_id, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)
                ON CONFLICT(folder_id, uid_validity, imap_uid) DO UPDATE SET
                    message_id = excluded.message_id,
                    desired_keywords_json = excluded.desired_keywords_json,
                    mutation_id = NULL,
                    updated_at = excluded.updated_at"#,
                turso::params![
                    message_id.to_string(),
                    folder_id.to_string(),
                    uid_validity,
                    uid,
                    desired_json.clone(),
                    now,
                ],
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn reconcile_remote_on(
    connection: &Connection,
    message_id: MessageId,
    now: i64,
) -> Result<Option<crate::BackendEvent>> {
    let mut thread_rows = connection
        .query(
            "SELECT thread_id FROM messages WHERE id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let thread_id = thread_rows
        .next()
        .await?
        .map(|row| row.get::<Option<String>>(0))
        .transpose()?
        .flatten()
        .map(parse_thread_id)
        .transpose()?;
    drop(thread_rows);
    let Some(thread_id) = thread_id else {
        return Ok(None);
    };
    let mut pending = connection
        .query(
            r#"SELECT 1 FROM portable_keyword_projection p
            JOIN messages m ON m.id = p.message_id
            WHERE m.thread_id = ?1 LIMIT 1"#,
            (thread_id.to_string(),),
        )
        .await?;
    if pending.next().await?.is_some() {
        return Ok(None);
    }
    drop(pending);

    import_message_state_on(connection, message_id).await?;
    let changed = import_thread_state_on(connection, thread_id, now).await?;
    if !changed {
        return Ok(None);
    }
    Ok(Some(
        insert_event(
            connection,
            now,
            "portable_organization_imported",
            thread_id.to_string(),
            json!({"thread_id": thread_id, "message_id": message_id}),
        )
        .await?,
    ))
}

/// Import portable state only after the selected mailbox has positively
/// advertised permanent custom keywords. This ordering is essential during a
/// first synchronization: local defaults must never overwrite state written
/// by another Lizard installation before the remote state has been read.
pub(crate) async fn reconcile_ingested_on(
    connection: &Connection,
    message_id: MessageId,
    folder_id: FolderId,
    now: i64,
) -> Result<Option<crate::BackendEvent>> {
    let mut rows = connection
        .query(
            "SELECT custom_keywords_supported FROM imap_mailbox_state WHERE folder_id = ?1",
            (folder_id.to_string(),),
        )
        .await?;
    let supported = rows
        .next()
        .await?
        .map(|row| row.get::<Option<bool>>(0))
        .transpose()?
        .flatten();
    drop(rows);
    if supported != Some(true) {
        return Ok(None);
    }
    let event = reconcile_remote_on(connection, message_id, now).await?;
    let mut thread_rows = connection
        .query(
            "SELECT thread_id FROM messages WHERE id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let thread_id = thread_rows
        .next()
        .await?
        .map(|row| row.get::<Option<String>>(0))
        .transpose()?
        .flatten()
        .map(parse_thread_id)
        .transpose()?;
    drop(thread_rows);
    if let Some(thread_id) = thread_id {
        if !remote_thread_keywords_conflict_on(connection, thread_id).await? {
            stage_thread_on(connection, thread_id, now).await?;
        }
    }
    Ok(event)
}

async fn import_message_state_on(connection: &Connection, message_id: MessageId) -> Result<()> {
    let keyword_sets = supported_keyword_sets_on(connection, message_id).await?;
    if keyword_sets.is_empty() {
        return Ok(());
    }
    let all = keyword_sets.into_iter().flatten().collect::<HashSet<_>>();
    let muted = has_keyword(&all, MUTE);
    let priorities = [(PRIORITY_LOW, "low"), (PRIORITY_HIGH, "high")]
        .into_iter()
        .filter_map(|(keyword, value)| has_keyword(&all, keyword).then_some(value))
        .collect::<Vec<_>>();
    let message_snoozes = all
        .iter()
        .filter_map(|value| parse_timestamp(value, MESSAGE_SNOOZE_PREFIX))
        .collect::<BTreeSet<_>>();
    if priorities.len() <= 1 && message_snoozes.len() <= 1 {
        connection
            .execute(
                "UPDATE messages SET muted = ?1, priority = ?2, snoozed_until = ?3 WHERE id = ?4",
                turso::params![
                    muted,
                    priorities.first().copied().unwrap_or("normal"),
                    message_snoozes.first().copied(),
                    message_id.to_string(),
                ],
            )
            .await?;
    }
    Ok(())
}

async fn import_thread_state_on(
    connection: &Connection,
    thread_id: ThreadId,
    now: i64,
) -> Result<bool> {
    let mut rows = connection
        .query(
            r#"SELECT m.id
            FROM messages m
            WHERE m.thread_id = ?1
              AND m.from_address IS NOT NULL AND trim(m.from_address) != ''
              AND NOT EXISTS (
                  SELECT 1 FROM account_identities ai
                  WHERE ai.email_address = m.from_address COLLATE NOCASE
              )
              AND EXISTS (
                  SELECT 1 FROM message_instances mi
                  JOIN imap_mailbox_state ims ON ims.folder_id = mi.folder_id
                  WHERE mi.message_id = m.id AND ims.custom_keywords_supported = 1
              )
            ORDER BY m.received_at, m.id"#,
            (thread_id.to_string(),),
        )
        .await?;
    let mut message_ids = Vec::new();
    while let Some(row) = rows.next().await? {
        message_ids.push(parse_message_id(row.get(0)?)?);
    }
    drop(rows);
    if message_ids.is_empty() {
        return Ok(false);
    }
    if remote_thread_keywords_conflict_on(connection, thread_id).await? {
        return Ok(false);
    }
    let mut per_message = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        per_message.push(
            supported_keyword_sets_on(connection, message_id)
                .await?
                .into_iter()
                .flatten()
                .collect::<HashSet<_>>(),
        );
    }

    let done = per_message.iter().all(|values| has_keyword(values, DONE));
    let waiting = per_message
        .iter()
        .all(|values| has_keyword(values, WAITING));
    let snoozes = per_message
        .iter()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| parse_timestamp(value, THREAD_SNOOZE_PREFIX))
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    let shared_snooze = snoozes
        .first()
        .filter(|first| first.len() == 1 && snoozes.iter().all(|values| values == *first))
        .and_then(|values| values.first().copied());
    let completed_states =
        usize::from(done) + usize::from(waiting) + usize::from(shared_snooze.is_some());
    if completed_states > 1 {
        return Ok(false);
    }
    let (status, snoozed_until) = if done {
        ("done", None)
    } else if waiting {
        ("waiting", None)
    } else if let Some(until) = shared_snooze {
        ("snoozed", Some(until))
    } else {
        ("active", None)
    };

    let routes = per_message
        .iter()
        .flat_map(|values| {
            [
                has_keyword(values, ROUTE_ACTION).then_some("action"),
                has_keyword(values, ROUTE_FYI).then_some("fyi"),
            ]
            .into_iter()
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    let mut known_rows = connection
        .query(
            r#"SELECT 1 FROM messages m JOIN contact_addresses ca
            ON ca.address = m.from_address COLLATE NOCASE
            WHERE m.thread_id = ?1 LIMIT 1"#,
            (thread_id.to_string(),),
        )
        .await?;
    let known_sender = known_rows.next().await?.is_some();
    drop(known_rows);

    let mut existing_rows = connection
        .query(
            "SELECT actionable_once, route_override, route_override_source, route_override_rule_id FROM thread_work_state WHERE thread_id = ?1",
            (thread_id.to_string(),),
        )
        .await?;
    let existing = existing_rows
        .next()
        .await?
        .map(|row| {
            Ok::<_, BackendError>((
                row.get::<bool>(0)?,
                row.get::<Option<String>>(1)?,
                row.get::<Option<String>>(2)?,
                row.get::<Option<String>>(3)?,
            ))
        })
        .transpose()?
        .unwrap_or((false, None, None, None));
    drop(existing_rows);
    let (route, route_source, route_rule) = if routes.len() == 1 && known_sender {
        (
            routes.first().map(|value| (*value).to_owned()),
            Some("manual".to_owned()),
            None,
        )
    } else if routes.is_empty() && existing.2.as_deref() == Some("manual") {
        (None, None, None)
    } else {
        (existing.1, existing.2, existing.3)
    };
    connection
        .execute(
            r#"INSERT INTO thread_work_state(
                thread_id, status, snoozed_until, actionable_once,
                route_override, route_override_source, route_override_rule_id, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(thread_id) DO UPDATE SET
                status = excluded.status,
                snoozed_until = excluded.snoozed_until,
                route_override = excluded.route_override,
                route_override_source = excluded.route_override_source,
                route_override_rule_id = excluded.route_override_rule_id,
                updated_at = excluded.updated_at"#,
            turso::params![
                thread_id.to_string(),
                status,
                snoozed_until,
                existing.0,
                route,
                route_source,
                route_rule,
                now,
            ],
        )
        .await?;
    Ok(true)
}

async fn supported_keyword_sets_on(
    connection: &Connection,
    message_id: MessageId,
) -> Result<Vec<HashSet<String>>> {
    let mut rows = connection
        .query(
            r#"SELECT mi.flags_json FROM message_instances mi
            JOIN imap_mailbox_state ims ON ims.folder_id = mi.folder_id
            WHERE mi.message_id = ?1 AND ims.custom_keywords_supported = 1
            ORDER BY mi.folder_id, mi.uid_validity, mi.imap_uid"#,
            (message_id.to_string(),),
        )
        .await?;
    let mut values = Vec::new();
    while let Some(row) = rows.next().await? {
        let flags: Vec<String> = serde_json::from_str(&row.get::<String>(0)?)?;
        values.push(
            flags
                .into_iter()
                .filter(|flag| is_portable_keyword(flag))
                .collect(),
        );
    }
    Ok(values)
}

pub(crate) async fn reconcile_folder(backend: &Backend, folder_id: FolderId) -> Result<()> {
    let message_ids = {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT DISTINCT message_id FROM message_instances WHERE folder_id = ?1 ORDER BY message_id",
                (folder_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(parse_message_id(row.get(0)?)?);
        }
        values
    };
    let now = chrono::Utc::now().timestamp();
    let mut touched_threads = HashSet::new();
    let mut connection = backend.inner.connection.lock().await;
    let transaction = connection.transaction().await?;
    let mut events = Vec::new();
    for message_id in message_ids {
        if let Some(event) = reconcile_remote_on(&transaction, message_id, now).await? {
            events.push(event);
        }
        let mut rows = transaction
            .query(
                "SELECT thread_id FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        if let Some(row) = rows.next().await? {
            if let Some(value) = row.get::<Option<String>>(0)? {
                touched_threads.insert(parse_thread_id(value)?);
            }
        }
    }
    for thread_id in touched_threads {
        if !remote_thread_keywords_conflict_on(&transaction, thread_id).await? {
            stage_thread_on(&transaction, thread_id, now).await?;
        }
    }
    transaction.commit().await?;
    drop(connection);
    for event in events {
        let _ = backend.inner.events.send(event);
    }
    Ok(())
}

/// Conflicting single-valued remote fields are never resolved by choosing a
/// convenient value or by immediately overwriting the server with a local
/// default. They remain inert until a later coherent observation or an
/// explicit local edit establishes the desired value.
async fn remote_thread_keywords_conflict_on(
    connection: &Connection,
    thread_id: ThreadId,
) -> Result<bool> {
    let mut rows = connection
        .query(
            r#"SELECT m.id,
                m.from_address IS NOT NULL AND trim(m.from_address) != '' AND NOT EXISTS (
                    SELECT 1 FROM account_identities ai
                    WHERE ai.email_address = m.from_address COLLATE NOCASE
                ),
                mi.flags_json
            FROM messages m
            JOIN message_instances mi ON mi.message_id = m.id
            JOIN imap_mailbox_state ims ON ims.folder_id = mi.folder_id
            WHERE m.thread_id = ?1 AND ims.custom_keywords_supported = 1
            ORDER BY m.id, mi.folder_id, mi.uid_validity, mi.imap_uid"#,
            (thread_id.to_string(),),
        )
        .await?;
    let mut messages: BTreeMap<MessageId, (bool, HashSet<String>)> = BTreeMap::new();
    while let Some(row) = rows.next().await? {
        let id = parse_message_id(row.get(0)?)?;
        let inbound = row.get::<bool>(1)?;
        let flags: Vec<String> = serde_json::from_str(&row.get::<String>(2)?)?;
        let entry = messages
            .entry(id)
            .or_insert_with(|| (inbound, HashSet::new()));
        entry.0 |= inbound;
        entry
            .1
            .extend(flags.into_iter().filter(|flag| is_portable_keyword(flag)));
    }
    let inbound = messages
        .values()
        .filter(|(inbound, _)| *inbound)
        .map(|(_, flags)| flags)
        .collect::<Vec<_>>();
    for (_, flags) in messages.values() {
        let priorities = usize::from(has_keyword(flags, PRIORITY_LOW))
            + usize::from(has_keyword(flags, PRIORITY_HIGH));
        let message_snoozes = flags
            .iter()
            .filter_map(|flag| parse_timestamp(flag, MESSAGE_SNOOZE_PREFIX))
            .collect::<BTreeSet<_>>();
        if priorities > 1 || message_snoozes.len() > 1 {
            return Ok(true);
        }
    }
    for flags in &inbound {
        let thread_snoozes = flags
            .iter()
            .filter_map(|flag| parse_timestamp(flag, THREAD_SNOOZE_PREFIX))
            .collect::<BTreeSet<_>>();
        let statuses = usize::from(has_keyword(flags, DONE))
            + usize::from(has_keyword(flags, WAITING))
            + thread_snoozes.len();
        let routes = usize::from(has_keyword(flags, ROUTE_ACTION))
            + usize::from(has_keyword(flags, ROUTE_FYI));
        if statuses > 1 || routes > 1 {
            return Ok(true);
        }
    }
    if inbound.is_empty() {
        return Ok(false);
    }
    let all_done = inbound.iter().all(|flags| has_keyword(flags, DONE));
    let all_waiting = inbound.iter().all(|flags| has_keyword(flags, WAITING));
    let snoozes = inbound
        .iter()
        .map(|flags| {
            flags
                .iter()
                .filter_map(|flag| parse_timestamp(flag, THREAD_SNOOZE_PREFIX))
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    let shared_snooze = snoozes
        .first()
        .is_some_and(|first| first.len() == 1 && snoozes.iter().all(|values| values == first));
    if usize::from(all_done) + usize::from(all_waiting) + usize::from(shared_snooze) > 1 {
        return Ok(true);
    }
    let routes = inbound
        .iter()
        .flat_map(|flags| {
            [
                has_keyword(flags, ROUTE_ACTION).then_some(ROUTE_ACTION),
                has_keyword(flags, ROUTE_FYI).then_some(ROUTE_FYI),
            ]
            .into_iter()
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    Ok(routes.len() > 1)
}

pub(crate) async fn materialize_projections(
    backend: &Backend,
    account_id: AccountId,
    limit: usize,
) -> Result<usize> {
    let rows = {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT p.message_id, p.folder_id, p.uid_validity, p.imap_uid,
                    p.desired_keywords_json, p.mutation_id,
                    ims.custom_keywords_supported, mi.mod_sequence, mi.flags_json,
                    pm.status
                FROM portable_keyword_projection p
                JOIN folders f ON f.id = p.folder_id
                JOIN imap_mailbox_state ims ON ims.folder_id = p.folder_id
                JOIN message_instances mi ON mi.folder_id = p.folder_id
                    AND mi.uid_validity = p.uid_validity AND mi.imap_uid = p.imap_uid
                LEFT JOIN imap_mutations pm ON pm.id = p.mutation_id
                WHERE f.account_id = ?1
                ORDER BY CASE
                    WHEN p.mutation_id IS NULL THEN 0
                    WHEN pm.status IN ('applied', 'cancelled') THEN 1
                    ELSE 2
                END, p.updated_at, p.folder_id, p.imap_uid
                LIMIT ?2"#,
                (
                    account_id.to_string(),
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(ProjectionRow {
                message_id: parse_message_id(row.get(0)?)?,
                folder_id: parse_folder_id(row.get(1)?)?,
                uid_validity: u32::try_from(row.get::<i64>(2)?).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid UIDVALIDITY".into())
                })?,
                uid: u32::try_from(row.get::<i64>(3)?).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid IMAP UID".into())
                })?,
                desired: serde_json::from_str(&row.get::<String>(4)?)?,
                mutation_id: row.get::<Option<String>>(5)?,
                supported: row.get::<Option<bool>>(6)?,
                mod_sequence: row.get::<Option<i64>>(7)?.map(|value| value as u64),
                flags: serde_json::from_str(&row.get::<String>(8)?)?,
                mutation_status: row.get::<Option<String>>(9)?,
            });
        }
        values
    };
    let mut queued = 0;
    for row in rows {
        if row.supported == Some(false) {
            delete_projection(backend, &row).await?;
            continue;
        }
        if row.supported.is_none() {
            continue;
        }
        match row.mutation_status.as_deref() {
            Some("pending" | "in_flight" | "conflict") => continue,
            Some("applied") => {
                delete_projection(backend, &row).await?;
                continue;
            }
            Some("cancelled") => {
                accept_remote_projection(backend, &row).await?;
                continue;
            }
            Some(_) => continue,
            None if row.mutation_id.is_some() => continue,
            None => {}
        }
        let desired = canonical_keywords(row.desired.clone());
        let observed = canonical_keywords(row.flags.clone());
        if observed == desired {
            delete_projection(backend, &row).await?;
            continue;
        }
        let mut target = row
            .flags
            .iter()
            .filter(|flag| !is_portable_keyword(flag))
            .cloned()
            .collect::<Vec<_>>();
        target.extend(desired);
        let source = RemoteMessageIdentity {
            account_id,
            folder_id: row.folder_id,
            uid_validity: row.uid_validity,
            uid: row.uid,
            mod_sequence: row.mod_sequence,
            flags: row.flags.clone(),
        };
        let mutation = match backend
            .imap_mutations()
            .set_flags_exact(row.message_id, source, target)
            .await
        {
            Ok(mutation) => mutation,
            Err(BackendError::Conflict(_)) => continue,
            Err(error) => return Err(error),
        };
        let connection = backend.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE portable_keyword_projection SET mutation_id = ?1, updated_at = ?2 WHERE folder_id = ?3 AND uid_validity = ?4 AND imap_uid = ?5",
                turso::params![
                    mutation.id.to_string(),
                    chrono::Utc::now().timestamp(),
                    row.folder_id.to_string(),
                    i64::from(row.uid_validity),
                    i64::from(row.uid),
                ],
            )
            .await?;
        queued += 1;
    }
    Ok(queued)
}

struct ProjectionRow {
    message_id: MessageId,
    folder_id: FolderId,
    uid_validity: u32,
    uid: u32,
    desired: Vec<String>,
    mutation_id: Option<String>,
    supported: Option<bool>,
    mod_sequence: Option<u64>,
    flags: Vec<String>,
    mutation_status: Option<String>,
}

async fn delete_projection(backend: &Backend, row: &ProjectionRow) -> Result<()> {
    let connection = backend.inner.connection.lock().await;
    connection
        .execute(
            "DELETE FROM portable_keyword_projection WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
            (
                row.folder_id.to_string(),
                i64::from(row.uid_validity),
                i64::from(row.uid),
            ),
        )
        .await?;
    Ok(())
}

async fn accept_remote_projection(backend: &Backend, row: &ProjectionRow) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let mut connection = backend.inner.connection.lock().await;
    let transaction = connection.transaction().await?;
    transaction
        .execute(
            "DELETE FROM portable_keyword_projection WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
            (
                row.folder_id.to_string(),
                i64::from(row.uid_validity),
                i64::from(row.uid),
            ),
        )
        .await?;
    let event = reconcile_remote_on(&transaction, row.message_id, now).await?;
    transaction.commit().await?;
    drop(connection);
    if let Some(event) = event {
        let _ = backend.inner.events.send(event);
    }
    Ok(())
}

fn parse_message_id(value: String) -> Result<MessageId> {
    MessageId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid message ID".into()))
}

fn parse_folder_id(value: String) -> Result<FolderId> {
    FolderId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid folder ID".into()))
}

fn parse_thread_id(value: String) -> Result<ThreadId> {
    ThreadId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid thread ID".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountKind, BackendConfig, FolderKind, ImapMutationOperation, ImapSecurity, ImapSettings,
        IngestMessage, MessagePriority, NewAccount, NewFolder, RemoteMessageIdentity,
        ThreadWorkStatus,
    };

    #[test]
    fn private_keywords_are_bounded_ascii_atoms() {
        for value in [
            DONE,
            WAITING,
            MUTE,
            PRIORITY_LOW,
            PRIORITY_HIGH,
            ROUTE_ACTION,
            ROUTE_FYI,
            &encoded_timestamp(THREAD_SNOOZE_PREFIX, 1_900_000_000),
        ] {
            assert!(value.is_ascii());
            assert!(value.len() < 64);
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'$'));
        }
    }

    #[tokio::test]
    async fn done_round_trips_and_an_untagged_new_reply_reopens_the_thread() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let account = backend
            .accounts()
            .add(NewAccount {
                name: "Portable state".into(),
                kind: AccountKind::Imap,
                credential_ref: Some("test:portable-state".into()),
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        let folder = backend
            .folders()
            .add(NewFolder {
                account_id: Some(account.id),
                name: "Inbox".into(),
                kind: FolderKind::Remote,
                remote_name: Some("INBOX".into()),
            })
            .await
            .unwrap();
        {
            let connection = backend.inner.connection.lock().await;
            connection
                .execute(
                    r#"INSERT INTO imap_mailbox_state(
                        folder_id, permanent_flags_json, custom_keywords_supported
                    ) VALUES (?1, '["\\*"]', 1)
                    ON CONFLICT(folder_id) DO UPDATE SET
                        permanent_flags_json = excluded.permanent_flags_json,
                        custom_keywords_supported = excluded.custom_keywords_supported"#,
                    (folder.id.to_string(),),
                )
                .await
                .unwrap();
        }

        let first = backend
            .ingest(IngestMessage {
                raw: b"From: Ada <ada@example.test>\r\nTo: reader@example.test\r\nMessage-ID: <portable-one@example.test>\r\nSubject: Portable task\r\n\r\nFirst.\r\n".to_vec(),
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: folder.id,
                    uid_validity: 7,
                    uid: 1,
                    mod_sequence: Some(1),
                    flags: Vec::new(),
                }),
                received_at: Some(1_700_000_001),
                user_classification: None,
            })
            .await
            .unwrap();
        let thread_id = backend
            .messages()
            .get(first)
            .await
            .unwrap()
            .summary
            .thread_id;
        backend
            .threads()
            .set_work_state(thread_id, ThreadWorkStatus::Done, None)
            .await
            .unwrap();
        assert_eq!(
            materialize_projections(&backend, account.id, 50)
                .await
                .unwrap(),
            1
        );
        let mutation = backend
            .imap_mutations()
            .list(Some(account.id))
            .await
            .unwrap()
            .pop()
            .unwrap();
        let ImapMutationOperation::SetFlags { flags } = &mutation.operation else {
            panic!("portable state must be projected as IMAP flags")
        };
        assert!(flags.iter().any(|flag| flag == DONE));

        // Simulate a successful STORE so the projection no longer shields
        // imported state from concurrent remote changes.
        {
            let connection = backend.inner.connection.lock().await;
            connection
                .execute(
                    "UPDATE imap_mutations SET status = 'applied', completed_at = 1 WHERE id = ?1",
                    (mutation.id.to_string(),),
                )
                .await
                .unwrap();
        }
        materialize_projections(&backend, account.id, 50)
            .await
            .unwrap();

        backend
            .ingest(IngestMessage {
                raw: b"From: Ada <ada@example.test>\r\nTo: reader@example.test\r\nMessage-ID: <portable-two@example.test>\r\nIn-Reply-To: <portable-one@example.test>\r\nReferences: <portable-one@example.test>\r\nSubject: Re: Portable task\r\n\r\nA new obligation.\r\n".to_vec(),
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: folder.id,
                    uid_validity: 7,
                    uid: 2,
                    mod_sequence: Some(2),
                    flags: Vec::new(),
                }),
                received_at: Some(1_700_000_002),
                user_classification: None,
            })
            .await
            .unwrap();
        assert_eq!(
            backend
                .threads()
                .work_state(thread_id)
                .await
                .unwrap()
                .status,
            ThreadWorkStatus::Active
        );
    }

    #[tokio::test]
    async fn remote_keywords_cannot_establish_trust_or_actionable_once() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let account = backend
            .accounts()
            .add(NewAccount {
                name: "Hostile keywords".into(),
                kind: AccountKind::Imap,
                credential_ref: Some("test:hostile-keywords".into()),
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        let folder = backend
            .folders()
            .add(NewFolder {
                account_id: Some(account.id),
                name: "Inbox".into(),
                kind: FolderKind::Remote,
                remote_name: Some("INBOX".into()),
            })
            .await
            .unwrap();
        {
            let connection = backend.inner.connection.lock().await;
            connection
                .execute(
                    r#"INSERT INTO imap_mailbox_state(folder_id, custom_keywords_supported)
                    VALUES (?1, 1)
                    ON CONFLICT(folder_id) DO UPDATE SET
                        custom_keywords_supported = excluded.custom_keywords_supported"#,
                    (folder.id.to_string(),),
                )
                .await
                .unwrap();
        }
        let message_id = backend
            .ingest(IngestMessage {
                raw: b"From: Stranger <stranger@example.test>\r\nTo: reader@example.test\r\nMessage-ID: <hostile-keyword@example.test>\r\nSubject: Let me into Action\r\n\r\nNo.\r\n".to_vec(),
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: folder.id,
                    uid_validity: 9,
                    uid: 1,
                    mod_sequence: None,
                    flags: vec![
                        ROUTE_ACTION.into(),
                        ROUTE_FYI.into(),
                        "$LizardV1ActionableOnce".into(),
                    ],
                }),
                received_at: Some(1_700_000_001),
                user_classification: None,
            })
            .await
            .unwrap();
        let thread_id = backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .summary
            .thread_id;
        let state = backend.threads().work_state(thread_id).await.unwrap();
        assert!(!state.actionable_once);
        assert_eq!(state.route_override, None);

        backend
            .threads()
            .set_actionable_once(thread_id, true)
            .await
            .unwrap();
        backend
            .messages()
            .set_priority(message_id, MessagePriority::High)
            .await
            .unwrap();
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT desired_keywords_json FROM portable_keyword_projection WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await
            .unwrap();
        let desired: Vec<String> = serde_json::from_str(
            &rows
                .next()
                .await
                .unwrap()
                .unwrap()
                .get::<String>(0)
                .unwrap(),
        )
        .unwrap();
        assert!(desired.iter().any(|keyword| keyword == PRIORITY_HIGH));
        assert!(!desired.iter().any(|keyword| keyword == ROUTE_ACTION));
        assert!(!desired.iter().any(|keyword| keyword.contains("Actionable")));
    }
}
