use crate::backend::insert_event;
use crate::{
    Backend, BackendError, MessageId, Result, RouteOverrideSource, SimilarityMatch,
    SimilarityPreview, SimilarityRule, SimilarityRuleApplication, SimilarityRuleId, ThreadId,
    WarmRoute,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use turso::{params_from_iter, Value};

const MIN_CUTOFF_MILLIS: u16 = 100;
const MAX_CUTOFF_MILLIS: u16 = 1_000;
const MAX_PROFILE_SUBJECT_BYTES: usize = 2 * 1024;
const MAX_PROFILE_BODY_BYTES: usize = 64 * 1024;
const MAX_RULE_MATCHES: usize = 5_000;
const MESSAGE_BATCH: usize = 100;

#[derive(Clone)]
pub struct SimilarityRules(Backend);

#[derive(Clone)]
struct RuleProfile {
    rule: SimilarityRule,
    subject: Option<String>,
    body_text: String,
}

impl SimilarityRules {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    /// Preview the exact sender-scoped set a lexical workflow rule would
    /// affect. This never mutates mail, contacts, relationships or work state.
    pub async fn preview(
        &self,
        seed_message_id: MessageId,
        route: WarmRoute,
        cutoff_millis: u16,
        sample_limit: usize,
    ) -> Result<SimilarityPreview> {
        validate_cutoff(cutoff_millis)?;
        let profile = self.profile_from_message(seed_message_id).await?;
        let ranked = self.rank_profile(&profile, cutoff_millis).await?;
        let match_set_digest = match_set_digest(&ranked);
        let truncated = ranked.len() > MAX_RULE_MATCHES;
        let ranked = ranked
            .into_iter()
            .take(MAX_RULE_MATCHES)
            .collect::<Vec<_>>();
        let message_threads = self.message_threads(&ranked).await?;
        let thread_ids = message_threads.values().copied().collect::<HashSet<_>>();
        let route_states = self.route_states(&thread_ids).await?;
        let affected = thread_ids
            .iter()
            .filter(|thread_id| {
                route_states
                    .get(thread_id)
                    .is_some_and(|state| state.rule_can_move_to(route))
            })
            .count() as u64;

        let sample_ids = ranked
            .iter()
            .take(sample_limit.clamp(1, MAX_RULE_MATCHES))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let messages = self.0.messages().summaries_many(&sample_ids).await?;
        let scores = ranked.iter().copied().collect::<HashMap<_, _>>();
        let matches = messages
            .into_iter()
            .map(|message| {
                let thread_id = message.thread_id;
                Ok(SimilarityMatch {
                    relative_score_millis: *scores.get(&message.id).ok_or_else(|| {
                        BackendError::SearchIndex(
                            "similar-mail preview lost a ranked message".into(),
                        )
                    })?,
                    would_move: route_states
                        .get(&thread_id)
                        .is_some_and(|state| state.rule_can_move_to(route)),
                    message,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(SimilarityPreview {
            seed_message_id,
            sender_address: profile.rule.sender_address,
            route,
            cutoff_millis,
            matches,
            matching_messages: ranked.len() as u64,
            affected_threads: affected,
            truncated,
            match_set_digest,
        })
    }

    /// Persist exactly the match set represented by a prior preview. If mail
    /// or the search projection changed in the meantime, the caller must show
    /// a fresh preview rather than applying unseen matches.
    pub async fn create_from_preview(
        &self,
        preview: &SimilarityPreview,
    ) -> Result<SimilarityRuleApplication> {
        validate_cutoff(preview.cutoff_millis)?;
        // Keep the projection stable from verification through the metadata
        // transaction. Writers take the exclusive half of this same lock.
        let _search_guard = self.0.inner.search_sync.read().await;
        let mut profile = self.profile_from_message(preview.seed_message_id).await?;
        profile.rule.route = preview.route;
        profile.rule.cutoff_millis = preview.cutoff_millis;
        if profile.rule.sender_address != preview.sender_address {
            return Err(BackendError::InvalidInput(
                "the seed sender changed after preview; review the rule again".into(),
            ));
        }
        let ranked = self
            .rank_profile_locked(&profile, preview.cutoff_millis)
            .await?;
        if ranked.len() > MAX_RULE_MATCHES {
            return Err(BackendError::InvalidInput(format!(
                "similar-mail rule matches more than the {MAX_RULE_MATCHES}-message safety limit; choose a stricter cutoff"
            )));
        }
        if preview.truncated
            || preview.matching_messages != ranked.len() as u64
            || preview.match_set_digest != match_set_digest(&ranked)
        {
            return Err(BackendError::InvalidInput(
                "the similar-mail match set changed after preview; review the updated list before saving"
                    .into(),
            ));
        }
        let message_threads = self.message_threads(&ranked).await?;
        let thread_ids = message_threads.values().copied().collect::<HashSet<_>>();
        let route_states = self.route_states(&thread_ids).await?;
        let affected_threads = thread_ids
            .iter()
            .filter(|thread_id| {
                route_states
                    .get(thread_id)
                    .is_some_and(|state| state.rule_can_move_to(preview.route))
            })
            .count() as u64;
        let now = Utc::now().timestamp();
        profile.rule.created_at = now;
        profile.rule.updated_at = now;
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                r#"INSERT INTO workflow_similarity_rules(
                    id, name, sender_address, seed_message_id, route,
                    profile_subject, profile_body_text, cutoff_millis,
                    enabled, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?9)"#,
                turso::params![
                    profile.rule.id.to_string(),
                    profile.rule.name.clone(),
                    profile.rule.sender_address.clone(),
                    preview.seed_message_id.to_string(),
                    route_text(preview.route),
                    profile.subject,
                    profile.body_text,
                    i64::from(preview.cutoff_millis),
                    now,
                ],
            )
            .await?;
        apply_rule_to_threads_on(
            &transaction,
            profile.rule.id,
            preview.route,
            &thread_ids,
            now,
        )
        .await?;
        let event = insert_event(
            &transaction,
            now,
            "workflow_similarity_rule_created",
            profile.rule.id.to_string(),
            serde_json::json!({
                "rule_id": profile.rule.id,
                "seed_message_id": preview.seed_message_id,
                "sender_address": profile.rule.sender_address.clone(),
                "route": preview.route,
                "cutoff_millis": preview.cutoff_millis,
                "matching_messages": ranked.len(),
                "affected_threads": affected_threads,
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(SimilarityRuleApplication {
            rule: profile.rule,
            matching_messages: ranked.len() as u64,
            affected_threads,
        })
    }

    pub async fn list(&self) -> Result<Vec<SimilarityRule>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, sender_address, seed_message_id, route, cutoff_millis, enabled, created_at, updated_at FROM workflow_similarity_rules ORDER BY updated_at DESC, id",
                (),
            )
            .await?;
        let mut rules = Vec::new();
        while let Some(row) = rows.next().await? {
            rules.push(rule_from_row(&row)?);
        }
        Ok(rules)
    }

    /// Removing a rule undoes only overrides still owned by that rule. Manual
    /// corrections and overrides subsequently written by another rule remain.
    pub async fn remove(&self, id: SimilarityRuleId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE thread_work_state SET route_override = NULL, route_override_source = NULL, route_override_rule_id = NULL, updated_at = ?1 WHERE route_override_source = 'similarity_rule' AND route_override_rule_id = ?2",
                (now, id.to_string()),
            )
            .await?;
        if transaction
            .execute(
                "DELETE FROM workflow_similarity_rules WHERE id = ?1",
                (id.to_string(),),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "workflow similarity rule",
                id: id.to_string(),
            });
        }
        let event = insert_event(
            &transaction,
            now,
            "workflow_similarity_rule_removed",
            id.to_string(),
            serde_json::json!({"rule_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub(crate) async fn has_enabled(&self) -> Result<bool> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM workflow_similarity_rules WHERE enabled = 1 LIMIT 1",
                (),
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    /// Evaluate only newly ingested or newly completed messages. Corpus score
    /// drift never causes unrelated old conversations to move in the
    /// background; retroactive application happens only on user confirmation.
    pub(crate) async fn evaluate_messages(&self, message_ids: &[MessageId]) -> Result<()> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let wanted = message_ids.iter().copied().collect::<HashSet<_>>();
        let profiles = self.enabled_profiles_for_messages(message_ids).await?;
        for profile in profiles {
            let ranked = self
                .rank_profile(&profile, profile.rule.cutoff_millis)
                .await?;
            let relevant = ranked
                .into_iter()
                .filter(|(message_id, _)| wanted.contains(message_id))
                .collect::<Vec<_>>();
            if relevant.is_empty() {
                continue;
            }
            let threads = self
                .message_threads(&relevant)
                .await?
                .into_values()
                .collect::<HashSet<_>>();
            let now = Utc::now().timestamp();
            let mut connection = self.0.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            apply_rule_to_threads_on(
                &transaction,
                profile.rule.id,
                profile.rule.route,
                &threads,
                now,
            )
            .await?;
            let event = insert_event(
                &transaction,
                now,
                "workflow_similarity_rule_applied",
                profile.rule.id.to_string(),
                serde_json::json!({
                    "rule_id": profile.rule.id,
                    "message_ids": relevant.iter().map(|(id, _)| id).collect::<Vec<_>>(),
                    "thread_ids": threads,
                    "route": profile.rule.route,
                }),
            )
            .await?;
            transaction.commit().await?;
            drop(connection);
            let _ = self.0.inner.events.send(event);
        }
        Ok(())
    }

    async fn profile_from_message(&self, message_id: MessageId) -> Result<RuleProfile> {
        let message = self.0.messages().get(message_id).await?;
        let sender_address = message
            .summary
            .from_address
            .as_deref()
            .map(normalize_address)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                BackendError::InvalidInput(
                    "similar-mail rules require one unambiguous sender address".into(),
                )
            })?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM contact_addresses WHERE lower(address) = ?1 LIMIT 1",
                (sender_address.clone(),),
            )
            .await?;
        if rows.next().await?.is_none() {
            return Err(BackendError::InvalidInput(
                "similar Action/FYI routing requires a known contact; use Make Actionable Once for Cold mail"
                    .into(),
            ));
        }
        let subject = message
            .summary
            .subject
            .as_deref()
            .map(|value| bounded_text(value, MAX_PROFILE_SUBJECT_BYTES))
            .filter(|value| !value.trim().is_empty());
        let body_text = bounded_text(&message.body_text, MAX_PROFILE_BODY_BYTES);
        if subject.is_none() && body_text.trim().is_empty() {
            return Err(BackendError::InvalidInput(
                "similar-mail rules require a subject or searchable message body".into(),
            ));
        }
        let label = subject.as_deref().unwrap_or("message template");
        let name = bounded_text(&format!("Mail like {label} from {sender_address}"), 256);
        Ok(RuleProfile {
            rule: SimilarityRule {
                id: SimilarityRuleId::new(),
                name,
                sender_address,
                seed_message_id: Some(message_id),
                route: WarmRoute::Fyi,
                cutoff_millis: crate::DEFAULT_SIMILARITY_CUTOFF_MILLIS,
                enabled: true,
                created_at: 0,
                updated_at: 0,
            },
            subject,
            body_text,
        })
    }

    async fn rank_profile(
        &self,
        profile: &RuleProfile,
        cutoff_millis: u16,
    ) -> Result<Vec<(MessageId, u16)>> {
        let _search_guard = self.0.inner.search_sync.read().await;
        self.rank_profile_locked(profile, cutoff_millis).await
    }

    async fn rank_profile_locked(
        &self,
        profile: &RuleProfile,
        cutoff_millis: u16,
    ) -> Result<Vec<(MessageId, u16)>> {
        let index = Arc::clone(&self.0.inner.search_index);
        let subject = profile.subject.clone();
        let body_text = profile.body_text.clone();
        let sender = profile.rule.sender_address.clone();
        let scores = tokio::task::spawn_blocking(move || {
            index.similar_messages(
                subject.as_deref(),
                &body_text,
                &sender,
                MAX_RULE_MATCHES + 1,
            )
        })
        .await
        .map_err(|error| {
            BackendError::SearchIndex(format!("similar-mail query task failed: {error}"))
        })??;
        let maximum = scores
            .iter()
            .map(|(_, score)| *score)
            .filter(|score| score.is_finite() && *score > 0.0)
            .fold(0.0_f32, f32::max);
        if maximum <= 0.0 {
            return Err(BackendError::InvalidInput(
                "this message does not contain enough searchable text for a similarity rule".into(),
            ));
        }
        let mut ranked = Vec::new();
        for (id, score) in scores {
            if !score.is_finite() || score <= 0.0 {
                continue;
            }
            let relative = ((score / maximum) * f32::from(MAX_CUTOFF_MILLIS)).round();
            let relative = relative.clamp(0.0, f32::from(MAX_CUTOFF_MILLIS)) as u16;
            if relative < cutoff_millis {
                continue;
            }
            let id = MessageId::from_str(&id).map_err(|_| {
                BackendError::SearchIndex(
                    "similar-mail index returned an invalid message identifier".into(),
                )
            })?;
            ranked.push((id, relative));
        }
        Ok(ranked)
    }

    async fn message_threads(
        &self,
        ranked: &[(MessageId, u16)],
    ) -> Result<HashMap<MessageId, ThreadId>> {
        let connection = self.0.inner.connection.lock().await;
        let mut values = HashMap::with_capacity(ranked.len());
        for chunk in ranked.chunks(MESSAGE_BATCH) {
            let placeholders = placeholders(chunk.len());
            let mut rows = connection
                .query(
                    format!("SELECT id, thread_id FROM messages WHERE id IN ({placeholders})"),
                    params_from_iter(
                        chunk
                            .iter()
                            .map(|(id, _)| Value::Text(id.to_string()))
                            .collect::<Vec<_>>(),
                    ),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                let message_id = parse_message_id(row.get::<String>(0)?)?;
                let thread_id = parse_thread_id(row.get::<String>(1)?)?;
                values.insert(message_id, thread_id);
            }
        }
        let indexed_ids = ranked
            .iter()
            .map(|(message_id, _)| *message_id)
            .collect::<HashSet<_>>();
        if values.len() != indexed_ids.len()
            || indexed_ids
                .iter()
                .any(|message_id| !values.contains_key(message_id))
        {
            return Err(BackendError::SearchIndex(
                "similar-mail index references a missing or unthreaded message; reopen the profile to rebuild the index"
                    .into(),
            ));
        }
        Ok(values)
    }

    async fn route_states(
        &self,
        thread_ids: &HashSet<ThreadId>,
    ) -> Result<HashMap<ThreadId, RouteState>> {
        let connection = self.0.inner.connection.lock().await;
        let ids = thread_ids.iter().copied().collect::<Vec<_>>();
        let mut values = HashMap::with_capacity(ids.len());
        for chunk in ids.chunks(MESSAGE_BATCH) {
            let placeholders = placeholders(chunk.len());
            let mut rows = connection
                .query(
                    format!(
                        r#"SELECT t.id, tws.route_override, tws.route_override_source,
                            COALESCE(tws.actionable_once, 0),
                            EXISTS (
                                SELECT 1 FROM messages m
                                JOIN contact_addresses ca
                                    ON ca.address = m.from_address COLLATE NOCASE
                                JOIN contact_relationships cr ON cr.contact_id = ca.contact_id
                                WHERE m.thread_id = t.id AND cr.may_create_obligations = 1
                            ),
                            EXISTS (
                                SELECT 1 FROM messages m
                                JOIN contact_addresses ca
                                    ON ca.address = m.from_address COLLATE NOCASE
                                JOIN contact_relationships cr ON cr.contact_id = ca.contact_id
                                WHERE m.thread_id = t.id AND cr.may_create_obligations = 0
                            )
                        FROM threads t
                        LEFT JOIN thread_work_state tws ON tws.thread_id = t.id
                        WHERE t.id IN ({placeholders})"#
                    ),
                    params_from_iter(
                        chunk
                            .iter()
                            .map(|id| Value::Text(id.to_string()))
                            .collect::<Vec<_>>(),
                    ),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                let id = parse_thread_id(row.get::<String>(0)?)?;
                values.insert(
                    id,
                    RouteState {
                        route_override: row
                            .get::<Option<String>>(1)?
                            .map(|value| parse_route(&value))
                            .transpose()?,
                        source: row
                            .get::<Option<String>>(2)?
                            .map(|value| parse_source(&value))
                            .transpose()?,
                        actionable_once: row.get(3)?,
                        has_action: row.get(4)?,
                        has_fyi: row.get(5)?,
                    },
                );
            }
        }
        Ok(values)
    }

    async fn enabled_profiles_for_messages(
        &self,
        message_ids: &[MessageId],
    ) -> Result<Vec<RuleProfile>> {
        let connection = self.0.inner.connection.lock().await;
        let mut senders = HashSet::new();
        for chunk in message_ids.chunks(MESSAGE_BATCH) {
            let placeholders = placeholders(chunk.len());
            let mut rows = connection
                .query(
                    format!(
                        "SELECT DISTINCT lower(from_address) FROM messages WHERE id IN ({placeholders}) AND from_address IS NOT NULL"
                    ),
                    params_from_iter(
                        chunk
                            .iter()
                            .map(|id| Value::Text(id.to_string()))
                            .collect::<Vec<_>>(),
                    ),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                senders.insert(row.get::<String>(0)?);
            }
        }
        if senders.is_empty() {
            return Ok(Vec::new());
        }
        let senders = senders.into_iter().collect::<Vec<_>>();
        let mut profiles = Vec::new();
        for chunk in senders.chunks(MESSAGE_BATCH) {
            let placeholders = placeholders(chunk.len());
            let mut rows = connection
                .query(
                    format!(
                        "SELECT id, name, sender_address, seed_message_id, route, cutoff_millis, enabled, created_at, updated_at, profile_subject, profile_body_text FROM workflow_similarity_rules WHERE enabled = 1 AND sender_address IN ({placeholders}) ORDER BY id"
                    ),
                    params_from_iter(
                        chunk
                            .iter()
                            .cloned()
                            .map(Value::Text)
                            .collect::<Vec<_>>(),
                    ),
                )
                .await?;
            while let Some(row) = rows.next().await? {
                profiles.push(RuleProfile {
                    rule: rule_from_row(&row)?,
                    subject: row.get(9)?,
                    body_text: row.get(10)?,
                });
            }
        }
        Ok(profiles)
    }
}

#[derive(Clone, Copy)]
struct RouteState {
    route_override: Option<WarmRoute>,
    source: Option<RouteOverrideSource>,
    actionable_once: bool,
    has_action: bool,
    has_fyi: bool,
}

impl RouteState {
    fn effective(self) -> Option<WarmRoute> {
        if self.actionable_once {
            Some(WarmRoute::Action)
        } else if let Some(route) = self.route_override {
            Some(route)
        } else if self.has_action {
            Some(WarmRoute::Action)
        } else if self.has_fyi {
            Some(WarmRoute::Fyi)
        } else {
            None
        }
    }

    fn rule_can_move_to(self, route: WarmRoute) -> bool {
        self.source != Some(RouteOverrideSource::Manual) && self.effective() != Some(route)
    }
}

async fn apply_rule_to_threads_on(
    connection: &turso::Connection,
    rule_id: SimilarityRuleId,
    route: WarmRoute,
    thread_ids: &HashSet<ThreadId>,
    now: i64,
) -> Result<()> {
    for thread_id in thread_ids {
        connection
            .execute(
                r#"INSERT INTO thread_work_state(
                    thread_id, status, snoozed_until, actionable_once,
                    route_override, route_override_source, route_override_rule_id,
                    updated_at
                ) VALUES (?1, 'active', NULL, 0, ?2, 'similarity_rule', ?3, ?4)
                ON CONFLICT(thread_id) DO UPDATE SET
                    actionable_once = 0,
                    route_override = excluded.route_override,
                    route_override_source = excluded.route_override_source,
                    route_override_rule_id = excluded.route_override_rule_id,
                    updated_at = excluded.updated_at
                WHERE thread_work_state.route_override_source IS NULL
                   OR thread_work_state.route_override_source != 'manual'"#,
                (
                    thread_id.to_string(),
                    route_text(route),
                    rule_id.to_string(),
                    now,
                ),
            )
            .await?;
    }
    Ok(())
}

fn rule_from_row(row: &turso::Row) -> Result<SimilarityRule> {
    Ok(SimilarityRule {
        id: SimilarityRuleId::from_str(&row.get::<String>(0)?).map_err(|_| {
            BackendError::InvalidInput(
                "database contains invalid workflow similarity rule ID".into(),
            )
        })?,
        name: row.get(1)?,
        sender_address: row.get(2)?,
        seed_message_id: row
            .get::<Option<String>>(3)?
            .map(parse_message_id)
            .transpose()?,
        route: parse_route(&row.get::<String>(4)?)?,
        cutoff_millis: u16::try_from(row.get::<i64>(5)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid similarity cutoff".into())
        })?,
        enabled: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn validate_cutoff(value: u16) -> Result<()> {
    if !(MIN_CUTOFF_MILLIS..=MAX_CUTOFF_MILLIS).contains(&value) {
        return Err(BackendError::InvalidInput(format!(
            "relative similarity cutoff must be between {MIN_CUTOFF_MILLIS} and {MAX_CUTOFF_MILLIS}"
        )));
    }
    Ok(())
}

fn bounded_text(value: &str, bytes: usize) -> String {
    if value.len() <= bytes {
        return value.to_owned();
    }
    let mut end = bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn normalize_address(value: &str) -> String {
    value.trim().to_lowercase()
}

fn route_text(route: WarmRoute) -> &'static str {
    match route {
        WarmRoute::Action => "action",
        WarmRoute::Fyi => "fyi",
    }
}

fn parse_route(value: &str) -> Result<WarmRoute> {
    match value {
        "action" => Ok(WarmRoute::Action),
        "fyi" => Ok(WarmRoute::Fyi),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid workflow route".into(),
        )),
    }
}

fn parse_source(value: &str) -> Result<RouteOverrideSource> {
    match value {
        "manual" => Ok(RouteOverrideSource::Manual),
        "similarity_rule" => Ok(RouteOverrideSource::SimilarityRule),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid workflow route source".into(),
        )),
    }
}

fn parse_message_id(value: String) -> Result<MessageId> {
    MessageId::from_str(&value).map_err(|_| {
        BackendError::InvalidInput("database contains invalid message identifier".into())
    })
}

fn parse_thread_id(value: String) -> Result<ThreadId> {
    ThreadId::from_str(&value).map_err(|_| {
        BackendError::InvalidInput("database contains invalid thread identifier".into())
    })
}

fn placeholders(count: usize) -> String {
    std::iter::repeat_n("?", count)
        .collect::<Vec<_>>()
        .join(", ")
}

fn match_set_digest(ranked: &[(MessageId, u16)]) -> String {
    let mut canonical = ranked
        .iter()
        .map(|(message_id, score)| (message_id.to_string(), *score))
        .collect::<Vec<_>>();
    canonical.sort_unstable();
    let mut hasher = Sha256::new();
    for (message_id, score) in canonical {
        hasher.update(message_id.as_bytes());
        hasher.update([0]);
        hasher.update(score.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}
