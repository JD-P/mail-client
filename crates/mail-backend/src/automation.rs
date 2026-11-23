use crate::backend::{enqueue_search_on, insert_event, not_found, parse_id};
use crate::heuristic::{
    compile_program, run_program_traced, CompiledHeuristic, HeuristicRunError,
    HEURISTIC_COMPILER_VERSION,
};
use crate::{
    AutomationEvaluationStatus, AutomationReevaluation, Backend, BackendError, FilterAction,
    FilterCondition, FilterConditionTrace, FilterRule, FilterRuleApplication, FilterRuleEvaluation,
    FilterRuleId, FilterRuleMessagePreview, FilterRulePreview, FilterRuleReplay, FilterRuleUndo,
    FindingId, FolderId, Heuristic, HeuristicEvaluation, HeuristicEvaluationStatus,
    HeuristicFinding, HeuristicId, HeuristicMessagePreview, HeuristicPreview,
    HeuristicPreviewFinding, HeuristicSourceKind, HeuristicTraceStep, ImapMutationId,
    ImapMutationOperation, ImapMutationStatus, Message, MessageContentAvailability, MessageId,
    NewFilterRule, NewHeuristic, OpenPgpDecryptedMessage, OpenPgpEncryptionStatus, Result,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use turso::{params_from_iter, Value};
use uuid::Uuid;

const PREVIEW_SAMPLE_LIMIT: usize = 20;
const AUTOMATION_MESSAGE_BATCH: usize = 100;
const FILTER_PREVIEW_FROM: &str = r#"FROM messages m
    LEFT JOIN openpgp_decrypted_messages odm ON odm.message_id = m.id
    LEFT JOIN openpgp_message_evidence opme ON opme.message_id = m.id"#;

#[derive(Clone, Copy)]
enum FilterSqlOutcome {
    Matched,
    PendingContent,
    PendingDecryption,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FilterPriorState {
    #[serde(default)]
    captured: bool,
    local_folder_ids: Vec<FolderId>,
    remote_mutation_ids: Vec<ImapMutationId>,
}

struct FilterDecision {
    message_id: MessageId,
    status: AutomationEvaluationStatus,
    evidence_revision: String,
    trace: Vec<FilterConditionTrace>,
}

impl FilterDecision {
    fn preview(&self, would_change: bool) -> FilterRuleMessagePreview {
        FilterRuleMessagePreview {
            message_id: self.message_id,
            status: self.status,
            would_change,
            evidence_revision: self.evidence_revision.clone(),
            trace: self.trace.clone(),
        }
    }
}

struct HeuristicDecision {
    message_id: MessageId,
    status: HeuristicEvaluationStatus,
    detail: Option<String>,
    findings: Vec<crate::heuristic::ProducedFinding>,
    evidence_revision: String,
    trace: Vec<HeuristicTraceStep>,
}

struct PreparedHeuristicMessage {
    message: Message,
    thread_openpgp_required: bool,
    evidence_revision: String,
    pending: Option<(HeuristicEvaluationStatus, &'static str)>,
}

impl HeuristicDecision {
    fn pending(
        message_id: MessageId,
        status: HeuristicEvaluationStatus,
        evidence_revision: String,
        detail: &str,
    ) -> Self {
        Self {
            message_id,
            status,
            detail: Some(detail.into()),
            findings: Vec::new(),
            evidence_revision,
            trace: vec![HeuristicTraceStep {
                sequence: 0,
                kind: "pending".into(),
                expression: None,
                outcome: None,
                detail: detail.into(),
            }],
        }
    }

    fn preview(self, message_id: MessageId) -> HeuristicMessagePreview {
        debug_assert_eq!(self.message_id, message_id);
        HeuristicMessagePreview {
            message_id,
            status: self.status,
            evidence_revision: self.evidence_revision,
            findings: self
                .findings
                .into_iter()
                .map(|finding| HeuristicPreviewFinding {
                    code: finding.code,
                    presentation: finding.presentation,
                    severity: finding.severity,
                    target_kind: finding.target_kind,
                    target_id: finding.target_id,
                    text: finding.text,
                    evidence: finding.evidence,
                })
                .collect(),
            trace: self.trace,
            detail: self.detail,
        }
    }
}

#[derive(Clone)]
pub struct FilterRules(Backend);

impl FilterRules {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn add(&self, rule: NewFilterRule) -> Result<FilterRule> {
        validate_filter_rule(&self.0, &rule).await?;
        let now = Utc::now().timestamp();
        let value = FilterRule {
            id: FilterRuleId::new(),
            name: rule.name,
            revision: 1,
            priority: rule.priority,
            enabled: rule.enabled,
            conditions: rule.conditions,
            actions: rule.actions,
            created_at: now,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO filter_rules(id, name, revision, priority, enabled, conditions_json, actions_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                turso::params![
                    value.id.to_string(),
                    value.name.clone(),
                    i64::from(value.revision),
                    i64::from(value.priority),
                    value.enabled,
                    serde_json::to_string(&value.conditions)?,
                    serde_json::to_string(&value.actions)?,
                    value.created_at,
                    value.updated_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO filter_rule_versions(rule_id, revision, name, conditions_json, actions_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                turso::params![
                    value.id.to_string(),
                    i64::from(value.revision),
                    value.name.clone(),
                    serde_json::to_string(&value.conditions)?,
                    serde_json::to_string(&value.actions)?,
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "filter_rule_added",
            value.id.to_string(),
            json!({"filter_rule_id": value.id, "revision": value.revision}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(value)
    }

    pub async fn update(&self, id: FilterRuleId, rule: NewFilterRule) -> Result<FilterRule> {
        validate_filter_rule(&self.0, &rule).await?;
        let existing = self.get(id).await?;
        let revision = existing
            .revision
            .checked_add(1)
            .ok_or_else(|| BackendError::Conflict("filter rule revision overflow".into()))?;
        let now = Utc::now().timestamp();
        let value = FilterRule {
            id,
            name: rule.name,
            revision,
            priority: rule.priority,
            enabled: rule.enabled,
            conditions: rule.conditions,
            actions: rule.actions,
            created_at: existing.created_at,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE filter_rules SET name = ?1, revision = ?2, priority = ?3, enabled = ?4, conditions_json = ?5, actions_json = ?6, updated_at = ?7 WHERE id = ?8 AND revision = ?9 AND deleted_at IS NULL",
                turso::params![
                    value.name.clone(),
                    i64::from(value.revision),
                    i64::from(value.priority),
                    value.enabled,
                    serde_json::to_string(&value.conditions)?,
                    serde_json::to_string(&value.actions)?,
                    value.updated_at,
                    id.to_string(),
                    i64::from(existing.revision),
                ],
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "filter rule changed during update".into(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO filter_rule_versions(rule_id, revision, name, conditions_json, actions_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                turso::params![
                    id.to_string(),
                    i64::from(revision),
                    value.name.clone(),
                    serde_json::to_string(&value.conditions)?,
                    serde_json::to_string(&value.actions)?,
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "filter_rule_updated",
            id.to_string(),
            json!({"filter_rule_id": id, "revision": revision}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(value)
    }

    pub async fn get(&self, id: FilterRuleId) -> Result<FilterRule> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, revision, priority, enabled, conditions_json, actions_json, created_at, updated_at FROM filter_rules WHERE id = ?1 AND deleted_at IS NULL",
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| filter_rule_from_row(&row))
            .transpose()?
            .ok_or_else(|| not_found("filter rule", id))
    }

    pub async fn list(&self) -> Result<Vec<FilterRule>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, revision, priority, enabled, conditions_json, actions_json, created_at, updated_at FROM filter_rules WHERE deleted_at IS NULL ORDER BY priority, id",
                (),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(filter_rule_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn remove(&self, id: FilterRuleId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "UPDATE filter_rules SET enabled = 0, deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND deleted_at IS NULL",
                (now, id.to_string()),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("filter rule", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "filter_rule_removed",
            id.to_string(),
            json!({"filter_rule_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    /// Evaluate enabled rules against one immutable message snapshot. Rules
    /// run by priority; a matched `Stop` action prevents later rules.
    pub async fn evaluate_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<FilterRuleApplication>> {
        let rules = self
            .list()
            .await?
            .into_iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return Ok(Vec::new());
        }
        let message = self.0.messages().get(message_id).await?;
        self.evaluate_loaded_with_rules(&rules, &message).await
    }

    pub(crate) async fn evaluate_loaded_messages(
        &self,
        messages: &[Message],
    ) -> Result<Vec<FilterRuleApplication>> {
        let rules = self
            .list()
            .await?
            .into_iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return Ok(Vec::new());
        }
        let mut applications = Vec::new();
        for message in messages {
            applications.extend(self.evaluate_loaded_with_rules(&rules, message).await?);
        }
        Ok(applications)
    }

    async fn evaluate_loaded_with_rules(
        &self,
        rules: &[FilterRule],
        message: &Message,
    ) -> Result<Vec<FilterRuleApplication>> {
        let mut applications = Vec::new();
        for rule in rules {
            let decision = self
                .evaluate_rule(&rule.conditions, message, None, true)
                .await?;
            self.store_evaluation(rule, &decision).await?;
            if decision.status != AutomationEvaluationStatus::Matched {
                continue;
            }
            if let Some(application) = self.apply_rule(rule, message.summary.id).await? {
                applications.push(application);
            }
            if rule
                .actions
                .iter()
                .any(|action| matches!(action, FilterAction::Stop))
            {
                break;
            }
        }
        Ok(applications)
    }

    /// Count matches and messages whose current organization would materially
    /// change, without recording applications or queuing server mutations.
    pub async fn preview(&self, rule: &NewFilterRule) -> Result<FilterRulePreview> {
        validate_filter_rule(&self.0, rule).await?;
        let (matching, matching_parameters) =
            filter_sql_predicate(&rule.conditions, FilterSqlOutcome::Matched)?;
        let (affected, mut parameters) = filter_affected_sql(&rule.actions);
        parameters.extend(matching_parameters);
        let sql = format!(
            "SELECT count(*), COALESCE(sum(CASE WHEN {affected} THEN 1 ELSE 0 END), 0) {FILTER_PREVIEW_FROM} WHERE {matching}"
        );
        let (matching_messages, affected_messages) = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
            let row = rows.next().await?.ok_or_else(|| {
                BackendError::InvalidInput("filter preview count returned no row".into())
            })?;
            (
                database_u64(row.get(0)?, "matching message count")?,
                database_u64(row.get(1)?, "affected message count")?,
            )
        };
        let pending_decryption_messages = self
            .count_filter_outcome(&rule.conditions, FilterSqlOutcome::PendingDecryption)
            .await?;
        let pending_content_messages = self
            .count_filter_outcome(&rule.conditions, FilterSqlOutcome::PendingContent)
            .await?;
        let sample_ids = self.sample_message_ids(PREVIEW_SAMPLE_LIMIT).await?;
        let messages = self.0.messages().get_many(&sample_ids).await?;
        let mut samples = Vec::with_capacity(messages.len());
        for message in messages {
            let message_id = message.summary.id;
            let decision = self
                .evaluate_rule(&rule.conditions, &message, None, true)
                .await?;
            let would_change = if decision.status == AutomationEvaluationStatus::Matched {
                self.would_affect(message_id, &rule.actions).await?
            } else {
                false
            };
            samples.push(decision.preview(would_change));
        }
        Ok(FilterRulePreview {
            matching_messages,
            affected_messages,
            pending_content_messages,
            pending_decryption_messages,
            samples,
        })
    }

    /// Explain one sample without applying the candidate rule.
    pub async fn preview_message(
        &self,
        rule: &NewFilterRule,
        message_id: MessageId,
    ) -> Result<FilterRuleMessagePreview> {
        validate_filter_rule(&self.0, rule).await?;
        let message = self.0.messages().get(message_id).await?;
        let decision = self
            .evaluate_rule(&rule.conditions, &message, None, true)
            .await?;
        let would_change = decision.status == AutomationEvaluationStatus::Matched
            && self.would_affect(message_id, &rule.actions).await?;
        Ok(decision.preview(would_change))
    }

    /// Apply exactly the current rule revision to all existing matches.
    /// Applications committed before an error remain durable; rerunning is
    /// idempotent and resumes at the first unapplied message.
    pub async fn replay(&self, id: FilterRuleId) -> Result<FilterRuleReplay> {
        let rule = self.get(id).await?;
        if !rule.enabled {
            return Err(BackendError::Conflict(
                "a disabled filter rule cannot be replayed".into(),
            ));
        }
        let ids = self.all_message_ids().await?;
        let mut matching_messages = 0u64;
        let mut newly_applied_messages = 0u64;
        let mut already_applied_messages = 0u64;
        let mut pending_content_messages = 0u64;
        let mut pending_decryption_messages = 0u64;
        for chunk in ids.chunks(AUTOMATION_MESSAGE_BATCH) {
            for message in self.0.messages().get_many(chunk).await? {
                let message_id = message.summary.id;
                let decision = self
                    .evaluate_rule(&rule.conditions, &message, None, true)
                    .await?;
                self.store_evaluation(&rule, &decision).await?;
                match decision.status {
                    AutomationEvaluationStatus::Matched => matching_messages += 1,
                    AutomationEvaluationStatus::PendingContent => {
                        pending_content_messages += 1;
                        continue;
                    }
                    AutomationEvaluationStatus::PendingDecryption => {
                        pending_decryption_messages += 1;
                        continue;
                    }
                    _ => continue,
                }
                if self.apply_rule(&rule, message_id).await?.is_some() {
                    newly_applied_messages += 1;
                } else {
                    already_applied_messages += 1;
                }
            }
        }
        Ok(FilterRuleReplay {
            matching_messages,
            newly_applied_messages,
            already_applied_messages,
            pending_content_messages,
            pending_decryption_messages,
        })
    }

    pub async fn undo(
        &self,
        rule_id: FilterRuleId,
        rule_revision: u32,
        message_id: MessageId,
    ) -> Result<FilterRuleUndo> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT prior_state_json, undone_at FROM filter_rule_applications WHERE rule_id = ?1 AND rule_revision = ?2 AND message_id = ?3",
                turso::params![
                    rule_id.to_string(),
                    i64::from(rule_revision),
                    message_id.to_string(),
                ],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(BackendError::NotFound {
                entity: "filter rule application",
                id: format!("{rule_id}:{rule_revision}:{message_id}"),
            });
        };
        let prior: FilterPriorState = serde_json::from_str(&row.get::<String>(0)?)?;
        if row.get::<Option<i64>>(1)?.is_some() {
            return Err(BackendError::Conflict(
                "filter rule application was already undone".into(),
            ));
        }
        if !prior.captured {
            return Err(BackendError::Conflict(
                "this legacy filter application predates placement snapshots and cannot be safely undone"
                    .into(),
            ));
        }
        drop(rows);
        let transaction = connection.transaction().await?;
        let mut cancelled = Vec::new();
        let mut inverses = Vec::new();
        let mut events = Vec::new();
        for mutation_id in &prior.remote_mutation_ids {
            let mut rows = transaction
                .query(
                    "SELECT source_folder_id, operation_json, status FROM imap_mutations WHERE id = ?1",
                    (mutation_id.to_string(),),
                )
                .await?;
            let Some(row) = rows.next().await? else {
                return Err(not_found("IMAP mutation", mutation_id));
            };
            let source_folder_id = parse_id::<FolderId>(row.get(0)?, "folder")?;
            let operation: ImapMutationOperation = serde_json::from_str(&row.get::<String>(1)?)?;
            let status = parse_mutation_status_for_undo(&row.get::<String>(2)?)?;
            drop(rows);
            match status {
                ImapMutationStatus::Pending | ImapMutationStatus::Conflict => {
                    transaction
                        .execute(
                            "UPDATE imap_mutations SET status = 'cancelled', updated_at = ?1, completed_at = ?1 WHERE id = ?2",
                            (now, mutation_id.to_string()),
                        )
                        .await?;
                    transaction
                        .execute(
                            "UPDATE imap_mutation_conflicts SET resolved_at = ?1 WHERE mutation_id = ?2 AND resolved_at IS NULL",
                            (now, mutation_id.to_string()),
                        )
                        .await?;
                    cancelled.push(*mutation_id);
                    events.push(
                        insert_event(
                            &transaction,
                            now,
                            "imap_mutation_cancelled",
                            mutation_id.to_string(),
                            json!({"mutation_id": mutation_id, "origin": "filter_rule_undo"}),
                        )
                        .await?,
                    );
                }
                ImapMutationStatus::Cancelled => {}
                ImapMutationStatus::InFlight => {
                    return Err(BackendError::Conflict(
                        "an in-flight remote filter action cannot be safely undone".into(),
                    ));
                }
                ImapMutationStatus::Applied => {
                    let inverse = match operation {
                        ImapMutationOperation::Move {
                            destination_folder_id,
                        } => (
                            destination_folder_id,
                            ImapMutationOperation::Move {
                                destination_folder_id: source_folder_id,
                            },
                        ),
                        ImapMutationOperation::Copy {
                            destination_folder_id,
                        } => (destination_folder_id, ImapMutationOperation::Delete),
                        ImapMutationOperation::Delete => {
                            return Err(BackendError::Conflict(
                                "a completed permanent deletion cannot be undone".into(),
                            ));
                        }
                        ImapMutationOperation::SetFlags { .. } => {
                            return Err(BackendError::Conflict(
                                "filter application contains an unsupported flag mutation".into(),
                            ));
                        }
                    };
                    let (id, event) = crate::imap_mutation::queue_exact_on(
                        &transaction,
                        message_id,
                        inverse.0,
                        inverse.1,
                        now,
                    )
                    .await?;
                    inverses.push(id);
                    events.push(event);
                }
            }
        }
        transaction
            .execute(
                "DELETE FROM local_folder_memberships WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        for folder_id in &prior.local_folder_ids {
            transaction
                .execute(
                    "INSERT INTO local_folder_memberships(message_id, folder_id, created_at) VALUES (?1, ?2, ?3)",
                    (message_id.to_string(), folder_id.to_string(), now),
                )
                .await?;
        }
        transaction
            .execute(
                "UPDATE filter_rule_applications SET undone_at = ?1 WHERE rule_id = ?2 AND rule_revision = ?3 AND message_id = ?4 AND undone_at IS NULL",
                turso::params![
                    now,
                    rule_id.to_string(),
                    i64::from(rule_revision),
                    message_id.to_string(),
                ],
            )
            .await?;
        enqueue_search_on(&transaction, message_id).await?;
        events.push(
            insert_event(
                &transaction,
                now,
                "filter_rule_application_undone",
                message_id.to_string(),
                json!({
                    "message_id": message_id,
                    "filter_rule_id": rule_id,
                    "rule_revision": rule_revision,
                    "restored_local_folders": prior.local_folder_ids,
                    "cancelled_remote_mutations": cancelled,
                    "queued_inverse_mutations": inverses,
                }),
            )
            .await?,
        );
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        for event in events {
            let _ = self.0.inner.events.send(event);
        }
        Ok(FilterRuleUndo {
            restored_local_folders: prior.local_folder_ids,
            cancelled_remote_mutations: cancelled,
            queued_inverse_mutations: inverses,
            undone_at: now,
        })
    }

    pub(crate) async fn evaluate_message_with_decrypted(
        &self,
        message_id: MessageId,
        decrypted: &OpenPgpDecryptedMessage,
    ) -> Result<Vec<FilterRuleApplication>> {
        let rules = self
            .list()
            .await?
            .into_iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        let message = self.0.messages().get(message_id).await?;
        let mut applications = Vec::new();
        for rule in rules {
            let decision = self
                .evaluate_rule(&rule.conditions, &message, Some(decrypted), false)
                .await?;
            self.store_evaluation(&rule, &decision).await?;
            if decision.status != AutomationEvaluationStatus::Matched {
                continue;
            }
            if let Some(application) = self.apply_rule(&rule, message_id).await? {
                applications.push(application);
            }
            if rule
                .actions
                .iter()
                .any(|action| matches!(action, FilterAction::Stop))
            {
                break;
            }
        }
        Ok(applications)
    }

    pub async fn evaluations(&self, message_id: MessageId) -> Result<Vec<FilterRuleEvaluation>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT rule_id, rule_revision, message_id, status, evidence_revision, trace_json, evaluated_at FROM filter_rule_evaluations WHERE message_id = ?1 ORDER BY rule_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(FilterRuleEvaluation {
                rule_id: parse_id(row.get::<String>(0)?, "filter rule")?,
                rule_revision: database_u32(row.get(1)?, "filter rule revision")?,
                message_id: parse_id(row.get::<String>(2)?, "message")?,
                status: parse_automation_status(&row.get::<String>(3)?)?,
                evidence_revision: row.get(4)?,
                trace: serde_json::from_str(&row.get::<String>(5)?)?,
                evaluated_at: row.get(6)?,
            });
        }
        Ok(values)
    }

    pub async fn reevaluate_stale(&self, limit: usize) -> Result<AutomationReevaluation> {
        let rules = self
            .list()
            .await?
            .into_iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return Ok(AutomationReevaluation {
                evaluated_messages: 0,
                remaining_stale_messages: 0,
            });
        }
        let mut evaluated_messages = 0u64;
        let mut remaining_stale_messages = 0u64;
        let ids = self.all_message_ids().await?;
        for chunk in ids.chunks(AUTOMATION_MESSAGE_BATCH) {
            let evaluations = self.evaluations_for_messages(chunk).await?;
            for message in self.0.messages().get_many(chunk).await? {
                let message_id = message.summary.id;
                let mut decisions = Vec::with_capacity(rules.len());
                let mut stale = false;
                for rule in &rules {
                    let decision = self
                        .evaluate_rule(&rule.conditions, &message, None, true)
                        .await?;
                    stale |= evaluations.get(&(rule.id, message_id)).is_none_or(
                        |(revision, evidence_revision)| {
                            *revision != rule.revision
                                || evidence_revision != &decision.evidence_revision
                        },
                    );
                    decisions.push((rule, decision));
                }
                if !stale {
                    continue;
                }
                if evaluated_messages as usize >= limit.max(1) {
                    remaining_stale_messages += 1;
                    continue;
                }
                for (rule, decision) in decisions {
                    self.store_evaluation(rule, &decision).await?;
                    if decision.status == AutomationEvaluationStatus::Matched {
                        let _ = self.apply_rule(rule, message_id).await?;
                        if rule
                            .actions
                            .iter()
                            .any(|action| matches!(action, FilterAction::Stop))
                        {
                            break;
                        }
                    }
                }
                evaluated_messages += 1;
            }
        }
        Ok(AutomationReevaluation {
            evaluated_messages,
            remaining_stale_messages,
        })
    }

    async fn all_message_ids(&self) -> Result<Vec<MessageId>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query("SELECT id FROM messages ORDER BY received_at, id", ())
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_id(row.get::<String>(0)?, "message")?);
        }
        Ok(ids)
    }

    async fn sample_message_ids(&self, limit: usize) -> Result<Vec<MessageId>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id FROM messages ORDER BY received_at DESC, id DESC LIMIT ?1",
                (i64::try_from(limit).unwrap_or(i64::MAX),),
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_id(row.get::<String>(0)?, "message")?);
        }
        Ok(ids)
    }

    async fn count_filter_outcome(
        &self,
        conditions: &[FilterCondition],
        outcome: FilterSqlOutcome,
    ) -> Result<u64> {
        let (predicate, parameters) = filter_sql_predicate(conditions, outcome)?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                format!("SELECT count(*) {FILTER_PREVIEW_FROM} WHERE {predicate}"),
                params_from_iter(parameters),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| {
            BackendError::InvalidInput("filter pending count returned no row".into())
        })?;
        database_u64(row.get(0)?, "pending filter message count")
    }

    async fn would_affect(&self, message_id: MessageId, actions: &[FilterAction]) -> Result<bool> {
        let (predicate, mut parameters) = filter_affected_sql(actions);
        parameters.push(Value::Text(message_id.to_string()));
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                format!(
                    "SELECT CASE WHEN {predicate} THEN 1 ELSE 0 END FROM messages m WHERE m.id = ?"
                ),
                params_from_iter(parameters),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| row.get::<bool>(0))
            .transpose()?
            .ok_or_else(|| not_found("message", message_id))
    }

    async fn evaluate_rule(
        &self,
        conditions: &[FilterCondition],
        message: &Message,
        decrypted: Option<&OpenPgpDecryptedMessage>,
        allow_cached: bool,
    ) -> Result<FilterDecision> {
        let needs_protected = conditions
            .iter()
            .any(filter_condition_needs_protected_content);
        let mut decrypted_owned = None;
        let encrypted = message.openpgp.encryption != OpenPgpEncryptionStatus::NotEncrypted;
        if needs_protected && encrypted && decrypted.is_none() && allow_cached {
            decrypted_owned = self
                .0
                .openpgp()
                .load_cached_decrypted(message.summary.id)
                .await?;
        }
        let decrypted = decrypted.or(decrypted_owned.as_ref());
        let projected = project_decrypted_message(message, decrypted, &self.0);
        let mut trace = Vec::with_capacity(conditions.len());
        let mut saw_pending_content = false;
        let mut saw_pending_decryption = false;
        let mut saw_false = false;
        for (index, condition) in conditions.iter().enumerate() {
            let (status, detail) = if filter_condition_needs_protected_content(condition)
                && encrypted
                && decrypted.is_none()
                && message.summary.content_availability != MessageContentAvailability::Complete
            {
                saw_pending_content = true;
                (
                    AutomationEvaluationStatus::PendingContent,
                    "requires the complete encrypted message before decryption".into(),
                )
            } else if filter_condition_needs_protected_content(condition)
                && encrypted
                && decrypted.is_none()
            {
                saw_pending_decryption = true;
                (
                    AutomationEvaluationStatus::PendingDecryption,
                    "requires authenticated decrypted message content".into(),
                )
            } else if filter_condition_needs_downloaded_content(condition)
                && message.summary.content_availability != MessageContentAvailability::Complete
            {
                saw_pending_content = true;
                (
                    AutomationEvaluationStatus::PendingContent,
                    "requires a complete locally downloaded message".into(),
                )
            } else if filter_matches(condition, &projected) {
                (
                    AutomationEvaluationStatus::Matched,
                    "condition matched".into(),
                )
            } else {
                saw_false = true;
                (
                    AutomationEvaluationStatus::NotMatched,
                    "condition did not match".into(),
                )
            };
            trace.push(FilterConditionTrace {
                index,
                condition: condition.clone(),
                status,
                detail,
            });
        }
        let status = if saw_false {
            AutomationEvaluationStatus::NotMatched
        } else if saw_pending_decryption {
            AutomationEvaluationStatus::PendingDecryption
        } else if saw_pending_content {
            AutomationEvaluationStatus::PendingContent
        } else {
            AutomationEvaluationStatus::Matched
        };
        let features = filter_required_features(conditions);
        Ok(FilterDecision {
            message_id: message.summary.id,
            status,
            evidence_revision: evidence_revision(&projected, &features, false)?,
            trace,
        })
    }

    async fn store_evaluation(&self, rule: &FilterRule, decision: &FilterDecision) -> Result<()> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        connection
            .execute(
                "INSERT INTO filter_rule_evaluations(rule_id, rule_revision, message_id, status, evidence_revision, trace_json, evaluated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(rule_id, message_id) DO UPDATE SET rule_revision = excluded.rule_revision, status = excluded.status, evidence_revision = excluded.evidence_revision, trace_json = excluded.trace_json, evaluated_at = excluded.evaluated_at",
                turso::params![
                    rule.id.to_string(),
                    i64::from(rule.revision),
                    decision.message_id.to_string(),
                    automation_status_text(decision.status),
                    decision.evidence_revision.clone(),
                    serde_json::to_string(&decision.trace)?,
                    now,
                ],
            )
            .await?;
        Ok(())
    }

    async fn evaluations_for_messages(
        &self,
        message_ids: &[MessageId],
    ) -> Result<HashMap<(FilterRuleId, MessageId), (u32, String)>> {
        if message_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", message_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                format!(
                    "SELECT rule_id, message_id, rule_revision, evidence_revision FROM filter_rule_evaluations WHERE message_id IN ({placeholders})"
                ),
                params_from_iter(
                    message_ids
                        .iter()
                        .map(|id| Value::Text(id.to_string()))
                        .collect::<Vec<_>>(),
                ),
            )
            .await?;
        let mut evaluations = HashMap::new();
        while let Some(row) = rows.next().await? {
            evaluations.insert(
                (
                    parse_id(row.get::<String>(0)?, "filter rule")?,
                    parse_id(row.get::<String>(1)?, "message")?,
                ),
                (
                    database_u32(row.get(2)?, "filter rule revision")?,
                    row.get(3)?,
                ),
            );
        }
        Ok(evaluations)
    }

    pub(crate) async fn has_enabled(&self) -> Result<bool> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM filter_rules WHERE enabled = 1 AND deleted_at IS NULL LIMIT 1",
                (),
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    pub async fn applications(&self, message_id: MessageId) -> Result<Vec<FilterRuleApplication>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT applications.rule_id, applications.rule_revision, applications.message_id, versions.conditions_json, applications.actions_json, applications.prior_state_json, applications.applied_at, applications.undone_at FROM filter_rule_applications applications JOIN filter_rule_versions versions ON versions.rule_id = applications.rule_id AND versions.revision = applications.rule_revision WHERE applications.message_id = ?1 ORDER BY applications.applied_at, applications.rule_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let prior: FilterPriorState = serde_json::from_str(&row.get::<String>(5)?)?;
            values.push(FilterRuleApplication {
                rule_id: parse_id(row.get::<String>(0)?, "filter rule")?,
                rule_revision: database_u32(row.get(1)?, "filter rule revision")?,
                message_id: parse_id(row.get::<String>(2)?, "message")?,
                conditions: serde_json::from_str(&row.get::<String>(3)?)?,
                actions: serde_json::from_str(&row.get::<String>(4)?)?,
                applied_at: row.get(6)?,
                remote_mutation_ids: prior.remote_mutation_ids,
                undone_at: row.get(7)?,
            });
        }
        Ok(values)
    }

    async fn apply_rule(
        &self,
        rule: &FilterRule,
        message_id: MessageId,
    ) -> Result<Option<FilterRuleApplication>> {
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT revision, enabled, deleted_at FROM filter_rules WHERE id = ?1",
                (rule.id.to_string(),),
            )
            .await?;
        let Some(current) = rows.next().await? else {
            return Ok(None);
        };
        if database_u32(current.get(0)?, "filter rule revision")? != rule.revision
            || !current.get::<bool>(1)?
            || current.get::<Option<i64>>(2)?.is_some()
        {
            return Ok(None);
        }
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT 1 FROM filter_rule_applications WHERE rule_id = ?1 AND rule_revision = ?2 AND message_id = ?3",
                turso::params![
                    rule.id.to_string(),
                    i64::from(rule.revision),
                    message_id.to_string(),
                ],
            )
            .await?;
        if rows.next().await?.is_some() {
            return Ok(None);
        }
        drop(rows);

        let mut rows = connection
            .query(
                "SELECT folder_id FROM local_folder_memberships WHERE message_id = ?1 ORDER BY folder_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut prior = FilterPriorState {
            captured: true,
            ..FilterPriorState::default()
        };
        while let Some(row) = rows.next().await? {
            prior
                .local_folder_ids
                .push(parse_id(row.get::<String>(0)?, "folder")?);
        }
        drop(rows);

        let transaction = connection.transaction().await?;
        let mut placement_changed = false;
        let mut mutation_events = Vec::new();
        for action in &rule.actions {
            match action {
                FilterAction::AddToLocalFolder { folder_id } => {
                    placement_changed |= transaction
                        .execute(
                            "INSERT OR IGNORE INTO local_folder_memberships(message_id, folder_id, created_at) VALUES (?1, ?2, ?3)",
                            (message_id.to_string(), folder_id.to_string(), now),
                        )
                        .await?
                        > 0;
                }
                FilterAction::RemoveFromLocalFolder { folder_id } => {
                    placement_changed |= transaction
                        .execute(
                            "DELETE FROM local_folder_memberships WHERE message_id = ?1 AND folder_id = ?2",
                            (message_id.to_string(), folder_id.to_string()),
                        )
                        .await?
                        > 0;
                }
                FilterAction::MoveToLocalFolder { folder_id } => {
                    placement_changed |= transaction
                        .execute(
                            "DELETE FROM local_folder_memberships WHERE message_id = ?1",
                            (message_id.to_string(),),
                        )
                        .await?
                        > 0;
                    placement_changed |= transaction
                        .execute(
                            "INSERT OR IGNORE INTO local_folder_memberships(message_id, folder_id, created_at) VALUES (?1, ?2, ?3)",
                            (message_id.to_string(), folder_id.to_string(), now),
                        )
                        .await?
                        > 0;
                }
                FilterAction::MoveToRemoteFolder {
                    source_folder_id,
                    destination_folder_id,
                } => {
                    let (id, event) = crate::imap_mutation::queue_exact_on(
                        &transaction,
                        message_id,
                        *source_folder_id,
                        ImapMutationOperation::Move {
                            destination_folder_id: *destination_folder_id,
                        },
                        now,
                    )
                    .await?;
                    prior.remote_mutation_ids.push(id);
                    mutation_events.push(event);
                }
                FilterAction::TrashRemote { source_folder_id } => {
                    let source =
                        message_remote_account_on(&transaction, message_id, *source_folder_id)
                            .await?;
                    let destination =
                        crate::imap_mutation::trash_folder_on(&transaction, source).await?;
                    let (id, event) = crate::imap_mutation::queue_exact_on(
                        &transaction,
                        message_id,
                        *source_folder_id,
                        ImapMutationOperation::Move {
                            destination_folder_id: destination,
                        },
                        now,
                    )
                    .await?;
                    prior.remote_mutation_ids.push(id);
                    mutation_events.push(event);
                }
                FilterAction::DeleteRemote { source_folder_id } => {
                    let (id, event) = crate::imap_mutation::queue_exact_on(
                        &transaction,
                        message_id,
                        *source_folder_id,
                        ImapMutationOperation::Delete,
                        now,
                    )
                    .await?;
                    prior.remote_mutation_ids.push(id);
                    mutation_events.push(event);
                }
                FilterAction::Stop => {}
            }
        }
        let actions_json = serde_json::to_string(&rule.actions)?;
        transaction
            .execute(
                "INSERT INTO filter_rule_applications(rule_id, rule_revision, message_id, actions_json, prior_state_json, applied_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                turso::params![
                    rule.id.to_string(),
                    i64::from(rule.revision),
                    message_id.to_string(),
                    actions_json,
                    serde_json::to_string(&prior)?,
                    now,
                ],
            )
            .await?;
        if placement_changed {
            enqueue_search_on(&transaction, message_id).await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "filter_rule_applied",
            message_id.to_string(),
            json!({
                "message_id": message_id,
                "filter_rule_id": rule.id,
                "rule_revision": rule.revision,
                "actions": rule.actions,
            }),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        if placement_changed {
            self.0.flush_search_projection().await?;
        }
        for event in mutation_events {
            let _ = self.0.inner.events.send(event);
        }
        let _ = self.0.inner.events.send(event);
        Ok(Some(FilterRuleApplication {
            rule_id: rule.id,
            rule_revision: rule.revision,
            message_id,
            conditions: rule.conditions.clone(),
            actions: rule.actions.clone(),
            applied_at: now,
            remote_mutation_ids: prior.remote_mutation_ids,
            undone_at: None,
        }))
    }
}

#[derive(Clone)]
pub struct Heuristics(Backend);

impl Heuristics {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    /// Recompile persisted source with the current restricted-language
    /// compiler. Evaluation rows carry the compiler version, so this updates
    /// executable IR without pretending the user edited the heuristic.
    pub(crate) async fn refresh_compiled_programs(&self) -> Result<()> {
        let sources = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT id, version, source FROM heuristics WHERE deleted_at IS NULL AND source != ?1 ORDER BY id",
                    (crate::security::definition().source,),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push((
                    row.get::<String>(0)?,
                    database_u32(row.get(1)?, "heuristic version")?,
                    row.get::<String>(2)?,
                ));
            }
            values
        };
        let mut compiled = Vec::with_capacity(sources.len());
        for (id, version, source) in sources {
            compiled.push((id, version, compile_program(&source)?));
        }
        if compiled.is_empty() {
            return Ok(());
        }
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        for (id, version, program) in compiled {
            let compiled_json = serde_json::to_string(&program)?;
            let features_json = serde_json::to_string(&program.required_features)?;
            transaction
                .execute(
                    "UPDATE heuristics SET compiled_json = ?1, required_features_json = ?2, maximum_steps = ?3 WHERE id = ?4 AND version = ?5 AND deleted_at IS NULL",
                    turso::params![
                        compiled_json.clone(),
                        features_json.clone(),
                        i64::from(program.maximum_steps),
                        id.clone(),
                        i64::from(version),
                    ],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE heuristic_versions SET compiled_json = ?1, required_features_json = ?2, maximum_steps = ?3 WHERE heuristic_id = ?4 AND version = ?5",
                    turso::params![
                        compiled_json,
                        features_json,
                        i64::from(program.maximum_steps),
                        id,
                        i64::from(version),
                    ],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn add(&self, heuristic: NewHeuristic) -> Result<Heuristic> {
        validate_heuristic_input(&heuristic)?;
        let program = compile_program(&heuristic.source)?;
        let now = Utc::now().timestamp();
        let value = Heuristic {
            id: HeuristicId::new(),
            name: heuristic.name,
            version: 1,
            source: heuristic.source,
            source_kind: heuristic.source_kind,
            enabled: heuristic.enabled,
            required_features: program.required_features.clone(),
            maximum_steps: program.maximum_steps,
            created_at: now,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO heuristics(id, name, version, source, source_kind, enabled, compiled_json, required_features_json, maximum_steps, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                turso::params![
                    value.id.to_string(),
                    value.name.clone(),
                    i64::from(value.version),
                    value.source.clone(),
                    source_kind_text(value.source_kind),
                    value.enabled,
                    serde_json::to_string(&program)?,
                    serde_json::to_string(&value.required_features)?,
                    i64::from(value.maximum_steps),
                    value.created_at,
                    value.updated_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO heuristic_versions(heuristic_id, version, source, source_kind, compiled_json, required_features_json, maximum_steps, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                turso::params![
                    value.id.to_string(),
                    i64::from(value.version),
                    value.source.clone(),
                    source_kind_text(value.source_kind),
                    serde_json::to_string(&program)?,
                    serde_json::to_string(&value.required_features)?,
                    i64::from(value.maximum_steps),
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "heuristic_added",
            value.id.to_string(),
            json!({"heuristic_id": value.id, "version": value.version}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        Ok(value)
    }

    pub async fn update(&self, id: HeuristicId, heuristic: NewHeuristic) -> Result<Heuristic> {
        validate_heuristic_input(&heuristic)?;
        let program = compile_program(&heuristic.source)?;
        let existing = self.get(id).await?;
        if crate::security::is_builtin_native(&existing) {
            return Err(BackendError::Conflict(
                "native built-in security evidence cannot be edited".into(),
            ));
        }
        let version = existing
            .version
            .checked_add(1)
            .ok_or_else(|| BackendError::Conflict("heuristic version overflow".into()))?;
        let now = Utc::now().timestamp();
        let value = Heuristic {
            id,
            name: heuristic.name,
            version,
            source: heuristic.source,
            source_kind: heuristic.source_kind,
            enabled: heuristic.enabled,
            required_features: program.required_features.clone(),
            maximum_steps: program.maximum_steps,
            created_at: existing.created_at,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE heuristics SET name = ?1, version = ?2, source = ?3, source_kind = ?4, enabled = ?5, compiled_json = ?6, required_features_json = ?7, maximum_steps = ?8, updated_at = ?9 WHERE id = ?10 AND version = ?11 AND deleted_at IS NULL",
                turso::params![
                    value.name.clone(),
                    i64::from(value.version),
                    value.source.clone(),
                    source_kind_text(value.source_kind),
                    value.enabled,
                    serde_json::to_string(&program)?,
                    serde_json::to_string(&value.required_features)?,
                    i64::from(value.maximum_steps),
                    value.updated_at,
                    id.to_string(),
                    i64::from(existing.version),
                ],
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "heuristic changed during update".into(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO heuristic_versions(heuristic_id, version, source, source_kind, compiled_json, required_features_json, maximum_steps, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                turso::params![
                    id.to_string(),
                    i64::from(version),
                    value.source.clone(),
                    source_kind_text(value.source_kind),
                    serde_json::to_string(&program)?,
                    serde_json::to_string(&value.required_features)?,
                    i64::from(value.maximum_steps),
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "heuristic_updated",
            id.to_string(),
            json!({"heuristic_id": id, "version": version}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        self.0.schedule_heuristic_reevaluation();
        Ok(value)
    }

    pub async fn get(&self, id: HeuristicId) -> Result<Heuristic> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, version, source, source_kind, enabled, required_features_json, maximum_steps, created_at, updated_at FROM heuristics WHERE id = ?1 AND deleted_at IS NULL",
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| heuristic_from_row(&row))
            .transpose()?
            .ok_or_else(|| not_found("heuristic", id))
    }

    pub async fn list(&self) -> Result<Vec<Heuristic>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, version, source, source_kind, enabled, required_features_json, maximum_steps, created_at, updated_at FROM heuristics WHERE deleted_at IS NULL ORDER BY created_at, id",
                (),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(heuristic_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn remove(&self, id: HeuristicId) -> Result<()> {
        let existing = self.get(id).await?;
        if crate::security::is_builtin_native(&existing) {
            return Err(BackendError::Conflict(
                "native built-in security evidence cannot be removed".into(),
            ));
        }
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "UPDATE heuristics SET enabled = 0, deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND deleted_at IS NULL",
                (now, id.to_string()),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("heuristic", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "heuristic_removed",
            id.to_string(),
            json!({"heuristic_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub async fn evaluate_message(&self, message_id: MessageId) -> Result<Vec<HeuristicFinding>> {
        let programs = self.load_enabled_programs().await?;
        let message = self.0.messages().get(message_id).await?;
        self.evaluate_loaded_with_programs(&programs, &message)
            .await
    }

    pub(crate) async fn evaluate_loaded_messages(
        &self,
        messages: &[Message],
    ) -> Result<Vec<HeuristicFinding>> {
        let programs = self.load_enabled_programs().await?;
        let builtin_evaluations = crate::security::evaluate_many(&self.0, messages).await?;
        let contact_revision = self.contact_model_revision().await?;
        let mut all_findings = Vec::new();
        for (message, builtin) in messages.iter().zip(builtin_evaluations) {
            all_findings.extend(
                self.store_builtin_evaluation(message, builtin, contact_revision)
                    .await?,
            );
            for (heuristic, program) in &programs {
                let decision = self.evaluate_program(program, message, None, true).await?;
                all_findings.extend(
                    self.replace_findings(
                        heuristic,
                        message.summary.id,
                        decision.status,
                        decision.detail,
                        decision.findings,
                        decision.evidence_revision,
                        decision.trace,
                    )
                    .await?,
                );
            }
        }
        Ok(all_findings)
    }

    async fn evaluate_loaded_with_programs(
        &self,
        programs: &[(Heuristic, CompiledHeuristic)],
        message: &Message,
    ) -> Result<Vec<HeuristicFinding>> {
        let mut all_findings = self.evaluate_builtin(message).await?;
        for (heuristic, program) in programs {
            let decision = self.evaluate_program(program, message, None, true).await?;
            all_findings.extend(
                self.replace_findings(
                    heuristic,
                    message.summary.id,
                    decision.status,
                    decision.detail,
                    decision.findings,
                    decision.evidence_revision,
                    decision.trace,
                )
                .await?,
            );
        }
        Ok(all_findings)
    }

    pub(crate) async fn evaluate_message_with_decrypted(
        &self,
        message_id: MessageId,
        decrypted: &OpenPgpDecryptedMessage,
    ) -> Result<Vec<HeuristicFinding>> {
        let programs = self.load_enabled_programs().await?;
        let message = self.0.messages().get(message_id).await?;
        let mut all_findings = self.evaluate_builtin(&message).await?;
        for (heuristic, program) in programs {
            let decision = self
                .evaluate_program(&program, &message, Some(decrypted), false)
                .await?;
            all_findings.extend(
                self.replace_findings(
                    &heuristic,
                    message_id,
                    decision.status,
                    decision.detail,
                    decision.findings,
                    decision.evidence_revision,
                    decision.trace,
                )
                .await?,
            );
        }
        Ok(all_findings)
    }

    /// Compile a candidate, count exact outcomes over the local corpus, and
    /// return detailed traces for selected sample messages. This never stores
    /// findings or prompts for decryption.
    pub async fn preview(
        &self,
        heuristic: &NewHeuristic,
        sample_message_ids: &[MessageId],
    ) -> Result<HeuristicPreview> {
        validate_heuristic_input(heuristic)?;
        let program = compile_program(&heuristic.source)?;
        let ids = self.all_message_ids().await?;
        let requested = sample_message_ids.iter().copied().collect::<HashSet<_>>();
        let automatic_samples = requested.is_empty();
        let mut seen_requested = HashSet::new();
        let mut preview = HeuristicPreview {
            evaluated_messages: 0,
            affected_messages: 0,
            finding_count: 0,
            pending_content_messages: 0,
            pending_decryption_messages: 0,
            failed_messages: 0,
            samples: Vec::new(),
        };
        for chunk in ids.chunks(AUTOMATION_MESSAGE_BATCH) {
            for message in self.0.messages().get_many(chunk).await? {
                let message_id = message.summary.id;
                let decision = self
                    .evaluate_program(&program, &message, None, true)
                    .await?;
                preview.evaluated_messages += 1;
                match decision.status {
                    HeuristicEvaluationStatus::Complete => {
                        if !decision.findings.is_empty() {
                            preview.affected_messages += 1;
                        }
                        preview.finding_count += decision.findings.len() as u64;
                    }
                    HeuristicEvaluationStatus::PendingContent => {
                        preview.pending_content_messages += 1
                    }
                    HeuristicEvaluationStatus::PendingDecryption => {
                        preview.pending_decryption_messages += 1
                    }
                    HeuristicEvaluationStatus::NotEvaluatedBudget
                    | HeuristicEvaluationStatus::Failed => preview.failed_messages += 1,
                }
                if requested.contains(&message_id)
                    || (automatic_samples && preview.samples.len() < PREVIEW_SAMPLE_LIMIT)
                {
                    seen_requested.insert(message_id);
                    preview.samples.push(decision.preview(message_id));
                }
            }
        }
        if !automatic_samples && seen_requested.len() != requested.len() {
            let missing = requested
                .difference(&seen_requested)
                .next()
                .copied()
                .expect("different set sizes have a missing value");
            return Err(not_found("message", missing));
        }
        Ok(preview)
    }

    pub async fn reevaluate_stale(&self, limit: usize) -> Result<AutomationReevaluation> {
        let programs = self.load_enabled_programs().await?;
        let contact_revision = self.contact_model_revision().await?;
        let builtin_features = vec![
            "built_in_security".into(),
            format!("contact_model:{contact_revision}"),
        ];
        let mut stale_messages = Vec::new();
        let mut remaining_stale_messages = 0u64;
        let ids = self.all_message_ids().await?;
        for chunk in ids.chunks(AUTOMATION_MESSAGE_BATCH) {
            let evaluations = self.evaluation_records_for_messages(chunk).await?;
            for message in self.0.messages().get_many(chunk).await? {
                let message_id = message.summary.id;
                let builtin = crate::security::definition();
                let builtin_revision = evidence_revision(&message, &builtin_features, false)?;
                let mut stale = heuristic_record_is_stale(
                    evaluations.get(&(builtin.id, message_id)),
                    builtin.version,
                    &builtin_revision,
                );
                for (heuristic, program) in &programs {
                    let prepared = self
                        .prepare_program_message(program, &message, None, true)
                        .await?;
                    stale |= heuristic_record_is_stale(
                        evaluations.get(&(heuristic.id, message_id)),
                        heuristic.version,
                        &prepared.evidence_revision,
                    );
                }
                if !stale {
                    continue;
                }
                if stale_messages.len() >= limit.max(1) {
                    remaining_stale_messages += 1;
                } else {
                    stale_messages.push(message);
                }
            }
        }
        self.evaluate_loaded_messages(&stale_messages).await?;
        Ok(AutomationReevaluation {
            evaluated_messages: stale_messages.len() as u64,
            remaining_stale_messages,
        })
    }

    pub(crate) async fn evaluate_builtin_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<HeuristicFinding>> {
        let message = self.0.messages().get(message_id).await?;
        self.evaluate_builtin(&message).await
    }

    async fn evaluate_builtin(&self, message: &Message) -> Result<Vec<HeuristicFinding>> {
        let evaluation = crate::security::evaluate(&self.0, message).await?;
        let contact_revision = self.contact_model_revision().await?;
        self.store_builtin_evaluation(message, evaluation, contact_revision)
            .await
    }

    async fn store_builtin_evaluation(
        &self,
        message: &Message,
        evaluation: crate::security::NativeEvaluation,
        contact_revision: i64,
    ) -> Result<Vec<HeuristicFinding>> {
        let heuristic = crate::security::definition();
        let revision = evidence_revision(
            message,
            &[
                "built_in_security".into(),
                format!("contact_model:{contact_revision}"),
            ],
            false,
        )?;
        let trace = vec![HeuristicTraceStep {
            sequence: 0,
            kind: "built_in_security".into(),
            expression: None,
            outcome: Some(!evaluation.findings.is_empty()),
            detail: format!("produced {} finding(s)", evaluation.findings.len()),
        }];
        self.replace_findings(
            &heuristic,
            message.summary.id,
            evaluation.status,
            evaluation.detail,
            evaluation.findings,
            revision,
            trace,
        )
        .await
    }

    async fn contact_model_revision(&self) -> Result<i64> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT COALESCE(max(sequence), 0) FROM changes WHERE kind IN ('contact_added', 'contact_updated', 'contact_removed')",
                (),
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get::<i64>(0))
            .transpose()?
            .unwrap_or(0))
    }

    pub(crate) async fn backfill_builtin(&self, limit: usize) -> Result<(usize, bool)> {
        let limit = limit.clamp(1, 1_000);
        let ids = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    r#"SELECT m.id FROM messages m
                    WHERE NOT EXISTS (
                        SELECT 1 FROM heuristic_evaluations evaluation
                        WHERE evaluation.message_id = m.id
                            AND evaluation.heuristic_id = ?1
                            AND evaluation.heuristic_version = ?2
                    )
                    ORDER BY m.received_at DESC, m.id DESC LIMIT ?3"#,
                    (
                        crate::security::builtin_id().to_string(),
                        i64::from(crate::security::definition().version),
                        i64::try_from(limit).unwrap_or(i64::MAX),
                    ),
                )
                .await?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next().await? {
                ids.push(parse_id::<MessageId>(row.get(0)?, "message")?);
            }
            ids
        };
        for id in &ids {
            self.evaluate_builtin_message(*id).await?;
        }
        let remaining = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    r#"SELECT 1 FROM messages m
                    WHERE NOT EXISTS (
                        SELECT 1 FROM heuristic_evaluations evaluation
                        WHERE evaluation.message_id = m.id
                            AND evaluation.heuristic_id = ?1
                            AND evaluation.heuristic_version = ?2
                    ) LIMIT 1"#,
                    (
                        crate::security::builtin_id().to_string(),
                        i64::from(crate::security::definition().version),
                    ),
                )
                .await?;
            rows.next().await?.is_some()
        };
        Ok((ids.len(), remaining))
    }

    pub(crate) async fn has_enabled(&self) -> Result<bool> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM heuristics WHERE enabled = 1 AND deleted_at IS NULL LIMIT 1",
                (),
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    pub async fn dismiss_finding(&self, id: FindingId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT 1 FROM heuristic_findings WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        if rows.next().await?.is_none() {
            return Err(not_found("heuristic finding", id));
        }
        drop(rows);
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO heuristic_finding_responses(finding_id, dismissed_at) VALUES (?1, ?2) ON CONFLICT(finding_id) DO UPDATE SET dismissed_at = excluded.dismissed_at",
                (id.to_string(), now),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "heuristic_finding_dismissed",
            id.to_string(),
            json!({"finding_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub async fn evaluations(&self, message_id: MessageId) -> Result<Vec<HeuristicEvaluation>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT message_id, heuristic_id, heuristic_version, status, detail, evidence_revision, compiler_version, trace_json, evaluated_at FROM heuristic_evaluations WHERE message_id = ?1 ORDER BY heuristic_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(HeuristicEvaluation {
                message_id: parse_id(row.get::<String>(0)?, "message")?,
                heuristic_id: parse_id(row.get::<String>(1)?, "heuristic")?,
                heuristic_version: database_u32(row.get(2)?, "heuristic version")?,
                status: parse_evaluation_status(&row.get::<String>(3)?)?,
                detail: row.get(4)?,
                evidence_revision: row.get(5)?,
                compiler_version: database_u32(row.get(6)?, "heuristic compiler version")?,
                trace: serde_json::from_str(&row.get::<String>(7)?)?,
                evaluated_at: row.get(8)?,
            });
        }
        Ok(values)
    }

    async fn all_message_ids(&self) -> Result<Vec<MessageId>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query("SELECT id FROM messages ORDER BY received_at, id", ())
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_id(row.get::<String>(0)?, "message")?);
        }
        Ok(ids)
    }

    async fn evaluate_program(
        &self,
        program: &CompiledHeuristic,
        message: &Message,
        decrypted: Option<&OpenPgpDecryptedMessage>,
        allow_cached: bool,
    ) -> Result<HeuristicDecision> {
        let prepared = self
            .prepare_program_message(program, message, decrypted, allow_cached)
            .await?;
        if let Some((status, detail)) = prepared.pending {
            return Ok(HeuristicDecision::pending(
                message.summary.id,
                status,
                prepared.evidence_revision,
                detail,
            ));
        }
        Ok(
            match run_program_traced(program, &prepared.message, prepared.thread_openpgp_required) {
                Ok((findings, trace)) => HeuristicDecision {
                    message_id: message.summary.id,
                    status: HeuristicEvaluationStatus::Complete,
                    detail: None,
                    findings,
                    evidence_revision: prepared.evidence_revision,
                    trace,
                },
                Err((HeuristicRunError::Budget, trace)) => HeuristicDecision {
                    message_id: message.summary.id,
                    status: HeuristicEvaluationStatus::NotEvaluatedBudget,
                    detail: Some("heuristic exceeded its runtime budget".into()),
                    findings: Vec::new(),
                    evidence_revision: prepared.evidence_revision,
                    trace,
                },
                Err((HeuristicRunError::Failed(error), trace)) => HeuristicDecision {
                    message_id: message.summary.id,
                    status: HeuristicEvaluationStatus::Failed,
                    detail: Some(error),
                    findings: Vec::new(),
                    evidence_revision: prepared.evidence_revision,
                    trace,
                },
            },
        )
    }

    async fn prepare_program_message(
        &self,
        program: &CompiledHeuristic,
        message: &Message,
        decrypted: Option<&OpenPgpDecryptedMessage>,
        allow_cached: bool,
    ) -> Result<PreparedHeuristicMessage> {
        let needs_decryption = program.required_features.iter().any(|feature| {
            matches!(
                feature.as_str(),
                "body_text" | "attachments" | "links" | "protected_headers"
            )
        });
        let needs_download = program
            .required_features
            .iter()
            .any(|feature| matches!(feature.as_str(), "body_text" | "attachments" | "links"));
        let encrypted = message.openpgp.encryption != OpenPgpEncryptionStatus::NotEncrypted;
        let mut decrypted_owned = None;
        if needs_decryption && encrypted && decrypted.is_none() && allow_cached {
            decrypted_owned = self
                .0
                .openpgp()
                .load_cached_decrypted(message.summary.id)
                .await?;
        }
        let decrypted = decrypted.or(decrypted_owned.as_ref());
        let projected = project_decrypted_message(message, decrypted, &self.0);
        let thread_openpgp_required = if program
            .required_features
            .iter()
            .any(|feature| feature == "thread_security")
        {
            self.thread_openpgp_required(message.summary.thread_id)
                .await?
        } else {
            false
        };
        let evidence_revision = evidence_revision(
            &projected,
            &program.required_features,
            thread_openpgp_required,
        )?;
        let pending = if needs_decryption
            && encrypted
            && decrypted.is_none()
            && message.summary.content_availability != MessageContentAvailability::Complete
        {
            Some((
                HeuristicEvaluationStatus::PendingContent,
                "requires the complete encrypted message before decryption",
            ))
        } else if needs_decryption && encrypted && decrypted.is_none() {
            Some((
                HeuristicEvaluationStatus::PendingDecryption,
                "requires authenticated decrypted message content",
            ))
        } else if needs_download
            && message.summary.content_availability != MessageContentAvailability::Complete
        {
            Some((
                HeuristicEvaluationStatus::PendingContent,
                "requires a complete locally downloaded message",
            ))
        } else {
            None
        };
        Ok(PreparedHeuristicMessage {
            message: projected,
            thread_openpgp_required,
            evidence_revision,
            pending,
        })
    }

    async fn thread_openpgp_required(&self, thread_id: crate::ThreadId) -> Result<bool> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT openpgp_encryption_required FROM threads WHERE id = ?1",
                (thread_id.to_string(),),
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get::<bool>(0))
            .transpose()?
            .unwrap_or(false))
    }

    async fn evaluation_records_for_messages(
        &self,
        message_ids: &[MessageId],
    ) -> Result<HashMap<(HeuristicId, MessageId), (u32, String, u32)>> {
        if message_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", message_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                format!(
                    "SELECT heuristic_id, message_id, heuristic_version, evidence_revision, compiler_version FROM heuristic_evaluations WHERE message_id IN ({placeholders})"
                ),
                params_from_iter(
                    message_ids
                        .iter()
                        .map(|id| Value::Text(id.to_string()))
                        .collect::<Vec<_>>(),
                ),
            )
            .await?;
        let mut evaluations = HashMap::new();
        while let Some(row) = rows.next().await? {
            evaluations.insert(
                (
                    parse_id(row.get::<String>(0)?, "heuristic")?,
                    parse_id(row.get::<String>(1)?, "message")?,
                ),
                (
                    database_u32(row.get(2)?, "heuristic version")?,
                    row.get(3)?,
                    database_u32(row.get(4)?, "heuristic compiler version")?,
                ),
            );
        }
        Ok(evaluations)
    }

    async fn load_enabled_programs(&self) -> Result<Vec<(Heuristic, CompiledHeuristic)>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, version, source, source_kind, enabled, required_features_json, maximum_steps, created_at, updated_at, compiled_json FROM heuristics WHERE enabled = 1 AND deleted_at IS NULL AND source != ?1 ORDER BY id",
                (crate::security::definition().source,),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let heuristic = heuristic_from_row(&row)?;
            let program = serde_json::from_str(&row.get::<String>(10)?)?;
            values.push((heuristic, program));
        }
        Ok(values)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn replace_findings(
        &self,
        heuristic: &Heuristic,
        message_id: MessageId,
        status: HeuristicEvaluationStatus,
        detail: Option<String>,
        findings: Vec<crate::heuristic::ProducedFinding>,
        evidence_revision: String,
        trace: Vec<HeuristicTraceStep>,
    ) -> Result<Vec<HeuristicFinding>> {
        let now = Utc::now().timestamp();
        let mut values = Vec::with_capacity(findings.len());
        let mut finding_ids = HashSet::new();
        for finding in findings {
            let identity = serde_json::to_vec(&json!({
                "message_id": message_id,
                "heuristic_id": heuristic.id,
                "heuristic_version": heuristic.version,
                "code": &finding.code,
                "target_kind": finding.target_kind,
                "target_id": &finding.target_id,
                "evidence": &finding.evidence,
            }))?;
            let id = FindingId::from_uuid(Uuid::new_v5(&heuristic.id.as_uuid(), &identity));
            if !finding_ids.insert(id) {
                continue;
            }
            values.push(HeuristicFinding {
                id,
                message_id,
                heuristic_id: heuristic.id,
                heuristic_version: heuristic.version,
                code: finding.code,
                presentation: finding.presentation,
                severity: finding.severity,
                target_kind: finding.target_kind,
                target_id: finding.target_id,
                text: finding.text,
                evidence: finding.evidence,
                source_kind: heuristic.source_kind,
                created_at: now,
                dismissed_at: None,
            });
        }
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT version, enabled, deleted_at FROM heuristics WHERE id = ?1",
                (heuristic.id.to_string(),),
            )
            .await?;
        let Some(current) = rows.next().await? else {
            transaction.rollback().await?;
            return Ok(Vec::new());
        };
        if database_u32(current.get(0)?, "heuristic version")? != heuristic.version
            || !current.get::<bool>(1)?
            || current.get::<Option<i64>>(2)?.is_some()
        {
            drop(rows);
            transaction.rollback().await?;
            return Ok(Vec::new());
        }
        drop(rows);
        let mut rows = transaction
            .query(
                "SELECT id FROM heuristic_findings WHERE message_id = ?1 AND heuristic_id = ?2",
                (message_id.to_string(), heuristic.id.to_string()),
            )
            .await?;
        let mut obsolete = HashSet::new();
        while let Some(row) = rows.next().await? {
            obsolete.insert(row.get::<String>(0)?);
        }
        drop(rows);
        for finding in &values {
            obsolete.remove(&finding.id.to_string());
            transaction
                .execute(
                    "INSERT INTO heuristic_findings(id, message_id, heuristic_id, heuristic_version, code, presentation, severity, target_kind, target_id, text, evidence_json, source_kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) ON CONFLICT(id) DO UPDATE SET presentation = excluded.presentation, severity = excluded.severity, text = excluded.text, source_kind = excluded.source_kind",
                    turso::params![
                        finding.id.to_string(),
                        finding.message_id.to_string(),
                        finding.heuristic_id.to_string(),
                        i64::from(finding.heuristic_version),
                        finding.code.clone(),
                        presentation_text(finding.presentation),
                        severity_text(finding.severity),
                        target_kind_text(finding.target_kind),
                        finding.target_id.clone(),
                        finding.text.clone(),
                        serde_json::to_string(&finding.evidence)?,
                        source_kind_text(finding.source_kind),
                        finding.created_at,
                    ],
                )
                .await?;
        }
        for id in obsolete {
            transaction
                .execute("DELETE FROM heuristic_findings WHERE id = ?1", (id,))
                .await?;
        }
        transaction
            .execute(
                "INSERT INTO heuristic_evaluations(message_id, heuristic_id, heuristic_version, status, detail, evidence_revision, compiler_version, trace_json, evaluated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(message_id, heuristic_id) DO UPDATE SET heuristic_version = excluded.heuristic_version, status = excluded.status, detail = excluded.detail, evidence_revision = excluded.evidence_revision, compiler_version = excluded.compiler_version, trace_json = excluded.trace_json, evaluated_at = excluded.evaluated_at",
                turso::params![
                    message_id.to_string(),
                    heuristic.id.to_string(),
                    i64::from(heuristic.version),
                    evaluation_status_text(status),
                    detail.clone(),
                    evidence_revision.clone(),
                    i64::from(HEURISTIC_COMPILER_VERSION),
                    serde_json::to_string(&trace)?,
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "heuristic_evaluated",
            message_id.to_string(),
            json!({
                "message_id": message_id,
                "heuristic_id": heuristic.id,
                "heuristic_version": heuristic.version,
                "status": status,
                "finding_count": values.len(),
                "detail": detail,
                "evidence_revision": evidence_revision,
                "compiler_version": HEURISTIC_COMPILER_VERSION,
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(values)
    }
}

fn filter_sql_predicate(
    conditions: &[FilterCondition],
    outcome: FilterSqlOutcome,
) -> Result<(String, Vec<Value>)> {
    let encrypted = "COALESCE(json_extract(opme.evidence_json, '$.encryption'), 'not_encrypted') != 'not_encrypted'";
    let decrypt_pending = |condition: &FilterCondition| {
        if filter_condition_needs_protected_content(condition) {
            format!(
                "({encrypted} AND odm.message_id IS NULL AND m.content_availability = 'complete')"
            )
        } else {
            "0".into()
        }
    };
    let content_pending = |condition: &FilterCondition| {
        let mut clauses = Vec::new();
        if filter_condition_needs_protected_content(condition) {
            clauses.push(format!(
                "({encrypted} AND odm.message_id IS NULL AND m.content_availability != 'complete')"
            ));
        }
        if filter_condition_needs_downloaded_content(condition) {
            clauses.push(format!(
                "(NOT ({encrypted}) AND m.content_availability != 'complete')"
            ));
        }
        if clauses.is_empty() {
            "0".into()
        } else {
            format!("({})", clauses.join(" OR "))
        }
    };

    let mut parameters = Vec::new();
    let mut clauses = Vec::with_capacity(conditions.len());
    let mut decrypt_pending_clauses = Vec::new();
    let mut content_pending_clauses = Vec::new();
    for condition in conditions {
        let expression = match condition {
            FilterCondition::SenderAddressEquals { value } => {
                parameters.push(Value::Text(value.clone()));
                "lower(COALESCE(CASE WHEN odm.message_id IS NOT NULL THEN odm.from_address ELSE m.from_address END, '')) = lower(?)".into()
            }
            FilterCondition::SenderDomainEquals { value } => {
                parameters.push(Value::Text(value.clone()));
                "instr(COALESCE(CASE WHEN odm.message_id IS NOT NULL THEN odm.from_address ELSE m.from_address END, ''), '@') > 0 AND lower(substr(COALESCE(CASE WHEN odm.message_id IS NOT NULL THEN odm.from_address ELSE m.from_address END, ''), instr(COALESCE(CASE WHEN odm.message_id IS NOT NULL THEN odm.from_address ELSE m.from_address END, ''), '@') + 1)) = lower(?)".into()
            }
            FilterCondition::SubjectContains { value } => {
                parameters.push(Value::Text(value.clone()));
                "instr(lower(COALESCE(CASE WHEN odm.message_id IS NOT NULL THEN odm.subject ELSE m.subject END, '')), lower(?)) > 0".into()
            }
            FilterCondition::BodyContains { value } => {
                parameters.push(Value::Text(value.clone()));
                "instr(lower(COALESCE(odm.body_text, m.body_text, '')), lower(?)) > 0".into()
            }
            FilterCondition::HasAttachment { value } => format!(
                "COALESCE(odm.has_attachment, m.has_attachment) = {}",
                i64::from(*value)
            ),
            FilterCondition::AttachmentDeclaredType { value } => {
                parameters.push(Value::Text(value.clone()));
                parameters.push(Value::Text(value.clone()));
                "((odm.message_id IS NOT NULL AND EXISTS (SELECT 1 FROM json_each(odm.attachments_json) da WHERE lower(json_extract(da.value, '$.declared_media_type')) = lower(?))) OR (odm.message_id IS NULL AND EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id AND lower(a.declared_media_type) = lower(?))))".into()
            }
            FilterCondition::SizeAtLeast { bytes } => {
                parameters.push(Value::Integer(i64::try_from(*bytes).map_err(|_| {
                    BackendError::InvalidInput("filter byte size exceeds database range".into())
                })?));
                "m.size_bytes >= ?".into()
            }
            FilterCondition::SizeAtMost { bytes } => {
                parameters.push(Value::Integer(i64::try_from(*bytes).map_err(|_| {
                    BackendError::InvalidInput("filter byte size exceeds database range".into())
                })?));
                "m.size_bytes <= ?".into()
            }
            FilterCondition::DeliveredTo { address } => {
                parameters.push(Value::Text(address.clone()));
                "EXISTS (SELECT 1 FROM json_each(m.delivered_to_addresses) WHERE lower(value) = lower(?))".into()
            }
            FilterCondition::Account { id } => {
                parameters.push(Value::Text(id.to_string()));
                "EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.account_id = ?)".into()
            }
            FilterCondition::DeliveryFolder { id } => {
                parameters.push(Value::Text(id.to_string()));
                "EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.folder_id = ?)".into()
            }
        };
        let decryption = decrypt_pending(condition);
        let content = content_pending(condition);
        clauses.push(match outcome {
            FilterSqlOutcome::Matched => {
                format!("(NOT ({decryption}) AND NOT ({content}) AND ({expression}))")
            }
            FilterSqlOutcome::PendingContent | FilterSqlOutcome::PendingDecryption => {
                format!("(({decryption}) OR ({content}) OR ({expression}))")
            }
        });
        decrypt_pending_clauses.push(decryption);
        content_pending_clauses.push(content);
    }
    if conditions.is_empty() {
        return Ok((
            if matches!(outcome, FilterSqlOutcome::Matched) {
                "1".into()
            } else {
                "0".into()
            },
            parameters,
        ));
    }
    let viable = clauses.join(" AND ");
    let any_decryption = decrypt_pending_clauses.join(" OR ");
    let any_content = content_pending_clauses.join(" OR ");
    let predicate = match outcome {
        FilterSqlOutcome::Matched => viable,
        FilterSqlOutcome::PendingDecryption => {
            format!("({viable}) AND ({any_decryption})")
        }
        FilterSqlOutcome::PendingContent => {
            format!("({viable}) AND NOT ({any_decryption}) AND ({any_content})")
        }
    };
    Ok((predicate, parameters))
}

fn filter_affected_sql(actions: &[FilterAction]) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut parameters = Vec::new();
    for action in actions {
        match action {
            FilterAction::AddToLocalFolder { folder_id } => {
                clauses.push("NOT EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = ?)");
                parameters.push(Value::Text(folder_id.to_string()));
            }
            FilterAction::RemoveFromLocalFolder { folder_id } => {
                clauses.push("EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = ?)");
                parameters.push(Value::Text(folder_id.to_string()));
            }
            FilterAction::MoveToLocalFolder { folder_id } => {
                clauses.push("(NOT EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id = ?) OR EXISTS (SELECT 1 FROM local_folder_memberships lm WHERE lm.message_id = m.id AND lm.folder_id != ?))");
                parameters.push(Value::Text(folder_id.to_string()));
                parameters.push(Value::Text(folder_id.to_string()));
            }
            FilterAction::MoveToRemoteFolder {
                source_folder_id, ..
            }
            | FilterAction::TrashRemote { source_folder_id }
            | FilterAction::DeleteRemote { source_folder_id } => {
                clauses.push("EXISTS (SELECT 1 FROM message_instances mi WHERE mi.message_id = m.id AND mi.folder_id = ?)");
                parameters.push(Value::Text(source_folder_id.to_string()));
            }
            FilterAction::Stop => {}
        }
    }
    (
        if clauses.is_empty() {
            "0".into()
        } else {
            clauses.join(" OR ")
        },
        parameters,
    )
}

async fn message_remote_account_on(
    connection: &turso::Connection,
    message_id: MessageId,
    folder_id: FolderId,
) -> Result<crate::AccountId> {
    let mut rows = connection
        .query(
            "SELECT account_id FROM message_instances WHERE message_id = ?1 AND folder_id = ?2 ORDER BY uid_validity DESC, imap_uid DESC",
            (message_id.to_string(), folder_id.to_string()),
        )
        .await?;
    let account_id = rows
        .next()
        .await?
        .ok_or_else(|| BackendError::NotFound {
            entity: "remote message instance",
            id: format!("{message_id}@{folder_id}"),
        })?
        .get::<String>(0)?;
    if rows.next().await?.is_some() {
        return Err(BackendError::Conflict(
            "message has more than one instance in the source mailbox".into(),
        ));
    }
    parse_id(account_id, "account")
}

fn parse_mutation_status_for_undo(value: &str) -> Result<ImapMutationStatus> {
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

async fn validate_filter_rule(backend: &Backend, rule: &NewFilterRule) -> Result<()> {
    require_name("filter rule", &rule.name)?;
    if rule.conditions.len() > 256 {
        return Err(BackendError::InvalidInput(
            "filter rules may contain at most 256 conditions".into(),
        ));
    }
    if rule.actions.len() > 256 {
        return Err(BackendError::InvalidInput(
            "filter rules may contain at most 256 actions".into(),
        ));
    }
    // An empty conjunction is a useful explicit catch-all. A Stop-only rule is
    // likewise a useful exemption barrier before a lower-priority catch-all.
    if rule.actions.is_empty() {
        return Err(BackendError::InvalidInput(
            "filter rule requires at least one action".into(),
        ));
    }
    if let Some(position) = rule
        .actions
        .iter()
        .position(|action| matches!(action, FilterAction::Stop))
    {
        if position + 1 != rule.actions.len() {
            return Err(BackendError::InvalidInput(
                "Stop must be the final filter action".into(),
            ));
        }
    }
    let mut local_folders = HashSet::new();
    let mut remote_sources = HashSet::new();
    let mut remote_moves = Vec::new();
    for action in &rule.actions {
        match action {
            FilterAction::AddToLocalFolder { folder_id }
            | FilterAction::RemoveFromLocalFolder { folder_id }
            | FilterAction::MoveToLocalFolder { folder_id } => {
                local_folders.insert(*folder_id);
            }
            FilterAction::MoveToRemoteFolder {
                source_folder_id,
                destination_folder_id,
            } => {
                if !remote_sources.insert(*source_folder_id) {
                    return Err(BackendError::InvalidInput(
                        "a filter rule can queue only one remote action for each source mailbox"
                            .into(),
                    ));
                }
                remote_moves.push((*source_folder_id, *destination_folder_id));
            }
            FilterAction::TrashRemote { source_folder_id }
            | FilterAction::DeleteRemote { source_folder_id } => {
                if !remote_sources.insert(*source_folder_id) {
                    return Err(BackendError::InvalidInput(
                        "a filter rule can queue only one remote action for each source mailbox"
                            .into(),
                    ));
                }
            }
            FilterAction::Stop => {}
        }
    }
    let connection = backend.inner.connection.lock().await;
    for source in &remote_sources {
        if !rule.conditions.iter().any(
            |condition| matches!(condition, FilterCondition::DeliveryFolder { id } if id == source),
        ) {
            return Err(BackendError::InvalidInput(
                "remote filter actions require a matching DeliveryFolder condition for their exact source mailbox"
                    .into(),
            ));
        }
    }
    for folder_id in local_folders {
        let mut rows = connection
            .query(
                "SELECT kind FROM folders WHERE id = ?1",
                (folder_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(not_found("folder", folder_id));
        };
        if row.get::<String>(0)? != "local" {
            return Err(BackendError::InvalidInput(
                "filter placement actions require local folders".into(),
            ));
        }
    }
    for folder_id in remote_sources {
        let mut rows = connection
            .query(
                "SELECT kind, account_id FROM folders WHERE id = ?1",
                (folder_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(not_found("folder", folder_id));
        };
        if row.get::<String>(0)? != "remote" || row.get::<Option<String>>(1)?.is_none() {
            return Err(BackendError::InvalidInput(
                "remote filter actions require a remote source folder".into(),
            ));
        }
    }
    for (source, destination) in remote_moves {
        if source == destination {
            return Err(BackendError::InvalidInput(
                "remote filter source and destination must differ".into(),
            ));
        }
        let mut rows = connection
            .query(
                "SELECT source.account_id, destination.account_id, destination.kind FROM folders source JOIN folders destination ON destination.id = ?2 WHERE source.id = ?1",
                (source.to_string(), destination.to_string()),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(not_found("destination folder", destination));
        };
        if row.get::<Option<String>>(0)? != row.get::<Option<String>>(1)?
            || row.get::<String>(2)? != "remote"
        {
            return Err(BackendError::InvalidInput(
                "remote filter moves must remain within one IMAP account".into(),
            ));
        }
    }
    for condition in &rule.conditions {
        match condition {
            FilterCondition::SenderAddressEquals { value }
            | FilterCondition::DeliveredTo { address: value } => {
                if !valid_address(value) {
                    return Err(BackendError::InvalidInput(
                        "filter condition contains an invalid email address".into(),
                    ));
                }
            }
            FilterCondition::SenderDomainEquals { value } => {
                if value.trim().is_empty()
                    || value.contains('@')
                    || value.chars().any(char::is_whitespace)
                    || !value.is_ascii()
                    || value
                        .bytes()
                        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-'))
                {
                    return Err(BackendError::InvalidInput(
                        "filter condition contains an invalid domain".into(),
                    ));
                }
            }
            FilterCondition::SubjectContains { value }
            | FilterCondition::BodyContains { value }
            | FilterCondition::AttachmentDeclaredType { value }
                if value.is_empty() =>
            {
                return Err(BackendError::InvalidInput(
                    "filter string conditions cannot be empty".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn filter_matches(condition: &FilterCondition, message: &Message) -> bool {
    match condition {
        FilterCondition::SenderAddressEquals { value } => message
            .summary
            .from_address
            .as_deref()
            .is_some_and(|address| address.eq_ignore_ascii_case(value)),
        FilterCondition::SenderDomainEquals { value } => message
            .summary
            .from_address
            .as_deref()
            .and_then(|address| address.split_once('@').map(|(_, domain)| domain))
            .is_some_and(|domain| domain.eq_ignore_ascii_case(value)),
        FilterCondition::SubjectContains { value } => message
            .summary
            .subject
            .as_deref()
            .is_some_and(|subject| contains_case_insensitive(subject, value)),
        FilterCondition::BodyContains { value } => {
            contains_case_insensitive(&message.body_text, value)
        }
        FilterCondition::HasAttachment { value } => message.summary.has_attachment == *value,
        FilterCondition::AttachmentDeclaredType { value } => {
            message.attachments.iter().any(|item| {
                item.declared_media_type
                    .as_deref()
                    .is_some_and(|media_type| media_type.eq_ignore_ascii_case(value))
            })
        }
        FilterCondition::SizeAtLeast { bytes } => message.summary.size_bytes >= *bytes,
        FilterCondition::SizeAtMost { bytes } => message.summary.size_bytes <= *bytes,
        FilterCondition::DeliveredTo { address } => message
            .delivered_to_addresses
            .iter()
            .any(|value| value.eq_ignore_ascii_case(address)),
        FilterCondition::Account { id } => {
            message.instances.iter().any(|item| item.account_id == *id)
        }
        FilterCondition::DeliveryFolder { id } => {
            message.instances.iter().any(|item| item.folder_id == *id)
        }
    }
}

fn filter_condition_needs_downloaded_content(condition: &FilterCondition) -> bool {
    matches!(
        condition,
        FilterCondition::BodyContains { .. } | FilterCondition::AttachmentDeclaredType { .. }
    )
}

fn filter_condition_needs_protected_content(condition: &FilterCondition) -> bool {
    matches!(
        condition,
        FilterCondition::SenderAddressEquals { .. }
            | FilterCondition::SenderDomainEquals { .. }
            | FilterCondition::SubjectContains { .. }
            | FilterCondition::BodyContains { .. }
            | FilterCondition::HasAttachment { .. }
            | FilterCondition::AttachmentDeclaredType { .. }
    )
}

fn filter_required_features(conditions: &[FilterCondition]) -> Vec<String> {
    let mut features = std::collections::BTreeSet::new();
    for condition in conditions {
        let feature = match condition {
            FilterCondition::SenderAddressEquals { .. }
            | FilterCondition::SenderDomainEquals { .. }
            | FilterCondition::SubjectContains { .. }
            | FilterCondition::HasAttachment { .. } => "protected_headers",
            FilterCondition::SizeAtLeast { .. }
            | FilterCondition::SizeAtMost { .. }
            | FilterCondition::DeliveredTo { .. } => "headers",
            FilterCondition::BodyContains { .. } => "body_text",
            FilterCondition::AttachmentDeclaredType { .. } => "attachments",
            FilterCondition::Account { .. } | FilterCondition::DeliveryFolder { .. } => "delivery",
        };
        features.insert(feature.into());
    }
    features.into_iter().collect()
}

fn project_decrypted_message(
    message: &Message,
    decrypted: Option<&OpenPgpDecryptedMessage>,
    backend: &Backend,
) -> Message {
    let Some(decrypted) = decrypted else {
        return message.clone();
    };
    let mut projected = message.clone();
    projected.summary.subject = decrypted.subject.clone();
    projected.summary.from_address = decrypted.from_address.clone();
    projected.summary.has_attachment = !decrypted.attachments.is_empty();
    projected.body_text = decrypted.body_text.clone();
    projected.body_html = None;
    projected.to_addresses = decrypted.to_addresses.clone();
    projected.cc_addresses = decrypted.cc_addresses.clone();
    projected.attachments = decrypted.attachments.clone();
    projected.links =
        crate::mime::extract_plain_text_links(&decrypted.body_text, &backend.inner.config.limits);
    projected.openpgp = decrypted.security.clone();
    projected
}

fn evidence_revision(
    message: &Message,
    features: &[String],
    thread_openpgp_required: bool,
) -> Result<String> {
    let mut evidence = serde_json::Map::new();
    let encrypted = message.openpgp.encryption != OpenPgpEncryptionStatus::NotEncrypted;
    let encrypted_identity = || {
        json!({
            "immutable_message_id": message.summary.id,
            "openpgp": message.openpgp,
        })
    };
    evidence.insert("message_id".into(), json!(message.summary.id));
    evidence.insert(
        "content_availability".into(),
        json!(message.summary.content_availability),
    );
    for feature in features {
        let value = match feature.as_str() {
            "headers" => json!({
                "subject": message.summary.subject,
                "from_address": message.summary.from_address,
                "from_name": message.summary.from_name,
                "size_bytes": message.summary.size_bytes,
                "has_attachment": message.summary.has_attachment,
                "delivered_to": message.delivered_to_addresses,
            }),
            "protected_headers" if encrypted => encrypted_identity(),
            "protected_headers" => {
                json!({
                    "subject": message.summary.subject,
                    "from_address": message.summary.from_address,
                    "from_name": message.summary.from_name,
                    "has_attachment": message.summary.has_attachment,
                })
            }
            "delivery" => json!(message.instances),
            "authentication" => json!(message.dkim),
            "delivery_authentication" => json!(message.delivery_authentication),
            "openpgp" => json!(message.openpgp),
            "spam" => json!({
                "inbox_class": message.summary.inbox_class,
                "user": message.user_classification,
                "provider": message.provider_spam,
                "local": message.local_spam,
            }),
            "thread_security" => json!({
                "membership": message.threading,
                "openpgp_required": thread_openpgp_required,
            }),
            "body_text" | "attachments" | "links" if encrypted => encrypted_identity(),
            "body_text" => json!({
                "sha256": hex::encode(Sha256::digest(message.body_text.as_bytes())),
                "bytes": message.body_text.len(),
            }),
            "attachments" => json!(message.attachments),
            "links" => json!(message.links),
            "built_in_security" => json!({
                "headers": {
                    "subject": message.summary.subject,
                    "from_address": message.summary.from_address,
                    "from_name": message.summary.from_name,
                },
                "body_sha256": hex::encode(Sha256::digest(message.body_text.as_bytes())),
                "attachments": message.attachments,
                "links": message.links,
                "dkim": message.dkim,
                "delivery_authentication": message.delivery_authentication,
                "openpgp": message.openpgp,
                "spam": {
                    "user": message.user_classification,
                    "provider": message.provider_spam,
                    "local": message.local_spam,
                },
                "threading": message.threading,
            }),
            _ => json!(null),
        };
        evidence.insert(feature.clone(), value);
    }
    let bytes = serde_json::to_vec(&evidence)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn filter_rule_from_row(row: &turso::Row) -> Result<FilterRule> {
    Ok(FilterRule {
        id: parse_id(row.get::<String>(0)?, "filter rule")?,
        name: row.get(1)?,
        revision: database_u32(row.get(2)?, "filter rule revision")?,
        priority: i32::try_from(row.get::<i64>(3)?).map_err(|_| {
            BackendError::InvalidInput("database contains invalid filter priority".into())
        })?,
        enabled: row.get(4)?,
        conditions: serde_json::from_str(&row.get::<String>(5)?)?,
        actions: serde_json::from_str(&row.get::<String>(6)?)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn heuristic_from_row(row: &turso::Row) -> Result<Heuristic> {
    Ok(Heuristic {
        id: parse_id(row.get::<String>(0)?, "heuristic")?,
        name: row.get(1)?,
        version: database_u32(row.get(2)?, "heuristic version")?,
        source: row.get(3)?,
        source_kind: parse_source_kind(&row.get::<String>(4)?)?,
        enabled: row.get(5)?,
        required_features: serde_json::from_str(&row.get::<String>(6)?)?,
        maximum_steps: database_u32(row.get(7)?, "maximum heuristic steps")?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn validate_heuristic_input(heuristic: &NewHeuristic) -> Result<()> {
    require_name("heuristic", &heuristic.name)
}

fn require_name(entity: &str, name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 200 {
        Err(BackendError::InvalidInput(format!(
            "{entity} name must be 1-200 bytes"
        )))
    } else {
        Ok(())
    }
}

fn valid_address(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value.contains('@') && !value.chars().any(char::is_whitespace)
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    // SQLite's built-in lower()/NOCASE behavior is deliberately ASCII-only.
    // Keep live delivery evaluation identical to preview and replay instead of
    // letting the same rule acquire subtly different Unicode semantics.
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn heuristic_record_is_stale(
    record: Option<&(u32, String, u32)>,
    heuristic_version: u32,
    evidence_revision: &str,
) -> bool {
    record.is_none_or(|(version, revision, compiler_version)| {
        *version != heuristic_version
            || revision != evidence_revision
            || *compiler_version != HEURISTIC_COMPILER_VERSION
    })
}

fn database_u32(value: i64, label: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {label}")))
}

fn database_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {label}")))
}

pub(crate) fn source_kind_text(value: HeuristicSourceKind) -> &'static str {
    match value {
        HeuristicSourceKind::BuiltIn => "built_in",
        HeuristicSourceKind::User => "user",
        HeuristicSourceKind::ThirdParty => "third_party",
    }
}

pub(crate) fn parse_source_kind(value: &str) -> Result<HeuristicSourceKind> {
    match value {
        "built_in" => Ok(HeuristicSourceKind::BuiltIn),
        "user" => Ok(HeuristicSourceKind::User),
        "third_party" => Ok(HeuristicSourceKind::ThirdParty),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid heuristic source kind".into(),
        )),
    }
}

pub(crate) fn presentation_text(value: crate::FindingPresentation) -> &'static str {
    match value {
        crate::FindingPresentation::MessageAnnotation => "message_annotation",
        crate::FindingPresentation::PersistentWarningFooter => "persistent_warning_footer",
        crate::FindingPresentation::OpenInterstitial => "open_interstitial",
        crate::FindingPresentation::LinkInterstitial => "link_interstitial",
        crate::FindingPresentation::AttachmentInterstitial => "attachment_interstitial",
    }
}

pub(crate) fn parse_presentation(value: &str) -> Result<crate::FindingPresentation> {
    match value {
        "message_annotation" => Ok(crate::FindingPresentation::MessageAnnotation),
        "persistent_warning_footer" => Ok(crate::FindingPresentation::PersistentWarningFooter),
        "open_interstitial" => Ok(crate::FindingPresentation::OpenInterstitial),
        "link_interstitial" => Ok(crate::FindingPresentation::LinkInterstitial),
        "attachment_interstitial" => Ok(crate::FindingPresentation::AttachmentInterstitial),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid finding presentation".into(),
        )),
    }
}

pub(crate) fn severity_text(value: crate::FindingSeverity) -> &'static str {
    match value {
        crate::FindingSeverity::Information => "information",
        crate::FindingSeverity::Warning => "warning",
        crate::FindingSeverity::Danger => "danger",
    }
}

pub(crate) fn parse_severity(value: &str) -> Result<crate::FindingSeverity> {
    match value {
        "information" => Ok(crate::FindingSeverity::Information),
        "warning" => Ok(crate::FindingSeverity::Warning),
        "danger" => Ok(crate::FindingSeverity::Danger),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid finding severity".into(),
        )),
    }
}

pub(crate) fn target_kind_text(value: crate::FindingTargetKind) -> &'static str {
    match value {
        crate::FindingTargetKind::Message => "message",
        crate::FindingTargetKind::Link => "link",
        crate::FindingTargetKind::Attachment => "attachment",
    }
}

pub(crate) fn parse_target_kind(value: &str) -> Result<crate::FindingTargetKind> {
    match value {
        "message" => Ok(crate::FindingTargetKind::Message),
        "link" => Ok(crate::FindingTargetKind::Link),
        "attachment" => Ok(crate::FindingTargetKind::Attachment),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid finding target kind".into(),
        )),
    }
}

fn evaluation_status_text(value: HeuristicEvaluationStatus) -> &'static str {
    match value {
        HeuristicEvaluationStatus::Complete => "complete",
        HeuristicEvaluationStatus::PendingContent => "pending_content",
        HeuristicEvaluationStatus::PendingDecryption => "pending_decryption",
        HeuristicEvaluationStatus::NotEvaluatedBudget => "not_evaluated_budget",
        HeuristicEvaluationStatus::Failed => "failed",
    }
}

fn parse_evaluation_status(value: &str) -> Result<HeuristicEvaluationStatus> {
    match value {
        "complete" => Ok(HeuristicEvaluationStatus::Complete),
        "pending_content" => Ok(HeuristicEvaluationStatus::PendingContent),
        "pending_decryption" => Ok(HeuristicEvaluationStatus::PendingDecryption),
        "not_evaluated_budget" => Ok(HeuristicEvaluationStatus::NotEvaluatedBudget),
        "failed" => Ok(HeuristicEvaluationStatus::Failed),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid heuristic evaluation status".into(),
        )),
    }
}

fn automation_status_text(value: AutomationEvaluationStatus) -> &'static str {
    match value {
        AutomationEvaluationStatus::Matched => "matched",
        AutomationEvaluationStatus::NotMatched => "not_matched",
        AutomationEvaluationStatus::PendingContent => "pending_content",
        AutomationEvaluationStatus::PendingDecryption => "pending_decryption",
        AutomationEvaluationStatus::Failed => "failed",
    }
}

fn parse_automation_status(value: &str) -> Result<AutomationEvaluationStatus> {
    match value {
        "matched" => Ok(AutomationEvaluationStatus::Matched),
        "not_matched" => Ok(AutomationEvaluationStatus::NotMatched),
        "pending_content" => Ok(AutomationEvaluationStatus::PendingContent),
        "pending_decryption" => Ok(AutomationEvaluationStatus::PendingDecryption),
        "failed" => Ok(AutomationEvaluationStatus::Failed),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid automation evaluation status".into(),
        )),
    }
}
