use crate::backend::{enqueue_search_on, insert_event, not_found, parse_id};
use crate::heuristic::{compile_program, run_program, CompiledHeuristic, HeuristicRunError};
use crate::{
    Backend, BackendError, FilterAction, FilterCondition, FilterRule, FilterRuleApplication,
    FilterRuleId, FindingId, Heuristic, HeuristicEvaluation, HeuristicEvaluationStatus,
    HeuristicFinding, HeuristicId, HeuristicSourceKind, Message, MessageId, NewFilterRule,
    NewHeuristic, Result,
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

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
        let mut applications = Vec::new();
        for rule in rules {
            if !rule
                .conditions
                .iter()
                .all(|condition| filter_matches(condition, &message))
            {
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
                "SELECT applications.rule_id, applications.rule_revision, applications.message_id, versions.conditions_json, applications.actions_json, applications.applied_at FROM filter_rule_applications applications JOIN filter_rule_versions versions ON versions.rule_id = applications.rule_id AND versions.revision = applications.rule_revision WHERE applications.message_id = ?1 ORDER BY applications.applied_at, applications.rule_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(FilterRuleApplication {
                rule_id: parse_id(row.get::<String>(0)?, "filter rule")?,
                rule_revision: database_u32(row.get(1)?, "filter rule revision")?,
                message_id: parse_id(row.get::<String>(2)?, "message")?,
                conditions: serde_json::from_str(&row.get::<String>(3)?)?,
                actions: serde_json::from_str(&row.get::<String>(4)?)?,
                applied_at: row.get(5)?,
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

        let transaction = connection.transaction().await?;
        let mut placement_changed = false;
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
                FilterAction::Stop => {}
            }
        }
        let actions_json = serde_json::to_string(&rule.actions)?;
        transaction
            .execute(
                "INSERT INTO filter_rule_applications(rule_id, rule_revision, message_id, actions_json, applied_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                turso::params![
                    rule.id.to_string(),
                    i64::from(rule.revision),
                    message_id.to_string(),
                    actions_json,
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
        let _ = self.0.inner.events.send(event);
        Ok(Some(FilterRuleApplication {
            rule_id: rule.id,
            rule_revision: rule.revision,
            message_id,
            conditions: rule.conditions.clone(),
            actions: rule.actions.clone(),
            applied_at: now,
        }))
    }
}

#[derive(Clone)]
pub struct Heuristics(Backend);

impl Heuristics {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
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
        Ok(value)
    }

    pub async fn update(&self, id: HeuristicId, heuristic: NewHeuristic) -> Result<Heuristic> {
        validate_heuristic_input(&heuristic)?;
        let program = compile_program(&heuristic.source)?;
        let existing = self.get(id).await?;
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
        if programs.is_empty() {
            return Ok(Vec::new());
        }
        let message = self.0.messages().get(message_id).await?;
        let mut all_findings = Vec::new();
        for (heuristic, program) in programs {
            let (status, detail, findings) = match run_program(&program, &message) {
                Ok(findings) => (HeuristicEvaluationStatus::Complete, None, findings),
                Err(HeuristicRunError::Budget) => (
                    HeuristicEvaluationStatus::NotEvaluatedBudget,
                    Some("heuristic exceeded its runtime budget".into()),
                    Vec::new(),
                ),
                Err(HeuristicRunError::Failed(error)) => {
                    (HeuristicEvaluationStatus::Failed, Some(error), Vec::new())
                }
            };
            all_findings.extend(
                self.replace_findings(&heuristic, message_id, status, detail, findings)
                    .await?,
            );
        }
        Ok(all_findings)
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
                "SELECT message_id, heuristic_id, heuristic_version, status, detail, evaluated_at FROM heuristic_evaluations WHERE message_id = ?1 ORDER BY heuristic_id",
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
                evaluated_at: row.get(5)?,
            });
        }
        Ok(values)
    }

    async fn load_enabled_programs(&self) -> Result<Vec<(Heuristic, CompiledHeuristic)>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, version, source, source_kind, enabled, required_features_json, maximum_steps, created_at, updated_at, compiled_json FROM heuristics WHERE enabled = 1 AND deleted_at IS NULL ORDER BY id",
                (),
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

    async fn replace_findings(
        &self,
        heuristic: &Heuristic,
        message_id: MessageId,
        status: HeuristicEvaluationStatus,
        detail: Option<String>,
        findings: Vec<crate::heuristic::ProducedFinding>,
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
                "INSERT INTO heuristic_evaluations(message_id, heuristic_id, heuristic_version, status, detail, evaluated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(message_id, heuristic_id) DO UPDATE SET heuristic_version = excluded.heuristic_version, status = excluded.status, detail = excluded.detail, evaluated_at = excluded.evaluated_at",
                turso::params![
                    message_id.to_string(),
                    heuristic.id.to_string(),
                    i64::from(heuristic.version),
                    evaluation_status_text(status),
                    detail.clone(),
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
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(values)
    }
}

async fn validate_filter_rule(backend: &Backend, rule: &NewFilterRule) -> Result<()> {
    require_name("filter rule", &rule.name)?;
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
    let mut folders = HashSet::new();
    for action in &rule.actions {
        let folder_id = match action {
            FilterAction::AddToLocalFolder { folder_id }
            | FilterAction::RemoveFromLocalFolder { folder_id }
            | FilterAction::MoveToLocalFolder { folder_id } => Some(*folder_id),
            FilterAction::Stop => None,
        };
        if let Some(folder_id) = folder_id {
            folders.insert(folder_id);
        }
    }
    let connection = backend.inner.connection.lock().await;
    for folder_id in folders {
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
            .and_then(|address| address.rsplit_once('@').map(|(_, domain)| domain))
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
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn database_u32(value: i64, label: &str) -> Result<u32> {
    u32::try_from(value)
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
        HeuristicEvaluationStatus::NotEvaluatedBudget => "not_evaluated_budget",
        HeuristicEvaluationStatus::Failed => "failed",
    }
}

fn parse_evaluation_status(value: &str) -> Result<HeuristicEvaluationStatus> {
    match value {
        "complete" => Ok(HeuristicEvaluationStatus::Complete),
        "not_evaluated_budget" => Ok(HeuristicEvaluationStatus::NotEvaluatedBudget),
        "failed" => Ok(HeuristicEvaluationStatus::Failed),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid heuristic evaluation status".into(),
        )),
    }
}
