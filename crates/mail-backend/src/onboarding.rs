use crate::backend::{insert_event, SPAM_PREDICATE};
use crate::{
    AccountId, Backend, BackendError, Contact, ContactProvenance, ContactProvenanceKind,
    ContactRelationship, ContactSuggestion, NewContact, NewContactRelationship, RelationshipKind,
    Result, WarmRoute,
};
use chrono::Utc;
use serde_json::json;

#[derive(Clone)]
pub struct Onboarding(Backend);

impl Onboarding {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    /// Suggests the most frequent recent correspondents for one account,
    /// including inbound senders and recipients of the user's outbound mail.
    /// Existing contacts, the user's own identities, spam and prior onboarding
    /// decisions are excluded. The result is intentionally bounded and
    /// contains message-supplied names only as claims.
    pub async fn contact_suggestions(
        &self,
        account_id: AccountId,
        since: i64,
        limit: usize,
    ) -> Result<Vec<ContactSuggestion>> {
        if since <= 0 {
            return Err(BackendError::InvalidInput(
                "contact suggestion start time must be positive Unix seconds".into(),
            ));
        }
        let limit = limit.clamp(1, 100);
        let connection = self.0.inner.connection.lock().await;
        let mut account_rows = connection
            .query(
                "SELECT 1 FROM accounts WHERE id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        if account_rows.next().await?.is_none() {
            return Err(BackendError::NotFound {
                entity: "account",
                id: account_id.to_string(),
            });
        }
        drop(account_rows);
        let sql = format!(
            r#"WITH candidate_messages(address, claimed_name, message_id,
                    received_at, list_message, outbound_message) AS (
                SELECT lower(m.from_address), NULLIF(trim(m.from_name), ''),
                    m.id, m.received_at,
                    CASE WHEN m.list_id IS NOT NULL THEN 1 ELSE 0 END, 0
                FROM messages m
                WHERE m.received_at >= ?1
                  AND m.from_address IS NOT NULL AND trim(m.from_address) != ''
                  AND EXISTS (
                    SELECT 1 FROM message_instances mi
                    WHERE mi.message_id = m.id AND mi.account_id = ?2
                  )
                  AND NOT ({SPAM_PREDICATE})

                UNION ALL

                SELECT lower(trim(recipient.value)), NULL, m.id, m.received_at, 0, 1
                FROM messages m
                JOIN json_each(
                    json_array(m.to_addresses, m.cc_addresses, m.bcc_addresses)
                ) address_arrays
                JOIN json_each(address_arrays.value) recipient
                WHERE m.received_at >= ?1
                  AND trim(recipient.value) != ''
                  AND EXISTS (
                    SELECT 1 FROM message_instances mi
                    WHERE mi.message_id = m.id AND mi.account_id = ?2
                  )
                  AND EXISTS (
                    SELECT 1 FROM account_identities sender_identity
                    WHERE sender_identity.account_id = ?2
                      AND sender_identity.email_address = m.from_address COLLATE NOCASE
                  )
                  AND NOT ({SPAM_PREDICATE})
            )
            SELECT cm.address, MAX(cm.claimed_name),
                COUNT(DISTINCT cm.message_id), MAX(cm.received_at),
                SUM(cm.list_message), SUM(cm.outbound_message)
            FROM candidate_messages cm
            WHERE NOT EXISTS (
                    SELECT 1 FROM contact_addresses ca
                    WHERE ca.address = cm.address COLLATE NOCASE
                )
              AND NOT EXISTS (
                    SELECT 1 FROM account_identities ai
                    WHERE ai.email_address = cm.address COLLATE NOCASE
                )
              AND NOT EXISTS (
                    SELECT 1 FROM onboarding_contact_decisions ocd
                    WHERE ocd.account_id = ?2
                      AND ocd.address = cm.address COLLATE NOCASE
                )
            GROUP BY cm.address
            ORDER BY COUNT(DISTINCT cm.message_id) DESC, MAX(cm.received_at) DESC,
                cm.address
            LIMIT ?3"#
        );
        let mut rows = connection
            .query(
                sql,
                turso::params![since, account_id.to_string(), limit as i64],
            )
            .await?;
        let mut suggestions = Vec::new();
        while let Some(row) = rows.next().await? {
            let address: String = row.get(0)?;
            let claimed_name = row.get(1)?;
            let message_count = row.get::<i64>(2)?.max(0) as u64;
            let latest_received_at = row.get(3)?;
            let list_messages = row.get::<i64>(4)?.max(0) as u64;
            let outbound_messages = row.get::<i64>(5)?.max(0) as u64;
            let automated = looks_automated(&address);
            let list_like = list_messages.saturating_mul(2) >= message_count;
            let (kind, route, obligations, reasons) = if list_like {
                (
                    RelationshipKind::Newsletter,
                    WarmRoute::Fyi,
                    false,
                    vec![format!(
                        "{list_messages} of {message_count} recent messages identify themselves as mailing-list traffic"
                    )],
                )
            } else if outbound_messages > 0 {
                (
                    RelationshipKind::Person,
                    WarmRoute::Action,
                    true,
                    vec![format!(
                        "you wrote to this address in {outbound_messages} recent conversation(s)"
                    )],
                )
            } else if automated {
                (
                    RelationshipKind::AutomatedService,
                    WarmRoute::Fyi,
                    false,
                    vec![
                        "the address looks automated and no recent outgoing correspondence was found"
                            .into(),
                    ],
                )
            } else {
                (
                    RelationshipKind::Person,
                    WarmRoute::Action,
                    true,
                    vec![
                        "no strong mailing-list or automated-sender signal was found; uncertain correspondents stay actionable"
                            .into(),
                    ],
                )
            };
            suggestions.push(ContactSuggestion {
                account_id,
                address,
                claimed_name,
                message_count,
                latest_received_at,
                suggested_kind: kind,
                suggested_warm_route: route,
                suggested_may_create_obligations: obligations,
                suggestion_reasons: reasons,
            });
        }
        Ok(suggestions)
    }

    pub async fn accept_contact(
        &self,
        account_id: AccountId,
        suggested_address: &str,
        contact: NewContact,
        relationship: NewContactRelationship,
    ) -> Result<Contact> {
        let suggested_address = normalize_address(suggested_address)?;
        if !contact.addresses.iter().any(|candidate| {
            normalize_address(&candidate.address).is_ok_and(|address| address == suggested_address)
        }) {
            return Err(BackendError::InvalidInput(
                "accepted onboarding contact must retain the suggested address".into(),
            ));
        }
        let route_is_action = relationship.warm_route == WarmRoute::Action;
        if route_is_action != relationship.may_create_obligations {
            return Err(BackendError::InvalidInput(
                "Warm Action routing and obligation permission must change together".into(),
            ));
        }
        let contact = self
            .0
            .contacts()
            .add_with_provenance(
                contact,
                ContactProvenance {
                    kind: ContactProvenanceKind::OnboardingSuggestion,
                    source_label: Some(format!("account:{account_id}")),
                    imported_at: Some(Utc::now().timestamp()),
                },
            )
            .await?;
        self.0
            .contacts()
            .set_relationship(
                contact.id,
                ContactRelationship {
                    contact_id: contact.id,
                    kind: relationship.kind,
                    warm_route: relationship.warm_route,
                    may_create_obligations: relationship.may_create_obligations,
                    notify: relationship.notify,
                    remote_content: relationship.remote_content,
                    updated_at: 0,
                },
            )
            .await?;
        self.record_decision(account_id, &suggested_address, "accepted")
            .await?;
        Ok(contact)
    }

    pub async fn dismiss_contact(
        &self,
        account_id: AccountId,
        suggested_address: &str,
    ) -> Result<()> {
        let address = normalize_address(suggested_address)?;
        self.record_decision(account_id, &address, "dismissed")
            .await
    }

    async fn record_decision(
        &self,
        account_id: AccountId,
        address: &str,
        decision: &'static str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT 1 FROM accounts WHERE id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        if rows.next().await?.is_none() {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "account",
                id: account_id.to_string(),
            });
        }
        drop(rows);
        transaction
            .execute(
                r#"INSERT INTO onboarding_contact_decisions(
                    account_id, address, decision, decided_at
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(account_id, address) DO UPDATE SET
                    decision = excluded.decision,
                    decided_at = excluded.decided_at"#,
                turso::params![account_id.to_string(), address, decision, now],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "onboarding_contact_decided",
            format!("{account_id}:{address}"),
            json!({
                "account_id": account_id,
                "address": address,
                "decision": decision,
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }
}

fn normalize_address(value: &str) -> Result<String> {
    let value = value.trim().to_lowercase();
    if value.is_empty() || !value.contains('@') || value.len() > 320 {
        return Err(BackendError::InvalidInput(
            "invalid onboarding email address".into(),
        ));
    }
    Ok(value)
}

fn looks_automated(address: &str) -> bool {
    let local = address.split('@').next().unwrap_or_default();
    [
        "no-reply",
        "noreply",
        "do-not-reply",
        "donotreply",
        "notifications",
        "alerts",
        "mailer-daemon",
    ]
    .iter()
    .any(|marker| local.contains(marker))
}
