use crate::backend::{insert_event, not_found};
use crate::{
    AccountId, AccountIdentity, AccountIdentityId, Backend, BackendError, NewAccountIdentity,
    Result,
};
use chrono::Utc;
use serde_json::json;

#[derive(Clone)]
pub struct AccountIdentities(pub(crate) Backend);

impl AccountIdentities {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn add(&self, value: NewAccountIdentity) -> Result<AccountIdentity> {
        let value = normalize_identity(value)?;
        let now = Utc::now().timestamp();
        let id = AccountIdentityId::new();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        require_account_on(&transaction, value.account_id).await?;
        require_openpgp_provider_on(
            &transaction,
            value.account_id,
            value.openpgp_fingerprint.as_deref(),
        )
        .await?;
        let mut rows = transaction
            .query(
                "SELECT COUNT(*) FROM account_identities WHERE account_id = ?1",
                (value.account_id.to_string(),),
            )
            .await?;
        let first = rows
            .next()
            .await?
            .ok_or_else(|| BackendError::InvalidInput("identity count returned no row".into()))?
            .get::<i64>(0)?
            == 0;
        drop(rows);
        let make_default = first || value.is_default;
        if make_default {
            transaction
                .execute(
                    "UPDATE account_identities SET is_default = 0, revision = revision + 1, updated_at = ?1 WHERE account_id = ?2 AND is_default = 1",
                    (now, value.account_id.to_string()),
                )
                .await?;
        }
        transaction
            .execute(
                r#"INSERT INTO account_identities(
                    id, account_id, revision, email_address, display_name,
                    reply_to, openpgp_fingerprint, is_default, created_at, updated_at
                ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?8)"#,
                turso::params![
                    id.to_string(),
                    value.account_id.to_string(),
                    value.email_address,
                    value.display_name,
                    value.reply_to,
                    value.openpgp_fingerprint,
                    make_default,
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "account_identity_created",
            id.to_string(),
            json!({"identity_id": id, "account_id": value.account_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn get(&self, id: AccountIdentityId) -> Result<AccountIdentity> {
        let connection = self.0.inner.connection.lock().await;
        load_identity_on(&connection, id).await
    }

    pub async fn list(&self, account_id: AccountId) -> Result<Vec<AccountIdentity>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT id, account_id, revision, email_address, display_name,
                    reply_to, openpgp_fingerprint, is_default, created_at, updated_at
                FROM account_identities WHERE account_id = ?1
                ORDER BY is_default DESC, created_at, id"#,
                (account_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(identity_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn update(
        &self,
        id: AccountIdentityId,
        expected_revision: u32,
        value: NewAccountIdentity,
    ) -> Result<AccountIdentity> {
        let value = normalize_identity(value)?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let current = load_identity_on(&transaction, id).await?;
        if current.account_id != value.account_id {
            transaction.rollback().await?;
            return Err(BackendError::InvalidInput(
                "an identity cannot be moved between accounts".into(),
            ));
        }
        require_openpgp_provider_on(
            &transaction,
            value.account_id,
            value.openpgp_fingerprint.as_deref(),
        )
        .await?;
        let make_default = current.is_default || value.is_default;
        if value.is_default && !current.is_default {
            transaction
                .execute(
                    "UPDATE account_identities SET is_default = 0, revision = revision + 1, updated_at = ?1 WHERE account_id = ?2 AND is_default = 1",
                    (now, value.account_id.to_string()),
                )
                .await?;
        }
        let changed = transaction
            .execute(
                r#"UPDATE account_identities SET
                    revision = revision + 1, email_address = ?1,
                    display_name = ?2, reply_to = ?3, openpgp_fingerprint = ?4,
                    is_default = ?5, updated_at = ?6
                WHERE id = ?7 AND revision = ?8"#,
                turso::params![
                    value.email_address,
                    value.display_name,
                    value.reply_to,
                    value.openpgp_fingerprint,
                    make_default,
                    now,
                    id.to_string(),
                    i64::from(expected_revision),
                ],
            )
            .await?;
        if changed != 1 {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "account identity changed since it was read".into(),
            ));
        }
        let event = insert_event(
            &transaction,
            now,
            "account_identity_updated",
            id.to_string(),
            json!({"identity_id": id, "revision": expected_revision + 1}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn set_default(&self, id: AccountIdentityId) -> Result<AccountIdentity> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let identity = load_identity_on(&transaction, id).await?;
        transaction
            .execute(
                "UPDATE account_identities SET is_default = 0, revision = revision + 1, updated_at = ?1 WHERE account_id = ?2 AND is_default = 1 AND id != ?3",
                (now, identity.account_id.to_string(), id.to_string()),
            )
            .await?;
        transaction
            .execute(
                "UPDATE account_identities SET is_default = 1, revision = revision + 1, updated_at = ?1 WHERE id = ?2 AND is_default = 0",
                (now, id.to_string()),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "account_identity_default_changed",
            id.to_string(),
            json!({"identity_id": id, "account_id": identity.account_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn remove(&self, id: AccountIdentityId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let identity = load_identity_on(&transaction, id).await?;
        let mut rows = transaction
            .query(
                "SELECT COUNT(*) FROM account_identities WHERE account_id = ?1",
                (identity.account_id.to_string(),),
            )
            .await?;
        let count = rows
            .next()
            .await?
            .expect("COUNT returns a row")
            .get::<i64>(0)?;
        drop(rows);
        let mut rows = transaction
            .query(
                "SELECT 1 FROM smtp_accounts WHERE account_id = ?1",
                (identity.account_id.to_string(),),
            )
            .await?;
        let smtp_configured = rows.next().await?.is_some();
        drop(rows);
        if count == 1 && smtp_configured {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "the final identity cannot be removed while SMTP is configured".into(),
            ));
        }
        transaction
            .execute(
                "DELETE FROM account_identities WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        if identity.is_default {
            transaction
                .execute(
                    "UPDATE account_identities SET is_default = 1, revision = revision + 1, updated_at = ?1 WHERE id = (SELECT id FROM account_identities WHERE account_id = ?2 ORDER BY created_at, id LIMIT 1)",
                    (now, identity.account_id.to_string()),
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "account_identity_removed",
            id.to_string(),
            json!({"identity_id": id, "account_id": identity.account_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub(crate) async fn resolve(
        &self,
        account_id: AccountId,
        identity_id: Option<AccountIdentityId>,
    ) -> Result<AccountIdentity> {
        let connection = self.0.inner.connection.lock().await;
        if let Some(identity_id) = identity_id {
            let identity = load_identity_on(&connection, identity_id).await?;
            if identity.account_id != account_id {
                return Err(BackendError::InvalidInput(
                    "draft identity belongs to a different account".into(),
                ));
            }
            return Ok(identity);
        }
        let mut rows = connection
            .query(
                r#"SELECT id, account_id, revision, email_address, display_name,
                    reply_to, openpgp_fingerprint, is_default, created_at, updated_at
                FROM account_identities WHERE account_id = ?1
                ORDER BY is_default DESC, created_at, id LIMIT 1"#,
                (account_id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| identity_from_row(&row))
            .transpose()?
            .ok_or_else(|| not_found("default account identity", account_id))
    }
}

fn normalize_identity(mut value: NewAccountIdentity) -> Result<NewAccountIdentity> {
    value.email_address = normalize_address(&value.email_address)?;
    value.reply_to = value
        .reply_to
        .as_deref()
        .map(normalize_address)
        .transpose()?;
    value.display_name = normalize_optional_text("identity display name", value.display_name, 256)?;
    value.openpgp_fingerprint = value
        .openpgp_fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .transpose()?;
    Ok(value)
}

pub(crate) fn normalize_address(value: &str) -> Result<String> {
    let value = value.trim();
    let Some((local, domain)) = value.rsplit_once('@') else {
        return Err(BackendError::InvalidInput(
            "invalid identity email address".into(),
        ));
    };
    if local.is_empty()
        || domain.is_empty()
        || local.contains('@')
        || value.len() > 320
        || value.contains(['<', '>', ',', ' '])
        || value.chars().any(char::is_control)
    {
        return Err(BackendError::InvalidInput(
            "invalid identity email address".into(),
        ));
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn normalize_optional_text(
    label: &str,
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>> {
    let value = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if value
        .as_ref()
        .is_some_and(|value| value.len() > maximum || value.chars().any(char::is_control))
    {
        return Err(BackendError::InvalidInput(format!("invalid {label}")));
    }
    Ok(value)
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    let value = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendError::InvalidInput(
            "OpenPGP fingerprint must be 40 or 64 hexadecimal digits".into(),
        ));
    }
    Ok(value)
}

async fn require_account_on(connection: &turso::Connection, account_id: AccountId) -> Result<()> {
    let mut rows = connection
        .query(
            "SELECT 1 FROM accounts WHERE id = ?1",
            (account_id.to_string(),),
        )
        .await?;
    if rows.next().await?.is_none() {
        return Err(not_found("account", account_id));
    }
    Ok(())
}

async fn require_openpgp_provider_on(
    connection: &turso::Connection,
    account_id: AccountId,
    fingerprint: Option<&str>,
) -> Result<()> {
    let Some(fingerprint) = fingerprint else {
        return Ok(());
    };
    let mut rows = connection
        .query(
            "SELECT 1 FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2",
            (account_id.to_string(), fingerprint),
        )
        .await?;
    if rows.next().await?.is_none() {
        return Err(BackendError::InvalidInput(
            "identity OpenPGP key is not a secret-key provider for this account".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn load_identity_on(
    connection: &turso::Connection,
    id: AccountIdentityId,
) -> Result<AccountIdentity> {
    let mut rows = connection
        .query(
            r#"SELECT id, account_id, revision, email_address, display_name,
                reply_to, openpgp_fingerprint, is_default, created_at, updated_at
            FROM account_identities WHERE id = ?1"#,
            (id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| identity_from_row(&row))
        .transpose()?
        .ok_or_else(|| not_found("account identity", id))
}

fn identity_from_row(row: &turso::Row) -> Result<AccountIdentity> {
    Ok(AccountIdentity {
        id: row
            .get::<String>(0)?
            .parse()
            .map_err(|_| BackendError::InvalidInput("invalid account identity ID".into()))?,
        account_id: row
            .get::<String>(1)?
            .parse()
            .map_err(|_| BackendError::InvalidInput("invalid account ID".into()))?,
        revision: u32::try_from(row.get::<i64>(2)?)
            .map_err(|_| BackendError::InvalidInput("invalid identity revision".into()))?,
        email_address: row.get(3)?,
        display_name: row.get(4)?,
        reply_to: row.get(5)?,
        openpgp_fingerprint: row.get(6)?,
        is_default: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

pub(crate) async fn ensure_default_identity_on(
    connection: &turso::Connection,
    account_id: AccountId,
    display_name: &str,
    email_address: &str,
    now: i64,
) -> Result<Option<AccountIdentityId>> {
    let mut rows = connection
        .query(
            "SELECT id FROM account_identities WHERE account_id = ?1 ORDER BY is_default DESC, created_at, id LIMIT 1",
            (account_id.to_string(),),
        )
        .await?;
    if let Some(row) = rows.next().await? {
        let id = row
            .get::<String>(0)?
            .parse()
            .map_err(|_| BackendError::InvalidInput("invalid account identity ID".into()))?;
        return Ok(Some(id));
    }
    drop(rows);
    let Ok(email_address) = normalize_address(email_address) else {
        return Ok(None);
    };
    let display_name =
        normalize_optional_text("identity display name", Some(display_name.to_owned()), 256)?;
    let id = AccountIdentityId::new();
    connection
        .execute(
            r#"INSERT INTO account_identities(
                id, account_id, revision, email_address, display_name,
                reply_to, openpgp_fingerprint, is_default, created_at, updated_at
            ) VALUES (?1, ?2, 1, ?3, ?4, NULL, NULL, 1, ?5, ?5)"#,
            turso::params![
                id.to_string(),
                account_id.to_string(),
                email_address,
                display_name,
                now,
            ],
        )
        .await?;
    Ok(Some(id))
}
