use crate::{AccountId, Backend, BackendError, MessageId, Result};
use chrono::Utc;
use lizard_verified_kernel::{charge_u64, materialize_bytes, reservation_commit_allowed};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use turso::transaction::TransactionBehavior;
use turso::Connection;

const DEFAULT_MINIMUM_FREE_BYTES: u64 = 64 * 1024 * 1024;
const BUDGET_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_AUDIT_ISSUES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageLimits {
    /// Maximum bytes occupied by the complete profile. `None` leaves profile
    /// size bounded only by the filesystem and per-message limits.
    #[serde(default)]
    pub max_profile_bytes: Option<u64>,
    /// Space deliberately kept free so a message download cannot consume the
    /// final bytes needed for database rollback, cleanup, and normal OS use.
    #[serde(default = "default_minimum_free_bytes")]
    pub minimum_free_bytes: u64,
}

const fn default_minimum_free_bytes() -> u64 {
    DEFAULT_MINIMUM_FREE_BYTES
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_profile_bytes: None,
            minimum_free_bytes: default_minimum_free_bytes(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageUsage {
    pub total_bytes: u64,
    pub database_bytes: u64,
    pub blob_bytes: u64,
    pub search_index_bytes: u64,
    pub partial_download_bytes: u64,
    pub credential_bytes: u64,
    pub other_bytes: u64,
    pub available_filesystem_bytes: u64,
    pub profile_quota_bytes: Option<u64>,
    pub minimum_free_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountStorageQuota {
    pub account_id: AccountId,
    pub used_bytes: u64,
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegritySeverity {
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityIssueKind {
    DatabaseIntegrity,
    ForeignKeyViolation,
    MissingBlob,
    CorruptBlob,
    BlobSizeMismatch,
    InvalidBlobPath,
    OrphanBlob,
    AbandonedTemporaryFile,
    PartialDownloadMismatch,
    SearchProjectionMismatch,
    PendingSearchWork,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub severity: IntegritySeverity,
    pub kind: IntegrityIssueKind,
    pub identifier: Option<String>,
    pub detail: String,
    pub repairable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegrityAuditOptions {
    /// Re-read every referenced blob and compare it with its SHA-256 filename.
    /// Disable only for a quick metadata audit.
    pub verify_blob_hashes: bool,
    /// Report unreferenced blobs. They are safe to remove only while the
    /// profile is not being mutated by another process.
    pub report_orphan_blobs: bool,
    /// Bounds report memory without stopping the underlying checks.
    pub max_issues: usize,
}

impl Default for IntegrityAuditOptions {
    fn default() -> Self {
        Self {
            verify_blob_hashes: true,
            report_orphan_blobs: true,
            max_issues: 10_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegrityAuditReport {
    pub started_at: i64,
    pub finished_at: i64,
    pub healthy: bool,
    pub database_integrity_ok: bool,
    pub foreign_key_violations: u64,
    pub referenced_blobs: u64,
    pub blob_files: u64,
    pub verified_blob_bytes: u64,
    pub database_messages: u64,
    pub search_documents: u64,
    pub pending_search_updates: u64,
    pub pending_search_deletions: u64,
    pub issues: Vec<IntegrityIssue>,
    pub omitted_issues: u64,
    pub usage: StorageUsage,
}

#[derive(Clone)]
pub struct Storage(Backend);

impl Storage {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn usage(&self) -> Result<StorageUsage> {
        self.0.inner.storage.measure().await
    }

    pub async fn account_quota(&self, account_id: AccountId) -> Result<AccountStorageQuota> {
        let connection = self.0.inner.connection.lock().await;
        account_quota_on(&connection, account_id).await
    }

    /// Set the downloaded-message budget for an account. Lowering the limit
    /// below current use is allowed; it blocks growth without deleting mail.
    pub async fn set_account_quota(
        &self,
        account_id: AccountId,
        max_bytes: Option<u64>,
    ) -> Result<AccountStorageQuota> {
        let max_database = max_bytes
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    BackendError::InvalidInput(
                        "account storage quota exceeds database range".into(),
                    )
                })
            })
            .transpose()?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT kind FROM accounts WHERE id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "account",
                id: account_id.to_string(),
            });
        };
        if row.get::<String>(0)? != "imap" {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::InvalidInput(
                "downloaded-message quotas apply only to IMAP accounts".into(),
            ));
        }
        drop(rows);
        match max_database {
            Some(limit) => {
                transaction
                    .execute(
                        "INSERT INTO account_storage_quotas(account_id, max_bytes, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(account_id) DO UPDATE SET max_bytes = excluded.max_bytes, updated_at = excluded.updated_at",
                        (account_id.to_string(), limit, now),
                    )
                    .await?;
            }
            None => {
                transaction
                    .execute(
                        "DELETE FROM account_storage_quotas WHERE account_id = ?1",
                        (account_id.to_string(),),
                    )
                    .await?;
            }
        }
        let event = crate::backend::insert_event(
            &transaction,
            now,
            "account_storage_quota_updated",
            account_id.to_string(),
            json!({"account_id": account_id, "max_bytes": max_bytes}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.account_quota(account_id).await
    }

    pub async fn audit(&self, options: IntegrityAuditOptions) -> Result<IntegrityAuditReport> {
        let started_at = Utc::now().timestamp();
        let maximum_issues = options.max_issues.min(MAX_AUDIT_ISSUES);
        let mut collector = IssueCollector::new(maximum_issues);
        let usage = self.usage().await?;

        let (
            database_integrity_ok,
            foreign_key_violations,
            references,
            downloads,
            database_messages,
            pending_search_updates,
            pending_search_deletions,
        ) = {
            let connection = self.0.inner.connection.lock().await;
            let database_integrity_ok =
                audit_database_integrity(&connection, &mut collector).await?;
            let foreign_key_violations = audit_foreign_keys(&connection, &mut collector).await?;
            let references = load_blob_references(&connection, &mut collector).await?;
            let downloads = load_download_states(&connection).await?;
            let database_messages =
                scalar_count(&connection, "SELECT count(*) FROM messages").await?;
            let pending_search_updates =
                scalar_count(&connection, "SELECT count(*) FROM search_index_queue").await?;
            let pending_search_deletions = scalar_count(
                &connection,
                "SELECT count(*) FROM search_index_delete_queue",
            )
            .await?;
            (
                database_integrity_ok,
                foreign_key_violations,
                references,
                downloads,
                database_messages,
                pending_search_updates,
                pending_search_deletions,
            )
        };

        let search_documents = self.0.inner.search_index.num_docs();
        if pending_search_updates != 0 || pending_search_deletions != 0 {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::PendingSearchWork,
                identifier: None,
                detail: format!(
                    "{pending_search_updates} search updates and {pending_search_deletions} deletions are pending"
                ),
                repairable: true,
            });
        }
        if search_documents != database_messages {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::SearchProjectionMismatch,
                identifier: None,
                detail: format!(
                    "Tantivy contains {search_documents} documents while Turso contains {database_messages} messages"
                ),
                repairable: true,
            });
        }

        let blob_audit =
            audit_blob_files(self.0.inner.blobs.root().to_owned(), &references, options).await?;
        let blob_error_count = blob_audit.error_count;
        for issue in blob_audit.issues {
            collector.push(issue);
        }
        audit_partial_downloads(
            &self.0.inner.config.profile_dir.join("downloads"),
            &downloads,
            &mut collector,
        )?;

        collector.omitted = collector.omitted.saturating_add(blob_audit.omitted_issues);
        let healthy = database_integrity_ok
            && foreign_key_violations == 0
            && collector.error_count == 0
            && blob_error_count == 0;
        Ok(IntegrityAuditReport {
            started_at,
            finished_at: Utc::now().timestamp(),
            healthy,
            database_integrity_ok,
            foreign_key_violations,
            referenced_blobs: references.len() as u64,
            blob_files: blob_audit.files,
            verified_blob_bytes: blob_audit.verified_bytes,
            database_messages,
            search_documents,
            pending_search_updates,
            pending_search_deletions,
            issues: collector.issues,
            omitted_issues: collector.omitted,
            usage,
        })
    }

    /// Atomically reserve the as-yet-unmaterialized portion of a remote
    /// message for every account which references it. Reservations are
    /// durable so a crashed synchronization worker cannot let another
    /// download oversubscribe an account quota before the partial is retried.
    pub(crate) async fn reserve_message_capacity(
        &self,
        message_id: MessageId,
        expected_bytes: u64,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        // Reserve the writer before reading counters so concurrent worker
        // processes cannot both validate against the same quota snapshot.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let mut rows = transaction
            .query(
                "SELECT size_bytes, downloaded_bytes FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            drop(rows);
            transaction.rollback().await?;
            return Err(BackendError::NotFound {
                entity: "message",
                id: message_id.to_string(),
            });
        };
        let stored_size =
            u64::try_from(row.get::<i64>(0)?).map_err(|_| invalid_storage_value("message size"))?;
        let downloaded_bytes = u64::try_from(row.get::<i64>(1)?)
            .map_err(|_| invalid_storage_value("downloaded byte count"))?;
        drop(rows);
        if stored_size != expected_bytes || downloaded_bytes > expected_bytes {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "message size changed before storage could be reserved".into(),
            ));
        }
        let desired_bytes = expected_bytes - downloaded_bytes;
        let mut rows = transaction
            .query(
                "SELECT DISTINCT account_id FROM message_instances WHERE message_id = ?1 ORDER BY account_id",
                (message_id.to_string(),),
            )
            .await?;
        let mut account_ids = Vec::new();
        while let Some(row) = rows.next().await? {
            account_ids.push(crate::backend::parse_id::<AccountId>(
                row.get(0)?,
                "account",
            )?);
        }
        drop(rows);
        if account_ids.is_empty() {
            transaction.rollback().await?;
            return Err(BackendError::Conflict(
                "message has no account storage owner".into(),
            ));
        }

        let mut previous = Vec::with_capacity(account_ids.len());
        for account_id in &account_ids {
            let mut rows = transaction
                .query(
                    "SELECT reserved_bytes FROM account_storage_reservations WHERE account_id = ?1 AND message_id = ?2",
                    (account_id.to_string(), message_id.to_string()),
                )
                .await?;
            let old_bytes = rows
                .next()
                .await?
                .map(|row| row.get::<i64>(0))
                .transpose()?
                .map(|value| {
                    u64::try_from(value).map_err(|_| invalid_storage_value("account reservation"))
                })
                .transpose()?
                .unwrap_or(0);
            drop(rows);
            transaction
                .execute(
                    r#"INSERT INTO account_storage_reservations(
                        account_id, message_id, reserved_bytes, updated_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(account_id, message_id) DO UPDATE SET
                        reserved_bytes = excluded.reserved_bytes,
                        updated_at = excluded.updated_at"#,
                    (
                        account_id.to_string(),
                        message_id.to_string(),
                        i64::try_from(desired_bytes).unwrap_or(i64::MAX),
                        now,
                    ),
                )
                .await?;
            previous.push(old_bytes);
        }

        for (account_id, old_bytes) in account_ids.iter().zip(previous) {
            let capacity = account_capacity_on(&transaction, *account_id).await?;
            let added_reservation = desired_bytes.saturating_sub(old_bytes);
            if let Some(limit) = capacity.quota.max_bytes {
                let occupied = capacity
                    .quota
                    .used_bytes
                    .saturating_add(capacity.reserved_bytes);
                if added_reservation > 0 && occupied > limit {
                    let used = occupied.saturating_sub(added_reservation);
                    let error = BackendError::StorageQuotaExceeded {
                        scope: format!("account:{account_id}"),
                        used,
                        requested: added_reservation,
                        limit,
                    };
                    transaction.rollback().await?;
                    return Err(error);
                }
            }
        }
        transaction.commit().await?;
        Ok(())
    }
}

pub(crate) async fn ensure_account_capacity_on(
    connection: &Connection,
    account_id: AccountId,
    requested_bytes: u64,
) -> Result<()> {
    let capacity = account_capacity_on(connection, account_id).await?;
    if let Some(limit) = capacity.quota.max_bytes {
        let used = capacity
            .quota
            .used_bytes
            .saturating_add(capacity.reserved_bytes);
        if requested_bytes > 0 && used.saturating_add(requested_bytes) > limit {
            return Err(BackendError::StorageQuotaExceeded {
                scope: format!("account:{account_id}"),
                used,
                requested: requested_bytes,
                limit,
            });
        }
    }
    Ok(())
}

async fn account_quota_on(
    connection: &Connection,
    account_id: AccountId,
) -> Result<AccountStorageQuota> {
    Ok(account_capacity_on(connection, account_id).await?.quota)
}

struct AccountCapacity {
    quota: AccountStorageQuota,
    reserved_bytes: u64,
}

async fn account_capacity_on(
    connection: &Connection,
    account_id: AccountId,
) -> Result<AccountCapacity> {
    let mut rows = connection
        .query(
            r#"SELECT a.id, q.max_bytes, COALESCE(u.used_bytes, 0),
                COALESCE((
                    SELECT SUM(r.reserved_bytes)
                    FROM account_storage_reservations r
                    WHERE r.account_id = a.id
                ), 0)
            FROM accounts a
            LEFT JOIN account_storage_quotas q ON q.account_id = a.id
            LEFT JOIN account_storage_usage u ON u.account_id = a.id
            WHERE a.id = ?1"#,
            (account_id.to_string(),),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Err(BackendError::NotFound {
            entity: "account",
            id: account_id.to_string(),
        });
    };
    let max_bytes = row
        .get::<Option<i64>>(1)?
        .map(|value| u64::try_from(value).map_err(|_| invalid_storage_value("account quota")))
        .transpose()?;
    let used_bytes =
        u64::try_from(row.get::<i64>(2)?).map_err(|_| invalid_storage_value("account usage"))?;
    let reserved_bytes = u64::try_from(row.get::<i64>(3)?)
        .map_err(|_| invalid_storage_value("account reservations"))?;
    Ok(AccountCapacity {
        quota: AccountStorageQuota {
            account_id,
            used_bytes,
            max_bytes,
        },
        reserved_bytes,
    })
}

fn invalid_storage_value(name: &str) -> BackendError {
    BackendError::InvalidInput(format!("database contains invalid {name}"))
}

#[derive(Debug)]
struct BlobReference {
    expected_sizes: HashSet<u64>,
    sources: Vec<String>,
}

#[derive(Debug)]
struct DownloadState {
    availability: String,
    downloaded_bytes: u64,
}

async fn audit_database_integrity(
    connection: &Connection,
    collector: &mut IssueCollector,
) -> Result<bool> {
    let mut rows = connection.query("PRAGMA integrity_check", ()).await?;
    let mut ok = true;
    while let Some(row) = rows.next().await? {
        let detail = row.get::<String>(0)?;
        if !detail.eq_ignore_ascii_case("ok") {
            ok = false;
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Error,
                kind: IntegrityIssueKind::DatabaseIntegrity,
                identifier: None,
                detail,
                repairable: false,
            });
        }
    }
    Ok(ok)
}

async fn audit_foreign_keys(
    connection: &Connection,
    collector: &mut IssueCollector,
) -> Result<u64> {
    let mut rows = connection.query("PRAGMA foreign_key_check", ()).await?;
    let mut violations = 0u64;
    while let Some(row) = rows.next().await? {
        violations = violations.saturating_add(1);
        collector.push(IntegrityIssue {
            severity: IntegritySeverity::Error,
            kind: IntegrityIssueKind::ForeignKeyViolation,
            identifier: row.get::<Option<String>>(0)?,
            detail: "database row violates a foreign-key constraint".into(),
            repairable: false,
        });
    }
    Ok(violations)
}

async fn load_blob_references(
    connection: &Connection,
    collector: &mut IssueCollector,
) -> Result<HashMap<String, BlobReference>> {
    let mut rows = connection
        .query(
            r#"
            SELECT blob_hash,
                   CASE WHEN content_availability = 'complete' THEN size_bytes ELSE NULL END,
                   'message:' || id
            FROM messages
            UNION ALL
            SELECT blob_hash, decoded_size, 'mime:' || message_id || ':' || part_id
            FROM mime_part_blobs
            UNION ALL
            SELECT blob_hash, decoded_size, 'attachment:' || message_id || ':' || ordinal
            FROM attachments WHERE blob_hash IS NOT NULL
            UNION ALL
            SELECT blob_hash, size_bytes, 'draft_attachment:' || id
            FROM draft_attachments
            UNION ALL
            SELECT raw_blob_hash, raw_size_bytes, 'submission:' || id
            FROM submissions
            UNION ALL
            SELECT blob_hash, NULL, 'sent_reconciliation:' || rfc_message_id
            FROM sent_reconciliation
            UNION ALL
            SELECT decrypted_blob_hash, decrypted_size_bytes, 'openpgp_decrypted:' || message_id
            FROM openpgp_decrypted_messages
            "#,
            (),
        )
        .await?;
    let mut references: HashMap<String, BlobReference> = HashMap::new();
    while let Some(row) = rows.next().await? {
        let hash = row.get::<String>(0)?;
        let expected = row
            .get::<Option<i64>>(1)?
            .map(|value| u64::try_from(value).map_err(|_| invalid_storage_value("blob size")))
            .transpose()?;
        let source = row.get::<String>(2)?;
        if !valid_blob_hash(&hash) {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Error,
                kind: IntegrityIssueKind::InvalidBlobPath,
                identifier: Some(hash),
                detail: format!("{source} contains an invalid blob hash"),
                repairable: false,
            });
            continue;
        }
        let reference = references.entry(hash).or_insert_with(|| BlobReference {
            expected_sizes: HashSet::new(),
            sources: Vec::new(),
        });
        if let Some(expected) = expected {
            reference.expected_sizes.insert(expected);
        }
        if reference.sources.len() < 8 {
            reference.sources.push(source);
        }
    }
    Ok(references)
}

async fn load_download_states(connection: &Connection) -> Result<HashMap<String, DownloadState>> {
    let mut rows = connection
        .query(
            "SELECT id, content_availability, downloaded_bytes FROM messages",
            (),
        )
        .await?;
    let mut states = HashMap::new();
    while let Some(row) = rows.next().await? {
        states.insert(
            row.get::<String>(0)?,
            DownloadState {
                availability: row.get(1)?,
                downloaded_bytes: u64::try_from(row.get::<i64>(2)?)
                    .map_err(|_| invalid_storage_value("downloaded byte count"))?,
            },
        );
    }
    Ok(states)
}

async fn scalar_count(connection: &Connection, sql: &str) -> Result<u64> {
    let mut rows = connection.query(sql, ()).await?;
    let value = rows
        .next()
        .await?
        .ok_or_else(|| BackendError::InvalidInput("count query returned no row".into()))?
        .get::<i64>(0)?;
    u64::try_from(value).map_err(|_| invalid_storage_value("count"))
}

struct BlobAudit {
    files: u64,
    verified_bytes: u64,
    issues: Vec<IntegrityIssue>,
    omitted_issues: u64,
    error_count: u64,
}

async fn audit_blob_files(
    root: PathBuf,
    references: &HashMap<String, BlobReference>,
    options: IntegrityAuditOptions,
) -> Result<BlobAudit> {
    let references = references
        .iter()
        .map(|(hash, reference)| {
            (
                hash.clone(),
                (reference.expected_sizes.clone(), reference.sources.clone()),
            )
        })
        .collect::<HashMap<_, _>>();
    tokio::task::spawn_blocking(move || {
        let mut collector = IssueCollector::new(options.max_issues.min(MAX_AUDIT_ISSUES));
        let mut actual = HashMap::new();
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(BackendError::Io {
                        path: directory,
                        source,
                    });
                }
            };
            for entry in entries {
                let entry = entry.map_err(|source| BackendError::Io {
                    path: directory.clone(),
                    source,
                })?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(|source| BackendError::Io {
                    path: path.clone(),
                    source,
                })?;
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() {
                    collector.push(IntegrityIssue {
                        severity: IntegritySeverity::Warning,
                        kind: IntegrityIssueKind::InvalidBlobPath,
                        identifier: Some(path.display().to_string()),
                        detail: "blob storage contains a non-regular file".into(),
                        repairable: true,
                    });
                    continue;
                }
                let relative = path.strip_prefix(&root).unwrap_or(&path);
                let components = relative
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                if components.first().is_some_and(|value| value == "incoming")
                    || components
                        .last()
                        .is_some_and(|value| value.starts_with('.'))
                {
                    collector.push(IntegrityIssue {
                        severity: IntegritySeverity::Warning,
                        kind: IntegrityIssueKind::AbandonedTemporaryFile,
                        identifier: Some(relative.display().to_string()),
                        detail: "temporary blob file was left behind by an interrupted write"
                            .into(),
                        repairable: true,
                    });
                    continue;
                }
                let hash = if components.len() == 2 {
                    format!("{}{}", components[0], components[1])
                } else {
                    String::new()
                };
                if !valid_blob_hash(&hash) || components[0].len() != 2 {
                    collector.push(IntegrityIssue {
                        severity: IntegritySeverity::Warning,
                        kind: IntegrityIssueKind::InvalidBlobPath,
                        identifier: Some(relative.display().to_string()),
                        detail: "file is not stored under a canonical SHA-256 blob path".into(),
                        repairable: true,
                    });
                    continue;
                }
                actual.insert(hash, path);
            }
        }

        let mut verified_bytes = 0u64;
        for (hash, (expected_sizes, sources)) in &references {
            let Some(path) = actual.get(hash) else {
                collector.push(IntegrityIssue {
                    severity: IntegritySeverity::Error,
                    kind: IntegrityIssueKind::MissingBlob,
                    identifier: Some(hash.clone()),
                    detail: format!("referenced by {}", sources.join(", ")),
                    repairable: false,
                });
                continue;
            };
            let metadata = fs::metadata(path).map_err(|source| BackendError::Io {
                path: path.clone(),
                source,
            })?;
            if !expected_sizes.is_empty() && !expected_sizes.contains(&metadata.len()) {
                collector.push(IntegrityIssue {
                    severity: IntegritySeverity::Error,
                    kind: IntegrityIssueKind::BlobSizeMismatch,
                    identifier: Some(hash.clone()),
                    detail: format!(
                        "blob is {} bytes but database references expect {:?}",
                        metadata.len(),
                        expected_sizes
                    ),
                    repairable: false,
                });
            }
            if options.verify_blob_hashes {
                let (actual_hash, size) = hash_file(path)?;
                verified_bytes = verified_bytes.saturating_add(size);
                if actual_hash != *hash {
                    collector.push(IntegrityIssue {
                        severity: IntegritySeverity::Error,
                        kind: IntegrityIssueKind::CorruptBlob,
                        identifier: Some(hash.clone()),
                        detail: format!("content hashes to {actual_hash}"),
                        repairable: false,
                    });
                }
            }
        }
        if options.report_orphan_blobs {
            for hash in actual.keys().filter(|hash| !references.contains_key(*hash)) {
                collector.push(IntegrityIssue {
                    severity: IntegritySeverity::Warning,
                    kind: IntegrityIssueKind::OrphanBlob,
                    identifier: Some(hash.clone()),
                    detail: "blob is not referenced by current database state".into(),
                    repairable: true,
                });
            }
        }
        Ok(BlobAudit {
            files: actual.len() as u64,
            verified_bytes,
            issues: collector.issues,
            omitted_issues: collector.omitted,
            error_count: collector.error_count,
        })
    })
    .await
    .map_err(|error| BackendError::InvalidInput(format!("blob audit task failed: {error}")))?
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(|source| BackendError::Io {
            path: path.to_owned(),
            source,
        })?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), size))
}

fn audit_partial_downloads(
    root: &Path,
    states: &HashMap<String, DownloadState>,
    collector: &mut IssueCollector,
) -> Result<()> {
    let mut seen = HashSet::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BackendError::Io {
                path: root.to_owned(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| BackendError::Io {
            path: root.to_owned(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".part") else {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::PartialDownloadMismatch,
                identifier: Some(name),
                detail: "downloads directory contains an unexpected file".into(),
                repairable: true,
            });
            continue;
        };
        let Some(state) = states.get(id) else {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::PartialDownloadMismatch,
                identifier: Some(id.to_owned()),
                detail: "partial download has no corresponding message".into(),
                repairable: true,
            });
            continue;
        };
        let metadata = fs::metadata(&path).map_err(|source| BackendError::Io {
            path: path.clone(),
            source,
        })?;
        seen.insert(id.to_owned());
        if state.availability == "complete" || metadata.len() != state.downloaded_bytes {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::PartialDownloadMismatch,
                identifier: Some(id.to_owned()),
                detail: format!(
                    "partial file is {} bytes while state {:?} records {} bytes",
                    metadata.len(),
                    state.availability,
                    state.downloaded_bytes
                ),
                repairable: true,
            });
        }
    }
    for (id, state) in states {
        if state.downloaded_bytes > 0
            && matches!(state.availability.as_str(), "downloading" | "failed")
            && !seen.contains(id)
        {
            collector.push(IntegrityIssue {
                severity: IntegritySeverity::Warning,
                kind: IntegrityIssueKind::PartialDownloadMismatch,
                identifier: Some(id.clone()),
                detail: format!(
                    "database records {} resumable bytes but the partial file is missing",
                    state.downloaded_bytes
                ),
                repairable: true,
            });
        }
    }
    Ok(())
}

fn valid_blob_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct IssueCollector {
    maximum: usize,
    issues: Vec<IntegrityIssue>,
    omitted: u64,
    error_count: u64,
}

impl IssueCollector {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            issues: Vec::new(),
            omitted: 0,
            error_count: 0,
        }
    }

    fn push(&mut self, issue: IntegrityIssue) {
        if issue.severity == IntegritySeverity::Error {
            self.error_count = self.error_count.saturating_add(1);
        }
        if self.issues.len() < self.maximum {
            self.issues.push(issue);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}

pub(crate) struct StorageBudget {
    profile_dir: PathBuf,
    limits: StorageLimits,
    refresh_profile: bool,
    gate: Arc<RwLock<()>>,
    state: StdMutex<BudgetState>,
}

struct BudgetState {
    observed_blob_bytes: u64,
    observed_non_blob_bytes: u64,
    reservations: HashMap<u64, ReservationState>,
    next_reservation: u64,
    last_refresh: Instant,
}

#[derive(Clone, Copy)]
struct ReservationState {
    reserved: u64,
    materialized: u64,
}

impl StorageBudget {
    pub(crate) async fn open(profile_dir: PathBuf, limits: StorageLimits) -> Result<Arc<Self>> {
        // A recursive profile census is proportional to the complete local
        // mail mirror and therefore cannot be part of application startup.
        // When a profile quota exists, begin conservatively at the limit so
        // writes fail closed until the delayed exact measurement completes.
        let conservative_total = limits.max_profile_bytes.unwrap_or(0);
        Ok(Arc::new(Self {
            profile_dir,
            limits,
            refresh_profile: true,
            gate: Arc::new(RwLock::new(())),
            state: StdMutex::new(BudgetState {
                observed_blob_bytes: 0,
                observed_non_blob_bytes: conservative_total,
                reservations: HashMap::new(),
                next_reservation: 1,
                last_refresh: Instant::now(),
            }),
        }))
    }

    /// O(1) supervisor snapshot for disposable workers. Exact categorized
    /// usage remains available through the explicit `Storage::usage` census.
    pub(crate) fn cached_usage(&self) -> Result<StorageUsage> {
        let state = lock_state(&self.state);
        let total_bytes = state
            .observed_blob_bytes
            .saturating_add(state.observed_non_blob_bytes);
        Ok(StorageUsage {
            total_bytes,
            blob_bytes: state.observed_blob_bytes,
            other_bytes: state.observed_non_blob_bytes,
            available_filesystem_bytes: fs2::available_space(&self.profile_dir).map_err(
                |source| BackendError::Io {
                    path: self.profile_dir.clone(),
                    source,
                },
            )?,
            profile_quota_bytes: self.limits.max_profile_bytes,
            minimum_free_bytes: self.limits.minimum_free_bytes,
            ..StorageUsage::default()
        })
    }

    /// Construct a worker-side budget from a supervisor measurement.  The
    /// isolated worker cannot read the credential or search-index trees, so
    /// it must not re-walk the complete profile while it is running.
    pub(crate) fn from_observed(
        profile_dir: PathBuf,
        limits: StorageLimits,
        usage: StorageUsage,
    ) -> Arc<Self> {
        Arc::new(Self {
            profile_dir,
            limits,
            refresh_profile: false,
            gate: Arc::new(RwLock::new(())),
            state: StdMutex::new(BudgetState {
                observed_blob_bytes: usage.blob_bytes,
                observed_non_blob_bytes: usage.total_bytes.saturating_sub(usage.blob_bytes),
                reservations: HashMap::new(),
                next_reservation: 1,
                last_refresh: Instant::now(),
            }),
        })
    }

    pub(crate) async fn measure(&self) -> Result<StorageUsage> {
        let _guard = self.gate.write().await;
        let usage = measure_profile(self.profile_dir.clone(), self.limits).await?;
        let mut state = lock_state(&self.state);
        state.observed_blob_bytes = usage.blob_bytes;
        state.observed_non_blob_bytes = usage.total_bytes.saturating_sub(usage.blob_bytes);
        state.last_refresh = Instant::now();
        Ok(usage)
    }

    async fn refresh_if_stale(&self) -> Result<()> {
        if !self.refresh_profile {
            return Ok(());
        }
        if lock_state(&self.state).last_refresh.elapsed() < BUDGET_REFRESH_INTERVAL {
            return Ok(());
        }
        let _guard = self.gate.write().await;
        if lock_state(&self.state).last_refresh.elapsed() < BUDGET_REFRESH_INTERVAL {
            return Ok(());
        }
        let non_blob_bytes = measure_non_blob_profile(self.profile_dir.clone()).await?;
        let mut state = lock_state(&self.state);
        state.observed_non_blob_bytes = non_blob_bytes;
        state.last_refresh = Instant::now();
        Ok(())
    }

    pub(crate) async fn start_reservation(self: &Arc<Self>) -> Result<StorageReservation> {
        self.refresh_if_stale().await?;
        let guard = Arc::clone(&self.gate).read_owned().await;
        let id = {
            let mut state = lock_state(&self.state);
            let id = state.next_reservation;
            state.next_reservation = state.next_reservation.wrapping_add(1).max(1);
            state.reservations.insert(
                id,
                ReservationState {
                    reserved: 0,
                    materialized: 0,
                },
            );
            id
        };
        Ok(StorageReservation {
            budget: Arc::clone(self),
            id,
            _guard: guard,
            active: true,
        })
    }
}

pub(crate) struct StorageReservation {
    budget: Arc<StorageBudget>,
    id: u64,
    _guard: OwnedRwLockReadGuard<()>,
    active: bool,
}

impl StorageReservation {
    pub(crate) fn grow(&mut self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let mut state = lock_state(&self.budget.state);
        let reserved = sum_reservations(state.reservations.values().map(|value| value.reserved))?;
        if let Some(limit) = self.budget.limits.max_profile_bytes {
            let used = charge_u64(
                state.observed_blob_bytes,
                state.observed_non_blob_bytes,
                limit,
            )
            .and_then(|value| charge_u64(value, reserved, limit));
            let Some(used) = used else {
                return Err(BackendError::StorageQuotaExceeded {
                    scope: "profile".into(),
                    used: limit,
                    requested: bytes,
                    limit,
                });
            };
            if charge_u64(used, bytes, limit).is_none() {
                return Err(BackendError::StorageQuotaExceeded {
                    scope: "profile".into(),
                    used,
                    requested: bytes,
                    limit,
                });
            }
        }
        let unmaterialized = sum_unmaterialized(state.reservations.values().copied())?;
        let available =
            fs2::available_space(&self.budget.profile_dir).map_err(|source| BackendError::Io {
                path: self.budget.profile_dir.clone(),
                source,
            })?;
        let required = charge_u64(
            self.budget.limits.minimum_free_bytes,
            unmaterialized,
            u64::MAX,
        )
        .and_then(|value| charge_u64(value, bytes, u64::MAX))
        .unwrap_or(u64::MAX);
        if available < required {
            return Err(BackendError::StorageFull {
                path: Some(self.budget.profile_dir.clone()),
                required_bytes: required,
                available_bytes: Some(available),
            });
        }
        let reservation = state
            .reservations
            .get_mut(&self.id)
            .expect("active storage reservation exists");
        reservation.reserved = charge_u64(reservation.reserved, bytes, u64::MAX)
            .ok_or_else(|| BackendError::InvalidInput("storage reservation overflow".into()))?;
        Ok(())
    }

    pub(crate) fn materialized(&mut self, bytes: u64) -> Result<()> {
        let mut state = lock_state(&self.budget.state);
        let reservation = state
            .reservations
            .get_mut(&self.id)
            .expect("active storage reservation exists");
        reservation.materialized =
            materialize_bytes(reservation.reserved, reservation.materialized, bytes).ok_or_else(
                || BackendError::InvalidInput("materialized bytes exceed their reservation".into()),
            )?;
        Ok(())
    }

    pub(crate) fn commit(mut self, added_bytes: u64) -> Result<()> {
        let mut state = lock_state(&self.budget.state);
        let reservation = state
            .reservations
            .get(&self.id)
            .copied()
            .expect("active storage reservation exists");
        if !reservation_commit_allowed(reservation.reserved, reservation.materialized, added_bytes)
        {
            return Err(BackendError::InvalidInput(
                "storage commit exceeds materialized reservation".into(),
            ));
        }
        let observed = charge_u64(state.observed_blob_bytes, added_bytes, u64::MAX)
            .ok_or_else(|| BackendError::InvalidInput("observed storage overflow".into()))?;
        state.reservations.remove(&self.id);
        state.observed_blob_bytes = observed;
        self.active = false;
        Ok(())
    }
}

fn sum_reservations(mut values: impl Iterator<Item = u64>) -> Result<u64> {
    values.try_fold(0, |total, value| {
        charge_u64(total, value, u64::MAX)
            .ok_or_else(|| BackendError::InvalidInput("storage reservation total overflow".into()))
    })
}

fn sum_unmaterialized(mut values: impl Iterator<Item = ReservationState>) -> Result<u64> {
    values.try_fold(0, |total, value| {
        let remaining = value
            .reserved
            .checked_sub(value.materialized)
            .ok_or_else(|| {
                BackendError::InvalidInput("materialized bytes exceed their reservation".into())
            })?;
        charge_u64(total, remaining, u64::MAX).ok_or_else(|| {
            BackendError::InvalidInput("unmaterialized reservation total overflow".into())
        })
    })
}

impl Drop for StorageReservation {
    fn drop(&mut self) {
        if self.active {
            lock_state(&self.budget.state).reservations.remove(&self.id);
        }
    }
}

fn lock_state<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn measure_non_blob_profile(profile_dir: PathBuf) -> Result<u64> {
    tokio::task::spawn_blocking(move || {
        let entries = match fs::read_dir(&profile_dir) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => {
                return Err(BackendError::Io {
                    path: profile_dir,
                    source,
                });
            }
        };
        let mut total = 0u64;
        for entry in entries {
            let entry = entry.map_err(|source| BackendError::Io {
                path: profile_dir.clone(),
                source,
            })?;
            if entry.file_name() == "blobs" {
                continue;
            }
            total = total.saturating_add(tree_size(&entry.path())?);
        }
        Ok(total)
    })
    .await
    .map_err(|error| BackendError::InvalidInput(format!("storage refresh failed: {error}")))?
}

async fn measure_profile(profile_dir: PathBuf, limits: StorageLimits) -> Result<StorageUsage> {
    tokio::task::spawn_blocking(move || {
        let mut usage = StorageUsage {
            available_filesystem_bytes: fs2::available_space(&profile_dir).map_err(|source| {
                BackendError::Io {
                    path: profile_dir.clone(),
                    source,
                }
            })?,
            profile_quota_bytes: limits.max_profile_bytes,
            minimum_free_bytes: limits.minimum_free_bytes,
            ..StorageUsage::default()
        };
        let entries = match fs::read_dir(&profile_dir) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(usage),
            Err(source) => {
                return Err(BackendError::Io {
                    path: profile_dir,
                    source,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| BackendError::Io {
                path: profile_dir.clone(),
                source,
            })?;
            let path = entry.path();
            let bytes = tree_size(&path)?;
            usage.total_bytes = usage.total_bytes.saturating_add(bytes);
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "blobs" {
                usage.blob_bytes = usage.blob_bytes.saturating_add(bytes);
            } else if name == "search-index" || name == "search-index.json" {
                usage.search_index_bytes = usage.search_index_bytes.saturating_add(bytes);
            } else if name == "downloads" {
                usage.partial_download_bytes = usage.partial_download_bytes.saturating_add(bytes);
            } else if name == "credentials" {
                usage.credential_bytes = usage.credential_bytes.saturating_add(bytes);
            } else if name == "mail.db" || name.starts_with("mail.db-") {
                usage.database_bytes = usage.database_bytes.saturating_add(bytes);
            } else {
                usage.other_bytes = usage.other_bytes.saturating_add(bytes);
            }
        }
        Ok(usage)
    })
    .await
    .map_err(|error| BackendError::InvalidInput(format!("storage measurement failed: {error}")))?
}

fn tree_size(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(0);
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| BackendError::Io {
            path: path.to_owned(),
            source,
        })?;
        total = total.saturating_add(tree_size(&entry.path())?);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn remote_target(backend: &Backend) -> (crate::Account, crate::Folder) {
        let account = backend
            .accounts()
            .add(crate::NewAccount {
                name: "Storage ledger test".into(),
                kind: crate::AccountKind::Imap,
                credential_ref: Some("test:storage-ledger".into()),
                imap: Some(crate::ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: crate::ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        let folder = backend
            .folders()
            .add(crate::NewFolder {
                account_id: Some(account.id),
                name: "Inbox".into(),
                kind: crate::FolderKind::Remote,
                remote_name: Some("INBOX".into()),
            })
            .await
            .unwrap();
        (account, folder)
    }

    #[tokio::test]
    async fn opening_a_budget_does_not_walk_the_existing_blob_tree() {
        let profile = tempfile::tempdir().unwrap();
        let blob_dir = profile.path().join("blobs/aa");
        std::fs::create_dir_all(&blob_dir).unwrap();
        std::fs::write(blob_dir.join("payload"), vec![7_u8; 16 * 1024]).unwrap();

        let budget = StorageBudget::open(profile.path().to_owned(), StorageLimits::default())
            .await
            .unwrap();
        assert_eq!(budget.cached_usage().unwrap().total_bytes, 0);

        let measured = budget.measure().await.unwrap();
        assert!(measured.blob_bytes >= 16 * 1024);
        assert!(budget.cached_usage().unwrap().blob_bytes >= 16 * 1024);
    }

    #[tokio::test]
    async fn account_usage_ledger_counts_a_message_once_per_account() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(crate::BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let (account, first_folder) = remote_target(&backend).await;
        let second_folder = backend
            .folders()
            .add(crate::NewFolder {
                account_id: Some(account.id),
                name: "Archive".into(),
                kind: crate::FolderKind::Remote,
                remote_name: Some("Archive".into()),
            })
            .await
            .unwrap();
        let raw = b"From: sender@example.test\r\nSubject: ledger\r\n\r\nbody\r\n".to_vec();
        let message_id = backend
            .messages()
            .ingest(crate::IngestMessage {
                raw: raw.clone(),
                remote: Some(crate::RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: first_folder.id,
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
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            raw.len() as u64
        );

        let connection = backend.inner.connection.lock().await;
        connection
            .execute(
                "INSERT INTO message_instances(message_id, account_id, folder_id, uid_validity, imap_uid, mod_sequence, flags_json) VALUES (?1, ?2, ?3, 1, 2, NULL, '[]')",
                (
                    message_id.to_string(),
                    account.id.to_string(),
                    second_folder.id.to_string(),
                ),
            )
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            raw.len() as u64
        );

        let connection = backend.inner.connection.lock().await;
        connection
            .execute(
                "DELETE FROM message_instances WHERE folder_id = ?1",
                (first_folder.id.to_string(),),
            )
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            raw.len() as u64
        );

        let connection = backend.inner.connection.lock().await;
        connection
            .execute(
                "DELETE FROM message_instances WHERE folder_id = ?1",
                (second_folder.id.to_string(),),
            )
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            0
        );

        let connection = backend.inner.connection.lock().await;
        connection
            .execute(
                "INSERT INTO message_instances(message_id, account_id, folder_id, uid_validity, imap_uid, mod_sequence, flags_json) VALUES (?1, ?2, ?3, 1, 3, NULL, '[]')",
                (
                    message_id.to_string(),
                    account.id.to_string(),
                    second_folder.id.to_string(),
                ),
            )
            .await
            .unwrap();
        connection
            .execute(
                "DELETE FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            0
        );
    }

    #[tokio::test]
    async fn download_reservations_are_atomic_and_release_on_failure() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(crate::BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let (account, folder) = remote_target(&backend).await;
        let message_id = backend
            .sync()
            .ingest_imap_header_batch(
                account.id,
                folder.id,
                7,
                vec![crate::ImapFetchedHeaders {
                    uid: 1,
                    mod_sequence: None,
                    flags: Vec::new(),
                    internal_date: None,
                    size_bytes: 1_000,
                    has_attachment: false,
                    headers: b"From: sender@example.test\r\nSubject: reservation\r\n\r\n".to_vec(),
                }],
            )
            .await
            .unwrap()
            .message_ids[0];

        backend
            .storage()
            .set_account_quota(account.id, Some(999))
            .await
            .unwrap();
        let error = backend
            .storage()
            .reserve_message_capacity(message_id, 1_000)
            .await
            .unwrap_err();
        assert_eq!(error.code(), crate::ErrorCode::StorageQuotaExceeded);

        backend
            .storage()
            .set_account_quota(account.id, Some(1_000))
            .await
            .unwrap();
        backend
            .storage()
            .reserve_message_capacity(message_id, 1_000)
            .await
            .unwrap();
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT reserved_bytes FROM account_storage_reservations WHERE account_id = ?1 AND message_id = ?2",
                (account.id.to_string(), message_id.to_string()),
            )
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            1_000
        );
        drop(rows);
        drop(connection);

        backend
            .store_download_failure(message_id, 250, "test interruption")
            .await
            .unwrap();
        assert_eq!(
            backend
                .storage()
                .account_quota(account.id)
                .await
                .unwrap()
                .used_bytes,
            250
        );
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT count(*) FROM account_storage_reservations WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn concurrent_workers_cannot_oversubscribe_an_account_quota() {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(crate::BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let (account, folder) = remote_target(&backend).await;
        let result = backend
            .sync()
            .ingest_imap_header_batch(
                account.id,
                folder.id,
                7,
                vec![
                    crate::ImapFetchedHeaders {
                        uid: 1,
                        mod_sequence: None,
                        flags: Vec::new(),
                        internal_date: None,
                        size_bytes: 600,
                        has_attachment: false,
                        headers: b"From: one@example.test\r\nSubject: one\r\n\r\n".to_vec(),
                    },
                    crate::ImapFetchedHeaders {
                        uid: 2,
                        mod_sequence: None,
                        flags: Vec::new(),
                        internal_date: None,
                        size_bytes: 600,
                        has_attachment: false,
                        headers: b"From: two@example.test\r\nSubject: two\r\n\r\n".to_vec(),
                    },
                ],
            )
            .await
            .unwrap();
        backend
            .storage()
            .set_account_quota(account.id, Some(1_000))
            .await
            .unwrap();
        let observed = backend.storage().usage().await.unwrap();
        let worker = Backend::open_sync_worker(crate::BackendConfig::new(profile.path()), observed)
            .await
            .unwrap();
        let first = backend.storage();
        let second = worker.storage();
        let (first_result, second_result) = tokio::join!(
            first.reserve_message_capacity(result.message_ids[0], 600),
            second.reserve_message_capacity(result.message_ids[1], 600),
        );
        let results = [first_result, second_result];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let error = results
            .into_iter()
            .find_map(std::result::Result::err)
            .expect("one reservation must exceed the quota");
        assert_eq!(error.code(), crate::ErrorCode::StorageQuotaExceeded);

        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT count(*), COALESCE(SUM(reserved_bytes), 0) FROM account_storage_reservations WHERE account_id = ?1",
                (account.id.to_string(),),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<i64>(0).unwrap(), 1);
        assert_eq!(row.get::<i64>(1).unwrap(), 600);
    }
}
