use crate::backend::{enqueue_search_on, insert_event, refresh_remote_in_transaction};
use crate::imap::imap_fetch_state;
use crate::imap_mutation::normalize_mutable_flags;
use crate::{
    Account, AccountId, AccountKind, Backend, BackendError, FolderId, ImapMutation,
    ImapMutationConflictKind, ImapMutationOperation, ImapMutationStatus, ImapSecurity,
    RemoteMessageIdentity, Result,
};
use async_imap::extensions::idle::IdleResponse;
use async_imap::types::{Capabilities, Capability, CopyUid, NameAttribute};
use async_imap::{Authenticator, Client, Session};
use chrono::Utc;
use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

const MAX_QRESYNC_UID_SET_BYTES: usize = 32 * 1024;
const MAX_TRACKED_UIDS: usize = 10_000_000;

/// A secret returned by a platform credential adapter.
///
/// Its debug representation is always redacted and the owned buffer is
/// zeroized when dropped. It is deliberately neither serializable nor cloneable.
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Authentication material resolved from an account's opaque credential
/// reference. Plaintext secrets never enter the account database.
pub enum ImapCredential {
    Password(SecretValue),
    OAuth2 { access_token: SecretValue },
}

impl fmt::Debug for ImapCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("ImapCredential::Password([REDACTED])"),
            Self::OAuth2 { .. } => formatter.write_str("ImapCredential::OAuth2([REDACTED])"),
        }
    }
}

/// Boundary implemented by an OS keychain, OAuth broker, hardware-backed
/// secret store, or test adapter.
pub trait CredentialProvider: Send + Sync {
    fn resolve<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>>;
}

#[derive(Clone, Debug)]
pub struct ImapAccountEngineConfig {
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub folder_sync_timeout: Duration,
    pub polling_interval: Duration,
    pub idle_refresh: Duration,
    pub backoff_initial: Duration,
    pub backoff_maximum: Duration,
    /// Maximum durable outbound mutations attempted on one synchronization
    /// connection before ordinary mailbox reconciliation resumes.
    pub mutation_batch_size: usize,
    /// Whether the built-in Mozilla/WebPKI root set is accepted.
    pub use_webpki_roots: bool,
    /// Additional DER-encoded trust anchors, primarily for private mail
    /// infrastructure and deterministic integration tests.
    pub additional_root_certificates_der: Vec<Vec<u8>>,
}

impl Default for ImapAccountEngineConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(20),
            command_timeout: Duration::from_secs(60),
            folder_sync_timeout: Duration::from_secs(30 * 60),
            polling_interval: Duration::from_secs(5 * 60),
            idle_refresh: Duration::from_secs(25 * 60),
            backoff_initial: Duration::from_secs(2),
            backoff_maximum: Duration::from_secs(15 * 60),
            mutation_batch_size: 100,
            use_webpki_roots: true,
            additional_root_certificates_der: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImapAccountSyncStatus {
    Idle,
    Connecting,
    Authenticating,
    Discovering,
    Synchronizing,
    Waiting,
    Backoff,
    Error,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImapMailboxCompleteness {
    NotStarted,
    Partial,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapAccountSyncState {
    pub account_id: AccountId,
    pub capabilities: Vec<String>,
    pub status: ImapAccountSyncStatus,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub next_retry_at: Option<i64>,
    pub failure_count: u32,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapMailboxSyncState {
    pub folder_id: FolderId,
    pub remote_name: String,
    pub delimiter: Option<String>,
    pub attributes: Vec<String>,
    pub selectable: bool,
    pub remote_present: bool,
    pub uid_validity: Option<u32>,
    pub uid_next: Option<u32>,
    pub highest_mod_sequence: Option<u64>,
    pub exists_count: Option<u32>,
    pub completeness: ImapMailboxCompleteness,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapFolderSyncReport {
    pub folder_id: FolderId,
    pub fetched_messages: usize,
    pub removed_instances: usize,
    pub refreshed_instances: usize,
    pub used_qresync: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapAccountSyncReport {
    pub account_id: AccountId,
    pub capabilities: Vec<String>,
    pub mutations: ImapMutationSyncReport,
    pub folders: Vec<ImapFolderSyncReport>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapMutationSyncReport {
    pub attempted: usize,
    pub applied: usize,
    pub conflicts: usize,
}

#[derive(Clone)]
pub struct ImapAccountEngine {
    backend: Backend,
    credentials: Arc<dyn CredentialProvider>,
    config: ImapAccountEngineConfig,
    tls: TlsConnector,
}

impl ImapAccountEngine {
    pub fn new(
        backend: Backend,
        credentials: Arc<dyn CredentialProvider>,
        config: ImapAccountEngineConfig,
    ) -> Result<Self> {
        if config.connect_timeout.is_zero()
            || config.command_timeout.is_zero()
            || config.folder_sync_timeout.is_zero()
            || config.polling_interval.is_zero()
            || config.idle_refresh.is_zero()
            || config.backoff_initial.is_zero()
            || config.backoff_maximum < config.backoff_initial
            || config.mutation_batch_size == 0
        {
            return Err(BackendError::InvalidInput(
                "IMAP engine timeouts, backoff bounds, and mutation batch size must be positive and ordered"
                    .into(),
            ));
        }
        let mut roots = RootCertStore::empty();
        if config.use_webpki_roots {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for certificate in &config.additional_root_certificates_der {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|error| {
                    BackendError::InvalidInput(format!(
                        "invalid additional IMAP TLS root certificate: {error}"
                    ))
                })?;
        }
        if roots.is_empty() {
            return Err(BackendError::InvalidInput(
                "IMAP TLS requires at least one trust anchor".into(),
            ));
        }
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            backend,
            credentials,
            config,
            tls: TlsConnector::from(Arc::new(tls)),
        })
    }

    pub async fn state(&self, account_id: AccountId) -> Result<ImapAccountSyncState> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT capabilities_json, status, last_attempt_at, last_success_at, next_retry_at, failure_count, last_error FROM imap_account_state WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(ImapAccountSyncState {
                account_id,
                capabilities: Vec::new(),
                status: ImapAccountSyncStatus::Idle,
                last_attempt_at: None,
                last_success_at: None,
                next_retry_at: None,
                failure_count: 0,
                last_error: None,
            });
        };
        Ok(ImapAccountSyncState {
            account_id,
            capabilities: serde_json::from_str(&row.get::<String>(0)?)?,
            status: parse_account_status(&row.get::<String>(1)?)?,
            last_attempt_at: row.get(2)?,
            last_success_at: row.get(3)?,
            next_retry_at: row.get(4)?,
            failure_count: u32::try_from(row.get::<i64>(5)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid IMAP failure count".into())
            })?,
            last_error: row.get(6)?,
        })
    }

    pub async fn mailbox_states(&self, account_id: AccountId) -> Result<Vec<ImapMailboxSyncState>> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT f.id, f.remote_name, s.delimiter, s.attributes_json, s.selectable, s.remote_present, f.uid_validity, f.uid_next, s.highest_modseq, s.exists_count, s.completeness, s.last_attempt_at, s.last_success_at, s.last_error FROM folders f JOIN imap_mailbox_state s ON s.folder_id = f.id WHERE f.account_id = ?1 ORDER BY f.remote_name, f.id",
                (account_id.to_string(),),
            )
            .await?;
        let mut states = Vec::new();
        while let Some(row) = rows.next().await? {
            states.push(ImapMailboxSyncState {
                folder_id: parse_folder_id(row.get(0)?)?,
                remote_name: row.get::<Option<String>>(1)?.ok_or_else(|| {
                    BackendError::InvalidInput("remote folder has no remote name".into())
                })?,
                delimiter: row.get(2)?,
                attributes: serde_json::from_str(&row.get::<String>(3)?)?,
                selectable: row.get(4)?,
                remote_present: row.get(5)?,
                uid_validity: database_u32(row.get(6)?, "folders.uid_validity")?,
                uid_next: database_u32(row.get(7)?, "folders.uid_next")?,
                highest_mod_sequence: database_u64(
                    row.get(8)?,
                    "imap_mailbox_state.highest_modseq",
                )?,
                exists_count: database_u32(row.get(9)?, "imap_mailbox_state.exists_count")?,
                completeness: parse_completeness(&row.get::<String>(10)?)?,
                last_attempt_at: row.get(11)?,
                last_success_at: row.get(12)?,
                last_error: row.get(13)?,
            });
        }
        Ok(states)
    }

    pub async fn sync_once(&self, account_id: AccountId) -> Result<ImapAccountSyncReport> {
        let now = Utc::now().timestamp();
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Connecting,
            None,
            None,
            Some(now),
            false,
        )
        .await?;
        let result = self.sync_once_inner(account_id).await;
        match &result {
            Ok(report) => {
                self.store_account_state(
                    account_id,
                    ImapAccountSyncStatus::Idle,
                    Some(&report.capabilities),
                    None,
                    None,
                    true,
                )
                .await?;
            }
            Err(error) => {
                self.store_account_state(
                    account_id,
                    ImapAccountSyncStatus::Error,
                    None,
                    Some(&error.to_string()),
                    None,
                    false,
                )
                .await?;
            }
        }
        result
    }

    /// Continuously synchronizes an account until cancellation, using IDLE for
    /// prompt wakeups when supported and bounded polling otherwise.
    pub async fn run(&self, account_id: AccountId, cancellation: CancellationToken) -> Result<()> {
        let mut consecutive_failures = 0_u32;
        while !cancellation.is_cancelled() {
            let sync_result = tokio::select! {
                _ = cancellation.cancelled() => break,
                result = self.sync_once(account_id) => result,
            };
            match sync_result {
                Ok(report) => {
                    consecutive_failures = 0;
                    self.store_account_state(
                        account_id,
                        ImapAccountSyncStatus::Waiting,
                        Some(&report.capabilities),
                        None,
                        None,
                        false,
                    )
                    .await?;
                    if let Err(error) = self.wait_for_change(account_id, &cancellation).await {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        self.wait_backoff(
                            account_id,
                            consecutive_failures,
                            &error,
                            true,
                            &cancellation,
                        )
                        .await?;
                    }
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    // sync_once already recorded this failure. Moving to the
                    // backoff state must not count the same failure twice.
                    self.wait_backoff(
                        account_id,
                        consecutive_failures,
                        &error,
                        false,
                        &cancellation,
                    )
                    .await?;
                }
            }
        }
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Stopped,
            None,
            None,
            None,
            false,
        )
        .await
    }

    async fn sync_once_inner(&self, account_id: AccountId) -> Result<ImapAccountSyncReport> {
        let account = self.load_imap_account(account_id).await?;
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Authenticating,
            None,
            None,
            None,
            false,
        )
        .await?;
        let (mut session, capabilities) = self.connect_and_authenticate(&account).await?;
        let capability_names = capability_names(&capabilities);
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Discovering,
            Some(&capability_names),
            None,
            None,
            false,
        )
        .await?;
        let discovered = self.discover_mailboxes(&mut session, account_id).await?;
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Synchronizing,
            Some(&capability_names),
            None,
            None,
            false,
        )
        .await?;

        let qresync_enabled = capabilities.has_str("QRESYNC")
            && command_timeout(
                self.config.command_timeout,
                "ENABLE QRESYNC",
                session.enable_qresync(),
            )
            .await
            .is_ok();
        let mutations = self
            .process_mutations(&mut session, account_id, &capabilities)
            .await?;
        let mut folders = Vec::new();
        for mailbox in discovered.iter().filter(|mailbox| mailbox.selectable) {
            match timeout(
                self.config.folder_sync_timeout,
                self.sync_folder(
                    &mut session,
                    account_id,
                    mailbox,
                    &capabilities,
                    qresync_enabled,
                ),
            )
            .await
            {
                Ok(Ok(report)) => folders.push(report),
                Ok(Err(error)) => {
                    self.store_mailbox_failure(mailbox.folder_id, &error.to_string())
                        .await?;
                    return Err(error);
                }
                Err(_) => {
                    let error = BackendError::Imap(format!(
                        "mailbox {} synchronization timed out",
                        mailbox.remote_name
                    ));
                    self.store_mailbox_failure(mailbox.folder_id, &error.to_string())
                        .await?;
                    return Err(error);
                }
            }
        }
        let _ = timeout(self.config.command_timeout, session.logout()).await;
        Ok(ImapAccountSyncReport {
            account_id,
            capabilities: capability_names,
            mutations,
            folders,
        })
    }

    async fn load_imap_account(&self, account_id: AccountId) -> Result<Account> {
        let account = self.backend.accounts().get(account_id).await?;
        if account.kind != AccountKind::Imap || account.imap.is_none() {
            return Err(BackendError::InvalidInput(
                "account is not configured for IMAP".into(),
            ));
        }
        if account.credential_ref.is_none() {
            return Err(BackendError::InvalidInput(
                "IMAP account has no credential reference".into(),
            ));
        }
        Ok(account)
    }

    async fn connect_and_authenticate(
        &self,
        account: &Account,
    ) -> Result<(Session<ImapTransport>, Capabilities)> {
        let settings = account.imap.as_ref().ok_or_else(|| {
            BackendError::InvalidInput("IMAP account has no connection settings".into())
        })?;
        let credential_reference = account.credential_ref.as_deref().ok_or_else(|| {
            BackendError::InvalidInput("IMAP account has no credential reference".into())
        })?;
        let credential = timeout(
            self.config.command_timeout,
            self.credentials.resolve(credential_reference),
        )
        .await
        .map_err(|_| BackendError::Imap("credential lookup timed out".into()))??;

        let tcp = timeout(
            self.config.connect_timeout,
            TcpStream::connect((settings.host.as_str(), settings.port)),
        )
        .await
        .map_err(|_| BackendError::Imap("TCP connection timed out".into()))?
        .map_err(|error| BackendError::Imap(format!("TCP connection failed: {error}")))?;
        tcp.set_nodelay(true)
            .map_err(|error| BackendError::Imap(format!("could not configure TCP: {error}")))?;

        let mut client = match settings.security {
            ImapSecurity::ImplicitTls => {
                let tls = self.upgrade_tls(&settings.host, tcp).await?;
                let mut client = Client::new(ImapTransport::Tls(Box::new(tls)));
                read_greeting(&mut client, self.config.command_timeout).await?;
                client
            }
            ImapSecurity::StartTls => {
                let mut client = Client::new(ImapTransport::Plain(tcp));
                read_greeting(&mut client, self.config.command_timeout).await?;
                let capabilities = command_timeout(
                    self.config.command_timeout,
                    "pre-TLS CAPABILITY",
                    client.capabilities(),
                )
                .await?;
                if !capabilities.has_str("STARTTLS") {
                    return Err(BackendError::Imap(
                        "server did not advertise STARTTLS".into(),
                    ));
                }
                command_timeout(
                    self.config.command_timeout,
                    "STARTTLS",
                    client.run_command_and_check_ok("STARTTLS", None),
                )
                .await?;
                let plain = match client.into_inner() {
                    ImapTransport::Plain(stream) => stream,
                    ImapTransport::Tls(_) => {
                        return Err(BackendError::Imap(
                            "internal STARTTLS transport state is invalid".into(),
                        ));
                    }
                };
                let tls = self.upgrade_tls(&settings.host, plain).await?;
                Client::new(ImapTransport::Tls(Box::new(tls)))
            }
        };

        // Capabilities can change after STARTTLS, so authentication decisions
        // are based only on a fresh encrypted-channel response.
        let pre_auth_capabilities = command_timeout(
            self.config.command_timeout,
            "post-TLS CAPABILITY",
            client.capabilities(),
        )
        .await?;
        let mut session = match credential {
            ImapCredential::Password(secret) => {
                if secret.expose().contains('\0') {
                    return Err(BackendError::InvalidInput(
                        "IMAP password cannot contain a NUL byte".into(),
                    ));
                }
                if pre_auth_capabilities.has_str("AUTH=PLAIN") {
                    command_timeout_auth(
                        self.config.command_timeout,
                        "SASL PLAIN authentication",
                        client.authenticate(
                            "PLAIN",
                            PlainAuthenticator {
                                username: &settings.username,
                                password: secret.expose(),
                                responded: false,
                            },
                        ),
                    )
                    .await?
                } else if !pre_auth_capabilities.has_str("LOGINDISABLED") {
                    command_timeout_auth(
                        self.config.command_timeout,
                        "IMAP LOGIN authentication",
                        client.login(&settings.username, secret.expose()),
                    )
                    .await?
                } else {
                    return Err(BackendError::Imap(
                        "server disables LOGIN and does not advertise SASL PLAIN".into(),
                    ));
                }
            }
            ImapCredential::OAuth2 { access_token } => {
                if access_token.expose().chars().any(char::is_control) {
                    return Err(BackendError::InvalidInput(
                        "OAuth access token contains a protocol control character".into(),
                    ));
                }
                if pre_auth_capabilities.has_str("AUTH=OAUTHBEARER") {
                    command_timeout_auth(
                        self.config.command_timeout,
                        "OAUTHBEARER authentication",
                        client.authenticate(
                            "OAUTHBEARER",
                            OAuthBearerAuthenticator {
                                username: &settings.username,
                                host: &settings.host,
                                port: settings.port,
                                access_token: access_token.expose(),
                                responded: false,
                            },
                        ),
                    )
                    .await?
                } else if pre_auth_capabilities.has_str("AUTH=XOAUTH2") {
                    command_timeout_auth(
                        self.config.command_timeout,
                        "XOAUTH2 authentication",
                        client.authenticate(
                            "XOAUTH2",
                            XOAuth2Authenticator {
                                username: &settings.username,
                                access_token: access_token.expose(),
                                responded: false,
                            },
                        ),
                    )
                    .await?
                } else {
                    return Err(BackendError::Imap(
                        "server does not advertise OAUTHBEARER or XOAUTH2".into(),
                    ));
                }
            }
        };
        let capabilities = command_timeout(
            self.config.command_timeout,
            "authenticated CAPABILITY",
            session.capabilities(),
        )
        .await?;
        Ok((session, capabilities))
    }

    async fn upgrade_tls(&self, host: &str, stream: TcpStream) -> Result<TlsStream<TcpStream>> {
        let server_name = ServerName::try_from(host.to_owned()).map_err(|error| {
            BackendError::InvalidInput(format!("invalid IMAP TLS server name: {error}"))
        })?;
        timeout(
            self.config.connect_timeout,
            self.tls.connect(server_name, stream),
        )
        .await
        .map_err(|_| BackendError::Imap("TLS handshake timed out".into()))?
        .map_err(|error| BackendError::Imap(format!("TLS handshake failed: {error}")))
    }

    async fn process_mutations(
        &self,
        session: &mut Session<ImapTransport>,
        account_id: AccountId,
        capabilities: &Capabilities,
    ) -> Result<ImapMutationSyncReport> {
        let mutations_api = self.backend.imap_mutations();
        if mutations_api.has_blocking_conflict(account_id).await? {
            return Err(BackendError::Conflict(
                "account synchronization is paused because a COPY or MOVE has an ambiguous server outcome"
                    .into(),
            ));
        }
        let due = mutations_api
            .due(account_id, self.config.mutation_batch_size)
            .await?;
        let mut report = ImapMutationSyncReport::default();
        for mutation in due {
            report.attempted += 1;
            if mutation.status == ImapMutationStatus::InFlight
                && matches!(
                    mutation.operation,
                    ImapMutationOperation::Copy { .. } | ImapMutationOperation::Move { .. }
                )
            {
                mutations_api
                    .conflict(
                        &mutation,
                        ImapMutationConflictKind::AmbiguousOutcome,
                        json_mutation_source(&mutation),
                        serde_json::json!({"status": "outcome_unknown_after_interruption"}),
                        "the client was interrupted after sending a non-idempotent COPY or MOVE; automatic retry could duplicate mail",
                    )
                    .await?;
                return Err(BackendError::Conflict(
                    "account synchronization paused after an interrupted COPY or MOVE".into(),
                ));
            }
            match self
                .process_mutation(session, capabilities, &mutation)
                .await?
            {
                MutationOutcome::Applied => report.applied += 1,
                MutationOutcome::Conflict => report.conflicts += 1,
            }
        }
        Ok(report)
    }

    async fn process_mutation(
        &self,
        session: &mut Session<ImapTransport>,
        capabilities: &Capabilities,
        queued: &ImapMutation,
    ) -> Result<MutationOutcome> {
        let mutations_api = self.backend.imap_mutations();
        let Some(source_mailbox) = self
            .remote_mailbox_name(queued.account_id, queued.source.folder_id)
            .await?
        else {
            mutations_api
                .conflict(
                    queued,
                    ImapMutationConflictKind::SourceMissing,
                    json_mutation_source(queued),
                    serde_json::json!({"mailbox": "unavailable"}),
                    "the source mailbox is no longer present and selectable",
                )
                .await?;
            return Ok(MutationOutcome::Conflict);
        };
        let selected = if capabilities.has_str("CONDSTORE") {
            command_timeout(
                self.config.command_timeout,
                "mutation source SELECT CONDSTORE",
                session.select_condstore(&source_mailbox),
            )
            .await?
        } else {
            command_timeout(
                self.config.command_timeout,
                "mutation source SELECT",
                session.select(&source_mailbox),
            )
            .await?
        };
        if selected.uid_validity != Some(queued.source.uid_validity) {
            mutations_api
                .conflict(
                    queued,
                    ImapMutationConflictKind::UidValidityChanged,
                    json_mutation_source(queued),
                    serde_json::json!({"uid_validity": selected.uid_validity}),
                    "the source mailbox UIDVALIDITY epoch changed before the mutation was applied",
                )
                .await?;
            return Ok(MutationOutcome::Conflict);
        }
        let current = self
            .fetch_mutation_source(session, queued, "mutation precondition FETCH")
            .await?;
        let Some(current) = current else {
            if queued.status == ImapMutationStatus::InFlight
                && matches!(queued.operation, ImapMutationOperation::Delete)
            {
                mutations_api.applied(queued, None, None).await?;
                return Ok(MutationOutcome::Applied);
            }
            mutations_api
                .conflict(
                    queued,
                    ImapMutationConflictKind::SourceMissing,
                    json_mutation_source(queued),
                    serde_json::json!({"source_uid": "absent"}),
                    "the source UID disappeared before the mutation could be applied",
                )
                .await?;
            return Ok(MutationOutcome::Conflict);
        };

        match &queued.operation {
            ImapMutationOperation::SetFlags { flags } => {
                if same_flags(&current.flags, flags) {
                    let active = self.begin_if_needed(queued).await?;
                    mutations_api.applied(&active, Some(&current), None).await?;
                    return Ok(MutationOutcome::Applied);
                }
                if !same_flags(&current.flags, &queued.source.flags) {
                    mutations_api
                        .conflict(
                            queued,
                            ImapMutationConflictKind::ServerStateChanged,
                            serde_json::json!({
                                "flags": queued.source.flags,
                                "mod_sequence": queued.source.mod_sequence,
                            }),
                            serde_json::json!({
                                "flags": current.flags,
                                "mod_sequence": current.mod_sequence,
                            }),
                            "server flags changed after the local edit; the backend refused to overwrite them",
                        )
                        .await?;
                    return Ok(MutationOutcome::Conflict);
                }
                let active = self.begin_for_send(queued).await?;
                let flags_argument = format_flag_list(flags);
                let result = if let (true, Some(mod_sequence)) =
                    (capabilities.has_str("CONDSTORE"), current.mod_sequence)
                {
                    let query =
                        format!("(UNCHANGEDSINCE {mod_sequence}) FLAGS.SILENT {flags_argument}");
                    command_timeout(
                        self.config.command_timeout,
                        "conditional UID STORE",
                        async {
                            session
                                .uid_store(active.source.uid.to_string(), query)
                                .await?
                                .try_collect::<Vec<_>>()
                                .await?;
                            Ok::<(), async_imap::error::Error>(())
                        },
                    )
                    .await
                } else {
                    // Without CONDSTORE there is no atomic compare-and-set.
                    // Apply only the intended delta so a concurrently-added
                    // unrelated keyword is never erased by a full replacement.
                    let current_flags = normalize_mutable_flags(current.flags.clone())?;
                    let additions = flag_difference(flags, &current_flags);
                    let removals = flag_difference(&current_flags, flags);
                    command_timeout(self.config.command_timeout, "delta UID STORE", async {
                        if !additions.is_empty() {
                            session
                                .uid_store(
                                    active.source.uid.to_string(),
                                    format!("+FLAGS.SILENT {}", format_flag_list(&additions)),
                                )
                                .await?
                                .try_collect::<Vec<_>>()
                                .await?;
                        }
                        if !removals.is_empty() {
                            session
                                .uid_store(
                                    active.source.uid.to_string(),
                                    format!("-FLAGS.SILENT {}", format_flag_list(&removals)),
                                )
                                .await?
                                .try_collect::<Vec<_>>()
                                .await?;
                        }
                        Ok::<(), async_imap::error::Error>(())
                    })
                    .await
                };
                if let Err(error) = result {
                    mutations_api
                        .note_in_flight_error(&active, &error.to_string())
                        .await?;
                    return Err(error);
                }
                let observed = self
                    .fetch_mutation_source(session, &active, "mutation verification FETCH")
                    .await?;
                let Some(observed) = observed else {
                    mutations_api
                        .conflict(
                            &active,
                            ImapMutationConflictKind::SourceMissing,
                            serde_json::json!({"flags": flags}),
                            serde_json::json!({"source_uid": "absent_after_store"}),
                            "the source UID disappeared while its flags were being changed",
                        )
                        .await?;
                    return Ok(MutationOutcome::Conflict);
                };
                if same_flags(&observed.flags, flags) {
                    mutations_api
                        .applied(&active, Some(&observed), None)
                        .await?;
                    Ok(MutationOutcome::Applied)
                } else {
                    mutations_api
                        .conflict(
                            &active,
                            ImapMutationConflictKind::ServerStateChanged,
                            serde_json::json!({"flags": flags}),
                            serde_json::json!({
                                "flags": observed.flags,
                                "mod_sequence": observed.mod_sequence,
                            }),
                            "the conditional flag update was not applied because the server state changed",
                        )
                        .await?;
                    Ok(MutationOutcome::Conflict)
                }
            }
            ImapMutationOperation::Copy {
                destination_folder_id,
            } => {
                if !self
                    .require_uidplus_or_conflict(queued, capabilities)
                    .await?
                {
                    return Ok(MutationOutcome::Conflict);
                }
                let Some(destination_name) = self
                    .remote_mailbox_name(queued.account_id, *destination_folder_id)
                    .await?
                else {
                    mutations_api
                        .conflict(
                            queued,
                            ImapMutationConflictKind::DestinationUnavailable,
                            serde_json::json!({"destination_folder_id": destination_folder_id}),
                            serde_json::json!({"mailbox": "unavailable"}),
                            "the destination mailbox is no longer present and selectable",
                        )
                        .await?;
                    return Ok(MutationOutcome::Conflict);
                };
                let active = self.begin_for_send(queued).await?;
                let mapping = command_timeout(
                    self.config.command_timeout,
                    "UID COPY",
                    session.uid_copy_with_mapping(active.source.uid.to_string(), destination_name),
                )
                .await;
                let mapping = match mapping {
                    Ok(Some(mapping)) => mapping,
                    Ok(None) => {
                        mutations_api
                            .conflict(
                                &active,
                                ImapMutationConflictKind::MissingServerMapping,
                                serde_json::json!({"capability": "UIDPLUS"}),
                                serde_json::json!({"copy_uid": null}),
                                "the server accepted COPY without returning the required UID mapping",
                            )
                            .await?;
                        return Err(BackendError::Conflict(
                            "account synchronization paused because COPY returned no UID mapping"
                                .into(),
                        ));
                    }
                    Err(error) => {
                        mutations_api
                            .conflict(
                                &active,
                                ImapMutationConflictKind::AmbiguousOutcome,
                                json_mutation_source(&active),
                                serde_json::json!({"error": error.to_string()}),
                                "COPY did not complete observably; automatic retry could create a duplicate",
                            )
                            .await?;
                        return Err(error);
                    }
                };
                let Some(destination_uid) = mapping_for_single_uid(&mapping, active.source.uid)
                else {
                    mutations_api
                        .conflict(
                            &active,
                            ImapMutationConflictKind::MissingServerMapping,
                            serde_json::json!({"source_uid": active.source.uid}),
                            serde_json::json!({"copy_uid": format!("{mapping:?}")}),
                            "COPYUID did not contain a one-to-one mapping for the requested UID",
                        )
                        .await?;
                    return Err(BackendError::Conflict(
                        "account synchronization paused because COPYUID was not one-to-one".into(),
                    ));
                };
                mutations_api
                    .applied(
                        &active,
                        None,
                        Some((
                            *destination_folder_id,
                            mapping.uid_validity,
                            destination_uid,
                            current.flags,
                        )),
                    )
                    .await?;
                Ok(MutationOutcome::Applied)
            }
            ImapMutationOperation::Move {
                destination_folder_id,
            } => {
                if !self
                    .require_uidplus_or_conflict(queued, capabilities)
                    .await?
                {
                    return Ok(MutationOutcome::Conflict);
                }
                let Some(destination_name) = self
                    .remote_mailbox_name(queued.account_id, *destination_folder_id)
                    .await?
                else {
                    mutations_api
                        .conflict(
                            queued,
                            ImapMutationConflictKind::DestinationUnavailable,
                            serde_json::json!({"destination_folder_id": destination_folder_id}),
                            serde_json::json!({"mailbox": "unavailable"}),
                            "the destination mailbox is no longer present and selectable",
                        )
                        .await?;
                    return Ok(MutationOutcome::Conflict);
                };
                let active = self.begin_for_send(queued).await?;
                let result = if capabilities.has_str("MOVE") {
                    command_timeout(
                        self.config.command_timeout,
                        "UID MOVE",
                        session
                            .uid_move_with_mapping(active.source.uid.to_string(), destination_name),
                    )
                    .await
                } else {
                    self.fallback_move(session, active.source.uid, &destination_name)
                        .await
                };
                let mapping = match result {
                    Ok(Some(mapping)) => mapping,
                    Ok(None) => {
                        mutations_api
                            .conflict(
                                &active,
                                ImapMutationConflictKind::MissingServerMapping,
                                serde_json::json!({"capability": "UIDPLUS"}),
                                serde_json::json!({"copy_uid": null}),
                                "the server moved mail without returning a destination UID mapping",
                            )
                            .await?;
                        return Err(BackendError::Conflict(
                            "account synchronization paused because MOVE returned no UID mapping"
                                .into(),
                        ));
                    }
                    Err(error) => {
                        mutations_api
                            .conflict(
                                &active,
                                ImapMutationConflictKind::AmbiguousOutcome,
                                json_mutation_source(&active),
                                serde_json::json!({"error": error.to_string()}),
                                "MOVE may have completed partially; automatic retry could duplicate or misplace mail",
                            )
                            .await?;
                        return Err(error);
                    }
                };
                let Some(destination_uid) = mapping_for_single_uid(&mapping, active.source.uid)
                else {
                    mutations_api
                        .conflict(
                            &active,
                            ImapMutationConflictKind::MissingServerMapping,
                            serde_json::json!({"source_uid": active.source.uid}),
                            serde_json::json!({"copy_uid": format!("{mapping:?}")}),
                            "COPYUID did not contain a one-to-one mapping for the moved UID",
                        )
                        .await?;
                    return Err(BackendError::Conflict(
                        "account synchronization paused because MOVE COPYUID was not one-to-one"
                            .into(),
                    ));
                };
                mutations_api
                    .applied(
                        &active,
                        None,
                        Some((
                            *destination_folder_id,
                            mapping.uid_validity,
                            destination_uid,
                            current.flags,
                        )),
                    )
                    .await?;
                Ok(MutationOutcome::Applied)
            }
            ImapMutationOperation::Delete => {
                if !self
                    .require_uidplus_or_conflict(queued, capabilities)
                    .await?
                {
                    return Ok(MutationOutcome::Conflict);
                }
                let active = self.begin_for_send(queued).await?;
                let result =
                    command_timeout(self.config.command_timeout, "UID delete STORE", async {
                        session
                            .uid_store(active.source.uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                            .await?
                            .try_collect::<Vec<_>>()
                            .await?;
                        session
                            .uid_expunge(active.source.uid.to_string())
                            .await?
                            .try_collect::<Vec<_>>()
                            .await
                    })
                    .await;
                if let Err(error) = result {
                    mutations_api
                        .note_in_flight_error(&active, &error.to_string())
                        .await?;
                    return Err(error);
                }
                mutations_api.applied(&active, None, None).await?;
                Ok(MutationOutcome::Applied)
            }
        }
    }

    async fn begin_if_needed(&self, mutation: &ImapMutation) -> Result<ImapMutation> {
        if mutation.status == ImapMutationStatus::InFlight {
            Ok(mutation.clone())
        } else {
            self.backend.imap_mutations().begin(mutation.id).await
        }
    }

    async fn begin_for_send(&self, mutation: &ImapMutation) -> Result<ImapMutation> {
        if mutation.status == ImapMutationStatus::InFlight {
            self.backend
                .imap_mutations()
                .resume_attempt(mutation.id)
                .await
        } else {
            self.backend.imap_mutations().begin(mutation.id).await
        }
    }

    async fn require_uidplus_or_conflict(
        &self,
        mutation: &ImapMutation,
        capabilities: &Capabilities,
    ) -> Result<bool> {
        if capabilities.has_str("UIDPLUS") {
            return Ok(true);
        }
        self.backend
            .imap_mutations()
            .conflict(
                mutation,
                ImapMutationConflictKind::CapabilityUnavailable,
                serde_json::json!({"required": "UIDPLUS"}),
                serde_json::json!({"capabilities": capability_names(capabilities)}),
                "safe copy, move, and exact expunge require UIDPLUS",
            )
            .await?;
        Ok(false)
    }

    async fn fetch_mutation_source(
        &self,
        session: &mut Session<ImapTransport>,
        mutation: &ImapMutation,
        operation: &str,
    ) -> Result<Option<RemoteMessageIdentity>> {
        let fetches = command_timeout(self.config.command_timeout, operation, async {
            session
                .uid_fetch(mutation.source.uid.to_string(), "(UID FLAGS MODSEQ)")
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        for fetch in &fetches {
            let (uid, mod_sequence, flags) = imap_fetch_state(fetch)?;
            if uid == mutation.source.uid {
                return Ok(Some(RemoteMessageIdentity {
                    account_id: mutation.account_id,
                    folder_id: mutation.source.folder_id,
                    uid_validity: mutation.source.uid_validity,
                    uid,
                    mod_sequence,
                    flags,
                }));
            }
        }
        Ok(None)
    }

    async fn remote_mailbox_name(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
    ) -> Result<Option<String>> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT f.remote_name, s.selectable, s.remote_present FROM folders f JOIN imap_mailbox_state s ON s.folder_id = f.id WHERE f.id = ?1 AND f.account_id = ?2 AND f.kind = 'remote'",
                (folder_id.to_string(), account_id.to_string()),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let selectable: bool = row.get(1)?;
        let present: bool = row.get(2)?;
        if !selectable || !present {
            return Ok(None);
        }
        row.get(0).map_err(Into::into)
    }

    async fn fallback_move(
        &self,
        session: &mut Session<ImapTransport>,
        uid: u32,
        destination_name: &str,
    ) -> Result<Option<CopyUid>> {
        let mapping = command_timeout(
            self.config.command_timeout,
            "fallback UID COPY",
            session.uid_copy_with_mapping(uid.to_string(), destination_name),
        )
        .await?;
        command_timeout(self.config.command_timeout, "fallback move STORE", async {
            session
                .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        command_timeout(
            self.config.command_timeout,
            "fallback move UID EXPUNGE",
            async {
                session
                    .uid_expunge(uid.to_string())
                    .await?
                    .try_collect::<Vec<_>>()
                    .await
            },
        )
        .await?;
        Ok(mapping)
    }

    async fn discover_mailboxes(
        &self,
        session: &mut Session<ImapTransport>,
        account_id: AccountId,
    ) -> Result<Vec<DiscoveredMailbox>> {
        let names = command_timeout(self.config.command_timeout, "LIST", async {
            session
                .list(None, Some("\"*\""))
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        let mailboxes = names
            .iter()
            .map(|name| DiscoveredMailbox {
                folder_id: FolderId::new(),
                remote_name: name.name().to_owned(),
                delimiter: name.delimiter().map(str::to_owned),
                attributes: name.attributes().iter().map(attribute_name).collect(),
                selectable: !name
                    .attributes()
                    .iter()
                    .any(|attribute| matches!(attribute, NameAttribute::NoSelect)),
            })
            .collect::<Vec<_>>();
        self.upsert_discovered_mailboxes(account_id, mailboxes)
            .await
    }

    async fn upsert_discovered_mailboxes(
        &self,
        account_id: AccountId,
        mut mailboxes: Vec<DiscoveredMailbox>,
    ) -> Result<Vec<DiscoveredMailbox>> {
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT id, remote_name FROM folders WHERE account_id = ?1 AND kind = 'remote'",
                (account_id.to_string(),),
            )
            .await?;
        let mut existing = HashMap::new();
        while let Some(row) = rows.next().await? {
            if let Some(remote_name) = row.get::<Option<String>>(1)? {
                existing.insert(remote_name, parse_folder_id(row.get(0)?)?);
            }
        }
        drop(rows);
        transaction
            .execute(
                "UPDATE imap_mailbox_state SET remote_present = 0 WHERE folder_id IN (SELECT id FROM folders WHERE account_id = ?1)",
                (account_id.to_string(),),
            )
            .await?;
        let mut events = Vec::new();
        for mailbox in &mut mailboxes {
            if let Some(id) = existing.get(&mailbox.remote_name) {
                mailbox.folder_id = *id;
            } else {
                transaction
                    .execute(
                        "INSERT INTO folders(id, account_id, name, kind, remote_name, created_at) VALUES (?1, ?2, ?3, 'remote', ?4, ?5)",
                        (
                            mailbox.folder_id.to_string(),
                            account_id.to_string(),
                            mailbox.remote_name.clone(),
                            mailbox.remote_name.clone(),
                            now,
                        ),
                    )
                    .await?;
                events.push(
                    insert_event(
                        &transaction,
                        now,
                        "folder_added",
                        mailbox.folder_id.to_string(),
                        serde_json::json!({
                            "folder_id": mailbox.folder_id,
                            "account_id": account_id,
                            "remote_name": mailbox.remote_name,
                        }),
                    )
                    .await?,
                );
            }
            transaction
                .execute(
                    "INSERT INTO imap_mailbox_state(folder_id, delimiter, attributes_json, selectable, remote_present) VALUES (?1, ?2, ?3, ?4, 1) ON CONFLICT(folder_id) DO UPDATE SET delimiter = excluded.delimiter, attributes_json = excluded.attributes_json, selectable = excluded.selectable, remote_present = 1",
                    turso::params![
                        mailbox.folder_id.to_string(),
                        mailbox.delimiter.clone(),
                        serde_json::to_string(&mailbox.attributes)?,
                        mailbox.selectable,
                    ],
                )
                .await?;
        }
        transaction.commit().await?;
        drop(connection);
        for event in events {
            let _ = self.backend.inner.events.send(event);
        }
        Ok(mailboxes)
    }

    async fn sync_folder(
        &self,
        session: &mut Session<ImapTransport>,
        account_id: AccountId,
        mailbox: &DiscoveredMailbox,
        capabilities: &Capabilities,
        qresync_enabled: bool,
    ) -> Result<ImapFolderSyncReport> {
        let attempt_at = Utc::now().timestamp();
        self.mark_mailbox_attempt(mailbox.folder_id, attempt_at)
            .await?;
        let target = self.load_mailbox_target(mailbox.folder_id).await?;
        let mut known = self
            .known_instances(mailbox.folder_id, target.uid_validity)
            .await?;
        if known.len() > MAX_TRACKED_UIDS {
            return Err(BackendError::Imap(format!(
                "mailbox {} exceeds the configured UID tracking budget",
                mailbox.remote_name
            )));
        }
        let qresync_uids = compact_uid_set(known.keys().copied());
        let can_qresync = qresync_enabled
            && target.uid_validity.is_some()
            && target.highest_mod_sequence.is_some()
            && qresync_uids
                .as_ref()
                .is_some_and(|value| value.len() <= MAX_QRESYNC_UID_SET_BYTES);

        let mut changed = Vec::new();
        let mut vanished = HashSet::new();
        let (selected, used_qresync) = if can_qresync {
            let result = command_timeout(
                self.config.command_timeout,
                "QRESYNC EXAMINE",
                session.examine_qresync(
                    &mailbox.remote_name,
                    target.uid_validity.expect("checked above"),
                    target.highest_mod_sequence.expect("checked above"),
                    qresync_uids.as_deref(),
                ),
            )
            .await?;
            for range in result.vanished {
                for uid in known.keys().copied().filter(|uid| range.contains(uid)) {
                    vanished.insert(uid);
                }
            }
            changed = result.changed;
            (result.mailbox, true)
        } else if capabilities.has_str("CONDSTORE") {
            (
                command_timeout(
                    self.config.command_timeout,
                    "CONDSTORE EXAMINE",
                    session.examine_condstore(&mailbox.remote_name),
                )
                .await?,
                false,
            )
        } else {
            (
                command_timeout(
                    self.config.command_timeout,
                    "EXAMINE",
                    session.examine(&mailbox.remote_name),
                )
                .await?,
                false,
            )
        };
        let uid_validity = selected.uid_validity.ok_or_else(|| {
            BackendError::Imap(format!(
                "mailbox {} did not report UIDVALIDITY",
                mailbox.remote_name
            ))
        })?;
        let same_epoch = target.uid_validity == Some(uid_validity);
        let mut removed_instances = 0;
        if !same_epoch && !known.is_empty() {
            let removed = known.keys().copied().collect::<HashSet<_>>();
            removed_instances += self
                .remove_remote_instances(mailbox.folder_id, target.uid_validity, &removed)
                .await?;
            known.clear();
            changed.clear();
            vanished.clear();
        }
        if same_epoch && !vanished.is_empty() {
            removed_instances += self
                .remove_remote_instances(mailbox.folder_id, Some(uid_validity), &vanished)
                .await?;
            for uid in &vanished {
                known.remove(uid);
            }
        }

        if !used_qresync && same_epoch {
            if capabilities.has_str("CONDSTORE") {
                if let Some(mod_sequence) = target.highest_mod_sequence {
                    changed =
                        command_timeout(self.config.command_timeout, "CHANGEDSINCE FETCH", async {
                            session
                                .uid_fetch(
                                    "1:*",
                                    format!("(UID FLAGS MODSEQ) (CHANGEDSINCE {mod_sequence})"),
                                )
                                .await?
                                .try_collect::<Vec<_>>()
                                .await
                        })
                        .await?;
                }
            } else {
                changed =
                    command_timeout(self.config.command_timeout, "flag reconciliation", async {
                        session
                            .uid_fetch("1:*", "(UID FLAGS)")
                            .await?
                            .try_collect::<Vec<_>>()
                            .await
                    })
                    .await?;
            }
        }
        let refreshed_instances = self
            .apply_changed_fetches(
                account_id,
                mailbox.folder_id,
                uid_validity,
                &known,
                &changed,
            )
            .await?;

        if !used_qresync {
            let current = command_timeout(
                self.config.command_timeout,
                "UID SEARCH ALL",
                session.uid_search("ALL"),
            )
            .await?;
            if current.len() > MAX_TRACKED_UIDS {
                return Err(BackendError::Imap(format!(
                    "mailbox {} exceeds the configured UID tracking budget",
                    mailbox.remote_name
                )));
            }
            let removed = known
                .keys()
                .copied()
                .filter(|uid| !current.contains(uid))
                .collect::<HashSet<_>>();
            if !removed.is_empty() {
                removed_instances += self
                    .remove_remote_instances(mailbox.folder_id, Some(uid_validity), &removed)
                    .await?;
            }
        }

        // The lower-level puller performs bounded streaming body downloads and
        // advances UIDNEXT only after each ingested chunk is durable.
        let pulled = self
            .backend
            .sync()
            .pull_imap_folder(session, account_id, mailbox.folder_id)
            .await?;
        self.store_mailbox_success(
            mailbox.folder_id,
            selected.highest_modseq,
            selected.exists,
            attempt_at,
        )
        .await?;
        Ok(ImapFolderSyncReport {
            folder_id: mailbox.folder_id,
            fetched_messages: pulled.message_ids.len(),
            removed_instances,
            refreshed_instances,
            used_qresync,
        })
    }

    async fn load_mailbox_target(&self, folder_id: FolderId) -> Result<MailboxTarget> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT f.uid_validity, f.uid_next, s.highest_modseq FROM folders f JOIN imap_mailbox_state s ON s.folder_id = f.id WHERE f.id = ?1",
                (folder_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(BackendError::NotFound {
                entity: "IMAP mailbox state",
                id: folder_id.to_string(),
            });
        };
        Ok(MailboxTarget {
            uid_validity: database_u32(row.get(0)?, "folders.uid_validity")?,
            _uid_next: database_u32(row.get(1)?, "folders.uid_next")?,
            highest_mod_sequence: database_u64(row.get(2)?, "imap_mailbox_state.highest_modseq")?,
        })
    }

    async fn known_instances(
        &self,
        folder_id: FolderId,
        uid_validity: Option<u32>,
    ) -> Result<HashMap<u32, crate::MessageId>> {
        let Some(uid_validity) = uid_validity else {
            return Ok(HashMap::new());
        };
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT imap_uid, message_id FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2 ORDER BY imap_uid",
                (folder_id.to_string(), i64::from(uid_validity)),
            )
            .await?;
        let mut instances = HashMap::new();
        while let Some(row) = rows.next().await? {
            let uid = u32::try_from(row.get::<i64>(0)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid IMAP UID".into())
            })?;
            let id = crate::MessageId::from_str(&row.get::<String>(1)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid message ID".into())
            })?;
            instances.insert(uid, id);
        }
        Ok(instances)
    }

    async fn apply_changed_fetches(
        &self,
        account_id: AccountId,
        folder_id: FolderId,
        uid_validity: u32,
        known: &HashMap<u32, crate::MessageId>,
        fetches: &[async_imap::types::Fetch],
    ) -> Result<usize> {
        let mut changes = Vec::new();
        for fetch in fetches {
            let (uid, mod_sequence, flags) = imap_fetch_state(fetch)?;
            if let Some(message_id) = known.get(&uid) {
                changes.push((*message_id, uid, mod_sequence, flags));
            }
        }
        if changes.is_empty() {
            return Ok(0);
        }
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut events = Vec::new();
        let mut refreshed = 0;
        for (message_id, uid, mod_sequence, flags) in changes {
            if let Some(event) = refresh_remote_in_transaction(
                &transaction,
                message_id,
                &RemoteMessageIdentity {
                    account_id,
                    folder_id,
                    uid_validity,
                    uid,
                    mod_sequence,
                    flags,
                },
            )
            .await?
            {
                refreshed += 1;
                events.push(event);
            }
        }
        transaction.commit().await?;
        drop(connection);
        self.backend.flush_search_projection().await?;
        for event in events {
            let _ = self.backend.inner.events.send(event);
        }
        Ok(refreshed)
    }

    async fn remove_remote_instances(
        &self,
        folder_id: FolderId,
        uid_validity: Option<u32>,
        removed: &HashSet<u32>,
    ) -> Result<usize> {
        let Some(uid_validity) = uid_validity else {
            return Ok(0);
        };
        if removed.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT imap_uid, message_id FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2",
                (folder_id.to_string(), i64::from(uid_validity)),
            )
            .await?;
        let mut matches = Vec::new();
        while let Some(row) = rows.next().await? {
            let uid = u32::try_from(row.get::<i64>(0)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid IMAP UID".into())
            })?;
            if removed.contains(&uid) {
                matches.push((uid, row.get::<String>(1)?));
            }
        }
        drop(rows);
        let mut events = Vec::new();
        for (uid, message_id) in &matches {
            transaction
                .execute(
                    "DELETE FROM message_instances WHERE folder_id = ?1 AND uid_validity = ?2 AND imap_uid = ?3",
                    (
                        folder_id.to_string(),
                        i64::from(uid_validity),
                        i64::from(*uid),
                    ),
                )
                .await?;
            let mut rows = transaction
                .query(
                    "SELECT EXISTS(SELECT 1 FROM message_instances WHERE message_id = ?1), EXISTS(SELECT 1 FROM local_folder_memberships WHERE message_id = ?1), (SELECT thread_id FROM messages WHERE id = ?1)",
                    (message_id.clone(),),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| {
                BackendError::InvalidInput("database failed to evaluate message ownership".into())
            })?;
            let has_remote: bool = row.get(0)?;
            let has_local: bool = row.get(1)?;
            let thread_id: Option<String> = row.get(2)?;
            drop(rows);
            if has_remote || has_local {
                let id = crate::MessageId::from_str(message_id).map_err(|_| {
                    BackendError::InvalidInput("database contains invalid message ID".into())
                })?;
                enqueue_search_on(&transaction, id).await?;
            } else {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO search_index_delete_queue(message_id) VALUES (?1)",
                        (message_id.clone(),),
                    )
                    .await?;
                transaction
                    .execute("DELETE FROM messages WHERE id = ?1", (message_id.clone(),))
                    .await?;
                if let Some(thread_id) = thread_id {
                    transaction
                        .execute(
                            "UPDATE threads SET updated_at = (SELECT MAX(received_at) FROM messages WHERE thread_id = ?1) WHERE id = ?1 AND EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                            (thread_id.clone(),),
                        )
                        .await?;
                    transaction
                        .execute(
                            "DELETE FROM threads WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                            (thread_id,),
                        )
                        .await?;
                }
            }
            events.push(
                insert_event(
                    &transaction,
                    now,
                    "message_remote_instance_removed",
                    message_id.clone(),
                    serde_json::json!({
                        "message_id": message_id,
                        "folder_id": folder_id,
                        "uid_validity": uid_validity,
                        "uid": uid,
                        "message_removed": !(has_remote || has_local),
                    }),
                )
                .await?,
            );
        }
        transaction.commit().await?;
        drop(connection);
        self.backend.flush_search_projection().await?;
        for event in events {
            let _ = self.backend.inner.events.send(event);
        }
        Ok(matches.len())
    }

    async fn mark_mailbox_attempt(&self, folder_id: FolderId, now: i64) -> Result<()> {
        let connection = self.backend.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE imap_mailbox_state SET sync_status = 'synchronizing', last_attempt_at = ?1, last_error = NULL WHERE folder_id = ?2",
                (now, folder_id.to_string()),
            )
            .await?;
        Ok(())
    }

    async fn store_mailbox_success(
        &self,
        folder_id: FolderId,
        highest_mod_sequence: Option<u64>,
        exists: u32,
        now: i64,
    ) -> Result<()> {
        let connection = self.backend.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE imap_mailbox_state SET highest_modseq = ?1, exists_count = ?2, sync_status = 'idle', completeness = 'complete', last_success_at = ?3, last_error = NULL WHERE folder_id = ?4",
                turso::params![
                    highest_mod_sequence.map(|value| value as i64),
                    i64::from(exists),
                    now,
                    folder_id.to_string(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn store_mailbox_failure(&self, folder_id: FolderId, error: &str) -> Result<()> {
        let connection = self.backend.inner.connection.lock().await;
        connection
            .execute(
                "UPDATE imap_mailbox_state SET sync_status = 'error', completeness = CASE WHEN last_success_at IS NULL THEN 'partial' ELSE completeness END, last_error = ?1 WHERE folder_id = ?2",
                (error.to_owned(), folder_id.to_string()),
            )
            .await?;
        Ok(())
    }

    async fn store_account_state(
        &self,
        account_id: AccountId,
        status: ImapAccountSyncStatus,
        capabilities: Option<&[String]>,
        error: Option<&str>,
        next_retry_at: Option<i64>,
        success: bool,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let connection = self.backend.inner.connection.lock().await;
        let current = self.state_without_lock(&connection, account_id).await?;
        let capabilities = capabilities
            .map(|value| value.to_vec())
            .unwrap_or(current.capabilities);
        let failure_count = if success {
            0
        } else if error.is_some() {
            current.failure_count.saturating_add(1)
        } else {
            current.failure_count
        };
        connection
            .execute(
                "INSERT INTO imap_account_state(account_id, capabilities_json, status, last_attempt_at, last_success_at, next_retry_at, failure_count, last_error) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(account_id) DO UPDATE SET capabilities_json = excluded.capabilities_json, status = excluded.status, last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at, next_retry_at = excluded.next_retry_at, failure_count = excluded.failure_count, last_error = excluded.last_error",
                turso::params![
                    account_id.to_string(),
                    serde_json::to_string(&capabilities)?,
                    account_status_text(status),
                    if status == ImapAccountSyncStatus::Connecting { Some(now) } else { current.last_attempt_at },
                    if success { Some(now) } else { current.last_success_at },
                    next_retry_at,
                    i64::from(failure_count),
                    error
                        .map(str::to_owned)
                        .or(if success { None } else { current.last_error }),
                ],
            )
            .await?;
        Ok(())
    }

    async fn state_without_lock(
        &self,
        connection: &turso::Connection,
        account_id: AccountId,
    ) -> Result<ImapAccountSyncState> {
        let mut rows = connection
            .query(
                "SELECT capabilities_json, status, last_attempt_at, last_success_at, next_retry_at, failure_count, last_error FROM imap_account_state WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(ImapAccountSyncState {
                account_id,
                capabilities: Vec::new(),
                status: ImapAccountSyncStatus::Idle,
                last_attempt_at: None,
                last_success_at: None,
                next_retry_at: None,
                failure_count: 0,
                last_error: None,
            });
        };
        Ok(ImapAccountSyncState {
            account_id,
            capabilities: serde_json::from_str(&row.get::<String>(0)?)?,
            status: parse_account_status(&row.get::<String>(1)?)?,
            last_attempt_at: row.get(2)?,
            last_success_at: row.get(3)?,
            next_retry_at: row.get(4)?,
            failure_count: u32::try_from(row.get::<i64>(5)?).map_err(|_| {
                BackendError::InvalidInput("database contains invalid IMAP failure count".into())
            })?,
            last_error: row.get(6)?,
        })
    }

    async fn wait_for_change(
        &self,
        account_id: AccountId,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let account = self.load_imap_account(account_id).await?;
        let (mut session, capabilities) = self.connect_and_authenticate(&account).await?;
        if !capabilities.has_str("IDLE") {
            let _ = timeout(self.config.command_timeout, session.logout()).await;
            tokio::select! {
                _ = cancellation.cancelled() => Ok(()),
                _ = sleep(self.config.polling_interval) => Ok(()),
            }
        } else {
            let inbox = self
                .mailbox_states(account_id)
                .await?
                .into_iter()
                .find(|mailbox| {
                    mailbox.remote_present
                        && mailbox.selectable
                        && mailbox.remote_name.eq_ignore_ascii_case("INBOX")
                });
            let Some(inbox) = inbox else {
                let _ = timeout(self.config.command_timeout, session.logout()).await;
                return tokio::select! {
                    _ = cancellation.cancelled() => Ok(()),
                    _ = sleep(self.config.polling_interval) => Ok(()),
                };
            };
            command_timeout(
                self.config.command_timeout,
                "IDLE EXAMINE",
                session.examine(&inbox.remote_name),
            )
            .await?;
            let mut idle = session.idle();
            command_timeout(
                self.config.command_timeout,
                "IDLE initialization",
                idle.init(),
            )
            .await?;
            {
                let (wait, _interrupt) = idle.wait_with_timeout(self.config.idle_refresh);
                tokio::select! {
                    _ = cancellation.cancelled() => {},
                    result = wait => {
                        match result.map_err(imap_error)? {
                            IdleResponse::ManualInterrupt
                            | IdleResponse::Timeout
                            | IdleResponse::NewData(_) => {}
                        }
                    }
                }
            }
            let mut session =
                command_timeout(self.config.command_timeout, "IDLE completion", idle.done())
                    .await?;
            let _ = timeout(self.config.command_timeout, session.logout()).await;
            Ok(())
        }
    }

    async fn wait_backoff(
        &self,
        account_id: AccountId,
        failures: u32,
        error: &BackendError,
        record_error: bool,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let multiplier = 1_u32 << failures.saturating_sub(1).min(16);
        let delay = self
            .config
            .backoff_initial
            .saturating_mul(multiplier)
            .min(self.config.backoff_maximum);
        let retry_at = Utc::now()
            .timestamp()
            .saturating_add(i64::try_from(delay.as_secs()).unwrap_or(i64::MAX));
        let error_text = record_error.then(|| error.to_string());
        self.store_account_state(
            account_id,
            ImapAccountSyncStatus::Backoff,
            None,
            error_text.as_deref(),
            Some(retry_at),
            false,
        )
        .await?;
        tokio::select! {
            _ = cancellation.cancelled() => Ok(()),
            _ = sleep(delay) => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
struct DiscoveredMailbox {
    folder_id: FolderId,
    remote_name: String,
    delimiter: Option<String>,
    attributes: Vec<String>,
    selectable: bool,
}

struct MailboxTarget {
    uid_validity: Option<u32>,
    _uid_next: Option<u32>,
    highest_mod_sequence: Option<u64>,
}

enum MutationOutcome {
    Applied,
    Conflict,
}

fn same_flags(left: &[String], right: &[String]) -> bool {
    let normalize = |flags: &[String]| {
        let mut values = flags
            .iter()
            .filter(|flag| !flag.eq_ignore_ascii_case("\\Recent"))
            .map(|flag| flag.to_ascii_lowercase())
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        values
    };
    normalize(left) == normalize(right)
}

fn format_flag_list(flags: &[String]) -> String {
    format!("({})", flags.join(" "))
}

fn flag_difference(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|candidate| {
            !right
                .iter()
                .any(|other| candidate.eq_ignore_ascii_case(other))
        })
        .cloned()
        .collect()
}

fn mapping_for_single_uid(mapping: &CopyUid, source_uid: u32) -> Option<u32> {
    if mapping.source.len() != 1 || mapping.destination.len() != 1 {
        return None;
    }
    let source = &mapping.source[0];
    let destination = &mapping.destination[0];
    if source.start() != source.end()
        || destination.start() != destination.end()
        || *source.start() != source_uid
    {
        return None;
    }
    Some(*destination.start())
}

fn json_mutation_source(mutation: &ImapMutation) -> serde_json::Value {
    serde_json::json!({
        "message_id": mutation.message_id,
        "account_id": mutation.account_id,
        "folder_id": mutation.source.folder_id,
        "uid_validity": mutation.source.uid_validity,
        "uid": mutation.source.uid,
        "mod_sequence": mutation.source.mod_sequence,
        "flags": mutation.source.flags,
    })
}

enum ImapTransport {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl fmt::Debug for ImapTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => formatter.write_str("ImapTransport::Plain"),
            Self::Tls(_) => formatter.write_str("ImapTransport::Tls"),
        }
    }
}

impl AsyncRead for ImapTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ImapTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

struct PlainAuthenticator<'a> {
    username: &'a str,
    password: &'a str,
    responded: bool,
}

impl Authenticator for PlainAuthenticator<'_> {
    type Response = Vec<u8>;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        if self.responded {
            return Vec::new();
        }
        self.responded = true;
        let mut response = Vec::with_capacity(self.username.len() + self.password.len() + 2);
        response.push(0);
        response.extend_from_slice(self.username.as_bytes());
        response.push(0);
        response.extend_from_slice(self.password.as_bytes());
        response
    }
}

struct XOAuth2Authenticator<'a> {
    username: &'a str,
    access_token: &'a str,
    responded: bool,
}

impl Authenticator for XOAuth2Authenticator<'_> {
    type Response = Vec<u8>;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        if self.responded {
            return Vec::new();
        }
        self.responded = true;
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.username, self.access_token
        )
        .into_bytes()
    }
}

struct OAuthBearerAuthenticator<'a> {
    username: &'a str,
    host: &'a str,
    port: u16,
    access_token: &'a str,
    responded: bool,
}

impl Authenticator for OAuthBearerAuthenticator<'_> {
    type Response = Vec<u8>;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        if self.responded {
            return Vec::new();
        }
        self.responded = true;
        format!(
            "n,a={},\x01host={}\x01port={}\x01auth=Bearer {}\x01\x01",
            sasl_name(self.username),
            self.host,
            self.port,
            self.access_token
        )
        .into_bytes()
    }
}

fn sasl_name(value: &str) -> String {
    value.replace('=', "=3D").replace(',', "=2C")
}

async fn read_greeting(client: &mut Client<ImapTransport>, duration: Duration) -> Result<()> {
    timeout(duration, client.read_response())
        .await
        .map_err(|_| BackendError::Imap("server greeting timed out".into()))?
        .map_err(|error| BackendError::Imap(format!("could not read server greeting: {error}")))?
        .ok_or_else(|| BackendError::Imap("server closed before its greeting".into()))?;
    Ok(())
}

async fn command_timeout<T, E, F>(duration: Duration, operation: &str, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: fmt::Display,
{
    timeout(duration, future)
        .await
        .map_err(|_| BackendError::Imap(format!("{operation} timed out")))?
        .map_err(|error| BackendError::Imap(format!("{operation} failed: {error}")))
}

async fn command_timeout_auth<T, F, C>(duration: Duration, operation: &str, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, (async_imap::error::Error, C)>>,
{
    timeout(duration, future)
        .await
        .map_err(|_| BackendError::Imap(format!("{operation} timed out")))?
        .map_err(|(error, _)| BackendError::Imap(format!("{operation} failed: {error}")))
}

fn imap_error(error: async_imap::error::Error) -> BackendError {
    BackendError::Imap(error.to_string())
}

fn capability_names(capabilities: &Capabilities) -> Vec<String> {
    let mut values = capabilities
        .iter()
        .map(|capability| match capability {
            Capability::Imap4rev1 => "IMAP4rev1".to_owned(),
            Capability::Auth(mechanism) => format!("AUTH={mechanism}"),
            Capability::Atom(atom) => atom.clone(),
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|value| value.to_ascii_uppercase());
    values.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    values
}

fn attribute_name(attribute: &NameAttribute<'_>) -> String {
    match attribute {
        NameAttribute::NoInferiors => "\\NoInferiors".into(),
        NameAttribute::NoSelect => "\\NoSelect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::All => "\\All".into(),
        NameAttribute::Archive => "\\Archive".into(),
        NameAttribute::Drafts => "\\Drafts".into(),
        NameAttribute::Flagged => "\\Flagged".into(),
        NameAttribute::Junk => "\\Junk".into(),
        NameAttribute::Sent => "\\Sent".into(),
        NameAttribute::Trash => "\\Trash".into(),
        NameAttribute::Extension(value) => value.to_string(),
        _ => "\\Unknown".into(),
    }
}

fn compact_uid_set(uids: impl IntoIterator<Item = u32>) -> Option<String> {
    let mut uids = uids.into_iter().filter(|uid| *uid != 0).collect::<Vec<_>>();
    if uids.is_empty() {
        return None;
    }
    uids.sort_unstable();
    uids.dedup();
    let mut ranges = Vec::new();
    let mut start = uids[0];
    let mut end = start;
    for uid in uids.into_iter().skip(1) {
        if uid == end.saturating_add(1) {
            end = uid;
        } else {
            ranges.push(if start == end {
                start.to_string()
            } else {
                format!("{start}:{end}")
            });
            start = uid;
            end = uid;
        }
    }
    ranges.push(if start == end {
        start.to_string()
    } else {
        format!("{start}:{end}")
    });
    Some(ranges.join(","))
}

fn parse_folder_id(value: String) -> Result<FolderId> {
    FolderId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid folder ID".into()))
}

fn database_u32(value: Option<i64>, field: &str) -> Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|_| {
                BackendError::InvalidInput(format!("database contains invalid {field}"))
            })
        })
        .transpose()
}

fn database_u64(value: Option<i64>, field: &str) -> Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                BackendError::InvalidInput(format!("database contains invalid {field}"))
            })
        })
        .transpose()
}

fn account_status_text(status: ImapAccountSyncStatus) -> &'static str {
    match status {
        ImapAccountSyncStatus::Idle => "idle",
        ImapAccountSyncStatus::Connecting => "connecting",
        ImapAccountSyncStatus::Authenticating => "authenticating",
        ImapAccountSyncStatus::Discovering => "discovering",
        ImapAccountSyncStatus::Synchronizing => "synchronizing",
        ImapAccountSyncStatus::Waiting => "waiting",
        ImapAccountSyncStatus::Backoff => "backoff",
        ImapAccountSyncStatus::Error => "error",
        ImapAccountSyncStatus::Stopped => "stopped",
    }
}

fn parse_account_status(value: &str) -> Result<ImapAccountSyncStatus> {
    match value {
        "idle" => Ok(ImapAccountSyncStatus::Idle),
        "connecting" => Ok(ImapAccountSyncStatus::Connecting),
        "authenticating" => Ok(ImapAccountSyncStatus::Authenticating),
        "discovering" => Ok(ImapAccountSyncStatus::Discovering),
        "synchronizing" => Ok(ImapAccountSyncStatus::Synchronizing),
        "waiting" => Ok(ImapAccountSyncStatus::Waiting),
        "backoff" => Ok(ImapAccountSyncStatus::Backoff),
        "error" => Ok(ImapAccountSyncStatus::Error),
        "stopped" => Ok(ImapAccountSyncStatus::Stopped),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid IMAP account status".into(),
        )),
    }
}

fn parse_completeness(value: &str) -> Result<ImapMailboxCompleteness> {
    match value {
        "not_started" => Ok(ImapMailboxCompleteness::NotStarted),
        "partial" => Ok(ImapMailboxCompleteness::Partial),
        "complete" => Ok(ImapMailboxCompleteness::Complete),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid IMAP mailbox completeness".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_and_uid_sets_are_compact() {
        let secret = SecretValue::new("correct horse battery staple");
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        assert_eq!(compact_uid_set([7, 2, 3, 4, 9, 7]), Some("2:4,7,9".into()));
        assert_eq!(
            flag_difference(&["\\Seen".into(), "$Label".into()], &["\\seen".into()]),
            vec!["$Label"]
        );
    }
}
