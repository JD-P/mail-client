//! Disposable process boundary for hostile IMAP protocol and message input.
//!
//! The supervisor retains the live Tantivy writer and event subscribers.  A
//! worker receives one resolved credential, operates on the durable profile,
//! and exits.  On Linux the worker fails closed unless Landlock, no-new-privs,
//! resource limits, signal scoping, TCP port restrictions, and the small
//! seccomp adapter below are all installed.

use crate::{
    backend::DownloadAttemptGuard, AccountId, Backend, BackendConfig, BackendError,
    CredentialProvider, DkimDnsResolver, ImapAccountEngine, ImapAccountEngineConfig,
    ImapAccountSyncReport, ImapAccountSyncState, ImapAccountSyncStatus, ImapCredential,
    ImapMailboxSyncState, MessageContentStatus, MessageId, Result, SecretValue, StorageUsage,
};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::process::Command;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const WORKER_PROTOCOL_VERSION: u32 = 1;
const MAX_WORKER_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKER_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKER_ERROR_CHARS: usize = 4 * 1024;

#[derive(Clone, Debug)]
pub struct ImapSyncIsolationConfig {
    /// Absolute path to the separately installed worker executable.
    pub worker_path: PathBuf,
    /// Hard virtual-address-space ceiling for each disposable worker.
    pub memory_limit_bytes: u64,
    /// Hard CPU-time ceiling for each disposable worker.
    pub cpu_time_seconds: u64,
    /// Maximum size of any file the worker may create.
    pub file_size_limit_bytes: u64,
    /// Wall-clock ceiling for a complete synchronization operation.
    pub operation_timeout: Duration,
}

impl Default for ImapSyncIsolationConfig {
    fn default() -> Self {
        Self {
            worker_path: default_worker_path(),
            memory_limit_bytes: 1024 * 1024 * 1024,
            cpu_time_seconds: 5 * 60,
            file_size_limit_bytes: 64 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(2 * 60 * 60),
        }
    }
}

fn default_worker_path() -> PathBuf {
    let name = if cfg!(windows) {
        "lizard-mail-sync-worker.exe"
    } else {
        "lizard-mail-sync-worker"
    };
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_owned))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(name)
}

#[derive(Clone)]
pub struct IsolatedImapAccountEngine {
    backend: Backend,
    credentials: Arc<dyn CredentialProvider>,
    engine: ImapAccountEngine,
    engine_config: ImapAccountEngineConfig,
    isolation: ImapSyncIsolationConfig,
}

impl IsolatedImapAccountEngine {
    pub fn new(
        backend: Backend,
        credentials: Arc<dyn CredentialProvider>,
        engine_config: ImapAccountEngineConfig,
        mut isolation: ImapSyncIsolationConfig,
    ) -> Result<Self> {
        if isolation.memory_limit_bytes < 256 * 1024 * 1024
            || isolation.cpu_time_seconds == 0
            || isolation.file_size_limit_bytes < 64 * 1024 * 1024
            || isolation.operation_timeout.is_zero()
        {
            return Err(BackendError::InvalidInput(
                "isolated IMAP worker limits are too small or zero".into(),
            ));
        }
        if backend.inner.config.dkim_dns != DkimDnsResolver::Quad9Tls {
            return Err(BackendError::InvalidInput(
                "isolated IMAP synchronization requires the encrypted TCP DKIM resolver".into(),
            ));
        }
        isolation.worker_path = std::fs::canonicalize(&isolation.worker_path)
            .map_err(|source| crate::error::io_error(isolation.worker_path.clone(), source))?;
        if !isolation.worker_path.is_absolute() {
            return Err(BackendError::InvalidInput(
                "isolated IMAP worker path must be absolute".into(),
            ));
        }
        let engine = ImapAccountEngine::new(
            backend.clone(),
            Arc::clone(&credentials),
            engine_config.clone(),
        )?;
        Ok(Self {
            backend,
            credentials,
            engine,
            engine_config,
            isolation,
        })
    }

    pub async fn state(&self, account_id: AccountId) -> Result<ImapAccountSyncState> {
        self.engine.state(account_id).await
    }

    pub async fn mailbox_states(&self, account_id: AccountId) -> Result<Vec<ImapMailboxSyncState>> {
        self.engine.mailbox_states(account_id).await
    }

    pub async fn sync_once(&self, account_id: AccountId) -> Result<ImapAccountSyncReport> {
        let cursor = self.backend.current_change_cursor().await?;
        let outcome = self.execute(account_id, WorkerOperation::SyncOnce).await;
        let publish = self.backend.publish_worker_changes(cursor).await;
        match (outcome, publish) {
            (Ok(WorkerResult::Sync(report)), Ok(())) => Ok(report),
            (Ok(_), _) => Err(BackendError::Imap(
                "isolated IMAP worker returned the wrong result type".into(),
            )),
            (Err(error), Ok(())) => {
                if error.infrastructure {
                    self.record_infrastructure_failure(account_id, &error.detail)
                        .await?;
                }
                Err(BackendError::Imap(error.detail))
            }
            (_, Err(error)) => Err(error),
        }
    }

    pub async fn fetch_message_content(
        &self,
        message_id: MessageId,
    ) -> Result<MessageContentStatus> {
        let account_id = self.remote_account_for_message(message_id).await?;
        let mut attempt = DownloadAttemptGuard::new(self.backend.clone(), message_id);
        let cursor = self.backend.current_change_cursor().await?;
        let outcome = self
            .execute(
                account_id,
                WorkerOperation::FetchMessageContent { message_id },
            )
            .await;
        self.backend.publish_worker_changes(cursor).await?;
        match outcome {
            Ok(WorkerResult::Content(status)) => {
                attempt.disarm();
                Ok(status)
            }
            Ok(_) => Err(BackendError::Imap(
                "isolated IMAP worker returned the wrong result type".into(),
            )),
            Err(error) => {
                if error.infrastructure {
                    let current = self.backend.messages().content_status(message_id).await?;
                    self.backend
                        .store_download_failure(message_id, current.downloaded_bytes, &error.detail)
                        .await?;
                    self.record_infrastructure_failure(account_id, &error.detail)
                        .await?;
                }
                attempt.disarm();
                Err(BackendError::Imap(error.detail))
            }
        }
    }

    /// Continuously synchronize in short-lived workers.  IDLE itself runs in
    /// a separate disposable worker, so every notification cycle receives a
    /// fresh resource budget and a parser crash cannot terminate the parent.
    pub async fn run(&self, account_id: AccountId, cancellation: CancellationToken) -> Result<()> {
        let mut consecutive_failures = 0_u32;
        while !cancellation.is_cancelled() {
            let sync = tokio::select! {
                _ = cancellation.cancelled() => break,
                result = self.sync_once(account_id) => result,
            };
            match sync {
                Ok(report) => {
                    consecutive_failures = 0;
                    self.engine
                        .store_account_state(
                            account_id,
                            ImapAccountSyncStatus::Waiting,
                            Some(&report.capabilities),
                            None,
                            None,
                            false,
                        )
                        .await?;
                    let wait_timeout = self
                        .engine_config
                        .idle_refresh
                        .saturating_add(self.engine_config.connect_timeout)
                        .saturating_add(self.engine_config.command_timeout.saturating_mul(4));
                    let wait = tokio::select! {
                        _ = cancellation.cancelled() => break,
                        result = self.execute_with_timeout(account_id, WorkerOperation::WaitForChange, wait_timeout) => result,
                    };
                    if let Err(error) = wait {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        self.engine
                            .wait_backoff(
                                account_id,
                                consecutive_failures,
                                &BackendError::Imap(error.detail),
                                true,
                                &cancellation,
                            )
                            .await?;
                    }
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    self.engine
                        .wait_backoff(
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
        self.engine
            .store_account_state(
                account_id,
                ImapAccountSyncStatus::Stopped,
                None,
                None,
                None,
                false,
            )
            .await
    }

    async fn execute(
        &self,
        account_id: AccountId,
        operation: WorkerOperation,
    ) -> std::result::Result<WorkerResult, WorkerFailure> {
        self.execute_with_timeout(account_id, operation, self.isolation.operation_timeout)
            .await
    }

    async fn execute_with_timeout(
        &self,
        account_id: AccountId,
        operation: WorkerOperation,
        wall_timeout: Duration,
    ) -> std::result::Result<WorkerResult, WorkerFailure> {
        let account = self
            .engine
            .load_imap_account(account_id)
            .await
            .map_err(WorkerFailure::operation)?;
        let settings = account.imap.as_ref().ok_or_else(|| {
            WorkerFailure::operation(BackendError::InvalidInput(
                "IMAP account has no connection settings".into(),
            ))
        })?;
        let reference = account.credential_ref.as_deref().ok_or_else(|| {
            WorkerFailure::operation(BackendError::InvalidInput(
                "IMAP account has no credential reference".into(),
            ))
        })?;
        let credential = timeout(
            self.engine_config.command_timeout,
            self.credentials.resolve(reference),
        )
        .await
        .map_err(|_| WorkerFailure::infrastructure("credential lookup timed out"))?
        .map_err(WorkerFailure::operation)?;
        let mut addresses = timeout(
            self.engine_config.connect_timeout,
            lookup_host((settings.host.as_str(), settings.port)),
        )
        .await
        .map_err(|_| WorkerFailure::infrastructure("IMAP hostname lookup timed out"))?
        .map_err(|error| {
            WorkerFailure::infrastructure(format!("IMAP hostname lookup failed: {error}"))
        })?
        .take(16)
        .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(WorkerFailure::infrastructure(
                "IMAP hostname resolved to no addresses",
            ));
        }
        let mut tcp_ports = vec![settings.port, 853];
        tcp_ports.sort_unstable();
        tcp_ports.dedup();
        let mut backend_config = self.backend.inner.config.clone();
        backend_config.profile_dir =
            std::fs::canonicalize(&backend_config.profile_dir).map_err(|error| {
                WorkerFailure::infrastructure(format!(
                    "could not resolve the mail profile directory: {error}"
                ))
            })?;
        let observed_storage = self
            .backend
            .storage()
            .usage()
            .await
            .map_err(WorkerFailure::operation)?;
        let request = WorkerRequest {
            protocol: WORKER_PROTOCOL_VERSION,
            backend: backend_config,
            engine: self.engine_config.clone(),
            account_id,
            credential_reference: reference.to_owned(),
            credential: WireCredential::from(credential),
            imap_host: settings.host.clone(),
            imap_port: settings.port,
            resolved_addresses: addresses,
            operation,
            limits: WorkerLimits {
                memory_bytes: self.isolation.memory_limit_bytes,
                cpu_seconds: self.isolation.cpu_time_seconds,
                file_size_bytes: self.isolation.file_size_limit_bytes,
                tcp_ports,
            },
            observed_storage,
        };
        self.spawn_worker(request, wall_timeout).await
    }

    async fn spawn_worker(
        &self,
        request: WorkerRequest,
        wall_timeout: Duration,
    ) -> std::result::Result<WorkerResult, WorkerFailure> {
        let worker_current_dir = request.backend.profile_dir.clone();
        let mut payload =
            Zeroizing::new(serde_json::to_vec(&request).map_err(WorkerFailure::operation)?);
        drop(request);
        if payload.len() > MAX_WORKER_REQUEST_BYTES {
            return Err(WorkerFailure::infrastructure(
                "isolated IMAP worker request exceeds its protocol limit",
            ));
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| WorkerFailure::infrastructure("worker request length overflow"))?;
        let mut child = Command::new(&self.isolation.worker_path)
            .arg("--worker-v1")
            .env_clear()
            .env("RUST_BACKTRACE", "0")
            .current_dir(worker_current_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                WorkerFailure::infrastructure(format!("could not start IMAP worker: {error}"))
            })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerFailure::infrastructure("IMAP worker stdin was unavailable"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerFailure::infrastructure("IMAP worker stdout was unavailable"))?;
        let exchange = async {
            stdin.write_all(&length.to_be_bytes()).await?;
            stdin.write_all(payload.as_slice()).await?;
            stdin.shutdown().await?;
            payload.zeroize();

            let mut response_length = [0_u8; 4];
            stdout.read_exact(&mut response_length).await?;
            let response_length = u32::from_be_bytes(response_length) as usize;
            if response_length > MAX_WORKER_RESPONSE_BYTES {
                return Err(std::io::Error::other(
                    "IMAP worker response exceeds its protocol limit",
                ));
            }
            let mut response = vec![0_u8; response_length];
            stdout.read_exact(&mut response).await?;
            let status = child.wait().await?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "IMAP worker exited unsuccessfully: {status}"
                )));
            }
            Ok::<_, std::io::Error>(response)
        };
        let response = match timeout(wall_timeout, exchange).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(WorkerFailure::infrastructure(format!(
                    "isolated IMAP worker protocol failed: {error}"
                )));
            }
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(WorkerFailure::infrastructure(
                    "isolated IMAP worker exceeded its wall-clock limit",
                ));
            }
        };
        let response: WorkerResponse = serde_json::from_slice(&response).map_err(|error| {
            WorkerFailure::infrastructure(format!("invalid IMAP worker response: {error}"))
        })?;
        if response.protocol != WORKER_PROTOCOL_VERSION {
            return Err(WorkerFailure::infrastructure(
                "IMAP worker protocol version mismatch",
            ));
        }
        response
            .result
            .map_err(|detail| WorkerFailure::operation_detail(bounded_error(&detail)))
    }

    async fn remote_account_for_message(&self, message_id: MessageId) -> Result<AccountId> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                r#"SELECT mi.account_id
                FROM message_instances mi
                JOIN folders f ON f.id = mi.folder_id
                LEFT JOIN imap_mailbox_state ims ON ims.folder_id = f.id
                WHERE mi.message_id = ?1 AND f.kind = 'remote'
                    AND f.remote_name IS NOT NULL
                    AND COALESCE(ims.remote_present, 1) = 1
                    AND COALESCE(ims.selectable, 1) = 1
                ORDER BY mi.account_id, mi.folder_id, mi.imap_uid
                LIMIT 1"#,
                (message_id.to_string(),),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| {
            BackendError::InvalidInput("message has no remote account to download from".into())
        })?;
        row.get::<String>(0)?.parse().map_err(|_| {
            BackendError::InvalidInput("database contains an invalid account identifier".into())
        })
    }

    async fn record_infrastructure_failure(
        &self,
        account_id: AccountId,
        detail: &str,
    ) -> Result<()> {
        self.engine
            .store_account_state(
                account_id,
                ImapAccountSyncStatus::Error,
                None,
                Some(&bounded_error(detail)),
                None,
                false,
            )
            .await
    }
}

struct WorkerFailure {
    detail: String,
    infrastructure: bool,
}

impl WorkerFailure {
    fn infrastructure(detail: impl Into<String>) -> Self {
        Self {
            detail: bounded_error(&detail.into()),
            infrastructure: true,
        }
    }

    fn operation(error: impl std::fmt::Display) -> Self {
        Self::operation_detail(error.to_string())
    }

    fn operation_detail(detail: impl Into<String>) -> Self {
        Self {
            detail: bounded_error(&detail.into()),
            infrastructure: false,
        }
    }
}

fn bounded_error(detail: &str) -> String {
    detail
        .chars()
        .take(MAX_WORKER_ERROR_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
struct WorkerRequest {
    protocol: u32,
    backend: BackendConfig,
    engine: ImapAccountEngineConfig,
    account_id: AccountId,
    credential_reference: String,
    credential: WireCredential,
    imap_host: String,
    imap_port: u16,
    resolved_addresses: Vec<SocketAddr>,
    operation: WorkerOperation,
    limits: WorkerLimits,
    observed_storage: StorageUsage,
}

#[derive(Serialize, Deserialize)]
struct WorkerLimits {
    memory_bytes: u64,
    cpu_seconds: u64,
    file_size_bytes: u64,
    tcp_ports: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
enum WorkerOperation {
    SyncOnce,
    FetchMessageContent { message_id: MessageId },
    WaitForChange,
}

#[derive(Serialize, Deserialize)]
enum WorkerResult {
    Sync(ImapAccountSyncReport),
    Content(MessageContentStatus),
    Waited,
}

#[derive(Serialize, Deserialize)]
struct WorkerResponse {
    protocol: u32,
    result: std::result::Result<WorkerResult, String>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum WireCredentialKind {
    Password,
    OAuth2,
}

#[derive(Serialize, Deserialize)]
struct WireCredential {
    kind: WireCredentialKind,
    secret: String,
}

impl From<ImapCredential> for WireCredential {
    fn from(credential: ImapCredential) -> Self {
        match credential {
            ImapCredential::Password(secret) => Self {
                kind: WireCredentialKind::Password,
                secret: secret.expose().to_owned(),
            },
            ImapCredential::OAuth2 { access_token } => Self {
                kind: WireCredentialKind::OAuth2,
                secret: access_token.expose().to_owned(),
            },
        }
    }
}

impl Drop for WireCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

struct WorkerCredentialProvider {
    reference: String,
    kind: WireCredentialKind,
    secret: Zeroizing<String>,
}

impl CredentialProvider for WorkerCredentialProvider {
    fn resolve<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>> {
        Box::pin(async move {
            if reference != self.reference {
                return Err(BackendError::CredentialStore(
                    "isolated worker was asked for an unexpected credential".into(),
                ));
            }
            Ok(match self.kind {
                WireCredentialKind::Password => {
                    ImapCredential::Password(SecretValue::new(self.secret.to_string()))
                }
                WireCredentialKind::OAuth2 => ImapCredential::OAuth2 {
                    access_token: SecretValue::new(self.secret.to_string()),
                },
            })
        })
    }
}

pub(crate) fn run_worker_process() -> std::result::Result<(), String> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    if mode.as_deref() == Some(std::ffi::OsStr::new("--sandbox-self-test")) {
        let profile = arguments
            .next()
            .ok_or("sandbox self-test requires a profile directory")?;
        return sandbox_self_test(Path::new(&profile));
    }
    if mode.as_deref() != Some(std::ffi::OsStr::new("--worker-v1")) {
        return Err("this executable is an internal isolated worker".into());
    }
    let mut length = [0_u8; 4];
    std::io::stdin()
        .read_exact(&mut length)
        .map_err(|error| format!("reading request length: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_WORKER_REQUEST_BYTES {
        return Err("worker request exceeds its protocol limit".into());
    }
    let mut payload = vec![0_u8; length];
    std::io::stdin()
        .read_exact(&mut payload)
        .map_err(|error| format!("reading request: {error}"))?;
    let request: WorkerRequest = serde_json::from_slice(&payload)
        .map_err(|error| format!("parsing worker request: {error}"))?;
    payload.zeroize();
    if request.protocol != WORKER_PROTOCOL_VERSION {
        return Err("worker protocol version mismatch".into());
    }
    validate_worker_request(&request)?;
    install_worker_sandbox(&request)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("creating worker runtime: {error}"))?;
    let response = runtime.block_on(run_worker_request(request));
    let response = WorkerResponse {
        protocol: WORKER_PROTOCOL_VERSION,
        result: response.map_err(|error| bounded_error(&error.to_string())),
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|error| format!("serializing worker response: {error}"))?;
    if bytes.len() > MAX_WORKER_RESPONSE_BYTES {
        return Err("worker response exceeds its protocol limit".into());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "worker response length overflow")?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&length.to_be_bytes())
        .and_then(|()| stdout.write_all(&bytes))
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("writing worker response: {error}"))
}

#[cfg(target_os = "linux")]
fn sandbox_self_test(profile: &Path) -> std::result::Result<(), String> {
    #[derive(Serialize)]
    struct Evidence {
        profile_write_allowed: bool,
        credential_read_denied: bool,
        unrelated_profile_write_denied: bool,
        outside_read_denied: bool,
        outside_write_denied: bool,
        execute_denied: bool,
        udp_socket_denied: bool,
        unlisted_tcp_port_denied: bool,
    }

    std::fs::create_dir_all(profile)
        .map_err(|error| format!("creating self-test profile: {error}"))?;
    std::fs::create_dir_all(profile.join("blobs"))
        .map_err(|error| format!("creating self-test blob directory: {error}"))?;
    std::fs::create_dir_all(profile.join("downloads"))
        .map_err(|error| format!("creating self-test download directory: {error}"))?;
    std::fs::create_dir_all(profile.join("credentials"))
        .map_err(|error| format!("creating self-test credential directory: {error}"))?;
    std::fs::write(profile.join("mail.db"), b"db")
        .map_err(|error| format!("creating self-test database: {error}"))?;
    std::fs::write(profile.join("mail.db-wal"), b"wal")
        .map_err(|error| format!("creating self-test database WAL: {error}"))?;
    std::fs::write(profile.join("credentials/secret"), b"not for the worker")
        .map_err(|error| format!("creating self-test credential: {error}"))?;
    let limits = WorkerLimits {
        memory_bytes: 512 * 1024 * 1024,
        cpu_seconds: 30,
        file_size_bytes: 64 * 1024 * 1024,
        tcp_ports: vec![9],
    };
    set_worker_limits(&limits)?;
    enter_landlock(profile, &limits.tcp_ports)?;
    enter_seccomp()?;

    let inside = profile.join("blobs/sandbox-self-test.tmp");
    let profile_write_allowed = std::fs::write(&inside, b"bounded worker").is_ok();
    let _ = std::fs::remove_file(&inside);
    let credential_read_denied = std::fs::read(profile.join("credentials/secret")).is_err();
    let unrelated_profile_write_denied =
        std::fs::write(profile.join("sandbox-escape.tmp"), b"no").is_err();
    let outside_read_denied = std::fs::read("/etc/passwd").is_err();
    let outside_write_denied = std::fs::write("/tmp/lizard-worker-escape", b"no").is_err();
    let execute_denied = std::process::Command::new("/bin/true").status().is_err();
    let udp_socket_denied = std::net::UdpSocket::bind("127.0.0.1:0").is_err();
    let unlisted_tcp_port_denied = std::net::TcpStream::connect("127.0.0.1:10").is_err();
    let evidence = Evidence {
        profile_write_allowed,
        credential_read_denied,
        unrelated_profile_write_denied,
        outside_read_denied,
        outside_write_denied,
        execute_denied,
        udp_socket_denied,
        unlisted_tcp_port_denied,
    };
    if !profile_write_allowed
        || !credential_read_denied
        || !unrelated_profile_write_denied
        || !outside_read_denied
        || !outside_write_denied
        || !execute_denied
        || !udp_socket_denied
        || !unlisted_tcp_port_denied
    {
        return Err(format!(
            "sandbox self-test failed: {}",
            serde_json::to_string(&evidence).map_err(|error| error.to_string())?
        ));
    }
    println!(
        "{}",
        serde_json::to_string(&evidence).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn sandbox_self_test(_profile: &Path) -> std::result::Result<(), String> {
    Err("isolated IMAP sandbox self-test is unavailable on this platform".into())
}

fn validate_worker_request(request: &WorkerRequest) -> std::result::Result<(), String> {
    if request.resolved_addresses.is_empty() || request.resolved_addresses.len() > 16 {
        return Err("worker received an invalid resolved-address count".into());
    }
    let account = request
        .resolved_addresses
        .first()
        .ok_or("worker received no resolved address")?;
    if request
        .resolved_addresses
        .iter()
        .any(|address| address.port() != account.port())
        || account.port() != request.imap_port
        || !request.limits.tcp_ports.contains(&account.port())
    {
        return Err("worker received an address outside its TCP-port policy".into());
    }
    if request.backend.dkim_dns != DkimDnsResolver::Quad9Tls {
        return Err("worker requires the encrypted TCP DKIM resolver".into());
    }
    Ok(())
}

async fn run_worker_request(mut request: WorkerRequest) -> Result<WorkerResult> {
    let credential = Arc::new(WorkerCredentialProvider {
        reference: request.credential_reference.clone(),
        kind: request.credential.kind,
        secret: Zeroizing::new(std::mem::take(&mut request.credential.secret)),
    });
    let backend = Backend::open_sync_worker(request.backend, request.observed_storage).await?;
    let account = backend.accounts().get(request.account_id).await?;
    let current = account.imap.as_ref().ok_or_else(|| {
        BackendError::InvalidInput("isolated worker account is no longer IMAP".into())
    })?;
    if current.host != request.imap_host || current.port != request.imap_port {
        return Err(BackendError::Conflict(
            "IMAP account endpoint changed while the isolated worker was starting".into(),
        ));
    }
    let engine = ImapAccountEngine::new(backend, credential, request.engine)?
        .with_resolved_addresses(request.resolved_addresses)?;
    match request.operation {
        WorkerOperation::SyncOnce => engine
            .sync_once(request.account_id)
            .await
            .map(WorkerResult::Sync),
        WorkerOperation::FetchMessageContent { message_id } => engine
            .fetch_message_content(message_id)
            .await
            .map(WorkerResult::Content),
        WorkerOperation::WaitForChange => engine
            .wait_for_change(request.account_id, &CancellationToken::new())
            .await
            .map(|()| WorkerResult::Waited),
    }
}

#[cfg(target_os = "linux")]
fn install_worker_sandbox(request: &WorkerRequest) -> std::result::Result<(), String> {
    set_worker_limits(&request.limits)?;
    enter_landlock(&request.backend.profile_dir, &request.limits.tcp_ports)?;
    enter_seccomp()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_worker_sandbox(_request: &WorkerRequest) -> std::result::Result<(), String> {
    Err("isolated IMAP synchronization has no fail-closed sandbox on this platform".into())
}

#[cfg(target_os = "linux")]
fn set_worker_limits(limits: &WorkerLimits) -> std::result::Result<(), String> {
    fn set(
        resource: libc::__rlimit_resource_t,
        current: u64,
        maximum: u64,
    ) -> std::result::Result<(), String> {
        let value = libc::rlimit {
            rlim_cur: current,
            rlim_max: maximum,
        };
        // SAFETY: setrlimit only reads the initialized rlimit structure.
        if unsafe { libc::setrlimit(resource, &value) } != 0 {
            return Err(format!(
                "could not set worker resource limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    set(libc::RLIMIT_AS, limits.memory_bytes, limits.memory_bytes)?;
    set(
        libc::RLIMIT_CPU,
        limits.cpu_seconds,
        limits.cpu_seconds.saturating_add(1),
    )?;
    set(
        libc::RLIMIT_FSIZE,
        limits.file_size_bytes,
        limits.file_size_bytes,
    )?;
    set(libc::RLIMIT_CORE, 0, 0)?;
    set(libc::RLIMIT_NOFILE, 128, 128)?;
    // SAFETY: PR_SET_DUMPABLE takes an integer flag and does not dereference pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "could not disable worker ptrace access: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_landlock(profile: &Path, tcp_ports: &[u16]) -> std::result::Result<(), String> {
    use landlock::{
        Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, Scope, ABI,
    };
    let abi = ABI::V6;
    let data_access = AccessFs::from_all(abi)
        & !AccessFs::Execute
        & !AccessFs::MakeSock
        & !AccessFs::MakeChar
        & !AccessFs::MakeBlock
        & !AccessFs::MakeFifo
        & !AccessFs::MakeSym
        & !AccessFs::IoctlDev;
    let database_access = AccessFs::from_file(abi) & !AccessFs::Execute & !AccessFs::IoctlDev;
    let read_access = AccessFs::from_read(abi) & !AccessFs::Execute;
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::ConnectTcp))
        .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket))
        .and_then(|ruleset| ruleset.scope(Scope::Signal))
        .map_err(|error| format!("could not configure Landlock: {error}"))?;
    let mut created = ruleset
        .create()
        .map_err(|error| format!("could not create Landlock ruleset: {error}"))?
        .add_rule(PathBeneath::new(
            PathFd::new(profile)
                .map_err(|error| format!("could not open worker profile for Landlock: {error}"))?,
            AccessFs::ReadDir,
        ))
        .map_err(|error| format!("could not allow worker profile listing: {error}"))?;
    for path in [profile.join("mail.db"), profile.join("mail.db-wal")] {
        created = created
            .add_rule(PathBeneath::new(
                PathFd::new(&path).map_err(|error| {
                    format!(
                        "could not open worker database path {}: {error}",
                        path.display()
                    )
                })?,
                database_access,
            ))
            .map_err(|error| {
                format!(
                    "could not allow worker database path {}: {error}",
                    path.display()
                )
            })?;
    }
    for path in [profile.join("blobs"), profile.join("downloads")] {
        created = created
            .add_rule(PathBeneath::new(
                PathFd::new(&path).map_err(|error| {
                    format!(
                        "could not open worker data path {}: {error}",
                        path.display()
                    )
                })?,
                data_access,
            ))
            .map_err(|error| {
                format!(
                    "could not allow worker data path {}: {error}",
                    path.display()
                )
            })?;
    }
    for path in [
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/usr/share/zoneinfo",
        "/proc/self",
        "/proc/meminfo",
        "/proc/cpuinfo",
        "/sys/devices/system/cpu",
        "/dev/urandom",
    ] {
        if Path::new(path).exists() {
            created = created
                .add_rule(PathBeneath::new(
                    PathFd::new(path).map_err(|error| {
                        format!("could not open Landlock read path {path}: {error}")
                    })?,
                    read_access,
                ))
                .map_err(|error| format!("could not allow Landlock read path {path}: {error}"))?;
        }
    }
    let mut ports = tcp_ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    for port in ports {
        created = created
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|error| format!("could not allow worker TCP port {port}: {error}"))?;
    }
    let status = created
        .restrict_self()
        .map_err(|error| format!("could not enter Landlock sandbox: {error}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!(
            "Landlock sandbox was not fully enforced: {status:?}"
        ));
    }
    Ok(())
}

/// A deliberately small unsafe OS adapter.  Landlock owns path and TCP-port
/// policy; this filter removes socket families/types Landlock cannot govern
/// and process-introspection or namespace escape syscalls.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enter_seccomp() -> std::result::Result<(), String> {
    // SAFETY: the BPF program is an initialized local array consumed
    // synchronously by prctl. Jump offsets are covered by the sandbox test.
    unsafe {
        const LD: u16 = 0x20;
        const JEQ: u16 = 0x15;
        const RET: u16 = 0x06;
        const AND: u16 = 0x54;
        const ALLOW: u32 = 0x7fff0000;
        const KILL: u32 = 0x80000000;
        const ERRNO: u32 = 0x00050000;
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |k, jt, jf| libc::sock_filter {
            code: JEQ,
            jt,
            jf,
            k,
        };
        let mut code = vec![
            stmt(LD, 4),
            jump(0xc000003e, 1, 0),
            stmt(RET, KILL),
            stmt(LD, 0),
        ];
        for syscall in [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_kcmp,
            libc::SYS_bpf,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_socketpair,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_chmod,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_fchmodat2,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_fchownat,
            libc::SYS_setxattr,
            libc::SYS_lsetxattr,
            libc::SYS_fsetxattr,
            libc::SYS_removexattr,
            libc::SYS_lremovexattr,
            libc::SYS_fremovexattr,
        ] {
            code.push(jump(syscall as u32, 0, 1));
            code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        }
        // socket(domain, type, protocol): only TCP-capable INET stream
        // sockets survive; UDP, raw, packet and Unix sockets are rejected.
        code.push(jump(libc::SYS_socket as u32, 0, 8));
        code.push(stmt(LD, 16));
        code.push(jump(libc::AF_INET as u32, 2, 0));
        code.push(jump(libc::AF_INET6 as u32, 1, 0));
        code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        code.push(stmt(LD, 24));
        code.push(stmt(
            AND,
            !((libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32),
        ));
        code.push(jump(libc::SOCK_STREAM as u32, 1, 0));
        code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        code.push(stmt(RET, ALLOW));
        code.push(stmt(RET, ALLOW));
        let program = libc::sock_fprog {
            len: u16::try_from(code.len()).map_err(|_| "seccomp program is too large")?,
            filter: code.as_mut_ptr(),
        };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
            return Err(format!(
                "could not enter seccomp sandbox: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn enter_seccomp() -> std::result::Result<(), String> {
    Err("isolated IMAP seccomp is not implemented for this architecture".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_and_worker_frames_are_bounded() {
        assert_eq!(
            bounded_error(&"x".repeat(MAX_WORKER_ERROR_CHARS + 10)).len(),
            MAX_WORKER_ERROR_CHARS
        );
        assert!(ImapSyncIsolationConfig::default().memory_limit_bytes >= 256 * 1024 * 1024);
        assert_eq!(
            bounded_error("server\r\nstatus\x1b[31m"),
            "server  status [31m"
        );
    }
}
