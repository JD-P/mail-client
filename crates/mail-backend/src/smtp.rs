use crate::{
    Backend, BackendError, CredentialProvider, ImapCredential, Result, SmtpAccount, SmtpAuthMethod,
    SmtpSecurity, Submission, SubmissionStatus,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::HashSet,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MAX_SMTP_LINE: usize = 8 * 1024;
const MAX_SMTP_RESPONSE_LINES: usize = 100;

#[derive(Clone, Debug)]
pub struct SmtpEngineConfig {
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub polling_interval: Duration,
    pub retry_initial: Duration,
    pub retry_maximum: Duration,
    pub batch_size: usize,
    pub use_webpki_roots: bool,
    pub additional_root_certificates_der: Vec<Vec<u8>>,
}

impl Default for SmtpEngineConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(20),
            command_timeout: Duration::from_secs(60),
            polling_interval: Duration::from_secs(30),
            retry_initial: Duration::from_secs(30),
            retry_maximum: Duration::from_secs(30 * 60),
            batch_size: 20,
            use_webpki_roots: true,
            additional_root_certificates_der: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct SmtpEngine {
    backend: Backend,
    credentials: Arc<dyn CredentialProvider>,
    config: SmtpEngineConfig,
    tls: TlsConnector,
}

impl SmtpEngine {
    pub async fn new(
        backend: Backend,
        credentials: Arc<dyn CredentialProvider>,
        config: SmtpEngineConfig,
    ) -> Result<Self> {
        if config.connect_timeout.is_zero()
            || config.command_timeout.is_zero()
            || config.polling_interval.is_zero()
            || config.retry_initial.is_zero()
            || config.retry_maximum < config.retry_initial
            || config.batch_size == 0
        {
            return Err(BackendError::InvalidInput(
                "SMTP timeouts, retry bounds, and batch size must be positive and ordered".into(),
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
                        "invalid additional SMTP TLS root certificate: {error}"
                    ))
                })?;
        }
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let engine = Self {
            backend,
            credentials,
            config,
            tls,
        };
        engine.backend.outbox().recover_inflight().await?;
        Ok(engine)
    }

    pub async fn send_due(&self, cancellation: &CancellationToken) -> Result<Vec<Submission>> {
        let ids = self.backend.outbox().due(self.config.batch_size).await?;
        let mut completed = Vec::with_capacity(ids.len());
        for id in ids {
            if cancellation.is_cancelled() {
                break;
            }
            // Resolve configuration and credentials before changing durable
            // state to in-flight. Keychain/OAuth failures mean no SMTP attempt
            // happened and must not strand or ambiguously classify the row.
            let due_submission = self.backend.outbox().get(id).await?;
            let account = self
                .backend
                .sending()
                .smtp_account(due_submission.account_id)
                .await?;
            let credential = tokio::select! {
                _ = cancellation.cancelled() => break,
                result = timeout(
                    self.config.command_timeout,
                    self.credentials.resolve(&account.credential_ref),
                ) => result
                    .map_err(|_| BackendError::InvalidInput("SMTP credential resolution timed out".into()))??,
            };
            let (submission, raw, recipients, envelope_from) =
                match self.backend.outbox().begin(id).await {
                    Ok(values) => values,
                    Err(BackendError::Conflict(_)) => continue,
                    Err(error) => return Err(error),
                };
            let data_started = Arc::new(AtomicBool::new(false));
            let outcome = {
                let delivery = self.deliver(
                    &account,
                    &credential,
                    &envelope_from,
                    &recipients,
                    &raw,
                    Arc::clone(&data_started),
                );
                tokio::pin!(delivery);
                tokio::select! {
                    result = &mut delivery => Some(result),
                    _ = cancellation.cancelled() => None,
                }
            };
            let Some(outcome) = outcome else {
                if data_started.load(Ordering::Acquire) {
                    self.backend
                        .outbox()
                        .mark_failed(
                            id,
                            SubmissionStatus::Ambiguous,
                            "delivery was cancelled after SMTP DATA began; server acceptance is unknown".into(),
                            None,
                        )
                        .await?;
                } else {
                    self.backend
                        .outbox()
                        .mark_retry(
                            id,
                            "delivery worker stopped before SMTP DATA; no message was transferred"
                                .into(),
                            0,
                            None,
                        )
                        .await?;
                }
                completed.push(self.backend.outbox().get(id).await?);
                break;
            };
            match outcome {
                Ok(response) => {
                    self.backend.outbox().mark_sent(id, raw, response).await?;
                }
                Err(error) => match error.kind {
                    DeliveryErrorKind::Transient => {
                        let delay = retry_delay(&self.config, submission.attempts);
                        self.backend
                            .outbox()
                            .mark_retry(
                                id,
                                error.message,
                                delay.as_secs().min(i64::MAX as u64) as i64,
                                error.response,
                            )
                            .await?;
                    }
                    DeliveryErrorKind::Permanent => {
                        self.backend
                            .outbox()
                            .mark_failed(
                                id,
                                SubmissionStatus::Failed,
                                error.message,
                                error.response,
                            )
                            .await?;
                    }
                    DeliveryErrorKind::Ambiguous => {
                        self.backend
                            .outbox()
                            .mark_failed(
                                id,
                                SubmissionStatus::Ambiguous,
                                error.message,
                                error.response,
                            )
                            .await?;
                    }
                },
            }
            completed.push(self.backend.outbox().get(id).await?);
        }
        Ok(completed)
    }

    pub async fn run(&self, cancellation: CancellationToken) -> Result<()> {
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            self.send_due(&cancellation).await?;
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = sleep(self.config.polling_interval) => {}
            }
        }
    }

    async fn deliver(
        &self,
        account: &SmtpAccount,
        credential: &ImapCredential,
        envelope_from: &str,
        recipients: &[String],
        raw: &[u8],
        data_started: Arc<AtomicBool>,
    ) -> std::result::Result<String, DeliveryError> {
        let timeout_stage = Arc::clone(&data_started);
        match timeout(
            self.config.command_timeout.saturating_mul(4),
            self.deliver_inner(
                account,
                credential,
                envelope_from,
                recipients,
                raw,
                data_started,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) if timeout_stage.load(Ordering::Acquire) => Err(DeliveryError::ambiguous(
                "SMTP delivery timed out after DATA began",
            )),
            Err(_) => Err(DeliveryError::transient("SMTP delivery timed out")),
        }
    }

    async fn deliver_inner(
        &self,
        account: &SmtpAccount,
        credential: &ImapCredential,
        envelope_from: &str,
        recipients: &[String],
        raw: &[u8],
        data_started: Arc<AtomicBool>,
    ) -> std::result::Result<String, DeliveryError> {
        let address = format!("{}:{}", account.settings.host, account.settings.port);
        let tcp = timeout(self.config.connect_timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| DeliveryError::transient("SMTP connect timed out"))?
            .map_err(|error| DeliveryError::transient(format!("SMTP connect failed: {error}")))?;
        let mut stream: Box<dyn IoStream> = match account.settings.security {
            SmtpSecurity::ImplicitTls => {
                Box::new(self.tls_connect(&account.settings.host, tcp).await?)
            }
            SmtpSecurity::StartTls => Box::new(tcp),
        };
        expect_code(&mut stream, 220, false).await?;
        let mut capabilities = ehlo(&mut stream).await?;
        if account.settings.security == SmtpSecurity::StartTls {
            if !capabilities.has("STARTTLS") {
                return Err(DeliveryError::permanent(
                    "SMTP server does not advertise required STARTTLS",
                ));
            }
            send_command(&mut stream, "STARTTLS").await?;
            expect_code(&mut stream, 220, false).await?;
            let tcp = stream
                .into_tcp()
                .ok_or_else(|| DeliveryError::permanent("invalid SMTP STARTTLS state"))?;
            stream = Box::new(self.tls_connect(&account.settings.host, tcp).await?);
            capabilities = ehlo(&mut stream).await?;
        }
        authenticate(&mut stream, account, credential, &capabilities).await?;
        let needs_utf8 = !raw.is_ascii()
            || !envelope_from.is_ascii()
            || recipients.iter().any(|item| !item.is_ascii());
        if needs_utf8 && !capabilities.has("SMTPUTF8") {
            return Err(DeliveryError::permanent(
                "message requires SMTPUTF8 but the server does not advertise it",
            ));
        }
        if capabilities
            .size_limit
            .is_some_and(|maximum| raw.len() as u64 > maximum)
        {
            return Err(DeliveryError::permanent(
                "message exceeds the SMTP server's advertised SIZE limit",
            ));
        }
        let mut mail = format!("MAIL FROM:<{envelope_from}>");
        if capabilities.has_size {
            mail.push_str(&format!(" SIZE={}", raw.len()));
        }
        if needs_utf8 {
            mail.push_str(" SMTPUTF8");
        }
        send_command(&mut stream, &mail).await?;
        expect_success(&mut stream, false).await?;
        for recipient in recipients {
            send_command(&mut stream, &format!("RCPT TO:<{recipient}>")).await?;
            if let Err(error) = expect_success(&mut stream, false).await {
                let _ = send_command(&mut stream, "RSET").await;
                return Err(error);
            }
        }
        send_command(&mut stream, "DATA").await?;
        expect_code(&mut stream, 354, false).await?;
        data_started.store(true, Ordering::Release);
        write_dot_stuffed(&mut stream, raw).await?;
        let response = read_response(&mut stream, true).await?;
        if response.code / 100 != 2 {
            return Err(DeliveryError::from_response(response, true));
        }
        let _ = send_command(&mut stream, "QUIT").await;
        Ok(response.text)
    }

    async fn tls_connect(
        &self,
        host: &str,
        tcp: TcpStream,
    ) -> std::result::Result<tokio_rustls::client::TlsStream<TcpStream>, DeliveryError> {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| DeliveryError::permanent("invalid SMTP TLS server name"))?;
        timeout(
            self.config.connect_timeout,
            self.tls.connect(server_name, tcp),
        )
        .await
        .map_err(|_| DeliveryError::transient("SMTP TLS handshake timed out"))?
        .map_err(|error| DeliveryError::permanent(format!("SMTP TLS verification failed: {error}")))
    }
}

trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        None
    }
}

impl IoStream for TcpStream {
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        Some(*self)
    }
}

impl IoStream for tokio_rustls::client::TlsStream<TcpStream> {}

#[derive(Default)]
struct SmtpCapabilities {
    names: HashSet<String>,
    auth_mechanisms: HashSet<String>,
    has_size: bool,
    size_limit: Option<u64>,
}

impl SmtpCapabilities {
    fn has(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

async fn ehlo(
    stream: &mut Box<dyn IoStream>,
) -> std::result::Result<SmtpCapabilities, DeliveryError> {
    send_command(stream, "EHLO localhost").await?;
    let response = read_response(stream, false).await?;
    if response.code != 250 {
        return Err(DeliveryError::from_response(response, false));
    }
    let mut capabilities = SmtpCapabilities::default();
    for line in response.lines.iter().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let first = first.to_ascii_uppercase();
        let (name, inline_value) = first
            .split_once('=')
            .map(|(name, value)| (name.to_owned(), Some(value.to_owned())))
            .unwrap_or_else(|| (first, None));
        capabilities.names.insert(name.clone());
        match name.as_str() {
            "AUTH" => {
                if let Some(value) = inline_value {
                    capabilities.auth_mechanisms.insert(value);
                }
                capabilities
                    .auth_mechanisms
                    .extend(fields.map(str::to_ascii_uppercase));
            }
            "SIZE" => {
                capabilities.has_size = true;
                capabilities.size_limit = inline_value
                    .as_deref()
                    .or_else(|| fields.next())
                    .and_then(|value| value.parse().ok());
            }
            _ => {}
        }
    }
    Ok(capabilities)
}

async fn authenticate(
    stream: &mut Box<dyn IoStream>,
    account: &SmtpAccount,
    credential: &ImapCredential,
    capabilities: &SmtpCapabilities,
) -> std::result::Result<(), DeliveryError> {
    if !capabilities.has("AUTH") {
        return Err(DeliveryError::permanent(
            "SMTP server does not advertise authentication",
        ));
    }
    let mechanism = match account.settings.auth {
        SmtpAuthMethod::Password => "PLAIN",
        SmtpAuthMethod::XOAuth2 => "XOAUTH2",
        SmtpAuthMethod::OAuthBearer => "OAUTHBEARER",
    };
    if !capabilities.auth_mechanisms.contains(mechanism) {
        return Err(DeliveryError::permanent(format!(
            "SMTP server does not advertise configured {mechanism} authentication"
        )));
    }
    let (mechanism, cleartext) = match (account.settings.auth, credential) {
        (SmtpAuthMethod::Password, ImapCredential::Password(secret)) => (
            "PLAIN",
            Zeroizing::new(format!(
                "\0{}\0{}",
                account.settings.username,
                secret.expose()
            )),
        ),
        (SmtpAuthMethod::XOAuth2, ImapCredential::OAuth2 { access_token }) => (
            "XOAUTH2",
            Zeroizing::new(format!(
                "user={}\x01auth=Bearer {}\x01\x01",
                account.settings.username,
                access_token.expose()
            )),
        ),
        (SmtpAuthMethod::OAuthBearer, ImapCredential::OAuth2 { access_token }) => (
            "OAUTHBEARER",
            Zeroizing::new(format!(
                "n,a={},\x01auth=Bearer {}\x01\x01",
                account.settings.username,
                access_token.expose()
            )),
        ),
        _ => {
            return Err(DeliveryError::permanent(
                "credential kind does not match configured SMTP authentication",
            ))
        }
    };
    let payload = Zeroizing::new(format!(
        "AUTH {mechanism} {}",
        STANDARD.encode(cleartext.as_bytes())
    ));
    send_command(stream, payload.as_str()).await?;
    expect_success(stream, false).await?;
    Ok(())
}

async fn send_command(
    stream: &mut Box<dyn IoStream>,
    command: &str,
) -> std::result::Result<(), DeliveryError> {
    if command.len() > MAX_SMTP_LINE || command.contains(['\r', '\n']) {
        return Err(DeliveryError::permanent("invalid SMTP command"));
    }
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(|error| DeliveryError::transient(format!("SMTP write failed: {error}")))?;
    stream
        .write_all(b"\r\n")
        .await
        .map_err(|error| DeliveryError::transient(format!("SMTP write failed: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| DeliveryError::transient(format!("SMTP flush failed: {error}")))
}

async fn write_dot_stuffed(
    stream: &mut Box<dyn IoStream>,
    raw: &[u8],
) -> std::result::Result<(), DeliveryError> {
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if line.first() == Some(&b'.') {
            stream.write_all(b".").await.map_err(|error| {
                DeliveryError::ambiguous(format!("SMTP DATA write failed: {error}"))
            })?;
        }
        stream.write_all(line).await.map_err(|error| {
            DeliveryError::ambiguous(format!("SMTP DATA write failed: {error}"))
        })?;
    }
    if !raw.ends_with(b"\r\n") {
        stream.write_all(b"\r\n").await.map_err(|error| {
            DeliveryError::ambiguous(format!("SMTP DATA write failed: {error}"))
        })?;
    }
    stream
        .write_all(b".\r\n")
        .await
        .map_err(|error| DeliveryError::ambiguous(format!("SMTP DATA write failed: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| DeliveryError::ambiguous(format!("SMTP DATA flush failed: {error}")))
}

async fn expect_code(
    stream: &mut Box<dyn IoStream>,
    expected: u16,
    after_data: bool,
) -> std::result::Result<SmtpResponse, DeliveryError> {
    let response = read_response(stream, after_data).await?;
    if response.code == expected {
        Ok(response)
    } else {
        Err(DeliveryError::from_response(response, after_data))
    }
}

async fn expect_success(
    stream: &mut Box<dyn IoStream>,
    after_data: bool,
) -> std::result::Result<SmtpResponse, DeliveryError> {
    let response = read_response(stream, after_data).await?;
    if response.code / 100 == 2 {
        Ok(response)
    } else {
        Err(DeliveryError::from_response(response, after_data))
    }
}

async fn read_response(
    stream: &mut Box<dyn IoStream>,
    after_data: bool,
) -> std::result::Result<SmtpResponse, DeliveryError> {
    let mut lines = Vec::new();
    let mut code = None;
    for _ in 0..MAX_SMTP_RESPONSE_LINES {
        let line = read_line(stream, after_data).await?;
        if line.len() < 4 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(DeliveryError::permanent("malformed SMTP response"));
        }
        let line_code = line[..3]
            .parse::<u16>()
            .map_err(|_| DeliveryError::permanent("malformed SMTP response code"))?;
        if code.is_some_and(|value| value != line_code) {
            return Err(DeliveryError::permanent(
                "SMTP multiline response changed status code",
            ));
        }
        code = Some(line_code);
        let continued = line.as_bytes()[3] == b'-';
        if line.as_bytes()[3] != b'-' && line.as_bytes()[3] != b' ' {
            return Err(DeliveryError::permanent(
                "malformed SMTP response separator",
            ));
        }
        lines.push(line[4..].to_owned());
        if !continued {
            let text = lines.join("\n");
            return Ok(SmtpResponse {
                code: line_code,
                lines,
                text,
            });
        }
    }
    Err(DeliveryError::permanent(
        "SMTP response exceeds line-count limit",
    ))
}

async fn read_line(
    stream: &mut Box<dyn IoStream>,
    after_data: bool,
) -> std::result::Result<String, DeliveryError> {
    let mut bytes = Vec::new();
    while bytes.len() <= MAX_SMTP_LINE {
        let mut byte = [0u8; 1];
        let count = stream.read(&mut byte).await.map_err(|error| {
            if after_data {
                DeliveryError::ambiguous(format!("SMTP response read failed: {error}"))
            } else {
                DeliveryError::transient(format!("SMTP response read failed: {error}"))
            }
        })?;
        if count == 0 {
            return Err(if after_data {
                DeliveryError::ambiguous("SMTP connection closed after DATA")
            } else {
                DeliveryError::transient("SMTP connection closed")
            });
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes)
                .map_err(|_| DeliveryError::permanent("SMTP response is not UTF-8/ASCII"));
        }
    }
    Err(DeliveryError::permanent(
        "SMTP response line exceeds size limit",
    ))
}

fn retry_delay(config: &SmtpEngineConfig, attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(20);
    let multiplier = 1u32 << exponent;
    config
        .retry_initial
        .saturating_mul(multiplier)
        .min(config.retry_maximum)
}

struct SmtpResponse {
    code: u16,
    lines: Vec<String>,
    text: String,
}

#[derive(Clone, Copy)]
enum DeliveryErrorKind {
    Transient,
    Permanent,
    Ambiguous,
}

struct DeliveryError {
    kind: DeliveryErrorKind,
    message: String,
    response: Option<String>,
}

impl DeliveryError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            kind: DeliveryErrorKind::Transient,
            message: message.into(),
            response: None,
        }
    }

    fn permanent(message: impl Into<String>) -> Self {
        Self {
            kind: DeliveryErrorKind::Permanent,
            message: message.into(),
            response: None,
        }
    }

    fn ambiguous(message: impl Into<String>) -> Self {
        Self {
            kind: DeliveryErrorKind::Ambiguous,
            message: message.into(),
            response: None,
        }
    }

    fn from_response(response: SmtpResponse, after_data: bool) -> Self {
        let kind = match response.code / 100 {
            4 => DeliveryErrorKind::Transient,
            5 => DeliveryErrorKind::Permanent,
            _ if after_data => DeliveryErrorKind::Ambiguous,
            _ => DeliveryErrorKind::Permanent,
        };
        Self {
            kind,
            message: format!("SMTP server returned {}: {}", response.code, response.text),
            response: Some(format!("{} {}", response.code, response.text)),
        }
    }
}

impl fmt::Debug for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryError")
            .field("message", &self.message)
            .field("response", &self.response)
            .finish()
    }
}
