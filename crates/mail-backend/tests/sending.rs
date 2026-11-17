use futures_util::future::BoxFuture;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, CredentialProvider, DraftAttachmentDisposition,
    DraftContent, ImapCredential, NewAccount, NewDraftAttachment, SecretValue, SendingLimits,
    SmtpAuthMethod, SmtpEngine, SmtpEngineConfig, SmtpSecurity, SmtpSettings, SubmissionStatus,
    ThreadId, ThreadSenderTrust,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

struct FixtureCredentials;

impl CredentialProvider for FixtureCredentials {
    fn resolve<'a>(
        &'a self,
        reference: &'a str,
    ) -> BoxFuture<'a, lizard_mail_backend::Result<ImapCredential>> {
        Box::pin(async move {
            assert_eq!(reference, "test-only:smtp");
            Ok(ImapCredential::Password(SecretValue::new("correct horse")))
        })
    }
}

#[derive(Clone, Copy)]
enum ServerOutcome {
    Accept,
    RejectMail,
    TemporaryMailFailure,
    DisconnectAfterData,
}

struct ServerTranscript {
    raw: Vec<u8>,
    recipients: Vec<String>,
}

async fn smtp_server(
    outcome: ServerOutcome,
) -> (u16, Vec<u8>, tokio::task::JoinHandle<ServerTranscript>) {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let certificate = server_params.signed_by(&key, &root).unwrap();
    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let root_der = root.der().to_vec();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"220 fixture ESMTP\r\n").await.unwrap();
        assert!(read_line(&mut socket).await.starts_with("EHLO "));
        socket
            .write_all(b"250-fixture\r\n250-STARTTLS\r\n250 SIZE 67108864\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut socket).await, "STARTTLS");
        socket.write_all(b"220 begin TLS\r\n").await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        assert!(read_line(&mut socket).await.starts_with("EHLO "));
        socket
            .write_all(
                b"250-fixture\r\n250-AUTH PLAIN XOAUTH2 OAUTHBEARER\r\n250-SMTPUTF8\r\n250 SIZE 67108864\r\n",
            )
            .await
            .unwrap();
        let auth = read_line(&mut socket).await;
        assert!(auth.starts_with("AUTH PLAIN "));
        socket.write_all(b"235 authenticated\r\n").await.unwrap();
        let mail = read_line(&mut socket).await;
        assert!(mail.starts_with("MAIL FROM:<sender@example.test> SIZE="));
        if matches!(outcome, ServerOutcome::RejectMail) {
            socket.write_all(b"550 sender rejected\r\n").await.unwrap();
            return ServerTranscript {
                raw: Vec::new(),
                recipients: Vec::new(),
            };
        }
        if matches!(outcome, ServerOutcome::TemporaryMailFailure) {
            socket.write_all(b"451 try later\r\n").await.unwrap();
            return ServerTranscript {
                raw: Vec::new(),
                recipients: Vec::new(),
            };
        }
        socket.write_all(b"250 sender ok\r\n").await.unwrap();
        let mut recipients = Vec::new();
        loop {
            let line = read_line(&mut socket).await;
            if line == "DATA" {
                break;
            }
            assert!(line.starts_with("RCPT TO:<") && line.ends_with('>'));
            recipients.push(
                line.trim_start_matches("RCPT TO:<")
                    .trim_end_matches('>')
                    .to_owned(),
            );
            socket.write_all(b"250 recipient ok\r\n").await.unwrap();
        }
        socket.write_all(b"354 send message\r\n").await.unwrap();
        let mut raw = Vec::new();
        loop {
            let line = read_line_bytes(&mut socket).await;
            if line == b".\r\n" {
                break;
            }
            if line.starts_with(b"..") {
                raw.extend_from_slice(&line[1..]);
            } else {
                raw.extend_from_slice(&line);
            }
        }
        if matches!(outcome, ServerOutcome::DisconnectAfterData) {
            return ServerTranscript { raw, recipients };
        }
        socket
            .write_all(b"250 queued as fixture-42\r\n")
            .await
            .unwrap();
        if read_line(&mut socket).await == "QUIT" {
            let _ = socket.write_all(b"221 goodbye\r\n").await;
        }
        ServerTranscript { raw, recipients }
    });
    (port, root_der, task)
}

async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let bytes = read_line_bytes(stream).await;
    String::from_utf8(bytes[..bytes.len() - 2].to_vec()).unwrap()
}

async fn read_line_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        line.push(byte);
        if line.ends_with(b"\r\n") {
            return line;
        }
    }
}

async fn configured_backend(
    outcome: ServerOutcome,
) -> (
    tempfile::TempDir,
    Backend,
    lizard_mail_backend::AccountId,
    SmtpEngine,
    tokio::task::JoinHandle<ServerTranscript>,
) {
    let (port, root, server) = smtp_server(outcome).await;
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Sending fixture".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    backend
        .sending()
        .configure_smtp(
            account.id,
            SmtpSettings {
                host: "localhost".into(),
                port,
                username: "sender@example.test".into(),
                security: SmtpSecurity::StartTls,
                auth: SmtpAuthMethod::Password,
            },
            "test-only:smtp".into(),
        )
        .await
        .unwrap();
    let engine = SmtpEngine::new(
        backend.clone(),
        Arc::new(FixtureCredentials),
        SmtpEngineConfig {
            use_webpki_roots: false,
            additional_root_certificates_der: vec![root],
            connect_timeout: Duration::from_secs(3),
            command_timeout: Duration::from_secs(3),
            retry_initial: Duration::from_secs(1),
            retry_maximum: Duration::from_secs(2),
            ..SmtpEngineConfig::default()
        },
    )
    .await
    .unwrap();
    (profile, backend, account.id, engine, server)
}

async fn queued_submission(
    backend: &Backend,
    account_id: lizard_mail_backend::AccountId,
) -> lizard_mail_backend::Submission {
    let draft = backend
        .drafts()
        .create(DraftContent {
            account_id,
            thread_id: ThreadId::new(),
            parent_message_id: None,
            to_addresses: vec!["reader@example.test".into()],
            cc_addresses: vec!["copy@example.test".into()],
            bcc_addresses: vec!["hidden@example.test".into()],
            subject: "Protected headers 🦎".into(),
            body_text: "plain body".into(),
            body_html: Some("<p>html body</p>".into()),
            in_reply_to: None,
            references: Vec::new(),
        })
        .await
        .unwrap();
    assert!(backend
        .drafts()
        .save(draft.id, draft.revision + 1, draft.content.clone())
        .await
        .is_err());
    let mut attachment: &[u8] = b"exact attachment bytes";
    let draft = backend
        .drafts()
        .add_attachment(
            draft.id,
            draft.revision,
            NewDraftAttachment {
                name: "evidence.txt".into(),
                media_type: "text/plain".into(),
                disposition: DraftAttachmentDisposition::Attachment,
                content_id: None,
            },
            &mut attachment,
            SendingLimits::default(),
        )
        .await
        .unwrap();
    backend
        .outbox()
        .enqueue(draft.id, draft.revision, SendingLimits::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn drafts_autosave_build_protected_mime_and_submit_over_starttls() {
    let (_profile, backend, account_id, engine, server) =
        configured_backend(ServerOutcome::Accept).await;
    let mut events = backend.events().subscribe();
    let queued = queued_submission(&backend, account_id).await;
    assert_eq!(queued.status, SubmissionStatus::Pending);
    assert_eq!(events.recv().await.unwrap().kind, "draft_created");
    assert_eq!(events.recv().await.unwrap().kind, "draft_attachment_added");
    assert_eq!(events.recv().await.unwrap().kind, "submission_enqueued");

    let completed = engine.send_due(&CancellationToken::new()).await.unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].status, SubmissionStatus::Sent);
    assert_eq!(events.recv().await.unwrap().kind, "submission_in_flight");
    assert_eq!(events.recv().await.unwrap().kind, "message_ingested");
    assert_eq!(events.recv().await.unwrap().kind, "submission_sent");
    let sent_id = completed[0].sent_message_id.unwrap();
    let transcript = server.await.unwrap();
    assert_eq!(
        transcript.recipients,
        [
            "reader@example.test",
            "copy@example.test",
            "hidden@example.test"
        ]
    );
    assert_eq!(
        backend.messages().raw(sent_id).await.unwrap(),
        transcript.raw
    );
    let raw_text = String::from_utf8_lossy(&transcript.raw);
    assert!(raw_text.contains("From: sender@example.test\r\n"));
    assert!(raw_text.contains("To: reader@example.test\r\n"));
    assert!(raw_text.contains("Cc: copy@example.test\r\n"));
    assert!(!raw_text.contains("Bcc:"));
    assert!(!raw_text.contains("DKIM-Signature:"));
    assert!(raw_text.contains("Content-Type: multipart/mixed"));
    assert!(raw_text.contains("Content-Type: multipart/alternative"));
    assert!(raw_text.contains("filename*=UTF-8''evidence.txt"));
    let sent = backend.messages().get(sent_id).await.unwrap();
    assert_eq!(sent.threading.sender_trust, ThreadSenderTrust::Known);
    let attachment = sent
        .attachments
        .iter()
        .find(|item| item.name.as_deref() == Some("evidence.txt"))
        .unwrap();
    let mut decoded = Vec::new();
    backend
        .mime()
        .stream_attachment(sent_id, &attachment.id, &mut decoded, 1_024)
        .await
        .unwrap();
    assert_eq!(decoded, b"exact attachment bytes");
}

#[tokio::test]
async fn definite_smtp_rejection_is_a_durable_failure() {
    let (_profile, backend, account_id, engine, server) =
        configured_backend(ServerOutcome::RejectMail).await;
    let queued = queued_submission(&backend, account_id).await;
    let completed = engine.send_due(&CancellationToken::new()).await.unwrap();
    assert_eq!(completed[0].status, SubmissionStatus::Failed);
    assert_eq!(backend.outbox().get(queued.id).await.unwrap().attempts, 1);
    assert!(completed[0]
        .smtp_response
        .as_deref()
        .unwrap()
        .contains("550"));
    server.await.unwrap();
}

#[tokio::test]
async fn temporary_smtp_failure_is_scheduled_with_bounded_backoff() {
    let (_profile, backend, account_id, engine, server) =
        configured_backend(ServerOutcome::TemporaryMailFailure).await;
    let queued = queued_submission(&backend, account_id).await;
    let completed = engine.send_due(&CancellationToken::new()).await.unwrap();
    assert_eq!(completed[0].status, SubmissionStatus::RetryScheduled);
    assert_eq!(backend.outbox().get(queued.id).await.unwrap().attempts, 1);
    assert!(completed[0].next_attempt_at.is_some());
    assert!(completed[0]
        .smtp_response
        .as_deref()
        .unwrap()
        .contains("451"));
    server.await.unwrap();
}

#[tokio::test]
async fn lost_response_after_data_is_ambiguous_and_never_retried_automatically() {
    let (_profile, backend, account_id, engine, server) =
        configured_backend(ServerOutcome::DisconnectAfterData).await;
    let queued = queued_submission(&backend, account_id).await;
    let completed = engine.send_due(&CancellationToken::new()).await.unwrap();
    assert_eq!(completed[0].status, SubmissionStatus::Ambiguous);
    assert!(backend.outbox().retry(queued.id).await.is_err());
    assert!(engine
        .send_due(&CancellationToken::new())
        .await
        .unwrap()
        .is_empty());
    assert!(!server.await.unwrap().raw.is_empty());
}

#[tokio::test]
async fn queued_submission_can_be_cancelled_before_network_delivery() {
    let (_profile, backend, account_id, _engine, server) =
        configured_backend(ServerOutcome::Accept).await;
    let queued = queued_submission(&backend, account_id).await;
    let cancelled = backend.outbox().cancel(queued.id).await.unwrap();
    assert_eq!(cancelled.status, SubmissionStatus::Cancelled);
    server.abort();
}
