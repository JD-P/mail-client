use async_imap::Client;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapSecurity, ImapSettings, NewAccount,
    NewFolder, SearchRequest,
};
use std::process::{Command, Output};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const DOVECOT_IMAGE: &str =
    "dovecot/dovecot@sha256:a2e908c9a93698f3923104ea5be7f4beacde9586242aff5d8059599d0042c62a";

struct DovecotContainer {
    id: String,
    port: u16,
}

impl DovecotContainer {
    async fn start() -> Self {
        if !docker(&["image", "inspect", DOVECOT_IMAGE])
            .status
            .success()
        {
            let pull = docker(&["pull", DOVECOT_IMAGE]);
            assert_success("pull Dovecot image", &pull);
        }

        let run = docker(&[
            "run",
            "--detach",
            "--rm",
            "--publish",
            "127.0.0.1::31143",
            "--env",
            "USER_PASSWORD=password",
            "--volume",
            &format!(
                "{}:/etc/dovecot/conf.d/99-integration-test.conf:ro",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/dovecot/99-integration-test.conf"
                )
            ),
            DOVECOT_IMAGE,
        ]);
        assert_success("start Dovecot", &run);
        let id = String::from_utf8(run.stdout).unwrap().trim().to_owned();
        assert!(!id.is_empty(), "docker run returned no container ID");
        let mut container = Self { id, port: 0 };

        let port_output = docker(&["port", &container.id, "31143/tcp"]);
        assert_success("inspect Dovecot port", &port_output);
        let binding = String::from_utf8(port_output.stdout).unwrap();
        container.port = binding
            .trim()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("unexpected docker port output: {binding:?}"));
        container.wait_until_ready().await;
        container
    }

    async fn wait_until_ready(&self) {
        let address = ("127.0.0.1", self.port);
        for _ in 0..100 {
            if let Ok(Ok(mut stream)) =
                timeout(Duration::from_millis(250), TcpStream::connect(address)).await
            {
                let mut greeting = [0_u8; 256];
                if let Ok(Ok(count)) =
                    timeout(Duration::from_millis(250), stream.read(&mut greeting)).await
                {
                    if count > 0 && greeting[..count].starts_with(b"* OK") {
                        return;
                    }
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        let logs = docker(&["logs", &self.id]);
        panic!(
            "Dovecot did not listen within 10 seconds\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
    }
}

impl Drop for DovecotContainer {
    fn drop(&mut self) {
        let _ = docker(&["rm", "--force", &self.id]);
    }
}

fn docker(arguments: &[&str]) -> Output {
    Command::new("docker")
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("could not run Docker: {error}"))
}

fn assert_success(action: &str, output: &Output) {
    assert!(
        output.status.success(),
        "could not {action}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn plain_message(id: &str, subject: &str, body: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: Sender <sender@example.test>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n",
            "Message-ID: <{}@example.test>\r\n",
            "Subject: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{}\r\n"
        ),
        id, subject, body
    )
    .into_bytes()
}

fn multipart_message() -> Vec<u8> {
    concat!(
        "From: Reports <reports@example.test>\r\n",
        "To: Reader <reader@example.test>\r\n",
        "Date: Mon, 16 Nov 2026 10:01:00 +0000\r\n",
        "Message-ID: <dovecot-multipart@example.test>\r\n",
        "Subject: Dovecot multipart report\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=fixture-boundary\r\n",
        "\r\n",
        "--fixture-boundary\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>The amber narwhal report is attached.</p>\r\n",
        "--fixture-boundary\r\n",
        "Content-Type: text/plain; name=report.txt\r\n",
        "Content-Disposition: attachment; filename=report.txt\r\n",
        "\r\n",
        "fixture attachment\r\n",
        "--fixture-boundary--\r\n"
    )
    .as_bytes()
    .to_vec()
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn pulls_real_mail_from_dovecot_incrementally() {
    let dovecot = DovecotContainer::start().await;
    let stream = TcpStream::connect(("127.0.0.1", dovecot.port))
        .await
        .unwrap();
    let mut client = Client::new(stream);
    assert!(
        client.read_response().await.unwrap().is_some(),
        "Dovecot closed before its greeting"
    );
    let mut session = client
        .login("reader@example.test", "password")
        .await
        .unwrap_or_else(|(error, _)| panic!("Dovecot login failed: {error}"));

    // Cross the backend's 1 MiB IMAP body-chunk boundary and compare the exact
    // RFC bytes after multiple partial FETCH responses have been reassembled.
    let first_body = format!(
        "cobalt telescope\r\n{}",
        "0123456789abcdef\r\n".repeat(65_000)
    );
    let first_raw = plain_message("dovecot-one", "Dovecot alpha", &first_body);
    let second_raw = multipart_message();
    let third_raw = plain_message("dovecot-three", "Dovecot seen", "violet sextant");
    session
        .append("INBOX", None, None, &first_raw)
        .await
        .unwrap();
    session
        .append("INBOX", None, None, &second_raw)
        .await
        .unwrap();
    session
        .append("INBOX", Some("(\\Seen)"), None, &third_raw)
        .await
        .unwrap();

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:dovecot".into()),
            imap: Some(ImapSettings {
                host: "127.0.0.1".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let inbox = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();

    // The production API takes an already authenticated, TLS-protected session.
    // This fixture uses plaintext only across the Docker loopback port.
    let first_sync = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert_eq!(first_sync.message_ids.len(), 3);
    assert_eq!(
        backend
            .messages()
            .raw(first_sync.message_ids[0])
            .await
            .unwrap(),
        first_raw
    );
    assert!(
        !backend
            .messages()
            .get(first_sync.message_ids[0])
            .await
            .unwrap()
            .summary
            .is_read,
        "BODY.PEEK sync must not add the Seen flag"
    );
    assert!(
        backend
            .messages()
            .get(first_sync.message_ids[2])
            .await
            .unwrap()
            .summary
            .is_read
    );
    assert_eq!(search_count(&backend, "amber narwhal").await, 1);
    assert_eq!(search_count(&backend, "has:attachment").await, 1);

    let no_changes = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert!(no_changes.message_ids.is_empty());

    let fourth_raw = plain_message("dovecot-four", "Dovecot delta", "silver astrolabe");
    session
        .append("INBOX", None, None, &fourth_raw)
        .await
        .unwrap();
    let incremental = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert_eq!(incremental.message_ids.len(), 1);
    assert_eq!(search_count(&backend, "silver astrolabe").await, 1);
    assert_eq!(search_count(&backend, "in:Inbox").await, 4);

    session.logout().await.unwrap();
}

async fn search_count(backend: &Backend, query: &str) -> usize {
    backend
        .search()
        .search(SearchRequest {
            query: query.into(),
            page_size: 100,
            cursor: None,
        })
        .await
        .unwrap()
        .items
        .len()
}
