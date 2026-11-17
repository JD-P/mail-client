use async_imap::{Client, Session};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::process::{Command, Output};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const DOVECOT_IMAGE: &str =
    "dovecot/dovecot@sha256:a2e908c9a93698f3923104ea5be7f4beacde9586242aff5d8059599d0042c62a";

pub struct DovecotContainer {
    id: String,
    pub port: u16,
    pub imaps_port: u16,
    #[allow(dead_code)]
    pub certificate_der: Vec<u8>,
    _certificates: tempfile::TempDir,
}

impl DovecotContainer {
    pub async fn start() -> Self {
        let certificates = tempfile::tempdir().expect("create Dovecot certificate directory");
        let mut root_params = CertificateParams::new(Vec::<String>::new())
            .expect("empty root subject alternative names are valid");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = CertifiedIssuer::self_signed(
            root_params,
            KeyPair::generate().expect("generate test root key"),
        )
        .expect("generate test root certificate");
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("localhost is a valid subject alternative name");
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("generate Dovecot test server key");
        let server_certificate = server_params
            .signed_by(&server_key, &root)
            .expect("sign Dovecot test server certificate");
        fs::write(
            certificates.path().join("cert.pem"),
            server_certificate.pem(),
        )
        .expect("write Dovecot test certificate");
        fs::write(
            certificates.path().join("key.pem"),
            server_key.serialize_pem(),
        )
        .expect("write Dovecot test key");
        let certificate_der = root.der().to_vec();
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
            "--publish",
            "127.0.0.1::31993",
            "--env",
            "USER_PASSWORD=password",
            "--volume",
            &format!(
                "{}:/etc/dovecot/conf.d/zz-integration-test.conf:ro",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/dovecot/99-integration-test.conf"
                )
            ),
            "--volume",
            &format!("{}:/lizard-test-certs:ro", certificates.path().display()),
            DOVECOT_IMAGE,
        ]);
        assert_success("start Dovecot", &run);
        let id = String::from_utf8(run.stdout).unwrap().trim().to_owned();
        assert!(!id.is_empty(), "docker run returned no container ID");
        let mut container = Self {
            id,
            port: 0,
            imaps_port: 0,
            certificate_der,
            _certificates: certificates,
        };

        let port_output = docker(&["port", &container.id, "31143/tcp"]);
        assert_success("inspect Dovecot port", &port_output);
        let binding = String::from_utf8(port_output.stdout).unwrap();
        container.port = binding
            .trim()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("unexpected docker port output: {binding:?}"));
        let imaps_port_output = docker(&["port", &container.id, "31993/tcp"]);
        assert_success("inspect Dovecot IMAPS port", &imaps_port_output);
        let imaps_binding = String::from_utf8(imaps_port_output.stdout).unwrap();
        container.imaps_port = imaps_binding
            .trim()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("unexpected Docker IMAPS port output: {imaps_binding:?}"));
        container.wait_until_ready().await;
        container
    }

    pub async fn login(&self) -> Session<TcpStream> {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let mut client = Client::new(stream);
        assert!(
            client.read_response().await.unwrap().is_some(),
            "Dovecot closed before its greeting"
        );
        client
            .login("reader@example.test", "password")
            .await
            .unwrap_or_else(|(error, _)| panic!("Dovecot login failed: {error}"))
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
