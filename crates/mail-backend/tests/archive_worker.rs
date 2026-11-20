#![cfg(target_os = "linux")]

use base64::{engine::general_purpose::STANDARD, Engine};
use lizard_mail_backend::{
    ArchiveIsolationConfig, ArchiveLimits, Backend, BackendConfig, IngestMessage, MessageId,
};
use std::io::{Cursor, Write};
use std::os::unix::fs::PermissionsExt;
#[cfg(target_arch = "x86_64")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lizard-mail-archive-worker"))
}

fn zip_fixture() -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("note.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"bounded archive payload").unwrap();
    writer.finish().unwrap().into_inner()
}

fn message(zip: &[u8]) -> Vec<u8> {
    format!(
        concat!(
            "From: Archive <archive@example.test>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Message-ID: <archive-worker@example.test>\r\n",
            "Subject: Archive worker\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: application/zip; name=fixture.zip\r\n",
            "Content-Disposition: attachment; filename=fixture.zip\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "{}\r\n"
        ),
        STANDARD.encode(zip)
    )
    .into_bytes()
}

async fn fixture() -> (tempfile::TempDir, Backend, MessageId, String) {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(&zip_fixture())))
        .await
        .unwrap();
    let attachment = backend.messages().get(id).await.unwrap().attachments[0]
        .id
        .clone();
    (profile, backend, id, attachment)
}

fn isolation(path: impl Into<PathBuf>) -> ArchiveIsolationConfig {
    ArchiveIsolationConfig {
        worker_path: path.into(),
        wall_timeout: Duration::from_secs(5),
    }
}

#[test]
fn archive_sandbox_is_enforced_or_fails_closed() {
    let output = Command::new(worker_path())
        .arg("--sandbox-self-test")
        .output()
        .expect("archive worker must start");
    if output.status.success() {
        let evidence: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for property in [
            "filesystem_denied",
            "network_denied",
            "execution_denied",
            "pipe_creation_denied",
        ] {
            assert_eq!(evidence[property], true, "failed property {property}");
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Landlock") || stderr.contains("not implemented"),
            "unexpected sandbox failure: {stderr}"
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn archive_seccomp_denies_authority_and_kills_x32_syscalls() {
    let output = Command::new(worker_path())
        .arg("--seccomp-self-test")
        .output()
        .expect("archive seccomp self-test must start");
    assert!(
        output.status.success(),
        "seccomp self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = Command::new(worker_path())
        .arg("--seccomp-x32-self-test")
        .status()
        .expect("archive x32 self-test must start");
    assert_eq!(status.signal(), Some(libc::SIGSYS));
}

#[tokio::test]
async fn worker_failure_never_falls_back_to_in_process_zip_parsing() {
    let (_profile, backend, id, attachment) = fixture().await;
    let error = backend
        .mime()
        .inspect_archive_with_isolation(
            id,
            &attachment,
            ArchiveLimits::default(),
            isolation("/bin/false"),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("archive worker boundary"));
}

#[tokio::test]
async fn parent_rejects_oversized_worker_response_before_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("fake-archive-worker");
    std::fs::write(
        &script,
        concat!(
            "#!/usr/bin/env python3\n",
            "import json, struct, sys\n",
            "length = struct.unpack('>I', sys.stdin.buffer.read(4))[0]\n",
            "header = json.loads(sys.stdin.buffer.read(length))\n",
            "sys.stdin.buffer.read(header['archive_bytes'])\n",
            "sys.stdout.buffer.write(struct.pack('>I', 0xffffffff))\n",
            "sys.stdout.buffer.flush()\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_profile, backend, id, attachment) = fixture().await;
    let error = backend
        .mime()
        .inspect_archive_with_isolation(
            id,
            &attachment,
            ArchiveLimits::default(),
            isolation(&script),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("response header exceeds its protocol limit"),
        "unexpected boundary error: {error}"
    );
}

#[test]
fn installed_worker_path_is_absolute() {
    assert!(Path::new(&worker_path()).is_absolute());
}
