#![cfg(target_os = "linux")]

use lizard_mail_tui::{
    HtmlRenderIsolationConfig, IsolatedHtmlRenderer, IsolatedRenderError, Limits,
};
#[cfg(target_arch = "x86_64")]
use std::os::unix::process::ExitStatusExt;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lizard-mail-tui-render-worker"))
}

fn assert_denial_evidence(stdout: &[u8]) {
    let evidence: serde_json::Value =
        serde_json::from_slice(stdout).expect("self-test output must be JSON");
    assert_eq!(evidence["filesystem_denied"], true);
    assert_eq!(evidence["network_denied"], true);
    assert_eq!(evidence["execution_denied"], true);
    assert_eq!(evidence["sysv_ipc_denied"], true);
    assert_eq!(evidence["pidfd_access_denied"], true);
}

struct FakeWorker {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl FakeWorker {
    fn python(body: &str) -> Self {
        let directory = tempfile::tempdir().expect("fake-worker directory");
        let path = directory.path().join("fake-render-worker");
        let script = format!("#!/usr/bin/python3\nimport struct, sys, time\n{body}\n");
        std::fs::write(&path, script).expect("write fake worker");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make fake worker executable");
        Self {
            _directory: directory,
            path,
        }
    }

    fn response(payload: &[u8], trailing: &[u8]) -> Self {
        let payload = hex(payload);
        let trailing = hex(trailing);
        Self::python(&format!(
            "header = sys.stdin.buffer.read(4)\nrequest_len = struct.unpack('>I', header)[0]\nsys.stdin.buffer.read(request_len)\npayload = bytes.fromhex('{payload}')\nsys.stdout.buffer.write(struct.pack('>I', len(payload)) + payload + bytes.fromhex('{trailing}'))\nsys.stdout.buffer.flush()"
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn renderer_for(path: &Path, wall_timeout: Duration) -> IsolatedHtmlRenderer {
    IsolatedHtmlRenderer::new(
        Limits::default(),
        HtmlRenderIsolationConfig {
            worker_path: path.to_owned(),
            wall_timeout,
        },
    )
}

fn empty_page_response() -> serde_json::Value {
    serde_json::json!({
        "protocol": 1,
        "result": {
            "Ok": {
                "lines": [],
                "links": [],
                "images": [],
                "warnings": [],
                "truncated": false
            }
        }
    })
}

fn line(text: &str) -> serde_json::Value {
    serde_json::json!({
        "alignment": null,
        "spans": [{
            "text": text,
            "style": {
                "foreground": null,
                "bold": false,
                "dim": false,
                "italic": false,
                "underlined": false,
                "crossed_out": false
            }
        }]
    })
}

async fn fake_response_error(response: &serde_json::Value) -> IsolatedRenderError {
    let payload = serde_json::to_vec(response).unwrap();
    let worker = FakeWorker::response(&payload, &[]);
    renderer_for(&worker.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .expect_err("malicious worker response must be rejected")
}

#[test]
fn renderer_sandbox_is_enforced_or_fails_closed() {
    let output = Command::new(worker_path())
        .arg("--sandbox-self-test")
        .output()
        .expect("renderer worker must start");
    if output.status.success() {
        assert_denial_evidence(&output.stdout);
        return;
    }

    // Some containers disable Landlock. That is an acceptable deployment
    // state only because the worker refuses to parse or render anything.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Landlock sandbox was not fully enforced")
            && (stderr.contains("NotImplemented")
                || stderr.contains("NotEnforced")
                || stderr.contains("NotEnabled")
                || stderr.contains("PartiallyEnforced")),
        "unexpected sandbox failure: {stderr}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn seccomp_denies_authority_without_relying_on_landlock_availability() {
    let output = Command::new(worker_path())
        .arg("--seccomp-self-test")
        .output()
        .expect("renderer worker must start");
    assert!(
        output.status.success(),
        "seccomp self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_denial_evidence(&output.stdout);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn seccomp_kills_x32_syscalls_before_the_native_denylist() {
    let status = Command::new(worker_path())
        .arg("--seccomp-x32-self-test")
        .status()
        .expect("renderer worker must start");
    assert_eq!(status.signal(), Some(libc::SIGSYS));
}

#[tokio::test]
async fn worker_failure_is_an_error_not_an_in_process_fallback() {
    let renderer = IsolatedHtmlRenderer::new(
        Limits::default(),
        HtmlRenderIsolationConfig {
            worker_path: PathBuf::from("/bin/false"),
            wall_timeout: Duration::from_secs(1),
        },
    );
    let error = renderer
        .render(b"<h1>untrusted</h1>", 80)
        .await
        .expect_err("a failed worker must not trigger in-process HTML parsing");
    assert!(error.to_string().contains("renderer boundary failed"));
}

#[tokio::test]
async fn parent_accepts_a_valid_bounded_semantic_response() {
    let mut response = empty_page_response();
    response["result"]["Ok"]["lines"] = serde_json::json!([line("safe text")]);
    response["result"]["Ok"]["links"] = serde_json::json!([
        {
            "number": 1,
            "destination": "https://example.test/",
            "kind": "web",
            "blocked_scheme": null
        },
        {
            "number": 2,
            "destination": null,
            "kind": "blocked",
            "blocked_scheme": "javascript"
        }
    ]);
    response["result"]["Ok"]["images"] = serde_json::json!([{
        "number": 1,
        "alt": "example",
        "source": "remote",
        "location": "https://example.test/image.png"
    }]);
    let payload = serde_json::to_vec(&response).unwrap();
    let worker = FakeWorker::response(&payload, &[]);
    let page = renderer_for(&worker.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .expect("valid fake-worker response");
    assert_eq!(page.lines[0].to_string(), "safe text");
    assert_eq!(
        page.links[0].destination.as_deref(),
        Some("https://example.test/")
    );
    assert_eq!(
        page.images[0].location.as_deref(),
        Some("https://example.test/image.png")
    );
}

#[tokio::test]
async fn parent_rejects_forged_link_and_image_classification() {
    let mut forged_link = empty_page_response();
    forged_link["result"]["Ok"]["links"] = serde_json::json!([{
        "number": 1,
        "destination": "javascript:alert(1)",
        "kind": "web",
        "blocked_scheme": null
    }]);
    assert!(matches!(
        fake_response_error(&forged_link).await,
        IsolatedRenderError::Protocol(_)
    ));

    let mut forged_block = empty_page_response();
    forged_block["result"]["Ok"]["links"] = serde_json::json!([{
        "number": 1,
        "destination": null,
        "kind": "blocked",
        "blocked_scheme": "https"
    }]);
    assert!(matches!(
        fake_response_error(&forged_block).await,
        IsolatedRenderError::Protocol(_)
    ));

    let mut forged_image = empty_page_response();
    forged_image["result"]["Ok"]["images"] = serde_json::json!([{
        "number": 1,
        "alt": "invoice",
        "source": "remote",
        "location": "file:///etc/passwd"
    }]);
    assert!(matches!(
        fake_response_error(&forged_image).await,
        IsolatedRenderError::Protocol(_)
    ));
}

#[tokio::test]
async fn parent_rejects_bad_numbering_and_terminal_controls() {
    let mut bad_number = empty_page_response();
    bad_number["result"]["Ok"]["links"] = serde_json::json!([{
        "number": 2,
        "destination": "https://example.test/",
        "kind": "web",
        "blocked_scheme": null
    }]);
    assert!(matches!(
        fake_response_error(&bad_number).await,
        IsolatedRenderError::Protocol(_)
    ));

    for text in ["escape\u{1b}[2J", "reorder\u{202e}txt"] {
        let mut control = empty_page_response();
        control["result"]["Ok"]["lines"] = serde_json::json!([line(text)]);
        assert!(matches!(
            fake_response_error(&control).await,
            IsolatedRenderError::Protocol(_)
        ));
    }
}

#[tokio::test]
async fn parent_rejects_malformed_oversized_and_trailing_frames() {
    let payload = serde_json::to_vec(&empty_page_response()).unwrap();
    let trailing = FakeWorker::response(&payload, b"extra");
    let error = renderer_for(&trailing.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .unwrap_err();
    assert!(matches!(error, IsolatedRenderError::Protocol(_)));

    let malformed = FakeWorker::response(b"{", &[]);
    let error = renderer_for(&malformed.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .unwrap_err();
    assert!(matches!(error, IsolatedRenderError::Protocol(_)));

    let oversized = FakeWorker::python(
        "header = sys.stdin.buffer.read(4)\nrequest_len = struct.unpack('>I', header)[0]\nsys.stdin.buffer.read(request_len)\nsys.stdout.buffer.write(struct.pack('>I', 33554433))\nsys.stdout.buffer.flush()",
    );
    let error = renderer_for(&oversized.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .unwrap_err();
    assert!(matches!(error, IsolatedRenderError::Protocol(_)));

    let truncated = FakeWorker::python(
        "header = sys.stdin.buffer.read(4)\nrequest_len = struct.unpack('>I', header)[0]\nsys.stdin.buffer.read(request_len)\nsys.stdout.buffer.write(struct.pack('>I', 32) + b'x')\nsys.stdout.buffer.flush()",
    );
    let error = renderer_for(&truncated.path, Duration::from_secs(1))
        .render(b"<p>untrusted</p>", 80)
        .await
        .unwrap_err();
    assert!(matches!(error, IsolatedRenderError::Protocol(_)));
}

#[tokio::test]
async fn parent_kills_a_worker_that_exceeds_its_wall_timeout() {
    let worker = FakeWorker::python(
        "header = sys.stdin.buffer.read(4)\nrequest_len = struct.unpack('>I', header)[0]\nsys.stdin.buffer.read(request_len)\ntime.sleep(5)",
    );
    let error = renderer_for(&worker.path, Duration::from_millis(50))
        .render(b"<p>untrusted</p>", 80)
        .await
        .unwrap_err();
    assert_eq!(error, IsolatedRenderError::Timeout);
}

#[tokio::test]
async fn real_worker_renders_only_when_the_sandbox_is_available() {
    let sandbox_available = Command::new(worker_path())
        .arg("--sandbox-self-test")
        .status()
        .expect("renderer sandbox self-test must start")
        .success();
    let renderer = IsolatedHtmlRenderer::new(
        Limits::default(),
        HtmlRenderIsolationConfig {
            worker_path: worker_path(),
            wall_timeout: Duration::from_secs(5),
        },
    );
    let result = renderer
        .render(
            b"<h1>Hello</h1><p><a href='https://example.test'>world</a></p>",
            80,
        )
        .await;
    match (sandbox_available, result) {
        (true, Ok(page)) => {
            assert!(page
                .lines
                .iter()
                .any(|line| line.to_string().contains("Hello")));
            assert_eq!(page.links.len(), 1);
        }
        (false, Err(error)) => {
            // The public API intentionally hides child stderr, but an
            // unavailable Landlock sandbox must surface as a boundary error.
            assert!(error.to_string().contains("renderer boundary failed"));
        }
        (true, Err(error)) => panic!("sandboxed render unexpectedly failed: {error}"),
        (false, Ok(_)) => panic!("renderer ran even though its sandbox self-test failed"),
    }
}
