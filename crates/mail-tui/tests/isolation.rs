#![cfg(target_os = "linux")]

use lizard_mail_tui::{HtmlRenderIsolationConfig, IsolatedHtmlRenderer, Limits};
#[cfg(target_arch = "x86_64")]
use std::os::unix::process::ExitStatusExt;
use std::{path::PathBuf, process::Command, time::Duration};

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
