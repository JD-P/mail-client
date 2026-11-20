//! Disposable process boundary for ZIP directory parsing and expansion.
//!
//! The worker receives archive bytes over bounded pipes after entering an
//! empty Landlock filesystem/network policy. It can return only validated
//! directory metadata or one bounded byte string. It never receives a path,
//! profile handle, credential, terminal, or network capability.

use crate::{
    ArchiveEntry, ArchiveInspection, ArchiveInspectionState, ArchiveLimits, BackendError, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_VERSION: u32 = 1;
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const MAX_ENTRY_PATH_CHARS: usize = 4_096;
const MAX_DETAIL_CHARS: usize = 4_096;
const WORKER_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
const WORKER_CPU_SECONDS: u64 = 15;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Clone, Debug)]
pub struct ArchiveIsolationConfig {
    /// Absolute path to the separately installed worker executable.
    pub worker_path: PathBuf,
    /// Wall-clock ceiling for worker startup, parsing and response transfer.
    pub wall_timeout: Duration,
}

impl Default for ArchiveIsolationConfig {
    fn default() -> Self {
        Self {
            worker_path: default_worker_path(),
            wall_timeout: Duration::from_secs(30),
        }
    }
}

fn default_worker_path() -> PathBuf {
    let name = if cfg!(windows) {
        "lizard-mail-archive-worker.exe"
    } else {
        "lizard-mail-archive-worker"
    };
    let Some(executable) = std::env::current_exe().ok() else {
        return PathBuf::from(name);
    };
    let Some(directory) = executable.parent() else {
        return PathBuf::from(name);
    };
    let beside = directory.join(name);
    if beside.exists() {
        return beside;
    }
    // Cargo integration tests run from target/{profile}/deps while package
    // binaries are emitted one directory above it.
    if directory.file_name().is_some_and(|value| value == "deps") {
        if let Some(parent) = directory.parent() {
            let package_binary = parent.join(name);
            if package_binary.exists() {
                return package_binary;
            }
        }
    }
    beside
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ArchiveOperation {
    Inspect,
    ReadEntry { entry_index: u32 },
}

pub(crate) enum ArchiveOutput {
    Inspection(ArchiveInspection),
    Entry(Vec<u8>),
}

pub(crate) async fn execute(
    archive: Vec<u8>,
    limits: ArchiveLimits,
    operation: ArchiveOperation,
    mut isolation: ArchiveIsolationConfig,
) -> Result<ArchiveOutput> {
    validate_limits(&limits)?;
    if archive.len() > MAX_ARCHIVE_BYTES || archive.len() as u64 > limits.max_archive_bytes {
        return Err(BackendError::MessageTooLarge {
            actual: archive.len(),
            limit: usize::try_from(limits.max_archive_bytes)
                .unwrap_or(usize::MAX)
                .min(MAX_ARCHIVE_BYTES),
        });
    }
    if isolation.wall_timeout.is_zero() {
        return Err(BackendError::InvalidInput(
            "archive worker wall timeout must be positive".into(),
        ));
    }
    isolation.worker_path = std::fs::canonicalize(&isolation.worker_path).map_err(|error| {
        BackendError::InvalidInput(format!("archive worker is unavailable: {error}"))
    })?;
    if !isolation.worker_path.is_absolute() {
        return Err(BackendError::InvalidInput(
            "archive worker path must be absolute".into(),
        ));
    }

    let request = WorkerRequest {
        protocol: PROTOCOL_VERSION,
        operation: operation.into(),
        limits: limits.clone(),
        archive_bytes: archive.len() as u64,
    };
    let mut header = Zeroizing::new(serde_json::to_vec(&request)?);
    if header.len() > MAX_REQUEST_HEADER_BYTES {
        return Err(BackendError::InvalidInput(
            "archive worker request header exceeds its protocol limit".into(),
        ));
    }
    let header_length = u32::try_from(header.len())
        .map_err(|_| BackendError::InvalidInput("archive request length overflow".into()))?;
    let mut command = Command::new(&isolation.worker_path);
    command
        .arg("--worker-v1")
        .env_clear()
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    prepare_worker_command(&mut command).map_err(BackendError::InvalidInput)?;
    let mut child = command.spawn().map_err(|error| {
        BackendError::InvalidInput(format!("could not start archive worker: {error}"))
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| BackendError::InvalidInput("archive worker stdin was unavailable".into()))?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        BackendError::InvalidInput("archive worker stdout was unavailable".into())
    })?;

    let exchange = async {
        stdin.write_all(&header_length.to_be_bytes()).await?;
        stdin.write_all(header.as_slice()).await?;
        header.zeroize();
        stdin.write_all(&archive).await?;
        stdin.shutdown().await?;
        drop(stdin);

        let mut response_length = [0_u8; 4];
        stdout.read_exact(&mut response_length).await?;
        let response_length = u32::from_be_bytes(response_length) as usize;
        if response_length > MAX_RESPONSE_HEADER_BYTES {
            return Err(std::io::Error::other(
                "archive worker response header exceeds its protocol limit",
            ));
        }
        let mut response = vec![0_u8; response_length];
        stdout.read_exact(&mut response).await?;
        let response: WorkerResponse = serde_json::from_slice(&response)
            .map_err(|error| std::io::Error::other(format!("invalid response: {error}")))?;
        let output = response.result.map_err(std::io::Error::other)?;
        let output = match output {
            WorkerOutputHeader::Inspection(inspection) => ArchiveOutput::Inspection(inspection),
            WorkerOutputHeader::Entry { bytes } => {
                let bytes = usize::try_from(bytes)
                    .map_err(|_| std::io::Error::other("archive entry length overflow"))?;
                if bytes > MAX_ENTRY_BYTES || bytes as u64 > limits.max_entry_bytes {
                    return Err(std::io::Error::other(
                        "archive worker entry exceeds its response budget",
                    ));
                }
                let mut output = vec![0_u8; bytes];
                stdout.read_exact(&mut output).await?;
                ArchiveOutput::Entry(output)
            }
        };
        let mut trailing = [0_u8; 1];
        if stdout.read(&mut trailing).await? != 0 {
            return Err(std::io::Error::other(
                "archive worker sent trailing protocol data",
            ));
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "archive worker exited unsuccessfully: {status}"
            )));
        }
        Ok::<_, std::io::Error>((response.protocol, output))
    };
    let (protocol, output) = match timeout(isolation.wall_timeout, exchange).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(BackendError::InvalidInput(format!(
                "archive worker boundary failed: {}",
                bounded_detail(&error.to_string())
            )));
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(BackendError::InvalidInput(
                "archive worker exceeded its wall-clock limit".into(),
            ));
        }
    };
    if protocol != PROTOCOL_VERSION {
        return Err(BackendError::InvalidInput(
            "archive worker protocol version mismatch".into(),
        ));
    }
    match (&operation, &output) {
        (ArchiveOperation::Inspect, ArchiveOutput::Inspection(inspection)) => {
            validate_inspection(inspection, &limits)?;
        }
        (ArchiveOperation::ReadEntry { .. }, ArchiveOutput::Entry(bytes))
            if bytes.len() <= MAX_ENTRY_BYTES && bytes.len() as u64 <= limits.max_entry_bytes => {}
        _ => {
            return Err(BackendError::InvalidInput(
                "archive worker returned the wrong result type".into(),
            ));
        }
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn prepare_worker_command(command: &mut Command) -> std::result::Result<(), String> {
    // SAFETY: this closure runs after fork and before exec and performs one
    // async-signal-safe syscall with constant scalar arguments.
    unsafe {
        command.pre_exec(|| {
            let result = libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_worker_command(_command: &mut Command) -> std::result::Result<(), String> {
    Err("isolated archive processing is not implemented on this platform".into())
}

#[derive(Serialize, Deserialize)]
struct WorkerRequest {
    protocol: u32,
    operation: WorkerOperation,
    limits: ArchiveLimits,
    archive_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerOperation {
    Inspect,
    ReadEntry { entry_index: u32 },
}

impl From<ArchiveOperation> for WorkerOperation {
    fn from(value: ArchiveOperation) -> Self {
        match value {
            ArchiveOperation::Inspect => Self::Inspect,
            ArchiveOperation::ReadEntry { entry_index } => Self::ReadEntry { entry_index },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WorkerResponse {
    protocol: u32,
    result: std::result::Result<WorkerOutputHeader, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerOutputHeader {
    Inspection(ArchiveInspection),
    Entry { bytes: u64 },
}

pub(crate) fn run_worker_process() -> std::result::Result<(), String> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    if mode.as_deref() == Some(std::ffi::OsStr::new("--sandbox-self-test")) {
        return sandbox_self_test();
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--seccomp-self-test")) {
        return seccomp_self_test();
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--seccomp-x32-self-test")) {
        return seccomp_x32_self_test();
    }
    if mode.as_deref() != Some(std::ffi::OsStr::new("--worker-v1")) {
        return Err("this executable is an internal isolated archive worker".into());
    }
    install_worker_sandbox()?;

    let mut header_length = [0_u8; 4];
    std::io::stdin()
        .read_exact(&mut header_length)
        .map_err(|error| format!("reading archive request length: {error}"))?;
    let header_length = u32::from_be_bytes(header_length) as usize;
    if header_length > MAX_REQUEST_HEADER_BYTES {
        return Err("archive request header exceeds its protocol limit".into());
    }
    let mut header = Zeroizing::new(vec![0_u8; header_length]);
    std::io::stdin()
        .read_exact(header.as_mut_slice())
        .map_err(|error| format!("reading archive request header: {error}"))?;
    let request: WorkerRequest = serde_json::from_slice(header.as_slice())
        .map_err(|error| format!("parsing archive request header: {error}"))?;
    header.zeroize();
    if request.protocol != PROTOCOL_VERSION {
        return Err("archive worker protocol version mismatch".into());
    }
    validate_limits(&request.limits).map_err(|error| error.to_string())?;
    let archive_length = usize::try_from(request.archive_bytes)
        .map_err(|_| "archive request length overflow".to_owned())?;
    if archive_length > MAX_ARCHIVE_BYTES
        || request.archive_bytes > request.limits.max_archive_bytes
    {
        return Err("archive input exceeds its protocol limit".into());
    }
    let mut archive = Zeroizing::new(vec![0_u8; archive_length]);
    std::io::stdin()
        .read_exact(archive.as_mut_slice())
        .map_err(|error| format!("reading archive input: {error}"))?;
    let mut trailing = [0_u8; 1];
    if std::io::stdin()
        .read(&mut trailing)
        .map_err(|error| format!("checking archive request boundary: {error}"))?
        != 0
    {
        return Err("archive request contains trailing data".into());
    }

    let result = match request.operation {
        WorkerOperation::Inspect => {
            inspect_zip(&archive, request.limits).map(ArchiveOutput::Inspection)
        }
        WorkerOperation::ReadEntry { entry_index } => {
            read_zip_entry(&archive, entry_index, request.limits).map(ArchiveOutput::Entry)
        }
    };
    archive.zeroize();
    write_worker_response(result)
}

fn write_worker_response(result: Result<ArchiveOutput>) -> std::result::Result<(), String> {
    let (header_result, bytes) = match result {
        Ok(ArchiveOutput::Inspection(inspection)) => {
            (Ok(WorkerOutputHeader::Inspection(inspection)), None)
        }
        Ok(ArchiveOutput::Entry(bytes)) => {
            let length = bytes.len() as u64;
            (Ok(WorkerOutputHeader::Entry { bytes: length }), Some(bytes))
        }
        Err(error) => (Err(bounded_detail(&error.to_string())), None),
    };
    let response = WorkerResponse {
        protocol: PROTOCOL_VERSION,
        result: header_result,
    };
    let header = serde_json::to_vec(&response)
        .map_err(|error| format!("serializing archive response: {error}"))?;
    if header.len() > MAX_RESPONSE_HEADER_BYTES {
        return Err("archive response header exceeds its protocol limit".into());
    }
    let length = u32::try_from(header.len()).map_err(|_| "archive response length overflow")?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&length.to_be_bytes())
        .and_then(|()| stdout.write_all(&header))
        .map_err(|error| format!("writing archive response header: {error}"))?;
    if let Some(bytes) = bytes {
        stdout
            .write_all(&bytes)
            .map_err(|error| format!("writing archive response bytes: {error}"))?;
    }
    stdout
        .flush()
        .map_err(|error| format!("flushing archive response: {error}"))
}

pub(crate) fn inspect_zip(bytes: &[u8], limits: ArchiveLimits) -> Result<ArchiveInspection> {
    validate_limits(&limits)?;
    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(error) => {
            return Ok(ArchiveInspection {
                state: ArchiveInspectionState::Invalid,
                entries: Vec::new(),
                total_uncompressed_bytes: 0,
                detail: Some(bounded_detail(&error.to_string())),
            });
        }
    };
    let mut entries = Vec::new();
    let mut total = 0u64;
    let mut limited = archive.len() > limits.max_entries;
    let mut encrypted = false;
    for index in 0..archive.len().min(limits.max_entries) {
        let file = archive
            .by_index_raw(index)
            .map_err(|error| BackendError::InvalidInput(bounded_detail(&error.to_string())))?;
        let unsafe_name = file.enclosed_name().is_none();
        let (path, path_limited) = file.enclosed_name().map_or_else(
            || ("[unsafe path omitted]".to_owned(), false),
            |path| bounded_path(&path.to_string_lossy()),
        );
        encrypted |= file.encrypted();
        let size = file.size();
        let compressed = file.compressed_size();
        total = total.saturating_add(size);
        let ratio_exceeded = compressed == 0 && size > 0
            || compressed > 0
                && size > compressed.saturating_mul(u64::from(limits.max_compression_ratio));
        limited |= unsafe_name
            || path_limited
            || size > limits.max_entry_bytes
            || total > limits.max_total_uncompressed_bytes
            || ratio_exceeded;
        entries.push(ArchiveEntry {
            index: index as u32,
            path,
            directory: file.is_dir(),
            encrypted: file.encrypted(),
            compressed_size: compressed,
            uncompressed_size: size,
        });
    }
    Ok(ArchiveInspection {
        state: if encrypted {
            ArchiveInspectionState::Encrypted
        } else if limited {
            ArchiveInspectionState::Limited
        } else {
            ArchiveInspectionState::Complete
        },
        entries,
        total_uncompressed_bytes: total,
        detail: limited.then(|| {
            "archive expansion budget, path-length, or safe-path rule was exceeded".into()
        }),
    })
}

pub(crate) fn read_zip_entry(
    bytes: &[u8],
    entry_index: u32,
    limits: ArchiveLimits,
) -> Result<Vec<u8>> {
    let inspection = inspect_zip(bytes, limits.clone())?;
    if inspection.state != ArchiveInspectionState::Complete {
        return Err(BackendError::Conflict(
            "archive entry cannot be expanded unless inspection completed within budget".into(),
        ));
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| BackendError::InvalidInput(bounded_detail(&error.to_string())))?;
    let mut file = archive
        .by_index(entry_index as usize)
        .map_err(|error| BackendError::InvalidInput(bounded_detail(&error.to_string())))?;
    if file.encrypted() || file.enclosed_name().is_none() || file.is_dir() {
        return Err(BackendError::Conflict(
            "archive entry is encrypted, unsafe, or not a regular file".into(),
        ));
    }
    let capacity = usize::try_from(file.size().min(limits.max_entry_bytes))
        .unwrap_or(MAX_ENTRY_BYTES)
        .min(MAX_ENTRY_BYTES);
    let mut output = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limits.max_entry_bytes.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error| BackendError::InvalidInput(bounded_detail(&error.to_string())))?;
    if output.len() as u64 > limits.max_entry_bytes || output.len() > MAX_ENTRY_BYTES {
        return Err(BackendError::InvalidInput(
            "archive entry exceeded expansion budget".into(),
        ));
    }
    Ok(output)
}

pub(crate) fn validate_limits(limits: &ArchiveLimits) -> Result<()> {
    if limits.max_archive_bytes == 0
        || limits.max_entries == 0
        || limits.max_entry_bytes == 0
        || limits.max_total_uncompressed_bytes == 0
        || limits.max_compression_ratio == 0
    {
        return Err(BackendError::InvalidInput(
            "archive limits must be positive".into(),
        ));
    }
    if limits.max_archive_bytes > MAX_ARCHIVE_BYTES as u64
        || limits.max_entry_bytes > MAX_ENTRY_BYTES as u64
        || limits.max_entries > MAX_ENTRIES
    {
        return Err(BackendError::InvalidInput(format!(
            "archive limits exceed worker protocol maxima ({MAX_ARCHIVE_BYTES} input bytes, {MAX_ENTRY_BYTES} entry bytes, {MAX_ENTRIES} entries)"
        )));
    }
    Ok(())
}

fn validate_inspection(inspection: &ArchiveInspection, limits: &ArchiveLimits) -> Result<()> {
    if inspection.entries.len() > limits.max_entries || inspection.entries.len() > MAX_ENTRIES {
        return Err(BackendError::InvalidInput(
            "archive worker returned too many entries".into(),
        ));
    }
    if inspection
        .detail
        .as_deref()
        .is_some_and(|detail| detail.chars().count() > MAX_DETAIL_CHARS || has_control(detail))
    {
        return Err(BackendError::InvalidInput(
            "archive worker returned an invalid detail string".into(),
        ));
    }
    let mut total = 0u64;
    for (index, entry) in inspection.entries.iter().enumerate() {
        if entry.index as usize != index
            || entry.path.chars().count() > MAX_ENTRY_PATH_CHARS
            || has_control(&entry.path)
            || !safe_metadata_path(&entry.path)
            || entry.compressed_size > limits.max_archive_bytes
        {
            return Err(BackendError::InvalidInput(
                "archive worker returned invalid entry metadata".into(),
            ));
        }
        total = total.checked_add(entry.uncompressed_size).ok_or_else(|| {
            BackendError::InvalidInput("archive worker returned overflowing size metadata".into())
        })?;
    }
    if total != inspection.total_uncompressed_bytes {
        return Err(BackendError::InvalidInput(
            "archive worker returned inconsistent size metadata".into(),
        ));
    }
    match inspection.state {
        ArchiveInspectionState::Complete => {
            if total > limits.max_total_uncompressed_bytes
                || inspection.entries.iter().any(|entry| {
                    entry.path == "[unsafe path omitted]"
                        || entry.encrypted
                        || entry.uncompressed_size > limits.max_entry_bytes
                        || (entry.compressed_size == 0 && entry.uncompressed_size > 0)
                        || (entry.compressed_size > 0
                            && entry.uncompressed_size
                                > entry
                                    .compressed_size
                                    .saturating_mul(u64::from(limits.max_compression_ratio)))
                })
            {
                return Err(BackendError::InvalidInput(
                    "archive worker claimed unsafe metadata was complete".into(),
                ));
            }
        }
        ArchiveInspectionState::Encrypted => {
            if !inspection.entries.iter().any(|entry| entry.encrypted) {
                return Err(BackendError::InvalidInput(
                    "archive worker returned an inconsistent encrypted state".into(),
                ));
            }
        }
        ArchiveInspectionState::Invalid => {
            if !inspection.entries.is_empty() || total != 0 {
                return Err(BackendError::InvalidInput(
                    "archive worker returned metadata for an invalid archive".into(),
                ));
            }
        }
        ArchiveInspectionState::Unsupported => {
            return Err(BackendError::InvalidInput(
                "ZIP worker returned an unsupported-format result".into(),
            ));
        }
        ArchiveInspectionState::Limited => {}
    }
    Ok(())
}

fn bounded_path(value: &str) -> (String, bool) {
    let mut limited = false;
    let value = value
        .chars()
        .take(MAX_ENTRY_PATH_CHARS.saturating_add(1))
        .enumerate()
        .filter_map(|(index, character)| {
            if index == MAX_ENTRY_PATH_CHARS {
                limited = true;
                return None;
            }
            Some(if character.is_control() {
                limited = true;
                '�'
            } else {
                character
            })
        })
        .collect();
    (value, limited)
}

fn bounded_detail(value: &str) -> String {
    value
        .chars()
        .take(MAX_DETAIL_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn safe_metadata_path(value: &str) -> bool {
    use std::path::Component;

    if value == "[unsafe path omitted]" {
        return true;
    }
    let path = std::path::Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
        && path
            .components()
            .any(|component| matches!(component, Component::Normal(_)))
}

#[cfg(target_os = "linux")]
fn install_worker_sandbox() -> std::result::Result<(), String> {
    set_worker_limits()?;
    enter_landlock()?;
    enter_seccomp()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_worker_sandbox() -> std::result::Result<(), String> {
    Err("isolated archive processing has no fail-closed sandbox on this platform".into())
}

#[cfg(target_os = "linux")]
fn set_worker_limits() -> std::result::Result<(), String> {
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
                "could not set archive worker resource limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    set(libc::RLIMIT_AS, WORKER_MEMORY_BYTES, WORKER_MEMORY_BYTES)?;
    set(
        libc::RLIMIT_CPU,
        WORKER_CPU_SECONDS,
        WORKER_CPU_SECONDS.saturating_add(1),
    )?;
    set(libc::RLIMIT_FSIZE, 0, 0)?;
    set(libc::RLIMIT_CORE, 0, 0)?;
    set(libc::RLIMIT_NOFILE, 16, 16)?;
    // SAFETY: PR_SET_DUMPABLE takes a scalar integer flag.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "could not disable archive worker ptrace access: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_landlock() -> std::result::Result<(), String> {
    use landlock::{Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope, ABI};
    let abi = ABI::V6;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(abi)))
        .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket))
        .and_then(|ruleset| ruleset.scope(Scope::Signal))
        .map_err(|error| format!("could not configure archive Landlock: {error}"))?
        .create()
        .map_err(|error| format!("could not create archive Landlock ruleset: {error}"))?
        .restrict_self()
        .map_err(|error| format!("could not enter archive Landlock sandbox: {error}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!(
            "archive Landlock sandbox was not fully enforced: {status:?}"
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enter_seccomp() -> std::result::Result<(), String> {
    // SAFETY: the initialized classic-BPF program is consumed synchronously
    // by prctl after Landlock has set no_new_privs.
    unsafe {
        const LD: u16 = 0x20;
        const JEQ: u16 = 0x15;
        const JSET: u16 = 0x45;
        const RET: u16 = 0x06;
        const ALLOW: u32 = 0x7fff0000;
        const KILL: u32 = 0x80000000;
        const ERRNO: u32 = 0x00050000;
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
        let mut code = vec![
            stmt(LD, 4),
            jump(JEQ, 0xc000003e, 1, 0),
            stmt(RET, KILL),
            stmt(LD, 0),
            jump(JSET, X32_SYSCALL_BIT, 0, 1),
            stmt(RET, KILL),
        ];
        for syscall in [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_clone,
            libc::SYS_clone3,
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
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_creat,
            libc::SYS_name_to_handle_at,
            libc::SYS_open_by_handle_at,
            libc::SYS_chdir,
            libc::SYS_fchdir,
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
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_pidfd_send_signal,
            libc::SYS_process_madvise,
            libc::SYS_process_mrelease,
            libc::SYS_shmget,
            libc::SYS_shmat,
            libc::SYS_shmdt,
            libc::SYS_shmctl,
            libc::SYS_msgget,
            libc::SYS_msgsnd,
            libc::SYS_msgrcv,
            libc::SYS_msgctl,
            libc::SYS_semget,
            libc::SYS_semop,
            libc::SYS_semctl,
            libc::SYS_semtimedop,
            libc::SYS_pipe,
            libc::SYS_pipe2,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
            libc::SYS_fanotify_init,
            libc::SYS_fanotify_mark,
            libc::SYS_inotify_init,
            libc::SYS_inotify_init1,
            libc::SYS_inotify_add_watch,
            libc::SYS_inotify_rm_watch,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_prctl,
            libc::SYS_seccomp,
            libc::SYS_setrlimit,
            libc::SYS_prlimit64,
        ] {
            code.push(jump(JEQ, syscall as u32, 0, 1));
            code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        }
        code.push(stmt(RET, ALLOW));
        let program = libc::sock_fprog {
            len: u16::try_from(code.len()).map_err(|_| "archive seccomp program is too large")?,
            filter: code.as_mut_ptr(),
        };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
            return Err(format!(
                "could not enter archive seccomp sandbox: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn enter_seccomp() -> std::result::Result<(), String> {
    Err("isolated archive seccomp is not implemented for this architecture".into())
}

#[cfg(target_os = "linux")]
fn sandbox_self_test() -> std::result::Result<(), String> {
    install_worker_sandbox()?;
    report_sandbox_evidence()
}

#[cfg(not(target_os = "linux"))]
fn sandbox_self_test() -> std::result::Result<(), String> {
    Err("archive sandbox self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seccomp_self_test() -> std::result::Result<(), String> {
    enable_no_new_privs()?;
    enter_seccomp()?;
    report_sandbox_evidence()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn seccomp_self_test() -> std::result::Result<(), String> {
    Err("archive seccomp self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seccomp_x32_self_test() -> std::result::Result<(), String> {
    enable_no_new_privs()?;
    enter_seccomp()?;
    // SAFETY: this deliberately invokes a no-argument getpid-shaped syscall
    // in a disposable test process. The filter must terminate it with SIGSYS.
    unsafe {
        libc::syscall((libc::SYS_getpid as u32 | X32_SYSCALL_BIT) as libc::c_long);
    }
    Err("archive seccomp accepted an x32-numbered syscall".into())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn seccomp_x32_self_test() -> std::result::Result<(), String> {
    Err("archive x32 seccomp self-test is unavailable on this platform".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enable_no_new_privs() -> std::result::Result<(), String> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "could not set no_new_privs for archive self-test: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn report_sandbox_evidence() -> std::result::Result<(), String> {
    #[derive(Serialize)]
    struct Evidence {
        filesystem_denied: bool,
        network_denied: bool,
        execution_denied: bool,
        pipe_creation_denied: bool,
    }
    // SAFETY: the probe passes a valid two-integer buffer to pipe2 and closes
    // any unexpected descriptors before returning an error.
    let pipe_creation_denied = unsafe {
        let mut descriptors = [-1_i32; 2];
        let result = libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC);
        if result == 0 {
            libc::close(descriptors[0]);
            libc::close(descriptors[1]);
            false
        } else {
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    };
    let evidence = Evidence {
        filesystem_denied: std::fs::read("/etc/passwd").is_err(),
        network_denied: std::net::UdpSocket::bind("127.0.0.1:0").is_err(),
        execution_denied: std::process::Command::new("/bin/true").status().is_err(),
        pipe_creation_denied,
    };
    if !evidence.filesystem_denied
        || !evidence.network_denied
        || !evidence.execution_denied
        || !evidence.pipe_creation_denied
    {
        return Err(format!(
            "archive sandbox self-test failed: {}",
            serde_json::to_string(&evidence).map_err(|error| error.to_string())?
        ));
    }
    println!(
        "{}",
        serde_json::to_string(&evidence).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip(path: &str, contents: &[u8]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(path, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(contents).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn pure_zip_operations_are_bounded_before_the_process_adapter() {
        let archive = zip("folder/note.txt", b"payload");
        let limits = ArchiveLimits::default();
        let inspection = inspect_zip(&archive, limits.clone()).unwrap();
        assert_eq!(inspection.state, ArchiveInspectionState::Complete);
        assert_eq!(inspection.entries[0].path, "folder/note.txt");
        assert_eq!(read_zip_entry(&archive, 0, limits).unwrap(), b"payload");
    }

    #[test]
    fn unsafe_and_overlong_paths_never_cross_as_filesystem_names() {
        let unsafe_archive = zip("../escape.txt", b"payload");
        let inspection = inspect_zip(&unsafe_archive, ArchiveLimits::default()).unwrap();
        assert_eq!(inspection.state, ArchiveInspectionState::Limited);
        assert_eq!(inspection.entries[0].path, "[unsafe path omitted]");

        let long_name = format!("{}.txt", "a".repeat(MAX_ENTRY_PATH_CHARS + 16));
        let long_archive = zip(&long_name, b"payload");
        let inspection = inspect_zip(&long_archive, ArchiveLimits::default()).unwrap();
        assert_eq!(inspection.state, ArchiveInspectionState::Limited);
        assert_eq!(
            inspection.entries[0].path.chars().count(),
            MAX_ENTRY_PATH_CHARS
        );
    }

    #[test]
    fn parent_validation_rejects_traversal_and_size_overflow() {
        let limits = ArchiveLimits {
            max_entries: 2,
            max_total_uncompressed_bytes: u64::MAX,
            ..ArchiveLimits::default()
        };
        let entry = |index: u32, path: &str, size: u64| ArchiveEntry {
            index,
            path: path.to_owned(),
            directory: false,
            encrypted: false,
            compressed_size: 1,
            uncompressed_size: size,
        };
        let traversal = ArchiveInspection {
            state: ArchiveInspectionState::Limited,
            entries: vec![entry(0, "../escape", 1)],
            total_uncompressed_bytes: 1,
            detail: None,
        };
        assert!(validate_inspection(&traversal, &limits).is_err());

        let overflowing = ArchiveInspection {
            state: ArchiveInspectionState::Limited,
            entries: vec![entry(0, "first", u64::MAX), entry(1, "second", 1)],
            total_uncompressed_bytes: u64::MAX,
            detail: None,
        };
        assert!(validate_inspection(&overflowing, &limits).is_err());
    }
}
