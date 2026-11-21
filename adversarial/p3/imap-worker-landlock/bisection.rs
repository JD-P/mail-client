//! Standalone Landlock policy reproduction for the isolated IMAP worker.
//!
//! The harness constructs the same `/etc/resolv.conf`-style read rules the
//! production worker uses and reports the enforcement status. `current` mirrors
//! `crates/mail-backend/src/imap_worker.rs::enter_landlock`; `corrected`
//! chooses file-compatible access rights for regular files.
//!
//! This file is copied into a disposable workspace by `run.py`; it is never
//! added to product source.

use std::path::{Path, PathBuf};

use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, Scope, ABI,
};

const BUILTIN_PATHS: &[&str] = &[
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/usr/share/zoneinfo",
    "/proc/self",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/sys/devices/system/cpu",
    "/dev/urandom",
];

fn profile_fixture() -> PathBuf {
    let profile = std::env::temp_dir().join(format!("p3-landlock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&profile);
    std::fs::create_dir_all(profile.join("blobs")).unwrap();
    std::fs::create_dir_all(profile.join("downloads")).unwrap();
    std::fs::write(profile.join("mail.db"), b"db").unwrap();
    std::fs::write(profile.join("mail.db-wal"), b"wal").unwrap();
    std::fs::create_dir_all(profile.join("credentials")).unwrap();
    std::fs::write(profile.join("credentials/secret"), b"fixture").unwrap();
    profile
}

fn enter(corrected: bool, profile: &Path) -> landlock::RestrictionStatus {
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
    let file_read_access = AccessFs::from_file(abi) & !AccessFs::Execute & !AccessFs::IoctlDev;
    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .unwrap()
        .handle_access(AccessNet::from_all(abi))
        .unwrap()
        .scope(Scope::AbstractUnixSocket)
        .unwrap()
        .scope(Scope::Signal)
        .unwrap()
        .create()
        .unwrap()
        .add_rule(PathBeneath::new(
            PathFd::new(profile).unwrap(),
            AccessFs::ReadDir,
        ))
        .unwrap();
    for path in [profile.join("mail.db"), profile.join("mail.db-wal")] {
        created = created
            .add_rule(PathBeneath::new(
                PathFd::new(&path).unwrap(),
                database_access,
            ))
            .unwrap();
    }
    for path in [profile.join("blobs"), profile.join("downloads")] {
        created = created
            .add_rule(PathBeneath::new(PathFd::new(&path).unwrap(), data_access))
            .unwrap();
    }
    for path in BUILTIN_PATHS {
        let path = Path::new(path);
        if path.exists() {
            let access = if corrected && !path.is_dir() {
                file_read_access
            } else {
                read_access
            };
            created = created
                .add_rule(PathBeneath::new(PathFd::new(path).unwrap(), access))
                .unwrap();
        }
    }
    for port in [993_u16, 853] {
        created = created
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .unwrap();
    }
    created.restrict_self().unwrap()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let corrected = match mode.as_str() {
        "current" => false,
        "corrected" => true,
        other => panic!("expected `current` or `corrected`, got {other:?}"),
    };
    let profile = profile_fixture();
    let status = enter(corrected, &profile);
    let outside_read_denied = std::fs::read("/etc/passwd").is_err();
    let hosts_read_allowed = std::fs::read("/etc/hosts").is_ok();
    println!(
        "mode={mode} ruleset={:?} no_new_privs={} all_threads={} outside_read_denied={} hosts_read_allowed={}",
        status.ruleset, status.no_new_privs, status.all_threads, outside_read_denied, hosts_read_allowed
    );
    let _ = std::fs::remove_dir_all(&profile);
}
