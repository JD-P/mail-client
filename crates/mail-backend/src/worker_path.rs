use std::path::{Path, PathBuf};

const DEFAULT_LIBEXEC_DIR: &str = "/usr/libexec/lizard-mail";

pub(crate) fn discover(name: &str) -> PathBuf {
    let executable = std::env::current_exe().ok();
    discover_from(
        executable.as_deref(),
        name,
        Path::new(option_env!("LIZARD_MAIL_LIBEXEC_DIR").unwrap_or(DEFAULT_LIBEXEC_DIR)),
    )
}

fn discover_from(executable: Option<&Path>, name: &str, libexec: &Path) -> PathBuf {
    let Some(directory) = executable.and_then(Path::parent) else {
        return PathBuf::from(name);
    };
    let beside = directory.join(name);
    if beside.is_file() {
        return beside;
    }

    // Cargo integration tests run from target/{profile}/deps while package
    // binaries are emitted one directory above it.
    if directory.file_name().is_some_and(|value| value == "deps") {
        if let Some(parent) = directory.parent() {
            let cargo_binary = parent.join(name);
            if cargo_binary.is_file() {
                return cargo_binary;
            }
        }
    }

    // Native packages deliberately keep internal workers out of PATH. This
    // fallback is considered only after the sibling layout used by portable
    // archives, so an unpacked release remains self-contained.
    if libexec.is_absolute() {
        let installed = libexec.join(name);
        if installed.is_file() {
            return installed;
        }
    }
    beside
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_portable_sibling_then_cargo_then_libexec() {
        let root = tempfile::tempdir().unwrap();
        let debug = root.path().join("target/debug");
        let deps = debug.join("deps");
        let libexec = root.path().join("usr/libexec/lizard-mail");
        std::fs::create_dir_all(&deps).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        let executable = deps.join("integration-test");
        let name = "lizard-mail-worker";

        std::fs::write(libexec.join(name), b"worker").unwrap();
        assert_eq!(
            discover_from(Some(&executable), name, &libexec),
            libexec.join(name)
        );

        std::fs::write(debug.join(name), b"worker").unwrap();
        assert_eq!(
            discover_from(Some(&executable), name, &libexec),
            debug.join(name)
        );

        std::fs::write(deps.join(name), b"worker").unwrap();
        assert_eq!(
            discover_from(Some(&executable), name, &libexec),
            deps.join(name)
        );
    }

    #[test]
    fn never_uses_a_relative_libexec_fallback() {
        let executable = Path::new("/tmp/lizard/bin/lizard-mail-tui");
        assert_eq!(
            discover_from(Some(executable), "worker", Path::new("relative")),
            Path::new("/tmp/lizard/bin/worker")
        );
    }
}
