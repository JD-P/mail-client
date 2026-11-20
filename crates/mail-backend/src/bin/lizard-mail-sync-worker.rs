fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--version"))
        && arguments.next().is_none()
    {
        println!("lizard-mail-sync-worker {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(error) = lizard_mail_backend::__run_imap_sync_worker() {
        eprintln!("isolated IMAP worker failed: {error}");
        std::process::exit(1);
    }
}
