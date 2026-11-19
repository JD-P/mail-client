fn main() {
    if let Err(error) = lizard_mail_backend::__run_imap_sync_worker() {
        eprintln!("isolated IMAP worker failed: {error}");
        std::process::exit(1);
    }
}
