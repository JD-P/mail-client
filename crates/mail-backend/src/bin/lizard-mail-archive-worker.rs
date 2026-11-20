fn main() {
    if let Err(error) = lizard_mail_backend::__run_archive_worker() {
        eprintln!("isolated archive worker failed: {error}");
        std::process::exit(1);
    }
}
