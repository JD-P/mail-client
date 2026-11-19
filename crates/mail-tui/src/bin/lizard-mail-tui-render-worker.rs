fn main() {
    if let Err(error) = lizard_mail_tui::__run_html_render_worker() {
        eprintln!("isolated terminal renderer failed: {error}");
        std::process::exit(1);
    }
}
