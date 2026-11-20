fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--version"))
        && arguments.next().is_none()
    {
        println!(
            "lizard-mail-tui-render-worker {}",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    if let Err(error) = lizard_mail_tui::__run_html_render_worker() {
        eprintln!("isolated terminal renderer failed: {error}");
        std::process::exit(1);
    }
}
