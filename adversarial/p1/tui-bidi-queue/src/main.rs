use lizard_mail_backend::{Backend, BackendConfig, IngestMessage};
use lizard_mail_tui::app::{AppCommand, MailApp};
use ratatui::{backend::CrosstermBackend, layout::Rect, Terminal, TerminalOptions, Viewport};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

const RLO: &str = "\u{202e}";

#[tokio::main]
async fn main() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let raw = format!(
        "From: attacker@example.test\r\nTo: victim@example.test\r\nSubject: Invoice {RLO}moc.live@troppus\r\nMessage-ID: <bidi@example.test>\r\n\r\nNothing to see.\r\n"
    );
    backend
        .messages()
        .ingest(IngestMessage::local(raw.into_bytes()))
        .await
        .unwrap();
    let mut app = MailApp::open(backend).await.unwrap();
    app.dispatch(AppCommand::Cold).await.unwrap();
    println!(
        "stored_subject={:?}",
        app.threads[0].subject.as_deref().unwrap()
    );

    let captured = SharedWriter::default();
    let output = captured.0.clone();
    let terminal_backend = CrosstermBackend::new(captured);
    let mut terminal = Terminal::with_options(
        terminal_backend,
        TerminalOptions {
            viewport: Viewport::Fixed(Rect::new(0, 0, 120, 28)),
        },
    )
    .unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let output = output.lock().unwrap();
    println!(
        "terminal_contains_rlo={}",
        find(&output, RLO.as_bytes()).is_some()
    );
    if let Some(at) = find(&output, b"Invoice") {
        println!(
            "terminal_subject_window={:?}",
            &output[at..output.len().min(at + 80)]
        );
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
