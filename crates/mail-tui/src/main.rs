use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lizard_mail_backend::{Backend, BackendConfig};
use lizard_mail_tui::app::{AppCommand, MailApp, Screen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::error::Error;
use std::io;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let profile = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: lizard-mail-tui <profile-directory>")?;
    let backend = Backend::open(BackendConfig::new(profile)).await?;
    let mut app = MailApp::open(backend).await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let guard = TerminalGuard;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.clear()?;

    let result = run(&mut terminal, &mut app).await;
    drop(terminal);
    drop(guard);
    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut MailApp,
) -> Result<(), Box<dyn Error>> {
    while !app.quit {
        let render_width = terminal.size()?.width.saturating_sub(2);
        app.prepare_reader_html(render_width).await;
        terminal.draw(|frame| lizard_mail_tui::ui::draw(frame, app))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(command) = command_for(app.screen, key) {
            if let Err(error) = app.dispatch(command).await {
                app.status = Some(error.to_string());
            }
        }
    }
    Ok(())
}

fn command_for(screen: Screen, key: KeyEvent) -> Option<AppCommand> {
    if screen == Screen::OnboardingEdit {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Enter, _) => Some(AppCommand::OnboardingSaveEdit),
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char('r' | 'R'), KeyModifiers::CONTROL) => {
                Some(AppCommand::OnboardingToggleRoute)
            }
            (KeyCode::Char('k' | 'K'), KeyModifiers::CONTROL) => {
                Some(AppCommand::OnboardingCycleKind)
            }
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }

    match key.code {
        KeyCode::Char('q') => Some(AppCommand::Quit),
        KeyCode::Esc => Some(AppCommand::Back),
        KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
        KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
        KeyCode::Enter => Some(AppCommand::Open),
        KeyCode::Char('1') => Some(AppCommand::WarmAction),
        KeyCode::Char('f' | 'F') => Some(AppCommand::WarmFyi),
        KeyCode::Char('2') => Some(AppCommand::Cold),
        KeyCode::Char('3') => Some(AppCommand::Spam),
        KeyCode::Char('l' | 'L') => Some(AppCommand::Waiting),
        KeyCode::Char('z' | 'Z') => Some(AppCommand::Snoozed),
        KeyCode::Char('D') => Some(AppCommand::Done),
        KeyCode::Char('c' | 'C') => Some(AppCommand::Contacts),
        KeyCode::Char('?') => Some(AppCommand::Help),
        KeyCode::Char('d') => Some(AppCommand::MarkDone),
        KeyCode::Char('w') => Some(AppCommand::MarkWaiting),
        KeyCode::Char('s') => Some(AppCommand::SnoozeOneDay),
        KeyCode::Char('a') => Some(AppCommand::MakeActionableOnce),
        KeyCode::Char('O') => Some(AppCommand::RestrictedOpen),
        KeyCode::Char('y') if screen == Screen::Onboarding => Some(AppCommand::OnboardingAccept),
        KeyCode::Char('n') if screen == Screen::Onboarding => Some(AppCommand::OnboardingDismiss),
        KeyCode::Char('e') if screen == Screen::Onboarding => Some(AppCommand::OnboardingEdit),
        _ => None,
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
