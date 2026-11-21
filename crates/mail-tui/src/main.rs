use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lizard_mail_backend::{Backend, BackendConfig};
use lizard_mail_tui::app::{AppCommand, MailApp, Screen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsString::from("--version")] {
        println!("lizard-mail-tui {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments.as_slice() == [OsString::from("--help")]
        || arguments.as_slice() == [OsString::from("-h")]
    {
        println!("usage: lizard-mail-tui [--profile <directory>] [profile-directory]");
        println!("Without a path, Lizard uses the platform's per-user data directory.");
        return Ok(());
    }
    let profile = profile_from_arguments(&arguments)?;
    let backend = Backend::open(BackendConfig::new(profile)).await?;
    let mut app = MailApp::open(backend).await?;
    app.enable_auto_sync();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
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
        if let Err(error) = app.poll_background_tasks().await {
            app.status = Some(error.to_string());
        }
        let render_width = terminal.size()?.width.saturating_sub(2);
        app.prepare_reader_html(render_width).await;
        terminal.draw(|frame| lizard_mail_tui::ui::draw(frame, app))?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let command = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => command_for(app.screen, key),
            Event::Paste(value)
                if matches!(
                    app.screen,
                    Screen::AccountEdit | Screen::OnboardingEdit | Screen::ContactEdit
                ) =>
            {
                Some(AppCommand::EditPaste(Zeroizing::new(value)))
            }
            _ => None,
        };
        if let Some(command) = command {
            if let Err(error) = app.dispatch(command).await {
                app.status = Some(error.to_string());
            }
        }
    }
    Ok(())
}

fn command_for(screen: Screen, key: KeyEvent) -> Option<AppCommand> {
    if matches!(key.code, KeyCode::Char('c' | 'C')) && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        return Some(AppCommand::Quit);
    }
    if screen == Screen::AccountEdit {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Tab | KeyCode::Down, _) => Some(AppCommand::EditNextField),
            (KeyCode::BackTab | KeyCode::Up, _) => Some(AppCommand::EditPreviousField),
            (KeyCode::Left | KeyCode::Right, _) => Some(AppCommand::EditToggleChoice),
            (KeyCode::Char(' '), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditSpace)
            }
            (KeyCode::Enter, _) => Some(AppCommand::EditNextField),
            (KeyCode::Char('s' | 'S'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(AppCommand::AccountSave)
            }
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }
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
    if screen == Screen::ContactEdit {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Tab | KeyCode::Down, _) => Some(AppCommand::EditNextField),
            (KeyCode::BackTab | KeyCode::Up, _) => Some(AppCommand::EditPreviousField),
            (KeyCode::Left | KeyCode::Right, _) => Some(AppCommand::EditToggleChoice),
            (KeyCode::Char(' '), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditSpace)
            }
            (KeyCode::Enter, _) => Some(AppCommand::EditNextField),
            (KeyCode::Char('s' | 'S'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(AppCommand::ContactSave)
            }
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }
    if screen == Screen::SimilarityPreview {
        return match key.code {
            KeyCode::Esc | KeyCode::Char('n' | 'N') => Some(AppCommand::SimilarityCancel),
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => Some(AppCommand::SimilarityConfirm),
            KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
            KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
            KeyCode::Char('+' | '=') => Some(AppCommand::SimilarityStricter),
            KeyCode::Char('-' | '_') => Some(AppCommand::SimilarityBroader),
            _ => None,
        };
    }
    if screen == Screen::AccountDeleteConfirm {
        return match key.code {
            KeyCode::Char('y' | 'Y') => Some(AppCommand::AccountConfirmDelete),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => Some(AppCommand::AccountCancelDelete),
            _ => None,
        };
    }
    if screen == Screen::Accounts {
        return match key.code {
            KeyCode::Char('q') => Some(AppCommand::Quit),
            KeyCode::Esc => Some(AppCommand::Back),
            KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
            KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
            KeyCode::Char('n' | 'N') => Some(AppCommand::AccountNew),
            KeyCode::Enter | KeyCode::Char('e' | 'E') => Some(AppCommand::AccountEdit),
            KeyCode::Char('s' | 'S') => Some(AppCommand::AccountSync),
            KeyCode::Char('d') => Some(AppCommand::AccountDelete),
            KeyCode::Char('?') => Some(AppCommand::Help),
            _ => None,
        };
    }
    if screen == Screen::Contacts {
        return match key.code {
            KeyCode::Char('q') => Some(AppCommand::Quit),
            KeyCode::Esc => Some(AppCommand::Back),
            KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
            KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
            KeyCode::Enter | KeyCode::Char('e' | 'E') => Some(AppCommand::ContactEdit),
            KeyCode::Char('?') => Some(AppCommand::Help),
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
        KeyCode::Char('A') => Some(AppCommand::Accounts),
        KeyCode::Char('?') => Some(AppCommand::Help),
        KeyCode::Char('d') => Some(AppCommand::MarkDone),
        KeyCode::Char('w') => Some(AppCommand::MarkWaiting),
        KeyCode::Char('s') => Some(AppCommand::SnoozeOneDay),
        KeyCode::Char('a') => Some(AppCommand::MakeActionableOnce),
        KeyCode::Char('>') => Some(AppCommand::MoveToAction),
        KeyCode::Char('<') => Some(AppCommand::MoveToFyi),
        KeyCode::Char('M') => Some(AppCommand::PreviewSimilarFyi),
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
        let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
    }
}

fn profile_from_arguments(arguments: &[OsString]) -> Result<PathBuf, String> {
    match arguments {
        [] => default_profile_directory(),
        [path] if !path.to_string_lossy().starts_with('-') => Ok(PathBuf::from(path)),
        [flag, path] if flag == "--profile" => Ok(PathBuf::from(path)),
        _ => Err("usage: lizard-mail-tui [--profile <directory>] [profile-directory]".into()),
    }
}

fn default_profile_directory() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    if let Some(base) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        if base.is_absolute() {
            return Ok(base.join("Lizard Mail"));
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if home.is_absolute() {
            return Ok(home.join("Library/Application Support/Lizard Mail"));
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
            if base.is_absolute() {
                return Ok(base.join("lizard-mail"));
            }
        }
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            if home.is_absolute() {
                return Ok(home.join(".local/share/lizard-mail"));
            }
        }
    }

    Err("could not determine the per-user data directory; use --profile <directory>".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_profile_forms_remain_available() {
        let positional = profile_from_arguments(&[OsString::from("/tmp/lizard-portable")]);
        let flagged = profile_from_arguments(&[
            OsString::from("--profile"),
            OsString::from("/tmp/lizard-recovery"),
        ]);

        assert_eq!(positional.unwrap(), PathBuf::from("/tmp/lizard-portable"));
        assert_eq!(flagged.unwrap(), PathBuf::from("/tmp/lizard-recovery"));
    }

    #[test]
    fn bare_invocation_resolves_a_platform_profile() {
        let profile = profile_from_arguments(&[]).unwrap();

        assert!(profile.is_absolute());
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        assert!(profile.ends_with("lizard-mail"));
    }
}
