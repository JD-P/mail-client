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
use std::process::{Command, Stdio};
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
                    Screen::AccountEdit
                        | Screen::OnboardingEdit
                        | Screen::ContactEdit
                        | Screen::Compose
                        | Screen::SearchInput
                        | Screen::FolderEdit
                        | Screen::FolderDeleteConfirm
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
            if let Some(url) = app.take_external_url_request() {
                if let Err(error) = open_default_browser(&url) {
                    app.status = Some(format!("Could not open the default browser: {error}"));
                }
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
    if screen == Screen::SearchInput {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::SearchCancel),
            (KeyCode::Enter, _) => Some(AppCommand::SearchSubmit),
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }
    if screen == Screen::Compose {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Tab | KeyCode::Down, _) => Some(AppCommand::EditNextField),
            (KeyCode::BackTab | KeyCode::Up, _) => Some(AppCommand::EditPreviousField),
            (KeyCode::Char('s' | 'S'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(AppCommand::ComposeSave)
            }
            (KeyCode::Char('d' | 'D'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                Some(AppCommand::ComposeSend)
            }
            (KeyCode::Enter, _) => Some(AppCommand::ComposeNewline),
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
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
    if screen == Screen::FolderEdit {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Enter, _) => Some(AppCommand::FolderSave),
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }
    if screen == Screen::FolderDeleteConfirm {
        return match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => Some(AppCommand::Back),
            (KeyCode::Enter, _) => Some(AppCommand::FolderConfirmDelete),
            (KeyCode::Backspace, _) => Some(AppCommand::EditBackspace),
            (KeyCode::Char(character), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                Some(AppCommand::EditCharacter(character))
            }
            _ => None,
        };
    }
    if screen == Screen::FolderBind {
        return match key.code {
            KeyCode::Esc => Some(AppCommand::Back),
            KeyCode::Char('5') => Some(AppCommand::FolderBind(5)),
            KeyCode::Char('6') => Some(AppCommand::FolderBind(6)),
            KeyCode::Char('7') => Some(AppCommand::FolderBind(7)),
            KeyCode::Char('8') => Some(AppCommand::FolderBind(8)),
            KeyCode::Char('9') => Some(AppCommand::FolderBind(9)),
            KeyCode::Char('0') => Some(AppCommand::FolderBind(0)),
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
    if screen == Screen::Folders {
        return match key.code {
            KeyCode::Char('q') => Some(AppCommand::Quit),
            KeyCode::Esc => Some(AppCommand::Back),
            KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
            KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
            KeyCode::Enter => Some(AppCommand::Open),
            KeyCode::Char('b' | 'B') => Some(AppCommand::FolderBeginBind),
            KeyCode::Char('n' | 'N') => Some(AppCommand::FolderNew),
            KeyCode::Char('r' | 'R') => Some(AppCommand::FolderRename),
            KeyCode::Char('d') => Some(AppCommand::FolderDelete),
            KeyCode::Char('5') => Some(AppCommand::FolderOpenShortcut(5)),
            KeyCode::Char('6') => Some(AppCommand::FolderOpenShortcut(6)),
            KeyCode::Char('7') => Some(AppCommand::FolderOpenShortcut(7)),
            KeyCode::Char('8') => Some(AppCommand::FolderOpenShortcut(8)),
            KeyCode::Char('9') => Some(AppCommand::FolderOpenShortcut(9)),
            KeyCode::Char('0') => Some(AppCommand::FolderOpenShortcut(0)),
            KeyCode::Char('?') => Some(AppCommand::Help),
            _ => None,
        };
    }
    if screen == Screen::FolderMessages {
        return match key.code {
            KeyCode::Char('q') => Some(AppCommand::Quit),
            KeyCode::Esc => Some(AppCommand::Back),
            KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
            KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
            KeyCode::Enter => Some(AppCommand::Open),
            KeyCode::Char('f' | 'F') => Some(AppCommand::Folders),
            KeyCode::Char('/') => Some(AppCommand::SearchStart),
            KeyCode::Char('5') => Some(AppCommand::FolderOpenShortcut(5)),
            KeyCode::Char('6') => Some(AppCommand::FolderOpenShortcut(6)),
            KeyCode::Char('7') => Some(AppCommand::FolderOpenShortcut(7)),
            KeyCode::Char('8') => Some(AppCommand::FolderOpenShortcut(8)),
            KeyCode::Char('9') => Some(AppCommand::FolderOpenShortcut(9)),
            KeyCode::Char('0') => Some(AppCommand::FolderOpenShortcut(0)),
            KeyCode::Char('?') => Some(AppCommand::Help),
            _ => None,
        };
    }
    if screen == Screen::Reader {
        let command = match key.code {
            KeyCode::Tab => Some(AppCommand::ReaderNextLink),
            KeyCode::BackTab => Some(AppCommand::ReaderPreviousLink),
            KeyCode::Enter => Some(AppCommand::ReaderOpenLink),
            KeyCode::Up => Some(AppCommand::ReaderPrevious),
            KeyCode::Down => Some(AppCommand::ReaderNext),
            KeyCode::Char('k') => Some(AppCommand::ReaderScrollUp),
            KeyCode::Char('j') => Some(AppCommand::ReaderScrollDown),
            KeyCode::PageUp => Some(AppCommand::ReaderPageUp),
            KeyCode::PageDown | KeyCode::Char(' ') => Some(AppCommand::ReaderPageDown),
            KeyCode::Home | KeyCode::Char('g') => Some(AppCommand::ReaderScrollTop),
            KeyCode::End | KeyCode::Char('G') => Some(AppCommand::ReaderScrollBottom),
            KeyCode::Char('r') => Some(AppCommand::Reply),
            KeyCode::Char('R') => Some(AppCommand::ReplyAll),
            _ => None,
        };
        if command.is_some() {
            return command;
        }
    }

    match key.code {
        KeyCode::Char('q') => Some(AppCommand::Quit),
        KeyCode::Esc => Some(AppCommand::Back),
        KeyCode::Down | KeyCode::Char('j') => Some(AppCommand::Next),
        KeyCode::Up | KeyCode::Char('k') => Some(AppCommand::Previous),
        KeyCode::Enter => Some(AppCommand::Open),
        KeyCode::Char('1') => Some(AppCommand::WarmAction),
        KeyCode::Char('2') => Some(AppCommand::WarmFyi),
        KeyCode::Char('3') => Some(AppCommand::Cold),
        KeyCode::Char('4') => Some(AppCommand::Spam),
        KeyCode::Char('5') => Some(AppCommand::FolderOpenShortcut(5)),
        KeyCode::Char('6') => Some(AppCommand::FolderOpenShortcut(6)),
        KeyCode::Char('7') => Some(AppCommand::FolderOpenShortcut(7)),
        KeyCode::Char('8') => Some(AppCommand::FolderOpenShortcut(8)),
        KeyCode::Char('9') => Some(AppCommand::FolderOpenShortcut(9)),
        KeyCode::Char('0') => Some(AppCommand::FolderOpenShortcut(0)),
        KeyCode::Char('f' | 'F') => Some(AppCommand::Folders),
        KeyCode::Char('l' | 'L') => Some(AppCommand::Waiting),
        KeyCode::Char('z' | 'Z') => Some(AppCommand::Snoozed),
        KeyCode::Char('D') => Some(AppCommand::Done),
        KeyCode::Char('c' | 'C') => Some(AppCommand::Contacts),
        KeyCode::Char('A') => Some(AppCommand::Accounts),
        KeyCode::Char('?') => Some(AppCommand::Help),
        KeyCode::Char('d') => Some(AppCommand::MarkDone),
        KeyCode::Char('w') => Some(AppCommand::MarkWaiting),
        KeyCode::Char('s') => Some(AppCommand::SnoozeOneDay),
        KeyCode::Char('/') => Some(AppCommand::SearchStart),
        KeyCode::Char('a') => Some(AppCommand::MakeActionableOnce),
        KeyCode::Char('>') => Some(AppCommand::MoveToFyi),
        KeyCode::Char('<') => Some(AppCommand::MoveToAction),
        KeyCode::Char('M') => Some(AppCommand::PreviewSimilarFyi),
        KeyCode::Char('O') => Some(AppCommand::RestrictedOpen),
        KeyCode::Char('y') if screen == Screen::Onboarding => Some(AppCommand::OnboardingAccept),
        KeyCode::Char('n') if screen == Screen::Onboarding => Some(AppCommand::OnboardingDismiss),
        KeyCode::Char('e') if screen == Screen::Onboarding => Some(AppCommand::OnboardingEdit),
        _ => None,
    }
}

fn open_default_browser(url: &str) -> io::Result<()> {
    let mut command = default_browser_command(url);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(target_os = "windows")]
fn default_browser_command(url: &str) -> Command {
    let mut command = Command::new("explorer.exe");
    command.arg(url);
    command
}

#[cfg(target_os = "macos")]
fn default_browser_command(url: &str) -> Command {
    let mut command = Command::new("open");
    command.arg(url);
    command
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_browser_command(url: &str) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url);
    command
}

#[cfg(not(any(unix, target_os = "windows")))]
fn default_browser_command(_url: &str) -> Command {
    Command::new("unsupported-default-browser-platform")
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
    use lizard_mail_backend::WorkflowView;

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

    #[test]
    fn reader_keeps_message_navigation_separate_from_body_scrolling() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);

        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Up)),
            Some(AppCommand::ReaderPrevious)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Down)),
            Some(AppCommand::ReaderNext)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('k'))),
            Some(AppCommand::ReaderScrollUp)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('j'))),
            Some(AppCommand::ReaderScrollDown)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::PageDown)),
            Some(AppCommand::ReaderPageDown)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('>'))),
            Some(AppCommand::MoveToFyi)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('<'))),
            Some(AppCommand::MoveToAction)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('r'))),
            Some(AppCommand::Reply)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Char('R'))),
            Some(AppCommand::ReplyAll)
        ));
    }

    #[test]
    fn compose_has_explicit_save_and_send_shortcuts() {
        assert!(matches!(
            command_for(
                Screen::Compose,
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
            ),
            Some(AppCommand::ComposeSave)
        ));
        assert!(matches!(
            command_for(
                Screen::Compose,
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)
            ),
            Some(AppCommand::ComposeSend)
        ));
        assert!(matches!(
            command_for(
                Screen::Compose,
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)
            ),
            Some(AppCommand::Back)
        ));
    }

    #[test]
    fn numbered_inbox_shortcuts_follow_the_visible_workflow_order() {
        let key = |character| KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE);

        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('1')),
            Some(AppCommand::WarmAction)
        ));
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('2')),
            Some(AppCommand::WarmFyi)
        ));
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('3')),
            Some(AppCommand::Cold)
        ));
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('4')),
            Some(AppCommand::Spam)
        ));
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('f')),
            Some(AppCommand::Folders)
        ));
    }

    #[test]
    fn folder_binding_is_an_explicit_two_key_operation() {
        let key = |character| KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE);

        assert!(matches!(
            command_for(Screen::Folders, key('b')),
            Some(AppCommand::FolderBeginBind)
        ));
        assert!(matches!(
            command_for(Screen::FolderBind, key('7')),
            Some(AppCommand::FolderBind(7))
        ));
        assert!(matches!(
            command_for(Screen::Folders, key('7')),
            Some(AppCommand::FolderOpenShortcut(7))
        ));
        assert!(matches!(
            command_for(Screen::Folders, key('r')),
            Some(AppCommand::FolderRename)
        ));
    }

    #[test]
    fn slash_opens_search_without_displacing_snooze() {
        let key = |character| KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE);
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('/')),
            Some(AppCommand::SearchStart)
        ));
        assert!(matches!(
            command_for(Screen::Queue(WorkflowView::WarmAction), key('s')),
            Some(AppCommand::SnoozeOneDay)
        ));
        assert!(matches!(
            command_for(
                Screen::SearchInput,
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
            ),
            Some(AppCommand::SearchSubmit)
        ));
    }

    #[test]
    fn reader_reserves_tab_and_enter_for_trusted_link_navigation() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Tab)),
            Some(AppCommand::ReaderNextLink)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::BackTab)),
            Some(AppCommand::ReaderPreviousLink)
        ));
        assert!(matches!(
            command_for(Screen::Reader, key(KeyCode::Enter)),
            Some(AppCommand::ReaderOpenLink)
        ));
    }
}
