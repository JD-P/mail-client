use crate::app::{
    AccountAuthentication, AccountField, ComposeField, ContactField, FolderEditorMode, MailApp,
    Screen,
};
use crate::{LinkKind, LinkReference, RenderedPage};
use chrono::{DateTime, Datelike, Local, Utc};
use lizard_mail_backend::{
    AuthenticationMethodKind, AuthenticationMethodResult, AuthenticationResultsTrust,
    DkimAuthenticationStatus, DkimSignatureStatus, FindingSeverity, FindingTargetKind, FolderKind,
    HeuristicFinding, ImapSecurity, InboxClass, Message, MessageContentAvailability, MessageLink,
    MessageSummary, OpenPgpBindingState, OpenPgpEncryptionStatus, OpenPgpSignatureStatus,
    RelationshipKind, RemoteContentPolicy, ThreadWorkStatus, WarmRoute, WorkflowView,
};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use ratatui::Frame;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use unicode_width::UnicodeWidthChar;
use url::Url;

const WARM: Color = Color::Rgb(198, 48, 67);
const FYI_HINT: Color = Color::Rgb(222, 143, 43);
const COLD: Color = Color::Rgb(57, 132, 219);
const SPAM: Color = Color::Rgb(212, 169, 50);
const DANGER: Color = Color::Rgb(235, 65, 83);
const LINK_CONTEXT_WORD_RADIUS: usize = 6;
const LINK_CONTEXT_MAX_CHARS: usize = 240;

pub fn draw(frame: &mut Frame<'_>, app: &MailApp) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());
    draw_header(frame, app, areas[0]);
    match app.screen {
        Screen::Accounts => draw_accounts(frame, app, areas[1]),
        Screen::AccountEdit => draw_account_editor(frame, app, areas[1]),
        Screen::AccountDeleteConfirm => draw_account_delete_confirm(frame, app, areas[1]),
        Screen::Onboarding => draw_onboarding(frame, app, areas[1]),
        Screen::OnboardingEdit => draw_onboarding_edit(frame, app, areas[1]),
        Screen::SimilarityPreview => draw_similarity_preview(frame, app, areas[1]),
        Screen::Queue(_) => draw_queue(frame, app, areas[1]),
        Screen::Reader => draw_reader(frame, app, areas[1]),
        Screen::Compose => draw_compose(frame, app, areas[1]),
        Screen::SearchInput => draw_search_input(frame, app, areas[1]),
        Screen::SearchResults => draw_search_results(frame, app, areas[1]),
        Screen::Folders | Screen::FolderBind => draw_folders(frame, app, areas[1]),
        Screen::FolderMessages => draw_folder_messages(frame, app, areas[1]),
        Screen::FolderEdit => draw_folder_editor(frame, app, areas[1]),
        Screen::FolderDeleteConfirm => draw_folder_delete_confirm(frame, app, areas[1]),
        Screen::Contacts => draw_contacts(frame, app, areas[1]),
        Screen::ContactEdit => draw_contact_editor(frame, app, areas[1]),
        Screen::Help => draw_help(frame, areas[1]),
    }
    draw_footer(frame, app, areas[2]);
}

fn draw_header(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let accent = accent(app);
    let title = format!(" LIZARD MAIL · {} ", screen_title(app));
    let navigation = header_navigation(app);
    frame.render_widget(
        Paragraph::new(navigation).block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(accent)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(accent)),
        ),
        area,
    );
}

fn primary_navigation() -> Line<'static> {
    Line::from(vec![
        Span::styled("1", Style::default().fg(WARM).add_modifier(Modifier::BOLD)),
        Span::raw(" Action  "),
        Span::styled(
            "2",
            Style::default().fg(FYI_HINT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" FYI  "),
        Span::styled("3", Style::default().fg(COLD).add_modifier(Modifier::BOLD)),
        Span::raw(" Cold  "),
        Span::styled("4", Style::default().fg(SPAM).add_modifier(Modifier::BOLD)),
        Span::raw(" Spam  F Folders  L Later  / Search  C Contacts  A Accounts  ? Help"),
    ])
}

fn header_navigation(app: &MailApp) -> Text<'static> {
    let mut shortcuts = Vec::new();
    for digit in [5, 6, 7, 8, 9, 0] {
        if !shortcuts.is_empty() {
            shortcuts.push(Span::raw("  "));
        }
        shortcuts.push(Span::styled(
            digit.to_string(),
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ));
        shortcuts.push(Span::raw(" "));
        shortcuts.push(Span::raw(folder_shortcut_label(app, digit)));
    }
    Text::from(vec![primary_navigation(), Line::from(shortcuts)])
}

fn folder_shortcut_label(app: &MailApp, digit: u8) -> String {
    app.folder_shortcuts
        .get(&digit)
        .and_then(|id| app.folders.iter().find(|folder| folder.id == *id))
        .map_or_else(|| "—".into(), |folder| truncate_columns(&folder.name, 8))
}

fn truncate_columns(value: &str, maximum: usize) -> String {
    let value = safe_single_line_text(value);
    let width = value
        .chars()
        .map(|character| character.width().unwrap_or(0))
        .sum::<usize>();
    if width <= maximum {
        return value;
    }
    let mut result = String::new();
    let mut used = 0usize;
    for character in value.chars() {
        let character_width = character.width().unwrap_or(0);
        if used.saturating_add(character_width) > maximum {
            break;
        }
        used = used.saturating_add(character_width);
        result.push(character);
    }
    result.push('…');
    result
}

fn draw_accounts(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    if app.accounts.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No mail account is configured. Press N to connect an IMAP account. Credentials are stored in the operating-system credential store when available and otherwise in Lizard's encrypted profile store.",
            )
            .block(Block::default().title("Accounts").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let items = app
        .accounts
        .iter()
        .map(|account| {
            let settings = account.imap.as_ref();
            let endpoint = settings.map_or_else(
                || "not configured".to_owned(),
                |settings| {
                    format!(
                        "{} · {}:{} · {}",
                        safe_single_line_text(&settings.username),
                        safe_single_line_text(&settings.host),
                        settings.port,
                        match settings.security {
                            ImapSecurity::ImplicitTls => "TLS",
                            ImapSecurity::StartTls => "STARTTLS",
                        }
                    )
                },
            );
            let mut lines = vec![Line::from(vec![
                Span::styled(
                    safe_single_line_text(&account.name),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {endpoint}")),
            ])];
            if app.account_syncing(account.id) {
                lines.push(Line::styled(
                    "  Synchronizing in isolated worker…",
                    Style::default().fg(COLD),
                ));
            } else if let Some(state) = app.account_states.get(&account.id) {
                let mut detail = format!("  Sync: {:?}", state.status);
                if let Some(success) = state.last_success_at {
                    detail.push_str(&format!(" · last success {}", display_timestamp(success)));
                } else if state.last_attempt_at.is_none() {
                    detail.push_str(" · never synchronized");
                }
                if let Some(error) = &state.last_error {
                    detail.push_str(&format!(" · {}", safe_single_line_text(error)));
                }
                lines.push(Line::raw(detail));
            }
            lines.push(Line::raw(
                if let Some(smtp) = app.smtp_accounts.get(&account.id) {
                    format!(
                        "  Sending: {}:{} · {:?}",
                        safe_single_line_text(&smtp.settings.host),
                        smtp.settings.port,
                        smtp.settings.security
                    )
                } else {
                    "  Sending: not configured (receive only)".into()
                },
            ));
            ListItem::new(Text::from(lines))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title("Accounts").borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::Gray)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn display_timestamp(value: i64) -> String {
    DateTime::<Utc>::from_timestamp(value, 0)
        .map(|value| value.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "invalid time".into())
}

fn draw_account_editor(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(editor) = &app.account_editor else {
        frame.render_widget(Paragraph::new("No account is being edited"), area);
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(7)])
        .split(area);
    let introduction = if editor.account_id.is_none() {
        "Connect an existing mailbox. IMAP receives mail; optional SMTP settings send replies using the same username and credential. Lizard only permits encrypted TLS or STARTTLS connections."
    } else {
        "Update receiving and sending. Leave the secret unchanged to retain the stored credential. Leave SMTP server blank for a receive-only account."
    };
    frame.render_widget(
        Paragraph::new(introduction)
            .block(
                Block::default()
                    .title(if editor.account_id.is_none() {
                        "Connect an IMAP account"
                    } else {
                        "Edit IMAP account"
                    })
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    let fields = vec![
        ("Account name", safe_single_line_text(&editor.name)),
        ("Email / username", safe_single_line_text(&editor.username)),
        ("IMAP server", safe_single_line_text(&editor.host)),
        ("IMAP port", safe_single_line_text(&editor.port)),
        (
            "Transport security",
            match editor.security {
                ImapSecurity::ImplicitTls => "TLS from connection start (recommended)",
                ImapSecurity::StartTls => "STARTTLS upgrade",
            }
            .into(),
        ),
        (
            "Authentication",
            match editor.authentication {
                AccountAuthentication::Password => "Password or app password",
                AccountAuthentication::OAuthAccessToken => {
                    "OAuth access token (advanced; automatic refresh is not wired yet)"
                }
            }
            .into(),
        ),
        (
            match editor.authentication {
                AccountAuthentication::Password => "Password",
                AccountAuthentication::OAuthAccessToken => "OAuth access token",
            },
            editor.secret_label().into(),
        ),
        (
            "Trusted authserv-ids (advanced)",
            if editor.trusted_authserv_ids.trim().is_empty() {
                "None — provider Authentication-Results are not trusted".into()
            } else {
                safe_single_line_text(&editor.trusted_authserv_ids)
            },
        ),
        (
            "SMTP server (optional)",
            if editor.smtp_host.trim().is_empty() {
                "Not configured — replies remain as drafts".into()
            } else {
                safe_single_line_text(&editor.smtp_host)
            },
        ),
        ("SMTP port", safe_single_line_text(&editor.smtp_port)),
        (
            "SMTP transport security",
            match editor.smtp_security {
                lizard_mail_backend::SmtpSecurity::ImplicitTls => {
                    "TLS from connection start (usually port 465)"
                }
                lizard_mail_backend::SmtpSecurity::StartTls => {
                    "STARTTLS upgrade (usually port 587)"
                }
            }
            .into(),
        ),
    ];
    let items = fields
        .into_iter()
        .map(|(label, value)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{label}: "),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(value),
            ]))
        })
        .collect::<Vec<_>>();
    let selected = match editor.selected_field {
        AccountField::Name => 0,
        AccountField::Username => 1,
        AccountField::Host => 2,
        AccountField::Port => 3,
        AccountField::Security => 4,
        AccountField::Authentication => 5,
        AccountField::Secret => 6,
        AccountField::AuthservIds => 7,
        AccountField::SmtpHost => 8,
        AccountField::SmtpPort => 9,
        AccountField::SmtpSecurity => 10,
    };
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title("Connection settings")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(COLD).fg(Color::Black))
            .highlight_symbol("› "),
        chunks[1],
        &mut state,
    );
}

fn draw_account_delete_confirm(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let account = app
        .pending_account_delete
        .and_then(|id| app.accounts.iter().find(|account| account.id == id));
    let Some(account) = account else {
        frame.render_widget(Paragraph::new("No account selected for removal"), area);
        return;
    };
    let text = Text::from(vec![
        Line::styled(
            "REMOVE THIS ACCOUNT FROM LIZARD?",
            Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::raw(format!("Account: {}", safe_single_line_text(&account.name))),
        Line::raw(""),
        Line::raw(
            "This removes the account, its local messages and folders, cached bodies, sync state, and Lizard-managed credentials from this profile.",
        ),
        Line::raw("Mail stored on the remote server is not deleted."),
        Line::raw(""),
        Line::styled("Press Y to remove, or N/Esc to cancel.", Style::default().fg(DANGER)),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title("Confirm account removal")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(DANGER)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_queue(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let workflow = match app.screen {
        Screen::Queue(workflow) => workflow,
        _ => return,
    };
    let queue_area = draw_workflow_banner(frame, workflow, area);
    if app.threads.is_empty() {
        let message = match workflow {
            WorkflowView::WarmAction => "No active obligations. Warm inbox zero.",
            WorkflowView::WarmFyi => "No known-sender FYI mail is waiting.",
            WorkflowView::ColdReview => {
                "No unknown senders are waiting for review. Cold mail never becomes an obligation by default."
            }
            WorkflowView::SpamQuarantine => "Spam quarantine is empty.",
            WorkflowView::Waiting => "You are not waiting on any conversations.",
            WorkflowView::Snoozed => "No conversations are snoozed.",
            WorkflowView::Done => "No completed conversations yet.",
        };
        frame.render_widget(
            Paragraph::new(message)
                .block(Block::default().title("Queue").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            queue_area,
        );
        return;
    }
    let items = app
        .threads
        .iter()
        .map(|thread| {
            let unread = if thread.unread_count > 0 { "●" } else { " " };
            let subject = thread.subject.as_deref().unwrap_or("(no subject)");
            let subject = safe_single_line_text(subject);
            let state = match thread.work_state.status {
                ThreadWorkStatus::Active => "",
                ThreadWorkStatus::Waiting => " [waiting]",
                ThreadWorkStatus::Snoozed => " [snoozed]",
                ThreadWorkStatus::Done => " [done]",
            };
            let received = format_queue_timestamp(thread.latest_received_at);
            let address = thread.latest_from_address.as_deref();
            if let Some(contact) = address.and_then(|address| app.contact_name(address)) {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{unread} "), Style::default().fg(accent(app))),
                    Span::styled(
                        format!("{received}  "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        safe_single_line_text(contact),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("  {subject}{state}")),
                ]))
            } else {
                // Unknown identities get the entire author field. The address
                // is wrapped, never truncated, so padding and deceptive domain
                // structure remain visible instead of becoming camouflage.
                let width = usize::from(queue_area.width.saturating_sub(6).max(1));
                let address = address.unwrap_or("ambiguous or missing From address");
                let mut lines = wrap_untrusted_identity(address, width)
                    .into_iter()
                    .enumerate()
                    .map(|(index, segment)| {
                        Line::from(vec![
                            Span::styled(
                                if index == 0 {
                                    format!("{unread} ")
                                } else {
                                    "  ".to_owned()
                                },
                                Style::default().fg(accent(app)),
                            ),
                            Span::styled(segment, Style::default().add_modifier(Modifier::BOLD)),
                        ])
                    })
                    .collect::<Vec<_>>();
                if let Some(name) = thread
                    .latest_from_name
                    .as_deref()
                    .filter(|name| !name.trim().is_empty())
                {
                    for claim in wrap_untrusted_identity(
                        &format!("claims to be {}", safe_single_line_text(name)),
                        width,
                    ) {
                        lines.push(Line::raw(format!("  {claim}")));
                    }
                }
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {received}  "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(format!("{subject}{state}")),
                ]));
                ListItem::new(Text::from(lines))
            }
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    let title = match workflow {
        WorkflowView::WarmAction => format!("ACTION · {} conversations", app.threads.len()),
        WorkflowView::WarmFyi => format!("FYI · {} conversations", app.threads.len()),
        _ => format!("{} conversations", app.threads.len()),
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(accent(app))
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› "),
        queue_area,
        &mut state,
    );
}

fn draw_workflow_banner(frame: &mut Frame<'_>, workflow: WorkflowView, area: Rect) -> Rect {
    let (label, explanation, label_style) = match workflow {
        WorkflowView::WarmAction => (
            "ACTION",
            "People you know may be asking something of you · reply, schedule, snooze, or mark done",
            Style::default()
                .bg(WARM)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        WorkflowView::WarmFyi => (
            "FYI",
            "Informational mail from people you know · no response is expected",
            Style::default()
                .fg(FYI_HINT)
                .add_modifier(Modifier::BOLD),
        ),
        _ => return area,
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {label} "), label_style),
            Span::raw(format!("  {explanation}")),
        ]))
        .block(
            Block::default()
                .title("Warm workflow")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(WARM)),
        ),
        chunks[0],
    );
    chunks[1]
}

fn draw_compose(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(editor) = &app.compose_editor else {
        frame.render_widget(Paragraph::new("No reply draft is open"), area);
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);
    draw_compose_field(
        frame,
        chunks[0],
        "To — verify this address before sending",
        &editor.to,
        editor.selected_field == ComposeField::To,
    );
    draw_compose_field(
        frame,
        chunks[1],
        "Cc",
        &editor.cc,
        editor.selected_field == ComposeField::Cc,
    );
    draw_compose_field(
        frame,
        chunks[2],
        "Subject",
        &editor.subject,
        editor.selected_field == ComposeField::Subject,
    );
    draw_compose_field(
        frame,
        chunks[3],
        "Plain-text reply",
        &editor.body,
        editor.selected_field == ComposeField::Body,
    );
}

fn draw_search_input(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let query = app
        .search_editor
        .as_ref()
        .map(|editor| editor.query.as_str())
        .unwrap_or_default();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(5)])
        .split(area);
    frame.render_widget(
        Paragraph::new(safe_single_line_text(query))
            .block(
                Block::default()
                    .title("Search all locally indexed mail")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Gray)),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(
                "Words search message bodies; quote multiword phrases.",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::raw("Text: subject: from: to: cc: bcc: deliveredto: filename: list:"),
            Line::raw("State: has:attachment · is:read/unread/starred/warm/cold/spam"),
            Line::raw("Dates: after:/newer:YYYY-MM-DD · before:/older:YYYY-MM-DD"),
            Line::raw("Age: newer_than:/older_than:7d, 2w, 3m, or 1y"),
            Line::raw("Size: larger:10mb · smaller:500k · size:1024"),
            Line::raw("Location: in: or label: folder · account: account"),
            Line::raw("IDs: message-id: or rfc822msgid:"),
            Line::raw("Logic: adjacent terms mean AND · uppercase AND/OR · -negation · (groups)"),
            Line::raw("Examples:"),
            Line::raw("  from:alice@example.com subject:\"project update\""),
            Line::raw("  has:attachment after:2026-01-01"),
            Line::raw("  (invoice OR receipt) -from:marketing@example.com"),
            Line::raw(""),
            Line::raw(
                "Search is local. Results may be incomplete while mail is still downloading.",
            ),
        ]))
        .block(Block::default().title("Query help").borders(Borders::ALL))
        .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn draw_search_results(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    if app.search_results.is_empty() {
        frame.render_widget(
            Paragraph::new(format!(
                "No messages matched {:?}. Press / to edit the query.",
                safe_single_line_text(&app.search_query)
            ))
            .block(
                Block::default()
                    .title("Search results")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let title = format!(
        "Search results · {}{} · {:?}",
        app.search_results.len(),
        if app.search_has_more { "+" } else { "" },
        safe_single_line_text(&app.search_query)
    );
    draw_message_results(frame, app, area, &app.search_results, title);
}

fn draw_message_results(
    frame: &mut Frame<'_>,
    app: &MailApp,
    area: Rect,
    messages: &[MessageSummary],
    title: String,
) {
    let items = messages
        .iter()
        .map(|message| {
            let (class_label, class_color) = search_result_identity(message.inbox_class);
            let address = message.from_address.as_deref().unwrap_or("unknown sender");
            let sender = app.contact_name(address).map_or_else(
                || safe_single_line_text(address),
                |name| {
                    format!(
                        "{} <{}>",
                        safe_single_line_text(name),
                        safe_single_line_text(address)
                    )
                },
            );
            ListItem::new(Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        format!("[{class_label}] "),
                        Style::default()
                            .fg(class_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        safe_single_line_text(message.subject.as_deref().unwrap_or("(no subject)")),
                        Style::default()
                            .fg(class_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("  {}", format_queue_timestamp(message.received_at))),
                ]),
                Line::raw(format!("  From: {sender}")),
            ]))
            .style(Style::default().fg(class_color))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(45, 45, 45))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn draw_folders(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    if app.folders.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No folders are available yet. Press n to create one, or synchronize an account to discover its server folders.",
            )
            .block(Block::default().title("Folders").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let items = app
        .folders
        .iter()
        .map(|folder| {
            let account = folder
                .account_id
                .and_then(|id| app.accounts.iter().find(|account| account.id == id))
                .map(|account| safe_single_line_text(&account.name))
                .unwrap_or_else(|| "Local".into());
            let shortcut = app
                .folder_shortcuts
                .iter()
                .find_map(|(digit, id)| (*id == folder.id).then_some(*digit))
                .map_or_else(String::new, |digit| format!(" [{digit}]"));
            let count = app
                .folder_states
                .get(&folder.id)
                .and_then(|state| state.exists_count)
                .map_or_else(String::new, |count| format!(" · {count} messages"));
            let unavailable = app
                .folder_states
                .get(&folder.id)
                .is_some_and(|state| !state.selectable || !state.remote_present);
            let suffix = if unavailable { " · unavailable" } else { "" };
            ListItem::new(Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        safe_single_line_text(&folder.name),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(shortcut, Style::default().fg(Color::Gray)),
                ]),
                Line::styled(
                    format!("  {account}{count}{suffix}"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let title = if app.screen == Screen::FolderBind {
        "Bind selected folder — press 5, 6, 7, 8, 9, or 0"
    } else {
        "Folders"
    };
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::Gray)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn draw_folder_messages(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let folder_name = app
        .current_folder_id
        .and_then(|id| app.folders.iter().find(|folder| folder.id == id))
        .map(|folder| safe_single_line_text(&folder.name))
        .unwrap_or_else(|| "Folder".into());
    if app.folder_messages.is_empty() {
        frame.render_widget(
            Paragraph::new("This folder contains no locally known messages.")
                .block(Block::default().title(folder_name).borders(Borders::ALL)),
            area,
        );
        return;
    }
    let title = format!(
        "{} · {}{} messages",
        folder_name,
        app.folder_messages.len(),
        if app.folder_messages_has_more {
            "+"
        } else {
            ""
        }
    );
    draw_message_results(frame, app, area, &app.folder_messages, title);
}

fn draw_folder_editor(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(editor) = &app.folder_editor else {
        frame.render_widget(Paragraph::new("No folder is being edited"), area);
        return;
    };
    let action = match editor.mode {
        FolderEditorMode::Create => "Create folder",
        FolderEditorMode::Rename => "Rename folder",
    };
    let location = match (editor.kind, editor.account_id) {
        (FolderKind::Local, _) => "Local folder".into(),
        (FolderKind::Remote, Some(account_id)) => app
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .map_or_else(
                || "Remote IMAP folder".into(),
                |account| format!("Remote folder on {}", safe_single_line_text(&account.name)),
            ),
        (FolderKind::Remote, None) => "Remote IMAP folder".into(),
    };
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(location, Style::default().fg(Color::DarkGray)),
            Line::raw(""),
            Line::styled(
                safe_single_line_text(&editor.name),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(
            Block::default()
                .title(action)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Gray)),
        )
        .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_folder_delete_confirm(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(editor) = &app.folder_delete_editor else {
        frame.render_widget(Paragraph::new("No folder is selected for deletion"), area);
        return;
    };
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(
                "This deletes the folder. Remote folders are also deleted from the IMAP server.",
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            ),
            Line::raw("Messages may remain wherever another server folder still contains them."),
            Line::raw(""),
            Line::raw(format!(
                "Type {} to confirm:",
                safe_single_line_text(&editor.expected_name)
            )),
            Line::styled(
                safe_single_line_text(&editor.typed_name),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(
            Block::default()
                .title("Delete folder")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DANGER)),
        )
        .wrap(Wrap { trim: false }),
        area,
    );
}

fn search_result_identity(class: InboxClass) -> (&'static str, Color) {
    match class {
        InboxClass::Warm => ("WARM", WARM),
        InboxClass::Cold => ("COLD", COLD),
        InboxClass::Spam => ("SPAM", SPAM),
    }
}

fn draw_compose_field(frame: &mut Frame<'_>, area: Rect, label: &str, value: &str, selected: bool) {
    let title = if selected {
        format!("› {label}")
    } else {
        label.to_owned()
    };
    frame.render_widget(
        Paragraph::new(safe_text(value))
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if selected {
                        WARM
                    } else {
                        Color::DarkGray
                    })),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_reader(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    app.update_reader_link_rows(Vec::new());
    let area = if app.security_override {
        draw_restricted_caution_frame(frame, area);
        if area.width > 2 && area.height > 2 {
            area.inner(Margin {
                horizontal: 1,
                vertical: 1,
            })
        } else {
            area
        }
    } else {
        area
    };
    let Some(thread) = &app.current_thread else {
        let message = app
            .reader_load_status()
            .or(app.status.as_deref())
            .unwrap_or("No conversation selected");
        frame.render_widget(
            Paragraph::new(message)
                .block(Block::default().title("Conversation").borders(Borders::ALL)),
            area,
        );
        return;
    };
    let Some(message) = thread.messages.last() else {
        frame.render_widget(Paragraph::new("Conversation contains no messages"), area);
        return;
    };
    if app.reader_is_blocked() {
        let severity = highest_active_security_severity(message);
        let (level, warning_style) = finding_visual_style(severity);
        let mut lines = vec![
            Line::styled(
                format!("{level} SECURITY WARNING — MESSAGE BODY BLOCKED"),
                warning_style,
            ),
            Line::raw(""),
            Line::raw(format!(
                "Received: {}",
                format_full_timestamp(message.summary.received_at)
            )),
        ];
        if let Some(sent_at) = message.summary.sent_at {
            lines.push(Line::raw(format!(
                "Message claims sent: {}",
                format_full_timestamp(sent_at)
            )));
        }
        lines.extend([
            Line::raw(""),
            Line::raw(
                "The client found security evidence that must not be hidden in a detail pane.",
            ),
            Line::raw(""),
        ]);
        append_finding_lines(
            &mut lines,
            message,
            12,
            usize::from(area.width.saturating_sub(4).max(1)),
            "in the restricted message",
        );
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(5)])
            .split(area);
        draw_scrolling_panel(
            frame,
            app,
            sections[0],
            "Intrusive security interruption",
            lines,
            security_color(severity),
        );
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled(
                    "[Esc] Go back (recommended)    [O] Read restricted",
                    warning_style,
                ),
                Line::raw("Restricted view keeps links and remote content disabled."),
                Line::raw("Exact link warnings appear immediately above each affected link."),
            ]))
            .block(
                Block::default()
                    .title("Choose how to continue")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(security_color(severity))),
            ),
            sections[1],
        );
        return;
    }

    let inner_width = usize::from(area.width.saturating_sub(4).max(1));
    let mut header_lines = sender_identity_lines(app, message, inner_width);
    header_lines.push(Line::from(vec![
        Span::styled("Subject: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(safe_single_line_text(
            message.summary.subject.as_deref().unwrap_or("(no subject)"),
        )),
    ]));
    append_labeled_lines(
        &mut header_lines,
        "Received: ",
        &format_full_timestamp(message.summary.received_at),
        inner_width,
    );
    if let Some(sent_at) = message.summary.sent_at {
        append_labeled_lines(
            &mut header_lines,
            "Message claims sent: ",
            &format_full_timestamp(sent_at),
            inner_width,
        );
    }
    append_labeled_lines(
        &mut header_lines,
        "Domain signature: ",
        &dkim_summary(message),
        inner_width,
    );
    if let Some(delivery) = trusted_delivery_summary(message) {
        append_labeled_lines(
            &mut header_lines,
            "Delivery evidence: ",
            &delivery,
            inner_width,
        );
    }
    if let Some(openpgp) = openpgp_summary(app, message) {
        append_labeled_lines(&mut header_lines, "OpenPGP: ", &openpgp, inner_width);
    }
    header_lines.push(Line::from(vec![
        Span::styled("Work: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("{:?}", thread.summary.work_state.status)),
    ]));
    append_finding_lines(&mut header_lines, message, 8, inner_width, "below");

    let header_height = u16::try_from(header_lines.len().saturating_add(2))
        .unwrap_or(u16::MAX)
        .min(area.height);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(header_height), Constraint::Min(0)])
        .split(area);
    frame.render_widget(
        Paragraph::new(Text::from(header_lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(identity_block_title(message.summary.inbox_class))
                .border_style(Style::default().fg(accent(app))),
        ),
        chunks[0],
    );

    if message.summary.content_availability != MessageContentAvailability::Complete {
        frame.render_widget(
            Paragraph::new(
                app.reader_load_status()
                    .or(app.status.as_deref())
                    .unwrap_or("Message content and identity evidence are unavailable"),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Message · not yet available"),
            )
            .wrap(Wrap { trim: false }),
            chunks[1],
        );
        return;
    }

    let mut link_rows = Vec::new();
    let selected_link = app.reader_selected_link();
    let (title, body_lines) = if let Some(page) = app.reader_html() {
        let title = if app.security_override {
            "Message · RESTRICTED VIEW · links made non-clickable"
        } else {
            "Message"
        };
        (
            title,
            annotated_rendered_message_lines(
                page,
                message,
                inner_width,
                app.security_override,
                selected_link,
                &mut link_rows,
            ),
        )
    } else {
        let title = if app.security_override && message.body_html.is_some() {
            "Message · RESTRICTED VIEW · safe plain-text fallback"
        } else if app.security_override {
            "Message · RESTRICTED VIEW · warnings remain active"
        } else if message.body_html.is_some() {
            "Message · safe plain-text fallback"
        } else {
            "Message"
        };
        let width = usize::from(chunks[1].width.saturating_sub(2).max(1));
        let mut lines = wrap_message_body(&message.body_text, width);
        if app.security_override {
            defang_sender_lines(&mut lines);
        }
        append_backend_link_section(
            &mut lines,
            message,
            width,
            app.security_override,
            selected_link,
            &mut link_rows,
        );
        (title, lines)
    };
    app.update_reader_link_rows(link_rows);
    let border_color = accent(app);
    draw_scrolling_panel(frame, app, chunks[1], title, body_lines, border_color);
}

fn draw_restricted_caution_frame(frame: &mut Frame<'_>, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let caution_style = |index: usize| {
        if (index / 2).is_multiple_of(2) {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD)
        }
    };
    let horizontal = |width: u16| {
        Line::from(
            (0..usize::from(width))
                .map(|index| Span::styled("╱", caution_style(index)))
                .collect::<Vec<_>>(),
        )
    };
    frame.render_widget(
        Paragraph::new(horizontal(area.width)),
        Rect::new(area.x, area.y, area.width, 1),
    );
    if area.height > 1 {
        frame.render_widget(
            Paragraph::new(horizontal(area.width)),
            Rect::new(
                area.x,
                area.y.saturating_add(area.height - 1),
                area.width,
                1,
            ),
        );
    }
    if area.height > 2 {
        let vertical = |offset: usize, character: &'static str| {
            Text::from(
                (0..usize::from(area.height - 2))
                    .map(|row| Line::styled(character, caution_style(row + offset)))
                    .collect::<Vec<_>>(),
            )
        };
        frame.render_widget(
            Paragraph::new(vertical(0, "▌")),
            Rect::new(area.x, area.y + 1, 1, area.height - 2),
        );
        if area.width > 1 {
            frame.render_widget(
                Paragraph::new(vertical(1, "▐")),
                Rect::new(area.x + area.width - 1, area.y + 1, 1, area.height - 2),
            );
        }
    }
}

fn sender_identity_lines(app: &MailApp, message: &Message, width: usize) -> Vec<Line<'static>> {
    let address = message.summary.from_address.as_deref();
    let contact = address.and_then(|address| app.contact_name(address));
    let mut lines = Vec::new();
    if let Some(contact) = contact {
        for segment in
            wrap_untrusted_identity(&format!("From: {}", safe_single_line_text(contact)), width)
        {
            lines.push(Line::styled(
                segment,
                Style::default().add_modifier(Modifier::BOLD),
            ));
        }
        lines.push(Line::styled(
            "Complete address:",
            Style::default().add_modifier(Modifier::BOLD),
        ));
        for segment in wrap_untrusted_identity(address.unwrap_or_default(), width) {
            lines.push(Line::raw(segment));
        }
    } else {
        lines.push(Line::styled(
            "Complete sender address — not in contacts:",
            Style::default().add_modifier(Modifier::BOLD),
        ));
        for segment in wrap_untrusted_identity(
            address.unwrap_or("ambiguous or missing From address"),
            width,
        ) {
            lines.push(Line::styled(segment, Style::default().fg(COLD)));
        }
        if let Some(name) = message
            .summary
            .from_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
        {
            let domain = address.and_then(address_domain).unwrap_or("this address");
            for segment in wrap_untrusted_identity(
                &format!(
                    "{} claims to be \"{}\"",
                    safe_single_line_text(domain),
                    safe_single_line_text(name)
                ),
                width,
            ) {
                lines.push(Line::raw(segment));
            }
        }
    }
    lines
}

fn append_labeled_lines(lines: &mut Vec<Line<'static>>, label: &str, value: &str, width: usize) {
    for segment in
        wrap_untrusted_identity(&format!("{label}{}", safe_single_line_text(value)), width)
    {
        lines.push(Line::raw(segment));
    }
}

fn dkim_summary(message: &Message) -> String {
    if !message.dkim.signatures.is_empty() {
        let aligned = message
            .dkim
            .signatures
            .iter()
            .enumerate()
            .find(|(_, signature)| {
                signature.status == DkimSignatureStatus::Pass
                    && signature.from_domain_aligned == Some(true)
                    && signature.signing_domain.is_some()
            });
        if let Some((aligned_index, signature)) = aligned {
            let domain = signature
                .signing_domain
                .as_deref()
                .unwrap_or("unknown domain");
            let other = message
                .dkim
                .signatures
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != aligned_index)
                .map(|(_, signature)| dkim_signature_description(signature))
                .collect::<Vec<_>>();
            if other.is_empty() {
                return format!("This message was signed by {domain}");
            }
            return format!(
                "This message was signed by {domain}. Other signature evidence: {}",
                other.join("; ")
            );
        }
        return format!(
            "DKIM signature evidence: {}",
            message
                .dkim
                .signatures
                .iter()
                .map(dkim_signature_description)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let claimed = message
        .summary
        .from_address
        .as_deref()
        .and_then(address_domain);
    match message.dkim.status {
        DkimAuthenticationStatus::Pass => claimed.map_or_else(
            || "A signature passed, but it does not establish the visible From domain".into(),
            |domain| format!("No valid aligned signature from {domain}"),
        ),
        DkimAuthenticationStatus::Unsigned => claimed.map_or_else(
            || "Unsigned — no DKIM signature".into(),
            |domain| format!("Unsigned — {domain} did not attach a DKIM signature"),
        ),
        DkimAuthenticationStatus::Failed => "DKIM verification failed".into(),
        DkimAuthenticationStatus::TemporaryFailure => {
            "DKIM verification is temporarily unavailable".into()
        }
        DkimAuthenticationStatus::NotEvaluated => "DKIM has not been evaluated".into(),
    }
}

fn dkim_signature_description(signature: &lizard_mail_backend::DkimSignatureEvidence) -> String {
    let domain = signature
        .signing_domain
        .as_deref()
        .filter(|domain| !domain.is_empty());
    match signature.status {
        DkimSignatureStatus::Pass => match (domain, signature.from_domain_aligned) {
            (Some(domain), Some(true)) => {
                format!("{domain} signed this message and matches the visible From domain")
            }
            (Some(domain), Some(false)) => {
                format!("{domain} signed this message, but does not match the visible From domain")
            }
            (Some(domain), None) => format!(
                "{domain} signed this message; alignment with the visible From domain is unknown"
            ),
            (None, _) => "A signature passed, but its signing domain was unavailable".into(),
        },
        DkimSignatureStatus::Fail => dkim_nonpassing_description(
            &format!(
                "A signature claiming {} failed verification",
                domain.unwrap_or("an unknown domain")
            ),
            signature,
        ),
        DkimSignatureStatus::Neutral => dkim_nonpassing_description(
            &format!(
                "A signature claiming {} did not verify",
                domain.unwrap_or("an unknown domain")
            ),
            signature,
        ),
        DkimSignatureStatus::PermanentError => dkim_nonpassing_description(
            &format!(
                "A signature claiming {} could not be verified",
                domain.unwrap_or("an unknown domain")
            ),
            signature,
        ),
        DkimSignatureStatus::TemporaryError => dkim_nonpassing_description(
            &format!(
                "Verification for a signature claiming {} is temporarily unavailable",
                domain.unwrap_or("an unknown domain")
            ),
            signature,
        ),
    }
}

fn dkim_nonpassing_description(
    prefix: &str,
    signature: &lizard_mail_backend::DkimSignatureEvidence,
) -> String {
    if let Some(reason) = dkim_signature_reason(signature) {
        format!("{prefix}: {reason}")
    } else {
        format!("{prefix}, but the verifier gave no specific reason")
    }
}

fn dkim_signature_reason(signature: &lizard_mail_backend::DkimSignatureEvidence) -> Option<String> {
    let reason = signature
        .reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            signature
                .reason_code
                .as_deref()
                .filter(|reason| !reason.is_empty())
                .map(|reason| reason.replace('_', " "))
        })?;
    let safe = safe_single_line_text(reason.trim());
    let mut bounded = safe.chars().take(240).collect::<String>();
    if safe.chars().count() > 240 {
        bounded.push('…');
    }
    Some(bounded)
}

fn aligned_dkim_domain(signatures: &[lizard_mail_backend::DkimSignatureEvidence]) -> Option<&str> {
    signatures.iter().find_map(|signature| {
        (signature.status == DkimSignatureStatus::Pass
            && signature.from_domain_aligned == Some(true))
        .then_some(signature.signing_domain.as_deref())
        .flatten()
    })
}

fn trusted_delivery_summary(message: &Message) -> Option<String> {
    for preferred in [
        AuthenticationMethodKind::Dmarc,
        AuthenticationMethodKind::Dkim,
    ] {
        for observation in &message.delivery_authentication.observations {
            for header in &observation.headers {
                if header.trust != AuthenticationResultsTrust::Trusted {
                    continue;
                }
                if let Some(method) = header
                    .methods
                    .iter()
                    .find(|method| method.kind == preferred)
                {
                    let result = match method.result {
                        AuthenticationMethodResult::Pass => "pass",
                        AuthenticationMethodResult::Fail => "fail",
                        AuthenticationMethodResult::SoftFail => "soft fail",
                        AuthenticationMethodResult::Neutral => "neutral",
                        AuthenticationMethodResult::Policy => "policy result",
                        AuthenticationMethodResult::TemporaryError => "temporary error",
                        AuthenticationMethodResult::PermanentError => "permanent error",
                        AuthenticationMethodResult::None => "none",
                        AuthenticationMethodResult::Unknown => "unknown result",
                    };
                    return Some(format!(
                        "{} recorded {} {result}",
                        header
                            .authserv_id
                            .as_deref()
                            .unwrap_or("the receiving server"),
                        match preferred {
                            AuthenticationMethodKind::Dmarc => "DMARC",
                            AuthenticationMethodKind::Dkim => "DKIM",
                            _ => unreachable!(),
                        }
                    ));
                }
            }
        }
    }
    None
}

fn openpgp_summary(app: &MailApp, message: &Message) -> Option<String> {
    if message.openpgp.encryption == OpenPgpEncryptionStatus::NotEncrypted
        && message.openpgp.signatures.is_empty()
    {
        return None;
    }
    let encryption = match message.openpgp.encryption {
        OpenPgpEncryptionStatus::NotEncrypted => None,
        OpenPgpEncryptionStatus::Encrypted => Some("encrypted; decryption required"),
        OpenPgpEncryptionStatus::Decrypted => Some("decrypted for one of your keys"),
        OpenPgpEncryptionStatus::MissingSecretKey => Some("encrypted; private key unavailable"),
        OpenPgpEncryptionStatus::ProviderUnavailable => Some("encrypted; key provider unavailable"),
        OpenPgpEncryptionStatus::InteractionRequired => {
            Some("encrypted; hardware or PIN interaction required")
        }
        OpenPgpEncryptionStatus::FailedIntegrity => {
            Some("encrypted content failed integrity verification")
        }
        OpenPgpEncryptionStatus::Unsupported => Some("unsupported encrypted content"),
        OpenPgpEncryptionStatus::Malformed => Some("malformed encrypted content"),
    };
    let signature = message
        .openpgp
        .signatures
        .iter()
        .find(|signature| signature.status != OpenPgpSignatureStatus::None);
    let signature = signature.map(|signature| match signature.status {
        OpenPgpSignatureStatus::Valid
            if signature.binding_state == Some(OpenPgpBindingState::Accepted) =>
        {
            let owner = message
                .summary
                .from_address
                .as_deref()
                .and_then(|address| app.contact_name(address))
                .unwrap_or("this contact");
            format!("valid signature from a key you saved for {owner}")
        }
        OpenPgpSignatureStatus::Valid => format!(
            "valid signature from unassociated key {}",
            abbreviated_fingerprint(signature.certificate_fingerprint.as_deref())
        ),
        OpenPgpSignatureStatus::Invalid => "INVALID SIGNATURE".into(),
        OpenPgpSignatureStatus::MissingCertificate => "signature key unavailable".into(),
        OpenPgpSignatureStatus::Unsupported => "unsupported signature".into(),
        OpenPgpSignatureStatus::Obsolete => "obsolete signature algorithm".into(),
        OpenPgpSignatureStatus::None => "no signature".into(),
    });
    Some(
        [encryption.map(str::to_owned), signature]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn abbreviated_fingerprint(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "unknown fingerprint".into();
    };
    if value.chars().count() <= 16 {
        return value.to_owned();
    }
    let prefix = value.chars().take(8).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}…{suffix}")
}

fn append_finding_lines(
    lines: &mut Vec<Line<'static>>,
    message: &Message,
    limit: usize,
    width: usize,
    link_detail_location: &str,
) {
    let active = message
        .findings
        .iter()
        .filter(|finding| {
            finding.dismissed_at.is_none() && finding.severity >= FindingSeverity::Warning
        })
        .collect::<Vec<_>>();
    let mut summaries = active
        .iter()
        .filter(|finding| finding.target_kind != FindingTargetKind::Link)
        .map(|finding| (finding.severity, finding_summary(finding)))
        .collect::<Vec<_>>();
    let mut link_categories =
        BTreeMap::<&'static str, (FindingSeverity, BTreeSet<String>, usize)>::new();
    for finding in active
        .iter()
        .filter(|finding| finding.target_kind == FindingTargetKind::Link)
    {
        let entry = link_categories
            .entry(link_finding_category(&finding.code))
            .or_insert((finding.severity, BTreeSet::new(), 0));
        entry.0 = entry.0.max(finding.severity);
        if let Some(target) = &finding.target_id {
            entry.1.insert(target.clone());
        }
        entry.2 = entry.2.saturating_add(1);
    }
    for (category, (severity, targets, evidence_count)) in link_categories {
        let affected = if targets.is_empty() {
            format!("{evidence_count} warning(s)")
        } else if targets.len() == 1 {
            "1 link affected".into()
        } else {
            format!("{} links affected", targets.len())
        };
        summaries.push((
            severity,
            format!(
                "{category} ({affected}). Exact explanations appear above the affected links {link_detail_location}"
            ),
        ));
    }
    summaries.sort_by(|left, right| right.0.cmp(&left.0));
    for (severity, summary) in summaries.iter().take(limit) {
        let (level, style) = finding_visual_style(*severity);
        for line in wrap_untrusted_identity(&format!("{level} — {summary}"), width) {
            lines.push(Line::styled(line, style));
        }
    }
    if summaries.len() > limit {
        let hidden_severity = summaries
            .iter()
            .skip(limit)
            .map(|finding| finding.0)
            .max()
            .unwrap_or(FindingSeverity::Warning);
        let (level, style) = finding_visual_style(hidden_severity);
        lines.push(Line::styled(
            format!(
                "{level} — {} additional finding categories",
                summaries.len() - limit
            ),
            style,
        ));
    }
}

fn link_finding_category(code: &str) -> &'static str {
    match code {
        "misleading_link_text"
        | "misleading_userinfo"
        | "embedded_popular_link_domain"
        | "confusable_popular_link_domain"
        | "ascii_confusable_domain"
        | "unicode_confusable_domain"
        | "invisible_or_bidi_domain" => "Misleading or disguised links",
        "dangerous_scheme" => "Blocked link types",
        "raw_ip_destination"
        | "unusual_port"
        | "nested_redirect"
        | "cross_domain_account_action" => "Unexpected link destinations",
        _ => "Suspicious links",
    }
}

fn highest_active_security_severity(message: &Message) -> FindingSeverity {
    message
        .findings
        .iter()
        .filter(|finding| finding.dismissed_at.is_none())
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(FindingSeverity::Warning)
}

fn security_color(severity: FindingSeverity) -> Color {
    match severity {
        FindingSeverity::Danger => DANGER,
        FindingSeverity::Warning => FYI_HINT,
        FindingSeverity::Information => COLD,
    }
}

fn finding_visual_style(severity: FindingSeverity) -> (&'static str, Style) {
    match severity {
        FindingSeverity::Danger => (
            "HIGH RISK",
            Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
        ),
        FindingSeverity::Warning => (
            "CAUTION",
            Style::default().fg(FYI_HINT).add_modifier(Modifier::BOLD),
        ),
        FindingSeverity::Information => ("NOTICE", Style::default().fg(COLD)),
    }
}

fn finding_summary(finding: &HeuristicFinding) -> String {
    let string = |key: &str| {
        finding
            .evidence
            .get(key)
            .and_then(|value| value.as_str())
            .map(safe_single_line_text)
    };
    let strings = |key: &str| {
        finding
            .evidence
            .get(key)
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(safe_single_line_text)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|value| !value.is_empty())
    };
    let number = |key: &str| finding.evidence.get(key).and_then(|value| value.as_u64());
    let destination_host = || {
        string("destination_host").or_else(|| {
            string("destination").and_then(|destination| {
                Url::parse(&destination)
                    .ok()
                    .and_then(|url| url.host_str().map(safe_single_line_text))
            })
        })
    };
    match finding.code.as_str() {
        "ambiguous_sender_header" =>
            "The message does not contain exactly one unambiguous From mailbox; no sender identity was accepted".into(),
        "malformed_sender_header" =>
            "The sender headers are malformed; no sender identity was accepted".into(),
        "embedded_popular_sender_domain" => format!(
            "This address is controlled by {}, not {}; it places the popular domain before its real domain",
            string("actual_registrable_domain").unwrap_or_else(|| "another domain".into()),
            string("embedded_popular_domain").unwrap_or_else(|| "the domain it resembles".into()),
        ),
        "embedded_popular_reply_domain" => format!(
            "A reply would go to {}, not {}; its address places the popular domain before its real domain",
            string("actual_registrable_domain").unwrap_or_else(|| "another domain".into()),
            string("embedded_popular_domain").unwrap_or_else(|| "the domain it resembles".into()),
        ),
        "embedded_popular_link_domain" => format!(
            "A link opens {}, not {}; its hostname places the popular domain before its real domain",
            string("actual_registrable_domain").unwrap_or_else(|| "another domain".into()),
            string("embedded_popular_domain").unwrap_or_else(|| "the domain it resembles".into()),
        ),
        "confusable_sender_domain" => format!(
            "The sender domain resembles the saved domain {} but is not the same domain",
            string("confusable_with").unwrap_or_else(|| "of a contact".into()),
        ),
        "confusable_popular_sender_domain" => format!(
            "The sender domain resembles the popular domain {} but is not the same domain",
            string("confusable_with").unwrap_or_else(|| "it appears to name".into()),
        ),
        "confusable_popular_reply_domain" => format!(
            "The reply domain resembles the popular domain {} but is not the same domain",
            string("confusable_with").unwrap_or_else(|| "it appears to name".into()),
        ),
        "confusable_popular_link_domain" => format!(
            "A link domain resembles the popular domain {} but is not the same domain",
            string("confusable_with").unwrap_or_else(|| "it appears to name".into()),
        ),
        "misleading_link_text" => format!(
            "The link text says {}, but the link actually opens {}",
            string("displayed_host").unwrap_or_else(|| "one site".into()),
            destination_host().unwrap_or_else(|| "another site".into()),
        ),
        "misleading_userinfo" => format!(
            "The address puts {} before an @ sign, but the link actually opens {}",
            string("username").unwrap_or_else(|| "a site name".into()),
            destination_host().unwrap_or_else(|| "another site".into()),
        ),
        "raw_ip_destination" => format!(
            "This link opens the numeric network address {} instead of a named site",
            string("host").unwrap_or_else(|| "shown below".into()),
        ),
        "unusual_port" => format!(
            "This link connects to {} on unusual network port {}",
            destination_host().unwrap_or_else(|| "the site below".into()),
            number("port").map_or_else(|| "unknown".into(), |port| port.to_string()),
        ),
        "dangerous_scheme" => format!(
            "This is not a normal web link: it uses the blocked {} link type",
            string("scheme").unwrap_or_else(|| "unknown".into()),
        ),
        "nested_redirect" => format!(
            "This link first opens {}, then contains a redirect toward {}",
            destination_host().unwrap_or_else(|| "the site below".into()),
            string("nested_destination")
                .and_then(|destination| Url::parse(&destination).ok().and_then(|url| url.host_str().map(safe_single_line_text)))
                .unwrap_or_else(|| "another site".into()),
        ),
        "ascii_confusable_domain" | "unicode_confusable_domain" => format!(
            "The link opens {}, whose spelling resembles {} but is a different domain",
            string("raw_host").or_else(destination_host).unwrap_or_else(|| "the domain below".into()),
            string("confusable_with").unwrap_or_else(|| "a familiar domain".into()),
        ),
        "invisible_or_bidi_domain" => format!(
            "The link address contains invisible or direction-changing characters; its parsed host is {}",
            string("raw_host").or_else(destination_host).unwrap_or_else(|| "shown below".into()),
        ),
        "invisible_or_bidi_sender_identity" =>
            "The sender identity contains invisible or bidirectional characters".into(),
        "warm_sender_name_mismatch" => format!(
            "This known address claims a different name: {}",
            string("claimed_name").unwrap_or_else(|| "an untrusted name".into()),
        ),
        "cold_contact_name_collision" => format!(
            "This unknown address claims the name of one of your contacts: {}",
            string("claimed_name").unwrap_or_else(|| "contact name".into()),
        ),
        "sender_from_mismatch" =>
            "The RFC Sender field disagrees with the visible From address".into(),
        "reply_to_mismatch" => format!(
            "Visible From: {} · Replies go to: {}",
            string("from").unwrap_or_else(|| "unknown address".into()),
            strings("reply_to").unwrap_or_else(|| "unknown address".into()),
        ),
        "conversation_injection" =>
            "An unknown sender claims to belong to an established conversation".into(),
        "unaligned_dkim" => format!(
            "Expected a signature from {}, but the valid signature came from {}",
            string("from_domain").unwrap_or_else(|| "the visible From domain".into()),
            strings("signing_domains").unwrap_or_else(|| "an unrelated domain".into()),
        ),
        "missing_aligned_dkim" => match string("status").as_deref() {
            Some("unsigned") => format!(
                "{} did not attach a DKIM signature",
                string("from_domain").unwrap_or_else(|| "The visible From domain".into()),
            ),
            Some("failed") => format!(
                "A signature claiming {} failed verification; a valid signature from {} was expected",
                strings("claimed_signing_domains")
                    .unwrap_or_else(|| "an unknown signing domain".into()),
                string("from_domain").unwrap_or_else(|| "the visible From domain".into()),
            ),
            Some("temporary_failure") => format!(
                "Verification is temporarily unavailable for a signature claiming {}",
                strings("claimed_signing_domains")
                    .unwrap_or_else(|| "an unknown signing domain".into()),
            ),
            _ => format!(
                "There is no valid signature from {}",
                string("from_domain").unwrap_or_else(|| "the visible From domain".into()),
            ),
        },
        "unsigned_dkim_provider_verified" => format!(
            "Unsigned: your mail provider verified delivery through servers authorized by {}, but the domain did not sign this message",
            string("from_domain").unwrap_or_else(|| "the visible From domain".into()),
        ),
        "cross_domain_account_action" => format!(
            "This account-action link is in mail from {}, but it opens {}. Do not use it; use a bookmark, the official app, or type an address you already know",
            string("from_domain").unwrap_or_else(|| "unknown".into()),
            string("destination_domain").unwrap_or_else(|| "another site".into()),
        ),
        "openpgp_protected_header_mismatch" =>
            "The outer headers disagree with the integrity-protected OpenPGP headers".into(),
        "invalid_openpgp_signature" => "The OpenPGP signature is invalid".into(),
        _ => finding
            .text
            .as_deref()
            .map(safe_single_line_text)
            .unwrap_or_else(|| finding.code.replace('_', " ")),
    }
}

fn identity_block_title(class: InboxClass) -> &'static str {
    match class {
        InboxClass::Warm => "Warm identity · established address",
        InboxClass::Cold => "Cold identity · evaluate the complete address",
        InboxClass::Spam => "Spam identity · untrusted sender",
    }
}

fn address_domain(address: &str) -> Option<&str> {
    address.rsplit_once('@').map(|(_, domain)| domain)
}

fn wrap_untrusted_identity(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let value = safe_single_line_text(value);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0usize;
    for character in value.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(1).max(1);
        if used + character_width > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push(character);
        used += character_width;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn wrap_message_body(value: &str, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let sanitized = safe_text(value).replace('\t', "    ");
    let mut lines = Vec::new();
    for logical_line in sanitized.split('\n') {
        let mut line = String::new();
        let mut used = 0usize;
        for character in logical_line.chars() {
            let character_width = UnicodeWidthChar::width(character).unwrap_or(1).max(1);
            if used + character_width > width && !line.is_empty() {
                lines.push(Line::raw(std::mem::take(&mut line)));
                used = 0;
            }
            line.push(character);
            used += character_width;
        }
        lines.push(Line::raw(line));
    }
    if lines.is_empty() {
        lines.push(Line::raw(""));
    }
    lines
}

fn annotated_rendered_message_lines(
    page: &RenderedPage,
    message: &Message,
    width: usize,
    restricted: bool,
    selected_link: Option<usize>,
    link_rows: &mut Vec<usize>,
) -> Vec<Line<'static>> {
    if page.links.is_empty() {
        let mut lines = page.lines.clone();
        if restricted {
            defang_sender_lines(&mut lines);
        }
        return lines;
    }
    let generated_link_start = page.link_targets_start.or_else(|| {
        if page.truncated {
            None
        } else {
            page.lines
                .iter()
                .rposition(|line| rendered_line_text(line) == "Links")
        }
    });
    let mut lines = page.lines[..generated_link_start.unwrap_or(page.lines.len())].to_vec();
    if restricted {
        defang_sender_lines(&mut lines);
    }
    append_section_break(&mut lines);
    lines.push(Line::styled(
        "Links and safety",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if restricted {
        append_restricted_link_explanation(&mut lines, message, width);
    }
    let link_contexts = rendered_link_contexts(page);
    let link_targets = page
        .links
        .iter()
        .map(|link| (link.number, target_ids_for_reference(message, link)))
        .collect::<HashMap<_, _>>();
    let matched_targets = link_targets
        .values()
        .flat_map(|targets| targets.iter().cloned())
        .collect::<BTreeSet<_>>();
    append_unmatched_targeted_link_findings(&mut lines, message, &matched_targets, width);
    let mut browser_link_index = 0usize;
    for link in &page.links {
        let targets = link_targets.get(&link.number).cloned().unwrap_or_default();
        append_targeted_link_findings(&mut lines, message, &targets, width);
        if let Some(context) = link_contexts.get(&link.number) {
            append_link_context(&mut lines, context, width, restricted);
        }
        let destination = rendered_link_destination(link);
        let destination = if restricted {
            defang_destination(&destination)
        } else {
            destination
        };
        let browser_link = !restricted && rendered_link_is_browser_openable(link);
        let style = if browser_link && selected_link == Some(browser_link_index) {
            focused_link_style()
        } else {
            Style::default().fg(Color::Cyan)
        };
        if browser_link {
            link_rows.push(lines.len());
            browser_link_index += 1;
        }
        append_wrapped_styled(
            &mut lines,
            &format!("{}. {destination}", link.number),
            width,
            style,
        );
    }
    lines
}

fn append_backend_link_section(
    lines: &mut Vec<Line<'static>>,
    message: &Message,
    width: usize,
    restricted: bool,
    selected_link: Option<usize>,
    link_rows: &mut Vec<usize>,
) {
    if message.links.is_empty() {
        return;
    }
    append_section_break(lines);
    lines.push(Line::styled(
        "Links and safety",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if restricted {
        append_restricted_link_explanation(lines, message, width);
    }
    let link_contexts = backend_link_contexts(message);
    let link_targets = message
        .links
        .iter()
        .map(|link| (link.id.clone(), target_ids_for_backend_link(message, link)))
        .collect::<HashMap<_, _>>();
    let matched_targets = link_targets
        .values()
        .flat_map(|targets| targets.iter().cloned())
        .collect::<BTreeSet<_>>();
    append_unmatched_targeted_link_findings(lines, message, &matched_targets, width);
    let mut browser_link_index = 0usize;
    for link in &message.links {
        let targets = link_targets.get(&link.id).cloned().unwrap_or_default();
        append_targeted_link_findings(lines, message, &targets, width);
        if let Some(context) = link_contexts.get(&link.id) {
            append_link_context(lines, context, width, restricted);
        }
        let mut destination = if matches!(link.scheme.as_str(), "http" | "https" | "mailto" | "cid")
        {
            safe_single_line_text(&link.destination)
        } else {
            format!("[blocked {} link]", safe_single_line_text(&link.scheme))
        };
        if restricted {
            destination = defang_destination(&destination);
        }
        let browser_link = !restricted && backend_link_is_browser_openable(link);
        let style = if browser_link && selected_link == Some(browser_link_index) {
            focused_link_style()
        } else {
            Style::default().fg(Color::Cyan)
        };
        if browser_link {
            link_rows.push(lines.len());
            browser_link_index += 1;
        }
        append_wrapped_styled(
            lines,
            &format!("{}. {destination}", link.ordinal.saturating_add(1)),
            width,
            style,
        );
    }
}

fn append_restricted_link_explanation(
    lines: &mut Vec<Line<'static>>,
    message: &Message,
    width: usize,
) {
    let identity_warning = if aligned_dkim_domain(&message.dkim.signatures).is_none() {
        message
            .summary
            .from_address
            .as_deref()
            .and_then(address_domain)
            .map_or_else(
                || "The sender's site did not sign this email.".into(),
                |domain| format!("This email was not signed by {domain}."),
            )
    } else {
        "This email triggered a high-risk security warning.".into()
    };
    let explanation = format!(
        "{identity_warning} You are strongly advised to avoid using the links below. For your protection, spaces have been added to every address so your terminal cannot make it clickable. Remove those spaces manually only if you deliberately choose to use one."
    );
    append_wrapped_styled(
        lines,
        &explanation,
        width,
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
}

/// Make sender-controlled text inert before application-authored safety text is
/// appended. Keeping this boundary explicit prevents domains in our own
/// findings and explanations from being corrupted by URL defanging.
fn defang_sender_lines(lines: &mut [Line<'static>]) {
    for line in lines {
        for span in &mut line.spans {
            let defanged = defang_clickable_runs(span.content.as_ref());
            if defanged != span.content {
                span.content = defanged.into();
            }
        }
    }
}

fn defang_clickable_runs(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut token = String::new();
    let flush = |output: &mut String, token: &mut String| {
        if token_looks_clickable(token) {
            output.push_str(&defang_destination(token));
        } else {
            output.push_str(token);
        }
        token.clear();
    };
    for character in value.chars() {
        if character.is_whitespace() {
            flush(&mut output, &mut token);
            output.push(character);
        } else {
            token.push(character);
        }
    }
    flush(&mut output, &mut token);
    output
}

fn token_looks_clickable(value: &str) -> bool {
    let value = value.trim_matches(|character: char| {
        matches!(
            character,
            ',' | ';' | '!' | '.' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\''
        )
    });
    if value.contains("://") || value.to_ascii_lowercase().starts_with("www.") {
        return true;
    }
    if value.contains('@') && value.contains('.') {
        return true;
    }
    let authority = value
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    let Some(final_label) = authority
        .rsplit('.')
        .next()
        .filter(|_| authority.contains('.'))
    else {
        return false;
    };
    (2..=63).contains(&final_label.len())
        && final_label
            .chars()
            .all(|character| character.is_ascii_alphabetic())
}

fn defang_destination(value: &str) -> String {
    let mut output = String::with_capacity(value.len().saturating_add(8));
    for character in value.chars() {
        output.push(character);
        if matches!(
            character,
            ':' | '/' | '.' | '@' | '?' | '#' | '&' | '=' | '%'
        ) {
            output.push(' ');
        }
    }
    output
}

fn append_link_context(
    lines: &mut Vec<Line<'static>>,
    context: &str,
    width: usize,
    restricted: bool,
) {
    let context = if restricted {
        defang_clickable_runs(context)
    } else {
        context.to_owned()
    };
    append_wrapped_styled(
        lines,
        &format!("Context: {context}"),
        width,
        Style::default().fg(Color::White),
    );
}

fn rendered_link_contexts(page: &RenderedPage) -> HashMap<usize, String> {
    page.links
        .iter()
        .filter_map(|link| {
            link.context
                .as_ref()
                .map(|context| (link.number, context.clone()))
        })
        .collect()
}

fn backend_link_contexts(message: &Message) -> HashMap<String, String> {
    let mut contexts = HashMap::new();
    let mut cursor = 0;
    for link in &message.links {
        let relative = message.body_text[cursor..]
            .find(&link.destination)
            .map(|offset| cursor + offset);
        let Some(start) = relative.or_else(|| message.body_text.find(&link.destination)) else {
            continue;
        };
        let end = start.saturating_add(link.destination.len());
        cursor = end;
        if let Some(context) = bounded_surrounding_words(&message.body_text, start, end) {
            contexts.insert(link.id.clone(), context);
        }
    }
    contexts
}

fn bounded_surrounding_words(text: &str, start: usize, end: usize) -> Option<String> {
    if start > end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return None;
    }
    let mut left = text[..start]
        .split_whitespace()
        .rev()
        .take(LINK_CONTEXT_WORD_RADIUS + 1)
        .collect::<Vec<_>>();
    let left_truncated = left.len() > LINK_CONTEXT_WORD_RADIUS;
    left.truncate(LINK_CONTEXT_WORD_RADIUS);
    left.reverse();
    let mut right = text[end..]
        .split_whitespace()
        .take(LINK_CONTEXT_WORD_RADIUS + 1)
        .collect::<Vec<_>>();
    let right_truncated = right.len() > LINK_CONTEXT_WORD_RADIUS;
    right.truncate(LINK_CONTEXT_WORD_RADIUS);
    if left.is_empty() && right.is_empty() {
        return None;
    }

    let mut context = String::new();
    if left_truncated {
        context.push_str("… ");
    }
    context.push_str(&left.join(" "));
    if !context.is_empty() && !right.is_empty() {
        context.push(' ');
    }
    context.push_str(&right.join(" "));
    if right_truncated {
        context.push_str(" …");
    }
    let context = safe_single_line_text(&context);
    let mut bounded = context
        .chars()
        .take(LINK_CONTEXT_MAX_CHARS)
        .collect::<String>();
    if context.chars().count() > LINK_CONTEXT_MAX_CHARS {
        bounded.push('…');
    }
    (!bounded.trim().is_empty()).then_some(bounded)
}

fn append_targeted_link_findings(
    lines: &mut Vec<Line<'static>>,
    message: &Message,
    target_ids: &BTreeSet<String>,
    width: usize,
) {
    let mut findings = message
        .findings
        .iter()
        .filter(|finding| {
            finding.dismissed_at.is_none()
                && finding.target_kind == FindingTargetKind::Link
                && finding.severity >= FindingSeverity::Warning
                && finding
                    .target_id
                    .as_ref()
                    .is_some_and(|target| target_ids.contains(target))
        })
        .map(|finding| (finding.severity, finding_summary(finding)))
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    findings.dedup();
    for (severity, summary) in findings {
        let (level, style) = finding_visual_style(severity);
        append_wrapped_styled(lines, &format!("{level} — {summary}"), width, style);
    }
}

fn append_unmatched_targeted_link_findings(
    lines: &mut Vec<Line<'static>>,
    message: &Message,
    matched_targets: &BTreeSet<String>,
    width: usize,
) {
    let mut findings = message
        .findings
        .iter()
        .filter(|finding| {
            finding.dismissed_at.is_none()
                && finding.target_kind == FindingTargetKind::Link
                && finding.severity >= FindingSeverity::Warning
                && finding
                    .target_id
                    .as_ref()
                    .is_some_and(|target| !matched_targets.contains(target))
        })
        .map(|finding| (finding.severity, finding_summary(finding)))
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    findings.dedup();
    for (severity, summary) in findings {
        let (level, style) = finding_visual_style(severity);
        append_wrapped_styled(
            lines,
            &format!(
                "{level} — The client could not safely identify which displayed link triggered this warning: {summary}. Treat every link below as suspicious"
            ),
            width,
            style,
        );
    }
}

fn append_wrapped_styled(lines: &mut Vec<Line<'static>>, value: &str, width: usize, style: Style) {
    for segment in wrap_untrusted_identity(value, width) {
        lines.push(Line::styled(segment, style));
    }
}

fn append_section_break(lines: &mut Vec<Line<'static>>) {
    if lines
        .last()
        .is_some_and(|line| !rendered_line_text(line).is_empty())
    {
        lines.push(Line::default());
    }
}

fn rendered_line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

fn message_link_matches_reference(message_link: &MessageLink, reference: &LinkReference) -> bool {
    if reference.kind == LinkKind::Blocked {
        return reference.blocked_scheme.as_deref() == Some(message_link.scheme.as_str());
    }
    let Some(reference_destination) = reference.destination.as_deref() else {
        return false;
    };
    Url::parse(&message_link.destination)
        .ok()
        .is_some_and(|destination| destination.as_str() == reference_destination)
}

fn target_ids_for_reference(message: &Message, reference: &LinkReference) -> BTreeSet<String> {
    let mut targets = message
        .links
        .iter()
        .filter(|message_link| message_link_matches_reference(message_link, reference))
        .map(|message_link| message_link.id.clone())
        .collect::<BTreeSet<_>>();
    for finding in active_targeted_link_findings(message) {
        if finding_destination(finding)
            .is_some_and(|destination| destination_matches_reference(destination, reference))
        {
            if let Some(target) = &finding.target_id {
                targets.insert(target.clone());
            }
        }
    }
    targets
}

fn target_ids_for_backend_link(message: &Message, link: &MessageLink) -> BTreeSet<String> {
    let mut targets = BTreeSet::from([link.id.clone()]);
    for finding in active_targeted_link_findings(message) {
        if finding_destination(finding)
            .is_some_and(|destination| destinations_equivalent(destination, &link.destination))
        {
            if let Some(target) = &finding.target_id {
                targets.insert(target.clone());
            }
        }
    }
    targets
}

fn active_targeted_link_findings(message: &Message) -> impl Iterator<Item = &HeuristicFinding> {
    message.findings.iter().filter(|finding| {
        finding.dismissed_at.is_none()
            && finding.target_kind == FindingTargetKind::Link
            && finding.severity >= FindingSeverity::Warning
            && finding.target_id.is_some()
    })
}

fn finding_destination(finding: &HeuristicFinding) -> Option<&str> {
    finding
        .evidence
        .get("destination")
        .and_then(|value| value.as_str())
}

fn destination_matches_reference(destination: &str, reference: &LinkReference) -> bool {
    if reference.kind == LinkKind::Blocked {
        return Url::parse(destination.trim())
            .ok()
            .is_some_and(|destination| {
                reference.blocked_scheme.as_deref() == Some(destination.scheme())
            });
    }
    reference
        .destination
        .as_deref()
        .is_some_and(|reference| destinations_equivalent(destination, reference))
}

fn destinations_equivalent(left: &str, right: &str) -> bool {
    match (Url::parse(left.trim()), Url::parse(right.trim())) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.trim() == right.trim(),
    }
}

fn rendered_link_destination(link: &LinkReference) -> String {
    match link.kind {
        LinkKind::Blocked => link
            .blocked_scheme
            .as_deref()
            .map(|scheme| format!("[blocked {} link]", safe_single_line_text(scheme)))
            .unwrap_or_else(|| "[blocked link]".into()),
        LinkKind::Relative => format!(
            "[relative link] {}",
            link.destination
                .as_deref()
                .map(safe_single_line_text)
                .unwrap_or_default()
        ),
        _ => link
            .destination
            .as_deref()
            .map(safe_single_line_text)
            .unwrap_or_else(|| "[unavailable]".into()),
    }
}

fn rendered_link_is_browser_openable(link: &LinkReference) -> bool {
    link.kind == LinkKind::Web
        && link
            .destination
            .as_deref()
            .is_some_and(is_browser_destination)
}

fn backend_link_is_browser_openable(link: &MessageLink) -> bool {
    matches!(link.scheme.as_str(), "http" | "https") && is_browser_destination(&link.destination)
}

fn is_browser_destination(destination: &str) -> bool {
    Url::parse(destination.trim())
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

fn focused_link_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn draw_scrolling_panel(
    frame: &mut Frame<'_>,
    app: &MailApp,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    border_color: Color,
) {
    let content_rows = lines.len();
    let viewport_rows = usize::from(area.height.saturating_sub(2));
    let scroll = app.update_reader_scroll_bounds(content_rows, viewport_rows);
    let visible_start = if content_rows == 0 { 0 } else { scroll + 1 };
    let visible_end = scroll.saturating_add(viewport_rows).min(content_rows);
    let title = if content_rows > viewport_rows {
        format!("{title} · rows {visible_start}–{visible_end} of {content_rows}")
    } else {
        title.to_owned()
    };
    let visible = lines
        .into_iter()
        .skip(scroll)
        .take(viewport_rows)
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(Text::from(visible)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(border_color)),
        ),
        area,
    );
    if content_rows > viewport_rows && area.height > 2 {
        let mut state = ScrollbarState::default()
            .content_length(content_rows)
            .position(scroll)
            .viewport_content_length(viewport_rows);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_style(Style::default().fg(Color::DarkGray))
                .thumb_style(Style::default().fg(border_color)),
            area.inner(Margin {
                horizontal: 0,
                vertical: 1,
            }),
            &mut state,
        );
    }
}

fn draw_onboarding(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(5)])
        .split(area);
    frame.render_widget(
        Paragraph::new(
            "Lizard found your most frequent correspondents from the last six months. These are suggestions, not trusted identities. Accept, reject, or edit each one; likely automated/list mail defaults to FYI.",
        )
        .block(
            Block::default()
                .title("Build a useful Warm inbox")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false }),
        chunks[0],
    );
    let items = app
        .suggestions
        .iter()
        .map(|suggestion| {
            let name = suggestion
                .claimed_name
                .as_deref()
                .unwrap_or("no claimed name");
            let reason = suggestion
                .suggestion_reasons
                .first()
                .map(|value| safe_single_line_text(value))
                .unwrap_or_else(|| "no classification explanation available".into());
            ListItem::new(Text::from(vec![
                Line::raw(format!(
                    "{} claims to be {}  · {} messages · {:?}",
                    safe_single_line_text(&suggestion.address),
                    safe_single_line_text(name),
                    suggestion.message_count,
                    suggestion.suggested_warm_route
                )),
                Line::styled(
                    format!("  Why: {reason}"),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title("Top correspondents")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(COLD).fg(Color::Black))
            .highlight_symbol("› "),
        chunks[1],
        &mut state,
    );
}

fn draw_similarity_preview(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(preview) = &app.similarity_preview else {
        frame.render_widget(Paragraph::new("No similarity preview is available"), area);
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(4)])
        .split(area);
    let cutoff = f32::from(preview.cutoff_millis) / 1_000.0;
    let bounded = if preview.truncated {
        " The safety limit was reached; choose a stricter cutoff before saving."
    } else {
        ""
    };
    let matching_messages = if preview.truncated {
        format!("{}+", preview.matching_messages)
    } else {
        preview.matching_messages.to_string()
    };
    frame.render_widget(
        Paragraph::new(format!(
            "Sender: {}\nProposed route: FYI\nRelative BM25 cutoff: {cutoff:.2} (a ranking strength, not a probability)\n{} messages match; {} conversations would change. Each row below shows its actual effect.{bounded}",
            safe_single_line_text(&preview.sender_address),
            matching_messages,
            preview.affected_threads,
        ))
        .block(
            Block::default()
                .title("Confirm sender-scoped similar-mail rule")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false }),
        chunks[0],
    );
    let visible_items = usize::from(chunks[1].height.saturating_sub(2) / 2).max(1);
    let start = app
        .similarity_selected
        .saturating_sub(visible_items.saturating_sub(1));
    let end = start
        .saturating_add(visible_items)
        .min(preview.matches.len());
    let items = preview.matches[start..end]
        .iter()
        .map(|matched| {
            let score = f32::from(matched.relative_score_millis) / 1_000.0;
            let effect = if matched.would_move {
                "MOVE"
            } else {
                "already FYI/protected"
            };
            ListItem::new(Text::from(vec![
                Line::raw(format!(
                    "{score:.2}  {effect:>21}  {}  {}",
                    display_timestamp(matched.message.received_at),
                    safe_single_line_text(
                        matched.message.subject.as_deref().unwrap_or("(no subject)")
                    )
                )),
                Line::styled(
                    format!("      {}", safe_single_line_text(&matched.message.preview)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default()
        .with_selected((start < end).then_some(app.similarity_selected.saturating_sub(start)));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(format!(
                        "Ranked preview ({}–{} of {})",
                        start.saturating_add(1).min(end),
                        end,
                        matching_messages,
                    ))
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::Gray).fg(Color::Black))
            .highlight_symbol("› "),
        chunks[1],
        &mut state,
    );
}

fn draw_onboarding_edit(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(edit) = &app.onboarding_edit else {
        frame.render_widget(Paragraph::new("No suggestion selected"), area);
        return;
    };
    let text = Text::from(vec![
        Line::raw(
            "The address remains fixed and visible; edit the contact-owned identity and relationship policy.",
        ),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "Display name: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(safe_single_line_text(&edit.display_name)),
        ]),
        Line::from(vec![
            Span::styled(
                "Relationship: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{:?}", edit.relationship.kind)),
        ]),
        Line::from(vec![
            Span::styled(
                "Warm route: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{:?}", edit.relationship.warm_route)),
        ]),
        Line::from(vec![
            Span::styled(
                "May create obligations: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(if edit.relationship.may_create_obligations {
                "yes"
            } else {
                "no"
            }),
        ]),
        Line::raw(""),
        Line::raw(
            "Type to edit name · Ctrl-R toggle Action/FYI · Ctrl-K cycle relationship · Enter save · Esc cancel",
        ),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title("Edit contact suggestion")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_contacts(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let items = app
        .contacts
        .iter()
        .map(|contact| {
            let addresses = contact
                .addresses
                .iter()
                .map(|address| address.address.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let policy = app
                .contact_relationships
                .get(&contact.id)
                .map(|relationship| match relationship.warm_route {
                    WarmRoute::Action => "Action · may create obligations",
                    WarmRoute::Fyi => "FYI · does not create obligations",
                });
            ListItem::new(Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        safe_single_line_text(&contact.display_name),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("  <{}>", safe_single_line_text(&addresses))),
                ]),
                Line::styled(
                    format!("  {}", policy.unwrap_or("relationship policy unavailable")),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title("Contacts").borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::Gray).fg(Color::Black))
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn draw_contact_editor(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(editor) = &app.contact_editor else {
        frame.render_widget(Paragraph::new("No contact is being edited"), area);
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(area);
    frame.render_widget(
        Paragraph::new(
            "This is contact-owned identity and future-mail policy. Action mail may enter your obligation queue; FYI mail remains known but does not create work by default. Addresses are comma-separated.",
        )
        .block(
            Block::default()
                .title("Edit relationship")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false }),
        chunks[0],
    );
    let kind = match editor.relationship.kind {
        RelationshipKind::Person => "Person",
        RelationshipKind::Organization => "Organization",
        RelationshipKind::Merchant => "Merchant",
        RelationshipKind::Newsletter => "Newsletter",
        RelationshipKind::AutomatedService => "Automated service",
        RelationshipKind::Other => "Other",
    };
    let route = match editor.relationship.warm_route {
        WarmRoute::Action => "Action — may create obligations",
        WarmRoute::Fyi => "FYI — does not create obligations",
    };
    let remote_content = match editor.relationship.remote_content {
        RemoteContentPolicy::Ask => "Ask before telling the sender this mail was opened",
        RemoteContentPolicy::Allow => "Allow remote content for this contact",
        RemoteContentPolicy::Block => "Always block remote content for this contact",
    };
    let mut address_lines = vec![Line::styled(
        "Email addresses:",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    for line in wrap_untrusted_identity(
        &editor.addresses,
        usize::from(chunks[1].width.saturating_sub(6)).max(1),
    ) {
        address_lines.push(Line::raw(format!("  {line}")));
    }
    let items = vec![
        ListItem::new(Line::from(vec![
            Span::styled(
                "Display name: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(safe_single_line_text(&editor.display_name)),
        ])),
        ListItem::new(Text::from(address_lines)),
        contact_choice_item("Relationship kind", kind),
        contact_choice_item("Default inbox", route),
        contact_choice_item(
            "Notifications",
            if editor.relationship.notify {
                "On"
            } else {
                "Off"
            },
        ),
        contact_choice_item("Remote content", remote_content),
    ];
    let selected = match editor.selected_field {
        ContactField::Name => 0,
        ContactField::Addresses => 1,
        ContactField::Kind => 2,
        ContactField::Route => 3,
        ContactField::Notifications => 4,
        ContactField::RemoteContent => 5,
    };
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title("Contact identity and policy")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(WARM).fg(Color::Black))
            .highlight_symbol("› "),
        chunks[1],
        &mut state,
    );
}

fn contact_choice_item(label: &str, value: &str) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_owned()),
    ]))
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let text = Text::from(vec![
        Line::styled("Global", Style::default().add_modifier(Modifier::BOLD)),
        Line::raw(
            "1 Warm Action · 2 Warm FYI · 3 Cold · 4 Spam · L Waiting · Z Snoozed · D Done",
        ),
        Line::raw("/ Search · C Contacts · A Accounts · ? Help · q Quit · Esc Back"),
        Line::raw("F Folders · 5/6/7/8/9/0 Open assigned folders"),
        Line::raw(""),
        Line::styled(
            "Queues and reader",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw("Queue: j/k Move · Enter Open · d Done · w Waiting · s Snooze one day · / Search"),
        Line::raw(
            "Reader: ↑/↓ Previous/next email · j/k Scroll · PgUp/PgDn Page · g/G Top/bottom",
        ),
        Line::raw("Tab/Shift-Tab Select browser link · Enter Open selected link"),
        Line::raw("r Reply · R Reply all · reply editor: Ctrl-S save · Ctrl-D send"),
        Line::raw(
            "a Make Cold conversation actionable once · O Read through security warning with restrictions",
        ),
        Line::raw(
            "> Action → FYI · < FYI → Action · M Preview this-and-similar → FYI",
        ),
        Line::raw(""),
        Line::styled(
            "Onboarding",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw("y Accept suggestion · n Reject · e Edit"),
        Line::raw(
            "Edit: type name · Ctrl-R Action/FYI · Ctrl-K relationship kind · Enter Save",
        ),
        Line::raw(""),
        Line::styled(
            "Accounts",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw("N New · Enter/E Edit · S Synchronize · d Remove"),
        Line::raw(
            "Editor: ↑/↓ or Tab fields · Space toggle choices · Ctrl-S save · Esc cancel",
        ),
        Line::raw(""),
        Line::styled("Contacts", Style::default().add_modifier(Modifier::BOLD)),
        Line::raw("Enter/E Edit selected contact"),
        Line::raw(
            "Editor: change name/addresses · Space cycles policy choices · Ctrl-S save",
        ),
        Line::raw(""),
        Line::styled("Folders", Style::default().add_modifier(Modifier::BOLD)),
        Line::raw("Enter Open · b then 5–0 bind shortcut · n New · r Rename · d Delete"),
        Line::raw("Esc returns from a message to its folder, then to the folder list"),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title("Contextual commands")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let commands = match app.screen {
        Screen::Accounts => "j/k move · n new · Enter/e edit · S sync · d remove · Esc back",
        Screen::AccountEdit => {
            "↑/↓ or Tab fields · type value · Space toggle · Ctrl-S save · Esc cancel"
        }
        Screen::AccountDeleteConfirm => "y remove account · n/Esc cancel",
        Screen::SimilarityPreview => {
            "j/k inspect matches · y/Enter save rule · + stricter · - broader · n/Esc cancel"
        }
        Screen::Queue(WorkflowView::ColdReview) => {
            "j/k move · Enter inspect · a actionable once · d done · s snooze · / search"
        }
        Screen::Queue(WorkflowView::SpamQuarantine) => {
            "j/k move · Enter inspect safely · d done · / search · ? help"
        }
        Screen::Queue(WorkflowView::WarmAction) => {
            "j/k move · > move to FYI · M similar→FYI · d done · s snooze · / search"
        }
        Screen::Queue(WorkflowView::WarmFyi) => {
            "j/k move · < move to Action · M similar→FYI · d done · s snooze · / search"
        }
        Screen::Queue(_) => "j/k move · Enter inspect · d done · w waiting · s snooze · / search",
        Screen::Reader if app.reader_is_blocked() => {
            "↑/↓ previous/next · j/k scroll · Esc back · O inspect before reply · r reply"
        }
        Screen::Reader if app.previous_screen == Screen::SearchResults => {
            "↑/↓ previous/next result · j/k scroll · Tab links · Enter open · r reply · Esc results"
        }
        Screen::Reader if app.previous_screen == Screen::Queue(WorkflowView::WarmAction) => {
            "↑/↓ previous/next · j/k scroll · Tab links · Enter open · r reply · > FYI · Esc back"
        }
        Screen::Reader if app.previous_screen == Screen::Queue(WorkflowView::WarmFyi) => {
            "↑/↓ previous/next · j/k scroll · Tab links · Enter open · r reply · < Action · Esc back"
        }
        Screen::Reader => {
            "↑/↓ previous/next · j/k scroll · Tab/Shift-Tab links · Enter open · r reply · Esc back"
        }
        Screen::Compose => {
            "Tab/↑/↓ fields · Enter newline/next · Ctrl-S save draft · Ctrl-D send · Esc save/close"
        }
        Screen::SearchInput => "type query · Enter search · Esc cancel",
        Screen::SearchResults => "j/k move · Enter open exact match · / edit query · Esc back",
        Screen::Folders => {
            "j/k move · Enter open · b bind shortcut · n new · r rename · d delete · Esc back"
        }
        Screen::FolderBind => "press 5/6/7/8/9/0 to bind · Esc cancel",
        Screen::FolderMessages => "j/k move · Enter open exact message · Esc folders",
        Screen::FolderEdit => "type folder name · Enter save · Esc cancel",
        Screen::FolderDeleteConfirm => "type exact folder name · Enter delete · Esc cancel",
        Screen::Onboarding => "j/k move · y accept · n reject · e edit · Enter inspect/edit",
        Screen::OnboardingEdit => {
            "type name · Ctrl-R route · Ctrl-K kind · Enter save · Esc cancel"
        }
        Screen::Contacts => "j/k move · Enter/e edit contact · Esc back",
        Screen::ContactEdit => {
            "↑/↓ or Tab fields · type value · Space toggle · Ctrl-S save · Esc cancel"
        }
        Screen::Help => "Esc back",
    };
    let mut statuses = Vec::new();
    if let Some(status) = app.background_status.as_deref() {
        statuses.push(format!("Sync: {}", safe_single_line_text(status)));
    }
    if let Some(status) = app.reader_load_status() {
        statuses.push(format!("Reader: {}", safe_single_line_text(status)));
    }
    if let Some(status) = app.status.as_deref() {
        statuses.push(safe_single_line_text(status));
    }
    let mut lines = vec![Line::raw(commands)];
    if !statuses.is_empty() {
        lines.push(Line::raw(statuses.join("  │  ")));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn format_queue_timestamp(timestamp: i64) -> String {
    let Some(value) =
        DateTime::<Utc>::from_timestamp(timestamp, 0).map(|value| value.with_timezone(&Local))
    else {
        return "invalid date".into();
    };
    let now = Local::now();
    if value.year() == now.year() {
        value.format("%b %d %H:%M").to_string()
    } else {
        value.format("%Y-%m-%d %H:%M").to_string()
    }
}

fn format_full_timestamp(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| {
            value
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string()
        })
        .unwrap_or_else(|| "invalid date".into())
}

fn accent(app: &MailApp) -> Color {
    match app.screen {
        Screen::Queue(workflow) => accent_for_workflow(workflow),
        Screen::Onboarding | Screen::OnboardingEdit => COLD,
        Screen::Reader => app
            .current_thread
            .as_ref()
            .and_then(|thread| thread.messages.last())
            .map(|message| match message.summary.inbox_class {
                InboxClass::Warm => WARM,
                InboxClass::Cold => COLD,
                InboxClass::Spam => SPAM,
            })
            .unwrap_or(Color::Gray),
        Screen::Compose => WARM,
        Screen::SearchInput | Screen::SearchResults => Color::Gray,
        Screen::FolderDeleteConfirm => DANGER,
        Screen::Folders | Screen::FolderBind | Screen::FolderMessages | Screen::FolderEdit => {
            Color::Gray
        }
        Screen::AccountEdit => COLD,
        Screen::ContactEdit => WARM,
        Screen::AccountDeleteConfirm => DANGER,
        Screen::SimilarityPreview => WARM,
        _ => Color::Gray,
    }
}

fn accent_for_workflow(workflow: WorkflowView) -> Color {
    match workflow {
        WorkflowView::WarmAction | WorkflowView::WarmFyi => WARM,
        WorkflowView::ColdReview => COLD,
        WorkflowView::SpamQuarantine => SPAM,
        WorkflowView::Waiting | WorkflowView::Snoozed | WorkflowView::Done => Color::Gray,
    }
}

fn screen_title(app: &MailApp) -> &'static str {
    match app.screen {
        Screen::Accounts => "ACCOUNTS",
        Screen::AccountEdit => "ACCOUNT / MAIL CONNECTIONS",
        Screen::AccountDeleteConfirm => "ACCOUNT / CONFIRM REMOVAL",
        Screen::Onboarding => "ONBOARDING / CONTACT SUGGESTIONS",
        Screen::OnboardingEdit => "ONBOARDING / EDIT RELATIONSHIP",
        Screen::SimilarityPreview => "WARM / SIMILAR-MAIL PREVIEW",
        Screen::Queue(WorkflowView::WarmAction) => "WARM / ACTION",
        Screen::Queue(WorkflowView::WarmFyi) => "WARM / FYI",
        Screen::Queue(WorkflowView::ColdReview) => "COLD / REVIEW",
        Screen::Queue(WorkflowView::SpamQuarantine) => "SPAM / QUARANTINE",
        Screen::Queue(WorkflowView::Waiting) => "LATER / WAITING",
        Screen::Queue(WorkflowView::Snoozed) => "LATER / SNOOZED",
        Screen::Queue(WorkflowView::Done) => "DONE / HISTORY",
        Screen::Reader => match app.previous_screen {
            Screen::SearchResults => "SEARCH / MATCHED MESSAGE",
            Screen::FolderMessages => "FOLDER / MESSAGE",
            Screen::Queue(WorkflowView::WarmAction) => "WARM / ACTION / CONVERSATION",
            Screen::Queue(WorkflowView::WarmFyi) => "WARM / FYI / CONVERSATION",
            _ => app
                .current_thread
                .as_ref()
                .and_then(|thread| thread.messages.last())
                .map(|message| match message.summary.inbox_class {
                    InboxClass::Warm => "WARM / CONVERSATION",
                    InboxClass::Cold => "COLD / CONVERSATION",
                    InboxClass::Spam => "SPAM / CONVERSATION",
                })
                .unwrap_or("CONVERSATION"),
        },
        Screen::Compose => "WARM / REPLY",
        Screen::SearchInput => "SEARCH / QUERY",
        Screen::SearchResults => "SEARCH / RESULTS",
        Screen::Folders => "FOLDERS",
        Screen::FolderBind => "FOLDERS / BIND SHORTCUT",
        Screen::FolderMessages => "FOLDER / MESSAGES",
        Screen::FolderEdit => "FOLDERS / EDIT",
        Screen::FolderDeleteConfirm => "FOLDERS / CONFIRM DELETION",
        Screen::Contacts => "CONTACTS",
        Screen::ContactEdit => "CONTACTS / EDIT RELATIONSHIP",
        Screen::Help => "HELP",
    }
}

fn safe_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if matches!(character, '\n' | '\t') {
                character
            } else if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{feff}'
                        | '\u{2800}'
                )
            {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn safe_single_line_text(value: &str) -> String {
    safe_text(value)
        .chars()
        .map(|character| {
            if matches!(character, '\n' | '\t') {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_text_neutralizes_terminal_controls_and_bidi_overrides() {
        let sanitized =
            safe_single_line_text("safe\u{1b}[31m\u{202e}txt\u{2066}\u{200b}\u{2800}\nnext\tfield");

        assert_eq!(sanitized, "safe�[31m�txt��� next field");
        assert!(!sanitized.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        }));
    }

    #[test]
    fn navigation_places_amber_fyi_between_warm_and_cold() {
        let navigation = primary_navigation();
        let text = navigation
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let warm = text.find("1 Action").unwrap();
        let fyi = text.find("2 FYI").unwrap();
        let cold = text.find("3 Cold").unwrap();
        assert!(warm < fyi && fyi < cold);

        let fyi = navigation
            .spans
            .iter()
            .find(|span| span.content.contains("FYI"))
            .unwrap();
        assert_eq!(fyi.style.fg, None);
        let shortcut = navigation
            .spans
            .iter()
            .find(|span| span.content == "2")
            .unwrap();
        assert_eq!(shortcut.style.fg, Some(FYI_HINT));
        assert_eq!(accent_for_workflow(WorkflowView::WarmFyi), WARM);
    }

    #[test]
    fn folder_shortcut_labels_keep_eight_columns_then_show_an_ellipsis() {
        assert_eq!(truncate_columns("Receipts and statements", 8), "Receipts…");
        assert_eq!(truncate_columns("Inbox", 8), "Inbox");
        assert_eq!(truncate_columns("界界界界界", 8), "界界界界…");
    }

    #[test]
    fn search_result_identity_preserves_each_inbox_color() {
        assert_eq!(search_result_identity(InboxClass::Warm), ("WARM", WARM));
        assert_eq!(search_result_identity(InboxClass::Cold), ("COLD", COLD));
        assert_eq!(search_result_identity(InboxClass::Spam), ("SPAM", SPAM));
    }

    #[test]
    fn unknown_identity_wrapping_never_discards_address_characters() {
        let address = concat!(
            "sender@my.preceding.subdomain.crap.",
            "myreallylongdomainchase.com"
        );
        let wrapped = wrap_untrusted_identity(address, 24);

        assert!(wrapped.len() > 1);
        assert_eq!(wrapped.concat(), address);
        assert!(wrapped.iter().all(|line| line
            .chars()
            .map(|ch| ch.width().unwrap_or(1))
            .sum::<usize>()
            <= 24));
    }

    #[test]
    fn domain_signature_selects_only_a_passing_aligned_signature() {
        let signature =
            |status, aligned, domain: &str| lizard_mail_backend::DkimSignatureEvidence {
                header_index: None,
                status,
                reason_code: None,
                reason: None,
                signing_domain: Some(domain.into()),
                selector: None,
                identity: None,
                algorithm: None,
                signed_headers: Vec::new(),
                from_domain_aligned: aligned,
                key_bits: None,
                key_testing: false,
                raw_header_value: None,
            };
        let mut signatures = vec![
            signature(DkimSignatureStatus::Fail, Some(true), "failed.example"),
            signature(DkimSignatureStatus::Pass, Some(false), "relay.example"),
            signature(DkimSignatureStatus::Pass, Some(true), "author.example"),
        ];
        signatures[0].reason = Some("Calculated body hash does not match signature hash".into());

        assert_eq!(aligned_dkim_domain(&signatures), Some("author.example"));
        assert_eq!(
            dkim_signature_description(&signatures[0]),
            "A signature claiming failed.example failed verification: Calculated body hash does not match signature hash"
        );
        assert_eq!(
            dkim_signature_description(&signatures[1]),
            "relay.example signed this message, but does not match the visible From domain"
        );
        assert_eq!(
            dkim_signature_description(&signatures[2]),
            "author.example signed this message and matches the visible From domain"
        );
        let mut neutral = signature(
            DkimSignatureStatus::Neutral,
            Some(false),
            "mailing-list.example",
        );
        neutral.reason = Some("Unsupported algorithm in DKIM Signature".into());
        assert_eq!(
            dkim_signature_description(&neutral),
            "A signature claiming mailing-list.example did not verify: Unsupported algorithm in DKIM Signature"
        );
        neutral.reason = None;
        assert_eq!(
            dkim_signature_description(&neutral),
            "A signature claiming mailing-list.example did not verify, but the verifier gave no specific reason"
        );
    }

    #[test]
    fn timestamps_include_clock_time_and_full_reader_date() {
        let queue = format_queue_timestamp(1_700_000_000);
        let reader = format_full_timestamp(1_700_000_000);

        assert!(queue.contains(':'), "queue timestamp must include a time");
        assert!(reader.starts_with("2023-"));
        assert!(reader.matches('-').count() >= 2);
        assert!(reader.contains(':'));
        assert_ne!(queue, "invalid date");
    }

    #[test]
    fn security_levels_have_distinct_labels_and_visual_weight() {
        let (danger_label, danger) = finding_visual_style(FindingSeverity::Danger);
        let (warning_label, warning) = finding_visual_style(FindingSeverity::Warning);

        assert_eq!(danger_label, "HIGH RISK");
        assert_eq!(danger.bg, None);
        assert_eq!(danger.fg, Some(DANGER));
        assert_eq!(warning_label, "CAUTION");
        assert_eq!(warning.bg, None);
        assert_eq!(warning.fg, Some(FYI_HINT));
    }

    #[test]
    fn unaligned_dkim_copy_names_the_expected_and_actual_domains() {
        let mut finding = HeuristicFinding {
            id: lizard_mail_backend::FindingId::new(),
            message_id: lizard_mail_backend::MessageId::new(),
            heuristic_id: lizard_mail_backend::HeuristicId::new(),
            heuristic_version: 5,
            code: "unaligned_dkim".into(),
            presentation: lizard_mail_backend::FindingPresentation::OpenInterstitial,
            severity: FindingSeverity::Warning,
            target_kind: FindingTargetKind::Message,
            target_id: None,
            text: None,
            evidence: serde_json::json!({
                "from_domain": "expected.example",
                "signing_domains": ["actual.example"],
            }),
            source_kind: lizard_mail_backend::HeuristicSourceKind::BuiltIn,
            created_at: 0,
            dismissed_at: None,
        };

        assert_eq!(
            finding_summary(&finding),
            "Expected a signature from expected.example, but the valid signature came from actual.example"
        );
        finding.code = "missing_aligned_dkim".into();
        finding.evidence = serde_json::json!({
            "from_domain": "expected.example",
            "status": "failed",
            "claimed_signing_domains": ["mailing-list.example"],
        });
        assert_eq!(
            finding_summary(&finding),
            "A signature claiming mailing-list.example failed verification; a valid signature from expected.example was expected"
        );
    }

    #[test]
    fn message_body_wrapping_produces_exact_scroll_rows() {
        let lines = wrap_message_body("abcdef\nxy", 3)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();

        assert_eq!(lines, ["abc", "def", "xy"]);
    }

    #[tokio::test]
    async fn link_findings_are_summarized_at_top_and_explained_at_the_target() {
        let profile = tempfile::tempdir().unwrap();
        let backend = lizard_mail_backend::Backend::open(lizard_mail_backend::BackendConfig::new(
            profile.path(),
        ))
        .await
        .unwrap();
        let html = concat!(
            "<table><tr><td>Reset your password using ",
            "<a href='https://evil.example.net/login'>https://login.example.com</a>",
            " before noon to retain access.</td></tr></table>"
        );
        let raw = format!(
            concat!(
                "From: Accounts <notice@example.com>\r\n",
                "To: reader@example.test\r\n",
                "Subject: Reset your password\r\n",
                "Content-Type: text/html; charset=utf-8\r\n\r\n",
                "{}"
            ),
            html
        );
        let id = backend
            .ingest(lizard_mail_backend::IngestMessage::local(raw.into_bytes()))
            .await
            .unwrap();
        let message = backend.messages().get(id).await.unwrap();
        let page = crate::HtmlRenderer::default()
            .render(html.as_bytes(), 80, &crate::RenderOptions::default())
            .unwrap();

        let mut top = Vec::new();
        append_finding_lines(&mut top, &message, 12, 100, "in the restricted message");
        let top = top
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(top.contains("Misleading or disguised links"));
        assert!(!top.contains("link text says"));

        let annotated_lines =
            annotated_rendered_message_lines(&page, &message, 100, false, None, &mut Vec::new());
        let annotated = annotated_lines
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>();
        let warning = annotated
            .iter()
            .position(|line| {
                line.contains(
                    "The link text says login.example.com, but the link actually opens evil.example.net",
                )
            })
            .expect("the exact mismatch should be stated");
        let destination = annotated
            .iter()
            .position(|line| line.contains("1. https://evil.example.net/login"))
            .expect("the numbered destination should remain visible");
        let context = annotated
            .iter()
            .position(|line| {
                line.contains(
                    "Context: Reset your password using https://login.example.com before noon to retain access.",
                )
            })
            .expect("the surrounding link text should be repeated beside the destination");
        assert!(warning < context && context < destination);
        assert_eq!(annotated_lines[context].style.fg, Some(Color::White));

        let mut rebuilt_projection = message.clone();
        rebuilt_projection
            .findings
            .retain(|finding| finding.code == "misleading_link_text");
        for (ordinal, link) in rebuilt_projection.links.iter_mut().enumerate() {
            link.id = format!("rebuilt-link:{ordinal}");
        }
        let rebuilt = annotated_rendered_message_lines(
            &page,
            &rebuilt_projection,
            100,
            false,
            None,
            &mut Vec::new(),
        )
        .iter()
        .map(rendered_line_text)
        .collect::<Vec<_>>()
        .join("\n");
        assert!(rebuilt.contains(
            "The link text says login.example.com, but the link actually opens evil.example.net"
        ));
        assert!(!rebuilt.contains("could not safely identify"));

        let mut unresolved = rebuilt_projection;
        unresolved.findings[0].evidence["destination"] =
            serde_json::json!("https://unmatched.example.test/");
        let unresolved =
            annotated_rendered_message_lines(&page, &unresolved, 100, false, None, &mut Vec::new())
                .iter()
                .map(rendered_line_text)
                .collect::<Vec<_>>()
                .join("\n");
        let unresolved = unresolved.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(unresolved.contains("could not safely identify which displayed link"));
        assert!(unresolved.contains("Treat every link below as suspicious"));

        let restricted =
            annotated_rendered_message_lines(&page, &message, 100, true, None, &mut Vec::new());
        let restricted = restricted
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(restricted.contains("This email was not signed by example.com."));
        assert!(restricted.contains("spaces have been added to every address"));
        assert!(restricted.contains(
            "The link text says login.example.com, but the link actually opens evil.example.net"
        ));
        assert!(restricted.contains(
            "Context: Reset your password using https: / / login. example. com before noon to retain access."
        ));
        assert!(restricted.contains("https: / / evil. example. net/ login"));
        assert!(!restricted.contains("https://"));
    }

    #[test]
    fn link_context_is_bounded_to_neighboring_words() {
        let text = "zero one two three four five six https://example.test seven eight nine ten eleven twelve thirteen";
        let start = text.find("https://example.test").unwrap();
        let context =
            bounded_surrounding_words(text, start, start + "https://example.test".len()).unwrap();

        assert_eq!(
            context,
            "… one two three four five six seven eight nine ten eleven twelve …"
        );
    }

    #[test]
    fn restricted_destinations_are_inert_and_exactly_recoverable() {
        let original =
            "https://user@example.com/reset?next=https%3A%2F%2Faccounts.example.com&id=7";
        let defanged = defang_destination(original);

        assert_eq!(defanged.replace(' ', ""), original);
        assert!(!defanged.contains("://"));
        assert!(!defanged.contains("example.com"));
        assert!(!defanged.contains("user@example"));
    }
}
