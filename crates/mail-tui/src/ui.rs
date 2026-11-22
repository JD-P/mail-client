use crate::app::{AccountAuthentication, AccountField, ContactField, MailApp, Screen};
use crate::{LinkKind, LinkReference, RenderedPage};
use chrono::{DateTime, Datelike, Local, Utc};
use lizard_mail_backend::{
    AuthenticationMethodKind, AuthenticationMethodResult, AuthenticationResultsTrust,
    DkimAuthenticationStatus, DkimSignatureStatus, FindingSeverity, FindingTargetKind,
    HeuristicFinding, ImapSecurity, InboxClass, Message, MessageContentAvailability, MessageLink,
    OpenPgpBindingState, OpenPgpEncryptionStatus, OpenPgpSignatureStatus, RelationshipKind,
    RemoteContentPolicy, ThreadWorkStatus, WarmRoute, WorkflowView,
};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use ratatui::Frame;
use std::collections::{BTreeMap, BTreeSet};
use unicode_width::UnicodeWidthChar;
use url::Url;

const WARM: Color = Color::Rgb(198, 48, 67);
const FYI_HINT: Color = Color::Rgb(222, 143, 43);
const COLD: Color = Color::Rgb(57, 132, 219);
const SPAM: Color = Color::Rgb(212, 169, 50);
const DANGER: Color = Color::Rgb(235, 65, 83);

pub fn draw(frame: &mut Frame<'_>, app: &MailApp) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
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
        Screen::Contacts => draw_contacts(frame, app, areas[1]),
        Screen::ContactEdit => draw_contact_editor(frame, app, areas[1]),
        Screen::Help => draw_help(frame, areas[1]),
    }
    draw_footer(frame, app, areas[2]);
}

fn draw_header(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let accent = accent(app);
    let title = format!(" LIZARD MAIL · {} ", screen_title(app));
    let navigation = header_navigation();
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

fn header_navigation() -> Line<'static> {
    Line::from(vec![
        Span::styled("1", Style::default().fg(WARM).add_modifier(Modifier::BOLD)),
        Span::raw(" Action  "),
        Span::styled(
            "F FYI",
            Style::default().fg(FYI_HINT).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("2", Style::default().fg(COLD).add_modifier(Modifier::BOLD)),
        Span::raw(" Cold  "),
        Span::styled("3", Style::default().fg(SPAM).add_modifier(Modifier::BOLD)),
        Span::raw(" Spam  L Later  C Contacts  A Accounts  ? Help"),
    ])
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
        "Connect an existing mailbox. Lizard makes headers usable first, then downloads and verifies a full local copy in bounded batches inside an isolated process. Ordinary plaintext IMAP is not supported."
    } else {
        "Update this account's IMAP connection. Leave the secret unchanged to retain the stored credential. Saving tests the new settings with an isolated synchronization."
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

fn draw_reader(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
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

    let (title, body_lines) = if let Some(page) = app.reader_html() {
        let title = if app.security_override {
            "Message · RESTRICTED VIEW · links disabled"
        } else {
            "Message"
        };
        (
            title,
            annotated_rendered_message_lines(page, message, inner_width),
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
        append_backend_link_section(&mut lines, message, width);
        (title, lines)
    };
    let border_color = accent(app);
    draw_scrolling_panel(frame, app, chunks[1], title, body_lines, border_color);
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
    if let Some(domain) = aligned_dkim_domain(&message.dkim.signatures) {
        return format!("This message was signed by {domain}");
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
            Style::default()
                .bg(DANGER)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
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
        "reply_to_mismatch" =>
            "A reply would be sent somewhere other than the visible From address".into(),
        "conversation_injection" =>
            "An unknown sender claims to belong to an established conversation".into(),
        "unaligned_dkim" =>
            "A DKIM signature passed, but it does not establish the visible From domain".into(),
        "missing_aligned_dkim" => match string("status").as_deref() {
            Some("unsigned") => format!(
                "{} did not attach a DKIM signature",
                string("from_domain").unwrap_or_else(|| "The visible From domain".into()),
            ),
            Some("failed") => format!(
                "A DKIM signature was present but failed verification for {}",
                string("from_domain").unwrap_or_else(|| "the visible From domain".into()),
            ),
            Some("temporary_failure") =>
                "DKIM verification is temporarily unavailable".into(),
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
) -> Vec<Line<'static>> {
    if page.links.is_empty() {
        return page.lines.clone();
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
    append_section_break(&mut lines);
    lines.push(Line::styled(
        "Links and safety",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    for link in &page.links {
        let targets = message
            .links
            .iter()
            .filter(|message_link| message_link_matches_reference(message_link, link))
            .map(|message_link| message_link.id.clone())
            .collect::<BTreeSet<_>>();
        append_targeted_link_findings(&mut lines, message, &targets, width);
        append_wrapped_styled(
            &mut lines,
            &format!("{}. {}", link.number, rendered_link_destination(link)),
            width,
            Style::default().fg(Color::Cyan),
        );
    }
    lines
}

fn append_backend_link_section(lines: &mut Vec<Line<'static>>, message: &Message, width: usize) {
    if message.links.is_empty() {
        return;
    }
    append_section_break(lines);
    lines.push(Line::styled(
        "Links and safety",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    for link in &message.links {
        let targets = BTreeSet::from([link.id.clone()]);
        append_targeted_link_findings(lines, message, &targets, width);
        let destination = if matches!(link.scheme.as_str(), "http" | "https" | "mailto" | "cid") {
            safe_single_line_text(&link.destination)
        } else {
            format!("[blocked {} link]", safe_single_line_text(&link.scheme))
        };
        append_wrapped_styled(
            lines,
            &format!("{}. {destination}", link.ordinal.saturating_add(1)),
            width,
            Style::default().fg(Color::Cyan),
        );
    }
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
            "1 Warm Action · F Warm FYI · 2 Cold · 3 Spam · L Waiting · Z Snoozed · D Done",
        ),
        Line::raw("C Contacts · A Accounts · ? Help · q Quit · Esc Back"),
        Line::raw(""),
        Line::styled(
            "Queues and reader",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw("Queue: j/k Move · Enter Open · d Done · w Waiting · s Snooze one day"),
        Line::raw(
            "Reader: ↑/↓ Previous/next email · j/k Scroll · PgUp/PgDn Page · g/G Top/bottom",
        ),
        Line::raw(
            "a Make Cold conversation actionable once · O Read through security warning with restrictions",
        ),
        Line::raw(
            "< Move conversation to FYI · > Move conversation to Action · M Preview this-and-similar → FYI",
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
            "j/k move · Enter inspect · a actionable once · d done · s snooze · ? help"
        }
        Screen::Queue(WorkflowView::SpamQuarantine) => {
            "j/k move · Enter inspect safely · d done · ? help"
        }
        Screen::Queue(_) => {
            "j/k move · </> FYI/Action · M similar→FYI · d done · w waiting · s snooze"
        }
        Screen::Reader if app.reader_is_blocked() => {
            "↑/↓ previous/next email · j/k scroll · PgUp/PgDn page · Esc back · O read restricted"
        }
        Screen::Reader => {
            "↑/↓ previous/next email · j/k scroll · PgUp/PgDn page · </> FYI/Action · Esc back"
        }
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
        Screen::AccountEdit => "ACCOUNT / IMAP CONNECTION",
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
        let navigation = header_navigation();
        let text = navigation
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let warm = text.find("1 Action").unwrap();
        let fyi = text.find("F FYI").unwrap();
        let cold = text.find("2 Cold").unwrap();
        assert!(warm < fyi && fyi < cold);

        let fyi = navigation
            .spans
            .iter()
            .find(|span| span.content == "F FYI")
            .unwrap();
        assert_eq!(fyi.style.fg, Some(FYI_HINT));
        assert_eq!(accent_for_workflow(WorkflowView::WarmFyi), WARM);
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
        let signatures = vec![
            signature(DkimSignatureStatus::Fail, Some(true), "failed.example"),
            signature(DkimSignatureStatus::Pass, Some(false), "relay.example"),
            signature(DkimSignatureStatus::Pass, Some(true), "author.example"),
        ];

        assert_eq!(aligned_dkim_domain(&signatures), Some("author.example"));
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
        assert_eq!(danger.bg, Some(DANGER));
        assert_eq!(warning_label, "CAUTION");
        assert_eq!(warning.bg, None);
        assert_eq!(warning.fg, Some(FYI_HINT));
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
            "<p>Reset your password.</p>",
            "<a href='https://evil.example.net/login'>https://login.example.com</a>"
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

        let annotated = annotated_rendered_message_lines(&page, &message, 100)
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
        assert!(warning < destination);
    }
}
