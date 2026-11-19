use crate::app::{MailApp, Screen};
use crate::{HtmlRenderer, RenderOptions};
use lizard_mail_backend::{DkimAuthenticationStatus, ThreadWorkStatus, WorkflowView};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

const WARM: Color = Color::Rgb(198, 48, 67);
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
        Screen::Onboarding => draw_onboarding(frame, app, areas[1]),
        Screen::OnboardingEdit => draw_onboarding_edit(frame, app, areas[1]),
        Screen::Queue(_) => draw_queue(frame, app, areas[1]),
        Screen::Reader => draw_reader(frame, app, areas[1]),
        Screen::Contacts => draw_contacts(frame, app, areas[1]),
        Screen::Help => draw_help(frame, areas[1]),
    }
    draw_footer(frame, app, areas[2]);
}

fn draw_header(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let accent = accent(app.screen);
    let title = format!(" LIZARD MAIL · {} ", screen_title(app.screen));
    let navigation = Line::from(vec![
        Span::styled("1", Style::default().fg(WARM).add_modifier(Modifier::BOLD)),
        Span::raw(" Warm  "),
        Span::styled("2", Style::default().fg(COLD).add_modifier(Modifier::BOLD)),
        Span::raw(" Cold  "),
        Span::styled("3", Style::default().fg(SPAM).add_modifier(Modifier::BOLD)),
        Span::raw(" Spam  F FYI  L Later  C Contacts  ? Help"),
    ]);
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

fn draw_queue(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let workflow = match app.screen {
        Screen::Queue(workflow) => workflow,
        _ => return,
    };
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
            area,
        );
        return;
    }
    let items = app
        .threads
        .iter()
        .map(|thread| {
            let unread = if thread.unread_count > 0 { "●" } else { " " };
            let sender = thread
                .participants
                .first()
                .map(String::as_str)
                .unwrap_or("unknown sender");
            let subject = thread.subject.as_deref().unwrap_or("(no subject)");
            let sender = safe_single_line_text(sender);
            let subject = safe_single_line_text(subject);
            let state = match thread.work_state.status {
                ThreadWorkStatus::Active => "",
                ThreadWorkStatus::Waiting => " [waiting]",
                ThreadWorkStatus::Snoozed => " [snoozed]",
                ThreadWorkStatus::Done => " [done]",
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{unread} "),
                    Style::default().fg(accent(app.screen)),
                ),
                Span::styled(
                    format!("{sender:<28.28}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {subject}{state}")),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.selected));
    let title = format!("{} conversations", app.threads.len());
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(accent(app.screen))
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn draw_reader(frame: &mut Frame<'_>, app: &MailApp, area: Rect) {
    let Some(thread) = &app.current_thread else {
        frame.render_widget(Paragraph::new("No conversation selected"), area);
        return;
    };
    let Some(message) = thread.messages.last() else {
        frame.render_widget(Paragraph::new("Conversation contains no messages"), area);
        return;
    };
    if app.reader_is_blocked() {
        let text = Text::from(vec![
            Line::styled(
                "SECURITY WARNING — MESSAGE BODY BLOCKED",
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(
                "The client found security evidence that must not be hidden in a detail pane.",
            ),
            Line::raw("Go back unless you have a specific reason to inspect this message."),
            Line::raw(""),
            Line::styled(
                "If you continue, links and remote content remain disabled.",
                Style::default().fg(DANGER),
            ),
            Line::raw(
                "Use a bookmark, official app, or an address you already know; do not copy a site address from this email.",
            ),
            Line::raw(""),
            Line::raw("[Esc] Back   [O] Read restricted"),
        ]);
        frame.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .title("Intrusive security interruption")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(DANGER)),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }

    let sender = app.display_sender(
        message.summary.from_address.as_deref(),
        message.summary.from_name.as_deref(),
    );
    let dkim = match message.dkim.status {
        DkimAuthenticationStatus::Pass => message
            .dkim
            .signatures
            .iter()
            .find_map(|signature| signature.signing_domain.as_deref())
            .map(|domain| format!("Signed by {domain}"))
            .unwrap_or_else(|| "Signed message".into()),
        DkimAuthenticationStatus::Unsigned => "No DKIM signature".into(),
        DkimAuthenticationStatus::Failed => "DKIM verification failed".into(),
        DkimAuthenticationStatus::TemporaryFailure => "DKIM temporarily unavailable".into(),
        DkimAuthenticationStatus::NotEvaluated => "DKIM not evaluated".into(),
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(4)])
        .split(area);
    let header = Text::from(vec![
        Line::from(vec![
            Span::styled("From: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(safe_text(&sender)),
        ]),
        Line::from(vec![
            Span::styled("Subject: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(safe_text(
                message.summary.subject.as_deref().unwrap_or("(no subject)"),
            )),
        ]),
        Line::from(vec![
            Span::styled("Identity: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(safe_single_line_text(&dkim)),
        ]),
        Line::from(vec![
            Span::styled("Work: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{:?}", thread.summary.work_state.status)),
        ]),
    ]);
    frame.render_widget(
        Paragraph::new(header).block(Block::default().borders(Borders::ALL).title("Conversation")),
        chunks[0],
    );

    if let Some(html) = &message.body_html {
        match HtmlRenderer::default().render(
            html.as_bytes(),
            chunks[1].width.saturating_sub(2),
            &RenderOptions::default(),
        ) {
            Ok(page) => frame.render_widget(
                Paragraph::new(page.lines)
                    .block(Block::default().borders(Borders::ALL).title("Message"))
                    .wrap(Wrap { trim: false }),
                chunks[1],
            ),
            Err(_) => frame.render_widget(
                Paragraph::new(safe_text(&message.body_text))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Message · plain fallback"),
                    )
                    .wrap(Wrap { trim: false }),
                chunks[1],
            ),
        }
    } else {
        frame.render_widget(
            Paragraph::new(safe_text(&message.body_text))
                .block(Block::default().borders(Borders::ALL).title("Message"))
                .wrap(Wrap { trim: false }),
            chunks[1],
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
            ListItem::new(format!(
                "{} claims to be {}  · {} messages · {:?}",
                safe_single_line_text(&suggestion.address),
                safe_single_line_text(name),
                suggestion.message_count,
                suggestion.suggested_warm_route
            ))
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
            ListItem::new(format!(
                "{}  <{}>",
                safe_single_line_text(&contact.display_name),
                safe_single_line_text(&addresses)
            ))
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

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let text = Text::from(vec![
        Line::styled("Global", Style::default().add_modifier(Modifier::BOLD)),
        Line::raw(
            "1 Warm Action · F Warm FYI · 2 Cold · 3 Spam · L Waiting · Z Snoozed · D Done",
        ),
        Line::raw("C Contacts · ? Help · q Quit · Esc Back"),
        Line::raw(""),
        Line::styled(
            "Queues and reader",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw("j/k Move · Enter Open · d Done · w Waiting · s Snooze one day"),
        Line::raw(
            "a Make Cold conversation actionable once · O Read through security warning with restrictions",
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
        Screen::Queue(WorkflowView::ColdReview) => {
            "j/k move · Enter inspect · a actionable once · d done · s snooze · ? help"
        }
        Screen::Queue(_) => "j/k move · Enter open · d done · w waiting · s snooze · ? help",
        Screen::Reader if app.reader_is_blocked() => {
            "Esc back · O read restricted · ? evidence/help"
        }
        Screen::Reader => "d done · w waiting · s snooze · a actionable once (Cold) · Esc back",
        Screen::Onboarding => "j/k move · y accept · n reject · e edit · Enter inspect/edit",
        Screen::OnboardingEdit => {
            "type name · Ctrl-R route · Ctrl-K kind · Enter save · Esc cancel"
        }
        Screen::Contacts => "j/k move · Esc back",
        Screen::Help => "Esc back",
    };
    let line = if let Some(status) = &app.status {
        format!("{commands}  │  {}", safe_single_line_text(status))
    } else {
        commands.to_owned()
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn accent(screen: Screen) -> Color {
    match screen {
        Screen::Queue(WorkflowView::WarmAction | WorkflowView::WarmFyi) => WARM,
        Screen::Queue(WorkflowView::ColdReview) | Screen::Onboarding | Screen::OnboardingEdit => {
            COLD
        }
        Screen::Queue(WorkflowView::SpamQuarantine) => SPAM,
        _ => Color::Gray,
    }
}

fn screen_title(screen: Screen) -> &'static str {
    match screen {
        Screen::Onboarding => "ONBOARDING / CONTACT SUGGESTIONS",
        Screen::OnboardingEdit => "ONBOARDING / EDIT RELATIONSHIP",
        Screen::Queue(WorkflowView::WarmAction) => "WARM / ACTION",
        Screen::Queue(WorkflowView::WarmFyi) => "WARM / FYI",
        Screen::Queue(WorkflowView::ColdReview) => "COLD / REVIEW",
        Screen::Queue(WorkflowView::SpamQuarantine) => "SPAM / QUARANTINE",
        Screen::Queue(WorkflowView::Waiting) => "LATER / WAITING",
        Screen::Queue(WorkflowView::Snoozed) => "LATER / SNOOZED",
        Screen::Queue(WorkflowView::Done) => "DONE / HISTORY",
        Screen::Reader => "CONVERSATION",
        Screen::Contacts => "CONTACTS",
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
                    '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
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
        let sanitized = safe_single_line_text("safe\u{1b}[31m\u{202e}txt\u{2066}\nnext\tfield");

        assert_eq!(sanitized, "safe�[31m�txt� next field");
        assert!(!sanitized.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        }));
    }
}
