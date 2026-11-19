use chrono::{Duration, Utc};
use lizard_mail_backend::{
    AccountId, Backend, Contact, ContactAddress, ContactSuggestion, FindingPresentation,
    FindingSeverity, NewContact, NewContactRelationship, RelationshipKind, RemoteContentPolicy,
    Result, Thread, ThreadFilter, ThreadSummary, ThreadWorkStatus, WarmRoute, WorkflowView,
};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Onboarding,
    OnboardingEdit,
    Queue(WorkflowView),
    Reader,
    Contacts,
    Help,
}

#[derive(Clone, Debug)]
pub struct OnboardingEdit {
    pub display_name: String,
    pub relationship: NewContactRelationship,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppCommand {
    Quit,
    Next,
    Previous,
    Open,
    Back,
    WarmAction,
    WarmFyi,
    Cold,
    Spam,
    Waiting,
    Snoozed,
    Done,
    Contacts,
    Help,
    MarkDone,
    MarkWaiting,
    SnoozeOneDay,
    MakeActionableOnce,
    RestrictedOpen,
    OnboardingAccept,
    OnboardingDismiss,
    OnboardingEdit,
    OnboardingSaveEdit,
    OnboardingToggleRoute,
    OnboardingCycleKind,
    EditBackspace,
    EditCharacter(char),
}

pub struct MailApp {
    pub backend: Backend,
    pub screen: Screen,
    pub previous_screen: Screen,
    pub threads: Vec<ThreadSummary>,
    pub selected: usize,
    pub current_thread: Option<Thread>,
    pub onboarding_account: Option<AccountId>,
    pub suggestions: Vec<ContactSuggestion>,
    pub onboarding_edit: Option<OnboardingEdit>,
    pub contacts: Vec<Contact>,
    pub contact_names: HashMap<String, String>,
    pub status: Option<String>,
    pub security_override: bool,
    pub quit: bool,
}

impl MailApp {
    pub async fn open(backend: Backend) -> Result<Self> {
        let accounts = backend.accounts().list().await?;
        let contacts = backend.contacts().list().await?;
        let onboarding_account = accounts.first().map(|account| account.id);
        let suggestions = if contacts.is_empty() {
            if let Some(account_id) = onboarding_account {
                backend
                    .onboarding()
                    .contact_suggestions(
                        account_id,
                        (Utc::now() - Duration::days(183)).timestamp(),
                        20,
                    )
                    .await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let screen = if suggestions.is_empty() {
            Screen::Queue(WorkflowView::WarmAction)
        } else {
            Screen::Onboarding
        };
        let mut app = Self {
            backend,
            screen,
            previous_screen: Screen::Queue(WorkflowView::WarmAction),
            threads: Vec::new(),
            selected: 0,
            current_thread: None,
            onboarding_account,
            suggestions,
            onboarding_edit: None,
            contacts,
            contact_names: HashMap::new(),
            status: None,
            security_override: false,
            quit: false,
        };
        app.rebuild_contact_names();
        app.refresh().await?;
        Ok(app)
    }

    pub async fn refresh(&mut self) -> Result<()> {
        match self.screen {
            Screen::Queue(workflow) => {
                self.threads = self
                    .backend
                    .threads()
                    .list(ThreadFilter {
                        workflow: Some(workflow),
                        page_size: 200,
                        ..ThreadFilter::default()
                    })
                    .await?
                    .items;
                self.clamp_selection();
            }
            Screen::Contacts => {
                self.contacts = self.backend.contacts().list().await?;
                self.rebuild_contact_names();
                self.clamp_selection();
            }
            Screen::Reader => {
                if let Some(thread) = &self.current_thread {
                    self.current_thread =
                        Some(self.backend.threads().get(thread.summary.id).await?);
                }
            }
            Screen::Onboarding | Screen::OnboardingEdit | Screen::Help => {}
        }
        Ok(())
    }

    pub async fn dispatch(&mut self, command: AppCommand) -> Result<()> {
        self.status = None;
        match command {
            AppCommand::Quit => self.quit = true,
            AppCommand::Next => self.move_selection(1),
            AppCommand::Previous => self.move_selection(-1),
            AppCommand::Back => self.go_back().await?,
            AppCommand::Open => self.open_selected().await?,
            AppCommand::WarmAction => self.switch_queue(WorkflowView::WarmAction).await?,
            AppCommand::WarmFyi => self.switch_queue(WorkflowView::WarmFyi).await?,
            AppCommand::Cold => self.switch_queue(WorkflowView::ColdReview).await?,
            AppCommand::Spam => self.switch_queue(WorkflowView::SpamQuarantine).await?,
            AppCommand::Waiting => self.switch_queue(WorkflowView::Waiting).await?,
            AppCommand::Snoozed => self.switch_queue(WorkflowView::Snoozed).await?,
            AppCommand::Done => self.switch_queue(WorkflowView::Done).await?,
            AppCommand::Contacts => {
                self.previous_screen = self.screen;
                self.screen = Screen::Contacts;
                self.selected = 0;
                self.refresh().await?;
            }
            AppCommand::Help => {
                self.previous_screen = self.screen;
                self.screen = Screen::Help;
            }
            AppCommand::MarkDone => self.set_selected_work_state(ThreadWorkStatus::Done).await?,
            AppCommand::MarkWaiting => {
                self.set_selected_work_state(ThreadWorkStatus::Waiting)
                    .await?
            }
            AppCommand::SnoozeOneDay => self.snooze_selected().await?,
            AppCommand::MakeActionableOnce => self.make_actionable_once().await?,
            AppCommand::RestrictedOpen => {
                if self.screen == Screen::Reader {
                    self.security_override = true;
                }
            }
            AppCommand::OnboardingAccept => self.accept_suggestion(None).await?,
            AppCommand::OnboardingDismiss => self.dismiss_suggestion().await?,
            AppCommand::OnboardingEdit => self.begin_suggestion_edit(),
            AppCommand::OnboardingSaveEdit => {
                let edit = self.onboarding_edit.take();
                self.accept_suggestion(edit).await?;
            }
            AppCommand::OnboardingToggleRoute => self.toggle_onboarding_route(),
            AppCommand::OnboardingCycleKind => self.cycle_onboarding_kind(),
            AppCommand::EditBackspace => {
                if let Some(edit) = &mut self.onboarding_edit {
                    edit.display_name.pop();
                }
            }
            AppCommand::EditCharacter(character) => {
                if let Some(edit) = &mut self.onboarding_edit {
                    if !character.is_control() && edit.display_name.len() < 200 {
                        edit.display_name.push(character);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn selected_thread(&self) -> Option<&ThreadSummary> {
        self.threads.get(self.selected)
    }

    pub fn selected_suggestion(&self) -> Option<&ContactSuggestion> {
        self.suggestions.get(self.selected)
    }

    pub fn reader_is_blocked(&self) -> bool {
        if self.security_override {
            return false;
        }
        self.current_thread
            .as_ref()
            .and_then(|thread| thread.messages.last())
            .is_some_and(|message| {
                message.findings.iter().any(|finding| {
                    finding.dismissed_at.is_none()
                        && finding.presentation == FindingPresentation::OpenInterstitial
                        && finding.severity >= FindingSeverity::Warning
                })
            })
    }

    pub fn display_sender(&self, address: Option<&str>, claimed_name: Option<&str>) -> String {
        let Some(address) = address else {
            return "unknown sender".into();
        };
        if let Some(name) = self.contact_names.get(&address.to_lowercase()) {
            return format!("{name} <{address}>");
        }
        match claimed_name.filter(|name| !name.trim().is_empty()) {
            Some(name) => format!("{address} claims to be {name}"),
            None => address.to_owned(),
        }
    }

    async fn switch_queue(&mut self, workflow: WorkflowView) -> Result<()> {
        self.screen = Screen::Queue(workflow);
        self.previous_screen = self.screen;
        self.selected = 0;
        self.current_thread = None;
        self.security_override = false;
        self.refresh().await
    }

    async fn open_selected(&mut self) -> Result<()> {
        match self.screen {
            Screen::Queue(_) => {
                if let Some(id) = self.selected_thread().map(|summary| summary.id) {
                    self.previous_screen = self.screen;
                    self.current_thread = Some(self.backend.threads().get(id).await?);
                    self.screen = Screen::Reader;
                    self.security_override = false;
                }
            }
            Screen::Onboarding => self.begin_suggestion_edit(),
            _ => {}
        }
        Ok(())
    }

    async fn go_back(&mut self) -> Result<()> {
        match self.screen {
            Screen::Reader | Screen::Contacts | Screen::Help => {
                self.screen = self.previous_screen;
                self.current_thread = None;
                self.security_override = false;
                self.refresh().await?;
            }
            Screen::OnboardingEdit => {
                self.onboarding_edit = None;
                self.screen = Screen::Onboarding;
            }
            _ => {}
        }
        Ok(())
    }

    async fn set_selected_work_state(&mut self, status: ThreadWorkStatus) -> Result<()> {
        let id = match self.screen {
            Screen::Reader => self.current_thread.as_ref().map(|thread| thread.summary.id),
            Screen::Queue(_) => self.selected_thread().map(|thread| thread.id),
            _ => None,
        };
        if let Some(id) = id {
            self.backend
                .threads()
                .set_work_state(id, status, None)
                .await?;
            self.status = Some(match status {
                ThreadWorkStatus::Done => "Conversation marked done".into(),
                ThreadWorkStatus::Waiting => "Conversation moved to Waiting".into(),
                _ => "Conversation work state changed".into(),
            });
            if self.screen == Screen::Reader {
                self.screen = self.previous_screen;
                self.current_thread = None;
            }
            self.refresh().await?;
        }
        Ok(())
    }

    async fn snooze_selected(&mut self) -> Result<()> {
        let id = match self.screen {
            Screen::Reader => self.current_thread.as_ref().map(|thread| thread.summary.id),
            Screen::Queue(_) => self.selected_thread().map(|thread| thread.id),
            _ => None,
        };
        if let Some(id) = id {
            let until = (Utc::now() + Duration::days(1)).timestamp();
            self.backend
                .threads()
                .set_work_state(id, ThreadWorkStatus::Snoozed, Some(until))
                .await?;
            self.status = Some("Conversation snoozed for one day".into());
            if self.screen == Screen::Reader {
                self.screen = self.previous_screen;
                self.current_thread = None;
            }
            self.refresh().await?;
        }
        Ok(())
    }

    async fn make_actionable_once(&mut self) -> Result<()> {
        let id = match self.screen {
            Screen::Reader => self.current_thread.as_ref().map(|thread| thread.summary.id),
            Screen::Queue(WorkflowView::ColdReview) => {
                self.selected_thread().map(|thread| thread.id)
            }
            _ => None,
        };
        if let Some(id) = id {
            self.backend.threads().set_actionable_once(id, true).await?;
            self.status = Some("Conversation admitted to Warm Action once".into());
            self.switch_queue(WorkflowView::WarmAction).await?;
        }
        Ok(())
    }

    fn begin_suggestion_edit(&mut self) {
        let Some(suggestion) = self.selected_suggestion() else {
            return;
        };
        self.onboarding_edit = Some(OnboardingEdit {
            display_name: suggestion
                .claimed_name
                .clone()
                .unwrap_or_else(|| suggestion.address.clone()),
            relationship: suggestion_relationship(suggestion),
        });
        self.screen = Screen::OnboardingEdit;
    }

    async fn accept_suggestion(&mut self, edit: Option<OnboardingEdit>) -> Result<()> {
        let Some(account_id) = self.onboarding_account else {
            return Ok(());
        };
        let Some(suggestion) = self.selected_suggestion().cloned() else {
            return Ok(());
        };
        let edit = edit.unwrap_or_else(|| OnboardingEdit {
            display_name: suggestion
                .claimed_name
                .clone()
                .unwrap_or_else(|| suggestion.address.clone()),
            relationship: suggestion_relationship(&suggestion),
        });
        let name = edit.display_name.trim();
        if name.is_empty() {
            self.status = Some("A contact needs a display name".into());
            self.onboarding_edit = Some(edit);
            self.screen = Screen::OnboardingEdit;
            return Ok(());
        }
        self.backend
            .onboarding()
            .accept_contact(
                account_id,
                &suggestion.address,
                NewContact {
                    display_name: name.to_owned(),
                    addresses: vec![ContactAddress {
                        address: suggestion.address.clone(),
                        accepted_name: suggestion.claimed_name.clone(),
                    }],
                },
                edit.relationship,
            )
            .await?;
        self.suggestions.remove(self.selected);
        self.contacts = self.backend.contacts().list().await?;
        self.rebuild_contact_names();
        self.finish_onboarding_step().await
    }

    async fn dismiss_suggestion(&mut self) -> Result<()> {
        let Some(account_id) = self.onboarding_account else {
            return Ok(());
        };
        let Some(suggestion) = self.selected_suggestion().cloned() else {
            return Ok(());
        };
        self.backend
            .onboarding()
            .dismiss_contact(account_id, &suggestion.address)
            .await?;
        self.suggestions.remove(self.selected);
        self.finish_onboarding_step().await
    }

    async fn finish_onboarding_step(&mut self) -> Result<()> {
        self.onboarding_edit = None;
        if self.suggestions.is_empty() {
            self.status = Some("Contact bootstrap complete".into());
            self.switch_queue(WorkflowView::WarmAction).await
        } else {
            self.screen = Screen::Onboarding;
            self.clamp_selection();
            Ok(())
        }
    }

    fn toggle_onboarding_route(&mut self) {
        if let Some(edit) = &mut self.onboarding_edit {
            let action = edit.relationship.warm_route != WarmRoute::Action;
            edit.relationship.warm_route = if action {
                WarmRoute::Action
            } else {
                WarmRoute::Fyi
            };
            edit.relationship.may_create_obligations = action;
            edit.relationship.notify = action;
        }
    }

    fn cycle_onboarding_kind(&mut self) {
        if let Some(edit) = &mut self.onboarding_edit {
            edit.relationship.kind = match edit.relationship.kind {
                RelationshipKind::Person => RelationshipKind::Organization,
                RelationshipKind::Organization => RelationshipKind::Merchant,
                RelationshipKind::Merchant => RelationshipKind::Newsletter,
                RelationshipKind::Newsletter => RelationshipKind::AutomatedService,
                RelationshipKind::AutomatedService => RelationshipKind::Other,
                RelationshipKind::Other => RelationshipKind::Person,
            };
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let length = match self.screen {
            Screen::Onboarding => self.suggestions.len(),
            Screen::Contacts => self.contacts.len(),
            Screen::Queue(_) => self.threads.len(),
            _ => 0,
        };
        if length == 0 {
            self.selected = 0;
            return;
        }
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(length.saturating_sub(1));
    }

    fn clamp_selection(&mut self) {
        let length = match self.screen {
            Screen::Onboarding => self.suggestions.len(),
            Screen::Contacts => self.contacts.len(),
            Screen::Queue(_) => self.threads.len(),
            _ => 0,
        };
        self.selected = self.selected.min(length.saturating_sub(1));
    }

    fn rebuild_contact_names(&mut self) {
        self.contact_names.clear();
        for contact in &self.contacts {
            for address in &contact.addresses {
                self.contact_names
                    .insert(address.address.to_lowercase(), contact.display_name.clone());
            }
        }
    }
}

fn suggestion_relationship(suggestion: &ContactSuggestion) -> NewContactRelationship {
    NewContactRelationship {
        kind: suggestion.suggested_kind,
        warm_route: suggestion.suggested_warm_route,
        may_create_obligations: suggestion.suggested_may_create_obligations,
        notify: suggestion.suggested_may_create_obligations,
        remote_content: RemoteContentPolicy::Ask,
    }
}
