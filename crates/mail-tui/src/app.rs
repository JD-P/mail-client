use chrono::{Duration, Utc};
use lizard_mail_backend::{
    Account, AccountId, AccountKind, Backend, BackendError, Contact, ContactAddress,
    ContactSuggestion, FindingPresentation, FindingSeverity, ImapAccountEngineConfig,
    ImapAccountSyncReport, ImapAccountSyncState, ImapCredential, ImapSecurity,
    MessageContentAvailability, MessageId, NewAccount, NewContact, NewContactRelationship,
    RelationshipKind, RemoteContentPolicy, Result, SecretValue, Thread, ThreadFilter,
    ThreadSummary, ThreadWorkStatus, WarmRoute, WorkflowView,
};
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::{IsolatedHtmlRenderer, RenderedPage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Accounts,
    AccountEdit,
    AccountDeleteConfirm,
    Onboarding,
    OnboardingEdit,
    Queue(WorkflowView),
    Reader,
    Contacts,
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountAuthentication {
    Password,
    OAuthAccessToken,
}

impl AccountAuthentication {
    fn credential(self, secret: String) -> ImapCredential {
        match self {
            Self::Password => ImapCredential::Password(SecretValue::new(secret)),
            Self::OAuthAccessToken => ImapCredential::OAuth2 {
                access_token: SecretValue::new(secret),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountField {
    Name,
    Username,
    Host,
    Port,
    Security,
    Authentication,
    Secret,
}

impl AccountField {
    const ALL: [Self; 7] = [
        Self::Name,
        Self::Username,
        Self::Host,
        Self::Port,
        Self::Security,
        Self::Authentication,
        Self::Secret,
    ];
}

pub struct AccountEditor {
    pub account_id: Option<AccountId>,
    pub name: String,
    pub username: String,
    pub host: String,
    pub port: String,
    pub security: ImapSecurity,
    pub authentication: AccountAuthentication,
    pub selected_field: AccountField,
    pub secret_entered: bool,
    secret: Zeroizing<String>,
    original_authentication: Option<AccountAuthentication>,
    credential_ref: Option<String>,
}

impl AccountEditor {
    fn new() -> Self {
        Self {
            account_id: None,
            name: "Personal".into(),
            username: String::new(),
            host: String::new(),
            port: "993".into(),
            security: ImapSecurity::ImplicitTls,
            authentication: AccountAuthentication::Password,
            selected_field: AccountField::Username,
            secret_entered: false,
            secret: Zeroizing::new(String::new()),
            original_authentication: None,
            credential_ref: None,
        }
    }

    fn from_account(account: &Account, authentication: AccountAuthentication) -> Result<Self> {
        let settings = account
            .imap
            .as_ref()
            .ok_or_else(|| BackendError::InvalidInput("account is missing IMAP settings".into()))?;
        Ok(Self {
            account_id: Some(account.id),
            name: account.name.clone(),
            username: settings.username.clone(),
            host: settings.host.clone(),
            port: settings.port.to_string(),
            security: settings.security,
            authentication,
            selected_field: AccountField::Name,
            secret_entered: false,
            secret: Zeroizing::new(String::new()),
            original_authentication: Some(authentication),
            credential_ref: account.credential_ref.clone(),
        })
    }

    pub fn secret_label(&self) -> &'static str {
        if self.secret_entered {
            "entered — hidden"
        } else if self.account_id.is_some() {
            "unchanged"
        } else {
            "required"
        }
    }
}

struct AccountSyncTask {
    account_id: AccountId,
    begin_contact_onboarding: bool,
    handle: JoinHandle<Result<ImapAccountSyncReport>>,
}

#[derive(Clone, Debug)]
pub struct OnboardingEdit {
    pub display_name: String,
    pub relationship: NewContactRelationship,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReaderHtmlKey {
    message_id: MessageId,
    content_hash: u64,
    width: u16,
}

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
    Accounts,
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
    AccountNew,
    AccountEdit,
    AccountSave,
    AccountSync,
    AccountDelete,
    AccountConfirmDelete,
    AccountCancelDelete,
    EditNextField,
    EditPreviousField,
    EditToggleChoice,
    EditSpace,
    EditBackspace,
    EditCharacter(char),
    EditPaste(Zeroizing<String>),
}

pub struct MailApp {
    pub backend: Backend,
    pub screen: Screen,
    pub previous_screen: Screen,
    pub threads: Vec<ThreadSummary>,
    pub selected: usize,
    pub current_thread: Option<Thread>,
    pub accounts: Vec<Account>,
    pub account_states: HashMap<AccountId, ImapAccountSyncState>,
    pub account_editor: Option<AccountEditor>,
    pub pending_account_delete: Option<AccountId>,
    pub onboarding_account: Option<AccountId>,
    pub suggestions: Vec<ContactSuggestion>,
    pub onboarding_edit: Option<OnboardingEdit>,
    pub contacts: Vec<Contact>,
    pub contact_names: HashMap<String, String>,
    pub status: Option<String>,
    pub security_override: bool,
    reader_html: Option<RenderedPage>,
    reader_html_error: Option<String>,
    reader_html_key: Option<ReaderHtmlKey>,
    html_renderer: IsolatedHtmlRenderer,
    account_sync_task: Option<AccountSyncTask>,
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
        let screen = if accounts.is_empty() {
            Screen::AccountEdit
        } else if suggestions.is_empty() {
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
            account_editor: accounts.is_empty().then(AccountEditor::new),
            accounts,
            account_states: HashMap::new(),
            pending_account_delete: None,
            onboarding_account,
            suggestions,
            onboarding_edit: None,
            contacts,
            contact_names: HashMap::new(),
            status: None,
            security_override: false,
            reader_html: None,
            reader_html_error: None,
            reader_html_key: None,
            html_renderer: IsolatedHtmlRenderer::default(),
            account_sync_task: None,
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
            Screen::Accounts => self.refresh_accounts().await?,
            Screen::AccountEdit
            | Screen::AccountDeleteConfirm
            | Screen::Onboarding
            | Screen::OnboardingEdit
            | Screen::Help => {}
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
            AppCommand::Accounts => self.open_accounts().await?,
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
            AppCommand::AccountNew => self.begin_new_account(),
            AppCommand::AccountEdit => self.begin_selected_account_edit().await?,
            AppCommand::AccountSave => self.save_account().await?,
            AppCommand::AccountSync => self.sync_selected_account()?,
            AppCommand::AccountDelete => self.begin_account_delete(),
            AppCommand::AccountConfirmDelete => self.confirm_account_delete().await?,
            AppCommand::AccountCancelDelete => self.cancel_account_delete(),
            AppCommand::EditNextField => self.move_account_field(1),
            AppCommand::EditPreviousField => self.move_account_field(-1),
            AppCommand::EditToggleChoice => self.toggle_account_choice(),
            AppCommand::EditSpace => self.edit_space(),
            AppCommand::EditBackspace => self.edit_backspace(),
            AppCommand::EditCharacter(character) => self.edit_character(character),
            AppCommand::EditPaste(value) => self.edit_paste(&value),
        }
        Ok(())
    }

    /// Reaps a completed background synchronization without blocking terminal
    /// input while the isolated worker connects to a remote provider.
    pub async fn poll_background_tasks(&mut self) -> Result<()> {
        let Some(task) = self.account_sync_task.take() else {
            return Ok(());
        };
        if !task.handle.is_finished() {
            self.account_sync_task = Some(task);
            return Ok(());
        }
        let outcome = task.handle.await.map_err(|error| {
            BackendError::Imap(format!("account synchronization task failed: {error}"))
        })?;
        self.refresh_accounts().await?;
        match outcome {
            Ok(report) => {
                let fetched = report
                    .folders
                    .iter()
                    .map(|folder| folder.fetched_messages)
                    .sum::<usize>();
                self.status = Some(format!(
                    "Synchronization complete: {fetched} new message headers across {} folders",
                    report.folders.len()
                ));
                if task.begin_contact_onboarding {
                    self.begin_contact_onboarding(task.account_id).await?;
                } else if matches!(self.screen, Screen::Queue(_)) {
                    self.refresh().await?;
                }
            }
            Err(error) => {
                self.status = Some(format!("Synchronization failed: {error}"));
            }
        }
        Ok(())
    }

    pub fn account_syncing(&self, account_id: AccountId) -> bool {
        self.account_sync_task
            .as_ref()
            .is_some_and(|task| task.account_id == account_id)
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

    /// Prepares the current HTML body outside the terminal drawing closure.
    ///
    /// The renderer is a disposable Linux worker. Failure is deliberately not
    /// fatal to the mail client: the UI falls back to the backend's bounded
    /// plain-text body and never retries the same failed content every frame.
    pub async fn prepare_reader_html(&mut self, width: u16) {
        if self.screen != Screen::Reader || self.reader_is_blocked() {
            self.clear_reader_html();
            return;
        }
        let Some(message) = self
            .current_thread
            .as_ref()
            .and_then(|thread| thread.messages.last())
        else {
            self.clear_reader_html();
            return;
        };
        let Some(html) = message.body_html.as_deref() else {
            self.clear_reader_html();
            return;
        };
        let mut hasher = DefaultHasher::new();
        html.hash(&mut hasher);
        let key = ReaderHtmlKey {
            message_id: message.summary.id,
            content_hash: hasher.finish(),
            width,
        };
        if self.reader_html_key == Some(key) {
            return;
        }
        let html = html.as_bytes().to_vec();
        self.reader_html = None;
        self.reader_html_error = None;
        self.reader_html_key = Some(key);
        match self.html_renderer.render(&html, width).await {
            Ok(page) => self.reader_html = Some(page),
            Err(error) => self.reader_html_error = Some(error.to_string()),
        }
    }

    /// Overrides the worker command for embedders and isolation failure tests.
    pub fn set_html_renderer(&mut self, renderer: IsolatedHtmlRenderer) {
        self.html_renderer = renderer;
        self.clear_reader_html();
    }

    pub fn reader_html(&self) -> Option<&RenderedPage> {
        self.reader_html.as_ref()
    }

    pub fn reader_html_error(&self) -> Option<&str> {
        self.reader_html_error.as_deref()
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

    pub fn contact_name(&self, address: &str) -> Option<&str> {
        self.contact_names
            .get(&address.to_lowercase())
            .map(String::as_str)
    }

    fn selected_account(&self) -> Option<&Account> {
        self.accounts.get(self.selected)
    }

    async fn open_accounts(&mut self) -> Result<()> {
        if !matches!(
            self.screen,
            Screen::Accounts | Screen::AccountEdit | Screen::AccountDeleteConfirm
        ) {
            self.previous_screen = self.screen;
        }
        self.screen = Screen::Accounts;
        self.account_editor = None;
        self.pending_account_delete = None;
        self.selected = 0;
        self.refresh_accounts().await
    }

    async fn refresh_accounts(&mut self) -> Result<()> {
        self.accounts = self.backend.accounts().list().await?;
        self.account_states.clear();
        // Reading durable sync state does not touch the network or parse any
        // server input, so this does not bypass the isolated production sync
        // path used below.
        let state_reader = self
            .backend
            .managed_imap_account_engine_in_process(ImapAccountEngineConfig::default())?;
        for account in &self.accounts {
            if account.kind == AccountKind::Imap {
                let state = state_reader.state(account.id).await?;
                self.account_states.insert(account.id, state);
            }
        }
        self.clamp_selection();
        Ok(())
    }

    fn begin_new_account(&mut self) {
        if self.account_sync_task.is_some() {
            self.status = Some("Wait for the current account synchronization to finish".into());
            return;
        }
        self.account_editor = Some(AccountEditor::new());
        self.screen = Screen::AccountEdit;
    }

    async fn begin_selected_account_edit(&mut self) -> Result<()> {
        if self.account_sync_task.is_some() {
            self.status = Some("Wait for the current account synchronization to finish".into());
            return Ok(());
        }
        let Some(account) = self.selected_account().cloned() else {
            return Ok(());
        };
        let authentication = match account.credential_ref.as_deref() {
            Some(reference) => match self.backend.credentials().resolve(reference).await? {
                ImapCredential::Password(_) => AccountAuthentication::Password,
                ImapCredential::OAuth2 { .. } => AccountAuthentication::OAuthAccessToken,
            },
            None => AccountAuthentication::Password,
        };
        self.account_editor = Some(AccountEditor::from_account(&account, authentication)?);
        self.screen = Screen::AccountEdit;
        Ok(())
    }

    async fn save_account(&mut self) -> Result<()> {
        if self.account_sync_task.is_some() {
            self.status = Some("Wait for the current account synchronization to finish".into());
            return Ok(());
        }
        let Some(mut editor) = self.account_editor.take() else {
            return Ok(());
        };
        let port = match editor.port.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                self.status = Some("IMAP port must be a number from 1 through 65535".into());
                self.account_editor = Some(editor);
                return Ok(());
            }
        };
        let name = editor.name.trim().to_owned();
        let username = editor.username.trim().to_owned();
        let host = editor.host.trim().to_owned();
        if name.is_empty() || username.is_empty() || host.is_empty() {
            self.status = Some("Account name, email/username, and IMAP server are required".into());
            self.account_editor = Some(editor);
            return Ok(());
        }
        let authentication_changed = editor
            .original_authentication
            .is_some_and(|original| original != editor.authentication);
        let needs_credential = editor.account_id.is_none()
            || editor.credential_ref.is_none()
            || authentication_changed;
        if needs_credential && editor.secret.is_empty() {
            self.status = Some(
                match editor.authentication {
                    AccountAuthentication::Password => "Enter the account password or app password",
                    AccountAuthentication::OAuthAccessToken => "Enter an OAuth access token",
                }
                .into(),
            );
            self.account_editor = Some(editor);
            return Ok(());
        }
        let first_account = self.accounts.is_empty();
        let value = NewAccount {
            name,
            kind: AccountKind::Imap,
            credential_ref: editor.credential_ref.clone(),
            imap: Some(lizard_mail_backend::ImapSettings {
                host,
                port,
                username,
                security: editor.security,
            }),
        };
        let replacement = if editor.secret.is_empty() {
            None
        } else {
            editor.secret_entered = false;
            Some(
                editor
                    .authentication
                    .credential(std::mem::take(&mut *editor.secret)),
            )
        };
        let save_result: Result<Account> = async {
            if let Some(account_id) = editor.account_id {
                let updated = self.backend.accounts().update(account_id, value).await?;
                if let Some(credential) = replacement {
                    self.backend
                        .accounts()
                        .set_credential(account_id, credential)
                        .await
                } else {
                    Ok(updated)
                }
            } else {
                let credential = replacement.ok_or_else(|| {
                    BackendError::InvalidInput("a new IMAP account needs a credential".into())
                })?;
                self.backend
                    .accounts()
                    .add_with_credential(
                        NewAccount {
                            credential_ref: None,
                            ..value
                        },
                        credential,
                    )
                    .await
            }
        }
        .await;
        let saved = match save_result {
            Ok(saved) => saved,
            Err(error) => {
                // A failed credential write has consumed and zeroized the
                // attempted secret. Keep the non-secret fields for correction,
                // but require the user to enter the secret again.
                editor.secret_entered = false;
                self.account_editor = Some(editor);
                return Err(error);
            }
        };
        self.screen = Screen::Accounts;
        self.account_editor = None;
        self.refresh_accounts().await?;
        if let Some(index) = self
            .accounts
            .iter()
            .position(|account| account.id == saved.id)
        {
            self.selected = index;
        }
        self.status = Some("Account saved; starting isolated synchronization…".into());
        if let Err(error) = self.start_account_sync(saved.id, first_account) {
            self.status = Some(format!(
                "Account saved, but synchronization could not start: {error}"
            ));
        }
        Ok(())
    }

    fn sync_selected_account(&mut self) -> Result<()> {
        let Some(account_id) = self.selected_account().map(|account| account.id) else {
            return Ok(());
        };
        self.start_account_sync(account_id, false)
    }

    fn start_account_sync(
        &mut self,
        account_id: AccountId,
        begin_contact_onboarding: bool,
    ) -> Result<()> {
        if self.account_sync_task.is_some() {
            self.status = Some("Another account synchronization is already running".into());
            return Ok(());
        }
        let engine = self
            .backend
            .managed_imap_account_engine(ImapAccountEngineConfig::default())?;
        self.status = Some("Synchronizing in an isolated worker…".into());
        self.account_sync_task = Some(AccountSyncTask {
            account_id,
            begin_contact_onboarding,
            handle: tokio::spawn(async move { engine.sync_once(account_id).await }),
        });
        Ok(())
    }

    async fn begin_contact_onboarding(&mut self, account_id: AccountId) -> Result<()> {
        self.onboarding_account = Some(account_id);
        self.contacts = self.backend.contacts().list().await?;
        self.suggestions = if self.contacts.is_empty() {
            self.backend
                .onboarding()
                .contact_suggestions(
                    account_id,
                    (Utc::now() - Duration::days(183)).timestamp(),
                    20,
                )
                .await?
        } else {
            Vec::new()
        };
        self.selected = 0;
        if self.suggestions.is_empty() {
            self.switch_queue(WorkflowView::WarmAction).await
        } else {
            self.screen = Screen::Onboarding;
            Ok(())
        }
    }

    fn begin_account_delete(&mut self) {
        if self.account_sync_task.is_some() {
            self.status = Some("Wait for the current account synchronization to finish".into());
            return;
        }
        if let Some(account_id) = self.selected_account().map(|account| account.id) {
            self.pending_account_delete = Some(account_id);
            self.screen = Screen::AccountDeleteConfirm;
        }
    }

    async fn confirm_account_delete(&mut self) -> Result<()> {
        let Some(account_id) = self.pending_account_delete.take() else {
            return Ok(());
        };
        self.backend.accounts().remove(account_id).await?;
        self.refresh_accounts().await?;
        if self.accounts.is_empty() {
            self.account_editor = Some(AccountEditor::new());
            self.screen = Screen::AccountEdit;
            self.status = Some("Account and its local cached data were removed".into());
        } else {
            self.screen = Screen::Accounts;
            self.status = Some("Account and its local cached data were removed".into());
        }
        Ok(())
    }

    fn cancel_account_delete(&mut self) {
        self.pending_account_delete = None;
        self.screen = Screen::Accounts;
    }

    fn move_account_field(&mut self, delta: isize) {
        let Some(editor) = &mut self.account_editor else {
            return;
        };
        let index = AccountField::ALL
            .iter()
            .position(|field| *field == editor.selected_field)
            .unwrap_or(0);
        let last = AccountField::ALL.len().saturating_sub(1);
        let next = index.saturating_add_signed(delta).min(last);
        editor.selected_field = AccountField::ALL[next];
    }

    fn toggle_account_choice(&mut self) {
        let Some(editor) = &mut self.account_editor else {
            return;
        };
        match editor.selected_field {
            AccountField::Security => {
                editor.security = match editor.security {
                    ImapSecurity::ImplicitTls => {
                        if editor.port == "993" {
                            editor.port = "143".into();
                        }
                        ImapSecurity::StartTls
                    }
                    ImapSecurity::StartTls => {
                        if editor.port == "143" {
                            editor.port = "993".into();
                        }
                        ImapSecurity::ImplicitTls
                    }
                };
            }
            AccountField::Authentication => {
                editor.authentication = match editor.authentication {
                    AccountAuthentication::Password => AccountAuthentication::OAuthAccessToken,
                    AccountAuthentication::OAuthAccessToken => AccountAuthentication::Password,
                };
            }
            _ => {}
        }
    }

    fn edit_space(&mut self) {
        if self.account_editor.as_ref().is_some_and(|editor| {
            matches!(
                editor.selected_field,
                AccountField::Security | AccountField::Authentication
            )
        }) {
            self.toggle_account_choice();
        } else {
            self.edit_character(' ');
        }
    }

    fn edit_backspace(&mut self) {
        if let Some(edit) = &mut self.onboarding_edit {
            edit.display_name.pop();
            return;
        }
        let Some(editor) = &mut self.account_editor else {
            return;
        };
        match editor.selected_field {
            AccountField::Name => {
                editor.name.pop();
            }
            AccountField::Username => {
                editor.username.pop();
            }
            AccountField::Host => {
                editor.host.pop();
            }
            AccountField::Port => {
                editor.port.pop();
            }
            AccountField::Secret => {
                editor.secret.pop();
                editor.secret_entered = !editor.secret.is_empty();
            }
            AccountField::Security | AccountField::Authentication => {}
        }
    }

    fn edit_character(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        if let Some(edit) = &mut self.onboarding_edit {
            if edit.display_name.len() < 200 {
                edit.display_name.push(character);
            }
            return;
        }
        let Some(editor) = &mut self.account_editor else {
            return;
        };
        match editor.selected_field {
            AccountField::Name if editor.name.len() < 200 => editor.name.push(character),
            AccountField::Username if editor.username.len() < 320 => {
                editor.username.push(character)
            }
            AccountField::Host if editor.host.len() < 253 && !character.is_whitespace() => {
                editor.host.push(character)
            }
            AccountField::Port if editor.port.len() < 5 && character.is_ascii_digit() => {
                editor.port.push(character)
            }
            AccountField::Secret if editor.secret.len() < 16 * 1024 => {
                editor.secret.push(character);
                editor.secret_entered = true;
            }
            AccountField::Name
            | AccountField::Username
            | AccountField::Host
            | AccountField::Port
            | AccountField::Security
            | AccountField::Authentication
            | AccountField::Secret => {}
        }
    }

    fn edit_paste(&mut self, value: &str) {
        for character in value.chars().filter(|character| !character.is_control()) {
            self.edit_character(character);
        }
    }

    async fn switch_queue(&mut self, workflow: WorkflowView) -> Result<()> {
        self.screen = Screen::Queue(workflow);
        self.previous_screen = self.screen;
        self.selected = 0;
        self.current_thread = None;
        self.security_override = false;
        self.clear_reader_html();
        self.refresh().await
    }

    async fn open_selected(&mut self) -> Result<()> {
        match self.screen {
            Screen::Queue(_) => {
                if let Some(id) = self.selected_thread().map(|summary| summary.id) {
                    let mut thread = self.backend.threads().get(id).await?;
                    let message_id = thread
                        .messages
                        .last()
                        .ok_or_else(|| BackendError::InvalidInput("conversation is empty".into()))?
                        .summary
                        .id;
                    if thread.messages.last().is_some_and(|message| {
                        message.summary.content_availability != MessageContentAvailability::Complete
                    }) {
                        self.status = Some("Fetching and verifying message content…".into());
                        self.backend
                            .managed_imap_account_engine(ImapAccountEngineConfig::default())?
                            .fetch_message_content(message_id)
                            .await?;
                        thread = self.backend.threads().get(id).await?;
                    }
                    if thread.messages.last().is_some_and(|message| {
                        message.summary.content_availability != MessageContentAvailability::Complete
                    }) {
                        return Err(BackendError::InvalidInput(
                            "message content and identity evidence are not complete".into(),
                        ));
                    }
                    self.previous_screen = self.screen;
                    self.current_thread = Some(thread);
                    self.screen = Screen::Reader;
                    self.security_override = false;
                    self.clear_reader_html();
                }
            }
            Screen::Onboarding => self.begin_suggestion_edit(),
            Screen::Accounts => self.begin_selected_account_edit().await?,
            _ => {}
        }
        Ok(())
    }

    async fn go_back(&mut self) -> Result<()> {
        match self.screen {
            Screen::Reader | Screen::Contacts | Screen::Help | Screen::Accounts => {
                self.screen = self.previous_screen;
                self.current_thread = None;
                self.security_override = false;
                self.clear_reader_html();
                self.refresh().await?;
            }
            Screen::AccountEdit => {
                self.account_editor = None;
                self.screen = Screen::Accounts;
                self.refresh_accounts().await?;
            }
            Screen::AccountDeleteConfirm => self.cancel_account_delete(),
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
                self.clear_reader_html();
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
                self.clear_reader_html();
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
            Screen::Accounts => self.accounts.len(),
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
            Screen::Accounts => self.accounts.len(),
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

    fn clear_reader_html(&mut self) {
        self.reader_html = None;
        self.reader_html_error = None;
        self.reader_html_key = None;
    }
}

impl Drop for MailApp {
    fn drop(&mut self) {
        if let Some(task) = self.account_sync_task.take() {
            // The isolated engine configures its child with kill_on_drop, so
            // aborting the supervisor task cannot orphan a network worker.
            task.handle.abort();
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
