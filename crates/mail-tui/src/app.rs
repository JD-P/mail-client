use chrono::{Duration, Utc};
use lizard_mail_backend::{
    Account, AccountId, AccountKind, Backend, BackendError, Contact, ContactAddress, ContactId,
    ContactRelationship, ContactSuggestion, Draft, FindingPresentation, FindingSeverity,
    ImapAccountEngineConfig, ImapAccountSyncReport, ImapAccountSyncState, ImapCredential,
    ImapSecurity, MessageContentAvailability, MessageId, MessageSummary, NewAccount, NewContact,
    NewContactRelationship, RelationshipKind, RemoteContentPolicy, ReplyAudience, Result,
    SearchRequest, SecretValue, SendingLimits, SimilarityPreview, SmtpAccount, SmtpAuthMethod,
    SmtpEngineConfig, SmtpSecurity, SmtpSettings, SubmissionId, SubmissionStatus, Thread,
    ThreadFilter, ThreadId, ThreadSummary, ThreadWorkStatus, WarmRoute, WorkflowView,
    DEFAULT_SIMILARITY_CUTOFF_MILLIS,
};
use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    time::{Duration as StdDuration, Instant},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{IsolatedHtmlRenderer, RenderedPage};

/// Default interval between automatic background synchronizations.
const DEFAULT_AUTO_SYNC_INTERVAL: StdDuration = StdDuration::from_secs(5 * 60);
const SYNC_PROGRESS_REFRESH_INTERVAL: StdDuration = StdDuration::from_secs(1);
const SIMILARITY_PREVIEW_LIMIT: usize = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Accounts,
    AccountEdit,
    AccountDeleteConfirm,
    Onboarding,
    OnboardingEdit,
    SimilarityPreview,
    Queue(WorkflowView),
    Reader,
    Compose,
    SearchInput,
    SearchResults,
    Contacts,
    ContactEdit,
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
    AuthservIds,
    SmtpHost,
    SmtpPort,
    SmtpSecurity,
}

impl AccountField {
    const ALL: [Self; 11] = [
        Self::Name,
        Self::Username,
        Self::Host,
        Self::Port,
        Self::Security,
        Self::Authentication,
        Self::Secret,
        Self::AuthservIds,
        Self::SmtpHost,
        Self::SmtpPort,
        Self::SmtpSecurity,
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
    pub trusted_authserv_ids: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub smtp_security: SmtpSecurity,
    pub selected_field: AccountField,
    pub secret_entered: bool,
    secret: Zeroizing<String>,
    original_authentication: Option<AccountAuthentication>,
    credential_ref: Option<String>,
    original_smtp_settings: Option<SmtpSettings>,
    original_smtp_credential_ref: Option<String>,
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
            trusted_authserv_ids: String::new(),
            smtp_host: String::new(),
            smtp_port: "465".into(),
            smtp_security: SmtpSecurity::ImplicitTls,
            selected_field: AccountField::Username,
            secret_entered: false,
            secret: Zeroizing::new(String::new()),
            original_authentication: None,
            credential_ref: None,
            original_smtp_settings: None,
            original_smtp_credential_ref: None,
        }
    }

    fn from_account(
        account: &Account,
        authentication: AccountAuthentication,
        smtp: Option<&SmtpAccount>,
    ) -> Result<Self> {
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
            trusted_authserv_ids: account.trusted_authserv_ids.join(", "),
            smtp_host: smtp
                .map(|smtp| smtp.settings.host.clone())
                .unwrap_or_default(),
            smtp_port: smtp
                .map(|smtp| smtp.settings.port.to_string())
                .unwrap_or_else(|| "465".into()),
            smtp_security: smtp
                .map(|smtp| smtp.settings.security)
                .unwrap_or(SmtpSecurity::ImplicitTls),
            selected_field: AccountField::Name,
            secret_entered: false,
            secret: Zeroizing::new(String::new()),
            original_authentication: Some(authentication),
            credential_ref: account.credential_ref.clone(),
            original_smtp_settings: smtp.map(|smtp| smtp.settings.clone()),
            original_smtp_credential_ref: smtp.map(|smtp| smtp.credential_ref.clone()),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeField {
    To,
    Cc,
    Subject,
    Body,
}

impl ComposeField {
    const ALL: [Self; 4] = [Self::To, Self::Cc, Self::Subject, Self::Body];
}

pub struct ComposeEditor {
    pub draft: Draft,
    pub to: String,
    pub cc: String,
    pub subject: String,
    pub body: String,
    pub selected_field: ComposeField,
}

pub struct SearchEditor {
    pub query: String,
}

impl ComposeEditor {
    fn new(draft: Draft) -> Self {
        Self {
            to: draft.content.to_addresses.join(", "),
            cc: draft.content.cc_addresses.join(", "),
            subject: draft.content.subject.clone(),
            body: draft.content.body_text.clone(),
            draft,
            selected_field: ComposeField::Body,
        }
    }
}

struct SmtpWorkerTask {
    cancellation: CancellationToken,
    handle: JoinHandle<Result<()>>,
}

struct AccountSyncTask {
    account_id: AccountId,
    announce: bool,
    begin_contact_onboarding: bool,
    handle: JoinHandle<Result<ImapAccountSyncReport>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedSync {
    account_id: AccountId,
    announce: bool,
    begin_contact_onboarding: bool,
}

#[derive(Clone, Debug)]
pub struct OnboardingEdit {
    pub display_name: String,
    pub relationship: NewContactRelationship,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactField {
    Name,
    Addresses,
    Kind,
    Route,
    Notifications,
    RemoteContent,
}

impl ContactField {
    const ALL: [Self; 6] = [
        Self::Name,
        Self::Addresses,
        Self::Kind,
        Self::Route,
        Self::Notifications,
        Self::RemoteContent,
    ];
}

pub struct ContactEditor {
    pub contact_id: ContactId,
    pub display_name: String,
    /// Comma-separated bare mailbox addresses. The backend remains the
    /// authority for normalization, uniqueness, and cross-contact conflicts.
    pub addresses: String,
    pub relationship: ContactRelationship,
    pub selected_field: ContactField,
    original_addresses: Vec<ContactAddress>,
}

impl ContactEditor {
    fn new(contact: Contact, relationship: ContactRelationship) -> Self {
        let addresses = contact
            .addresses
            .iter()
            .map(|address| address.address.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            contact_id: contact.id,
            display_name: contact.display_name,
            addresses,
            relationship,
            selected_field: ContactField::Name,
            original_addresses: contact.addresses,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReaderHtmlKey {
    message_id: MessageId,
    content_hash: u64,
    width: u16,
}

struct ReaderLoadTask {
    thread_id: ThreadId,
    handle: JoinHandle<Result<Thread>>,
}

struct ReaderContentTask {
    thread_id: ThreadId,
    handle: JoinHandle<Result<Thread>>,
}

struct ReaderHtmlTask {
    key: ReaderHtmlKey,
    handle: JoinHandle<std::result::Result<RenderedPage, String>>,
}

pub enum AppCommand {
    Quit,
    Next,
    Previous,
    ReaderNext,
    ReaderPrevious,
    ReaderScrollDown,
    ReaderScrollUp,
    ReaderPageDown,
    ReaderPageUp,
    ReaderScrollTop,
    ReaderScrollBottom,
    Reply,
    ReplyAll,
    ComposeSave,
    ComposeSend,
    ComposeNewline,
    SearchStart,
    SearchSubmit,
    SearchCancel,
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
    MoveToAction,
    MoveToFyi,
    PreviewSimilarFyi,
    SimilarityBroader,
    SimilarityStricter,
    SimilarityConfirm,
    SimilarityCancel,
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
    ContactEdit,
    ContactSave,
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
    pub smtp_accounts: HashMap<AccountId, SmtpAccount>,
    pub account_editor: Option<AccountEditor>,
    pub compose_editor: Option<ComposeEditor>,
    pub search_editor: Option<SearchEditor>,
    pub search_query: String,
    pub search_results: Vec<MessageSummary>,
    pub search_has_more: bool,
    pub search_index_complete: bool,
    pub search_content_complete: bool,
    search_return_screen: Screen,
    search_return_selected: usize,
    pub pending_account_delete: Option<AccountId>,
    pub onboarding_account: Option<AccountId>,
    pub suggestions: Vec<ContactSuggestion>,
    pub onboarding_edit: Option<OnboardingEdit>,
    pub similarity_preview: Option<SimilarityPreview>,
    pub similarity_selected: usize,
    similarity_return_screen: Option<Screen>,
    pub contacts: Vec<Contact>,
    pub contact_relationships: HashMap<ContactId, ContactRelationship>,
    pub contact_editor: Option<ContactEditor>,
    pub contact_names: HashMap<String, String>,
    pub status: Option<String>,
    pub background_status: Option<String>,
    pub security_override: bool,
    pub reader_scroll: usize,
    reader_scroll_max: Cell<usize>,
    reader_viewport_rows: Cell<usize>,
    reader_html: Option<RenderedPage>,
    reader_html_error: Option<String>,
    reader_html_key: Option<ReaderHtmlKey>,
    reader_html_task: Option<ReaderHtmlTask>,
    reader_thread_id: Option<ThreadId>,
    reader_load_task: Option<ReaderLoadTask>,
    reader_content_task: Option<ReaderContentTask>,
    reader_target_message_id: Option<MessageId>,
    html_renderer: IsolatedHtmlRenderer,
    account_sync_task: Option<AccountSyncTask>,
    sync_queue: VecDeque<QueuedSync>,
    auto_sync: bool,
    auto_sync_interval: StdDuration,
    last_auto_sync: Option<Instant>,
    last_sync_progress_refresh: Option<Instant>,
    smtp_worker: Option<SmtpWorkerTask>,
    pending_submission: Option<SubmissionId>,
    last_submission_refresh: Option<Instant>,
    pub quit: bool,
}

impl MailApp {
    pub async fn open(backend: Backend) -> Result<Self> {
        let accounts = backend.accounts().list().await?;
        let contacts = backend.contacts().list().await?;
        let contact_relationships = backend
            .contacts()
            .relationships()
            .await?
            .into_iter()
            .map(|relationship| (relationship.contact_id, relationship))
            .collect();
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
        let mut smtp_accounts = HashMap::new();
        for account in &accounts {
            match backend.sending().smtp_account(account.id).await {
                Ok(smtp) => {
                    smtp_accounts.insert(account.id, smtp);
                }
                Err(BackendError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        let smtp_config = SmtpEngineConfig {
            polling_interval: StdDuration::from_secs(2),
            ..SmtpEngineConfig::default()
        };
        let smtp_engine = backend.managed_smtp_engine(smtp_config).await?;
        let smtp_cancellation = CancellationToken::new();
        let worker_cancellation = smtp_cancellation.clone();
        let smtp_worker = SmtpWorkerTask {
            cancellation: smtp_cancellation,
            handle: tokio::spawn(async move { smtp_engine.run(worker_cancellation).await }),
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
            smtp_accounts,
            pending_account_delete: None,
            compose_editor: None,
            search_editor: None,
            search_query: String::new(),
            search_results: Vec::new(),
            search_has_more: false,
            search_index_complete: true,
            search_content_complete: true,
            search_return_screen: Screen::Queue(WorkflowView::WarmAction),
            search_return_selected: 0,
            onboarding_account,
            suggestions,
            onboarding_edit: None,
            similarity_preview: None,
            similarity_selected: 0,
            similarity_return_screen: None,
            contacts,
            contact_relationships,
            contact_editor: None,
            contact_names: HashMap::new(),
            status: None,
            background_status: None,
            security_override: false,
            reader_scroll: 0,
            reader_scroll_max: Cell::new(0),
            reader_viewport_rows: Cell::new(1),
            reader_html: None,
            reader_html_error: None,
            reader_html_key: None,
            reader_html_task: None,
            reader_thread_id: None,
            reader_load_task: None,
            reader_content_task: None,
            reader_target_message_id: None,
            html_renderer: IsolatedHtmlRenderer::default(),
            account_sync_task: None,
            sync_queue: VecDeque::new(),
            auto_sync: false,
            auto_sync_interval: DEFAULT_AUTO_SYNC_INTERVAL,
            last_auto_sync: None,
            last_sync_progress_refresh: None,
            smtp_worker: Some(smtp_worker),
            pending_submission: None,
            last_submission_refresh: None,
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
                self.refresh_contacts().await?;
                self.clamp_selection();
            }
            Screen::Reader => {
                if let Some(thread_id) = self
                    .reader_thread_id
                    .or_else(|| self.current_thread.as_ref().map(|thread| thread.summary.id))
                {
                    self.start_reader_load(thread_id);
                }
            }
            Screen::Accounts => self.refresh_accounts().await?,
            Screen::Compose
            | Screen::SearchInput
            | Screen::SearchResults
            | Screen::AccountEdit
            | Screen::AccountDeleteConfirm
            | Screen::Onboarding
            | Screen::OnboardingEdit
            | Screen::ContactEdit
            | Screen::SimilarityPreview
            | Screen::Help => {}
        }
        Ok(())
    }

    pub async fn dispatch(&mut self, command: AppCommand) -> Result<()> {
        self.status = None;
        match command {
            AppCommand::Quit => {
                if let Some(worker) = &self.smtp_worker {
                    worker.cancellation.cancel();
                }
                self.quit = true;
            }
            AppCommand::Next => self.move_selection(1),
            AppCommand::Previous => self.move_selection(-1),
            AppCommand::ReaderNext => self.open_adjacent_reader(1),
            AppCommand::ReaderPrevious => self.open_adjacent_reader(-1),
            AppCommand::ReaderScrollDown => self.scroll_reader(1),
            AppCommand::ReaderScrollUp => self.scroll_reader(-1),
            AppCommand::ReaderPageDown => self.page_reader(1),
            AppCommand::ReaderPageUp => self.page_reader(-1),
            AppCommand::ReaderScrollTop => self.reader_scroll = 0,
            AppCommand::ReaderScrollBottom => self.reader_scroll = self.reader_scroll_max.get(),
            AppCommand::Reply => self.begin_reply(ReplyAudience::Sender).await?,
            AppCommand::ReplyAll => self.begin_reply(ReplyAudience::All).await?,
            AppCommand::ComposeSave => self.save_compose_draft(true).await?,
            AppCommand::ComposeSend => self.send_compose().await?,
            AppCommand::ComposeNewline => self.compose_newline(),
            AppCommand::SearchStart => self.begin_search(),
            AppCommand::SearchSubmit => self.submit_search().await?,
            AppCommand::SearchCancel => self.cancel_search().await?,
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
                self.contact_editor = None;
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
            AppCommand::MoveToAction => self.move_selected_route(WarmRoute::Action).await?,
            AppCommand::MoveToFyi => self.move_selected_route(WarmRoute::Fyi).await?,
            AppCommand::PreviewSimilarFyi => self.begin_similarity_preview().await?,
            AppCommand::SimilarityBroader => self.adjust_similarity_cutoff(-50).await?,
            AppCommand::SimilarityStricter => self.adjust_similarity_cutoff(50).await?,
            AppCommand::SimilarityConfirm => self.confirm_similarity_rule().await?,
            AppCommand::SimilarityCancel => self.cancel_similarity_preview(),
            AppCommand::RestrictedOpen => {
                if self.screen == Screen::Reader {
                    self.security_override = true;
                    self.reset_reader_scroll();
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
            AppCommand::ContactEdit => self.begin_selected_contact_edit().await?,
            AppCommand::ContactSave => self.save_contact().await?,
            AppCommand::EditNextField => self.move_editor_field(1),
            AppCommand::EditPreviousField => self.move_editor_field(-1),
            AppCommand::EditToggleChoice => self.toggle_editor_choice(),
            AppCommand::EditSpace => self.edit_space(),
            AppCommand::EditBackspace => self.edit_backspace(),
            AppCommand::EditCharacter(character) => self.edit_character(character),
            AppCommand::EditPaste(value) => self.edit_paste(&value),
        }
        Ok(())
    }

    /// Reaps a completed background synchronization without blocking terminal
    /// input while the isolated worker connects to a remote provider.
    /// Collect a finished synchronization, schedule the next automatic sync
    /// when its interval has elapsed, and start the next queued account.
    pub async fn poll_background_tasks(&mut self) -> Result<()> {
        self.collect_finished_reader_tasks().await;
        self.collect_smtp_worker().await;
        self.refresh_pending_submission(Instant::now()).await?;
        self.refresh_running_sync_progress(Instant::now()).await?;
        self.collect_finished_sync().await?;
        self.schedule_auto_sync(Instant::now());
        self.start_next_queued_sync()
    }

    async fn collect_smtp_worker(&mut self) {
        let Some(worker) = self.smtp_worker.take() else {
            return;
        };
        if !worker.handle.is_finished() {
            self.smtp_worker = Some(worker);
            return;
        }
        match worker.handle.await {
            Ok(Ok(())) if self.quit => {}
            Ok(Ok(())) => self.status = Some("Outgoing-mail worker stopped".into()),
            Ok(Err(error)) => {
                self.status = Some(format!("Outgoing-mail worker failed: {error}"));
            }
            Err(error) if error.is_cancelled() && self.quit => {}
            Err(error) => self.status = Some(format!("Outgoing-mail worker failed: {error}")),
        }
    }

    async fn refresh_pending_submission(&mut self, now: Instant) -> Result<()> {
        let Some(submission_id) = self.pending_submission else {
            self.last_submission_refresh = None;
            return Ok(());
        };
        if self
            .last_submission_refresh
            .is_some_and(|last| now.duration_since(last) < StdDuration::from_secs(1))
        {
            return Ok(());
        }
        self.last_submission_refresh = Some(now);
        let submission = self.backend.outbox().get(submission_id).await?;
        match submission.status {
            SubmissionStatus::Pending | SubmissionStatus::InFlight => {
                self.status = Some("Sending reply…".into());
            }
            SubmissionStatus::RetryScheduled => {
                self.status = Some(format!(
                    "Reply could not be sent yet; retry scheduled{}",
                    submission
                        .last_error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                ));
            }
            SubmissionStatus::Sent => {
                self.status = Some("Reply sent".into());
                self.pending_submission = None;
            }
            SubmissionStatus::Failed | SubmissionStatus::Ambiguous => {
                self.status = Some(format!(
                    "Reply delivery failed{}",
                    submission
                        .last_error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                ));
                self.pending_submission = None;
            }
            SubmissionStatus::Cancelled => {
                self.status = Some("Reply delivery was cancelled".into());
                self.pending_submission = None;
            }
        }
        Ok(())
    }

    async fn refresh_running_sync_progress(&mut self, now: Instant) -> Result<()> {
        let Some(account_id) = self.account_sync_task.as_ref().map(|task| task.account_id) else {
            self.last_sync_progress_refresh = None;
            return Ok(());
        };
        if self
            .last_sync_progress_refresh
            .is_some_and(|last| now.duration_since(last) < SYNC_PROGRESS_REFRESH_INTERVAL)
        {
            return Ok(());
        }
        self.last_sync_progress_refresh = Some(now);
        let state_reader = self
            .backend
            .managed_imap_account_engine_in_process(ImapAccountEngineConfig::default())?;
        let state = state_reader.state(account_id).await?;
        let previous_status = self
            .account_states
            .get(&account_id)
            .map(|state| state.status);
        self.background_status = Some(sync_background_status(&state));
        let refresh_headers = state.status
            == lizard_mail_backend::ImapAccountSyncStatus::Synchronizing
            || (state.status == lizard_mail_backend::ImapAccountSyncStatus::Hydrating
                && previous_status != Some(lizard_mail_backend::ImapAccountSyncStatus::Hydrating));
        self.account_states.insert(account_id, state);
        if refresh_headers && matches!(self.screen, Screen::Queue(_)) {
            self.refresh().await?;
        }
        Ok(())
    }

    async fn collect_finished_reader_tasks(&mut self) {
        if let Some(task) = self.reader_load_task.take() {
            if task.handle.is_finished() {
                let result = task.handle.await;
                if self.screen == Screen::Reader && self.reader_thread_id == Some(task.thread_id) {
                    match result {
                        Ok(Ok(thread)) => self.install_loaded_thread(task.thread_id, thread),
                        Ok(Err(error)) => {
                            self.status = Some(format!("Could not open conversation: {error}"));
                        }
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => {
                            self.status = Some(format!("Conversation loading failed: {error}"));
                        }
                    }
                }
            } else {
                self.reader_load_task = Some(task);
            }
        }

        if let Some(task) = self.reader_content_task.take() {
            if task.handle.is_finished() {
                let result = task.handle.await;
                if self.screen == Screen::Reader && self.reader_thread_id == Some(task.thread_id) {
                    match result {
                        Ok(Ok(thread)) => {
                            let complete = thread.messages.last().is_some_and(|message| {
                                message.summary.content_availability
                                    == MessageContentAvailability::Complete
                            });
                            self.current_thread = Some(thread);
                            self.clear_reader_html();
                            self.status = if complete {
                                None
                            } else {
                                Some("Message content and identity evidence are incomplete".into())
                            };
                        }
                        Ok(Err(error)) => {
                            self.status = Some(format!(
                                "Could not download and verify message content: {error}"
                            ));
                        }
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => {
                            self.status = Some(format!("Message download failed: {error}"));
                        }
                    }
                }
            } else {
                self.reader_content_task = Some(task);
            }
        }
    }

    fn install_loaded_thread(&mut self, thread_id: ThreadId, thread: Thread) {
        let message_id = thread.messages.last().map(|message| message.summary.id);
        let needs_content = thread.messages.last().is_some_and(|message| {
            message.summary.content_availability != MessageContentAvailability::Complete
        });
        self.current_thread = Some(thread);
        self.clear_reader_html();
        if needs_content {
            let Some(message_id) = message_id else {
                self.status = Some("Conversation contains no messages".into());
                return;
            };
            self.start_reader_content_load(thread_id, message_id);
        } else {
            self.status = None;
        }
    }

    fn start_reader_load(&mut self, thread_id: ThreadId) {
        if let Some(task) = self.reader_load_task.take() {
            task.handle.abort();
        }
        let backend = self.backend.clone();
        let target_message_id = self.reader_target_message_id;
        self.reader_thread_id = Some(thread_id);
        self.reader_load_task = Some(ReaderLoadTask {
            thread_id,
            handle: tokio::spawn(async move {
                let mut thread = backend.threads().get_latest(thread_id).await?;
                if let Some(message_id) = target_message_id {
                    if thread.messages.last().map(|message| message.summary.id) != Some(message_id)
                    {
                        thread.messages = vec![backend.messages().get(message_id).await?];
                    }
                }
                Ok(thread)
            }),
        });
    }

    fn start_reader_content_load(&mut self, thread_id: ThreadId, message_id: MessageId) {
        if let Some(task) = self.reader_content_task.take() {
            task.handle.abort();
        }
        let backend = self.backend.clone();
        let target_message_id = self.reader_target_message_id;
        self.reader_content_task = Some(ReaderContentTask {
            thread_id,
            handle: tokio::spawn(async move {
                backend
                    .managed_imap_account_engine(ImapAccountEngineConfig::default())?
                    .fetch_message_content(message_id)
                    .await?;
                let mut thread = backend.threads().get_latest(thread_id).await?;
                if let Some(target) = target_message_id {
                    if thread.messages.last().map(|message| message.summary.id) != Some(target) {
                        thread.messages = vec![backend.messages().get(target).await?];
                    }
                }
                Ok(thread)
            }),
        });
    }

    async fn collect_finished_sync(&mut self) -> Result<()> {
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
                if !report.offline_copy_complete {
                    self.background_status = Some(format!(
                        "Headers are current; local copy incomplete ({} downloaded, {} failed this pass)",
                        report.offline_downloaded_messages,
                        report.offline_download_failures
                    ));
                } else if fetched > 0 {
                    self.background_status = Some(format!(
                        "Synchronization complete: {fetched} new message headers and {} verified local messages across {} folders",
                        report.offline_downloaded_messages,
                        report.folders.len(),
                    ));
                } else if task.announce {
                    self.background_status =
                        Some("Headers and local mail copy are up to date".into());
                } else {
                    self.background_status = None;
                }
                if task.begin_contact_onboarding {
                    self.begin_contact_onboarding(task.account_id).await?;
                } else if matches!(self.screen, Screen::Queue(_)) {
                    self.refresh().await?;
                }
            }
            Err(error) => {
                self.background_status = Some(format!("Synchronization failed: {error}"));
            }
        }
        Ok(())
    }

    /// Queue one isolated header synchronization per configured IMAP account
    /// at startup and then once per interval.
    fn schedule_auto_sync(&mut self, now: Instant) {
        if !self.auto_sync {
            return;
        }
        if self
            .last_auto_sync
            .is_some_and(|last| now.duration_since(last) < self.auto_sync_interval)
        {
            return;
        }
        self.last_auto_sync = Some(now);
        let accounts = self
            .accounts
            .iter()
            .filter(|account| account.kind == AccountKind::Imap)
            .map(|account| account.id)
            .collect::<Vec<_>>();
        for account_id in accounts {
            self.enqueue_sync(account_id, false, false);
        }
    }

    fn enqueue_sync(
        &mut self,
        account_id: AccountId,
        announce: bool,
        begin_contact_onboarding: bool,
    ) -> bool {
        if self
            .account_sync_task
            .as_ref()
            .is_some_and(|task| task.account_id == account_id)
            || self
                .sync_queue
                .iter()
                .any(|request| request.account_id == account_id)
        {
            return false;
        }
        self.sync_queue.push_back(QueuedSync {
            account_id,
            announce,
            begin_contact_onboarding,
        });
        true
    }

    fn start_next_queued_sync(&mut self) -> Result<()> {
        if self.account_sync_task.is_some() {
            return Ok(());
        }
        let Some(request) = self.sync_queue.pop_front() else {
            return Ok(());
        };
        let engine = self
            .backend
            .managed_imap_account_engine(ImapAccountEngineConfig::default())?;
        self.background_status = Some("Synchronizing in an isolated worker…".into());
        self.account_sync_task = Some(AccountSyncTask {
            account_id: request.account_id,
            announce: request.announce,
            begin_contact_onboarding: request.begin_contact_onboarding,
            handle: tokio::spawn(async move { engine.sync_once(request.account_id).await }),
        });
        Ok(())
    }

    /// Enable background synchronization: each configured IMAP account syncs
    /// once at startup and again every automatic-sync interval.
    pub fn enable_auto_sync(&mut self) {
        self.auto_sync = true;
        self.last_auto_sync = None;
    }

    pub fn disable_auto_sync(&mut self) {
        self.auto_sync = false;
    }

    pub fn auto_sync_enabled(&self) -> bool {
        self.auto_sync
    }

    /// Accounts with a background synchronization waiting behind the running
    /// one, in execution order.
    pub fn queued_sync_accounts(&self) -> Vec<AccountId> {
        self.sync_queue
            .iter()
            .map(|request| request.account_id)
            .collect()
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

    pub fn reader_load_status(&self) -> Option<&'static str> {
        if self.reader_load_task.is_some() && self.current_thread.is_none() {
            Some("Opening conversation…")
        } else if self.reader_content_task.is_some() {
            Some("Downloading and verifying message content…")
        } else {
            None
        }
    }

    /// Prepares the current HTML body outside the terminal drawing closure.
    ///
    /// The renderer is a disposable Linux worker. Failure is deliberately not
    /// fatal to the mail client: the UI falls back to the backend's bounded
    /// plain-text body and never retries the same failed content every frame.
    /// Rendering is scheduled in the background so even a worker timeout can
    /// never delay the reader's first frame or terminal input.
    pub async fn prepare_reader_html(&mut self, width: u16) {
        self.collect_finished_html_render().await;
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
        if message.summary.content_availability != MessageContentAvailability::Complete {
            self.clear_reader_html();
            return;
        }
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
        if let Some(task) = self.reader_html_task.take() {
            task.handle.abort();
        }
        self.reader_html = None;
        self.reader_html_error = None;
        self.reader_html_key = Some(key);
        let renderer = self.html_renderer.clone();
        self.reader_html_task = Some(ReaderHtmlTask {
            key,
            handle: tokio::spawn(async move {
                renderer
                    .render(&html, width)
                    .await
                    .map_err(|error| error.to_string())
            }),
        });
    }

    async fn collect_finished_html_render(&mut self) {
        let Some(task) = self.reader_html_task.take() else {
            return;
        };
        if !task.handle.is_finished() {
            self.reader_html_task = Some(task);
            return;
        }
        let result = task.handle.await;
        if self.reader_html_key != Some(task.key) {
            return;
        }
        match result {
            Ok(Ok(page)) => self.reader_html = Some(page),
            Ok(Err(error)) => self.reader_html_error = Some(error),
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                self.reader_html_error = Some(format!("HTML rendering task failed: {error}"));
            }
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

    fn selected_contact(&self) -> Option<&Contact> {
        self.contacts.get(self.selected)
    }

    async fn refresh_contacts(&mut self) -> Result<()> {
        self.contacts = self.backend.contacts().list().await?;
        self.contact_relationships = self
            .backend
            .contacts()
            .relationships()
            .await?
            .into_iter()
            .map(|relationship| (relationship.contact_id, relationship))
            .collect();
        self.rebuild_contact_names();
        Ok(())
    }

    async fn begin_selected_contact_edit(&mut self) -> Result<()> {
        let Some(contact) = self.selected_contact().cloned() else {
            return Ok(());
        };
        let relationship = self.backend.contacts().relationship(contact.id).await?;
        self.contact_editor = Some(ContactEditor::new(contact, relationship));
        self.screen = Screen::ContactEdit;
        Ok(())
    }

    async fn save_contact(&mut self) -> Result<()> {
        let Some(editor) = self.contact_editor.take() else {
            return Ok(());
        };
        let display_name = editor.display_name.trim().to_owned();
        if display_name.is_empty() {
            self.status = Some("A contact needs a display name".into());
            self.contact_editor = Some(editor);
            return Ok(());
        }
        let addresses = editor
            .addresses
            .split([',', ';'])
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(|address| {
                let accepted_name = editor
                    .original_addresses
                    .iter()
                    .find(|existing| existing.address.eq_ignore_ascii_case(address))
                    .and_then(|existing| existing.accepted_name.clone());
                ContactAddress {
                    address: address.to_owned(),
                    accepted_name,
                }
            })
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            self.status = Some("A contact needs at least one email address".into());
            self.contact_editor = Some(editor);
            return Ok(());
        }
        let contact_id = editor.contact_id;
        let updated = self
            .backend
            .contacts()
            .update(
                contact_id,
                NewContact {
                    display_name,
                    addresses,
                },
            )
            .await;
        if let Err(error) = updated {
            self.contact_editor = Some(editor);
            return Err(error);
        }
        if let Err(error) = self
            .backend
            .contacts()
            .set_relationship(contact_id, editor.relationship.clone())
            .await
        {
            self.contact_editor = Some(editor);
            return Err(error);
        }
        self.refresh_contacts().await?;
        self.selected = self
            .contacts
            .iter()
            .position(|contact| contact.id == contact_id)
            .unwrap_or(0);
        self.screen = Screen::Contacts;
        self.status = Some("Contact and future-mail workflow updated".into());
        Ok(())
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

    fn begin_search(&mut self) {
        if self.screen == Screen::SearchInput {
            return;
        }
        if self.screen != Screen::SearchResults
            && !(self.screen == Screen::Reader && self.previous_screen == Screen::SearchResults)
        {
            self.search_return_selected = self.selected;
        }
        self.search_return_screen = match self.screen {
            Screen::Reader if self.previous_screen == Screen::SearchResults => {
                self.search_return_screen
            }
            Screen::Reader => Screen::Reader,
            Screen::SearchResults => self.search_return_screen,
            screen => screen,
        };
        self.search_editor = Some(SearchEditor {
            query: self.search_query.clone(),
        });
        self.screen = Screen::SearchInput;
        self.status = Some(
            "Search supports Gmail-style fields such as from:, to:, subject:, has:attachment, and after:"
                .into(),
        );
    }

    async fn submit_search(&mut self) -> Result<()> {
        let Some(editor) = self.search_editor.take() else {
            return Ok(());
        };
        let query = editor.query.trim().to_owned();
        if query.is_empty() {
            self.status = Some("Enter at least one search term".into());
            self.search_editor = Some(editor);
            return Ok(());
        }
        if let Err(error) = self.execute_search(query).await {
            self.search_editor = Some(editor);
            return Err(error);
        }
        Ok(())
    }

    async fn execute_search(&mut self, query: String) -> Result<()> {
        let page = self
            .backend
            .search()
            .search(SearchRequest {
                query: query.clone(),
                page_size: 200,
                cursor: None,
            })
            .await?;
        self.search_query = query;
        self.search_has_more = page.next_cursor.is_some();
        self.search_results = page.items;
        self.search_index_complete = page.index_results_complete;
        self.search_content_complete = page.content_results_complete;
        self.search_editor = None;
        if self.search_return_screen == Screen::Reader {
            self.search_return_screen = self.previous_screen;
        }
        self.screen = Screen::SearchResults;
        self.selected = 0;
        let count = self.search_results.len();
        let mut status = if self.search_has_more {
            format!("Showing the first {count} results; refine the query to narrow them")
        } else {
            format!("{count} search results")
        };
        if !self.search_index_complete {
            status.push_str("; the search index is still catching up");
        } else if !self.search_content_complete {
            status.push_str("; some message bodies are not downloaded");
        }
        self.status = Some(status);
        Ok(())
    }

    async fn cancel_search(&mut self) -> Result<()> {
        self.search_editor = None;
        self.screen = self.search_return_screen;
        self.selected = self.search_return_selected;
        self.refresh().await
    }

    async fn begin_reply(&mut self, audience: ReplyAudience) -> Result<()> {
        if self.screen != Screen::Reader {
            return Ok(());
        }
        if self.reader_is_blocked() && !self.security_override {
            self.status = Some(
                "Review the security warning and press O before choosing reply recipients".into(),
            );
            return Ok(());
        }
        let Some(message) = self
            .current_thread
            .as_ref()
            .and_then(|thread| thread.messages.last())
        else {
            self.status = Some("Wait for the message to finish loading before replying".into());
            return Ok(());
        };
        let account_id = message
            .instances
            .first()
            .map(|instance| instance.account_id)
            .or_else(|| (self.accounts.len() == 1).then(|| self.accounts[0].id));
        let Some(account_id) = account_id else {
            self.status = Some(
                "Could not determine which account received this message; reply was not created"
                    .into(),
            );
            return Ok(());
        };
        let existing = self
            .backend
            .drafts()
            .editing_reply(account_id, message.summary.id)
            .await?;
        let resumed = existing.is_some();
        let draft = match existing {
            Some(draft) => draft,
            None => {
                self.backend
                    .drafts()
                    .create_reply(account_id, message.summary.id, audience)
                    .await?
            }
        };
        let recipient_summary = draft.content.to_addresses.join(", ");
        self.compose_editor = Some(ComposeEditor::new(draft));
        self.screen = Screen::Compose;
        self.status = Some(if self.smtp_accounts.contains_key(&account_id) {
            if resumed {
                format!("Resumed saved reply to {recipient_summary}")
            } else {
                format!("Replying to {recipient_summary}")
            }
        } else {
            format!(
                "Draft created for {recipient_summary}; configure the SMTP server under Accounts before sending"
            )
        });
        Ok(())
    }

    async fn save_compose_draft(&mut self, announce: bool) -> Result<()> {
        let Some(mut editor) = self.compose_editor.take() else {
            return Ok(());
        };
        let to_addresses = match parse_recipient_list(&editor.to) {
            Ok(addresses) => addresses,
            Err(error) => {
                self.compose_editor = Some(editor);
                return Err(error);
            }
        };
        let cc_addresses = match parse_recipient_list(&editor.cc) {
            Ok(addresses) => addresses,
            Err(error) => {
                self.compose_editor = Some(editor);
                return Err(error);
            }
        };
        let mut content = editor.draft.content.clone();
        content.to_addresses = to_addresses;
        content.cc_addresses = cc_addresses;
        content.subject = editor.subject.clone();
        content.body_text = editor.body.clone();
        content.body_html = None;
        match self
            .backend
            .drafts()
            .save(editor.draft.id, editor.draft.revision, content)
            .await
        {
            Ok(draft) => {
                editor.draft = draft;
                self.compose_editor = Some(editor);
                if announce {
                    self.status = Some("Draft saved".into());
                }
                Ok(())
            }
            Err(error) => {
                self.compose_editor = Some(editor);
                Err(error)
            }
        }
    }

    async fn send_compose(&mut self) -> Result<()> {
        self.save_compose_draft(false).await?;
        let Some(editor) = self.compose_editor.take() else {
            return Ok(());
        };
        let submission = match self
            .backend
            .outbox()
            .enqueue(
                editor.draft.id,
                editor.draft.revision,
                SendingLimits::default(),
            )
            .await
        {
            Ok(submission) => submission,
            Err(error) => {
                self.compose_editor = Some(editor);
                return Err(error);
            }
        };
        self.pending_submission = Some(submission.id);
        self.last_submission_refresh = None;
        self.screen = Screen::Reader;
        self.status = Some("Reply queued for encrypted SMTP submission".into());
        Ok(())
    }

    fn compose_newline(&mut self) {
        let Some(editor) = &mut self.compose_editor else {
            return;
        };
        if editor.selected_field == ComposeField::Body {
            if editor.body.len() < 10 * 1024 * 1024 {
                editor.body.push('\n');
            }
        } else {
            self.move_compose_field(1);
        }
    }

    fn move_compose_field(&mut self, delta: isize) {
        let Some(editor) = &mut self.compose_editor else {
            return;
        };
        let index = ComposeField::ALL
            .iter()
            .position(|field| *field == editor.selected_field)
            .unwrap_or(0);
        let last = ComposeField::ALL.len().saturating_sub(1);
        editor.selected_field = ComposeField::ALL[index.saturating_add_signed(delta).min(last)];
    }

    async fn refresh_accounts(&mut self) -> Result<()> {
        self.accounts = self.backend.accounts().list().await?;
        self.account_states.clear();
        self.smtp_accounts.clear();
        // Reading durable sync state does not touch the network or parse any
        // server input, so this does not bypass the isolated production sync
        // path used below.
        let state_reader = self
            .backend
            .managed_imap_account_engine_in_process(ImapAccountEngineConfig::default())?;
        for account in &self.accounts {
            match self.backend.sending().smtp_account(account.id).await {
                Ok(smtp) => {
                    self.smtp_accounts.insert(account.id, smtp);
                }
                Err(BackendError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
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
        self.account_editor = Some(AccountEditor::from_account(
            &account,
            authentication,
            self.smtp_accounts.get(&account.id),
        )?);
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
        let smtp_host = editor.smtp_host.trim().to_owned();
        let smtp_settings = if smtp_host.is_empty() {
            None
        } else {
            let smtp_port = match editor.smtp_port.parse::<u16>() {
                Ok(port) if port > 0 => port,
                _ => {
                    self.status = Some("SMTP port must be a number from 1 through 65535".into());
                    self.account_editor = Some(editor);
                    return Ok(());
                }
            };
            Some(SmtpSettings {
                host: smtp_host,
                port: smtp_port,
                username: username.clone(),
                security: editor.smtp_security,
                auth: match editor.authentication {
                    AccountAuthentication::Password => SmtpAuthMethod::Password,
                    AccountAuthentication::OAuthAccessToken => SmtpAuthMethod::XOAuth2,
                },
            })
        };
        let trusted_authserv_ids = match parse_trusted_authserv_ids(&editor.trusted_authserv_ids) {
            Ok(values) => values,
            Err(detail) => {
                self.status = Some(detail);
                self.account_editor = Some(editor);
                return Ok(());
            }
        };
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
                username: username.clone(),
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
            Ok(saved) => match self
                .backend
                .accounts()
                .set_trusted_authserv_ids(saved.id, trusted_authserv_ids)
                .await
            {
                Ok(saved) => saved,
                Err(error) => {
                    // The account and credential have already committed. Keep
                    // editing that exact account rather than letting a retry
                    // create a duplicate.
                    editor.account_id = Some(saved.id);
                    editor.credential_ref = saved.credential_ref;
                    editor.secret_entered = false;
                    self.account_editor = Some(editor);
                    return Err(error);
                }
            },
            Err(error) => {
                // A failed credential write has consumed and zeroized the
                // attempted secret. Keep the non-secret fields for correction,
                // but require the user to enter the secret again.
                editor.secret_entered = false;
                self.account_editor = Some(editor);
                return Err(error);
            }
        };
        let smtp_followed_imap_credential = editor.original_smtp_credential_ref.is_some()
            && editor.original_smtp_credential_ref == editor.credential_ref;
        let smtp_result = match (&smtp_settings, &editor.original_smtp_settings) {
            (Some(settings), original)
                if original.as_ref() != Some(settings)
                    || (smtp_followed_imap_credential
                        && editor.original_smtp_credential_ref != saved.credential_ref) =>
            {
                if let Some(credential_ref) = saved.credential_ref.clone() {
                    self.backend
                        .sending()
                        .configure_smtp(saved.id, settings.clone(), credential_ref)
                        .await
                        .map(|_| ())
                } else {
                    Err(BackendError::InvalidInput(
                        "the IMAP account has no reusable credential for SMTP".into(),
                    ))
                }
            }
            (None, Some(_)) => self.backend.sending().remove_smtp(saved.id).await,
            _ => Ok(()),
        };
        if let Err(error) = smtp_result {
            editor.account_id = Some(saved.id);
            editor.credential_ref = saved.credential_ref;
            editor.secret_entered = false;
            self.account_editor = Some(editor);
            return Err(error);
        }
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
        self.enqueue_sync(saved.id, true, first_account);
        if let Err(error) = self.start_next_queued_sync() {
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
        let newly_queued = self.enqueue_sync(account_id, true, false);
        if self.account_sync_task.is_some() {
            self.status = Some(
                if newly_queued {
                    "Synchronization queued behind the running account"
                } else {
                    "This account is already synchronizing"
                }
                .into(),
            );
            return Ok(());
        }
        self.start_next_queued_sync()
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
        self.sync_queue
            .retain(|request| request.account_id != account_id);
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

    fn move_editor_field(&mut self, delta: isize) {
        if self.compose_editor.is_some() {
            self.move_compose_field(delta);
        } else if let Some(editor) = &mut self.contact_editor {
            let index = ContactField::ALL
                .iter()
                .position(|field| *field == editor.selected_field)
                .unwrap_or(0);
            let last = ContactField::ALL.len().saturating_sub(1);
            editor.selected_field = ContactField::ALL[index.saturating_add_signed(delta).min(last)];
        } else {
            self.move_account_field(delta);
        }
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
            AccountField::SmtpSecurity => {
                editor.smtp_security = match editor.smtp_security {
                    SmtpSecurity::ImplicitTls => {
                        if editor.smtp_port == "465" {
                            editor.smtp_port = "587".into();
                        }
                        SmtpSecurity::StartTls
                    }
                    SmtpSecurity::StartTls => {
                        if editor.smtp_port == "587" {
                            editor.smtp_port = "465".into();
                        }
                        SmtpSecurity::ImplicitTls
                    }
                };
            }
            _ => {}
        }
    }

    fn toggle_editor_choice(&mut self) {
        let Some(editor) = &mut self.contact_editor else {
            self.toggle_account_choice();
            return;
        };
        match editor.selected_field {
            ContactField::Kind => cycle_relationship_kind(&mut editor.relationship.kind),
            ContactField::Route => {
                let action = editor.relationship.warm_route != WarmRoute::Action;
                editor.relationship.warm_route = if action {
                    WarmRoute::Action
                } else {
                    WarmRoute::Fyi
                };
                editor.relationship.may_create_obligations = action;
            }
            ContactField::Notifications => {
                editor.relationship.notify = !editor.relationship.notify;
            }
            ContactField::RemoteContent => {
                editor.relationship.remote_content = match editor.relationship.remote_content {
                    RemoteContentPolicy::Ask => RemoteContentPolicy::Allow,
                    RemoteContentPolicy::Allow => RemoteContentPolicy::Block,
                    RemoteContentPolicy::Block => RemoteContentPolicy::Ask,
                };
            }
            ContactField::Name | ContactField::Addresses => {}
        }
    }

    fn edit_space(&mut self) {
        if self.contact_editor.as_ref().is_some_and(|editor| {
            !matches!(
                editor.selected_field,
                ContactField::Name | ContactField::Addresses
            )
        }) {
            self.toggle_editor_choice();
            return;
        }
        if self.account_editor.as_ref().is_some_and(|editor| {
            matches!(
                editor.selected_field,
                AccountField::Security | AccountField::Authentication | AccountField::SmtpSecurity
            )
        }) {
            self.toggle_account_choice();
        } else {
            self.edit_character(' ');
        }
    }

    fn edit_backspace(&mut self) {
        if let Some(editor) = &mut self.search_editor {
            editor.query.pop();
            return;
        }
        if let Some(editor) = &mut self.compose_editor {
            match editor.selected_field {
                ComposeField::To => {
                    editor.to.pop();
                }
                ComposeField::Cc => {
                    editor.cc.pop();
                }
                ComposeField::Subject => {
                    editor.subject.pop();
                }
                ComposeField::Body => {
                    editor.body.pop();
                }
            }
            return;
        }
        if let Some(edit) = &mut self.onboarding_edit {
            edit.display_name.pop();
            return;
        }
        if let Some(editor) = &mut self.contact_editor {
            match editor.selected_field {
                ContactField::Name => {
                    editor.display_name.pop();
                }
                ContactField::Addresses => {
                    editor.addresses.pop();
                }
                ContactField::Kind
                | ContactField::Route
                | ContactField::Notifications
                | ContactField::RemoteContent => {}
            }
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
            AccountField::AuthservIds => {
                editor.trusted_authserv_ids.pop();
            }
            AccountField::SmtpHost => {
                editor.smtp_host.pop();
            }
            AccountField::SmtpPort => {
                editor.smtp_port.pop();
            }
            AccountField::Secret => {
                editor.secret.pop();
                editor.secret_entered = !editor.secret.is_empty();
            }
            AccountField::Security | AccountField::Authentication | AccountField::SmtpSecurity => {}
        }
    }

    fn edit_character(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        if let Some(editor) = &mut self.search_editor {
            if editor.query.len() < 8 * 1024 {
                editor.query.push(character);
            }
            return;
        }
        if let Some(editor) = &mut self.compose_editor {
            match editor.selected_field {
                ComposeField::To if editor.to.len() < 16 * 1024 => editor.to.push(character),
                ComposeField::Cc if editor.cc.len() < 16 * 1024 => editor.cc.push(character),
                ComposeField::Subject if editor.subject.len() < 998 => {
                    editor.subject.push(character)
                }
                ComposeField::Body if editor.body.len() < 10 * 1024 * 1024 => {
                    editor.body.push(character)
                }
                ComposeField::To
                | ComposeField::Cc
                | ComposeField::Subject
                | ComposeField::Body => {}
            }
            return;
        }
        if let Some(edit) = &mut self.onboarding_edit {
            if edit.display_name.len() < 200 {
                edit.display_name.push(character);
            }
            return;
        }
        if let Some(editor) = &mut self.contact_editor {
            match editor.selected_field {
                ContactField::Name if editor.display_name.len() < 200 => {
                    editor.display_name.push(character)
                }
                ContactField::Addresses
                    if editor.addresses.len() < 16 * 1024 && !character.is_whitespace() =>
                {
                    editor.addresses.push(character)
                }
                ContactField::Name
                | ContactField::Addresses
                | ContactField::Kind
                | ContactField::Route
                | ContactField::Notifications
                | ContactField::RemoteContent => {}
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
            AccountField::AuthservIds
                if editor.trusted_authserv_ids.len() < 8 * 1024
                    && !matches!(character, '\r' | '\n' | '\t') =>
            {
                editor.trusted_authserv_ids.push(character)
            }
            AccountField::SmtpHost
                if editor.smtp_host.len() < 253 && !character.is_whitespace() =>
            {
                editor.smtp_host.push(character)
            }
            AccountField::SmtpPort if editor.smtp_port.len() < 5 && character.is_ascii_digit() => {
                editor.smtp_port.push(character)
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
            | AccountField::AuthservIds
            | AccountField::SmtpHost
            | AccountField::SmtpPort
            | AccountField::SmtpSecurity
            | AccountField::Secret => {}
        }
    }

    fn edit_paste(&mut self, value: &str) {
        if self.search_editor.is_some() {
            for character in value.chars() {
                if !character.is_control() || character == '\t' {
                    self.edit_character(if character == '\t' { ' ' } else { character });
                }
            }
            return;
        }
        if let Some(field) = self
            .compose_editor
            .as_ref()
            .map(|editor| editor.selected_field)
        {
            for character in value.chars() {
                match field {
                    ComposeField::Body if matches!(character, '\n' | '\t') => {
                        if let Some(editor) = &mut self.compose_editor {
                            if editor.body.len() < 10 * 1024 * 1024 {
                                editor.body.push(character);
                            }
                        }
                    }
                    ComposeField::Body if character == '\r' => {}
                    ComposeField::To | ComposeField::Cc | ComposeField::Subject
                        if matches!(character, '\r' | '\n' | '\t') =>
                    {
                        if field != ComposeField::Subject {
                            self.edit_character(',');
                        }
                    }
                    _ if !character.is_control() => self.edit_character(character),
                    _ => {}
                }
            }
            return;
        }
        let contact_addresses = self
            .contact_editor
            .as_ref()
            .is_some_and(|editor| editor.selected_field == ContactField::Addresses);
        for character in value.chars() {
            if contact_addresses && matches!(character, '\r' | '\n' | '\t') {
                self.edit_character(',');
            } else if !character.is_control() {
                self.edit_character(character);
            }
        }
    }

    async fn switch_queue(&mut self, workflow: WorkflowView) -> Result<()> {
        self.cancel_reader_tasks();
        self.screen = Screen::Queue(workflow);
        self.previous_screen = self.screen;
        self.selected = 0;
        self.current_thread = None;
        self.security_override = false;
        self.reset_reader_scroll();
        self.clear_reader_html();
        self.refresh().await
    }

    async fn open_selected(&mut self) -> Result<()> {
        match self.screen {
            Screen::Queue(_) => {
                if let Some(id) = self.selected_thread().map(|summary| summary.id) {
                    self.previous_screen = self.screen;
                    self.screen = Screen::Reader;
                    self.current_thread = None;
                    self.reader_target_message_id = None;
                    self.security_override = false;
                    self.reset_reader_scroll();
                    self.clear_reader_html();
                    self.start_reader_load(id);
                }
            }
            Screen::SearchResults => {
                if let Some(result) = self.search_results.get(self.selected).cloned() {
                    self.previous_screen = Screen::SearchResults;
                    self.screen = Screen::Reader;
                    self.current_thread = None;
                    self.reader_target_message_id = Some(result.id);
                    self.security_override = false;
                    self.reset_reader_scroll();
                    self.clear_reader_html();
                    self.start_reader_load(result.thread_id);
                }
            }
            Screen::Onboarding => self.begin_suggestion_edit(),
            Screen::Accounts => self.begin_selected_account_edit().await?,
            Screen::Contacts => self.begin_selected_contact_edit().await?,
            _ => {}
        }
        Ok(())
    }

    async fn go_back(&mut self) -> Result<()> {
        match self.screen {
            Screen::SimilarityPreview => self.cancel_similarity_preview(),
            Screen::SearchInput => self.cancel_search().await?,
            Screen::SearchResults => self.cancel_search().await?,
            Screen::Compose => {
                self.save_compose_draft(false).await?;
                self.compose_editor = None;
                self.screen = Screen::Reader;
                self.status = Some("Draft saved".into());
            }
            Screen::Reader | Screen::Contacts | Screen::Help | Screen::Accounts => {
                if self.screen == Screen::Reader {
                    self.cancel_reader_tasks();
                }
                self.screen = self.previous_screen;
                self.current_thread = None;
                self.security_override = false;
                self.reset_reader_scroll();
                self.clear_reader_html();
                self.refresh().await?;
            }
            Screen::AccountEdit => {
                self.account_editor = None;
                self.screen = Screen::Accounts;
                self.refresh_accounts().await?;
            }
            Screen::ContactEdit => {
                self.contact_editor = None;
                self.screen = Screen::Contacts;
                self.refresh_contacts().await?;
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
        let was_reader = self.screen == Screen::Reader;
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
            if was_reader && status == ThreadWorkStatus::Done {
                self.remove_current_reader_and_advance(id).await?;
            } else if was_reader {
                self.cancel_reader_tasks();
                self.screen = self.previous_screen;
                self.current_thread = None;
                self.clear_reader_html();
                self.refresh().await?;
            } else {
                self.refresh().await?;
            }
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
                self.cancel_reader_tasks();
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

    async fn move_selected_route(&mut self, route: WarmRoute) -> Result<()> {
        let Some(source) = self.active_workflow() else {
            return Ok(());
        };
        let allowed = matches!(
            (source, route),
            (WorkflowView::WarmAction, WarmRoute::Fyi) | (WorkflowView::WarmFyi, WarmRoute::Action)
        );
        if !allowed {
            self.status = Some(match (source, route) {
                (WorkflowView::WarmAction, WarmRoute::Action) => {
                    "Conversation is already in Action".into()
                }
                (WorkflowView::WarmFyi, WarmRoute::Fyi) => "Conversation is already in FYI".into(),
                (WorkflowView::SpamQuarantine, _) => {
                    "Spam must be rescued before assigning an Action/FYI workflow".into()
                }
                _ => "Action/FYI routing is available from the Action and FYI inboxes".into(),
            });
            return Ok(());
        }
        let was_reader = self.screen == Screen::Reader;
        let id = match self.screen {
            Screen::Reader => self.current_thread.as_ref().map(|thread| thread.summary.id),
            Screen::Queue(WorkflowView::WarmAction | WorkflowView::WarmFyi) => {
                self.selected_thread().map(|thread| thread.id)
            }
            _ => None,
        };
        if let Some(id) = id {
            self.backend
                .threads()
                .set_route_override(id, Some(route))
                .await?;
            self.status = Some(match route {
                WarmRoute::Action => "Conversation moved to Action".into(),
                WarmRoute::Fyi => "Conversation moved to FYI".into(),
            });
            if was_reader {
                self.remove_current_reader_and_advance(id).await?;
            } else {
                self.refresh().await?;
            }
        }
        Ok(())
    }

    fn active_workflow(&self) -> Option<WorkflowView> {
        match self.screen {
            Screen::Queue(workflow) => Some(workflow),
            Screen::Reader => match self.previous_screen {
                Screen::Queue(workflow) => Some(workflow),
                _ => None,
            },
            _ => None,
        }
    }

    async fn remove_current_reader_and_advance(&mut self, id: ThreadId) -> Result<()> {
        if self.previous_screen == Screen::SearchResults {
            let selected = self.selected;
            self.search_results
                .retain(|message| message.thread_id != id);
            if self.search_results.is_empty() {
                self.cancel_reader_tasks();
                self.screen = Screen::SearchResults;
                self.current_thread = None;
                self.selected = 0;
                self.clear_reader_html();
                return Ok(());
            }
            self.selected = selected.min(self.search_results.len().saturating_sub(1));
            let result = self.search_results[self.selected].clone();
            self.cancel_reader_tasks();
            self.reader_target_message_id = Some(result.id);
            self.current_thread = None;
            self.security_override = false;
            self.reset_reader_scroll();
            self.clear_reader_html();
            self.start_reader_load(result.thread_id);
            return Ok(());
        }
        let removed_index = self
            .threads
            .iter()
            .position(|thread| thread.id == id)
            .unwrap_or(self.selected.min(self.threads.len()));
        if removed_index < self.threads.len() {
            self.threads.remove(removed_index);
        }

        if let Some(next) = self.threads.get(removed_index) {
            self.selected = removed_index;
            let next_id = next.id;
            self.cancel_reader_tasks();
            self.current_thread = None;
            self.security_override = false;
            self.reset_reader_scroll();
            self.clear_reader_html();
            self.start_reader_load(next_id);
        } else {
            self.cancel_reader_tasks();
            self.screen = self.previous_screen;
            self.current_thread = None;
            self.security_override = false;
            self.reset_reader_scroll();
            self.clear_reader_html();
            self.refresh().await?;
        }
        Ok(())
    }

    async fn begin_similarity_preview(&mut self) -> Result<()> {
        if self.screen == Screen::Queue(WorkflowView::SpamQuarantine)
            || (self.screen == Screen::Reader
                && self.previous_screen == Screen::Queue(WorkflowView::SpamQuarantine))
        {
            self.status = Some("Spam must be rescued before creating a routing rule".into());
            return Ok(());
        }
        let thread = match self.screen {
            Screen::Reader => {
                if let Some(id) = self.current_thread.as_ref().map(|thread| thread.summary.id) {
                    Some(self.backend.threads().get(id).await?)
                } else {
                    None
                }
            }
            Screen::Queue(_) => {
                if let Some(id) = self.selected_thread().map(|thread| thread.id) {
                    Some(self.backend.threads().get(id).await?)
                } else {
                    None
                }
            }
            _ => None,
        };
        let seed_message_id = thread.as_ref().and_then(|thread| {
            thread.messages.iter().rev().find_map(|message| {
                let address = message.summary.from_address.as_deref()?.to_lowercase();
                self.contact_names
                    .contains_key(&address)
                    .then_some(message.summary.id)
            })
        });
        let Some(seed_message_id) = seed_message_id else {
            self.status = Some(
                "Similar-mail routing needs a message from a known contact in this conversation"
                    .into(),
            );
            return Ok(());
        };
        let preview = self
            .backend
            .similarity_rules()
            .preview(
                seed_message_id,
                WarmRoute::Fyi,
                DEFAULT_SIMILARITY_CUTOFF_MILLIS,
                SIMILARITY_PREVIEW_LIMIT,
            )
            .await?;
        self.similarity_return_screen = Some(self.screen);
        self.similarity_preview = Some(preview);
        self.similarity_selected = 0;
        self.screen = Screen::SimilarityPreview;
        Ok(())
    }

    async fn adjust_similarity_cutoff(&mut self, delta: i16) -> Result<()> {
        let Some(current) = self.similarity_preview.as_ref() else {
            return Ok(());
        };
        let seed = current.seed_message_id;
        let cutoff = i32::from(current.cutoff_millis)
            .saturating_add(i32::from(delta))
            .clamp(100, 1_000) as u16;
        self.similarity_preview = Some(
            self.backend
                .similarity_rules()
                .preview(seed, WarmRoute::Fyi, cutoff, SIMILARITY_PREVIEW_LIMIT)
                .await?,
        );
        self.similarity_selected = self.similarity_selected.min(
            self.similarity_preview
                .as_ref()
                .map_or(0, |preview| preview.matches.len().saturating_sub(1)),
        );
        Ok(())
    }

    async fn confirm_similarity_rule(&mut self) -> Result<()> {
        let Some(preview) = self.similarity_preview.clone() else {
            return Ok(());
        };
        let refreshed = self
            .backend
            .similarity_rules()
            .preview(
                preview.seed_message_id,
                preview.route,
                preview.cutoff_millis,
                SIMILARITY_PREVIEW_LIMIT,
            )
            .await?;
        if refreshed.match_set_digest != preview.match_set_digest {
            self.similarity_preview = Some(refreshed);
            self.similarity_selected = 0;
            self.status = Some(
                "New matching mail arrived; review the refreshed list, then confirm again".into(),
            );
            return Ok(());
        }
        self.similarity_preview = Some(refreshed.clone());
        let application = self
            .backend
            .similarity_rules()
            .create_from_preview(&refreshed)
            .await?;
        self.similarity_preview = None;
        self.similarity_return_screen = None;
        self.status = Some(format!(
            "FYI rule saved: {} messages across {} conversations",
            application.matching_messages, application.affected_threads
        ));
        self.switch_queue(WorkflowView::WarmFyi).await
    }

    fn cancel_similarity_preview(&mut self) {
        self.similarity_preview = None;
        self.screen = self
            .similarity_return_screen
            .take()
            .unwrap_or(Screen::Queue(WorkflowView::WarmAction));
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
            cycle_relationship_kind(&mut edit.relationship.kind);
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.screen == Screen::SimilarityPreview {
            let length = self
                .similarity_preview
                .as_ref()
                .map_or(0, |preview| preview.matches.len());
            if length == 0 {
                self.similarity_selected = 0;
            } else {
                self.similarity_selected = self
                    .similarity_selected
                    .saturating_add_signed(delta)
                    .min(length.saturating_sub(1));
            }
            return;
        }
        let length = match self.screen {
            Screen::Accounts => self.accounts.len(),
            Screen::Onboarding => self.suggestions.len(),
            Screen::Contacts => self.contacts.len(),
            Screen::Queue(_) => self.threads.len(),
            Screen::SearchResults => self.search_results.len(),
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

    fn open_adjacent_reader(&mut self, delta: isize) {
        if self.screen != Screen::Reader {
            return;
        }
        if self.previous_screen == Screen::SearchResults {
            if self.search_results.is_empty() {
                return;
            }
            let next = self
                .selected
                .saturating_add_signed(delta)
                .min(self.search_results.len().saturating_sub(1));
            if next == self.selected {
                self.status = Some(if delta < 0 {
                    "Already at the first search result".into()
                } else {
                    "Already at the last search result".into()
                });
                return;
            }
            self.selected = next;
            let result = self.search_results[next].clone();
            self.cancel_reader_tasks();
            self.reader_target_message_id = Some(result.id);
            self.current_thread = None;
            self.security_override = false;
            self.reset_reader_scroll();
            self.clear_reader_html();
            self.start_reader_load(result.thread_id);
            return;
        }
        if self.threads.is_empty() {
            return;
        }
        let next = self
            .selected
            .saturating_add_signed(delta)
            .min(self.threads.len().saturating_sub(1));
        if next == self.selected {
            self.status = Some(if delta < 0 {
                "Already at the first conversation in this inbox".into()
            } else {
                "Already at the last conversation in this inbox".into()
            });
            return;
        }
        self.selected = next;
        let thread_id = self.threads[next].id;
        self.cancel_reader_tasks();
        self.current_thread = None;
        self.security_override = false;
        self.reset_reader_scroll();
        self.clear_reader_html();
        self.start_reader_load(thread_id);
    }

    fn scroll_reader(&mut self, delta: isize) {
        if self.screen == Screen::Reader {
            self.reader_scroll = self
                .reader_scroll
                .saturating_add_signed(delta)
                .min(self.reader_scroll_max.get());
        }
    }

    fn page_reader(&mut self, delta: isize) {
        let page = self.reader_viewport_rows.get().saturating_sub(1).max(1);
        self.scroll_reader(delta.saturating_mul(isize::try_from(page).unwrap_or(isize::MAX)));
    }

    pub(crate) fn update_reader_scroll_bounds(
        &self,
        content_rows: usize,
        viewport_rows: usize,
    ) -> usize {
        self.reader_viewport_rows.set(viewport_rows.max(1));
        self.reader_scroll_max
            .set(content_rows.saturating_sub(self.reader_viewport_rows.get()));
        self.reader_scroll.min(self.reader_scroll_max.get())
    }

    fn reset_reader_scroll(&mut self) {
        self.reader_scroll = 0;
        self.reader_scroll_max.set(0);
        self.reader_viewport_rows.set(1);
    }

    fn clamp_selection(&mut self) {
        let length = match self.screen {
            Screen::Accounts => self.accounts.len(),
            Screen::Onboarding => self.suggestions.len(),
            Screen::Contacts => self.contacts.len(),
            Screen::Queue(_) => self.threads.len(),
            Screen::SearchResults => self.search_results.len(),
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
        if let Some(task) = self.reader_html_task.take() {
            task.handle.abort();
        }
        self.reader_html = None;
        self.reader_html_error = None;
        self.reader_html_key = None;
    }

    fn cancel_reader_tasks(&mut self) {
        if let Some(task) = self.reader_load_task.take() {
            task.handle.abort();
        }
        if let Some(task) = self.reader_content_task.take() {
            task.handle.abort();
        }
        self.reader_thread_id = None;
        self.reader_target_message_id = None;
    }
}

impl Drop for MailApp {
    fn drop(&mut self) {
        if let Some(worker) = self.smtp_worker.take() {
            worker.cancellation.cancel();
            worker.handle.abort();
        }
        if let Some(task) = self.account_sync_task.take() {
            // The isolated engine configures its child with kill_on_drop, so
            // aborting the supervisor task cannot orphan a network worker.
            task.handle.abort();
        }
        self.cancel_reader_tasks();
        self.clear_reader_html();
    }
}

fn parse_recipient_list(value: &str) -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    for raw in value.split([',', ';']) {
        let address = raw.trim();
        if address.is_empty() {
            continue;
        }
        if address.len() > 320 || address.chars().any(char::is_control) || !address.contains('@') {
            return Err(BackendError::InvalidInput(format!(
                "invalid recipient address: {address:?}"
            )));
        }
        if !recipients
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(address))
        {
            recipients.push(address.to_owned());
        }
    }
    Ok(recipients)
}

fn parse_trusted_authserv_ids(value: &str) -> std::result::Result<Vec<String>, String> {
    let mut values = Vec::new();
    for raw in value.split(',') {
        let normalized = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if normalized.len() > 255
            || !normalized.is_ascii()
            || normalized
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(format!(
                "Trusted authentication service ID {raw:?} is invalid"
            ));
        }
        if !values.contains(&normalized) {
            values.push(normalized);
        }
    }
    if values.len() > 32 {
        return Err("At most 32 trusted authentication service IDs may be configured".into());
    }
    values.sort_unstable();
    Ok(values)
}

fn sync_background_status(state: &ImapAccountSyncState) -> String {
    match state.status {
        lizard_mail_backend::ImapAccountSyncStatus::Connecting => {
            "Connecting securely to the mail server…".into()
        }
        lizard_mail_backend::ImapAccountSyncStatus::Authenticating => {
            "Authenticating to the mail server…".into()
        }
        lizard_mail_backend::ImapAccountSyncStatus::Discovering => {
            "Discovering remote mailboxes…".into()
        }
        lizard_mail_backend::ImapAccountSyncStatus::Synchronizing => {
            "Synchronizing message headers…".into()
        }
        lizard_mail_backend::ImapAccountSyncStatus::Hydrating => {
            if state.hydration_total_messages > 0 {
                format!(
                    "({}/{}) Downloading/verifying newest mail first",
                    state.hydration_completed_messages, state.hydration_total_messages
                )
            } else {
                "Headers are current; preparing local mail validation…".into()
            }
        }
        _ => "Synchronizing in an isolated worker…".into(),
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

fn cycle_relationship_kind(kind: &mut RelationshipKind) {
    *kind = match *kind {
        RelationshipKind::Person => RelationshipKind::Organization,
        RelationshipKind::Organization => RelationshipKind::Merchant,
        RelationshipKind::Merchant => RelationshipKind::Newsletter,
        RelationshipKind::Newsletter => RelationshipKind::AutomatedService,
        RelationshipKind::AutomatedService => RelationshipKind::Other,
        RelationshipKind::Other => RelationshipKind::Person,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use lizard_mail_backend::{AccountKind, Backend, BackendConfig, ImapSecurity, ImapSettings};

    async fn backend_with_imap_account() -> (tempfile::TempDir, Backend, AccountId) {
        let profile = tempfile::tempdir().unwrap();
        let backend = Backend::open(BackendConfig::new(profile.path()))
            .await
            .unwrap();
        let account = backend
            .accounts()
            .add(NewAccount {
                name: "Remote".into(),
                kind: AccountKind::Imap,
                credential_ref: Some("test:automatic-sync".into()),
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            })
            .await
            .unwrap();
        (profile, backend, account.id)
    }

    #[tokio::test]
    async fn automatic_sync_schedules_imap_accounts_once_per_interval() {
        let (_profile, backend, imap_id) = backend_with_imap_account().await;
        let local = backend
            .accounts()
            .add(NewAccount {
                name: "Local".into(),
                kind: AccountKind::Local,
                credential_ref: None,
                imap: None,
            })
            .await
            .unwrap();
        let mut app = MailApp::open(backend).await.unwrap();

        assert!(!app.auto_sync_enabled());
        app.schedule_auto_sync(Instant::now());
        assert!(
            app.queued_sync_accounts().is_empty(),
            "disabled automatic sync must not queue work"
        );

        app.enable_auto_sync();
        let start = Instant::now();
        app.schedule_auto_sync(start);
        assert_eq!(app.queued_sync_accounts(), vec![imap_id]);

        app.schedule_auto_sync(start + StdDuration::from_secs(1));
        assert_eq!(
            app.queued_sync_accounts(),
            vec![imap_id],
            "a call inside the interval must not duplicate the queue"
        );

        app.sync_queue.clear();
        app.schedule_auto_sync(start + app.auto_sync_interval + StdDuration::from_millis(1));
        assert_eq!(
            app.queued_sync_accounts(),
            vec![imap_id],
            "the next interval re-queues the configured IMAP account"
        );
        assert!(!app.queued_sync_accounts().contains(&local.id));
    }

    #[tokio::test]
    async fn queued_sync_deduplicates_requests() {
        let (_profile, backend, imap_id) = backend_with_imap_account().await;
        let mut app = MailApp::open(backend).await.unwrap();
        assert!(app.enqueue_sync(imap_id, true, false));
        assert!(!app.enqueue_sync(imap_id, false, false));
        assert_eq!(app.queued_sync_accounts(), vec![imap_id]);
    }

    #[test]
    fn hydration_status_reports_exact_newest_first_progress() {
        let state = ImapAccountSyncState {
            account_id: AccountId::new(),
            capabilities: Vec::new(),
            status: lizard_mail_backend::ImapAccountSyncStatus::Hydrating,
            last_attempt_at: None,
            last_success_at: None,
            next_retry_at: None,
            failure_count: 0,
            last_error: None,
            hydration_completed_messages: 17,
            hydration_total_messages: 2_345,
        };
        assert_eq!(
            sync_background_status(&state),
            "(17/2345) Downloading/verifying newest mail first"
        );
    }

    #[test]
    fn trusted_authserv_editor_normalizes_without_learning_from_mail() {
        assert_eq!(
            parse_trusted_authserv_ids(" MX.Provider.Example., mx.provider.example ").unwrap(),
            ["mx.provider.example"]
        );
        assert!(parse_trusted_authserv_ids("mx.example; dkim=pass").is_err());
    }
}
