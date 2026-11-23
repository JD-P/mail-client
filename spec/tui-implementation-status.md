# Lizard terminal client implementation status

This document tracks implementation of the product contract in
[`tui-workflows.md`](tui-workflows.md). A screen in the product specification is
not implemented merely because it is described there.

## Implemented

- Durable conversation work states: active, waiting, snoozed, and done.
- Independent per-message read state and per-conversation work state.
- Relationship policy with Action/FYI routing and obligation permission.
- Warm — Action, Warm — FYI, Cold — Review, Spam — Quarantine, Waiting,
  Snoozed, and Done backend projections.
- Make Actionable Once for a Cold conversation without creating a contact. Its
  authorization is local-only and excluded from server metadata synchronization.
- New inbound mail reactivates Done and Waiting conversations.
- First-account contact suggestions, limited to twenty candidates from the
  previous six months of inbound and outbound correspondence, with durable
  accept/dismiss decisions.
- First-run IMAP account connection with TLS/STARTTLS, password/app-password or
  access-token credentials, masked and zeroized secret entry, secure credential
  storage, asynchronous isolated header-first synchronization, and default
  background hydration into a verified full local mirror.
- Automatic header synchronization for configured IMAP accounts at startup and
  every five minutes, serialized through a bounded queue of disposable isolated
  workers, with manual synchronization available from the Accounts screen.
- Full-copy hydration selects the newest eligible message first and exposes a
  durable completed/total counter in the footer while download, verification,
  parsing, and publication continue in the background.
- Account management for adding, editing, synchronizing on demand, diagnosing,
  and removing IMAP accounts. Removal has an intrusive confirmation and uses
  the backend's durable credential-cleanup path.
- A default platform profile directory, with explicit `--profile` and legacy
  positional overrides for portable and recovery profiles.
- Suggested-contact editing for contact-owned name, relationship kind, and
  Action/FYI placement.
- Existing contacts can be edited from the Contacts list: contact-owned name,
  multiple addresses, relationship kind, Action/FYI obligation permission,
  notifications, and remote-content policy are all persisted through the
  backend relationship model.
- Terminal queue navigation, conversation reader, Contacts list, contextual
  help, Done, Waiting, one-day Snooze, and Make Actionable Once.
- Local Gmail-style search with mixed-result identity cues: Warm rows remain
  red, Cold rows blue, and Spam rows amber instead of inheriting one search
  palette.
- Symmetric one-conversation Action/FYI correction, with manual choices taking
  precedence over learned routing.
- Exact-sender similar-mail FYI rules backed by the Tantivy lexical index. The
  terminal client presents a read-only ranked preview and affected counts,
  supports stricter/broader adjustment, and requires explicit confirmation
  before persisting and replaying the rule.
- Address-first unknown identity presentation using “claims to be”.
- Complete, hard-wrapped Cold sender addresses with no identity truncation;
  conversation rows use the newest actual From mailbox rather than an
  arbitrary To/Cc/Reply-To participant.
- Intrusive ambiguous-From, invisible-identity, confusable-domain, and embedded
  popular-domain evidence backed by the offline Tranco Top 10K snapshot.
- Passing, From-aligned DKIM selection; trusted delivery-time authentication
  and OpenPGP identity evidence remain visibly distinct.
- Intrusive security interruptions which replace the ordinary reader and allow
  only an explicit restricted-view override where the finding permits it;
  explanations remain visible after that override.
- Warm red, Cold blue, and Spam amber workflow palettes.
- Bounded terminal rendering of the supported HTML-mail subset. In the Linux
  x86-64 CLI this runs in a disposable Landlock/seccomp worker; worker or
  sandbox failure falls back to the stored plain-text part without parsing HTML
  in the client process.
- Trusted keyboard link navigation in the reader: Tab and Shift-Tab traverse
  parsed absolute HTTP(S) destinations, Enter delegates the selected canonical
  destination to the platform default browser, and interstitial/restricted
  message views expose no openable links.
- A hierarchical-ready folder browser with message-level folder results,
  reader-to-folder-to-folder-list Escape navigation, and six durable global
  folder shortcuts on 5, 6, 7, 8, 9, and 0. Binding is the reversible `b` then
  digit operation and replaces the old slot without confirmation.
- Local and remote folder creation, rename, and deletion from the terminal.
  Remote mutations run in the disposable isolated IMAP worker; deletion
  requires typing the exact folder name before it can reach the server.

## Partially implemented

- Automatic onboarding currently begins only for the first configured account
  when the profile has no contacts. Per-new-account launch, Skip, rerun, and a
  final onboarding review remain to be wired into the terminal client.
- Suggested-contact editing exposes the highest-value relationship controls;
  notification and remote-content policy remain at defaults during onboarding
  but can be changed immediately from the ordinary Contacts editor.
- Snooze currently offers a one-day shortcut; a date/time picker is pending.
- The reader exposes the core work-state actions. Reply, delete, move,
  attachments, calendar creation, and profile navigation are backed elsewhere
  in the backend but not yet wired into this terminal surface.
- Folder creation, rename, deletion, browsing, and shortcuts are wired. IMAP
  subscription management and a dedicated hierarchy picker remain pending.

## Not yet wired into the terminal client

- Cross-client IMAP keyword synchronization for user tags, Done, Waiting,
  Snooze, Mute, Priority, and known-sender Action/FYI overrides.
- JMAP account transport. It is specified as deferred work and is not part of
  the current implementation phase.
- Sender grouping and priority variants of Warm — Action.
- Spam rescue, delete-now, classification explanation, and retention display.
- Full attachment inspector and raw-message view. Core identity,
  authentication, and warning evidence is present in the ordinary reader;
  exhaustive diagnostic detail remains to be wired.
- Composer, send review, Drafts, Outbox, and Sent screens.
- Calendar proposal and CalDAV account screens.
- Contact address history, OpenPGP key binding, contact import/export, and merge.
- Filter/heuristic editors and rules overview. Similar-mail rule creation and
  preview are wired; listing, disabling, and deleting those rules still need a
  management screen.
- Saved views and tags.
- Encryption/key, storage/offline, appearance, and keybinding screens.
