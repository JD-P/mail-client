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
- Make Actionable Once for a Cold conversation without creating a contact.
- New inbound mail reactivates Done and Waiting conversations.
- First-account contact suggestions, limited to twenty candidates from the
  previous six months of inbound and outbound correspondence, with durable
  accept/dismiss decisions.
- Suggested-contact editing for contact-owned name, relationship kind, and
  Action/FYI placement.
- Terminal queue navigation, conversation reader, Contacts list, contextual
  help, Done, Waiting, one-day Snooze, and Make Actionable Once.
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

## Partially implemented

- Automatic onboarding currently begins only for the first configured account
  when the profile has no contacts. Per-new-account launch, Skip, rerun, and a
  final onboarding review remain to be wired into the terminal client.
- Suggested-contact editing exposes the highest-value relationship controls;
  notification and remote-content policy editing still uses backend defaults.
- Snooze currently offers a one-day shortcut; a date/time picker is pending.
- The reader exposes the core work-state actions. Reply, delete, move,
  attachments, calendar creation, and profile navigation are backed elsewhere
  in the backend but not yet wired into this terminal surface.

## Not yet wired into the terminal client

- Sender grouping and priority variants of Warm — Action.
- Spam rescue, delete-now, classification explanation, and retention display.
- Full attachment inspector and raw-message view. Core identity,
  authentication, and warning evidence is present in the ordinary reader;
  exhaustive diagnostic detail remains to be wired.
- Composer, send review, Drafts, Outbox, and Sent screens.
- Calendar proposal and CalDAV account screens.
- Full relationship profile, address history, contact import/export, and merge.
- Similar-mail rule creation and preview, filter/heuristic editors, and rules
  overview.
- Search, search results, saved views, folders, and mailbox management.
- Account, encryption/key, storage/offline, appearance, and keybinding screens.
