# Lizard mail workflow and TUI screen specification

Status: product behavior specification. Implementation status is called out
separately; a screen appearing here does not by itself mean every operation is
already wired into the terminal client.

## Product model

Email is a to-do list onto which other people can propose work. Lizard therefore
keeps these dimensions independent:

- **trust class**: Warm, Cold, or Spam;
- **message knowledge**: read or unread, per message;
- **conversation work state**: active, waiting, snoozed, or done;
- **relationship policy**: known identity, obligation permission,
  notification policy, remote-content policy, and default Warm route;
- **physical organization**: accounts, folders, tags, rules, and saved views.

The work item is the conversation. Reading a message never completes it.
Deleting a conversation removes it from the workflow but does not rewrite
history to claim it was completed. A qualifying new inbound message reactivates
a completed or waiting conversation.

Serious security findings replace or interrupt the ordinary reader. Detailed
evidence may be inspected separately, but the security conclusion must never be
hidden in a secondary view.

There is no mandatory home screen. The client opens the last-used workflow and
keeps direct global navigation to Warm, Cold, Spam, Later, Search, Contacts,
outgoing mail, folders, rules, settings, and contextual help.

## Workflow screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Warm — Action** | Shows active conversations from relationships permitted to create obligations, plus Cold conversations explicitly made actionable once. Supports Done, Reply, Calendar, Waiting, Snooze, Delete, Move, Mute, chronological view, sender grouping, and priority view. | “Show me what I currently owe people and help me resolve it efficiently.” |
| **Warm — FYI** | Shows known-sender mail that does not enter the obligation queue: newsletters, receipts, notifications, social mail, marketing, and contacts whose messages are not presumed actionable. Supports rapid dismissal, deletion, promotion to Action, and similar-mail rule creation. | “I recognize these senders, but their mail should not become work unless I say so.” |
| **Cold — Review** | Shows unknown senders with the address first and “claims to be NAME.” Remote content begins blocked. Primary actions are Dismiss, Malicious, Add Contact, Make Actionable Once, Delete, and Create Rule. | “Help me determine who this is and whether I want any relationship with them.” |
| **Spam — Quarantine** | Shows probable spam in an inert preview. Supports Rescue, Delete Now, Explain Classification, and Empty Spam. Displays automatic deletion dates. | “Assume this is garbage, but let me recover mistakes before retention deletes them.” |
| **Waiting** | Shows conversations where the user has explicitly acted and is waiting for somebody else. A new relevant reply returns the conversation to Warm — Action. | “Keep track of delegated or blocked work without leaving it in my immediate queue.” |
| **Snoozed** | Shows conversations hidden until a selected date or time. Supports rescheduling and immediate reactivation. | “This remains my responsibility, but it is not actionable now.” |
| **Done** | Shows recently completed conversations with their resolution history. Supports Reopen and Undo. | “Let me verify what I completed and recover from accidental resolution.” |

Warm — Action has a meaningful inbox-zero state: no active obligations remain.
Cold does not shame the user for accumulating unknown mail; it emphasizes review
sessions and decisions made. Spam has no inbox-zero objective; retention handles
it.

Marketing is simply one common kind of Warm — FYI mail. It is not a separate
built-in workflow, view, folder, or default split. Users may add their own tags
or rules when useful, but the durable product distinction is Action versus FYI.

## Message and security screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Conversation Reader** | Displays the thread, contact-owned identity, authentication summary, and work state. Offers Done, Reply, Calendar, Waiting, Snooze, Delete, Move, Attachments, and Contact Profile. Its palette and action emphasis reflect Warm, Cold, or Spam provenance. | “Understand this exchange and decide what happens next.” |
| **Restricted Cold Reader** | Opens links, remote content, and risky attachments disabled. Shows the address first and grammatically attributes display metadata: “address claims to be Name.” | “Inspect an untrusted communication without accidentally granting it credibility or executing its requests.” |
| **Security Interruption** | Replaces or blocks the normal reader for failed expected signatures, spoof-like domains, dangerous attachments, suspicious credential links, invalid OpenPGP protection, and similar findings. Offers Back, Explain, Report Malicious, and, where safe, Read Restricted. | “Stop me before I treat a dangerous message as ordinary correspondence.” |
| **Authentication and Evidence Details** | Shows DKIM, trusted delivery-time DMARC, low-level SPF/ARC, heuristic traces, provider-spam evidence, and local classifier evidence. | “Explain exactly why the client made the security claim shown prominently in the reader.” |
| **Attachment Inspector** | Shows MIME structure, filename, declared type, detected type, size, inspection status, and safe operations. Allows bounded preview/export, blocks executables, and warns prominently about uninspectable archives. | “Tell me what this file actually is before I expose another application to it.” |
| **Raw Message / Headers** | Displays the lossless original message and structured headers. | “Let an expert inspect, diagnose, or export the original evidence.” |

## Obligation-resolution interactions

These are short transitions rather than permanent navigation destinations.

| Interaction | Behavior |
|---|---|
| **Done** | A single explicit command means “No further action is required.” It does not require a reason. |
| **Reply completed** | After successful sending, offer “Reply sent. Mark conversation done?” State never changes silently. |
| **Calendar event created** | After successful CalDAV creation, offer “Event created. Mark conversation done?” |
| **Waiting** | Records that the user acted and expects another participant to respond. |
| **Snooze** | Selects when the conversation becomes active again. |
| **Delete** | Moves mail to Trash and removes it from the active workflow without claiming the obligation was completed. |
| **Make Actionable Once** | Moves one Cold conversation into Warm — Action without creating a contact or granting the sender future obligation permission. The permission is scoped to the conversation. |
| **Reopen** | Returns a Done conversation to Warm — Action. |

Explicit compound commands such as Reply and Done or Create Event and Done may
exist for speed, but must remain deliberate user actions.

## Composition and calendar screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Composer** | Edits recipients, subject, body, attachments, reply/forward behavior, and continuously saves a draft. May invoke an external editor. | “Write the content with minimal interference.” |
| **Send Review** | Shows identity, recipients, subject, attachments, MIME types, encryption, protected headers, SMTP account, and scheduled time. Detects recipient confusion, dangerous attachments, and encryption downgrade. | “Verify the complete outgoing object before submitting it.” |
| **Drafts** | Lists unfinished compositions and autosave state. | “Resume incomplete work safely.” |
| **Outbox** | Shows queued, sending, retrying, scheduled, cancelled, and failed submissions. Allows retry and cancellation. | “Tell me whether my mail actually left and let me recover from failure.” |
| **Sent** | Shows submitted messages and Sent-folder reconciliation state. | “Confirm what I sent without duplicate local/server copies.” |
| **Calendar Proposal** | Extracts proposed event fields from a message, lets the user confirm/edit them, selects a CalDAV calendar, and links the created event back to its source conversation. | “Turn this request into scheduled work without trusting attacker-supplied text as calendar fact.” |

## Contact and relationship screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Contact Decision** | Invoked from Cold. Confirms the address, shows claimed and signed identities, and offers quick presets such as Person, Organization, Merchant, Newsletter, or Automated Service. | “Establish the smallest useful relationship without filling out a tedious form.” |
| **Relationship Profile** | Maintains contact-owned display identity, multiple addresses, keys, provenance, and history. Separately controls obligation permission, Action/FYI routing, notification priority, and remote-content policy. | “Control what this sender means to me and how future mail should behave.” |
| **Contacts List** | Searches and browses people, organizations, services, and mailing lists. Supports import/export, merging, and identity history. | “Find and maintain the identities the client uses to present mail safely.” |
| **Contact Address History** | Shows addresses added, removed, or replaced and detects unexpected message-name changes. | “Tell me when a familiar address begins presenting itself as somebody else.” |

Action/FYI placement is the visible expression of whether that relationship may
create obligations by default. That setting remains independent of known
identity, notification priority, remote-content policy, and accepted OpenPGP
certificates. Being in contacts never means “trust everything this sender
does.”

## First-account onboarding

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Account Connection** | Configures IMAP/SMTP credentials and explains header-first synchronization. The user may begin using the client while older bodies continue downloading according to offline policy. | “Connect my existing mailbox without waiting for a complete archive download.” |
| **Contact Suggestions** | After initial header synchronization, examines the previous six months and proposes at most the twenty most frequent correspondents. Excludes existing contacts, the user’s identities, spam, and previously dismissed suggestions. Displays the address first, claimed name, message count, recency, and why the suggested preset was chosen. | “Start with a useful Warm inbox without manually reconstructing my social graph.” |
| **Suggestion Editor** | Offers Yes, No, and Edit. Edit changes the contact-owned name, relationship kind, Action/FYI placement, obligation permission, notification policy, and remote-content policy. List-like and automated senders default to FYI with no obligation permission; likely personal correspondents default to Action. | “Approve useful defaults quickly without silently trusting inferred identity.” |
| **Onboarding Review** | Summarizes accepted Action contacts, accepted FYI contacts, skipped senders, and the resulting Warm/Cold counts before completing setup. | “Understand the consequences of the bootstrap decisions before entering the normal client.” |

Suggestions are proposals, not automatic contacts. Frequency is not proof of
identity or trust. A user may skip onboarding entirely, rerun it later, or
import contacts via vCard/CardDAV when available.

## Rules, search, and organization screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Create Similar-Mail Rule** | Starts from a message, scopes by sender/domain, builds a lexical/template profile, previews historical matches, and proposes an FYI tag/folder action. | “Make this recurring kind of boring mail disappear without hiding unlike mail from the same sender.” |
| **Similarity Preview** | Shows positive, borderline, and excluded matches while adjusting strictness; highlights terms and structure driving the match. | “Show me what this automation catches before I trust it.” |
| **Filter Rule Editor** | Creates Boolean conditions followed by restricted message actions such as move, trash/delete, mute, priority, or local categorization. | “Automate deterministic organization without arbitrary code.” |
| **Heuristic Editor** | Defines security or presentation findings in the restricted Python-like language, with sample execution and explanation traces. | “Extend warnings without allowing scripts to mutate unrelated state.” |
| **Rules Overview** | Lists rules with versions, match counts, preview, replay history, and undo. | “Understand and safely maintain the automation governing my mail.” |
| **Search** | Runs Gmail-like queries over headers, bodies, contacts, attachments, folders, workflow state, security evidence, and dates. | “Find mail by what I remember about it.” |
| **Search Results** | Behaves like a message queue and preserves each result’s source workflow. | “Operate on retrieved mail without pretending the results are a new mailbox.” |
| **Saved Views** | Presents persistent live queries. | “Create useful perspectives without moving or duplicating messages.” |
| **Folders / All Mail** | Browses accounts, IMAP mailboxes, and physical placement; supports conventional server-side organization. | “Retain interoperability even though folders are not the primary workflow.” |

BM25 scores are not percentages or stable probabilities. Similar-mail UI should
offer understandable strictness and an affected-message preview; raw score
thresholds belong in expert details.

## Account and system screens

| Screen | Functions | What it implies the user wants |
|---|---|---|
| **Accounts** | Adds, updates, removes, synchronizes, and diagnoses IMAP/SMTP accounts. | “Connect and maintain mail providers.” |
| **Mailbox Management** | Creates, renames, deletes, and subscribes to remote mailboxes. | “Administer server-visible organization.” |
| **Calendar Accounts** | Configures CalDAV servers, collections, and default destinations. | “Choose where events created from mail live.” |
| **Encryption and Keys** | Manages OpenPGP identities, accepted recipient certificates, YubiKey providers, key changes, and encrypted-search policy. | “Control cryptographic identity and local plaintext exposure deliberately.” |
| **Storage and Offline Policy** | Configures quotas, body retention, offline downloads, integrity audits, backup, and export. | “Control disk use and recoverability.” |
| **Appearance and Keys** | Configures palettes, layouts, keybindings, and external-editor behavior without weakening Warm/Cold/Spam semantics. | “Customize operation while retaining coherent safe defaults.” |
| **Contextual Help / Command List** | Shows every command valid on the current screen, including unbound commands and workflow explanations. | “Discover capabilities without memorizing a manual.” |

Implementation progress is tracked separately in
[`tui-implementation-status.md`](tui-implementation-status.md), so this product
contract does not drift as individual screens are completed.
