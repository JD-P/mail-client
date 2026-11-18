# Provenance-preserving mail security UI

Status: design requirements for future application frontends. This document
does not claim that the current renderer or any mail backend implements these
requirements.

## Product rule

Never present attacker-controlled identity metadata in the grammatical or
visual voice of the application itself.

More generally, preserve the provenance of every security-relevant claim:

- locally established facts may be presented as facts;
- cryptographically established facts must state exactly what was proved;
- message-supplied assertions must be presented as claims; and
- heuristics must describe the observed contradiction, not announce a vague
  verdict such as "suspicious" or "authenticated."

A warning should normally say:

1. what the message claims;
2. what the client can establish;
3. the consequential difference; and
4. the safe action available to the user.

The security state belongs to the message and sender evidence, not to the view
in which a message happens to appear. Search results, custom folders, mixed
threads and third-party views must receive the same structured evidence as the
canonical Warm, Cold and Spam workflows.

## Workflow selection

The backend should expose orthogonal facts. The official frontend policy may
then derive a default workflow approximately as follows:

```text
spam verdict?             yes -> Spam workflow
                           no -> continue

sender address in contacts? yes -> Warm workflow
                            no -> Cold workflow

Warm sender/message profile -> personal, transactional, marketing,
                               newsletter, or unknown treatment
```

Spam state, contact membership, signature evidence, classification and
anomalies must not be collapsed into one stored enum. Combinations are useful:
a known sender can have a broken signature, and an unknown sender can have a
perfectly valid signature for a domain the user has never encountered.

Warm means an established local relationship, not safe. Both Warm and Cold
workflows retain anti-phishing behavior.

The canonical workflows are product-policy views over backend predicates. An
official frontend may pin them and make them undeletable. The backend need not
treat those particular views as protected security objects, and another
frontend may organize the same messages differently.

## Identity presentation

### Cold sender

The mailbox and domain are primary. The sender-supplied display name is an
explicit claim.

```text
abigail@example.friend
example.friend claims to be "Abigail Marie"

First message from this address
```

If a cold sender uses the name of a local contact:

```text
stranger@unrelated.example claims to be "Frank."

You have a contact named Frank, but this is not one of Frank's saved
addresses.
```

### Warm sender

The address book owns the primary displayed identity. A message does not get
to rename a known person.

```text
Frank
frank@example.com
```

If the message supplies a materially different name:

```text
Frank
frank@example.com

This message claims the sender is "Chase Bank."
You know this address as "Frank."
```

Legitimate name changes may be confirmed by the user and stored as accepted
aliases. Message-supplied names must never silently update contact data.

## Domain signatures

Normal UI should not use SPF. It may remain an input to receiving-server spam
and delivery policy.

A signature indicator is permitted only when at least one valid DKIM signature
is aligned with the visible From domain. A signature by an unrelated delivery
provider must not be relabeled as a signature by the From domain.

For a valid aligned signature, show a small key or signature indicator with an
accessible label and the precise explanation:

```text
This message was signed by example.com.
```

Do not call the person, message or domain "safe" or generically
"authenticated." A valid signature does not prove a display name, a human
author, benign intent or an uncompromised account.

When there is no valid aligned signature, opening may be gated by:

```text
No valid signature from example.com

This message claims to be from example.com, but it does not have a valid
signature from that domain. It could be a spoof.

Do you still want to read it?

[Go back]  [Read with links disabled]
```

Continuing dismisses the interstitial, not the security state. Links and remote
content remain disabled and a persistent warning remains visible:

```text
There's no proof this message is really from example.com.

Do not click or copy any link or web address from this message.

If you were expecting this message, return to the app or website where you
started. Otherwise, use the service's official app or a bookmark you saved
before receiving this message.

Legitimate mail can occasionally lose or fail its signature because of a
broken or misconfigured mail system.
```

The wording "no valid signature" intentionally covers an absent signature, an
invalid signature and unavailable trustworthy verification without claiming
to know which upstream component failed. The backend must preserve the more
specific machine-readable result.

### OpenPGP signatures and encryption

OpenPGP evidence is separate from a domain DKIM signature.

When a valid signature uses a key the user has locally associated with a
contact, state the local relationship:

```text
This message was signed with the key you saved for Frank.
```

When the mathematics is valid but the key is not locally associated with a
contact, do not turn an address or user ID embedded in the key into an
application identity claim:

```text
This message has a valid signature from OpenPGP key 1234 ... CDEF.

You have not associated this key with a contact.
```

An invalid signature is a concrete contradiction and receives a persistent
warning. Encryption is stated independently: encryption for one of the user's
keys provides confidentiality but does not identify the sender. Key discovery
may offer a candidate association; only a local user decision establishes the
contact binding.

#### Rendering encrypted OpenPGP mail

OpenPGP-encrypted content is never rendered as HTML and never receives remote
resource capabilities. This is a fixed application invariant, not a warning
the user can dismiss.

- If the integrity-checked decrypted entity contains `text/plain`, display its
  bounded plain-text representation.
- If it contains only HTML, an isolated parser may derive readable plain text
  without layout, CSS, forms, active elements or resource fetching. Explain
  that the original HTML was converted to text for security.
- Never splice decrypted MIME content into unencrypted sibling HTML or allow
  unencrypted markup to establish rendering context around decrypted bytes.
- Decrypted attachments remain separate attachments. They do not become inline
  active content merely because they were inside the encrypted entity.
- If ciphertext integrity cannot be established, display no decrypted content,
  do not index it and do not offer a click-through plaintext view.

This rule applies to encrypted content. A signed-but-unencrypted OpenPGP
message follows the ordinary HTML/resource policy; a signature alone creates
no plaintext-exfiltration boundary.

## Navigation and URL rules

### Displayed destination differs from the real destination

Destination UI must be generated from the parsed target, never from
message-controlled anchor text, `title` attributes or surrounding markup.

```text
This message displays:

    accounts.example.com

but the link actually opens:

    account-example.login
```

The link is blocked behind an action-specific interstitial. Detect misleading
userinfo (`example.com@evil.example`), raw IP destinations, unusual ports,
dangerous schemes and nested redirect targets where they can be decoded
without making a network request.

### Confusable domains

Use Unicode UTS #39 confusable skeletons and script data. Detect mixed-script
and whole-script confusables, ASCII lookalikes such as uppercase `I` for
lowercase `l`, invisible or bidirectional controls, and small edits relative
to domains meaningful to this user.

Do not classify all internationalized domains as malicious. The strongest
warning is reserved for a domain confusable with a saved contact domain,
user-approved site or the domain it is being presented as.

```text
This link opens "раypal.com," not "paypal.com."

The first two letters are Cyrillic characters that look like Latin letters.
```

Always display the complete registrable domain when the user is making a
trust decision. Do not elide the portion that distinguishes
`example.com.evil.example` from `example.com`.

### Account action crosses a domain boundary

Trigger when both conditions hold:

1. the message contains account-action language such as password, reset,
   account, sign in, login, verify, security alert, unlock, confirm identity or
   unusual activity; and
2. a link's registrable domain differs from the visible From domain.

```text
This message claims to be from example.com and asks you to reset or verify an
account.

The link opens login.other-example.com instead.

Do not use this link. Return to the app or website where you started.
```

The vocabulary will be evadable. That is acceptable: forcing attackers toward
indirect and unnatural language is still useful. This rule is a composite
heuristic, not a claim that every cross-domain account link is malicious.

## Reply destination

If Reply-To differs materially from From, disclose that fact at the moment of
replying. A change is especially relevant for a warm sender.

```text
This message is from billing@example.com, but your reply will be sent to
payments@unrelated.example.

[Cancel]  [Reply to unrelated.example]
```

## Conversation injection

Threading headers and a copied subject are message-supplied structural claims.
An unknown sender must not become visually indistinguishable from established
participants merely by supplying `References`, `In-Reply-To` or a matching
subject.

```text
This message claims to be part of this conversation, but it came from an
address that has not participated before.
```

The message may remain in the thread, separated by a strong identity boundary.

## Attachments

Determine attachment type from bounded content inspection and container
structure, not solely from MIME metadata or the filename.

- Incorrect metadata for harmless content may be repaired or annotated.
- Double extensions and bidirectional filename controls must not obscure the
  actual type.
- Executables and OS-launchable content presented as documents are blocked.
- Archives should be inspected for executable content when this can be done
  within strict input, expansion, nesting and time budgets.
- Password-protected or otherwise uninspectable archives must say that the
  client could not inspect them; they must not receive a clean verdict.

Automatic inspection itself must not become an expansion oracle. The current
backend reads bounded ZIP central-directory metadata only: it does not inflate
entries, decrypt them or recurse into nested archives. Declared sizes and
compression ratios can therefore identify a likely ZIP bomb without triggering
it. Malformed, encrypted, nested and over-budget containers are simply tagged
uninspectable. Opening an entry is a separate explicit operation with fresh
limits and is unavailable after an incomplete inspection.

```text
This attachment is named "invoice.pdf," but it is a program.

Programs attached to email cannot be opened.
```

An expert-only export mechanism, if one is eventually provided, must remain a
deliberate operation outside the ordinary Open flow.

## Remote resources

Do not ask the user whether to "load remote content" without explaining the
consequence.

```text
This message wants to download images from the internet.

Doing that can tell the sender that you opened the message, when you opened it,
and information about your internet connection.

[Not now]  [Load images]
```

An explicit per-sender decision may be remembered. Sender HTML and CSS never
authorize a request by themselves. The renderer continues to receive only
resources supplied through the trusted application broker.

## Behavior intentionally omitted from the default policy

The following ideas are too noisy or lack a reliable local source of truth:

- Do not warn merely because a known sender links to a domain not previously
  observed. Ordinary correspondence contains novel links constantly.
- Do not warn merely because a phone number, payment account or cryptocurrency
  address is new. Consumer address books rarely contain enough comparison data
  to make that meaningful. Such rules may be opt-in organizational policies.
- Do not attempt to infer that a human named in the body personally signed a
  platform notification. State only the signing domain that was actually
  verified.
- Do not say that an unsigned message is "usually" a spoof without evidence
  supporting that base-rate claim.
- Do not allow cold or unsigned messages to train sender-history profiles used
  to judge later messages.

## Interruption levels

Use the least disruptive treatment appropriate to the demonstrated risk:

1. **Annotation:** a useful fact with no immediate dangerous action.
2. **Action interstitial:** the user is crossing a boundary by opening an
   unsigned message, following a misleading link, replying elsewhere or
   opening risky content.
3. **Hard block:** behavior with no defensible ordinary mail use, including
   scripts, interactive credential forms and an executable masquerading as a
   document.

Warnings must be accessible without hover, must not rely on color alone and
must remain outside the message-controlled render surface.

## Backend evidence required by frontends

The backend/API should expose structured evidence, not finalized prose:

- parsed From mailbox and message-supplied display name;
- contact match and local contact identity;
- DKIM signatures, exact signing domains, alignment and verification result;
- OpenPGP signature/encryption results, fingerprints, protected content and
  locally established contact/key bindings;
- the trustworthy source and time of any receiving-server authentication
  result;
- parsed links, displayed link text, schemes, hosts, registrable domains and
  Unicode-confusable findings;
- Reply-To and Sender differences;
- thread-participant and threading-header facts;
- attachment declared type, detected type, filename hazards and bounded archive
  inspection results;
- remote resource origins; and
- semantic features such as account-action terms.

The frontend owns wording, visual hierarchy and action gating. The backend owns
parsing once, preserving evidence, bounded feature extraction and making the
same facts available to every frontend.

## References

- [Unicode UTS #39: Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/)
- [Unicode UTR #36: Unicode Security Considerations](https://www.unicode.org/reports/tr36/)
- [WHATWG URL Standard: URL rendering](https://url.spec.whatwg.org/)
- [RFC 6376: DKIM Signatures](https://www.rfc-editor.org/rfc/rfc6376.html)
- [RFC 5322: Internet Message Format](https://www.rfc-editor.org/rfc/rfc5322.html)
- [RFC 8601: Authentication-Results](https://www.rfc-editor.org/rfc/rfc8601.html)
- [RFC 9787: Guidance on End-to-End Email Security](https://www.rfc-editor.org/rfc/rfc9787.html)
- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [RFC 3156: OpenPGP/MIME](https://www.rfc-editor.org/rfc/rfc3156.html)
- [EFAIL: Breaking S/MIME and OpenPGP Email Encryption](https://efail.de/)
