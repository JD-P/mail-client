# Lizard Rules reference

Lizard Rules is a Python-shaped source language for mail heuristics. Source is
parsed with a Python grammar and compiled into Lizard's bounded, serializable
intermediate representation. It is never evaluated by Python.

This document describes the currently implemented language and is deliberately
usable as context for a code-generating model. Generated programs have no
authority until the backend compiles and the user activates them.

## Program shape

Every source contains exactly one function:

```python
@heuristic
def detect(message):
    if message.sender.registrable_domain != "example.com":
        return

    for link in message.links:
        if link.registrable_domain != message.sender.registrable_domain:
            yield Finding(
                code="cross_domain_link",
                presentation=LinkInterstitial,
                severity=Warning,
                target=link.id,
                text="This link goes to a different site.",
                evidence={"destination": link.destination},
            )
```

Accepted statements are:

- immutable top-level name binding, exactly once per name;
- `if` / `elif` / `else`;
- bare `return`;
- bounded `for` over `message.attachments` or `message.links`; and
- `yield Finding(...)`.

Imports, assignment to fields, reassignment, `while`, unapproved iteration,
recursion, nested functions, classes, exceptions, context managers, async,
reflection, filesystem/network access and arbitrary function calls are compile
errors.

## Expressions

The language supports `None`, Boolean, signed 64-bit integer and string
literals; `and`, `or`, `not`; `==`, `!=`, `<`, `<=`, `>` and `>=`; checked
integer `+`, `-`, `*`, `//`, and `%`; and these pure methods:

```python
value.contains("text")             # Unicode lowercase comparison
value.contains_exact_case("text")
value.starts_with("text")
value.ends_with("text")
value.lower()
value.is_missing()
```

An absent optional string is `None`. It compares unequal to strings and acts as
an empty string for string predicates.

## Message fields

```text
message.subject
message.sender.address
message.sender.domain
message.sender.registrable_domain
message.sender.claimed_name
message.body_text
message.size_bytes
message.has_attachment
message.attachments
message.links
```

Attachment loop bindings expose:

```text
attachment.id                 # "attachment:<ordinal>"
attachment.ordinal
attachment.name
attachment.declared_type
attachment.size
attachment.inline
```

Link loop bindings expose:

```text
link.id                       # "link:<ordinal>"
link.ordinal
link.destination
link.scheme
link.host
link.registrable_domain
```

Links are extracted from bounded plain-text URL recognition and parsed HTML
anchor `href` attributes. Host parsing uses the URL standard and registrable
domains use the public suffix list.

## Findings

`Finding` accepts keyword arguments only:

```text
code            required static lowercase identifier
presentation    required closed enum
severity        required closed enum
target          required only for link/attachment interstitials
text            optional static plain text, at most 2,048 bytes
evidence        optional dictionary with static keys and scalar expressions
```

Presentation values are:

```text
MessageAnnotation
PersistentWarningFooter
OpenInterstitial
LinkInterstitial
AttachmentInterstitial
```

Severity values are `Information`, `Warning`, and `Danger`. Link and attachment
targets must be the `.id` of the corresponding active loop binding. Programs
cannot provide HTML, styles, callbacks or client code.

The engine stores message ID, heuristic ID/version, source origin, code,
presentation, severity, target and evidence in Turso. Identical reevaluation
produces the same finding ID, preserving a separate user dismissal record.

## Budgets and execution

Compilation estimates worst-case steps and rejects programs above 100,000.
Runtime independently enforces 100,000 steps and additionally charges for the
number of bytes scanned by string operations. Message parsing limits links to
2,048 and attachments to 512; a program may emit at most 2,048 findings.
Strings and evidence dictionaries also have explicit limits.

Programs execute during ingestion after immutable message storage. A runtime
budget failure or type error produces a persisted evaluation status instead of
granting partial findings or aborting later heuristic evaluation.

## Filter rules

Filter rules do not use this language. They contain an ordered vector of typed
`FilterCondition` values with an implicit AND and short-circuit on the first
false condition. Their only actions are local message placement and `Stop`.
Applications record the exact condition/action version for later explanation.
