# Mail-server integration tests

`dovecot_imap.rs` starts the official Dovecot CE image, populates an account
through IMAP `APPEND`, and makes the backend pull that mail through its real
IMAP sync path. It checks MIME ingestion, flags, search indexing, cursor-based
deduplication, and a later incremental delivery.

The image is pinned by digest. The test is ignored during the ordinary unit
suite because it requires Docker and may need to pull the image. Run it with:

```sh
cargo test -p lizard-mail-backend --test dovecot_imap -- --ignored --nocapture
```

`dovecot_security.rs` delivers the complete hostile-message corpus from
`spec/security-ui.md` through the same real server. It inventories every
warning class, verifies exact RFC bytes survive IMAP, and asserts the structured
identity, link, attachment and heuristic evidence implemented so far:

```sh
cargo test -p lizard-mail-backend --test dovecot_security -- --ignored --nocapture
```

The container publishes Dovecot's IMAP port on a random loopback port and is
force-removed by the test guard, including when an assertion unwinds.
