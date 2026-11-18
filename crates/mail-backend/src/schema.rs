use crate::Result;
use std::collections::HashSet;

pub(crate) async fn migrate(connection: &turso::Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_meta (
                version INTEGER NOT NULL
            );
            INSERT INTO schema_meta(version)
                SELECT 16 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);

            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                credential_ref TEXT,
                settings_json TEXT,
                trusted_authserv_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credential_cleanup_queue (
                reference TEXT PRIMARY KEY,
                queued_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                remote_name TEXT,
                uid_validity INTEGER,
                uid_next INTEGER,
                created_at INTEGER NOT NULL,
                UNIQUE(account_id, remote_name)
            );

            CREATE TABLE IF NOT EXISTS threads (
                id TEXT PRIMARY KEY,
                subject TEXT,
                normalized_subject TEXT,
                sender_trust TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS thread_participants (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                address TEXT NOT NULL COLLATE NOCASE,
                PRIMARY KEY(message_id, address)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                blob_hash TEXT NOT NULL,
                rfc_message_id TEXT,
                thread_message_id TEXT,
                thread_id TEXT REFERENCES threads(id),
                parent_message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
                threading_source TEXT,
                sender_trust TEXT,
                normalized_subject TEXT,
                in_reply_to_json TEXT NOT NULL DEFAULT '[]',
                references_json TEXT NOT NULL DEFAULT '[]',
                subject TEXT,
                from_address TEXT,
                from_name TEXT,
                to_addresses TEXT NOT NULL,
                cc_addresses TEXT NOT NULL,
                bcc_addresses TEXT NOT NULL,
                sender_addresses TEXT NOT NULL DEFAULT '[]',
                reply_to_addresses TEXT NOT NULL DEFAULT '[]',
                delivered_to_addresses TEXT NOT NULL,
                list_id TEXT,
                body_text TEXT NOT NULL,
                body_html TEXT,
                preview TEXT NOT NULL,
                sent_at INTEGER,
                received_at INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                has_attachment INTEGER NOT NULL,
                attachment_names TEXT NOT NULL,
                is_read INTEGER NOT NULL,
                is_starred INTEGER NOT NULL,
                snoozed_until INTEGER,
                muted INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'normal'
                    CHECK(priority IN ('low', 'normal', 'high')),
                user_classification TEXT,
                content_state TEXT NOT NULL,
                search_metadata TEXT NOT NULL,
                dkim_json TEXT NOT NULL,
                delivery_auth_json TEXT NOT NULL,
                mime_state TEXT NOT NULL DEFAULT 'complete',
                mime_detail TEXT,
                content_availability TEXT NOT NULL DEFAULT 'complete',
                downloaded_bytes INTEGER NOT NULL DEFAULT 0,
                download_error TEXT,
                download_updated_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS message_instances (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                uid_validity INTEGER NOT NULL,
                imap_uid INTEGER NOT NULL,
                mod_sequence INTEGER,
                flags_json TEXT NOT NULL,
                PRIMARY KEY(folder_id, uid_validity, imap_uid)
            );

            CREATE TABLE IF NOT EXISTS provider_spam_evidence (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                folder_id TEXT NOT NULL,
                uid_validity INTEGER NOT NULL,
                imap_uid INTEGER NOT NULL,
                source TEXT NOT NULL CHECK(source IN (
                    'imap_junk_mailbox',
                    'imap_junk_keyword',
                    'imap_not_junk_keyword'
                )),
                verdict TEXT NOT NULL CHECK(verdict IN ('spam', 'not_spam')),
                observed_at INTEGER NOT NULL,
                PRIMARY KEY(folder_id, uid_validity, imap_uid, source),
                FOREIGN KEY(folder_id, uid_validity, imap_uid)
                    REFERENCES message_instances(folder_id, uid_validity, imap_uid)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS spam_model_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                seed_corpus_hash TEXT NOT NULL,
                seed_spam_messages INTEGER NOT NULL,
                seed_ham_messages INTEGER NOT NULL,
                user_spam_messages INTEGER NOT NULL,
                user_ham_messages INTEGER NOT NULL,
                model_version INTEGER NOT NULL CHECK(model_version > 0),
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS spam_token_counts (
                token TEXT PRIMARY KEY,
                seed_spam_documents INTEGER NOT NULL CHECK(seed_spam_documents >= 0),
                seed_ham_documents INTEGER NOT NULL CHECK(seed_ham_documents >= 0),
                user_spam_documents INTEGER NOT NULL CHECK(user_spam_documents >= 0),
                user_ham_documents INTEGER NOT NULL CHECK(user_ham_documents >= 0)
            );

            CREATE TABLE IF NOT EXISTS spam_user_training (
                message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                classification TEXT NOT NULL CHECK(classification IN ('spam', 'not_spam')),
                tokens_json TEXT NOT NULL,
                trained_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_spam_assessments (
                message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                verdict TEXT NOT NULL CHECK(verdict IN ('spam', 'not_spam', 'uncertain')),
                score REAL NOT NULL CHECK(score >= 0.0 AND score <= 1.0),
                model_version INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                evaluated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS spam_classification_queue (
                message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                reason TEXT NOT NULL,
                queued_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_folder_memberships (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(message_id, folder_id)
            );

            CREATE TABLE IF NOT EXISTS attachments (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                part_id INTEGER NOT NULL DEFAULT 0,
                name TEXT,
                declared_media_type TEXT,
                detected_media_type TEXT,
                decoded_size INTEGER NOT NULL,
                inline INTEGER NOT NULL,
                content_id TEXT,
                blob_hash TEXT,
                decode_state TEXT NOT NULL DEFAULT 'complete',
                decode_problems_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY(message_id, ordinal)
            );

            CREATE TABLE IF NOT EXISTS mime_parts (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                part_id INTEGER NOT NULL,
                parent_part_id INTEGER,
                child_ids_json TEXT NOT NULL,
                kind TEXT NOT NULL,
                role TEXT NOT NULL,
                declared_media_type TEXT,
                name TEXT,
                content_id TEXT,
                content_location TEXT,
                inline INTEGER NOT NULL,
                attachment INTEGER NOT NULL,
                decoded_size INTEGER NOT NULL,
                decode_state TEXT NOT NULL,
                parse_flags_json TEXT NOT NULL,
                decode_problems_json TEXT NOT NULL,
                in_plain_body INTEGER NOT NULL,
                in_html_body INTEGER NOT NULL,
                PRIMARY KEY(message_id, part_id)
            );

            CREATE TABLE IF NOT EXISTS mime_part_blobs (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                part_id INTEGER NOT NULL,
                blob_hash TEXT NOT NULL,
                decoded_size INTEGER NOT NULL,
                PRIMARY KEY(message_id, part_id),
                FOREIGN KEY(message_id, part_id)
                    REFERENCES mime_parts(message_id, part_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS message_links (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                destination TEXT NOT NULL,
                scheme TEXT NOT NULL,
                host TEXT,
                registrable_domain TEXT,
                source TEXT NOT NULL,
                PRIMARY KEY(message_id, ordinal)
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                provenance_json TEXT NOT NULL DEFAULT '{"kind":"manual","source_label":null,"imported_at":null}',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS contact_addresses (
                contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
                address TEXT PRIMARY KEY COLLATE NOCASE,
                accepted_name TEXT
            );

            CREATE TABLE IF NOT EXISTS changes (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at INTEGER NOT NULL,
                kind TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS search_index_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                generation TEXT NOT NULL
            );
            INSERT OR IGNORE INTO search_index_meta(singleton, generation)
                VALUES (1, lower(hex(randomblob(16))));

            CREATE TABLE IF NOT EXISTS search_index_queue (
                message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                revision INTEGER NOT NULL CHECK(revision > 0)
            );

            CREATE TABLE IF NOT EXISTS search_index_delete_queue (
                message_id TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS imap_account_state (
                account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                capabilities_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'idle',
                last_attempt_at INTEGER,
                last_success_at INTEGER,
                next_retry_at INTEGER,
                failure_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS imap_mailbox_state (
                folder_id TEXT PRIMARY KEY REFERENCES folders(id) ON DELETE CASCADE,
                delimiter TEXT,
                attributes_json TEXT NOT NULL DEFAULT '[]',
                selectable INTEGER NOT NULL DEFAULT 1,
                remote_present INTEGER NOT NULL DEFAULT 1,
                highest_modseq INTEGER,
                exists_count INTEGER,
                sync_status TEXT NOT NULL DEFAULT 'not_started',
                completeness TEXT NOT NULL DEFAULT 'not_started',
                last_attempt_at INTEGER,
                last_success_at INTEGER,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS imap_mutations (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                message_id TEXT NOT NULL,
                source_folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                source_uid_validity INTEGER NOT NULL,
                source_uid INTEGER NOT NULL,
                source_modseq INTEGER,
                source_flags_json TEXT NOT NULL,
                operation_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS imap_mutation_conflicts (
                id TEXT PRIMARY KEY,
                mutation_id TEXT NOT NULL REFERENCES imap_mutations(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                expected_json TEXT NOT NULL,
                observed_json TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                resolved_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS smtp_accounts (
                account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                settings_json TEXT NOT NULL,
                credential_ref TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS drafts (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                revision INTEGER NOT NULL CHECK(revision > 0),
                status TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                parent_message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
                to_addresses TEXT NOT NULL,
                cc_addresses TEXT NOT NULL,
                bcc_addresses TEXT NOT NULL,
                subject TEXT NOT NULL,
                body_text TEXT NOT NULL,
                body_html TEXT,
                in_reply_to TEXT,
                references_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS draft_attachments (
                id TEXT PRIMARY KEY,
                draft_id TEXT NOT NULL REFERENCES drafts(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                name TEXT NOT NULL,
                media_type TEXT NOT NULL,
                disposition TEXT NOT NULL,
                content_id TEXT,
                blob_hash TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(draft_id, ordinal)
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                draft_id TEXT NOT NULL UNIQUE REFERENCES drafts(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                rfc_message_id TEXT NOT NULL UNIQUE,
                envelope_from TEXT NOT NULL,
                recipients_json TEXT NOT NULL,
                raw_blob_hash TEXT NOT NULL,
                raw_size_bytes INTEGER NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER,
                last_error TEXT,
                smtp_response TEXT,
                sent_message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS sent_reconciliation (
                rfc_message_id TEXT PRIMARY KEY,
                blob_hash TEXT NOT NULL,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                submission_id TEXT NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                reconciled_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS filter_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                priority INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                conditions_json TEXT NOT NULL,
                actions_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deleted_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS filter_rule_applications (
                rule_id TEXT NOT NULL REFERENCES filter_rules(id) ON DELETE CASCADE,
                rule_revision INTEGER NOT NULL,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                actions_json TEXT NOT NULL,
                prior_state_json TEXT NOT NULL DEFAULT '{"local_folder_ids":[],"remote_mutation_ids":[]}',
                applied_at INTEGER NOT NULL,
                undone_at INTEGER,
                PRIMARY KEY(rule_id, rule_revision, message_id)
            );

            CREATE TABLE IF NOT EXISTS saved_searches (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                query TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS filter_rule_versions (
                rule_id TEXT NOT NULL REFERENCES filter_rules(id) ON DELETE CASCADE,
                revision INTEGER NOT NULL,
                name TEXT NOT NULL,
                conditions_json TEXT NOT NULL,
                actions_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(rule_id, revision)
            );

            CREATE TABLE IF NOT EXISTS heuristics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version > 0),
                source TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                compiled_json TEXT NOT NULL,
                required_features_json TEXT NOT NULL,
                maximum_steps INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deleted_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS heuristic_findings (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                heuristic_id TEXT NOT NULL REFERENCES heuristics(id) ON DELETE CASCADE,
                heuristic_version INTEGER NOT NULL,
                code TEXT NOT NULL,
                presentation TEXT NOT NULL,
                severity TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id TEXT,
                text TEXT,
                evidence_json TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS heuristic_versions (
                heuristic_id TEXT NOT NULL REFERENCES heuristics(id) ON DELETE CASCADE,
                version INTEGER NOT NULL,
                source TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                compiled_json TEXT NOT NULL,
                required_features_json TEXT NOT NULL,
                maximum_steps INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(heuristic_id, version)
            );

            CREATE TABLE IF NOT EXISTS heuristic_finding_responses (
                finding_id TEXT PRIMARY KEY REFERENCES heuristic_findings(id) ON DELETE CASCADE,
                dismissed_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS heuristic_evaluations (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                heuristic_id TEXT NOT NULL REFERENCES heuristics(id) ON DELETE CASCADE,
                heuristic_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                detail TEXT,
                evaluated_at INTEGER NOT NULL,
                PRIMARY KEY(message_id, heuristic_id)
            );

            CREATE INDEX IF NOT EXISTS messages_received
                ON messages(received_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS messages_sender
                ON messages(from_address COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS instances_message
                ON message_instances(message_id);
            CREATE INDEX IF NOT EXISTS instances_account_folder
                ON message_instances(account_id, folder_id, message_id);
            CREATE INDEX IF NOT EXISTS provider_spam_evidence_message
                ON provider_spam_evidence(message_id, verdict, source);
            CREATE INDEX IF NOT EXISTS local_spam_assessments_verdict
                ON local_spam_assessments(verdict, message_id);
            CREATE INDEX IF NOT EXISTS spam_classification_queue_order
                ON spam_classification_queue(queued_at, message_id);
            CREATE INDEX IF NOT EXISTS local_memberships_folder
                ON local_folder_memberships(folder_id, message_id);
            CREATE INDEX IF NOT EXISTS message_links_message
                ON message_links(message_id, ordinal);
            CREATE INDEX IF NOT EXISTS mime_parts_message
                ON mime_parts(message_id, part_id);
            CREATE INDEX IF NOT EXISTS changes_sequence
                ON changes(sequence);
            CREATE INDEX IF NOT EXISTS filter_rules_execution
                ON filter_rules(enabled, priority, id);
            CREATE INDEX IF NOT EXISTS saved_searches_name
                ON saved_searches(name COLLATE NOCASE, id);
            CREATE INDEX IF NOT EXISTS heuristic_findings_message
                ON heuristic_findings(message_id, presentation, severity, id);
            CREATE INDEX IF NOT EXISTS heuristics_execution
                ON heuristics(enabled, id);
            CREATE INDEX IF NOT EXISTS imap_mutations_due
                ON imap_mutations(account_id, status, created_at, id);
            CREATE INDEX IF NOT EXISTS imap_mutation_conflicts_active
                ON imap_mutation_conflicts(mutation_id, resolved_at, created_at);
            CREATE INDEX IF NOT EXISTS submissions_due
                ON submissions(status, next_attempt_at, created_at, id);
            "#,
        )
        .await?;

    let mut rows = connection
        .query("SELECT version FROM schema_meta LIMIT 1", ())
        .await?;
    let mut version = rows
        .next()
        .await?
        .ok_or_else(|| crate::BackendError::InvalidInput("missing schema version".into()))?
        .get::<i64>(0)?;
    drop(rows);
    if version == 1 {
        connection
            .execute("DROP INDEX IF EXISTS messages_fts", ())
            .await?;
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut has_search_metadata = false;
        while let Some(row) = rows.next().await? {
            has_search_metadata |= row.get::<String>(1)? == "search_metadata";
        }
        drop(rows);
        if !has_search_metadata {
            connection
                .execute(
                    "ALTER TABLE messages ADD COLUMN search_metadata TEXT NOT NULL DEFAULT '{}'",
                    (),
                )
                .await?;
        }
        connection
            .execute(
                r#"UPDATE messages SET search_metadata = '{"received_at":' || received_at || '}'"#,
                (),
            )
            .await?;
        // Update the version last. Every preceding step is idempotent, so
        // an interrupted migration resumes safely on the next open.
        connection
            .execute("UPDATE schema_meta SET version = 2", ())
            .await?;
        version = 2;
    }
    if version == 2 {
        connection
            .execute_batch(
                r#"
                DROP INDEX IF EXISTS messages_fts;
                INSERT OR IGNORE INTO search_index_queue(message_id, revision)
                    SELECT id, 1 FROM messages;
                UPDATE schema_meta SET version = 3;
                "#,
            )
            .await?;
        version = 3;
    }
    if version == 3 {
        connection
            .execute("UPDATE schema_meta SET version = 4", ())
            .await?;
        version = 4;
    }
    if version == 4 {
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut has_dkim_json = false;
        while let Some(row) = rows.next().await? {
            has_dkim_json |= row.get::<String>(1)? == "dkim_json";
        }
        drop(rows);
        if !has_dkim_json {
            connection
                .execute(
                    r#"ALTER TABLE messages ADD COLUMN dkim_json TEXT NOT NULL DEFAULT '{"status":"not_evaluated","signatures":[],"evaluated_at":0,"detail":"DKIM was not evaluated before this schema version"}'"#,
                    (),
                )
                .await?;
        }
        connection
            .execute("UPDATE schema_meta SET version = 5", ())
            .await?;
        version = 5;
    }
    if version == 5 {
        // Version-six tables are created idempotently by the common schema
        // batch above. Update the version last so an interrupted open simply
        // retries their creation.
        connection
            .execute("UPDATE schema_meta SET version = 6", ())
            .await?;
        version = 6;
    }
    if version == 6 {
        // Version-seven tables and indexes are created idempotently by the
        // common schema batch above.
        connection
            .execute("UPDATE schema_meta SET version = 7", ())
            .await?;
        version = 7;
    }
    if version == 7 {
        // A version-eight upgrade can be interrupted between ALTER TABLE
        // statements. Probe each column so reopening resumes safely.
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        for (name, definition) in [
            ("thread_id", "TEXT REFERENCES threads(id)"),
            ("thread_message_id", "TEXT"),
            (
                "parent_message_id",
                "TEXT REFERENCES messages(id) ON DELETE SET NULL",
            ),
            ("threading_source", "TEXT"),
            ("sender_trust", "TEXT"),
            ("normalized_subject", "TEXT"),
            ("in_reply_to_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("references_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("reply_to_addresses", "TEXT NOT NULL DEFAULT '[]'"),
        ] {
            if !columns.contains(name) {
                connection
                    .execute(
                        &format!("ALTER TABLE messages ADD COLUMN {name} {definition}"),
                        (),
                    )
                    .await?;
            }
        }
        connection
            .execute("UPDATE schema_meta SET version = 8", ())
            .await?;
        version = 8;
    }
    if version == 8 {
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut message_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            message_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        for (name, definition) in [
            ("mime_state", "TEXT NOT NULL DEFAULT 'complete'"),
            ("mime_detail", "TEXT"),
        ] {
            if !message_columns.contains(name) {
                connection
                    .execute(
                        &format!("ALTER TABLE messages ADD COLUMN {name} {definition}"),
                        (),
                    )
                    .await?;
            }
        }
        let mut rows = connection
            .query("PRAGMA table_info(attachments)", ())
            .await?;
        let mut attachment_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            attachment_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        for (name, definition) in [
            ("part_id", "INTEGER NOT NULL DEFAULT 0"),
            ("detected_media_type", "TEXT"),
            ("blob_hash", "TEXT"),
            ("decode_state", "TEXT NOT NULL DEFAULT 'complete'"),
            ("decode_problems_json", "TEXT NOT NULL DEFAULT '[]'"),
        ] {
            if !attachment_columns.contains(name) {
                connection
                    .execute(
                        &format!("ALTER TABLE attachments ADD COLUMN {name} {definition}"),
                        (),
                    )
                    .await?;
            }
        }
        connection
            .execute("UPDATE schema_meta SET version = 9", ())
            .await?;
        version = 9;
    }
    if version == 9 {
        // Existing messages were ingested from complete RFC 5322 payloads.
        // Probe every column so an interrupted migration resumes safely.
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        for (name, definition) in [
            ("content_availability", "TEXT NOT NULL DEFAULT 'complete'"),
            ("downloaded_bytes", "INTEGER NOT NULL DEFAULT 0"),
            ("download_error", "TEXT"),
            ("download_updated_at", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !columns.contains(name) {
                connection
                    .execute(
                        &format!("ALTER TABLE messages ADD COLUMN {name} {definition}"),
                        (),
                    )
                    .await?;
            }
        }
        connection
            .execute(
                "UPDATE messages SET downloaded_bytes = size_bytes, download_updated_at = created_at WHERE content_availability = 'complete' AND downloaded_bytes = 0",
                (),
            )
            .await?;
        connection
            .execute("UPDATE schema_meta SET version = 10", ())
            .await?;
        version = 10;
    }
    if version == 10 {
        // Preserve standardized provider observations which were already
        // present as IMAP mailbox attributes and per-message keywords.
        connection
            .execute_batch(
                r#"
                INSERT OR IGNORE INTO provider_spam_evidence (
                    message_id, account_id, folder_id, uid_validity, imap_uid,
                    source, verdict, observed_at
                )
                SELECT mi.message_id, mi.account_id, mi.folder_id,
                    mi.uid_validity, mi.imap_uid,
                    'imap_junk_mailbox', 'spam', unixepoch()
                FROM message_instances mi
                JOIN imap_mailbox_state mailbox ON mailbox.folder_id = mi.folder_id
                JOIN json_each(mailbox.attributes_json) attribute
                WHERE attribute.value = '\Junk' COLLATE NOCASE;

                INSERT OR IGNORE INTO provider_spam_evidence (
                    message_id, account_id, folder_id, uid_validity, imap_uid,
                    source, verdict, observed_at
                )
                SELECT mi.message_id, mi.account_id, mi.folder_id,
                    mi.uid_validity, mi.imap_uid,
                    'imap_junk_keyword', 'spam', unixepoch()
                FROM message_instances mi
                JOIN json_each(mi.flags_json) flag
                WHERE flag.value = '$Junk' COLLATE NOCASE;

                INSERT OR IGNORE INTO provider_spam_evidence (
                    message_id, account_id, folder_id, uid_validity, imap_uid,
                    source, verdict, observed_at
                )
                SELECT mi.message_id, mi.account_id, mi.folder_id,
                    mi.uid_validity, mi.imap_uid,
                    'imap_not_junk_keyword', 'not_spam', unixepoch()
                FROM message_instances mi
                JOIN json_each(mi.flags_json) flag
                WHERE flag.value = '$NotJunk' COLLATE NOCASE;

                INSERT INTO search_index_queue(message_id, revision)
                    SELECT DISTINCT message_id, 1 FROM provider_spam_evidence
                    WHERE true
                    ON CONFLICT(message_id) DO UPDATE
                    SET revision = search_index_queue.revision + 1;
                UPDATE schema_meta SET version = 11;
                "#,
            )
            .await?;
        version = 11;
    }
    if version == 11 {
        // Version-twelve classifier tables and indexes are created
        // idempotently by the common schema batch. The bundled seed corpus is
        // installed by the classifier after structural migration completes.
        connection
            .execute("UPDATE schema_meta SET version = 12", ())
            .await?;
        version = 12;
    }
    if version == 12 {
        // Sender is distinct from From under RFC 5322 and is required for
        // provenance-preserving reply/identity evidence. Existing rows are
        // backfilled from immutable raw headers after the blob store opens.
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !columns.contains("sender_addresses") {
            connection
                .execute("ALTER TABLE messages ADD COLUMN sender_addresses TEXT", ())
                .await?;
        }
        connection
            .execute("UPDATE schema_meta SET version = 13", ())
            .await?;
        version = 13;
    }
    if version == 13 {
        // Version fourteen separates trusted delivery-time observations from
        // attacker-supplied Authentication-Results copies. Existing messages
        // are reparsed from immutable raw bytes after the blob store opens.
        let mut rows = connection.query("PRAGMA table_info(accounts)", ()).await?;
        let mut account_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            account_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !account_columns.contains("trusted_authserv_ids_json") {
            connection
                .execute(
                    "ALTER TABLE accounts ADD COLUMN trusted_authserv_ids_json TEXT NOT NULL DEFAULT '[]'",
                    (),
                )
                .await?;
        }
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut message_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            message_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !message_columns.contains("delivery_auth_json") {
            connection
                .execute(
                    "ALTER TABLE messages ADD COLUMN delivery_auth_json TEXT",
                    (),
                )
                .await?;
        }
        connection
            .execute("UPDATE schema_meta SET version = 14", ())
            .await?;
        version = 14;
    }
    if version == 14 {
        // Version fifteen completes durable organization state. Every step is
        // independently probed so interrupted upgrades resume safely.
        let mut rows = connection.query("PRAGMA table_info(messages)", ()).await?;
        let mut message_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            message_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !message_columns.contains("snoozed_until") {
            connection
                .execute("ALTER TABLE messages ADD COLUMN snoozed_until INTEGER", ())
                .await?;
        }
        if !message_columns.contains("muted") {
            connection
                .execute(
                    "ALTER TABLE messages ADD COLUMN muted INTEGER NOT NULL DEFAULT 0",
                    (),
                )
                .await?;
        }
        if !message_columns.contains("priority") {
            connection
                .execute(
                    "ALTER TABLE messages ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal'",
                    (),
                )
                .await?;
        }

        let mut rows = connection.query("PRAGMA table_info(contacts)", ()).await?;
        let mut contact_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            contact_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !contact_columns.contains("provenance_json") {
            connection
                .execute(
                    r#"ALTER TABLE contacts ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{"kind":"manual","source_label":null,"imported_at":null}'"#,
                    (),
                )
                .await?;
        }
        if !contact_columns.contains("updated_at") {
            connection
                .execute("ALTER TABLE contacts ADD COLUMN updated_at INTEGER", ())
                .await?;
            connection
                .execute("UPDATE contacts SET updated_at = created_at", ())
                .await?;
        }

        let mut rows = connection
            .query("PRAGMA table_info(filter_rule_applications)", ())
            .await?;
        let mut application_columns = HashSet::new();
        while let Some(row) = rows.next().await? {
            application_columns.insert(row.get::<String>(1)?);
        }
        drop(rows);
        if !application_columns.contains("prior_state_json") {
            connection
                .execute(
                    r#"ALTER TABLE filter_rule_applications ADD COLUMN prior_state_json TEXT NOT NULL DEFAULT '{"local_folder_ids":[],"remote_mutation_ids":[]}'"#,
                    (),
                )
                .await?;
        }
        if !application_columns.contains("undone_at") {
            connection
                .execute(
                    "ALTER TABLE filter_rule_applications ADD COLUMN undone_at INTEGER",
                    (),
                )
                .await?;
        }
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS saved_searches (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    query TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS saved_searches_name
                    ON saved_searches(name COLLATE NOCASE, id);
                UPDATE schema_meta SET version = 15;
                "#,
            )
            .await?;
        version = 15;
    }
    if version == 15 {
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS credential_cleanup_queue (
                    reference TEXT PRIMARY KEY,
                    queued_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                UPDATE schema_meta SET version = 16;
                "#,
            )
            .await?;
        version = 16;
    }
    if version != 16 {
        return Err(crate::BackendError::InvalidInput(format!(
            "unsupported database schema version {version}"
        )));
    }
    connection
        .execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS messages_thread
                ON messages(thread_id, received_at, id);
            CREATE INDEX IF NOT EXISTS messages_thread_message_id
                ON messages(thread_message_id, sender_trust, thread_id);
            CREATE INDEX IF NOT EXISTS threads_subject_fallback
                ON threads(sender_trust, normalized_subject, updated_at DESC);
            CREATE INDEX IF NOT EXISTS thread_participants_address
                ON thread_participants(address, thread_id, message_id);
            CREATE INDEX IF NOT EXISTS messages_content_availability
                ON messages(content_availability);
            "#,
        )
        .await?;
    // Scratch rows never need durability. Keeping them in the connection's
    // temporary database avoids doubling main-database WAL traffic while a
    // normalized batch is copied into the authoritative messages table.
    connection
        .execute_batch(
            r#"
            CREATE TEMP TABLE IF NOT EXISTS ingest_message_stage (
                batch_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                id TEXT NOT NULL,
                blob_hash TEXT NOT NULL,
                rfc_message_id TEXT,
                subject TEXT,
                from_address TEXT,
                from_name TEXT,
                to_addresses TEXT NOT NULL,
                cc_addresses TEXT NOT NULL,
                bcc_addresses TEXT NOT NULL,
                sender_addresses TEXT NOT NULL,
                reply_to_addresses TEXT NOT NULL,
                delivered_to_addresses TEXT NOT NULL,
                list_id TEXT,
                body_text TEXT NOT NULL,
                body_html TEXT,
                preview TEXT NOT NULL,
                sent_at INTEGER,
                received_at INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                has_attachment INTEGER NOT NULL,
                attachment_names TEXT NOT NULL,
                is_read INTEGER NOT NULL,
                is_starred INTEGER NOT NULL,
                user_classification TEXT,
                content_state TEXT NOT NULL,
                search_metadata TEXT NOT NULL,
                dkim_json TEXT NOT NULL,
                delivery_auth_json TEXT NOT NULL,
                mime_state TEXT NOT NULL,
                mime_detail TEXT,
                content_availability TEXT NOT NULL,
                downloaded_bytes INTEGER NOT NULL,
                download_error TEXT,
                download_updated_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(batch_id, position)
            );
            "#,
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replaces_version_one_fts_with_native_index_queue() {
        let profile = tempfile::tempdir().unwrap();
        let path = profile.path().join("mail.db");
        let database = turso::Builder::new_local(path.to_str().unwrap())
            .experimental_index_method(true)
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE schema_meta (version INTEGER NOT NULL);
                INSERT INTO schema_meta VALUES (1);
                CREATE TABLE messages (
                    id TEXT PRIMARY KEY,
                    blob_hash TEXT NOT NULL,
                    rfc_message_id TEXT,
                    subject TEXT,
                    from_address TEXT,
                    from_name TEXT,
                    to_addresses TEXT NOT NULL,
                    cc_addresses TEXT NOT NULL,
                    bcc_addresses TEXT NOT NULL,
                    delivered_to_addresses TEXT NOT NULL,
                    list_id TEXT,
                    body_text TEXT NOT NULL,
                    body_html TEXT,
                    preview TEXT NOT NULL,
                    sent_at INTEGER,
                    received_at INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    has_attachment INTEGER NOT NULL,
                    attachment_names TEXT NOT NULL,
                    is_read INTEGER NOT NULL,
                    is_starred INTEGER NOT NULL,
                    user_classification TEXT,
                    content_state TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                INSERT INTO messages VALUES (
                    'message-1', 'blob', NULL, 'migration subject', NULL, NULL,
                    '[]', '[]', '[]', '[]', NULL, 'migration needle', NULL,
                    'migration', NULL, 123, 16, 0, '', 0, 0, NULL, 'safe', 123
                );
                CREATE INDEX messages_fts ON messages USING fts (
                    subject, body_text, from_address, from_name, to_addresses,
                    cc_addresses, bcc_addresses, delivered_to_addresses,
                    list_id, attachment_names
                );
                "#,
            )
            .await
            .unwrap();

        migrate(&connection).await.unwrap();

        let mut rows = connection
            .query(
                "SELECT version, search_metadata FROM schema_meta, messages LIMIT 1",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<i64>(0).unwrap(), 16);
        assert_eq!(row.get::<String>(1).unwrap(), r#"{"received_at":123}"#);
        drop(rows);

        let mut rows = connection
            .query(
                "SELECT q.message_id, q.revision, length(meta.generation) FROM search_index_queue q, search_index_meta meta WHERE meta.singleton = 1",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<String>(0).unwrap(), "message-1");
        assert_eq!(row.get::<i64>(1).unwrap(), 1);
        assert_eq!(row.get::<i64>(2).unwrap(), 32);
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'messages_fts'",
                (),
            )
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );
        drop(rows);

        // Simulate interruption after the column was added but before the
        // schema version advanced. Reopening must resume rather than attempt
        // to add the column twice.
        connection
            .execute_batch("UPDATE schema_meta SET version = 1;")
            .await
            .unwrap();
        migrate(&connection).await.unwrap();
        let mut rows = connection
            .query("SELECT version FROM schema_meta", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            16
        );
        drop(rows);

        // Version eleven recovers standardized evidence that was already
        // represented by the server's mailbox attributes and keywords.
        connection
            .execute_batch(
                r#"
                INSERT INTO accounts(id, name, kind, created_at)
                    VALUES ('account-1', 'Migration account', 'imap', 123);
                INSERT INTO folders(
                    id, account_id, name, kind, remote_name, created_at
                ) VALUES (
                    'folder-1', 'account-1', 'Junk', 'remote', 'Junk', 123
                );
                INSERT INTO imap_mailbox_state(folder_id, attributes_json)
                    VALUES ('folder-1', '["\\Junk"]');
                INSERT INTO message_instances(
                    message_id, account_id, folder_id, uid_validity,
                    imap_uid, flags_json
                ) VALUES (
                    'message-1', 'account-1', 'folder-1', 7, 9,
                    '["$Junk","$NotJunk"]'
                );
                DELETE FROM provider_spam_evidence;
                UPDATE schema_meta SET version = 10;
                "#,
            )
            .await
            .unwrap();
        migrate(&connection).await.unwrap();
        let mut rows = connection
            .query(
                "SELECT source, verdict FROM provider_spam_evidence ORDER BY source",
                (),
            )
            .await
            .unwrap();
        let mut recovered = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            recovered.push((row.get::<String>(0).unwrap(), row.get::<String>(1).unwrap()));
        }
        assert_eq!(
            recovered,
            vec![
                ("imap_junk_keyword".into(), "spam".into()),
                ("imap_junk_mailbox".into(), "spam".into()),
                ("imap_not_junk_keyword".into(), "not_spam".into()),
            ]
        );
    }
}
