use crate::Result;

pub(crate) async fn migrate(connection: &turso::Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_meta (
                version INTEGER NOT NULL
            );
            INSERT INTO schema_meta(version)
                SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);

            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                credential_ref TEXT,
                settings_json TEXT,
                created_at INTEGER NOT NULL
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

            CREATE TABLE IF NOT EXISTS messages (
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

            CREATE TABLE IF NOT EXISTS local_folder_memberships (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(message_id, folder_id)
            );

            CREATE TABLE IF NOT EXISTS attachments (
                message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                name TEXT,
                declared_media_type TEXT,
                decoded_size INTEGER NOT NULL,
                inline INTEGER NOT NULL,
                content_id TEXT,
                PRIMARY KEY(message_id, ordinal)
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                created_at INTEGER NOT NULL
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

            CREATE INDEX IF NOT EXISTS messages_received
                ON messages(received_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS messages_sender
                ON messages(from_address COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS instances_message
                ON message_instances(message_id);
            CREATE INDEX IF NOT EXISTS instances_account_folder
                ON message_instances(account_id, folder_id, message_id);
            CREATE INDEX IF NOT EXISTS local_memberships_folder
                ON local_folder_memberships(folder_id, message_id);
            CREATE INDEX IF NOT EXISTS changes_sequence
                ON changes(sequence);
            "#,
        )
        .await?;

    // Turso's local FTS method is Tantivy-backed. The index is rebuildable;
    // messages and raw blobs remain the authoritative state.
    connection
        .execute(
            "CREATE INDEX IF NOT EXISTS messages_fts ON messages USING fts (subject, body_text, from_address, from_name, to_addresses, cc_addresses, bcc_addresses, delivered_to_addresses, list_id, attachment_names)",
            (),
        )
        .await?;
    Ok(())
}
