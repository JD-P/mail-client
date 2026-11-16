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
                SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);

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
                search_metadata TEXT NOT NULL,
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
    if version != 3 {
        return Err(crate::BackendError::InvalidInput(format!(
            "unsupported database schema version {version}"
        )));
    }
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
        assert_eq!(row.get::<i64>(0).unwrap(), 3);
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
            3
        );
    }
}
