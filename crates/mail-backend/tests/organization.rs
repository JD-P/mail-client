use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ContactAddress, ContactProvenanceKind, FilterAction,
    FilterCondition, FolderKind, ImapMutationOperation, ImapMutationStatus, ImapSecurity,
    ImapSettings, IngestMessage, MessageFilter, MessagePriority, NewAccount, NewContact,
    NewFilterRule, NewFolder, NewSavedSearch, RemoteMessageIdentity,
};

fn message(subject: &str, from: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: Sender <{from}>\r\n",
            "To: reader@example.test\r\n",
            "Date: Mon, 16 Nov 2026 12:30:00 +0000\r\n",
            "Message-ID: <{id}@fixture.test>\r\n",
            "Subject: {subject}\r\n\r\n",
            "The cobalt invoice is ready.\r\n"
        ),
        from = from,
        id = uuid::Uuid::new_v4(),
        subject = subject,
    )
    .into_bytes()
}

fn imap_account(name: &str) -> NewAccount {
    NewAccount {
        name: name.into(),
        kind: AccountKind::Imap,
        credential_ref: Some("test:organization".into()),
        imap: Some(ImapSettings {
            host: "imap.example.test".into(),
            port: 993,
            username: "reader@example.test".into(),
            security: ImapSecurity::ImplicitTls,
        }),
    }
}

#[tokio::test]
async fn saved_searches_and_message_organization_are_durable() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let message_id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "November invoice",
            "billing@example.test",
        )))
        .await
        .unwrap();
    backend
        .messages()
        .set_snoozed_until(message_id, Some(1_900_000_000))
        .await
        .unwrap();
    backend
        .messages()
        .set_muted(message_id, true)
        .await
        .unwrap();
    backend
        .messages()
        .set_priority(message_id, MessagePriority::High)
        .await
        .unwrap();
    let stored = backend.messages().get(message_id).await.unwrap();
    assert_eq!(stored.summary.snoozed_until, Some(1_900_000_000));
    assert!(stored.summary.muted);
    assert_eq!(stored.summary.priority, MessagePriority::High);
    let filtered = backend
        .messages()
        .list(MessageFilter {
            snoozed: Some(true),
            muted: Some(true),
            priority: Some(MessagePriority::High),
            ..MessageFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(filtered.items.len(), 1);

    let saved = backend
        .saved_searches()
        .add(NewSavedSearch {
            name: "Invoices".into(),
            query: "subject:invoice".into(),
        })
        .await
        .unwrap();
    let page = backend
        .saved_searches()
        .run(saved.id, 20, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, message_id);
    let saved = backend
        .saved_searches()
        .update(
            saved.id,
            NewSavedSearch {
                name: "Receipts".into(),
                query: "subject:receipt".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(saved.name, "Receipts");
    assert!(backend
        .saved_searches()
        .run(saved.id, 20, None)
        .await
        .unwrap()
        .items
        .is_empty());

    drop(backend);
    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    assert_eq!(reopened.saved_searches().list().await.unwrap().len(), 1);
    assert!(
        reopened
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .summary
            .muted
    );
    reopened.saved_searches().remove(saved.id).await.unwrap();
}

#[tokio::test]
async fn filter_preview_replay_and_undo_restore_exact_local_placement() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let original = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Original".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    let receipts = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Receipts".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    let message_id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "November invoice",
            "billing@example.test",
        )))
        .await
        .unwrap();
    backend
        .messages()
        .add_to_local_folder(message_id, original.id)
        .await
        .unwrap();
    let definition = NewFilterRule {
        name: "Move invoices".into(),
        priority: 10,
        enabled: true,
        conditions: vec![FilterCondition::SubjectContains {
            value: "invoice".into(),
        }],
        actions: vec![FilterAction::MoveToLocalFolder {
            folder_id: receipts.id,
        }],
    };
    let preview = backend.filter_rules().preview(&definition).await.unwrap();
    assert_eq!(preview.matching_messages, 1);
    assert_eq!(preview.affected_messages, 1);
    let rule = backend.filter_rules().add(definition).await.unwrap();
    assert_eq!(
        backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .local_folder_ids,
        vec![original.id]
    );
    let replay = backend.filter_rules().replay(rule.id).await.unwrap();
    assert_eq!(replay.matching_messages, 1);
    assert_eq!(replay.newly_applied_messages, 1);
    assert_eq!(
        backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .local_folder_ids,
        vec![receipts.id]
    );
    assert_eq!(
        backend
            .filter_rules()
            .replay(rule.id)
            .await
            .unwrap()
            .already_applied_messages,
        1
    );
    let undone = backend
        .filter_rules()
        .undo(rule.id, rule.revision, message_id)
        .await
        .unwrap();
    assert_eq!(undone.restored_local_folders, vec![original.id]);
    assert_eq!(
        backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .local_folder_ids,
        vec![original.id]
    );
    assert!(backend
        .filter_rules()
        .undo(rule.id, rule.revision, message_id)
        .await
        .is_err());

    let edited = backend
        .filter_rules()
        .update(
            rule.id,
            NewFilterRule {
                name: "Tag invoices".into(),
                priority: 10,
                enabled: true,
                conditions: vec![FilterCondition::SubjectContains {
                    value: "invoice".into(),
                }],
                actions: vec![FilterAction::AddToLocalFolder {
                    folder_id: receipts.id,
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(edited.revision, 2);
    assert_eq!(
        backend
            .filter_rules()
            .replay(edited.id)
            .await
            .unwrap()
            .newly_applied_messages,
        1
    );
    let folders = backend
        .messages()
        .get(message_id)
        .await
        .unwrap()
        .local_folder_ids;
    assert_eq!(folders.len(), 2);
    assert!(folders.contains(&original.id));
    assert!(folders.contains(&receipts.id));
    backend
        .filter_rules()
        .undo(edited.id, edited.revision, message_id)
        .await
        .unwrap();
    assert_eq!(
        backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .local_folder_ids,
        vec![original.id]
    );
}

#[tokio::test]
async fn remote_delete_filters_use_the_mutation_outbox_and_pending_actions_undo() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(imap_account("Remote rules"))
        .await
        .unwrap();
    let inbox = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();
    let message_id = backend
        .messages()
        .ingest(IngestMessage {
            raw: message("Remote invoice", "billing@example.test"),
            remote: Some(RemoteMessageIdentity {
                account_id: account.id,
                folder_id: inbox.id,
                uid_validity: 7,
                uid: 11,
                mod_sequence: Some(12),
                flags: Vec::new(),
            }),
            received_at: None,
            user_classification: None,
        })
        .await
        .unwrap();
    let definition = NewFilterRule {
        name: "Delete remote invoices".into(),
        priority: 5,
        enabled: true,
        conditions: vec![FilterCondition::DeliveryFolder { id: inbox.id }],
        actions: vec![FilterAction::DeleteRemote {
            source_folder_id: inbox.id,
        }],
    };
    assert_eq!(
        backend
            .filter_rules()
            .preview(&definition)
            .await
            .unwrap()
            .affected_messages,
        1
    );
    let rule = backend.filter_rules().add(definition).await.unwrap();
    backend.filter_rules().replay(rule.id).await.unwrap();
    let mutations = backend
        .imap_mutations()
        .list(Some(account.id))
        .await
        .unwrap();
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].status, ImapMutationStatus::Pending);
    assert_eq!(mutations[0].operation, ImapMutationOperation::Delete);
    let undo = backend
        .filter_rules()
        .undo(rule.id, rule.revision, message_id)
        .await
        .unwrap();
    assert_eq!(undo.cancelled_remote_mutations, vec![mutations[0].id]);
    assert_eq!(
        backend
            .imap_mutations()
            .get(mutations[0].id)
            .await
            .unwrap()
            .status,
        ImapMutationStatus::Cancelled
    );

    let delete_rule = backend
        .filter_rules()
        .add(NewFilterRule {
            name: "Delete remote invoices".into(),
            priority: 6,
            enabled: true,
            conditions: vec![FilterCondition::DeliveryFolder { id: inbox.id }],
            actions: vec![FilterAction::DeleteRemote {
                source_folder_id: inbox.id,
            }],
        })
        .await
        .unwrap();
    backend.filter_rules().replay(delete_rule.id).await.unwrap();
    assert!(backend
        .imap_mutations()
        .list(Some(account.id))
        .await
        .unwrap()
        .iter()
        .any(|mutation| mutation.operation == ImapMutationOperation::Delete));
}

#[tokio::test]
async fn contacts_are_editable_and_vcard_imports_retain_provenance() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let contact = backend
        .contacts()
        .add(NewContact {
            display_name: "Frank".into(),
            addresses: vec![ContactAddress {
                address: "frank@example.test".into(),
                accepted_name: Some("Frank".into()),
            }],
        })
        .await
        .unwrap();
    assert_eq!(contact.provenance.kind, ContactProvenanceKind::Manual);
    let contact = backend
        .contacts()
        .update(
            contact.id,
            NewContact {
                display_name: "Franklin".into(),
                addresses: vec![ContactAddress {
                    address: "franklin@example.test".into(),
                    accepted_name: Some("Frank".into()),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(contact.display_name, "Franklin");
    assert_eq!(contact.provenance.kind, ContactProvenanceKind::Manual);

    let result = backend
        .contacts()
        .import_vcards(
            b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Abigail Marie\r\nEMAIL:abigail@example.test\r\nEND:VCARD\r\n",
            Some("address-book.vcf".into()),
        )
        .await
        .unwrap();
    assert_eq!(result.imported.len(), 1);
    let imported = backend.contacts().get(result.imported[0]).await.unwrap();
    assert_eq!(imported.provenance.kind, ContactProvenanceKind::VcardImport);
    assert_eq!(
        imported.provenance.source_label.as_deref(),
        Some("address-book.vcf")
    );
    assert!(imported.provenance.imported_at.is_some());
    let duplicate = backend
        .contacts()
        .import_vcards(
            b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Abigail Again\r\nEMAIL:abigail@example.test\r\nEND:VCARD\r\n",
            None,
        )
        .await
        .unwrap();
    assert_eq!(duplicate.skipped_duplicate_contacts, 1);
    let exported = String::from_utf8(backend.contacts().export_vcards().await.unwrap()).unwrap();
    assert!(exported.contains("FN:Abigail Marie\r\n"));
    assert!(exported.contains("EMAIL:abigail@example.test\r\n"));
    assert!(exported.contains("X-LIZARD-ACCEPTED-NAME:Frank\r\n"));
}

#[tokio::test]
async fn accounts_and_local_folders_can_be_updated_and_removed() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(imap_account("Old name"))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .update(account.id, imap_account("New name"))
        .await
        .unwrap();
    assert_eq!(account.name, "New name");
    let folder = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Old folder".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    let folder = backend
        .folders()
        .update(
            folder.id,
            NewFolder {
                account_id: None,
                name: "New folder".into(),
                kind: FolderKind::Local,
                remote_name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(folder.name, "New folder");
    backend.folders().remove(folder.id).await.unwrap();
    assert!(backend.folders().get(folder.id).await.is_err());

    let account_local_folder = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Account-local notes".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    let account_local_message = backend
        .messages()
        .ingest(IngestMessage {
            raw: message("Account-local", "sender@example.test"),
            remote: None,
            received_at: None,
            user_classification: None,
        })
        .await
        .unwrap();
    backend
        .messages()
        .add_to_local_folder(account_local_message, account_local_folder.id)
        .await
        .unwrap();
    backend.accounts().remove(account.id).await.unwrap();
    assert!(backend.accounts().get(account.id).await.is_err());
    assert!(backend.messages().get(account_local_message).await.is_err());
}
