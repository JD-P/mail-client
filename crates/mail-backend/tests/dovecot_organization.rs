mod support;

use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ImapSecurity, ImapSettings, NewAccount,
};
use support::dovecot::DovecotContainer;

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn creates_renames_and_deletes_remote_mailboxes_against_dovecot() {
    let dovecot = DovecotContainer::start().await;
    let mut session = dovecot.login().await;
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot organization".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:dovecot-organization".into()),
            imap: Some(ImapSettings {
                host: "127.0.0.1".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();

    let folder = backend
        .folders()
        .create_remote(&mut session, account.id, "Rules Archive".into())
        .await
        .unwrap();
    session
        .append(
            "Rules Archive",
            None,
            None,
            b"From: sender@example.test\r\nTo: reader@example.test\r\nSubject: mailbox lifecycle\r\n\r\nbody\r\n",
        )
        .await
        .unwrap();
    let sync = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, folder.id)
        .await
        .unwrap();
    assert_eq!(sync.message_ids.len(), 1);

    let folder = backend
        .folders()
        .rename_remote(&mut session, folder.id, "Rules Renamed".into())
        .await
        .unwrap();
    assert_eq!(folder.remote_name.as_deref(), Some("Rules Renamed"));
    session.examine("Rules Renamed").await.unwrap();
    session.examine("INBOX").await.unwrap();

    backend
        .folders()
        .delete_remote(&mut session, folder.id)
        .await
        .unwrap();
    assert!(backend.folders().get(folder.id).await.is_err());
    assert!(backend.messages().get(sync.message_ids[0]).await.is_err());
    assert!(session.examine("Rules Renamed").await.is_err());
}
