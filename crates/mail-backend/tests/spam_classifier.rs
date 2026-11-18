use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapFetchedMessage, ImapSecurity,
    ImapSettings, InboxClass, LocalSpamVerdict, NewAccount, NewFolder, SearchRequest,
    SpamClassifierStatus, UserClassification,
};

fn email(from: &str, subject: &str, body: &str, ordinal: usize) -> Vec<u8> {
    format!(
        concat!(
            "From: <{}>\r\n",
            "To: reader@example.net\r\n",
            "Date: Tue, 17 Nov 2026 12:00:00 +0000\r\n",
            "Message-ID: <spam-test-{}@fixture.example>\r\n",
            "Subject: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{}\r\n"
        ),
        from, ordinal, subject, body
    )
    .into_bytes()
}

async fn open() -> (tempfile::TempDir, Backend) {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    (profile, backend)
}

fn assert_pristine_seed(status: &SpamClassifierStatus) {
    assert_eq!(status.seed_spam_messages, 500);
    assert_eq!(status.seed_ham_messages, 500);
    assert_eq!(status.user_spam_messages, 0);
    assert_eq!(status.user_ham_messages, 0);
    assert_eq!(status.seed_corpus_hash.len(), 64);
}

#[tokio::test]
async fn pretrained_model_handles_held_out_spam_and_legitimate_edge_cases() {
    let (_profile, backend) = open().await;
    assert_pristine_seed(&backend.spam_classifier().status().await.unwrap());

    let cases = [
        (
            LocalSpamVerdict::Spam,
            "chief@executive-errand.example",
            "Quick confidential favor",
            "I cannot take calls. Buy six prepaid gift cards immediately, scratch the backs, and reply with photographs of every redemption code.",
        ),
        (
            LocalSpamVerdict::Spam,
            "desk@wallet-yield.example",
            "Risk-free investment window closes tonight",
            "Deposit cryptocurrency into the wallet below for guaranteed daily returns. Your private allocation expires in one hour.",
        ),
        (
            LocalSpamVerdict::Spam,
            "admin@credential-restore.example",
            "Mailbox disabled unless verified",
            "Confirm your email password on our external validation page now or every stored message will be permanently deleted.",
        ),
        (
            LocalSpamVerdict::Spam,
            "tracking@delivery-charge.example",
            "Your package could not be delivered",
            "Pay the redelivery charge using the card form within twelve hours or the unnamed parcel will be destroyed.",
        ),
        (
            LocalSpamVerdict::Spam,
            "agent@computer-rescue.example",
            "Virus warning - telephone support now",
            "Install our remote access utility and let the technician connect to your computer before your banking information is stolen.",
        ),
        (
            LocalSpamVerdict::Spam,
            "executor@unclaimed-estate.example",
            "Unclaimed family estate",
            "You may receive millions from a dormant inheritance. Reply secretly with identification and send the legal release fee by wire.",
        ),
        (
            LocalSpamVerdict::Spam,
            "billing@document-penalty.example",
            "Invoice overdue - legal action pending",
            "Open the attached executable invoice viewer and enable all content today to avoid collection penalties.",
        ),
        (
            LocalSpamVerdict::Spam,
            "recruiter@home-income.example",
            "Immediate remote job, no interview",
            "Deposit our check, purchase equipment gift cards, keep your weekly salary, and wire the remaining balance to our supplier.",
        ),
        (
            LocalSpamVerdict::Spam,
            "bonus@winner-casino.example",
            "Guaranteed winnings and free spins",
            "Deposit in the next hour to unlock a five hundred percent casino bonus with guaranteed winnings and unlimited free spins.",
        ),
        (
            LocalSpamVerdict::Spam,
            "audit@first-page-ranking.example",
            "Hundreds of errors on your website",
            "Our search experts guarantee first position and permanent backlinks. Pay today for an urgent optimization audit.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "security@museum.example",
            "Password reset requested",
            "A password reset was requested. Open the museum app yourself or type museum.example into your browser; do not copy a link from this email.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "painter@example.com",
            "Commission color proof and PayPal deposit",
            "The revised color proof is attached. If it looks right, send the deposit to the PayPal address from our signed commission agreement.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "lead@studio.example",
            "Urgent client deadline update",
            "The client moved delivery to Thursday. Please finish the ordinary PDF proof today and tell me if the schedule needs another illustrator.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "alerts@credit-union.example",
            "Card purchase notification",
            "Your card ending 1020 was used for 18.22 at the grocery store. If it was not you, call the number printed on your physical card.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "newsletter@history-club.example",
            "Monthly history club newsletter",
            "This issue contains archive photographs, next month's lecture schedule, and an unsubscribe link for members who no longer want the newsletter.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "tracking@shop.example",
            "Order S440 shipped",
            "Your paid order is on its way and should arrive Friday. Track it in the shop app. No redelivery or customs fee is due.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "trainer@company.example",
            "Gift card and password phishing examples",
            "Tomorrow's security workshop quotes urgent password links, fake invoices, and secret gift card requests so employees learn not to follow them.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "reminders@clinic.example",
            "Appointment reminder for Monday",
            "Your ordinary clinic appointment is Monday at 9:30. Call the clinic's published telephone number if you need to reschedule.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "tickets@rail.example",
            "Rail ticket R204 confirmed",
            "Your paid train ticket is confirmed for Tuesday morning. The attached PDF contains the barcode and platform information.",
        ),
        (
            LocalSpamVerdict::NotSpam,
            "announce@open-source.example",
            "Security release 4.2.1 available",
            "The project fixed two parser vulnerabilities. Download from the established project website and verify the published package signature.",
        ),
    ];

    for (index, (expected, from, subject, body)) in cases.into_iter().enumerate() {
        let id = backend
            .messages()
            .ingest(lizard_mail_backend::IngestMessage::local(email(
                from, subject, body, index,
            )))
            .await
            .unwrap();
        let stored = backend.messages().get(id).await.unwrap();
        let assessment = stored.local_spam.expect("ingest evaluates local spam");
        assert_eq!(
            assessment.verdict, expected,
            "unexpected score {} for {subject}; evidence: {:?}",
            assessment.score, assessment.evidence
        );
        assert_eq!(
            stored.summary.inbox_class,
            if expected == LocalSpamVerdict::Spam {
                InboxClass::Spam
            } else {
                InboxClass::Cold
            }
        );
    }
    let spam = backend
        .search()
        .search(SearchRequest {
            query: "is:spam".into(),
            page_size: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(spam.items.len(), 10);
}

#[tokio::test]
async fn explicit_feedback_trains_idempotently_and_relabels_reversibly() {
    let (profile, backend) = open().await;
    let id = backend
        .messages()
        .ingest(lizard_mail_backend::IngestMessage::local(email(
            "sender@novel.example",
            "Zqxj vrmpt kloth",
            "Zqxj vrmpt kloth qebnar flumed roxiven.",
            100,
        )))
        .await
        .unwrap();
    let initial = backend
        .messages()
        .get(id)
        .await
        .unwrap()
        .local_spam
        .unwrap();
    assert_eq!(initial.verdict, LocalSpamVerdict::Uncertain);

    backend
        .messages()
        .classify(id, Some(UserClassification::Spam))
        .await
        .unwrap();
    let trained = backend.spam_classifier().status().await.unwrap();
    assert_eq!(trained.user_spam_messages, 1);
    assert_eq!(trained.user_ham_messages, 0);
    assert_eq!(
        backend
            .messages()
            .get(id)
            .await
            .unwrap()
            .local_spam
            .unwrap()
            .verdict,
        LocalSpamVerdict::Spam
    );

    backend
        .messages()
        .classify(id, Some(UserClassification::Spam))
        .await
        .unwrap();
    let repeated = backend.spam_classifier().status().await.unwrap();
    assert_eq!(repeated.user_spam_messages, 1);
    assert_eq!(repeated.model_version, trained.model_version);

    backend
        .messages()
        .classify(id, Some(UserClassification::NotSpam))
        .await
        .unwrap();
    let relabeled = backend.spam_classifier().status().await.unwrap();
    assert_eq!(relabeled.user_spam_messages, 0);
    assert_eq!(relabeled.user_ham_messages, 1);
    assert_eq!(
        backend
            .messages()
            .get(id)
            .await
            .unwrap()
            .local_spam
            .unwrap()
            .verdict,
        LocalSpamVerdict::NotSpam
    );
    drop(backend);

    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let persisted = reopened.spam_classifier().status().await.unwrap();
    assert_eq!(persisted.user_spam_messages, 0);
    assert_eq!(persisted.user_ham_messages, 1);
    assert_eq!(persisted.model_version, relabeled.model_version);

    reopened.messages().classify(id, None).await.unwrap();
    let cleared = reopened.spam_classifier().status().await.unwrap();
    assert_eq!(cleared.user_spam_messages, 0);
    assert_eq!(cleared.user_ham_messages, 0);
}

#[tokio::test]
async fn provider_junk_is_evidence_but_never_training_data() {
    let (_profile, backend) = open().await;
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Provider".into(),
            kind: AccountKind::Imap,
            credential_ref: None,
            imap: Some(ImapSettings {
                host: "imap.example.com".into(),
                port: 993,
                username: "reader@example.com".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let folder = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();
    backend
        .sync()
        .ingest_imap_batch(
            account.id,
            folder.id,
            1,
            vec![ImapFetchedMessage {
                uid: 1,
                mod_sequence: Some(1),
                flags: vec!["$Junk".into()],
                internal_date: Some(1_800_000_000),
                raw: email(
                    "ordinary@example.com",
                    "An ordinary note",
                    "This message is intentionally ordinary provider evidence.",
                    200,
                ),
            }],
        )
        .await
        .unwrap();
    assert_pristine_seed(&backend.spam_classifier().status().await.unwrap());
}
