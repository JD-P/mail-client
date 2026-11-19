use crate::backend::{enqueue_search_on, insert_event};
use crate::{
    Backend, BackendError, LocalSpamAssessment, LocalSpamVerdict, MessageId, Result,
    SpamClassifierStatus, SpamReclassificationResult, SpamTokenEvidence, UserClassification,
};
use chrono::Utc;
use linkify::{LinkFinder, LinkKind};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;
use turso::{params_from_iter, Connection, Value};
use url::Url;

const SEED_CORPUS: &str = include_str!("spam_seed_corpus.tsv");
const MAX_FEATURES: usize = 2_048;
const MAX_WORDS_PER_FIELD: usize = 1_024;
const MAX_TOKEN_CHARS: usize = 48;
const MAX_HTML_INPUT_CHARS: usize = 262_144;
const MAX_HTML_VISIBLE_CHARS: usize = 65_536;
const MAX_MODEL_TOKENS: usize = 150;
const MAX_EXPLANATION_TOKENS: usize = 16;
const MIN_DISCRIMINATION: f64 = 0.10;
const ROBINSON_STRENGTH: f64 = 0.45;
const ROBINSON_ASSUMED_PROBABILITY: f64 = 0.50;
const SPAM_THRESHOLD: f64 = 0.90;
const HAM_THRESHOLD: f64 = 0.10;
const MAX_RECLASSIFICATION_BATCH: usize = 1_000;
const SQL_TOKEN_CHUNK: usize = 200;

struct SeedCorpus {
    license: String,
    description: String,
    messages: Vec<SeedMessage>,
}

struct SeedMessage {
    label: String,
    category: String,
    from: String,
    subject: String,
    body: String,
}

#[derive(Clone, Debug)]
struct MessageFeatures {
    from: Option<String>,
    subject: Option<String>,
    body: String,
    html: Option<String>,
    attachment_names: String,
    link_domains: Vec<String>,
}

#[derive(Clone, Debug)]
struct ScoredMessage {
    assessment: LocalSpamAssessment,
}

#[derive(Clone)]
pub struct SpamClassifier(Backend);

impl SpamClassifier {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn status(&self) -> Result<SpamClassifierStatus> {
        let connection = self.0.inner.connection.lock().await;
        status_on(&connection).await
    }

    /// Re-evaluate a bounded portion of the durable queue after seed/model
    /// changes. Hosts may call this from an idle worker; ingestion and direct
    /// user corrections always evaluate the affected message synchronously.
    pub async fn reclassify_pending(&self, limit: usize) -> Result<SpamReclassificationResult> {
        let limit = limit.clamp(1, MAX_RECLASSIFICATION_BATCH);
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT message_id FROM spam_classification_queue ORDER BY queued_at, message_id LIMIT ?1",
                (i64::try_from(limit).unwrap_or(i64::MAX),),
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(parse_message_id(row.get::<String>(0)?)?);
        }
        drop(rows);

        let mut changed_verdicts = 0usize;
        for message_id in &ids {
            if classify_message_on(&transaction, *message_id, now).await? {
                changed_verdicts += 1;
            }
        }
        let event = if changed_verdicts > 0 {
            Some(
                insert_event(
                    &transaction,
                    now,
                    "local_spam_batch_reclassified",
                    "spam_classifier".into(),
                    serde_json::json!({
                        "processed": ids.len(),
                        "changed_verdicts": changed_verdicts,
                    }),
                )
                .await?,
            )
        } else {
            None
        };
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        if let Some(event) = event {
            let _ = self.0.inner.events.send(event);
        }
        // Spam evidence is message-scoped. Re-evaluate exactly the processed
        // messages instead of scanning a large profile after every batch.
        for message_id in &ids {
            self.0.heuristics().evaluate_message(*message_id).await?;
        }
        let status = self.status().await?;
        Ok(SpamReclassificationResult {
            processed: ids.len(),
            changed_verdicts,
            remaining: status.pending_messages,
            model_version: status.model_version,
        })
    }
}

pub(crate) async fn initialize(connection: &mut Connection) -> Result<()> {
    let corpus = parse_seed_corpus(SEED_CORPUS)?;
    validate_seed_corpus(&corpus)?;
    let corpus_hash = hex::encode(Sha256::digest(SEED_CORPUS.as_bytes()));
    let mut rows = connection
        .query(
            "SELECT seed_corpus_hash FROM spam_model_meta WHERE singleton = 1",
            (),
        )
        .await?;
    let current_hash = rows
        .next()
        .await?
        .map(|row| row.get::<String>(0))
        .transpose()?;
    drop(rows);
    if current_hash.as_deref() == Some(corpus_hash.as_str()) {
        return Ok(());
    }

    let mut counts: HashMap<String, (i64, i64)> = HashMap::new();
    let mut spam_messages = 0i64;
    let mut ham_messages = 0i64;
    for message in &corpus.messages {
        let tokens = tokenize(&MessageFeatures {
            from: Some(message.from.clone()),
            subject: Some(message.subject.clone()),
            body: message.body.clone(),
            html: None,
            attachment_names: String::new(),
            link_domains: domains_in_text(&message.body),
        });
        let spam = message.label == "spam";
        if spam {
            spam_messages += 1;
        } else {
            ham_messages += 1;
        }
        for token in tokens {
            let entry = counts.entry(token).or_default();
            if spam {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }

    let now = Utc::now().timestamp();
    let transaction = connection.transaction().await?;
    transaction
        .execute(
            "UPDATE spam_token_counts SET seed_spam_documents = 0, seed_ham_documents = 0",
            (),
        )
        .await?;
    let mut counts = counts.into_iter().collect::<Vec<_>>();
    counts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for chunk in counts.chunks(100) {
        let values = std::iter::repeat_n("(?, ?, ?, 0, 0)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut parameters = Vec::with_capacity(chunk.len() * 3);
        for (token, (spam, ham)) in chunk {
            parameters.push(Value::Text(token.clone()));
            parameters.push(Value::Integer(*spam));
            parameters.push(Value::Integer(*ham));
        }
        let sql = format!(
            r#"INSERT INTO spam_token_counts(
                token, seed_spam_documents, seed_ham_documents,
                user_spam_documents, user_ham_documents
            ) VALUES {values}
            ON CONFLICT(token) DO UPDATE SET
                seed_spam_documents = excluded.seed_spam_documents,
                seed_ham_documents = excluded.seed_ham_documents"#
        );
        transaction
            .execute(sql, params_from_iter(parameters))
            .await?;
    }
    transaction
        .execute(
            "DELETE FROM spam_token_counts WHERE seed_spam_documents = 0 AND seed_ham_documents = 0 AND user_spam_documents = 0 AND user_ham_documents = 0",
            (),
        )
        .await?;
    transaction
        .execute(
            r#"INSERT INTO spam_model_meta(
                singleton, seed_corpus_hash, seed_spam_messages,
                seed_ham_messages, user_spam_messages, user_ham_messages,
                model_version, updated_at
            ) VALUES (1, ?1, ?2, ?3, 0, 0, 1, ?4)
            ON CONFLICT(singleton) DO UPDATE SET
                seed_corpus_hash = excluded.seed_corpus_hash,
                seed_spam_messages = excluded.seed_spam_messages,
                seed_ham_messages = excluded.seed_ham_messages,
                model_version = spam_model_meta.model_version + 1,
                updated_at = excluded.updated_at"#,
            (corpus_hash, spam_messages, ham_messages, now),
        )
        .await?;
    transaction
        .execute(
            r#"INSERT INTO spam_classification_queue(message_id, reason, queued_at)
                SELECT id, 'seed_corpus_changed', ?1 FROM messages WHERE true
                ON CONFLICT(message_id) DO UPDATE SET
                    reason = excluded.reason, queued_at = excluded.queued_at"#,
            (now,),
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn classify_message_on(
    connection: &Connection,
    message_id: MessageId,
    now: i64,
) -> Result<bool> {
    let features = load_message_features_on(connection, message_id).await?;
    let scored = score_tokens_on(connection, &tokenize(&features), now).await?;
    let mut rows = connection
        .query(
            "SELECT verdict FROM local_spam_assessments WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let previous = rows
        .next()
        .await?
        .map(|row| row.get::<String>(0))
        .transpose()?;
    drop(rows);
    let verdict = local_verdict_text(scored.assessment.verdict);
    connection
        .execute(
            r#"INSERT INTO local_spam_assessments(
                message_id, verdict, score, model_version, evidence_json,
                evaluated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(message_id) DO UPDATE SET
                verdict = excluded.verdict,
                score = excluded.score,
                model_version = excluded.model_version,
                evidence_json = excluded.evidence_json,
                evaluated_at = excluded.evaluated_at"#,
            turso::params![
                message_id.to_string(),
                verdict,
                scored.assessment.score,
                i64::try_from(scored.assessment.model_version).unwrap_or(i64::MAX),
                serde_json::to_string(&scored.assessment.evidence)?,
                scored.assessment.evaluated_at,
            ],
        )
        .await?;
    connection
        .execute(
            "DELETE FROM spam_classification_queue WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let changed = previous.as_deref() != Some(verdict);
    if changed {
        enqueue_search_on(connection, message_id).await?;
    }
    Ok(changed)
}

pub(crate) async fn sync_user_training_on(
    connection: &Connection,
    message_id: MessageId,
    classification: Option<UserClassification>,
    now: i64,
) -> Result<bool> {
    let mut rows = connection
        .query(
            "SELECT classification, tokens_json FROM spam_user_training WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let existing = rows
        .next()
        .await?
        .map(|row| {
            Ok::<_, crate::BackendError>((
                parse_user_classification(&row.get::<String>(0)?)?,
                serde_json::from_str::<Vec<String>>(&row.get::<String>(1)?)?,
            ))
        })
        .transpose()?;
    drop(rows);
    let new_tokens = if classification.is_some() {
        tokenize(&load_message_features_on(connection, message_id).await?)
    } else {
        Vec::new()
    };
    if existing
        .as_ref()
        .is_some_and(|(old, tokens)| Some(*old) == classification && *tokens == new_tokens)
        || (existing.is_none() && classification.is_none())
    {
        return Ok(false);
    }

    let mut spam_message_delta = 0i64;
    let mut ham_message_delta = 0i64;
    if let Some((old, tokens)) = &existing {
        adjust_user_token_counts(connection, tokens, *old, -1).await?;
        match old {
            UserClassification::Spam => spam_message_delta -= 1,
            UserClassification::NotSpam => ham_message_delta -= 1,
        }
    }
    if let Some(new) = classification {
        adjust_user_token_counts(connection, &new_tokens, new, 1).await?;
        match new {
            UserClassification::Spam => spam_message_delta += 1,
            UserClassification::NotSpam => ham_message_delta += 1,
        }
        connection
            .execute(
                r#"INSERT INTO spam_user_training(
                    message_id, classification, tokens_json, trained_at
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(message_id) DO UPDATE SET
                    classification = excluded.classification,
                    tokens_json = excluded.tokens_json,
                    trained_at = excluded.trained_at"#,
                (
                    message_id.to_string(),
                    user_classification_text(new),
                    serde_json::to_string(&new_tokens)?,
                    now,
                ),
            )
            .await?;
    } else {
        connection
            .execute(
                "DELETE FROM spam_user_training WHERE message_id = ?1",
                (message_id.to_string(),),
            )
            .await?;
    }
    connection
        .execute(
            "DELETE FROM spam_token_counts WHERE seed_spam_documents = 0 AND seed_ham_documents = 0 AND user_spam_documents = 0 AND user_ham_documents = 0",
            (),
        )
        .await?;
    let changed = connection
        .execute(
            r#"UPDATE spam_model_meta SET
                user_spam_messages = user_spam_messages + ?1,
                user_ham_messages = user_ham_messages + ?2,
                model_version = model_version + 1,
                updated_at = ?3
            WHERE singleton = 1"#,
            (spam_message_delta, ham_message_delta, now),
        )
        .await?;
    if changed == 0 {
        return Err(BackendError::InvalidInput(
            "local spam model is not initialized".into(),
        ));
    }
    connection
        .execute(
            r#"INSERT INTO spam_classification_queue(message_id, reason, queued_at)
                SELECT id, 'user_training_changed', ?1 FROM messages WHERE true
                ON CONFLICT(message_id) DO UPDATE SET
                    reason = excluded.reason, queued_at = excluded.queued_at"#,
            (now,),
        )
        .await?;
    Ok(true)
}

pub(crate) async fn refresh_training_and_classification_on(
    connection: &Connection,
    message_id: MessageId,
    now: i64,
) -> Result<bool> {
    let mut rows = connection
        .query(
            "SELECT classification FROM spam_user_training WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let classification = rows
        .next()
        .await?
        .map(|row| parse_user_classification(&row.get::<String>(0)?))
        .transpose()?;
    drop(rows);
    let model_changed = if classification.is_some() {
        sync_user_training_on(connection, message_id, classification, now).await?
    } else {
        false
    };
    classify_message_on(connection, message_id, now).await?;
    Ok(model_changed)
}

pub(crate) async fn load_assessment_on(
    connection: &Connection,
    message_id: MessageId,
) -> Result<Option<LocalSpamAssessment>> {
    let mut rows = connection
        .query(
            "SELECT verdict, score, model_version, evidence_json, evaluated_at FROM local_spam_assessments WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| {
            Ok(LocalSpamAssessment {
                verdict: parse_local_verdict(&row.get::<String>(0)?)?,
                score: row.get(1)?,
                model_version: u64::try_from(row.get::<i64>(2)?).map_err(|_| {
                    BackendError::InvalidInput(
                        "database contains invalid spam model version".into(),
                    )
                })?,
                evidence: serde_json::from_str(&row.get::<String>(3)?)?,
                evaluated_at: row.get(4)?,
            })
        })
        .transpose()
}

async fn status_on(connection: &Connection) -> Result<SpamClassifierStatus> {
    let mut rows = connection
        .query(
            r#"SELECT seed_corpus_hash, seed_spam_messages, seed_ham_messages,
                user_spam_messages, user_ham_messages, model_version,
                updated_at,
                (SELECT count(*) FROM spam_classification_queue)
            FROM spam_model_meta WHERE singleton = 1"#,
            (),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| BackendError::InvalidInput("local spam model is not initialized".into()))?;
    Ok(SpamClassifierStatus {
        seed_corpus_hash: row.get(0)?,
        seed_spam_messages: database_u64(row.get(1)?, "seed spam message count")?,
        seed_ham_messages: database_u64(row.get(2)?, "seed ham message count")?,
        user_spam_messages: database_u64(row.get(3)?, "user spam message count")?,
        user_ham_messages: database_u64(row.get(4)?, "user ham message count")?,
        model_version: database_u64(row.get(5)?, "spam model version")?,
        updated_at: row.get(6)?,
        pending_messages: database_u64(row.get(7)?, "pending spam message count")?,
    })
}

async fn load_message_features_on(
    connection: &Connection,
    message_id: MessageId,
) -> Result<MessageFeatures> {
    let mut rows = connection
        .query(
            "SELECT from_address, subject, body_text, body_html, attachment_names FROM messages WHERE id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    let row = rows.next().await?.ok_or_else(|| BackendError::NotFound {
        entity: "message",
        id: message_id.to_string(),
    })?;
    let mut features = MessageFeatures {
        from: row.get(0)?,
        subject: row.get(1)?,
        body: row.get(2)?,
        html: row.get(3)?,
        attachment_names: row.get(4)?,
        link_domains: Vec::new(),
    };
    drop(rows);
    let mut rows = connection
        .query(
            "SELECT COALESCE(registrable_domain, host) FROM message_links WHERE message_id = ?1 AND COALESCE(registrable_domain, host) IS NOT NULL ORDER BY ordinal",
            (message_id.to_string(),),
        )
        .await?;
    while let Some(row) = rows.next().await? {
        features.link_domains.push(row.get(0)?);
    }
    Ok(features)
}

async fn score_tokens_on(
    connection: &Connection,
    tokens: &[String],
    now: i64,
) -> Result<ScoredMessage> {
    let status = status_on(connection).await?;
    let spam_total = status.seed_spam_messages + status.user_spam_messages;
    let ham_total = status.seed_ham_messages + status.user_ham_messages;
    if spam_total == 0 || ham_total == 0 {
        return Err(BackendError::InvalidInput(
            "local spam model requires both spam and legitimate examples".into(),
        ));
    }
    let counts = load_token_counts_on(connection, tokens).await?;
    let mut probabilities = Vec::new();
    for token in tokens {
        let Some((spam_count, ham_count)) = counts.get(token) else {
            continue;
        };
        let spam_frequency = *spam_count as f64 / spam_total as f64;
        let ham_frequency = *ham_count as f64 / ham_total as f64;
        let denominator = spam_frequency + ham_frequency;
        if denominator <= f64::EPSILON {
            continue;
        }
        let raw = spam_frequency / denominator;
        let observations = (*spam_count + *ham_count) as f64;
        let probability = ((ROBINSON_STRENGTH * ROBINSON_ASSUMED_PROBABILITY) + observations * raw)
            / (ROBINSON_STRENGTH + observations);
        let probability = probability.clamp(0.01, 0.99);
        if (probability - 0.5).abs() >= MIN_DISCRIMINATION {
            probabilities.push((token.clone(), probability));
        }
    }
    probabilities.sort_by(|left, right| {
        (right.1 - 0.5)
            .abs()
            .total_cmp(&(left.1 - 0.5).abs())
            .then_with(|| left.0.cmp(&right.0))
    });
    probabilities.truncate(MAX_MODEL_TOKENS);
    let score = fisher_score(&probabilities);
    let verdict = if score >= SPAM_THRESHOLD {
        LocalSpamVerdict::Spam
    } else if score <= HAM_THRESHOLD {
        LocalSpamVerdict::NotSpam
    } else {
        LocalSpamVerdict::Uncertain
    };
    let evidence = probabilities
        .iter()
        .take(MAX_EXPLANATION_TOKENS)
        .map(|(token, probability)| SpamTokenEvidence {
            token: token.clone(),
            probability: *probability,
        })
        .collect();
    Ok(ScoredMessage {
        assessment: LocalSpamAssessment {
            verdict,
            score,
            model_version: status.model_version,
            evidence,
            evaluated_at: now,
        },
    })
}

async fn load_token_counts_on(
    connection: &Connection,
    tokens: &[String],
) -> Result<HashMap<String, (u64, u64)>> {
    let mut counts = HashMap::new();
    for chunk in tokens.chunks(SQL_TOKEN_CHUNK) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT token, seed_spam_documents + user_spam_documents, seed_ham_documents + user_ham_documents FROM spam_token_counts WHERE token IN ({placeholders})"
        );
        let parameters = chunk.iter().cloned().map(Value::Text).collect::<Vec<_>>();
        let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
        while let Some(row) = rows.next().await? {
            counts.insert(
                row.get::<String>(0)?,
                (
                    database_u64(row.get(1)?, "spam token count")?,
                    database_u64(row.get(2)?, "ham token count")?,
                ),
            );
        }
    }
    Ok(counts)
}

async fn adjust_user_token_counts(
    connection: &Connection,
    tokens: &[String],
    classification: UserClassification,
    delta: i64,
) -> Result<()> {
    if delta == -1 {
        for chunk in tokens.chunks(SQL_TOKEN_CHUNK) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let column = match classification {
                UserClassification::Spam => "user_spam_documents",
                UserClassification::NotSpam => "user_ham_documents",
            };
            let sql = format!(
                "UPDATE spam_token_counts SET {column} = {column} - 1 WHERE token IN ({placeholders})"
            );
            connection
                .execute(
                    sql,
                    params_from_iter(chunk.iter().cloned().map(Value::Text)),
                )
                .await?;
        }
        return Ok(());
    }
    debug_assert_eq!(delta, 1);
    for chunk in tokens.chunks(100) {
        let values = std::iter::repeat_n("(?, 0, 0, ?, ?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut parameters = Vec::with_capacity(chunk.len() * 3);
        for token in chunk {
            parameters.push(Value::Text(token.clone()));
            parameters.push(Value::Integer(i64::from(
                classification == UserClassification::Spam,
            )));
            parameters.push(Value::Integer(i64::from(
                classification == UserClassification::NotSpam,
            )));
        }
        let spam_update = if classification == UserClassification::Spam {
            "spam_token_counts.user_spam_documents + 1"
        } else {
            "spam_token_counts.user_spam_documents"
        };
        let ham_update = if classification == UserClassification::NotSpam {
            "spam_token_counts.user_ham_documents + 1"
        } else {
            "spam_token_counts.user_ham_documents"
        };
        let sql = format!(
            r#"INSERT INTO spam_token_counts(
                token, seed_spam_documents, seed_ham_documents,
                user_spam_documents, user_ham_documents
            ) VALUES {values}
            ON CONFLICT(token) DO UPDATE SET
                user_spam_documents = {spam_update},
                user_ham_documents = {ham_update}"#
        );
        connection
            .execute(sql, params_from_iter(parameters))
            .await?;
    }
    Ok(())
}

fn tokenize(features: &MessageFeatures) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    if let Some(from) = &features.from {
        if let Some((_, domain)) = from.rsplit_once('@') {
            insert_token(&mut tokens, format!("from:{}", domain.to_lowercase()));
        }
    }
    if let Some(subject) = &features.subject {
        add_word_features(&mut tokens, subject, "s:", "sb:", 128);
    }
    for domain in &features.link_domains {
        insert_token(&mut tokens, format!("url:{}", domain.to_lowercase()));
    }
    for name in features.attachment_names.split_whitespace().take(128) {
        if let Some((_, extension)) = name.rsplit_once('.') {
            insert_token(
                &mut tokens,
                format!("attachment:.{}", extension.to_lowercase()),
            );
        }
    }
    let html_text;
    let body = if features.body.trim().is_empty() {
        html_text = features
            .html
            .as_deref()
            .map(visible_html_prefix)
            .unwrap_or_default();
        html_text.as_str()
    } else {
        features.body.as_str()
    };
    add_meta_features(&mut tokens, body);
    add_word_features(&mut tokens, body, "w:", "b:", MAX_WORDS_PER_FIELD);
    tokens.into_iter().take(MAX_FEATURES).collect()
}

fn visible_html_prefix(html: &str) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    let mut output_chars = 0usize;
    for character in html.chars().take(MAX_HTML_INPUT_CHARS) {
        match character {
            '<' => {
                in_tag = true;
                if !output.ends_with(' ') {
                    output.push(' ');
                    output_chars += 1;
                }
            }
            '>' if in_tag => in_tag = false,
            _ if !in_tag && output_chars < MAX_HTML_VISIBLE_CHARS => {
                output.push(character);
                output_chars += 1;
            }
            _ => {}
        }
        if output_chars >= MAX_HTML_VISIBLE_CHARS {
            break;
        }
    }
    output
}

fn add_word_features(
    tokens: &mut BTreeSet<String>,
    value: &str,
    unigram_prefix: &str,
    bigram_prefix: &str,
    max_words: usize,
) {
    let words = words(value, max_words);
    for word in &words {
        insert_token(tokens, format!("{unigram_prefix}{word}"));
    }
    for pair in words.windows(2) {
        insert_token(tokens, format!("{bigram_prefix}{}_{}", pair[0], pair[1]));
    }
}

fn words(value: &str, max_words: usize) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for character in value.chars() {
        if character.is_alphanumeric() && current.chars().count() < MAX_TOKEN_CHARS {
            current.extend(character.to_lowercase());
        } else if !current.is_empty() {
            if current.chars().count() >= 2 {
                words.push(std::mem::take(&mut current));
                if words.len() >= max_words {
                    break;
                }
            } else {
                current.clear();
            }
        }
    }
    if !current.is_empty() && current.chars().count() >= 2 && words.len() < max_words {
        words.push(current);
    }
    words
}

fn add_meta_features(tokens: &mut BTreeSet<String>, body: &str) {
    let lower = body.to_lowercase();
    if body.contains('$') || body.contains('€') || body.contains('£') {
        insert_token(tokens, "meta:currency".into());
    }
    if body.matches('!').count() >= 3 {
        insert_token(tokens, "meta:many_exclamations".into());
    }
    if lower.contains("unsubscribe") {
        insert_token(tokens, "meta:unsubscribe".into());
    }
    if lower.contains("password") {
        insert_token(tokens, "meta:password".into());
    }
    if lower.contains("gift card") || lower.contains("giftcard") {
        insert_token(tokens, "meta:gift_card".into());
    }
    if lower.contains("cryptocurrency") || lower.contains("bitcoin") {
        insert_token(tokens, "meta:cryptocurrency".into());
    }
}

fn insert_token(tokens: &mut BTreeSet<String>, token: String) {
    if tokens.len() < MAX_FEATURES && token.len() <= 160 {
        tokens.insert(token);
    }
}

fn domains_in_text(value: &str) -> Vec<String> {
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);
    let mut domains = BTreeSet::new();
    for link in finder.links(value).take(128) {
        if let Ok(url) = Url::parse(link.as_str()) {
            if let Some(host) = url.host_str() {
                domains.insert(host.to_lowercase());
            }
        }
    }
    domains.into_iter().collect()
}

fn fisher_score(probabilities: &[(String, f64)]) -> f64 {
    if probabilities.is_empty() {
        return 0.5;
    }
    let spam_product = probabilities
        .iter()
        .map(|(_, probability)| probability.ln())
        .sum::<f64>();
    let ham_product = probabilities
        .iter()
        .map(|(_, probability)| (1.0 - probability).ln())
        .sum::<f64>();
    let degrees = probabilities.len() * 2;
    let spam_likelihood = chi_squared_survival(-2.0 * spam_product, degrees);
    let ham_likelihood = chi_squared_survival(-2.0 * ham_product, degrees);
    ((spam_likelihood - ham_likelihood + 1.0) / 2.0).clamp(0.0, 1.0)
}

fn chi_squared_survival(value: f64, degrees_of_freedom: usize) -> f64 {
    debug_assert_eq!(degrees_of_freedom % 2, 0);
    let half = value.max(0.0) / 2.0;
    let terms = degrees_of_freedom / 2;
    let mut term = (-half).exp();
    let mut sum = term;
    for index in 1..terms {
        term *= half / index as f64;
        sum += term;
    }
    sum.clamp(0.0, 1.0)
}

fn validate_seed_corpus(corpus: &SeedCorpus) -> Result<()> {
    if corpus.license != "CC0-1.0" || corpus.description.trim().is_empty() {
        return Err(BackendError::InvalidInput(
            "bundled spam seed corpus is missing its CC0 declaration".into(),
        ));
    }
    let mut spam = 0usize;
    let mut ham = 0usize;
    let mut categories: HashMap<(&str, &str), usize> = HashMap::new();
    for message in &corpus.messages {
        match message.label.as_str() {
            "spam" => spam += 1,
            "ham" => ham += 1,
            _ => {
                return Err(BackendError::InvalidInput(
                    "bundled spam seed corpus contains an invalid label".into(),
                ))
            }
        }
        if message.category.trim().is_empty()
            || message.from.trim().is_empty()
            || message.subject.trim().is_empty()
            || message.body.trim().is_empty()
        {
            return Err(BackendError::InvalidInput(
                "bundled spam seed corpus contains an incomplete message".into(),
            ));
        }
        let sender_domain = message
            .from
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .ok_or_else(|| {
                BackendError::InvalidInput(
                    "bundled spam seed corpus contains an invalid sender".into(),
                )
            })?;
        if sender_domain != "example.com" && !sender_domain.ends_with(".example") {
            return Err(BackendError::InvalidInput(
                "bundled spam seed corpus must use reserved example domains".into(),
            ));
        }
        *categories
            .entry((message.label.as_str(), message.category.as_str()))
            .or_default() += 1;
    }
    if spam < 500
        || ham < 500
        || categories.len() < 20
        || categories.values().any(|count| *count < 50)
    {
        return Err(BackendError::InvalidInput(
            "bundled spam seed corpus is too small or insufficiently varied".into(),
        ));
    }
    Ok(())
}

fn parse_seed_corpus(value: &str) -> Result<SeedCorpus> {
    let mut license = None;
    let mut description = Vec::new();
    let mut messages = Vec::new();
    for (line_number, line) in value.lines().enumerate() {
        if let Some(comment) = line.strip_prefix('#') {
            let comment = comment.trim();
            if let Some(value) = comment.strip_prefix("SPDX-License-Identifier:") {
                license = Some(value.trim().to_owned());
            } else if !comment.is_empty() {
                description.push(comment.to_owned());
            }
            continue;
        }
        if line.trim().is_empty() || line == "label\tcategory\tfrom\tsubject\tbody" {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(BackendError::InvalidInput(format!(
                "bundled spam seed corpus line {} does not have five TSV fields",
                line_number + 1
            )));
        }
        messages.push(SeedMessage {
            label: fields[0].to_owned(),
            category: fields[1].to_owned(),
            from: fields[2].to_owned(),
            subject: fields[3].to_owned(),
            body: fields[4].to_owned(),
        });
    }
    Ok(SeedCorpus {
        license: license.unwrap_or_default(),
        description: description.join(" "),
        messages,
    })
}

fn local_verdict_text(verdict: LocalSpamVerdict) -> &'static str {
    match verdict {
        LocalSpamVerdict::Spam => "spam",
        LocalSpamVerdict::NotSpam => "not_spam",
        LocalSpamVerdict::Uncertain => "uncertain",
    }
}

fn parse_local_verdict(value: &str) -> Result<LocalSpamVerdict> {
    match value {
        "spam" => Ok(LocalSpamVerdict::Spam),
        "not_spam" => Ok(LocalSpamVerdict::NotSpam),
        "uncertain" => Ok(LocalSpamVerdict::Uncertain),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid local spam verdict".into(),
        )),
    }
}

fn user_classification_text(classification: UserClassification) -> &'static str {
    match classification {
        UserClassification::Spam => "spam",
        UserClassification::NotSpam => "not_spam",
    }
}

fn parse_user_classification(value: &str) -> Result<UserClassification> {
    match value {
        "spam" => Ok(UserClassification::Spam),
        "not_spam" => Ok(UserClassification::NotSpam),
        _ => Err(BackendError::InvalidInput(
            "database contains invalid user spam training label".into(),
        )),
    }
}

fn parse_message_id(value: String) -> Result<MessageId> {
    MessageId::from_str(&value)
        .map_err(|_| BackendError::InvalidInput("database contains invalid message ID".into()))
}

fn database_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| BackendError::InvalidInput(format!("database contains invalid {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_corpus_is_balanced_varied_and_cc0() {
        let corpus = parse_seed_corpus(SEED_CORPUS).unwrap();
        validate_seed_corpus(&corpus).unwrap();
        assert_eq!(corpus.license, "CC0-1.0");
        assert_eq!(corpus.messages.len(), 1_000);
        assert!(corpus
            .messages
            .iter()
            .any(|message| { message.label == "ham" && message.category == "account_security" }));
        assert!(corpus
            .messages
            .iter()
            .any(|message| { message.label == "ham" && message.category == "freelance_payments" }));
        assert!(corpus
            .messages
            .iter()
            .any(|message| message.label == "spam" && message.category == "credential_phishing"));
    }

    #[test]
    fn tokenizer_is_bounded_deduplicated_and_field_aware() {
        let features = MessageFeatures {
            from: Some("sender@Example.COM".into()),
            subject: Some("Password reset".into()),
            body: "gift card gift card ".repeat(5_000),
            html: None,
            attachment_names: "invoice.PDF payload.EXE".into(),
            link_domains: vec!["login.example".into()],
        };
        let tokens = tokenize(&features);
        assert!(tokens.len() <= MAX_FEATURES);
        assert!(tokens.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(tokens.contains(&"from:example.com".into()));
        assert!(tokens.contains(&"s:password".into()));
        assert!(tokens.contains(&"meta:gift_card".into()));
        assert!(tokens.contains(&"url:login.example".into()));
        assert!(tokens.contains(&"attachment:.exe".into()));
    }

    #[test]
    fn html_only_messages_use_bounded_visible_text() {
        let features = MessageFeatures {
            from: Some("sender@example.com".into()),
            subject: Some("Notice".into()),
            body: String::new(),
            html: Some("<html><body><p>Buy secret gift cards immediately</p></body></html>".into()),
            attachment_names: String::new(),
            link_domains: Vec::new(),
        };
        let tokens = tokenize(&features);
        assert!(tokens.contains(&"w:gift".into()));
        assert!(tokens.contains(&"b:gift_cards".into()));
        assert!(!tokens.contains(&"w:body".into()));
    }

    #[test]
    fn fisher_combination_moves_in_the_expected_direction() {
        let spam = vec![("a".into(), 0.95), ("b".into(), 0.90), ("c".into(), 0.85)];
        let ham = vec![("a".into(), 0.05), ("b".into(), 0.10), ("c".into(), 0.15)];
        assert!(fisher_score(&spam) > 0.9);
        assert!(fisher_score(&ham) < 0.1);
        assert_eq!(fisher_score(&[]), 0.5);
    }
}
