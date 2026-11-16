//! Compare Turso's embedded FTS index with an external native Tantivy index.
//!
//! Both engines store the same normalized message rows in Turso. The only
//! difference is whether Turso maintains the search index itself or the
//! benchmark publishes the same document to a separate Tantivy `IndexWriter`.
//! Corpus generation is deliberately excluded from ingestion timings.

use serde::Serialize;
use std::ops::Bound;
use std::path::Path;
use std::time::{Duration, Instant};
use tantivy::collector::TopDocs;
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, QueryParser, RangeQuery, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::{doc, Index, IndexReader, IndexWriter, Order, ReloadPolicy, TantivyDocument, Term};

const BODY_BYTES: usize = 64 * 1024;
const BATCH_MESSAGES: usize = 1_000;
const QUERY_RUNS: usize = 31;
const RECEIVED_AT_BASE: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
const TANTIVY_THREADS: usize = 4;
const TANTIVY_MEMORY_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EngineKind {
    TursoFts,
    NativeTantivy,
}

impl EngineKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "turso-fts" => Ok(Self::TursoFts),
            "native-tantivy" => Ok(Self::NativeTantivy),
            _ => Err(format!(
                "unknown engine {value:?}; expected turso-fts or native-tantivy"
            )),
        }
    }
}

#[derive(Serialize)]
struct Report {
    engine: EngineKind,
    body_bytes_per_message: usize,
    batch_messages: usize,
    query_runs: usize,
    tantivy_writer_threads: Option<usize>,
    tantivy_memory_mib: Option<usize>,
    checkpoints: Vec<Checkpoint>,
}

#[derive(Serialize)]
struct Checkpoint {
    corpus_mib: f64,
    messages: usize,
    profile_mib: f64,
    ingest_seconds: f64,
    ingest_messages_per_second: f64,
    ingest_mib_per_second: f64,
    rss_mib: Option<f64>,
    queries: Vec<QueryTiming>,
}

#[derive(Serialize)]
struct QueryTiming {
    query: &'static str,
    first_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    returned: usize,
}

struct BenchDoc {
    id: String,
    subject: String,
    body_text: String,
    from_address: String,
    received_at: i64,
    search_metadata: String,
}

#[derive(Clone, Copy)]
enum BenchQuery {
    Rare,
    Common,
    Intersection,
    Subject,
    Sender,
    CommonAfter,
    NegativeSubject,
}

impl BenchQuery {
    const ALL: [Self; 7] = [
        Self::Rare,
        Self::Common,
        Self::Intersection,
        Self::Subject,
        Self::Sender,
        Self::CommonAfter,
        Self::NegativeSubject,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Rare => "unique00000013",
            Self::Common => "project",
            Self::Intersection => "alpha AND beta",
            Self::Subject => "subject:topic7",
            Self::Sender => "from:user13@example.com",
            Self::CommonAfter => "project AND after:2026-01-01",
            Self::NegativeSubject => "-subject:missing",
        }
    }

    fn turso_query(self) -> Option<&'static str> {
        match self {
            Self::Rare => Some("\"unique00000013\""),
            Self::Common | Self::CommonAfter => Some("\"project\""),
            Self::Intersection => Some("\"alpha\" AND \"beta\""),
            Self::Subject => Some("subject:\"topic7\""),
            Self::Sender => Some("from_address:\"user13@example.com\""),
            Self::NegativeSubject => None,
        }
    }
}

struct MetadataStore {
    _database: turso::Database,
    connection: turso::Connection,
}

impl MetadataStore {
    async fn open(path: &Path, embedded_fts: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let database = turso::Builder::new_local(path.to_str().ok_or("non-UTF-8 database path")?)
            .experimental_index_method(true)
            .build()
            .await?;
        let connection = database.connect()?;
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = ON;
                CREATE TABLE docs (
                    id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    body_text TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    search_metadata TEXT NOT NULL
                );
                CREATE INDEX docs_received ON docs(received_at DESC, id DESC);
                CREATE TEMP TABLE doc_stage (
                    position INTEGER PRIMARY KEY,
                    id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    body_text TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    search_metadata TEXT NOT NULL
                );
                "#,
            )
            .await?;
        if embedded_fts {
            connection
                .execute(
                    "CREATE INDEX docs_fts ON docs USING fts (subject, body_text, from_address, search_metadata) WITH (json_fields = 'search_metadata')",
                    (),
                )
                .await?;
        }
        Ok(Self {
            _database: database,
            connection,
        })
    }

    async fn insert_batch(&mut self, docs: &[BenchDoc]) -> Result<(), Box<dyn std::error::Error>> {
        let transaction = self.connection.transaction().await?;
        transaction.execute("DELETE FROM doc_stage", ()).await?;
        for (position, item) in docs.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO doc_stage(position, id, subject, body_text, from_address, received_at, search_metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    turso::params![
                        position as i64,
                        item.id.clone(),
                        item.subject.clone(),
                        item.body_text.clone(),
                        item.from_address.clone(),
                        item.received_at,
                        item.search_metadata.clone(),
                    ],
                )
                .await?;
        }
        transaction
            .execute(
                "INSERT INTO docs(id, subject, body_text, from_address, received_at, search_metadata) SELECT id, subject, body_text, from_address, received_at, search_metadata FROM doc_stage ORDER BY position",
                (),
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn turso_search(
        &self,
        query: BenchQuery,
        messages: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let oldest = RECEIVED_AT_BASE;
        let newest = RECEIVED_AT_BASE + messages as i64 - 1;
        let mut upper = newest;
        let mut window_seconds = 60_i64;
        let mut found = 0_usize;

        loop {
            let lower = upper
                .saturating_sub(window_seconds.saturating_sub(1))
                .max(oldest);
            let needed = 20 - found;
            let mut rows = if query.turso_query().is_some() {
                let fts = format!(
                    "({}) AND search_metadata.received_at:[{lower} TO {upper}]",
                    query.turso_query().expect("checked above")
                );
                self.connection
                    .query(
                        "SELECT id FROM docs WHERE (subject, body_text, from_address) MATCH ?1 AND received_at >= ?2 AND received_at <= ?3 AND (?4 = 0 OR received_at >= ?5) ORDER BY received_at DESC, id DESC LIMIT ?6",
                        turso::params![
                            fts,
                            lower,
                            upper,
                            i64::from(matches!(query, BenchQuery::CommonAfter)),
                            RECEIVED_AT_BASE,
                            needed as i64,
                        ],
                    )
                    .await?
            } else {
                let excluded = format!(
                    "subject:\"missing\" AND search_metadata.received_at:[{lower} TO {upper}]"
                );
                self.connection
                    .query(
                        "SELECT id FROM docs WHERE received_at >= ?1 AND received_at <= ?2 AND id NOT IN (SELECT id FROM docs WHERE (subject, body_text, from_address) MATCH ?3) ORDER BY received_at DESC, id DESC LIMIT ?4",
                        turso::params![lower, upper, excluded, needed as i64],
                    )
                    .await?
            };
            while rows.next().await?.is_some() {
                found += 1;
            }
            drop(rows);
            if found >= 20 || lower == oldest {
                return Ok(found);
            }
            upper = lower.saturating_sub(1);
            window_seconds = window_seconds.saturating_mul(2);
        }
    }
}

struct TantivyFields {
    id: Field,
    subject: Field,
    body_text: Field,
    from_address: Field,
    received_at: Field,
}

struct NativeSearch {
    index: Index,
    writer: IndexWriter<TantivyDocument>,
    reader: IndexReader,
    fields: TantivyFields,
}

impl NativeSearch {
    fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(path)?;
        let mut schema = Schema::builder();
        let id = schema.add_text_field("id", STRING | STORED);
        let subject = schema.add_text_field("subject", TEXT);
        let body_text = schema.add_text_field("body_text", TEXT);
        let from_address = schema.add_text_field("from_address", STRING);
        let received_at = schema.add_i64_field("received_at", FAST | INDEXED);
        let schema = schema.build();
        let index = Index::create_in_dir(path, schema)?;
        let writer = index
            .writer_with_num_threads::<TantivyDocument>(TANTIVY_THREADS, TANTIVY_MEMORY_BYTES)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        Ok(Self {
            index,
            writer,
            reader,
            fields: TantivyFields {
                id,
                subject,
                body_text,
                from_address,
                received_at,
            },
        })
    }

    fn insert_batch(&mut self, docs: &[BenchDoc]) -> Result<(), Box<dyn std::error::Error>> {
        for item in docs {
            self.writer.add_document(doc!(
                self.fields.id => item.id.as_str(),
                self.fields.subject => item.subject.as_str(),
                self.fields.body_text => item.body_text.as_str(),
                self.fields.from_address => item.from_address.as_str(),
                self.fields.received_at => item.received_at,
            ))?;
        }
        self.writer.commit()?;
        Ok(())
    }

    fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.reader.reload()?;
        Ok(())
    }

    fn search(&self, query: BenchQuery) -> Result<usize, Box<dyn std::error::Error>> {
        let parsed = self.query(query)?;
        let collector =
            TopDocs::with_limit(20).order_by_fast_field::<i64>("received_at", Order::Desc);
        let searcher = self.reader.searcher();
        let hits = searcher.search(&parsed, &collector)?;
        for (_, address) in &hits {
            let document = searcher.doc::<TantivyDocument>(*address)?;
            let _id = document
                .get_first(self.fields.id)
                .and_then(|value| value.as_str())
                .ok_or("Tantivy result missing stored message ID")?;
        }
        Ok(hits.len())
    }

    fn query(&self, query: BenchQuery) -> Result<Box<dyn Query>, Box<dyn std::error::Error>> {
        let parser = QueryParser::for_index(&self.index, vec![self.fields.body_text]);
        let result: Box<dyn Query> = match query {
            BenchQuery::Rare => parser.parse_query("unique00000013")?,
            BenchQuery::Common => parser.parse_query("project")?,
            BenchQuery::Intersection => parser.parse_query("alpha AND beta")?,
            BenchQuery::Subject => parser.parse_query("subject:topic7")?,
            BenchQuery::Sender => Box::new(TermQuery::new(
                Term::from_field_text(self.fields.from_address, "user13@example.com"),
                IndexRecordOption::Basic,
            )),
            BenchQuery::CommonAfter => Box::new(BooleanQuery::intersection(vec![
                parser.parse_query("project")?,
                Box::new(RangeQuery::new(
                    Bound::Included(Term::from_field_i64(
                        self.fields.received_at,
                        RECEIVED_AT_BASE,
                    )),
                    Bound::Unbounded,
                )),
            ])),
            BenchQuery::NegativeSubject => Box::new(BooleanQuery::new(vec![
                (Occur::Must, Box::new(AllQuery)),
                (
                    Occur::MustNot,
                    Box::new(TermQuery::new(
                        Term::from_field_text(self.fields.subject, "missing"),
                        IndexRecordOption::Basic,
                    )),
                ),
            ])),
        };
        Ok(result)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let engine = EngineKind::parse(args.next().as_deref().unwrap_or(""))?;
    let checkpoints = args
        .next()
        .unwrap_or_else(|| "128,256,512,1024".into())
        .split(',')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    if checkpoints.is_empty() || !checkpoints.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("checkpoints must be a non-empty increasing MiB list".into());
    }

    let profile = tempfile::tempdir()?;
    let embedded_fts = matches!(engine, EngineKind::TursoFts);
    let mut metadata =
        MetadataStore::open(&profile.path().join("metadata.db"), embedded_fts).await?;
    let mut native = if matches!(engine, EngineKind::NativeTantivy) {
        Some(NativeSearch::open(&profile.path().join("tantivy"))?)
    } else {
        None
    };
    let mut messages = 0_usize;
    let mut corpus_bytes = 0_u64;
    let mut ingest_elapsed = Duration::ZERO;
    let mut results = Vec::new();

    for target_mib in checkpoints {
        let target_bytes = target_mib * 1024 * 1024;
        while corpus_bytes < target_bytes {
            let remaining_messages = ((target_bytes - corpus_bytes) as usize / BODY_BYTES).max(1);
            let batch_len = remaining_messages.min(BATCH_MESSAGES);
            let docs = (messages..messages + batch_len)
                .map(generated_doc)
                .collect::<Vec<_>>();
            let started = Instant::now();
            metadata.insert_batch(&docs).await?;
            if let Some(native) = &mut native {
                native.insert_batch(&docs)?;
            }
            ingest_elapsed += started.elapsed();
            messages += batch_len;
            corpus_bytes += (batch_len * BODY_BYTES) as u64;
        }
        if let Some(native) = &native {
            native.reload()?;
        }
        let queries = benchmark_queries(engine, &metadata, native.as_ref(), messages).await?;
        let elapsed = ingest_elapsed.as_secs_f64();
        let checkpoint = Checkpoint {
            corpus_mib: corpus_bytes as f64 / 1_048_576.0,
            messages,
            profile_mib: directory_bytes(profile.path())? as f64 / 1_048_576.0,
            ingest_seconds: elapsed,
            ingest_messages_per_second: messages as f64 / elapsed,
            ingest_mib_per_second: corpus_bytes as f64 / 1_048_576.0 / elapsed,
            rss_mib: resident_set_mib(),
            queries,
        };
        eprintln!(
            "engine={} checkpoint={target_mib}MiB messages={messages} elapsed={elapsed:.2}s",
            if embedded_fts {
                "turso-fts"
            } else {
                "native-tantivy"
            }
        );
        results.push(checkpoint);
    }

    let report = Report {
        engine,
        body_bytes_per_message: BODY_BYTES,
        batch_messages: BATCH_MESSAGES,
        query_runs: QUERY_RUNS,
        tantivy_writer_threads: native.as_ref().map(|_| TANTIVY_THREADS),
        tantivy_memory_mib: native.as_ref().map(|_| TANTIVY_MEMORY_BYTES / 1_048_576),
        checkpoints: results,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn benchmark_queries(
    engine: EngineKind,
    metadata: &MetadataStore,
    native: Option<&NativeSearch>,
    messages: usize,
) -> Result<Vec<QueryTiming>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    for query in BenchQuery::ALL {
        let first_started = Instant::now();
        let first = run_query(engine, metadata, native, query, messages).await?;
        let first_ms = first_started.elapsed().as_secs_f64() * 1_000.0;
        let mut samples = Vec::with_capacity(QUERY_RUNS);
        for _ in 0..QUERY_RUNS {
            let started = Instant::now();
            let result = run_query(engine, metadata, native, query, messages).await?;
            assert_eq!(result, first, "unstable result page for {}", query.label());
            samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        }
        samples.sort_by(f64::total_cmp);
        output.push(QueryTiming {
            query: query.label(),
            first_ms,
            p50_ms: percentile(&samples, 0.50),
            p95_ms: percentile(&samples, 0.95),
            p99_ms: percentile(&samples, 0.99),
            returned: first,
        });
    }
    Ok(output)
}

async fn run_query(
    engine: EngineKind,
    metadata: &MetadataStore,
    native: Option<&NativeSearch>,
    query: BenchQuery,
    messages: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    match engine {
        EngineKind::TursoFts => metadata.turso_search(query, messages).await,
        EngineKind::NativeTantivy => native.expect("native engine initialized").search(query),
    }
}

fn generated_doc(index: usize) -> BenchDoc {
    let topic = index % 32;
    let sender = index % 1_000;
    let mut body = String::with_capacity(BODY_BYTES + 64);
    body.push_str(if index.is_multiple_of(5) {
        "project alpha beta "
    } else if index.is_multiple_of(2) {
        "project alpha "
    } else {
        "project gamma "
    });
    body.push_str(&format!("unique{index:08} "));
    let mut state = index as u64 ^ 0x9e37_79b9_7f4a_7c15;
    while body.len() < BODY_BYTES {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        body.push_str(&format!("word{:04} ", state % 2_048));
    }
    body.truncate(BODY_BYTES);
    let received_at = RECEIVED_AT_BASE + index as i64;
    BenchDoc {
        id: format!("message-{index:08}"),
        subject: format!("topic{topic} benchmark message {index}"),
        body_text: body,
        from_address: format!("user{sender}@example.com"),
        received_at,
        search_metadata: format!(r#"{{"received_at":{received_at}}}"#),
    }
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    let index = ((samples.len() - 1) as f64 * quantile).ceil() as usize;
    samples[index]
}

fn directory_bytes(path: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += directory_bytes(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}

fn resident_set_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<f64>().ok()?;
    Some(kib / 1024.0)
}
