use lizard_mail_backend::{Backend, BackendConfig, IngestMessage, SearchRequest};
use serde::Serialize;
use std::time::{Duration, Instant};

const MESSAGE_BODY_BYTES: usize = 64 * 1024;
const INGEST_BATCH_MESSAGES: usize = 1_000;
const QUERY_RUNS: usize = 31;

#[derive(Serialize)]
struct Checkpoint {
    target_mib: u64,
    raw_mib: f64,
    messages: usize,
    profile_mib: f64,
    ingest_messages_per_second: f64,
    ingest_mib_per_second: f64,
    rss_mib: Option<f64>,
    queries: Vec<QueryTiming>,
}

#[derive(Serialize)]
struct QueryTiming {
    query: String,
    first_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    returned: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let checkpoints = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "8,16,32,64,128".into())
        .split(',')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    if checkpoints.is_empty() || !checkpoints.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("checkpoints must be a non-empty, increasing comma-separated MiB list".into());
    }

    let profile = tempfile::tempdir()?;
    let backend = Backend::open(BackendConfig::new(profile.path())).await?;
    let mut ingest_elapsed = Duration::ZERO;
    let mut raw_bytes = 0_u64;
    let mut messages = 0_usize;
    let mut results = Vec::new();

    for target_mib in checkpoints {
        let target_bytes = target_mib * 1024 * 1024;
        while raw_bytes < target_bytes {
            let mut requests = Vec::with_capacity(INGEST_BATCH_MESSAGES);
            while raw_bytes < target_bytes && requests.len() < INGEST_BATCH_MESSAGES {
                let index = messages + requests.len();
                let raw = generated_message(index, MESSAGE_BODY_BYTES);
                raw_bytes += raw.len() as u64;
                requests.push(IngestMessage {
                    raw,
                    remote: None,
                    received_at: Some(1_767_225_600 + index as i64),
                    user_classification: None,
                });
            }
            let batch_len = requests.len();
            let started = Instant::now();
            backend.ingest_batch(requests).await?;
            ingest_elapsed += started.elapsed();
            messages += batch_len;
        }

        let elapsed = ingest_elapsed.as_secs_f64();
        let queries = benchmark_queries(&backend).await?;
        let checkpoint = Checkpoint {
            target_mib,
            raw_mib: raw_bytes as f64 / 1_048_576.0,
            messages,
            profile_mib: directory_bytes(profile.path())? as f64 / 1_048_576.0,
            ingest_messages_per_second: messages as f64 / elapsed,
            ingest_mib_per_second: raw_bytes as f64 / 1_048_576.0 / elapsed,
            rss_mib: resident_set_mib(),
            queries,
        };
        eprintln!(
            "checkpoint={}MiB messages={} elapsed={elapsed:.2}s",
            target_mib, messages
        );
        results.push(checkpoint);
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

async fn benchmark_queries(
    backend: &Backend,
) -> Result<Vec<QueryTiming>, Box<dyn std::error::Error>> {
    let queries = [
        "unique00000013",
        "project",
        "alpha AND beta",
        "subject:topic7",
        "from:user13@example.com",
        "project AND after:2026-01-01",
        "-subject:missing",
    ];
    let mut output = Vec::new();
    for query in queries {
        let first_started = Instant::now();
        let first = run_query(backend, query).await?;
        let first_ms = first_started.elapsed().as_secs_f64() * 1_000.0;
        let mut samples = Vec::with_capacity(QUERY_RUNS);
        for _ in 0..QUERY_RUNS {
            let started = Instant::now();
            let result = run_query(backend, query).await?;
            assert_eq!(result, first, "unstable result page for {query}");
            samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        }
        samples.sort_by(f64::total_cmp);
        output.push(QueryTiming {
            query: query.into(),
            first_ms,
            p50_ms: percentile(&samples, 0.50),
            p95_ms: percentile(&samples, 0.95),
            p99_ms: percentile(&samples, 0.99),
            returned: first,
        });
    }
    Ok(output)
}

async fn run_query(backend: &Backend, query: &str) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(backend
        .search()
        .search(SearchRequest {
            query: query.into(),
            page_size: 20,
            cursor: None,
        })
        .await?
        .items
        .len())
}

fn generated_message(index: usize, body_bytes: usize) -> Vec<u8> {
    let topic = index % 32;
    let sender = index % 1_000;
    let mut body = String::with_capacity(body_bytes + 256);
    body.push_str(if index.is_multiple_of(5) {
        "project alpha beta "
    } else if index.is_multiple_of(2) {
        "project alpha "
    } else {
        "project gamma "
    });
    body.push_str(&format!("unique{index:08} "));
    let mut state = index as u64 ^ 0x9e37_79b9_7f4a_7c15;
    while body.len() < body_bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        body.push_str(&format!("word{:04} ", state % 2_048));
    }
    body.truncate(body_bytes);
    format!(
        concat!(
            "From: User {sender} <user{sender}@example.com>\r\n",
            "To: reader@example.net\r\n",
            "Date: Thu, 01 Jan 2026 00:00:00 +0000\r\n",
            "Message-ID: <benchmark-{index}@example.com>\r\n",
            "Subject: topic{topic} benchmark message {index}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{body}"
        ),
        sender = sender,
        index = index,
        topic = topic,
        body = body,
    )
    .into_bytes()
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    let index = ((samples.len() - 1) as f64 * quantile).ceil() as usize;
    samples[index]
}

fn directory_bytes(path: &std::path::Path) -> std::io::Result<u64> {
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
