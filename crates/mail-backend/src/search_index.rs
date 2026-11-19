use crate::{BackendError, QueryExpr, QueryParseError, QueryTerm, Result};
use chrono::{Duration, NaiveDate};
use serde::{Deserialize, Serialize};
use std::fs;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tantivy::collector::sort_key::{SortByStaticFastValue, SortByString};
use tantivy::collector::TopDocs;
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, QueryParser, RangeQuery, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::{Index, IndexReader, IndexWriter, Order, ReloadPolicy, TantivyDocument, Term};

const INDEX_FORMAT_VERSION: u32 = 1;
const INDEX_WRITER_THREADS: usize = 4;
const INDEX_WRITER_MEMORY_BYTES: usize = 256 * 1024 * 1024;
const INDEX_DIRECTORY: &str = "search-index";
const INDEX_MANIFEST: &str = "search-index.json";

#[derive(Clone, Debug)]
pub(crate) struct SearchDocument {
    pub id: String,
    pub subject: Option<String>,
    pub body_text: String,
    pub from_address: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub list_id: Option<String>,
    pub attachment_names: String,
    pub rfc_message_id: Option<String>,
    pub received_at: i64,
    pub size_bytes: i64,
    pub has_attachment: bool,
    pub is_read: bool,
    pub is_starred: bool,
    pub inbox_class: String,
    pub folder_lookups: Vec<String>,
    pub account_lookups: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct QueuedSearchDocument {
    pub revision: i64,
    pub document: SearchDocument,
}

#[derive(Serialize, Deserialize)]
struct IndexManifest {
    format_version: u32,
    database_generation: String,
}

struct Fields {
    id: Field,
    subject: Field,
    body_text: Field,
    from_address: Field,
    to_address: Field,
    cc_address: Field,
    bcc_address: Field,
    delivered_to_address: Field,
    list_id: Field,
    attachment_names: Field,
    rfc_message_id: Field,
    received_at: Field,
    size_bytes: Field,
    has_attachment: Field,
    is_read: Field,
    is_starred: Field,
    inbox_class: Field,
    folder_lookup: Field,
    account_lookup: Field,
}

pub(crate) struct SearchIndex {
    profile_dir: PathBuf,
    index: Index,
    reader: IndexReader,
    writer: Mutex<IndexWriter<TantivyDocument>>,
    fields: Fields,
}

impl SearchIndex {
    pub(crate) fn open(profile_dir: &Path, database_generation: &str) -> Result<Self> {
        let manifest_path = profile_dir.join(INDEX_MANIFEST);
        let manifest: IndexManifest =
            serde_json::from_str(&fs::read_to_string(&manifest_path).map_err(|source| {
                BackendError::Io {
                    path: manifest_path.clone(),
                    source,
                }
            })?)?;
        if manifest.format_version != INDEX_FORMAT_VERSION
            || manifest.database_generation != database_generation
        {
            return Err(BackendError::SearchIndex(
                "search index manifest does not match the database".into(),
            ));
        }
        let index_path = profile_dir.join(INDEX_DIRECTORY);
        let index = Index::open_in_dir(&index_path).map_err(search_error)?;
        let (schema, fields) = schema_and_fields();
        if index.schema() != schema {
            return Err(BackendError::SearchIndex(
                "search index schema version is incompatible".into(),
            ));
        }
        Self::from_index(profile_dir.to_owned(), index, fields)
    }

    pub(crate) fn create(profile_dir: &Path) -> Result<Self> {
        let index_path = profile_dir.join(INDEX_DIRECTORY);
        if index_path.exists() {
            fs::remove_dir_all(&index_path).map_err(|source| BackendError::Io {
                path: index_path.clone(),
                source,
            })?;
        }
        let manifest_path = profile_dir.join(INDEX_MANIFEST);
        if manifest_path.exists() {
            fs::remove_file(&manifest_path).map_err(|source| BackendError::Io {
                path: manifest_path,
                source,
            })?;
        }
        fs::create_dir_all(&index_path)
            .map_err(|source| crate::error::io_error(index_path.clone(), source))?;
        let (schema, fields) = schema_and_fields();
        let index = Index::create_in_dir(&index_path, schema).map_err(search_error)?;
        Self::from_index(profile_dir.to_owned(), index, fields)
    }

    /// A worker-side placeholder which deliberately never touches the shared
    /// on-disk Tantivy directory.  Isolated synchronization leaves durable
    /// queue rows for the supervising backend to publish after the worker
    /// exits, avoiding a second cross-process index writer.
    pub(crate) fn create_deferred(profile_dir: &Path) -> Result<Self> {
        let (schema, fields) = schema_and_fields();
        let index = Index::create_in_ram(schema);
        Self::from_index_with_limits(profile_dir.to_owned(), index, fields, 1, 16 * 1024 * 1024)
    }

    fn from_index(profile_dir: PathBuf, index: Index, fields: Fields) -> Result<Self> {
        Self::from_index_with_limits(
            profile_dir,
            index,
            fields,
            INDEX_WRITER_THREADS,
            INDEX_WRITER_MEMORY_BYTES,
        )
    }

    fn from_index_with_limits(
        profile_dir: PathBuf,
        index: Index,
        fields: Fields,
        writer_threads: usize,
        writer_memory_bytes: usize,
    ) -> Result<Self> {
        let writer = index
            .writer_with_num_threads::<TantivyDocument>(writer_threads, writer_memory_bytes)
            .map_err(search_error)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(search_error)?;
        Ok(Self {
            profile_dir,
            index,
            reader,
            writer: Mutex::new(writer),
            fields,
        })
    }

    pub(crate) fn write_manifest(&self, database_generation: &str) -> Result<()> {
        let manifest_path = self.profile_dir.join(INDEX_MANIFEST);
        let temporary_path = self.profile_dir.join(format!("{INDEX_MANIFEST}.new"));
        let contents = serde_json::to_vec_pretty(&IndexManifest {
            format_version: INDEX_FORMAT_VERSION,
            database_generation: database_generation.to_owned(),
        })?;
        fs::write(&temporary_path, contents)
            .map_err(|source| crate::error::io_error(temporary_path.clone(), source))?;
        fs::rename(&temporary_path, &manifest_path)
            .map_err(|source| crate::error::io_error(manifest_path, source))?;
        Ok(())
    }

    pub(crate) fn replace_documents(&self, documents: Vec<SearchDocument>) -> Result<()> {
        if documents.is_empty() {
            return Ok(());
        }
        let mut writer = self.writer.lock().map_err(|_| {
            BackendError::SearchIndex("search index writer lock was poisoned".into())
        })?;
        let result = (|| {
            for document in documents {
                writer.delete_term(Term::from_field_text(self.fields.id, &document.id));
                writer
                    .add_document(self.tantivy_document(document))
                    .map_err(search_error)?;
            }
            writer.commit().map_err(search_error)?;
            self.reader.reload().map_err(search_error)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = writer.rollback();
        }
        result
    }

    pub(crate) fn delete_documents(&self, message_ids: Vec<String>) -> Result<()> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let mut writer = self.writer.lock().map_err(|_| {
            BackendError::SearchIndex("search index writer lock was poisoned".into())
        })?;
        let result = (|| {
            for message_id in message_ids {
                writer.delete_term(Term::from_field_text(self.fields.id, &message_id));
            }
            writer.commit().map_err(search_error)?;
            self.reader.reload().map_err(search_error)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = writer.rollback();
        }
        result
    }

    /// Rewrite every segment containing deleted documents, then unlink the
    /// obsolete segment files. Tantivy normally reclaims these lazily, but
    /// callers use this synchronous path when a user disables encrypted-mail
    /// search and asks us to discard the decrypted search projection now.
    pub(crate) fn expunge_deleted_documents(&self) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| {
            BackendError::SearchIndex("search index writer lock was poisoned".into())
        })?;
        let segment_ids = self
            .index
            .searchable_segment_metas()
            .map_err(search_error)?
            .into_iter()
            .filter(|segment| segment.num_deleted_docs() > 0)
            .map(|segment| segment.id())
            .collect::<Vec<_>>();
        if !segment_ids.is_empty() {
            writer.merge(&segment_ids).wait().map_err(search_error)?;
            self.reader.reload().map_err(search_error)?;
        }
        writer
            .garbage_collect_files()
            .wait()
            .map_err(search_error)?;
        Ok(())
    }

    pub(crate) fn num_docs(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub(crate) fn search(
        &self,
        expression: &QueryExpr,
        cursor: Option<(i64, &str)>,
        limit: usize,
        now: i64,
    ) -> Result<Vec<String>> {
        let mut query = self.compile(expression, now)?;
        if let Some((received_at, id)) = cursor {
            query = Box::new(BooleanQuery::intersection(vec![
                query,
                self.cursor_query(received_at, id),
            ]));
        }
        let collector = TopDocs::with_limit(limit).order_by((
            (
                SortByStaticFastValue::<i64>::for_field("received_at"),
                Order::Desc,
            ),
            (SortByString::for_field("id"), Order::Desc),
        ));
        let searcher = self.reader.searcher();
        let hits = searcher.search(&query, &collector).map_err(search_error)?;
        let mut ids = Vec::with_capacity(hits.len());
        for (_, address) in hits {
            let document = searcher
                .doc::<TantivyDocument>(address)
                .map_err(search_error)?;
            let id = document
                .get_first(self.fields.id)
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    BackendError::SearchIndex(
                        "search result is missing its stored message ID".into(),
                    )
                })?;
            ids.push(id.to_owned());
        }
        Ok(ids)
    }

    fn tantivy_document(&self, source: SearchDocument) -> TantivyDocument {
        let mut document = TantivyDocument::default();
        document.add_text(self.fields.id, &source.id);
        if let Some(value) = source.subject {
            document.add_text(self.fields.subject, value);
        }
        document.add_text(self.fields.body_text, source.body_text);
        add_normalized(&mut document, self.fields.from_address, source.from_address);
        add_normalized_many(&mut document, self.fields.to_address, source.to_addresses);
        add_normalized_many(&mut document, self.fields.cc_address, source.cc_addresses);
        add_normalized_many(&mut document, self.fields.bcc_address, source.bcc_addresses);
        add_normalized_many(
            &mut document,
            self.fields.delivered_to_address,
            source.delivered_to_addresses,
        );
        add_normalized(&mut document, self.fields.list_id, source.list_id);
        document.add_text(self.fields.attachment_names, source.attachment_names);
        if let Some(value) = source.rfc_message_id {
            document.add_text(self.fields.rfc_message_id, value);
        }
        document.add_i64(self.fields.received_at, source.received_at);
        document.add_i64(self.fields.size_bytes, source.size_bytes);
        document.add_bool(self.fields.has_attachment, source.has_attachment);
        document.add_bool(self.fields.is_read, source.is_read);
        document.add_bool(self.fields.is_starred, source.is_starred);
        document.add_text(self.fields.inbox_class, source.inbox_class);
        add_normalized_many(
            &mut document,
            self.fields.folder_lookup,
            source.folder_lookups,
        );
        add_normalized_many(
            &mut document,
            self.fields.account_lookup,
            source.account_lookups,
        );
        document
    }

    fn compile(&self, expression: &QueryExpr, now: i64) -> Result<Box<dyn Query>> {
        match expression {
            QueryExpr::Term(term) => self.compile_term(term, now),
            QueryExpr::And(items) => Ok(Box::new(BooleanQuery::intersection(
                items
                    .iter()
                    .map(|item| self.compile(item, now))
                    .collect::<Result<Vec<_>>>()?,
            ))),
            QueryExpr::Or(items) => Ok(Box::new(BooleanQuery::union(
                items
                    .iter()
                    .map(|item| self.compile(item, now))
                    .collect::<Result<Vec<_>>>()?,
            ))),
            QueryExpr::Not(item) => Ok(Box::new(BooleanQuery::new(vec![
                (Occur::Must, Box::new(AllQuery)),
                (Occur::MustNot, self.compile(item, now)?),
            ]))),
        }
    }

    fn compile_term(&self, term: &QueryTerm, now: i64) -> Result<Box<dyn Query>> {
        let exact = |field, value: &str| {
            Box::new(TermQuery::new(
                Term::from_field_text(field, value),
                IndexRecordOption::Basic,
            )) as Box<dyn Query>
        };
        let normalized = |field, value: &str| exact(field, &normalize(value));
        match term.field.as_deref() {
            None => self.text_query(self.fields.body_text, &term.value, term),
            Some("subject") => self.text_query(self.fields.subject, &term.value, term),
            Some("from") => self.text_query(self.fields.from_address, &term.value, term),
            Some("to") => self.text_query(self.fields.to_address, &term.value, term),
            Some("cc") => self.text_query(self.fields.cc_address, &term.value, term),
            Some("bcc") => self.text_query(self.fields.bcc_address, &term.value, term),
            Some("deliveredto") => {
                self.text_query(self.fields.delivered_to_address, &term.value, term)
            }
            Some("filename") => self.text_query(self.fields.attachment_names, &term.value, term),
            Some("list") => self.text_query(self.fields.list_id, &term.value, term),
            Some("has") if term.value.eq_ignore_ascii_case("attachment") => {
                Ok(Box::new(TermQuery::new(
                    Term::from_field_bool(self.fields.has_attachment, true),
                    IndexRecordOption::Basic,
                )))
            }
            Some("has") => Err(query_error(term, "unknown has: predicate")),
            Some("is") => {
                let value = term.value.to_ascii_lowercase();
                match value.as_str() {
                    "read" => Ok(bool_query(self.fields.is_read, true)),
                    "unread" => Ok(bool_query(self.fields.is_read, false)),
                    "starred" => Ok(bool_query(self.fields.is_starred, true)),
                    "warm" | "cold" | "spam" => Ok(exact(self.fields.inbox_class, &value)),
                    _ => Err(query_error(term, "unknown is: predicate")),
                }
            }
            Some("after" | "newer" | "before" | "older") => {
                let timestamp = parse_date(&term.value)
                    .ok_or_else(|| query_error(term, "date must use YYYY-MM-DD"))?;
                if matches!(term.field.as_deref(), Some("after" | "newer")) {
                    Ok(self.i64_range(
                        self.fields.received_at,
                        Bound::Included(timestamp),
                        Bound::Unbounded,
                    ))
                } else {
                    Ok(self.i64_range(
                        self.fields.received_at,
                        Bound::Unbounded,
                        Bound::Excluded(timestamp),
                    ))
                }
            }
            Some("older_than" | "newer_than") => {
                let duration = parse_age(&term.value)
                    .ok_or_else(|| query_error(term, "age must look like 7d, 2w, 3m, or 1y"))?;
                let threshold = now.saturating_sub(duration.num_seconds());
                if term.field.as_deref() == Some("older_than") {
                    Ok(self.i64_range(
                        self.fields.received_at,
                        Bound::Unbounded,
                        Bound::Excluded(threshold),
                    ))
                } else {
                    Ok(self.i64_range(
                        self.fields.received_at,
                        Bound::Included(threshold),
                        Bound::Unbounded,
                    ))
                }
            }
            Some("larger" | "smaller" | "size") => {
                let size = parse_size(&term.value)
                    .ok_or_else(|| query_error(term, "invalid byte size"))?;
                match term.field.as_deref() {
                    Some("larger") => Ok(self.i64_range(
                        self.fields.size_bytes,
                        Bound::Excluded(size),
                        Bound::Unbounded,
                    )),
                    Some("smaller") => Ok(self.i64_range(
                        self.fields.size_bytes,
                        Bound::Unbounded,
                        Bound::Excluded(size),
                    )),
                    _ => Ok(Box::new(TermQuery::new(
                        Term::from_field_i64(self.fields.size_bytes, size),
                        IndexRecordOption::Basic,
                    ))),
                }
            }
            Some("in" | "label") => Ok(normalized(self.fields.folder_lookup, &term.value)),
            Some("account") => Ok(normalized(self.fields.account_lookup, &term.value)),
            Some("rfc822msgid" | "message-id") => Ok(exact(
                self.fields.rfc_message_id,
                term.value.trim_matches(['<', '>']),
            )),
            Some(other) => Err(query_error(
                term,
                format!("unknown search operator {other}:"),
            )),
        }
    }

    fn text_query(&self, field: Field, value: &str, term: &QueryTerm) -> Result<Box<dyn Query>> {
        let parser = QueryParser::for_index(&self.index, vec![field]);
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        parser
            .parse_query(&format!("\"{escaped}\""))
            .map_err(|error| query_error(term, error.to_string()))
    }

    fn i64_range(&self, field: Field, lower: Bound<i64>, upper: Bound<i64>) -> Box<dyn Query> {
        Box::new(RangeQuery::new(
            lower.map(|value| Term::from_field_i64(field, value)),
            upper.map(|value| Term::from_field_i64(field, value)),
        ))
    }

    fn cursor_query(&self, received_at: i64, id: &str) -> Box<dyn Query> {
        let older = self.i64_range(
            self.fields.received_at,
            Bound::Unbounded,
            Bound::Excluded(received_at),
        );
        let same_time_lower_id = Box::new(BooleanQuery::intersection(vec![
            Box::new(TermQuery::new(
                Term::from_field_i64(self.fields.received_at, received_at),
                IndexRecordOption::Basic,
            )),
            Box::new(RangeQuery::new(
                Bound::Unbounded,
                Bound::Excluded(Term::from_field_text(self.fields.id, id)),
            )),
        ]));
        Box::new(BooleanQuery::union(vec![older, same_time_lower_id]))
    }
}

fn schema_and_fields() -> (Schema, Fields) {
    let mut schema = Schema::builder();
    let id = schema.add_text_field("id", STRING | STORED | FAST);
    let subject = schema.add_text_field("subject", TEXT);
    let body_text = schema.add_text_field("body_text", TEXT);
    let from_address = schema.add_text_field("from_address", TEXT);
    let to_address = schema.add_text_field("to_address", TEXT);
    let cc_address = schema.add_text_field("cc_address", TEXT);
    let bcc_address = schema.add_text_field("bcc_address", TEXT);
    let delivered_to_address = schema.add_text_field("delivered_to_address", TEXT);
    let list_id = schema.add_text_field("list_id", TEXT);
    let attachment_names = schema.add_text_field("attachment_names", TEXT);
    let rfc_message_id = schema.add_text_field("rfc_message_id", STRING);
    let received_at = schema.add_i64_field("received_at", INDEXED | FAST);
    let size_bytes = schema.add_i64_field("size_bytes", INDEXED | FAST);
    let has_attachment = schema.add_bool_field("has_attachment", INDEXED);
    let is_read = schema.add_bool_field("is_read", INDEXED);
    let is_starred = schema.add_bool_field("is_starred", INDEXED);
    let inbox_class = schema.add_text_field("inbox_class", STRING);
    let folder_lookup = schema.add_text_field("folder_lookup", STRING);
    let account_lookup = schema.add_text_field("account_lookup", STRING);
    (
        schema.build(),
        Fields {
            id,
            subject,
            body_text,
            from_address,
            to_address,
            cc_address,
            bcc_address,
            delivered_to_address,
            list_id,
            attachment_names,
            rfc_message_id,
            received_at,
            size_bytes,
            has_attachment,
            is_read,
            is_starred,
            inbox_class,
            folder_lookup,
            account_lookup,
        },
    )
}

fn add_normalized(document: &mut TantivyDocument, field: Field, value: Option<String>) {
    if let Some(value) = value {
        document.add_text(field, normalize(&value));
    }
}

fn add_normalized_many(document: &mut TantivyDocument, field: Field, values: Vec<String>) {
    for value in values {
        document.add_text(field, normalize(&value));
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn bool_query(field: Field, value: bool) -> Box<dyn Query> {
    Box::new(TermQuery::new(
        Term::from_field_bool(field, value),
        IndexRecordOption::Basic,
    ))
}

fn parse_date(value: &str) -> Option<i64> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)
        .map(|date| date.and_utc().timestamp())
}

fn parse_age(value: &str) -> Option<Duration> {
    let (amount, unit) = value.split_at(value.len().checked_sub(1)?);
    let amount = amount.parse::<i64>().ok()?;
    let days = match unit.to_ascii_lowercase().as_str() {
        "d" => amount,
        "w" => amount.checked_mul(7)?,
        "m" => amount.checked_mul(30)?,
        "y" => amount.checked_mul(365)?,
        _ => return None,
    };
    Duration::try_days(days)
}

fn parse_size(value: &str) -> Option<i64> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split].parse::<i64>().ok()?;
    let multiplier = match value[split..].to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn query_error(term: &QueryTerm, message: impl Into<String>) -> BackendError {
    QueryParseError::new(message, term.start, term.end).into()
}

fn search_error(error: impl std::fmt::Display) -> BackendError {
    let detail = error.to_string();
    if crate::error::is_storage_full_message(&detail) {
        crate::error::storage_full_unknown()
    } else {
        BackendError::SearchIndex(detail)
    }
}
