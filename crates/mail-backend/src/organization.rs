use crate::backend::{insert_event, not_found, parse_id};
use crate::{
    parse_query, Backend, BackendError, NewSavedSearch, Result, SavedSearch, SavedSearchId,
    SearchPage, SearchRequest,
};
use chrono::Utc;
use serde_json::json;

const MAX_SAVED_SEARCH_NAME_BYTES: usize = 256;

#[derive(Clone)]
pub struct SavedSearches(Backend);

impl SavedSearches {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn add(&self, search: NewSavedSearch) -> Result<SavedSearch> {
        validate(&search)?;
        let now = Utc::now().timestamp();
        let value = SavedSearch {
            id: SavedSearchId::new(),
            name: search.name.trim().to_owned(),
            query: search.query,
            created_at: now,
            updated_at: now,
        };
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO saved_searches(id, name, query, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    value.id.to_string(),
                    value.name.clone(),
                    value.query.clone(),
                    now,
                    now,
                ),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "saved_search_added",
            value.id.to_string(),
            json!({"saved_search_id": value.id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(value)
    }

    pub async fn update(&self, id: SavedSearchId, search: NewSavedSearch) -> Result<SavedSearch> {
        validate(&search)?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "UPDATE saved_searches SET name = ?1, query = ?2, updated_at = ?3 WHERE id = ?4",
                (
                    search.name.trim().to_owned(),
                    search.query,
                    now,
                    id.to_string(),
                ),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("saved search", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "saved_search_updated",
            id.to_string(),
            json!({"saved_search_id": id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.get(id).await
    }

    pub async fn get(&self, id: SavedSearchId) -> Result<SavedSearch> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, query, created_at, updated_at FROM saved_searches WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| saved_search_from_row(&row))
            .transpose()?
            .ok_or_else(|| not_found("saved search", id))
    }

    pub async fn list(&self) -> Result<Vec<SavedSearch>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, query, created_at, updated_at FROM saved_searches ORDER BY name COLLATE NOCASE, id",
                (),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(saved_search_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn remove(&self, id: SavedSearchId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        if transaction
            .execute(
                "DELETE FROM saved_searches WHERE id = ?1",
                (id.to_string(),),
            )
            .await?
            == 0
        {
            transaction.rollback().await?;
            return Err(not_found("saved search", id));
        }
        let event = insert_event(
            &transaction,
            now,
            "saved_search_removed",
            id.to_string(),
            json!({"saved_search_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.0.inner.events.send(event);
        Ok(())
    }

    pub async fn run(
        &self,
        id: SavedSearchId,
        page_size: usize,
        cursor: Option<String>,
    ) -> Result<SearchPage> {
        let saved = self.get(id).await?;
        self.0
            .search()
            .search(SearchRequest {
                query: saved.query,
                page_size,
                cursor,
            })
            .await
    }
}

fn validate(search: &NewSavedSearch) -> Result<()> {
    let name = search.name.trim();
    if name.is_empty() || name.len() > MAX_SAVED_SEARCH_NAME_BYTES {
        return Err(BackendError::InvalidInput(format!(
            "saved search name must contain 1 to {MAX_SAVED_SEARCH_NAME_BYTES} bytes"
        )));
    }
    parse_query(&search.query)?;
    Ok(())
}

fn saved_search_from_row(row: &turso::Row) -> Result<SavedSearch> {
    Ok(SavedSearch {
        id: parse_id(row.get::<String>(0)?, "saved search")?,
        name: row.get(1)?,
        query: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}
