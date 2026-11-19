//! Provider-neutral CalDAV discovery, synchronization, and event mutation.
//!
//! The protocol boundary accepts only explicitly configured HTTPS origins.
//! Server-supplied hrefs are resolved within that origin before credentials
//! are attached, and all XML/iCalendar bodies are bounded before parsing.

use crate::backend::{insert_event, not_found, parse_id};
use crate::{
    Backend, BackendError, CalDavEngineConfig, CalendarAccount, CalendarAccountId,
    CalendarAttendee, CalendarCollection, CalendarDiscoveryReport, CalendarEvent,
    CalendarEventDraft, CalendarEventFilter, CalendarEventId, CalendarId, CalendarMoment,
    CalendarSyncReport, Credentials, ImapCredential, MessageId, NewCalendarAccount, Page, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use futures_util::{future::BoxFuture, StreamExt};
use icalendar::{
    Calendar, CalendarDateTime as IcalDateTime, Component, DatePerhapsTime, Event, EventLike,
    Property,
};
use reqwest::{header, Method, StatusCode};
use roxmltree::{Document, Node};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, str::FromStr, sync::Arc, time::Duration};
use turso::Connection;
use url::Url;
use uuid::Uuid;

const MAX_NAME_BYTES: usize = 512;
const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_USERNAME_BYTES: usize = 2 * 1024;
const MAX_SUMMARY_BYTES: usize = 8 * 1024;
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
const MAX_LOCATION_BYTES: usize = 8 * 1024;
const MAX_ATTENDEES: usize = 1_000;
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;
const MAX_SYNC_TOKEN_BYTES: usize = 8 * 1024;
const MAX_CURSOR_BYTES: usize = 4 * 1024;
const DAV_NAMESPACE: &str = "DAV:";
const CALDAV_NAMESPACE: &str = "urn:ietf:params:xml:ns:caldav";
const CALENDAR_SERVER_NAMESPACE: &str = "http://calendarserver.org/ns/";
const APPLE_ICAL_NAMESPACE: &str = "http://apple.com/ns/ical/";
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 5 * 60;
const HARD_MAX_XML_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const HARD_MAX_ICALENDAR_RESOURCE_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_RESOURCES_PER_RESPONSE: usize = 100_000;
const HARD_MAX_XML_NODES: usize = 1_000_000;

/// Credential boundary for CalDAV. The stored credential representation is
/// shared with IMAP/SMTP, but providers can resolve OAuth tokens dynamically.
pub trait CalDavCredentialProvider: Send + Sync {
    fn resolve<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>>;
}

impl CalDavCredentialProvider for Credentials {
    fn resolve<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>> {
        Box::pin(async move { Credentials::resolve(self, reference).await })
    }
}

#[derive(Clone)]
pub struct CalendarAccounts {
    backend: Backend,
}

impl CalendarAccounts {
    pub(crate) fn new(backend: Backend) -> Self {
        Self { backend }
    }

    pub async fn add_with_credential(
        &self,
        name: impl Into<String>,
        base_url: impl Into<String>,
        username: impl Into<String>,
        credential: ImapCredential,
    ) -> Result<CalendarAccount> {
        let reference = self.backend.credentials().store(credential).await?;
        let account = NewCalendarAccount {
            name: name.into(),
            base_url: base_url.into(),
            username: username.into(),
            credential_ref: reference.clone(),
        };
        match self.add(account).await {
            Ok(value) => Ok(value),
            Err(error) => {
                let _ = self.backend.credentials().delete(&reference).await;
                Err(error)
            }
        }
    }

    pub async fn add(&self, account: NewCalendarAccount) -> Result<CalendarAccount> {
        let account = validate_new_account(account)?;
        let now = Utc::now().timestamp();
        let value = CalendarAccount {
            id: CalendarAccountId::new(),
            name: account.name,
            base_url: account.base_url,
            username: account.username,
            credential_ref: account.credential_ref,
            principal_url: None,
            home_url: None,
            created_at: now,
            updated_at: now,
        };
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "INSERT INTO calendar_accounts(id, name, base_url, username, credential_ref, principal_url, home_url, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?6)",
                turso::params![
                    value.id.to_string(),
                    value.name.clone(),
                    value.base_url.clone(),
                    value.username.clone(),
                    value.credential_ref.clone(),
                    now,
                ],
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "calendar_account_added",
            value.id.to_string(),
            json!({"calendar_account_id": value.id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.backend.inner.events.send(event);
        Ok(value)
    }

    pub async fn list(&self) -> Result<Vec<CalendarAccount>> {
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT id, name, base_url, username, credential_ref, principal_url, home_url, created_at, updated_at FROM calendar_accounts ORDER BY created_at, id",
                (),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(calendar_account_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn get(&self, id: CalendarAccountId) -> Result<CalendarAccount> {
        let connection = self.backend.inner.connection.lock().await;
        calendar_account_on(&connection, id).await
    }

    pub async fn update(
        &self,
        id: CalendarAccountId,
        account: NewCalendarAccount,
    ) -> Result<CalendarAccount> {
        let account = validate_new_account(account)?;
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let existing = calendar_account_on(&transaction, id).await?;
        let identity_changed =
            existing.base_url != account.base_url || existing.username != account.username;
        let changed = transaction
            .execute(
                "UPDATE calendar_accounts SET name = ?1, base_url = ?2, username = ?3, credential_ref = ?4, principal_url = CASE WHEN ?5 THEN NULL ELSE principal_url END, home_url = CASE WHEN ?5 THEN NULL ELSE home_url END, updated_at = ?6 WHERE id = ?7",
                turso::params![
                    account.name.clone(),
                    account.base_url.clone(),
                    account.username.clone(),
                    account.credential_ref.clone(),
                    identity_changed,
                    now,
                    id.to_string(),
                ],
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("calendar account", id));
        }
        if identity_changed {
            transaction
                .execute(
                    "DELETE FROM calendar_collections WHERE account_id = ?1",
                    (id.to_string(),),
                )
                .await?;
        }
        if existing.credential_ref != account.credential_ref {
            self.backend
                .queue_managed_credential_cleanup_on(&transaction, &existing.credential_ref, now)
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "calendar_account_updated",
            id.to_string(),
            json!({"calendar_account_id": id, "identity_changed": identity_changed}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.backend.inner.events.send(event);
        self.get(id).await
    }

    pub async fn set_credential(
        &self,
        id: CalendarAccountId,
        credential: ImapCredential,
    ) -> Result<CalendarAccount> {
        let existing = self.get(id).await?;
        let reference = self.backend.credentials().store(credential).await?;
        let result = self
            .update(
                id,
                NewCalendarAccount {
                    name: existing.name,
                    base_url: existing.base_url,
                    username: existing.username,
                    credential_ref: reference.clone(),
                },
            )
            .await;
        if result.is_err() {
            let committed = self
                .get(id)
                .await
                .ok()
                .is_some_and(|account| account.credential_ref == reference);
            if !committed {
                let _ = self.backend.credentials().delete(&reference).await;
            }
        }
        result
    }

    pub async fn remove(&self, id: CalendarAccountId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let existing = calendar_account_on(&transaction, id).await?;
        let changed = transaction
            .execute(
                "DELETE FROM calendar_accounts WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("calendar account", id));
        }
        self.backend
            .queue_managed_credential_cleanup_on(&transaction, &existing.credential_ref, now)
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "calendar_account_removed",
            id.to_string(),
            json!({"calendar_account_id": id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.backend.inner.events.send(event);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Calendars {
    backend: Backend,
}

impl Calendars {
    pub(crate) fn new(backend: Backend) -> Self {
        Self { backend }
    }

    pub async fn list(
        &self,
        account_id: Option<CalendarAccountId>,
    ) -> Result<Vec<CalendarCollection>> {
        let connection = self.backend.inner.connection.lock().await;
        let (sql, parameter) = if let Some(account_id) = account_id {
            (
                "SELECT id, account_id, remote_url, display_name, description, color, supports_events, writable, sync_token, ctag, created_at, updated_at FROM calendar_collections WHERE account_id = ?1 ORDER BY display_name COLLATE NOCASE, id",
                Some(account_id.to_string()),
            )
        } else {
            (
                "SELECT id, account_id, remote_url, display_name, description, color, supports_events, writable, sync_token, ctag, created_at, updated_at FROM calendar_collections ORDER BY display_name COLLATE NOCASE, id",
                None,
            )
        };
        let mut rows = if let Some(parameter) = parameter {
            connection.query(sql, (parameter,)).await?
        } else {
            connection.query(sql, ()).await?
        };
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(calendar_collection_from_row(&row)?);
        }
        Ok(values)
    }

    pub async fn get(&self, id: CalendarId) -> Result<CalendarCollection> {
        let connection = self.backend.inner.connection.lock().await;
        calendar_collection_on(&connection, id).await
    }

    pub async fn list_events(&self, filter: CalendarEventFilter) -> Result<Page<CalendarEvent>> {
        let page_size = filter.page_size.clamp(1, 200);
        let cursor = filter
            .cursor
            .as_deref()
            .map(decode_event_cursor)
            .transpose()?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.calendar_id != filter.calendar_id)
        {
            return Err(BackendError::InvalidInput(
                "calendar event cursor belongs to another calendar".into(),
            ));
        }
        let connection = self.backend.inner.connection.lock().await;
        let select = "SELECT id, calendar_id, remote_href, etag, uid, recurrence_id, summary, description, location, starts_at_json, ends_at_json, organizer, attendees_json, status, raw_icalendar, source_message_id, created_at, updated_at FROM calendar_events";
        let mut rows = if let Some(cursor) = cursor {
            connection
                .query(
                    &format!("{select} WHERE calendar_id = ?1 AND (updated_at < ?2 OR (updated_at = ?2 AND id < ?3)) ORDER BY updated_at DESC, id DESC LIMIT ?4"),
                    turso::params![
                        filter.calendar_id.to_string(),
                        cursor.updated_at,
                        cursor.event_id.to_string(),
                        (page_size + 1) as i64,
                    ],
                )
                .await?
        } else {
            connection
                .query(
                    &format!("{select} WHERE calendar_id = ?1 ORDER BY updated_at DESC, id DESC LIMIT ?2"),
                    (filter.calendar_id.to_string(), (page_size + 1) as i64),
                )
                .await?
        };
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(calendar_event_from_row(&row)?);
        }
        let next_cursor = if values.len() > page_size {
            values.truncate(page_size);
            values.last().map(encode_event_cursor).transpose()?
        } else {
            None
        };
        Ok(Page {
            items: values,
            next_cursor,
        })
    }

    pub async fn get_event(&self, id: CalendarEventId) -> Result<CalendarEvent> {
        let connection = self.backend.inner.connection.lock().await;
        calendar_event_on(&connection, id).await
    }

    /// Construct a proposal from a mail message. Dates and attendees are never
    /// guessed, and no calendar state changes until `create_event` is called.
    pub async fn draft_from_message(&self, message_id: MessageId) -> Result<CalendarEventDraft> {
        let message = self.backend.messages().get(message_id).await?;
        let mut description = message.body_text.trim().to_owned();
        if description.len() > MAX_DESCRIPTION_BYTES {
            description.truncate(floor_char_boundary(&description, MAX_DESCRIPTION_BYTES));
        }
        let mut summary = message
            .summary
            .subject
            .unwrap_or_else(|| "Email follow-up".to_owned());
        if summary.len() > MAX_SUMMARY_BYTES {
            summary.truncate(floor_char_boundary(&summary, MAX_SUMMARY_BYTES));
        }
        Ok(CalendarEventDraft {
            uid: None,
            summary,
            description: (!description.is_empty()).then_some(description),
            location: None,
            starts_at: None,
            ends_at: None,
            attendees: Vec::new(),
            status: None,
            source_message_id: Some(message_id),
        })
    }
}

#[derive(Clone)]
pub struct CalDavEngine {
    backend: Backend,
    credentials: Arc<dyn CalDavCredentialProvider>,
    transport: Arc<dyn CalDavTransport>,
    config: CalDavEngineConfig,
}

impl CalDavEngine {
    pub(crate) fn new(
        backend: Backend,
        credentials: Arc<dyn CalDavCredentialProvider>,
        config: CalDavEngineConfig,
    ) -> Result<Self> {
        validate_engine_config(&config)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("lizard-mail/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                BackendError::CalDav(format!("could not initialize HTTP client: {error}"))
            })?;
        Ok(Self {
            backend,
            credentials,
            transport: Arc::new(ReqwestCalDavTransport { client }),
            config,
        })
    }

    #[cfg(test)]
    fn with_transport(
        backend: Backend,
        credentials: Arc<dyn CalDavCredentialProvider>,
        config: CalDavEngineConfig,
        transport: Arc<dyn CalDavTransport>,
    ) -> Result<Self> {
        validate_engine_config(&config)?;
        Ok(Self {
            backend,
            credentials,
            transport,
            config,
        })
    }

    pub async fn discover(&self, account_id: CalendarAccountId) -> Result<CalendarDiscoveryReport> {
        let account = self.backend.calendar_accounts().get(account_id).await?;
        let credential = self.credentials.resolve(&account.credential_ref).await?;
        let base_url = validated_endpoint(&account.base_url)?;

        let discovery_body = propfind_discovery_body();
        let mut discovery = self
            .request_xml(
                &account,
                &credential,
                Method::from_bytes(b"PROPFIND").expect("static method"),
                base_url.clone(),
                Some("0"),
                discovery_body,
            )
            .await;
        if discovery.is_err() {
            let well_known = origin_root(&base_url)?
                .join(".well-known/caldav")
                .map_err(url_error)?;
            discovery = self
                .request_xml(
                    &account,
                    &credential,
                    Method::from_bytes(b"PROPFIND").expect("static method"),
                    well_known,
                    Some("0"),
                    propfind_discovery_body(),
                )
                .await;
        }
        let mut discovery = discovery?;
        let has_discovery_properties = {
            let xml = parse_xml(&discovery.body, &self.config)?;
            find_property_href(&xml, DAV_NAMESPACE, "current-user-principal").is_some()
                || find_property_href(&xml, CALDAV_NAMESPACE, "calendar-home-set").is_some()
        };
        if !has_discovery_properties {
            let well_known = origin_root(&base_url)?
                .join(".well-known/caldav")
                .map_err(url_error)?;
            if let Ok(candidate) = self
                .request_xml(
                    &account,
                    &credential,
                    Method::from_bytes(b"PROPFIND").expect("static method"),
                    well_known,
                    Some("0"),
                    propfind_discovery_body(),
                )
                .await
            {
                let candidate_has_properties = parse_xml(&candidate.body, &self.config)
                    .ok()
                    .is_some_and(|xml| {
                        find_property_href(&xml, DAV_NAMESPACE, "current-user-principal").is_some()
                            || find_property_href(&xml, CALDAV_NAMESPACE, "calendar-home-set")
                                .is_some()
                    });
                if candidate_has_properties {
                    discovery = candidate;
                }
            }
        }
        let discovery_url = validated_response_url(&account, &discovery.final_url)?;
        let discovery_xml = parse_xml(&discovery.body, &self.config)?;
        let principal_url =
            find_property_href(&discovery_xml, DAV_NAMESPACE, "current-user-principal")
                .map(|href| resolve_server_href(&account, &discovery_url, &href))
                .transpose()?
                .or_else(|| {
                    account
                        .principal_url
                        .as_deref()
                        .and_then(|value| Url::parse(value).ok())
                })
                .unwrap_or_else(|| discovery_url.clone());
        ensure_account_origin(&account, &principal_url)?;

        let principal = self
            .request_xml(
                &account,
                &credential,
                Method::from_bytes(b"PROPFIND").expect("static method"),
                principal_url.clone(),
                Some("0"),
                propfind_home_body(),
            )
            .await?;
        let principal_xml = parse_xml(&principal.body, &self.config)?;
        let principal_home =
            find_property_href(&principal_xml, CALDAV_NAMESPACE, "calendar-home-set")
                .map(|href| resolve_server_href(&account, &principal.final_url, &href))
                .transpose()?;
        let discovered_home =
            find_property_href(&discovery_xml, CALDAV_NAMESPACE, "calendar-home-set")
                .map(|href| resolve_server_href(&account, &discovery_url, &href))
                .transpose()?;
        let home_url = principal_home
            .or(discovered_home)
            .unwrap_or_else(|| principal_url.clone());
        ensure_account_origin(&account, &home_url)?;

        let listing = self
            .request_xml(
                &account,
                &credential,
                Method::from_bytes(b"PROPFIND").expect("static method"),
                home_url.clone(),
                Some("1"),
                propfind_calendars_body(),
            )
            .await?;
        let listing_xml = parse_xml(&listing.body, &self.config)?;
        let discovered = parse_calendar_collections(
            &listing_xml,
            &account,
            &listing.final_url,
            self.config.max_resources_per_response,
        )?;

        self.persist_discovery(account, principal_url, home_url, discovered)
            .await
    }

    /// Synchronize a complete calendar collection. Servers with RFC 6578 sync
    /// tokens use incremental REPORTs after the initial bounded full query.
    pub async fn sync_calendar(&self, calendar_id: CalendarId) -> Result<CalendarSyncReport> {
        let calendar = self.backend.calendars().get(calendar_id).await?;
        if !calendar.supports_events {
            return Err(BackendError::InvalidInput(
                "calendar collection does not support VEVENT resources".into(),
            ));
        }
        let account = self
            .backend
            .calendar_accounts()
            .get(calendar.account_id)
            .await?;
        let credential = self.credentials.resolve(&account.credential_ref).await?;
        let calendar_url = validated_endpoint(&calendar.remote_url)?;
        ensure_account_origin(&account, &calendar_url)?;

        if let Some(token) = calendar.sync_token.as_deref() {
            let response = self
                .request_xml_allow_status(
                    &account,
                    &credential,
                    Method::from_bytes(b"REPORT").expect("static method"),
                    calendar_url.clone(),
                    Some("1"),
                    sync_collection_body(token),
                )
                .await?;
            if response.status == StatusCode::MULTI_STATUS {
                let xml = parse_xml(&response.body, &self.config)?;
                let changes = parse_resource_changes(
                    &xml,
                    &account,
                    &response.final_url,
                    self.config.max_resources_per_response,
                    self.config.max_icalendar_resource_bytes,
                )?;
                let token = find_root_sync_token(&xml)?.or_else(|| Some(token.to_owned()));
                let changes = self
                    .hydrate_missing_resources(&account, &credential, changes)
                    .await?;
                return self.apply_sync(calendar, changes, token, false, None).await;
            }
            if !matches!(response.status.as_u16(), 403 | 409) {
                return Err(http_status_error("sync collection", &response));
            }
        }

        let initial_token = self
            .read_remote_sync_token(&account, &credential, calendar_url.clone())
            .await?;
        let full = self
            .request_xml(
                &account,
                &credential,
                Method::from_bytes(b"REPORT").expect("static method"),
                calendar_url.clone(),
                Some("1"),
                calendar_query_body(),
            )
            .await?;
        let xml = parse_xml(&full.body, &self.config)?;
        let mut changes = parse_resource_changes(
            &xml,
            &account,
            &full.final_url,
            self.config.max_resources_per_response,
            self.config.max_icalendar_resource_bytes,
        )?;
        changes = self
            .hydrate_missing_resources(&account, &credential, changes)
            .await?;

        let mut final_token = initial_token.clone();
        if let Some(token) = initial_token {
            let delta = self
                .request_xml_allow_status(
                    &account,
                    &credential,
                    Method::from_bytes(b"REPORT").expect("static method"),
                    calendar_url,
                    Some("1"),
                    sync_collection_body(&token),
                )
                .await?;
            if delta.status == StatusCode::MULTI_STATUS {
                let delta_xml = parse_xml(&delta.body, &self.config)?;
                let mut delta_changes = parse_resource_changes(
                    &delta_xml,
                    &account,
                    &delta.final_url,
                    self.config.max_resources_per_response,
                    self.config.max_icalendar_resource_bytes,
                )?;
                delta_changes = self
                    .hydrate_missing_resources(&account, &credential, delta_changes)
                    .await?;
                merge_changes(&mut changes, delta_changes);
                final_token = find_root_sync_token(&delta_xml)?.or(Some(token));
            } else if matches!(delta.status.as_u16(), 403 | 409) {
                // The collection advertised a token but declined to use it. A
                // full result is still useful, but retaining the rejected
                // token would make every later sync repeat this failure.
                final_token = None;
            } else {
                return Err(http_status_error("close full-sync race", &delta));
            }
        }
        self.apply_sync(calendar, changes, final_token, true, None)
            .await
    }

    pub async fn create_event(
        &self,
        calendar_id: CalendarId,
        draft: CalendarEventDraft,
    ) -> Result<CalendarEvent> {
        let calendar = self.backend.calendars().get(calendar_id).await?;
        if !calendar.supports_events {
            return Err(BackendError::InvalidInput(
                "calendar collection does not support VEVENT resources".into(),
            ));
        }
        if !calendar.writable {
            return Err(BackendError::Conflict("calendar is read-only".into()));
        }
        let account = self
            .backend
            .calendar_accounts()
            .get(calendar.account_id)
            .await?;
        let (raw, source_message_id) = build_icalendar(draft, None)?;
        self.require_source_message(source_message_id).await?;
        ensure_ical_size(&raw, &self.config)?;
        let credential = self.credentials.resolve(&account.credential_ref).await?;
        let base = validated_endpoint(&calendar.remote_url)?;
        let href = base
            .join(&format!("{}.ics", Uuid::new_v4()))
            .map_err(url_error)?;
        let submitted = raw.clone();
        let response = self
            .put_event(&account, &credential, href.clone(), raw, Some("*"))
            .await?;
        let remote_href = response
            .headers
            .get("location")
            .map(|location| resolve_server_href(&account, &response.final_url, location))
            .transpose()?
            .unwrap_or(href);
        let mut etag = response.headers.get("etag").cloned();
        if let Ok(resource) = self
            .fetch_resource(&account, &credential, remote_href.clone())
            .await
        {
            etag = resource.etag.or(etag);
            if let Some(raw) = resource.icalendar {
                if let Ok(parsed) = parse_icalendar_resource(&raw, &self.config, source_message_id)
                {
                    return self
                        .persist_single_event(calendar_id, remote_href, etag, parsed, true)
                        .await;
                }
            }
        }
        let parsed = parse_icalendar_resource(&submitted, &self.config, source_message_id)?;
        self.persist_single_event(calendar_id, remote_href, etag, parsed, true)
            .await
    }

    pub async fn update_event(
        &self,
        event_id: CalendarEventId,
        draft: CalendarEventDraft,
    ) -> Result<CalendarEvent> {
        let existing = self.backend.calendars().get_event(event_id).await?;
        let calendar = self.backend.calendars().get(existing.calendar_id).await?;
        if !calendar.supports_events {
            return Err(BackendError::InvalidInput(
                "calendar collection does not support VEVENT resources".into(),
            ));
        }
        if !calendar.writable {
            return Err(BackendError::Conflict("calendar is read-only".into()));
        }
        let etag = existing.etag.as_deref().ok_or_else(|| {
            BackendError::Conflict("event has no ETag; synchronize before updating it".into())
        })?;
        let account = self
            .backend
            .calendar_accounts()
            .get(calendar.account_id)
            .await?;
        let (raw, source_message_id) = build_icalendar(draft, Some(&existing.uid))?;
        self.require_source_message(source_message_id).await?;
        ensure_ical_size(&raw, &self.config)?;
        let credential = self.credentials.resolve(&account.credential_ref).await?;
        let href = validated_endpoint(&existing.remote_href)?;
        let submitted = raw.clone();
        let response = self
            .put_event(&account, &credential, href.clone(), raw, Some(etag))
            .await?;
        let mut new_etag = response.headers.get("etag").cloned();
        if let Ok(resource) = self
            .fetch_resource(&account, &credential, href.clone())
            .await
        {
            new_etag = resource.etag.or(new_etag);
            if let Some(raw) = resource.icalendar {
                if let Ok(parsed) = parse_icalendar_resource(&raw, &self.config, source_message_id)
                {
                    return self
                        .persist_single_event(existing.calendar_id, href, new_etag, parsed, false)
                        .await;
                }
            }
        }
        let parsed = parse_icalendar_resource(&submitted, &self.config, source_message_id)?;
        self.persist_single_event(existing.calendar_id, href, new_etag, parsed, false)
            .await
    }

    pub async fn delete_event(&self, event_id: CalendarEventId) -> Result<()> {
        let existing = self.backend.calendars().get_event(event_id).await?;
        let calendar = self.backend.calendars().get(existing.calendar_id).await?;
        if !calendar.supports_events {
            return Err(BackendError::InvalidInput(
                "calendar collection does not support VEVENT resources".into(),
            ));
        }
        if !calendar.writable {
            return Err(BackendError::Conflict("calendar is read-only".into()));
        }
        let account = self
            .backend
            .calendar_accounts()
            .get(calendar.account_id)
            .await?;
        let etag = existing.etag.clone().ok_or_else(|| {
            BackendError::Conflict("event has no ETag; synchronize before deleting it".into())
        })?;
        let credential = self.credentials.resolve(&account.credential_ref).await?;
        let response = self
            .request(
                &account,
                &credential,
                CalDavHttpRequest {
                    method: Method::DELETE,
                    url: validated_endpoint(&existing.remote_href)?,
                    depth: None,
                    content_type: None,
                    body: None,
                    if_match: Some(etag),
                    max_response_bytes: MAX_ERROR_BODY_BYTES,
                },
            )
            .await?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Err(BackendError::Conflict(
                "calendar event changed remotely; synchronize before deleting it".into(),
            ));
        }
        if !(response.status.is_success() || response.status == StatusCode::NOT_FOUND) {
            return Err(http_status_error("delete event", &response));
        }
        self.delete_local_event(event_id).await
    }
}

impl CalDavEngine {
    async fn require_source_message(&self, message_id: Option<MessageId>) -> Result<()> {
        let Some(message_id) = message_id else {
            return Ok(());
        };
        let connection = self.backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1)",
                (message_id.to_string(),),
            )
            .await?;
        let exists = rows
            .next()
            .await?
            .ok_or_else(|| BackendError::CalDav("message lookup returned no result".into()))?
            .get::<bool>(0)?;
        if exists {
            Ok(())
        } else {
            Err(not_found("message", message_id))
        }
    }

    async fn request_xml(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        method: Method,
        url: Url,
        depth: Option<&str>,
        body: String,
    ) -> Result<CalDavHttpResponse> {
        let response = self
            .request_xml_allow_status(account, credential, method, url, depth, body)
            .await?;
        if response.status != StatusCode::MULTI_STATUS {
            return Err(http_status_error("XML request", &response));
        }
        Ok(response)
    }

    async fn request_xml_allow_status(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        method: Method,
        url: Url,
        depth: Option<&str>,
        body: String,
    ) -> Result<CalDavHttpResponse> {
        self.request(
            account,
            credential,
            CalDavHttpRequest {
                method,
                url,
                depth: depth.map(str::to_owned),
                content_type: Some("application/xml; charset=utf-8".to_owned()),
                body: Some(body.into_bytes()),
                if_match: None,
                max_response_bytes: self.config.max_xml_response_bytes,
            },
        )
        .await
    }

    async fn request(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        request: CalDavHttpRequest,
    ) -> Result<CalDavHttpResponse> {
        ensure_account_origin(account, &request.url)?;
        let response = self
            .transport
            .execute(
                request,
                &account.username,
                credential,
                Duration::from_secs(self.config.request_timeout_seconds),
            )
            .await?;
        validated_response_url(account, &response.final_url)?;
        Ok(response)
    }

    async fn put_event(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        href: Url,
        raw: String,
        precondition: Option<&str>,
    ) -> Result<CalDavHttpResponse> {
        let response = self
            .request(
                account,
                credential,
                CalDavHttpRequest {
                    method: Method::PUT,
                    url: href,
                    depth: None,
                    content_type: Some("text/calendar; charset=utf-8".to_owned()),
                    body: Some(raw.into_bytes()),
                    if_match: precondition.map(str::to_owned),
                    max_response_bytes: MAX_ERROR_BODY_BYTES,
                },
            )
            .await?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Err(BackendError::Conflict(
                "calendar event changed remotely; synchronize before overwriting it".into(),
            ));
        }
        if !response.status.is_success() {
            return Err(http_status_error("write event", &response));
        }
        Ok(response)
    }

    async fn fetch_resource(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        href: Url,
    ) -> Result<ResourceChange> {
        let response = self
            .request(
                account,
                credential,
                CalDavHttpRequest {
                    method: Method::GET,
                    url: href.clone(),
                    depth: None,
                    content_type: None,
                    body: None,
                    if_match: None,
                    max_response_bytes: self.config.max_icalendar_resource_bytes,
                },
            )
            .await?;
        if !response.status.is_success() {
            return Err(http_status_error("fetch event", &response));
        }
        let raw = String::from_utf8(response.body)
            .map_err(|_| BackendError::CalDav("calendar resource is not UTF-8".into()))?;
        ensure_ical_size(&raw, &self.config)?;
        Ok(ResourceChange {
            href,
            etag: response.headers.get("etag").cloned(),
            icalendar: Some(raw),
            deleted: false,
        })
    }

    async fn hydrate_missing_resources(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        changes: Vec<ResourceChange>,
    ) -> Result<Vec<ResourceChange>> {
        let mut hydrated = Vec::with_capacity(changes.len());
        let mut total_icalendar_bytes = 0usize;
        for change in changes {
            let change = if !change.deleted && change.icalendar.is_none() {
                self.fetch_resource(account, credential, change.href.clone())
                    .await?
            } else {
                change
            };
            if let Some(raw) = &change.icalendar {
                total_icalendar_bytes = total_icalendar_bytes.saturating_add(raw.len());
                if total_icalendar_bytes > self.config.max_xml_response_bytes {
                    return Err(BackendError::CalDav(format!(
                        "calendar sync event data exceeds the {}-byte aggregate limit",
                        self.config.max_xml_response_bytes
                    )));
                }
            }
            hydrated.push(change);
        }
        Ok(hydrated)
    }

    async fn read_remote_sync_token(
        &self,
        account: &CalendarAccount,
        credential: &ImapCredential,
        calendar_url: Url,
    ) -> Result<Option<String>> {
        let response = self
            .request_xml(
                account,
                credential,
                Method::from_bytes(b"PROPFIND").expect("static method"),
                calendar_url,
                Some("0"),
                propfind_sync_token_body(),
            )
            .await?;
        let xml = parse_xml(&response.body, &self.config)?;
        find_root_sync_token(&xml)
    }

    async fn persist_discovery(
        &self,
        mut account: CalendarAccount,
        principal_url: Url,
        home_url: Url,
        discovered: Vec<DiscoveredCalendar>,
    ) -> Result<CalendarDiscoveryReport> {
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE calendar_accounts SET principal_url = ?1, home_url = ?2, updated_at = ?3 WHERE id = ?4",
                (
                    principal_url.as_str(),
                    home_url.as_str(),
                    now,
                    account.id.to_string(),
                ),
            )
            .await?;
        account.principal_url = Some(principal_url.to_string());
        account.home_url = Some(home_url.to_string());
        account.updated_at = now;

        let mut active_urls = HashSet::new();
        let mut calendars = Vec::with_capacity(discovered.len());
        for remote in discovered {
            active_urls.insert(remote.remote_url.clone());
            let mut rows = transaction
                .query(
                    "SELECT id, sync_token, created_at FROM calendar_collections WHERE account_id = ?1 AND remote_url = ?2",
                    (account.id.to_string(), remote.remote_url.clone()),
                )
                .await?;
            let existing = rows
                .next()
                .await?
                .map(|row| {
                    Ok::<_, BackendError>((
                        parse_id::<CalendarId>(row.get::<String>(0)?, "calendar")?,
                        row.get::<Option<String>>(1)?,
                        row.get::<i64>(2)?,
                    ))
                })
                .transpose()?;
            drop(rows);
            let (id, sync_token, created_at) =
                existing.unwrap_or_else(|| (CalendarId::new(), None, now));
            transaction
                .execute(
                    "INSERT INTO calendar_collections(id, account_id, remote_url, display_name, description, color, supports_events, writable, sync_token, ctag, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT(account_id, remote_url) DO UPDATE SET display_name = excluded.display_name, description = excluded.description, color = excluded.color, supports_events = excluded.supports_events, writable = excluded.writable, ctag = excluded.ctag, updated_at = excluded.updated_at",
                    turso::params![
                        id.to_string(),
                        account.id.to_string(),
                        remote.remote_url.clone(),
                        remote.display_name.clone(),
                        remote.description.clone(),
                        remote.color.clone(),
                        remote.supports_events,
                        remote.writable,
                        sync_token.clone(),
                        remote.ctag.clone(),
                        created_at,
                        now,
                    ],
                )
                .await?;
            calendars.push(CalendarCollection {
                id,
                account_id: account.id,
                remote_url: remote.remote_url,
                display_name: remote.display_name,
                description: remote.description,
                color: remote.color,
                supports_events: remote.supports_events,
                writable: remote.writable,
                sync_token,
                ctag: remote.ctag,
                created_at,
                updated_at: now,
            });
        }

        let mut rows = transaction
            .query(
                "SELECT id, remote_url FROM calendar_collections WHERE account_id = ?1",
                (account.id.to_string(),),
            )
            .await?;
        let mut removed = Vec::new();
        while let Some(row) = rows.next().await? {
            let id = parse_id::<CalendarId>(row.get::<String>(0)?, "calendar")?;
            let remote_url = row.get::<String>(1)?;
            if !active_urls.contains(&remote_url) {
                removed.push(id);
            }
        }
        drop(rows);
        for id in &removed {
            transaction
                .execute(
                    "DELETE FROM calendar_collections WHERE id = ?1",
                    (id.to_string(),),
                )
                .await?;
        }
        let event = insert_event(
            &transaction,
            now,
            "calendar_discovery_completed",
            account.id.to_string(),
            json!({
                "calendar_account_id": account.id,
                "calendar_ids": calendars.iter().map(|value| value.id).collect::<Vec<_>>(),
                "removed_calendar_ids": removed,
            }),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.backend.inner.events.send(event);
        Ok(CalendarDiscoveryReport {
            account,
            calendars,
            removed_calendar_ids: removed,
        })
    }

    async fn apply_sync(
        &self,
        calendar: CalendarCollection,
        changes: Vec<ResourceChange>,
        sync_token: Option<String>,
        full_sync: bool,
        source_message_id: Option<MessageId>,
    ) -> Result<CalendarSyncReport> {
        let mut parsed = Vec::new();
        let mut deleted_hrefs = HashSet::new();
        for change in changes {
            if change.deleted {
                deleted_hrefs.insert(change.href.to_string());
                continue;
            }
            let raw = change.icalendar.ok_or_else(|| {
                BackendError::CalDav("calendar response omitted event data".into())
            })?;
            let event = parse_icalendar_resource(&raw, &self.config, source_message_id)?;
            parsed.push((change.href.to_string(), change.etag, event));
        }

        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut created = 0u64;
        let mut updated = 0u64;
        let mut deleted = 0u64;

        if full_sync {
            let active: HashSet<&str> = parsed.iter().map(|value| value.0.as_str()).collect();
            let mut rows = transaction
                .query(
                    "SELECT id, remote_href FROM calendar_events WHERE calendar_id = ?1",
                    (calendar.id.to_string(),),
                )
                .await?;
            let mut stale = Vec::new();
            while let Some(row) = rows.next().await? {
                let id = row.get::<String>(0)?;
                let href = row.get::<String>(1)?;
                if !active.contains(href.as_str()) {
                    stale.push(id);
                }
            }
            drop(rows);
            for id in stale {
                deleted += transaction
                    .execute("DELETE FROM calendar_events WHERE id = ?1", (id,))
                    .await?;
            }
        }
        for href in deleted_hrefs {
            deleted += transaction
                .execute(
                    "DELETE FROM calendar_events WHERE calendar_id = ?1 AND remote_href = ?2",
                    (calendar.id.to_string(), href),
                )
                .await?;
        }
        for (href, etag, event) in parsed {
            let existed = event_exists_on(&transaction, calendar.id, &href).await?;
            upsert_event_on(&transaction, calendar.id, &href, etag, event, now).await?;
            if existed {
                updated += 1;
            } else {
                created += 1;
            }
        }
        transaction
            .execute(
                "UPDATE calendar_collections SET sync_token = ?1, updated_at = ?2 WHERE id = ?3",
                (sync_token.clone(), now, calendar.id.to_string()),
            )
            .await?;
        let report = CalendarSyncReport {
            calendar_id: calendar.id,
            full_sync,
            created,
            updated,
            deleted,
            sync_token,
        };
        let event = insert_event(
            &transaction,
            now,
            "calendar_synchronized",
            calendar.id.to_string(),
            serde_json::to_value(&report)?,
        )
        .await?;
        transaction.commit().await?;
        let _ = self.backend.inner.events.send(event);
        Ok(report)
    }

    async fn persist_single_event(
        &self,
        calendar_id: CalendarId,
        href: Url,
        etag: Option<String>,
        event: ParsedEvent,
        creating: bool,
    ) -> Result<CalendarEvent> {
        let now = Utc::now().timestamp();
        let id = CalendarEventId::new();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let existing = event_id_by_href_on(&transaction, calendar_id, href.as_str()).await?;
        upsert_event_on(&transaction, calendar_id, href.as_str(), etag, event, now).await?;
        let event_id = existing.unwrap_or(id);
        // upsert_event_on creates its own ID; resolve it after the write.
        let event_id = event_id_by_href_on(&transaction, calendar_id, href.as_str())
            .await?
            .unwrap_or(event_id);
        let backend_event = insert_event(
            &transaction,
            now,
            if creating {
                "calendar_event_created"
            } else {
                "calendar_event_updated"
            },
            event_id.to_string(),
            json!({"calendar_event_id": event_id, "calendar_id": calendar_id}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.backend.inner.events.send(backend_event);
        self.backend.calendars().get_event(event_id).await
    }

    async fn delete_local_event(&self, event_id: CalendarEventId) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.backend.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "DELETE FROM calendar_events WHERE id = ?1",
                (event_id.to_string(),),
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("calendar event", event_id));
        }
        let event = insert_event(
            &transaction,
            now,
            "calendar_event_deleted",
            event_id.to_string(),
            json!({"calendar_event_id": event_id}),
        )
        .await?;
        transaction.commit().await?;
        let _ = self.backend.inner.events.send(event);
        Ok(())
    }
}

struct CalDavHttpRequest {
    method: Method,
    url: Url,
    depth: Option<String>,
    content_type: Option<String>,
    body: Option<Vec<u8>>,
    if_match: Option<String>,
    max_response_bytes: usize,
}

struct CalDavHttpResponse {
    status: StatusCode,
    final_url: Url,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

trait CalDavTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: CalDavHttpRequest,
        username: &'a str,
        credential: &'a ImapCredential,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<CalDavHttpResponse>>;
}

struct ReqwestCalDavTransport {
    client: reqwest::Client,
}

impl CalDavTransport for ReqwestCalDavTransport {
    fn execute<'a>(
        &'a self,
        request: CalDavHttpRequest,
        username: &'a str,
        credential: &'a ImapCredential,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<CalDavHttpResponse>> {
        Box::pin(async move {
            let mut builder = self
                .client
                .request(request.method, request.url)
                .timeout(timeout);
            builder = match credential {
                ImapCredential::Password(password) => {
                    builder.basic_auth(username, Some(password.expose()))
                }
                ImapCredential::OAuth2 { access_token } => {
                    builder.bearer_auth(access_token.expose())
                }
            };
            if let Some(depth) = request.depth {
                builder = builder.header("Depth", depth);
            }
            if let Some(content_type) = request.content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            if let Some(if_match) = request.if_match {
                if if_match == "*" {
                    builder = builder.header(header::IF_NONE_MATCH, "*");
                } else {
                    builder = builder.header(header::IF_MATCH, if_match);
                }
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let response = builder
                .send()
                .await
                .map_err(|error| BackendError::CalDav(format!("HTTP request failed: {error}")))?;
            let status = response.status();
            let final_url = response.url().clone();
            if response
                .content_length()
                .is_some_and(|size| size > request.max_response_bytes as u64)
            {
                return Err(BackendError::CalDav(format!(
                    "response exceeds the {}-byte limit",
                    request.max_response_bytes
                )));
            }
            let mut headers = std::collections::HashMap::new();
            for name in [header::ETAG, header::LOCATION] {
                if let Some(value) = response.headers().get(&name) {
                    if let Ok(value) = value.to_str() {
                        headers.insert(name.as_str().to_owned(), value.to_owned());
                    }
                }
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    BackendError::CalDav(format!("could not read HTTP response: {error}"))
                })?;
                if body.len().saturating_add(chunk.len()) > request.max_response_bytes {
                    return Err(BackendError::CalDav(format!(
                        "response exceeds the {}-byte limit",
                        request.max_response_bytes
                    )));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(CalDavHttpResponse {
                status,
                final_url,
                headers,
                body,
            })
        })
    }
}

#[derive(Clone, Debug)]
struct DiscoveredCalendar {
    remote_url: String,
    display_name: String,
    description: Option<String>,
    color: Option<String>,
    supports_events: bool,
    writable: bool,
    ctag: Option<String>,
}

#[derive(Clone, Debug)]
struct ResourceChange {
    href: Url,
    etag: Option<String>,
    icalendar: Option<String>,
    deleted: bool,
}

#[derive(Clone, Debug)]
struct ParsedEvent {
    uid: String,
    recurrence_id: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    starts_at: Option<CalendarMoment>,
    ends_at: Option<CalendarMoment>,
    organizer: Option<String>,
    attendees: Vec<CalendarAttendee>,
    status: Option<String>,
    raw_icalendar: String,
    source_message_id: Option<MessageId>,
}

#[derive(Serialize, Deserialize)]
struct CalendarEventCursor {
    calendar_id: CalendarId,
    updated_at: i64,
    event_id: CalendarEventId,
}

fn encode_event_cursor(event: &CalendarEvent) -> Result<String> {
    let value = CalendarEventCursor {
        calendar_id: event.calendar_id,
        updated_at: event.updated_at,
        event_id: event.id,
    };
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value)?))
}

fn decode_event_cursor(value: &str) -> Result<CalendarEventCursor> {
    if value.len() > MAX_CURSOR_BYTES {
        return Err(BackendError::InvalidInput(
            "calendar event cursor is too long".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BackendError::InvalidInput("invalid calendar event cursor".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| BackendError::InvalidInput("invalid calendar event cursor".into()))
}

fn propfind_discovery_body() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:current-user-principal/><c:calendar-home-set/></d:prop>
</d:propfind>"#
        .to_owned()
}

fn propfind_home_body() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><c:calendar-home-set/></d:prop>
</d:propfind>"#
        .to_owned()
}

fn propfind_calendars_body() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:ical="http://apple.com/ns/ical/">
  <d:prop>
    <d:resourcetype/><d:displayname/><c:calendar-description/>
    <ical:calendar-color/><c:supported-calendar-component-set/>
    <d:current-user-privilege-set/><d:sync-token/><cs:getctag/>
  </d:prop>
</d:propfind>"#
        .to_owned()
}

fn propfind_sync_token_body() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:sync-token/></d:prop></d:propfind>"#
        .to_owned()
}

fn calendar_query_body() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
  <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"/></c:comp-filter></c:filter>
</c:calendar-query>"#
        .to_owned()
}

fn sync_collection_body(token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:sync-collection xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:sync-token>{}</d:sync-token><d:sync-level>1</d:sync-level>
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
</d:sync-collection>"#,
        xml_escape(token)
    )
}

fn parse_xml<'a>(body: &'a [u8], config: &CalDavEngineConfig) -> Result<Document<'a>> {
    if body.len() > config.max_xml_response_bytes {
        return Err(BackendError::CalDav(
            "XML response exceeds its size limit".into(),
        ));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| BackendError::CalDav("CalDAV XML is not UTF-8".into()))?;
    let estimated_nodes = text
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b'<')
        .take(config.max_xml_nodes + 1)
        .count();
    if estimated_nodes > config.max_xml_nodes {
        return Err(BackendError::CalDav(
            "CalDAV XML exceeds its node limit".into(),
        ));
    }
    Document::parse(text)
        .map_err(|error| BackendError::CalDav(format!("invalid CalDAV XML: {error}")))
}

fn find_property_href(document: &Document<'_>, namespace: &str, property: &str) -> Option<String> {
    let property = document
        .descendants()
        .find(|node| element_is(*node, namespace, property))?;
    property
        .descendants()
        .find(|node| element_is(*node, DAV_NAMESPACE, "href"))
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn find_root_sync_token(document: &Document<'_>) -> Result<Option<String>> {
    let token = document
        .root_element()
        .children()
        .find(|node| element_is(*node, DAV_NAMESPACE, "sync-token"))
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            document
                .descendants()
                .find(|node| element_is(*node, DAV_NAMESPACE, "sync-token"))
                .and_then(|node| node.text())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        });
    if let Some(token) = &token {
        validate_property_value("calendar sync token", token, MAX_SYNC_TOKEN_BYTES)
            .map_err(|_| BackendError::CalDav("calendar sync token is invalid".into()))?;
    }
    Ok(token)
}

fn parse_calendar_collections(
    document: &Document<'_>,
    account: &CalendarAccount,
    response_url: &Url,
    limit: usize,
) -> Result<Vec<DiscoveredCalendar>> {
    let mut output = Vec::new();
    let mut response_count = 0usize;
    for response in document
        .descendants()
        .filter(|node| element_is(*node, DAV_NAMESPACE, "response"))
    {
        response_count += 1;
        if response_count > limit {
            return Err(BackendError::CalDav(format!(
                "calendar discovery exceeds the {limit}-resource limit"
            )));
        }
        let prop = successful_prop(response).ok_or_else(|| {
            BackendError::CalDav(
                "calendar discovery response did not include successful properties".into(),
            )
        })?;
        let is_calendar =
            find_descendant(prop, DAV_NAMESPACE, "resourcetype").is_some_and(|types| {
                types
                    .descendants()
                    .any(|node| element_is(node, CALDAV_NAMESPACE, "calendar"))
            });
        if !is_calendar {
            continue;
        }
        let href = response_href(response)?;
        let url = resolve_server_href(account, response_url, &href)?;
        let supports = find_descendant(prop, CALDAV_NAMESPACE, "supported-calendar-component-set");
        let supports_events = supports.is_none_or(|node| {
            node.descendants().any(|component| {
                element_is(component, CALDAV_NAMESPACE, "comp")
                    && component
                        .attribute("name")
                        .is_some_and(|name| name.eq_ignore_ascii_case("VEVENT"))
            })
        });
        let privileges = find_descendant(prop, DAV_NAMESPACE, "current-user-privilege-set");
        let writable = privileges.is_none_or(|node| {
            node.descendants().any(|privilege| {
                element_is(privilege, DAV_NAMESPACE, "write")
                    || element_is(privilege, DAV_NAMESPACE, "write-content")
            })
        });
        let display_name = child_text(prop, DAV_NAMESPACE, "displayname")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                url.path_segments()
                    .and_then(|mut segments| segments.next_back())
                    .filter(|value| !value.is_empty())
                    .unwrap_or("Calendar")
                    .to_owned()
            });
        output.push(DiscoveredCalendar {
            remote_url: url.to_string(),
            display_name: bounded_string(display_name, MAX_NAME_BYTES),
            description: child_text(prop, CALDAV_NAMESPACE, "calendar-description")
                .map(|value| bounded_string(value, MAX_DESCRIPTION_BYTES)),
            color: child_text(prop, APPLE_ICAL_NAMESPACE, "calendar-color")
                .map(|value| bounded_string(value, 128)),
            supports_events,
            writable,
            ctag: child_text(prop, CALENDAR_SERVER_NAMESPACE, "getctag")
                .map(|value| bounded_string(value, 8 * 1024)),
        });
    }
    Ok(output)
}

fn parse_resource_changes(
    document: &Document<'_>,
    account: &CalendarAccount,
    response_url: &Url,
    limit: usize,
    max_icalendar_bytes: usize,
) -> Result<Vec<ResourceChange>> {
    let mut output = Vec::new();
    let mut response_count = 0usize;
    for response in document
        .descendants()
        .filter(|node| element_is(*node, DAV_NAMESPACE, "response"))
    {
        response_count += 1;
        if response_count > limit {
            return Err(BackendError::CalDav(format!(
                "calendar response exceeds the {limit}-resource limit"
            )));
        }
        let href = resolve_server_href(account, response_url, &response_href(response)?)?;
        let deleted = direct_status(response).is_some_and(|status| status.contains(" 404 "));
        if deleted {
            output.push(ResourceChange {
                href,
                etag: None,
                icalendar: None,
                deleted: true,
            });
            continue;
        }
        let prop = successful_prop(response).ok_or_else(|| {
            BackendError::CalDav(
                "calendar resource response did not include successful properties".into(),
            )
        })?;
        let etag = child_text(prop, DAV_NAMESPACE, "getetag");
        if let Some(etag) = &etag {
            validate_property_value("calendar ETag", etag, 8 * 1024)
                .map_err(|_| BackendError::CalDav("calendar ETag is invalid".into()))?;
        }
        let icalendar = child_raw_text(prop, CALDAV_NAMESPACE, "calendar-data");
        if icalendar
            .as_ref()
            .is_some_and(|value| value.len() > max_icalendar_bytes)
        {
            return Err(BackendError::CalDav(format!(
                "calendar resource exceeds the {max_icalendar_bytes}-byte limit"
            )));
        }
        output.push(ResourceChange {
            href,
            etag,
            icalendar,
            deleted: false,
        });
    }
    Ok(output)
}

fn successful_prop<'a, 'input>(response: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    response
        .children()
        .filter(|node| element_is(*node, DAV_NAMESPACE, "propstat"))
        .find_map(|propstat| {
            let successful = propstat
                .children()
                .find(|node| element_is(*node, DAV_NAMESPACE, "status"))
                .and_then(|node| node.text())
                .is_some_and(|status| status.contains(" 200 "));
            successful.then(|| {
                propstat
                    .children()
                    .find(|node| element_is(*node, DAV_NAMESPACE, "prop"))
            })?
        })
}

fn response_href(response: Node<'_, '_>) -> Result<String> {
    response
        .children()
        .find(|node| element_is(*node, DAV_NAMESPACE, "href"))
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| BackendError::CalDav("DAV response has no href".into()))
}

fn direct_status(response: Node<'_, '_>) -> Option<String> {
    response
        .children()
        .find(|node| element_is(*node, DAV_NAMESPACE, "status"))
        .and_then(|node| node.text())
        .map(str::to_owned)
}

fn element_is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

fn find_descendant<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    node.descendants()
        .find(|child| element_is(*child, namespace, name))
}

fn child_text(node: Node<'_, '_>, namespace: &str, name: &str) -> Option<String> {
    find_descendant(node, namespace, name)
        .and_then(|child| child.text())
        .map(str::trim)
        .map(str::to_owned)
}

fn child_raw_text(node: Node<'_, '_>, namespace: &str, name: &str) -> Option<String> {
    find_descendant(node, namespace, name)
        .and_then(|child| child.text())
        .map(str::to_owned)
}

fn merge_changes(target: &mut Vec<ResourceChange>, delta: Vec<ResourceChange>) {
    for change in delta {
        if let Some(index) = target
            .iter()
            .position(|existing| existing.href == change.href)
        {
            target[index] = change;
        } else {
            target.push(change);
        }
    }
}

fn build_icalendar(
    mut draft: CalendarEventDraft,
    forced_uid: Option<&str>,
) -> Result<(String, Option<MessageId>)> {
    require_bounded_nonempty("event summary", &draft.summary, MAX_SUMMARY_BYTES)?;
    validate_ical_text("event summary", &draft.summary)?;
    if draft
        .description
        .as_ref()
        .is_some_and(|value| value.len() > MAX_DESCRIPTION_BYTES)
    {
        return Err(BackendError::InvalidInput(format!(
            "event description exceeds {MAX_DESCRIPTION_BYTES} bytes"
        )));
    }
    if let Some(description) = &draft.description {
        validate_ical_text("event description", description)?;
    }
    if draft
        .location
        .as_ref()
        .is_some_and(|value| value.len() > MAX_LOCATION_BYTES)
    {
        return Err(BackendError::InvalidInput(format!(
            "event location exceeds {MAX_LOCATION_BYTES} bytes"
        )));
    }
    if let Some(location) = &draft.location {
        validate_ical_text("event location", location)?;
    }
    if draft.attendees.len() > MAX_ATTENDEES {
        return Err(BackendError::InvalidInput(format!(
            "event exceeds the {MAX_ATTENDEES}-attendee limit"
        )));
    }
    let starts_at = draft
        .starts_at
        .take()
        .ok_or_else(|| BackendError::InvalidInput("calendar event requires a start time".into()))?;
    let ends_at = draft
        .ends_at
        .take()
        .ok_or_else(|| BackendError::InvalidInput("calendar event requires an end time".into()))?;
    validate_moment_order(&starts_at, &ends_at)?;

    let uid = forced_uid
        .map(str::to_owned)
        .or(draft.uid.take())
        .unwrap_or_else(|| format!("{}@lizard.local", Uuid::new_v4()));
    validate_property_value("event UID", &uid, 2_048)?;
    let mut event = Event::with_uid(&uid);
    event.summary(&draft.summary);
    if let Some(description) = &draft.description {
        event.description(description);
    }
    if let Some(location) = &draft.location {
        event.location(location);
    }
    event.append_property(moment_property("DTSTART", &starts_at)?);
    event.append_property(moment_property("DTEND", &ends_at)?);
    if let Some(status) = &draft.status {
        let status = status.trim().to_ascii_uppercase();
        if !matches!(status.as_str(), "TENTATIVE" | "CONFIRMED" | "CANCELLED") {
            return Err(BackendError::InvalidInput(
                "event status must be tentative, confirmed, or cancelled".into(),
            ));
        }
        event.append_property(Property::new("STATUS", status));
    }
    for attendee in &draft.attendees {
        event.append_property(attendee_property(attendee)?);
    }
    let mut calendar = Calendar::new();
    calendar.push(event);
    Ok((calendar.to_string(), draft.source_message_id))
}

fn moment_property(name: &str, moment: &CalendarMoment) -> Result<Property> {
    match moment {
        CalendarMoment::Date { value } => {
            Ok(Property::new(name, value.format("%Y%m%d").to_string())
                .add_parameter("VALUE", "DATE")
                .done())
        }
        CalendarMoment::Utc { value } => Ok(Property::new(
            name,
            value.format("%Y%m%dT%H%M%SZ").to_string(),
        )),
        CalendarMoment::Local { value, timezone } => {
            validate_timezone(timezone)?;
            Ok(
                Property::new(name, value.format("%Y%m%dT%H%M%S").to_string())
                    .add_parameter("TZID", timezone)
                    .done(),
            )
        }
        CalendarMoment::Floating { value } => Ok(Property::new(
            name,
            value.format("%Y%m%dT%H%M%S").to_string(),
        )),
    }
}

fn attendee_property(attendee: &CalendarAttendee) -> Result<Property> {
    let address = attendee.address.trim();
    validate_email_address(address)?;
    let mut property = Property::new("ATTENDEE", format!("mailto:{address}"));
    if let Some(name) = &attendee.display_name {
        validate_property_value("attendee display name", name, 2_048)?;
        property.add_parameter("CN", name);
    }
    if let Some(role) = &attendee.role {
        let role = role.trim().to_ascii_uppercase();
        if !matches!(
            role.as_str(),
            "CHAIR" | "REQ-PARTICIPANT" | "OPT-PARTICIPANT" | "NON-PARTICIPANT"
        ) {
            return Err(BackendError::InvalidInput("invalid attendee role".into()));
        }
        property.add_parameter("ROLE", &role);
    }
    if let Some(status) = &attendee.participation_status {
        let status = status.trim().to_ascii_uppercase();
        if !matches!(
            status.as_str(),
            "NEEDS-ACTION" | "ACCEPTED" | "DECLINED" | "TENTATIVE" | "DELEGATED"
        ) {
            return Err(BackendError::InvalidInput(
                "invalid attendee participation status".into(),
            ));
        }
        property.add_parameter("PARTSTAT", &status);
    }
    if let Some(rsvp) = attendee.rsvp {
        property.add_parameter("RSVP", if rsvp { "TRUE" } else { "FALSE" });
    }
    Ok(property)
}

fn parse_icalendar_resource(
    raw: &str,
    config: &CalDavEngineConfig,
    source_message_id: Option<MessageId>,
) -> Result<ParsedEvent> {
    ensure_ical_size(raw, config)?;
    let components = raw
        .lines()
        .filter(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
        .take(config.max_resources_per_response + 1)
        .count();
    if components == 0 || components > config.max_resources_per_response {
        return Err(BackendError::CalDav(
            "calendar resource has an invalid VEVENT component count".into(),
        ));
    }
    let calendar = Calendar::from_str(raw)
        .map_err(|error| BackendError::CalDav(format!("invalid iCalendar resource: {error}")))?;
    let event = calendar
        .events()
        .find(|event| event.property_value("RECURRENCE-ID").is_none())
        .or_else(|| calendar.events().next())
        .ok_or_else(|| BackendError::CalDav("calendar resource contains no event".into()))?;
    let uid = event
        .property_value("UID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| BackendError::CalDav("calendar event has no UID".into()))?;
    validate_property_value("calendar UID", uid, 2_048)
        .map_err(|_| BackendError::CalDav("calendar event UID is invalid".into()))?;
    let attendees = event
        .multi_properties()
        .get("ATTENDEE")
        .into_iter()
        .flatten()
        .take(MAX_ATTENDEES + 1)
        .map(parse_attendee)
        .collect::<Result<Vec<_>>>()?;
    if attendees.len() > MAX_ATTENDEES {
        return Err(BackendError::CalDav(format!(
            "calendar event exceeds the {MAX_ATTENDEES}-attendee limit"
        )));
    }
    Ok(ParsedEvent {
        uid: uid.to_owned(),
        recurrence_id: event.property_value("RECURRENCE-ID").map(str::to_owned),
        summary: bounded_property(event.property_value("SUMMARY"), MAX_SUMMARY_BYTES),
        description: bounded_property(event.property_value("DESCRIPTION"), MAX_DESCRIPTION_BYTES),
        location: bounded_property(event.property_value("LOCATION"), MAX_LOCATION_BYTES),
        starts_at: event
            .properties()
            .get("DTSTART")
            .and_then(DatePerhapsTime::from_property)
            .map(convert_moment),
        ends_at: event
            .properties()
            .get("DTEND")
            .and_then(DatePerhapsTime::from_property)
            .map(convert_moment),
        organizer: bounded_property(event.property_value("ORGANIZER"), 8 * 1024),
        attendees,
        status: bounded_property(event.property_value("STATUS"), 128),
        raw_icalendar: raw.to_owned(),
        source_message_id,
    })
}

fn parse_attendee(property: &Property) -> Result<CalendarAttendee> {
    let calendar_address = property.value();
    validate_property_value("calendar attendee address", calendar_address, 8 * 1024)
        .map_err(|_| BackendError::CalDav("calendar attendee address is invalid".into()))?;
    // RFC 5545 defines ATTENDEE as a CAL-ADDRESS URI, not necessarily a
    // mailto address. Outbound drafts remain deliberately email-only, while
    // inbound resources must preserve legal URNs and provider-specific URIs.
    let address = calendar_address
        .strip_prefix("mailto:")
        .or_else(|| calendar_address.strip_prefix("MAILTO:"))
        .unwrap_or(calendar_address);
    let parameter = |name: &str| {
        property
            .params()
            .get(name)
            .map(|value| bounded_string(value.value().to_owned(), 2_048))
    };
    Ok(CalendarAttendee {
        address: address.to_owned(),
        display_name: parameter("CN"),
        role: parameter("ROLE"),
        participation_status: parameter("PARTSTAT"),
        rsvp: parameter("RSVP").and_then(|value| match value.to_ascii_uppercase().as_str() {
            "TRUE" => Some(true),
            "FALSE" => Some(false),
            _ => None,
        }),
    })
}

fn convert_moment(value: DatePerhapsTime) -> CalendarMoment {
    match value {
        DatePerhapsTime::Date(value) => CalendarMoment::Date { value },
        DatePerhapsTime::DateTime(IcalDateTime::Utc(value)) => CalendarMoment::Utc { value },
        DatePerhapsTime::DateTime(IcalDateTime::WithTimezone { date_time, tzid }) => {
            CalendarMoment::Local {
                value: date_time,
                timezone: tzid,
            }
        }
        DatePerhapsTime::DateTime(IcalDateTime::Floating(value)) => {
            CalendarMoment::Floating { value }
        }
    }
}

fn validate_moment_order(start: &CalendarMoment, end: &CalendarMoment) -> Result<()> {
    let valid = match (start, end) {
        (CalendarMoment::Date { value: start }, CalendarMoment::Date { value: end }) => end > start,
        (CalendarMoment::Utc { value: start }, CalendarMoment::Utc { value: end }) => end > start,
        (CalendarMoment::Floating { value: start }, CalendarMoment::Floating { value: end }) => {
            end > start
        }
        (
            CalendarMoment::Local {
                value: start,
                timezone: start_zone,
            },
            CalendarMoment::Local {
                value: end,
                timezone: end_zone,
            },
        ) if start_zone == end_zone => end > start,
        _ => true,
    };
    if !valid {
        return Err(BackendError::InvalidInput(
            "calendar event end must be after its start".into(),
        ));
    }
    Ok(())
}

async fn calendar_account_on(
    connection: &Connection,
    id: CalendarAccountId,
) -> Result<CalendarAccount> {
    let mut rows = connection
        .query(
            "SELECT id, name, base_url, username, credential_ref, principal_url, home_url, created_at, updated_at FROM calendar_accounts WHERE id = ?1",
            (id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| calendar_account_from_row(&row))
        .transpose()?
        .ok_or_else(|| not_found("calendar account", id))
}

fn calendar_account_from_row(row: &turso::Row) -> Result<CalendarAccount> {
    Ok(CalendarAccount {
        id: parse_id(row.get::<String>(0)?, "calendar account")?,
        name: row.get(1)?,
        base_url: row.get(2)?,
        username: row.get(3)?,
        credential_ref: row.get(4)?,
        principal_url: row.get(5)?,
        home_url: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

async fn calendar_collection_on(
    connection: &Connection,
    id: CalendarId,
) -> Result<CalendarCollection> {
    let mut rows = connection
        .query(
            "SELECT id, account_id, remote_url, display_name, description, color, supports_events, writable, sync_token, ctag, created_at, updated_at FROM calendar_collections WHERE id = ?1",
            (id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| calendar_collection_from_row(&row))
        .transpose()?
        .ok_or_else(|| not_found("calendar", id))
}

fn calendar_collection_from_row(row: &turso::Row) -> Result<CalendarCollection> {
    Ok(CalendarCollection {
        id: parse_id(row.get::<String>(0)?, "calendar")?,
        account_id: parse_id(row.get::<String>(1)?, "calendar account")?,
        remote_url: row.get(2)?,
        display_name: row.get(3)?,
        description: row.get(4)?,
        color: row.get(5)?,
        supports_events: row.get(6)?,
        writable: row.get(7)?,
        sync_token: row.get(8)?,
        ctag: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

async fn calendar_event_on(connection: &Connection, id: CalendarEventId) -> Result<CalendarEvent> {
    let mut rows = connection
        .query(
            "SELECT id, calendar_id, remote_href, etag, uid, recurrence_id, summary, description, location, starts_at_json, ends_at_json, organizer, attendees_json, status, raw_icalendar, source_message_id, created_at, updated_at FROM calendar_events WHERE id = ?1",
            (id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| calendar_event_from_row(&row))
        .transpose()?
        .ok_or_else(|| not_found("calendar event", id))
}

fn calendar_event_from_row(row: &turso::Row) -> Result<CalendarEvent> {
    Ok(CalendarEvent {
        id: parse_id(row.get::<String>(0)?, "calendar event")?,
        calendar_id: parse_id(row.get::<String>(1)?, "calendar")?,
        remote_href: row.get(2)?,
        etag: row.get(3)?,
        uid: row.get(4)?,
        recurrence_id: row.get(5)?,
        summary: row.get(6)?,
        description: row.get(7)?,
        location: row.get(8)?,
        starts_at: row
            .get::<Option<String>>(9)?
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        ends_at: row
            .get::<Option<String>>(10)?
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        organizer: row.get(11)?,
        attendees: serde_json::from_str(&row.get::<String>(12)?)?,
        status: row.get(13)?,
        raw_icalendar: row.get(14)?,
        source_message_id: row
            .get::<Option<String>>(15)?
            .map(|value| parse_id(value, "message"))
            .transpose()?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

async fn event_exists_on(
    connection: &Connection,
    calendar_id: CalendarId,
    href: &str,
) -> Result<bool> {
    Ok(event_id_by_href_on(connection, calendar_id, href)
        .await?
        .is_some())
}

async fn event_id_by_href_on(
    connection: &Connection,
    calendar_id: CalendarId,
    href: &str,
) -> Result<Option<CalendarEventId>> {
    let mut rows = connection
        .query(
            "SELECT id FROM calendar_events WHERE calendar_id = ?1 AND remote_href = ?2",
            (calendar_id.to_string(), href),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| parse_id(row.get::<String>(0)?, "calendar event"))
        .transpose()
}

async fn upsert_event_on(
    connection: &Connection,
    calendar_id: CalendarId,
    href: &str,
    etag: Option<String>,
    event: ParsedEvent,
    now: i64,
) -> Result<()> {
    let existing_id = event_id_by_href_on(connection, calendar_id, href).await?;
    let id = existing_id.unwrap_or_else(CalendarEventId::new);
    let existing_source = if existing_id.is_some() && event.source_message_id.is_none() {
        let mut rows = connection
            .query(
                "SELECT source_message_id FROM calendar_events WHERE id = ?1",
                (id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let requested_source = if let Some(message_id) = event.source_message_id {
        let mut rows = connection
            .query(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1)",
                (message_id.to_string(),),
            )
            .await?;
        let exists = rows
            .next()
            .await?
            .ok_or_else(|| BackendError::CalDav("message lookup returned no result".into()))?
            .get::<bool>(0)?;
        exists.then(|| message_id.to_string())
    } else {
        None
    };
    let source_message_id = requested_source.or(existing_source);
    connection
        .execute(
            "INSERT INTO calendar_events(id, calendar_id, remote_href, etag, uid, recurrence_id, summary, description, location, starts_at_json, ends_at_json, organizer, attendees_json, status, raw_icalendar, source_message_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) ON CONFLICT(calendar_id, remote_href) DO UPDATE SET etag = excluded.etag, uid = excluded.uid, recurrence_id = excluded.recurrence_id, summary = excluded.summary, description = excluded.description, location = excluded.location, starts_at_json = excluded.starts_at_json, ends_at_json = excluded.ends_at_json, organizer = excluded.organizer, attendees_json = excluded.attendees_json, status = excluded.status, raw_icalendar = excluded.raw_icalendar, source_message_id = COALESCE(excluded.source_message_id, calendar_events.source_message_id), updated_at = excluded.updated_at",
            turso::params![
                id.to_string(),
                calendar_id.to_string(),
                href,
                etag,
                event.uid,
                event.recurrence_id,
                event.summary,
                event.description,
                event.location,
                event.starts_at.map(|value| serde_json::to_string(&value)).transpose()?,
                event.ends_at.map(|value| serde_json::to_string(&value)).transpose()?,
                event.organizer,
                serde_json::to_string(&event.attendees)?,
                event.status,
                event.raw_icalendar,
                source_message_id,
                now,
                now,
            ],
        )
        .await?;
    Ok(())
}

fn validate_new_account(mut account: NewCalendarAccount) -> Result<NewCalendarAccount> {
    require_bounded_nonempty("calendar account name", &account.name, MAX_NAME_BYTES)?;
    require_bounded_nonempty("calendar username", &account.username, MAX_USERNAME_BYTES)?;
    require_bounded_nonempty(
        "calendar credential reference",
        &account.credential_ref,
        MAX_URL_BYTES,
    )?;
    let url = validated_endpoint(&account.base_url)?;
    account.base_url = url.to_string();
    Ok(account)
}

fn validate_engine_config(config: &CalDavEngineConfig) -> Result<()> {
    if config.request_timeout_seconds == 0
        || config.max_xml_response_bytes == 0
        || config.max_icalendar_resource_bytes == 0
        || config.max_resources_per_response == 0
        || config.max_xml_nodes == 0
    {
        return Err(BackendError::InvalidInput(
            "CalDAV resource limits must be nonzero".into(),
        ));
    }
    if config.request_timeout_seconds > MAX_REQUEST_TIMEOUT_SECONDS
        || config.max_xml_response_bytes > HARD_MAX_XML_RESPONSE_BYTES
        || config.max_icalendar_resource_bytes > HARD_MAX_ICALENDAR_RESOURCE_BYTES
        || config.max_resources_per_response > HARD_MAX_RESOURCES_PER_RESPONSE
        || config.max_xml_nodes > HARD_MAX_XML_NODES
    {
        return Err(BackendError::InvalidInput(
            "CalDAV resource limits exceed the backend safety ceiling".into(),
        ));
    }
    Ok(())
}

fn validated_endpoint(value: &str) -> Result<Url> {
    if value.len() > MAX_URL_BYTES {
        return Err(BackendError::InvalidInput("CalDAV URL is too long".into()));
    }
    let mut url = Url::parse(value).map_err(url_error)?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(BackendError::InvalidInput(
            "CalDAV endpoints must be absolute HTTPS URLs".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BackendError::InvalidInput(
            "CalDAV credentials must not be embedded in URLs".into(),
        ));
    }
    url.set_fragment(None);
    Ok(url)
}

fn origin_root(url: &Url) -> Result<Url> {
    let mut root = url.clone();
    root.set_path("/");
    root.set_query(None);
    root.set_fragment(None);
    Ok(root)
}

fn ensure_account_origin(account: &CalendarAccount, candidate: &Url) -> Result<()> {
    let configured = validated_endpoint(&account.base_url)?;
    if configured.scheme() != candidate.scheme()
        || configured.host_str() != candidate.host_str()
        || configured.port_or_known_default() != candidate.port_or_known_default()
    {
        return Err(BackendError::CalDav(
            "server supplied a cross-origin CalDAV URL; configure that canonical HTTPS origin explicitly before sending credentials"
                .into(),
        ));
    }
    Ok(())
}

fn validated_response_url(account: &CalendarAccount, value: &Url) -> Result<Url> {
    let url = validated_endpoint(value.as_str())?;
    ensure_account_origin(account, &url)?;
    Ok(url)
}

fn resolve_server_href(account: &CalendarAccount, base: &Url, href: &str) -> Result<Url> {
    if href.len() > MAX_URL_BYTES {
        return Err(BackendError::CalDav("server href is too long".into()));
    }
    let url = base
        .join(href.trim())
        .map_err(|error| BackendError::CalDav(format!("invalid server href: {error}")))?;
    let url = validated_endpoint(url.as_str())?;
    ensure_account_origin(account, &url)?;
    Ok(url)
}

fn url_error(error: url::ParseError) -> BackendError {
    BackendError::InvalidInput(format!("invalid CalDAV URL: {error}"))
}

fn http_status_error(operation: &str, response: &CalDavHttpResponse) -> BackendError {
    let detail = String::from_utf8_lossy(&response.body);
    let detail = detail
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>();
    let detail = bounded_string(detail.trim().to_owned(), MAX_ERROR_BODY_BYTES);
    BackendError::CalDav(if detail.is_empty() {
        format!("{operation} returned HTTP {}", response.status)
    } else {
        format!("{operation} returned HTTP {}: {detail}", response.status)
    })
}

fn ensure_ical_size(raw: &str, config: &CalDavEngineConfig) -> Result<()> {
    if raw.len() > config.max_icalendar_resource_bytes {
        return Err(BackendError::CalDav(format!(
            "calendar resource exceeds the {}-byte limit",
            config.max_icalendar_resource_bytes
        )));
    }
    Ok(())
}

fn validate_timezone(value: &str) -> Result<()> {
    validate_property_value("timezone", value, 512)?;
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "/_+-".contains(character)))
    {
        return Err(BackendError::InvalidInput(
            "timezone contains unsupported characters".into(),
        ));
    }
    Ok(())
}

fn validate_email_address(value: &str) -> Result<()> {
    validate_property_value("attendee address", value, 2_048)?;
    if value.starts_with('@')
        || value.ends_with('@')
        || value.matches('@').count() != 1
        || value.chars().any(char::is_whitespace)
    {
        return Err(BackendError::InvalidInput(
            "attendee address is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_property_value(label: &str, value: &str, maximum: usize) -> Result<()> {
    require_bounded_nonempty(label, value, maximum)?;
    if value.chars().any(char::is_control) {
        return Err(BackendError::InvalidInput(format!(
            "{label} contains control characters"
        )));
    }
    Ok(())
}

fn validate_ical_text(label: &str, value: &str) -> Result<()> {
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(BackendError::InvalidInput(format!(
            "{label} contains unsupported control characters"
        )));
    }
    Ok(())
}

fn require_bounded_nonempty(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(BackendError::InvalidInput(format!(
            "{label} cannot be empty"
        )));
    }
    if value.len() > maximum {
        return Err(BackendError::InvalidInput(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    Ok(())
}

fn bounded_property(value: Option<&str>, maximum: usize) -> Option<String> {
    value.map(|value| bounded_string(value.to_owned(), maximum))
}

fn bounded_string(mut value: String, maximum: usize) -> String {
    if value.len() > maximum {
        value.truncate(floor_char_boundary(&value, maximum));
    }
    value
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendConfig, CredentialStoragePolicy, IngestMessage, SecretValue};
    use chrono::{NaiveDate, TimeZone};
    use std::{collections::VecDeque, sync::Mutex};
    use tempfile::tempdir;

    struct FixedCredentials;

    impl CalDavCredentialProvider for FixedCredentials {
        fn resolve<'a>(&'a self, _reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>> {
            Box::pin(async {
                Ok(ImapCredential::OAuth2 {
                    access_token: SecretValue::new("token"),
                })
            })
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: Method,
        url: Url,
        if_match: Option<String>,
    }

    struct FakeTransport {
        responses: Mutex<VecDeque<CalDavHttpResponse>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<CalDavHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl CalDavTransport for FakeTransport {
        fn execute<'a>(
            &'a self,
            request: CalDavHttpRequest,
            _username: &'a str,
            _credential: &'a ImapCredential,
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<CalDavHttpResponse>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(RecordedRequest {
                    method: request.method.clone(),
                    url: request.url.clone(),
                    if_match: request.if_match.clone(),
                });
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| BackendError::CalDav("fake response queue is empty".into()))
            })
        }
    }

    fn response(status: u16, url: &str, body: impl Into<Vec<u8>>) -> CalDavHttpResponse {
        CalDavHttpResponse {
            status: StatusCode::from_u16(status).unwrap(),
            final_url: Url::parse(url).unwrap(),
            headers: std::collections::HashMap::new(),
            body: body.into(),
        }
    }

    fn multistatus(property: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/dav/</d:href><d:propstat><d:prop>{property}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
        )
    }

    async fn test_backend() -> (tempfile::TempDir, Backend) {
        let profile = tempdir().unwrap();
        let mut config = BackendConfig::new(profile.path());
        config.credential_storage = CredentialStoragePolicy::ProfileOnly;
        let backend = Backend::open(config).await.unwrap();
        (profile, backend)
    }

    #[tokio::test]
    async fn discovers_syncs_and_writes_calendar_events() {
        let (_profile, backend) = test_backend().await;
        let account = backend
            .calendar_accounts()
            .add(NewCalendarAccount {
                name: "Google Calendar".into(),
                base_url: "https://calendar.example/dav/".into(),
                username: "person@example.com".into(),
                credential_ref: "external:test-token".into(),
            })
            .await
            .unwrap();

        let discovery = multistatus(
            "<d:current-user-principal><d:href>/principals/person/</d:href></d:current-user-principal>",
        );
        let principal = multistatus(
            "<c:calendar-home-set><d:href>/calendars/person/</d:href></c:calendar-home-set>",
        );
        let listing = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/">
 <d:response><d:href>/calendars/person/primary/</d:href><d:propstat><d:prop>
  <d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Primary</d:displayname>
  <c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>
  <d:current-user-privilege-set><d:privilege><d:write/></d:privilege></d:current-user-privilege-set>
  <cs:getctag>ctag-1</cs:getctag>
 </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;
        let token = multistatus("<d:sync-token>token-1</d:sync-token>");
        let remote_ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:remote-1\r\nDTSTART:20261201T100000Z\r\nDTEND:20261201T110000Z\r\nSUMMARY:Remote meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let query = format!(
            r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/person/primary/remote-1.ics</d:href><d:propstat><d:prop><d:getetag>"one"</d:getetag><c:calendar-data>{}</c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
            xml_escape(remote_ical)
        );
        let delta = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:sync-token>token-2</d:sync-token></d:multistatus>"#;
        let created_ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:local-1\r\nDTSTART;VALUE=DATE:20261224\r\nDTEND;VALUE=DATE:20261225\r\nSUMMARY:Holiday\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let mut put = response(
            201,
            "https://calendar.example/calendars/person/primary/local.ics",
            "",
        );
        put.headers.insert("etag".into(), "\"two\"".into());
        put.headers.insert(
            "location".into(),
            "/calendars/person/primary/local.ics".into(),
        );
        let mut get = response(
            200,
            "https://calendar.example/calendars/person/primary/local.ics",
            created_ical,
        );
        get.headers.insert("etag".into(), "\"two\"".into());

        let transport = Arc::new(FakeTransport::new(vec![
            response(207, "https://calendar.example/dav/", discovery),
            response(
                207,
                "https://calendar.example/principals/person/",
                principal,
            ),
            response(207, "https://calendar.example/calendars/person/", listing),
            response(
                207,
                "https://calendar.example/calendars/person/primary/",
                token,
            ),
            response(
                207,
                "https://calendar.example/calendars/person/primary/",
                query,
            ),
            response(
                207,
                "https://calendar.example/calendars/person/primary/",
                delta,
            ),
            put,
            get,
        ]));
        let engine = CalDavEngine::with_transport(
            backend.clone(),
            Arc::new(FixedCredentials),
            CalDavEngineConfig::default(),
            transport.clone(),
        )
        .unwrap();

        let discovered = engine.discover(account.id).await.unwrap();
        assert_eq!(discovered.calendars.len(), 1);
        assert_eq!(discovered.calendars[0].display_name, "Primary");
        assert!(discovered.calendars[0].writable);

        let synced = engine
            .sync_calendar(discovered.calendars[0].id)
            .await
            .unwrap();
        assert!(synced.full_sync);
        assert_eq!(synced.created, 1);
        assert_eq!(synced.sync_token.as_deref(), Some("token-2"));
        let events = backend
            .calendars()
            .list_events(CalendarEventFilter::new(discovered.calendars[0].id))
            .await
            .unwrap();
        assert_eq!(events.items[0].summary.as_deref(), Some("Remote meeting"));

        let created = engine
            .create_event(
                discovered.calendars[0].id,
                CalendarEventDraft {
                    uid: Some("local-1".into()),
                    summary: "Holiday".into(),
                    description: None,
                    location: None,
                    starts_at: Some(CalendarMoment::Date {
                        value: NaiveDate::from_ymd_opt(2026, 12, 24).unwrap(),
                    }),
                    ends_at: Some(CalendarMoment::Date {
                        value: NaiveDate::from_ymd_opt(2026, 12, 25).unwrap(),
                    }),
                    attendees: Vec::new(),
                    status: Some("confirmed".into()),
                    source_message_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(created.uid, "local-1");
        assert_eq!(created.etag.as_deref(), Some("\"two\""));

        let mut first_page_filter = CalendarEventFilter::new(discovered.calendars[0].id);
        first_page_filter.page_size = 1;
        let first_page = backend
            .calendars()
            .list_events(first_page_filter)
            .await
            .unwrap();
        assert_eq!(first_page.items.len(), 1);
        let mut second_page_filter = CalendarEventFilter::new(discovered.calendars[0].id);
        second_page_filter.page_size = 1;
        second_page_filter.cursor = first_page.next_cursor;
        let second_page = backend
            .calendars()
            .list_events(second_page_filter)
            .await
            .unwrap();
        assert_eq!(second_page.items.len(), 1);
        assert_ne!(first_page.items[0].id, second_page.items[0].id);

        {
            let requests = transport.requests.lock().unwrap();
            assert!(requests.iter().any(|request| {
                request.method == Method::PUT && request.if_match.as_deref() == Some("*")
            }));
            assert!(requests
                .iter()
                .all(|request| request.url.host_str() == Some("calendar.example")));
        }

        backend
            .calendar_accounts()
            .update(
                account.id,
                NewCalendarAccount {
                    name: account.name,
                    base_url: account.base_url,
                    username: "another-person@example.com".into(),
                    credential_ref: account.credential_ref,
                },
            )
            .await
            .unwrap();
        assert!(backend
            .calendars()
            .list(Some(account.id))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn message_conversion_is_only_a_proposal() {
        let (_profile, backend) = test_backend().await;
        let message_id = backend
            .ingest(IngestMessage::local(
                b"From: person@example.test\r\nTo: me@example.test\r\nSubject: Discuss the launch\r\n\r\nCan we meet next week?"
                    .to_vec(),
            ))
            .await
            .unwrap();
        let draft = backend
            .calendars()
            .draft_from_message(message_id)
            .await
            .unwrap();
        assert_eq!(draft.summary, "Discuss the launch");
        assert_eq!(draft.source_message_id, Some(message_id));
        assert!(draft.starts_at.is_none());
        assert!(draft.ends_at.is_none());
        assert!(backend.calendars().list(None).await.unwrap().is_empty());
    }

    #[test]
    fn event_round_trip_preserves_time_forms_and_rejects_bad_order() {
        let start = CalendarMoment::Utc {
            value: Utc.with_ymd_and_hms(2026, 11, 20, 10, 0, 0).unwrap(),
        };
        let end = CalendarMoment::Utc {
            value: Utc.with_ymd_and_hms(2026, 11, 20, 11, 0, 0).unwrap(),
        };
        let (raw, _) = build_icalendar(
            CalendarEventDraft {
                uid: Some("roundtrip@example.test".into()),
                summary: "Round trip".into(),
                description: Some("line one\nline two".into()),
                location: None,
                starts_at: Some(start.clone()),
                ends_at: Some(end.clone()),
                attendees: Vec::new(),
                status: None,
                source_message_id: None,
            },
            None,
        )
        .unwrap();
        let parsed = parse_icalendar_resource(&raw, &CalDavEngineConfig::default(), None).unwrap();
        assert_eq!(parsed.starts_at, Some(start));
        assert_eq!(parsed.ends_at, Some(end.clone()));

        let invalid = CalendarEventDraft {
            uid: None,
            summary: "Backwards".into(),
            description: None,
            location: None,
            starts_at: Some(end),
            ends_at: parsed.starts_at,
            attendees: Vec::new(),
            status: None,
            source_message_id: None,
        };
        assert!(build_icalendar(invalid, None).is_err());
    }

    #[test]
    fn local_message_link_is_not_published_in_icalendar() {
        let message_id = MessageId::new();
        let (raw, linked_message) = build_icalendar(
            CalendarEventDraft {
                uid: Some("private-link@example.test".into()),
                summary: "Private local link".into(),
                description: None,
                location: None,
                starts_at: Some(CalendarMoment::Date {
                    value: NaiveDate::from_ymd_opt(2026, 11, 20).unwrap(),
                }),
                ends_at: Some(CalendarMoment::Date {
                    value: NaiveDate::from_ymd_opt(2026, 11, 21).unwrap(),
                }),
                attendees: Vec::new(),
                status: None,
                source_message_id: Some(message_id),
            },
            None,
        )
        .unwrap();
        assert_eq!(linked_message, Some(message_id));
        assert!(!raw.contains("X-LIZARD-SOURCE-MESSAGE"));
        assert!(!raw.contains(&message_id.to_string()));
    }

    #[test]
    fn inbound_non_email_calendar_addresses_are_preserved() {
        let raw = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:urn-attendee\r\nSUMMARY:Room booking\r\nATTENDEE;CN=Conference Room:urn:uuid:01234567-89ab-cdef-0123-456789abcdef\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let parsed = parse_icalendar_resource(raw, &CalDavEngineConfig::default(), None).unwrap();
        assert_eq!(parsed.attendees.len(), 1);
        assert_eq!(
            parsed.attendees[0].address,
            "urn:uuid:01234567-89ab-cdef-0123-456789abcdef"
        );
    }

    #[test]
    fn http_errors_do_not_emit_raw_control_characters() {
        let response = response(
            500,
            "https://calendar.example/",
            b"bad\x1b[31mserver".to_vec(),
        );
        let error = http_status_error("test", &response).to_string();
        assert!(!error.contains('\x1b'));
        assert!(error.contains("bad\u{fffd}[31mserver"));
    }

    #[test]
    fn discovery_rejects_cross_origin_calendar_hrefs() {
        let account = CalendarAccount {
            id: CalendarAccountId::new(),
            name: "Calendar".into(),
            base_url: "https://good.example/dav/".into(),
            username: "user".into(),
            credential_ref: "external:test".into(),
            principal_url: None,
            home_url: None,
            created_at: 0,
            updated_at: 0,
        };
        let xml = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>https://evil.example/calendar/</d:href><d:propstat><d:prop><d:resourcetype><c:calendar/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        let document = Document::parse(xml).unwrap();
        assert!(parse_calendar_collections(
            &document,
            &account,
            &Url::parse(&account.base_url).unwrap(),
            10,
        )
        .is_err());
    }

    #[test]
    fn dav_parsing_rejects_namespace_spoofs_and_failed_resource_rows() {
        let spoofed = Document::parse(
            r#"<d:multistatus xmlns:d="DAV:" xmlns:e="urn:evil"><e:current-user-principal><d:href>/stolen/</d:href></e:current-user-principal></d:multistatus>"#,
        )
        .unwrap();
        assert!(find_property_href(&spoofed, DAV_NAMESPACE, "current-user-principal").is_none());

        let account = CalendarAccount {
            id: CalendarAccountId::new(),
            name: "Calendar".into(),
            base_url: "https://calendar.example/dav/".into(),
            username: "user".into(),
            credential_ref: "external:test".into(),
            principal_url: None,
            home_url: None,
            created_at: 0,
            updated_at: 0,
        };
        let failed = Document::parse(
            r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/event.ics</d:href><d:status>HTTP/1.1 507 Insufficient Storage</d:status></d:response></d:multistatus>"#,
        )
        .unwrap();
        assert!(parse_resource_changes(
            &failed,
            &account,
            &Url::parse(&account.base_url).unwrap(),
            10,
            1024,
        )
        .is_err());
    }
}
