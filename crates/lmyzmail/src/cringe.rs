use std::{fmt, future::Future, time::Duration};

use chrono::{DateTime, Utc};
use deadpool_postgres::{Object, Pool};
use serde::Serialize;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, NoTls, Row};
use tokio_util::sync::CancellationToken;

const DATABASE_DEADLINE: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PAGE_SIZE: i64 = 500;
const MAX_EXPORT_ROWS: i64 = 10_000;

const IP_COLUMNS: &str = "ip_address, total_score, current_score, activity_count, \
    self_spoofing_count, open_relay_count, auth_probe_count, illegal_domain_count, \
    spamhaus_count, http_on_smtp_count, ssh_on_smtp_count, http_port_scanning_count, \
    honeypot_hit_count, ssh_bruteforce_count, other_count, first_seen_at, last_seen_at, \
    last_decay_at";

const ACTIVITY_COLUMNS: &str = "id, ip_address, activity_type, score, timestamp, mail_from, \
    rcpt_to, helo_name, session_id, response_message, metadata";

#[derive(Clone)]
pub struct CringeService {
    pool: Pool,
}

impl CringeService {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn above_score(
        &self,
        min_score: i32,
        current: bool,
        cancellation: &CancellationToken,
    ) -> Result<Vec<CringeIp>, CringeError> {
        let score_column = if current {
            "current_score"
        } else {
            "total_score"
        };
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let sql = format!(
            "SELECT {IP_COLUMNS} FROM skibidi_cringe_ip \
             WHERE {score_column} >= $1 ORDER BY {score_column} DESC \
             LIMIT {MAX_EXPORT_ROWS}"
        );
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let rows = connection
                .client()
                .query(&sql, &[&min_score])
                .await
                .map_err(database_error)?;
            Ok(rows.iter().map(cringe_ip_from_row).collect())
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn insults(
        &self,
        query: PageQuery,
        cancellation: &CancellationToken,
    ) -> Result<ActivityPage, CringeError> {
        let (page, size) = validated_page(query.page, query.size)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(
            deadline,
            cancellation,
            &cancel_token,
            activity_page_query(
                connection.client(),
                ActivityFilter::Insults(normalized_search(&query.search)),
                page,
                size.min(200),
            ),
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn activities(
        &self,
        ip_address: &str,
        fallback_ip_address: Option<&str>,
        page: i64,
        size: i64,
        cancellation: &CancellationToken,
    ) -> Result<ActivityPage, CringeError> {
        let (page, size) = validated_page(page, size)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let result = activity_page_query(
                connection.client(),
                ActivityFilter::Ip(ip_address.to_owned()),
                page,
                size,
            )
            .await?;
            if !result.empty {
                return Ok(result);
            }
            match fallback_ip_address.filter(|fallback| *fallback != ip_address) {
                Some(fallback) => {
                    activity_page_query(
                        connection.client(),
                        ActivityFilter::Ip(fallback.to_owned()),
                        page,
                        size,
                    )
                    .await
                }
                None => Ok(result),
            }
        })
        .await;
        connection.finish(outcome)
    }

    async fn client(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, CringeError> {
        wait_database(self.pool.get(), deadline, cancellation).await
    }
}

async fn activity_page_query(
    client: &Object,
    filter: ActivityFilter,
    page: i64,
    size: i64,
) -> Result<ActivityPage, CringeError> {
    let offset = page.checked_mul(size).ok_or(CringeError::InvalidInput)?;
    let (rows, total_elements) = match filter {
        ActivityFilter::Ip(ip_address) => {
            let sql = format!(
                "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                     WHERE ip_address = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3"
            );
            let rows = client
                .query(&sql, &[&ip_address, &size, &offset])
                .await
                .map_err(database_error)?;
            let total = client
                .query_one(
                    "SELECT COUNT(*) FROM skibidi_cringe_ip_activity WHERE ip_address = $1",
                    &[&ip_address],
                )
                .await
                .map_err(database_error)?
                .get::<_, i64>(0);
            (rows, total)
        }
        ActivityFilter::Insults(search) => {
            if let Some(search) = search {
                let pattern = format!("%{search}%");
                let sql = format!(
                    "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' AND LOWER(ip_address) LIKE LOWER($1) \
                         ORDER BY timestamp DESC LIMIT $2 OFFSET $3"
                );
                let rows = client
                    .query(&sql, &[&pattern, &size, &offset])
                    .await
                    .map_err(database_error)?;
                let total = client
                    .query_one(
                        "SELECT COUNT(*) FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' AND LOWER(ip_address) LIKE LOWER($1)",
                        &[&pattern],
                    )
                    .await
                    .map_err(database_error)?
                    .get::<_, i64>(0);
                (rows, total)
            } else {
                let sql = format!(
                    "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
                );
                let rows = client
                    .query(&sql, &[&size, &offset])
                    .await
                    .map_err(database_error)?;
                let total = client
                    .query_one(
                        "SELECT COUNT(*) FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> ''",
                        &[],
                    )
                    .await
                    .map_err(database_error)?
                    .get::<_, i64>(0);
                (rows, total)
            }
        }
    };
    Ok(ActivityPage::new(
        rows.iter().map(activity_from_row).collect(),
        page,
        size,
        total_elements,
    ))
}

enum ActivityFilter {
    Ip(String),
    Insults(Option<String>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PageQuery {
    pub page: i64,
    pub size: i64,
    pub search: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityPage {
    pub content: Vec<CringeActivity>,
    pub pageable: Pageable,
    pub last: bool,
    pub total_elements: i64,
    pub total_pages: i64,
    pub first: bool,
    pub size: i64,
    pub number: i64,
    pub sort: PageSort,
    pub number_of_elements: i64,
    pub empty: bool,
}

impl ActivityPage {
    fn new(content: Vec<CringeActivity>, page: i64, size: i64, total_elements: i64) -> Self {
        let total_pages = page_count(total_elements, size);
        let number_of_elements = content.len() as i64;
        Self {
            content,
            pageable: Pageable {
                page_number: page,
                page_size: size,
                sort: PageSort::unsorted(),
                offset: page * size,
                paged: true,
                unpaged: false,
            },
            last: page + 1 >= total_pages,
            total_elements,
            total_pages,
            first: page == 0,
            size,
            number: page,
            sort: PageSort::unsorted(),
            number_of_elements,
            empty: number_of_elements == 0,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pageable {
    pub page_number: i64,
    pub page_size: i64,
    pub sort: PageSort,
    pub offset: i64,
    pub paged: bool,
    pub unpaged: bool,
}

#[derive(Debug, Serialize)]
pub struct PageSort {
    pub sorted: bool,
    pub empty: bool,
    pub unsorted: bool,
}

impl PageSort {
    const fn unsorted() -> Self {
        Self {
            sorted: false,
            empty: true,
            unsorted: true,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CringeIp {
    pub ip_address: String,
    pub total_score: i32,
    pub current_score: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_decay_at: Option<String>,
    pub activity_count: i32,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub self_spoofing_count: i32,
    pub open_relay_count: i32,
    pub auth_probe_count: i32,
    pub illegal_domain_count: i32,
    pub spamhaus_count: i32,
    pub http_on_smtp_count: i32,
    pub ssh_on_smtp_count: i32,
    pub http_port_scanning_count: i32,
    pub honeypot_hit_count: i32,
    pub ssh_bruteforce_count: i32,
    pub other_count: i32,
    pub protocol_mismatch_count: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CringeActivity {
    pub id: i64,
    pub ip_address: String,
    pub activity_type: String,
    pub score: i32,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcpt_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helo_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

#[derive(Debug)]
pub enum CringeError {
    Cancelled,
    Timeout,
    InvalidInput,
    Database(String),
}

impl fmt::Display for CringeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("cringe request cancelled"),
            Self::Timeout => formatter.write_str("cringe database deadline exceeded"),
            Self::InvalidInput => formatter.write_str("invalid cringe request"),
            Self::Database(error) => write!(formatter, "cringe database failure: {error}"),
        }
    }
}

impl std::error::Error for CringeError {}

fn cringe_ip_from_row(row: &Row) -> CringeIp {
    let http_on_smtp_count = nullable_count(row, "http_on_smtp_count");
    let ssh_on_smtp_count = nullable_count(row, "ssh_on_smtp_count");
    let http_port_scanning_count = nullable_count(row, "http_port_scanning_count");
    CringeIp {
        ip_address: row.get("ip_address"),
        total_score: row.get("total_score"),
        current_score: row.get("current_score"),
        last_decay_at: row
            .get::<_, Option<DateTime<Utc>>>("last_decay_at")
            .map(instant),
        activity_count: row.get("activity_count"),
        first_seen_at: instant(row.get("first_seen_at")),
        last_seen_at: instant(row.get("last_seen_at")),
        self_spoofing_count: nullable_count(row, "self_spoofing_count"),
        open_relay_count: nullable_count(row, "open_relay_count"),
        auth_probe_count: nullable_count(row, "auth_probe_count"),
        illegal_domain_count: nullable_count(row, "illegal_domain_count"),
        spamhaus_count: nullable_count(row, "spamhaus_count"),
        http_on_smtp_count,
        ssh_on_smtp_count,
        http_port_scanning_count,
        honeypot_hit_count: nullable_count(row, "honeypot_hit_count"),
        ssh_bruteforce_count: nullable_count(row, "ssh_bruteforce_count"),
        other_count: nullable_count(row, "other_count"),
        protocol_mismatch_count: http_on_smtp_count
            .wrapping_add(ssh_on_smtp_count)
            .wrapping_add(http_port_scanning_count),
    }
}

fn activity_from_row(row: &Row) -> CringeActivity {
    CringeActivity {
        id: row.get("id"),
        ip_address: row.get("ip_address"),
        activity_type: row.get("activity_type"),
        score: row.get("score"),
        timestamp: instant(row.get("timestamp")),
        mail_from: row.get("mail_from"),
        rcpt_to: row.get("rcpt_to"),
        helo_name: row.get("helo_name"),
        session_id: row.get("session_id"),
        response_message: row.get("response_message"),
        metadata: row.get("metadata"),
    }
}

fn nullable_count(row: &Row, column: &str) -> i32 {
    row.get::<_, Option<i32>>(column).unwrap_or_default()
}

fn instant(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

fn page_count(total: i64, size: i64) -> i64 {
    if total == 0 {
        0
    } else {
        (total - 1) / size + 1
    }
}

fn validated_page(page: i64, size: i64) -> Result<(i64, i64), CringeError> {
    if page < 0 || page > i64::from(i32::MAX) || size <= 0 || size > i64::from(i32::MAX) {
        return Err(CringeError::InvalidInput);
    }
    Ok((page, size.min(MAX_PAGE_SIZE)))
}

fn normalized_search(search: &str) -> Option<String> {
    let search = search.trim();
    (!search.is_empty()).then(|| search.to_owned())
}

async fn wait_database<T, E, F>(
    future: F,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, CringeError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(CringeError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(CringeError::Database(error.to_string())),
            Err(_) => Err(CringeError::Timeout),
        }
    }
}

fn database_error(error: tokio_postgres::Error) -> CringeError {
    CringeError::Database(error.to_string())
}

struct DatabaseOutcome<T> {
    result: Result<T, CringeError>,
    discard_connection: bool,
}

struct DatabaseConnection {
    client: Option<Object>,
}

impl DatabaseConnection {
    fn new(client: Object) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn client(&self) -> &Object {
        self.client
            .as_ref()
            .expect("database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client().cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, CringeError> {
        let client = self.client.take().expect("database connection is present");
        if outcome.discard_connection {
            drop(Object::take(client));
        } else {
            drop(client);
        }
        outcome.result
    }
}

impl Drop for DatabaseConnection {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
    }
}

async fn database_read<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    future: F,
) -> DatabaseOutcome<T>
where
    F: Future<Output = Result<T, CringeError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => CringeError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return DatabaseOutcome {
                result,
                discard_connection: false,
            },
            Err(_) => CringeError::Timeout,
        },
    };

    let recovery = timeout_at(Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    let discard_connection = !matches!(recovery, Ok((Ok(()), _)));
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(id: i64) -> CringeActivity {
        CringeActivity {
            id,
            ip_address: "203.0.113.77".to_owned(),
            activity_type: "SELF_SPOOFING".to_owned(),
            score: 10,
            timestamp: "2024-01-02T03:04:05.123456Z".to_owned(),
            mail_from: Some("from@example.test".to_owned()),
            rcpt_to: None,
            helo_name: None,
            session_id: Some("session-1".to_owned()),
            response_message: Some("insult".to_owned()),
            metadata: None,
        }
    }

    #[test]
    fn page_counts_are_stable() {
        assert_eq!(page_count(0, 50), 0);
        assert_eq!(page_count(1, 50), 1);
        assert_eq!(page_count(51, 50), 2);
    }

    #[test]
    fn paging_rejects_invalid_java_integer_inputs_and_caps_valid_sizes() {
        assert!(matches!(
            validated_page(-1, 50),
            Err(CringeError::InvalidInput)
        ));
        assert!(matches!(
            validated_page(0, 0),
            Err(CringeError::InvalidInput)
        ));
        assert!(matches!(
            validated_page(i64::from(i32::MAX) + 1, 50),
            Err(CringeError::InvalidInput)
        ));
        assert_eq!(validated_page(2, 501).expect("valid page"), (2, 500));
    }

    #[test]
    fn activity_page_matches_spring_page_shape_and_order() {
        let json = serde_json::to_string(&ActivityPage::new(vec![activity(7)], 0, 50, 1))
            .expect("page must serialize");
        assert_eq!(
            json,
            r#"{"content":[{"id":7,"ipAddress":"203.0.113.77","activityType":"SELF_SPOOFING","score":10,"timestamp":"2024-01-02T03:04:05.123456Z","mailFrom":"from@example.test","sessionId":"session-1","responseMessage":"insult"}],"pageable":{"pageNumber":0,"pageSize":50,"sort":{"sorted":false,"empty":true,"unsorted":true},"offset":0,"paged":true,"unpaged":false},"last":true,"totalElements":1,"totalPages":1,"first":true,"size":50,"number":0,"sort":{"sorted":false,"empty":true,"unsorted":true},"numberOfElements":1,"empty":false}"#
        );
    }

    #[test]
    fn optional_cringe_fields_match_jackson_non_null_serialization() {
        let activity_json = serde_json::to_value(CringeActivity {
            response_message: Some(String::new()),
            ..activity(8)
        })
        .expect("activity must serialize");
        assert_eq!(activity_json["responseMessage"], "");
        assert!(activity_json.get("rcptTo").is_none());
        assert!(activity_json.get("heloName").is_none());
        assert!(activity_json.get("metadata").is_none());

        let ip_json = serde_json::to_value(CringeIp {
            ip_address: "198.51.100.9".to_owned(),
            total_score: 5,
            current_score: 19,
            last_decay_at: None,
            activity_count: 1,
            first_seen_at: "2024-01-01T12:00:00Z".to_owned(),
            last_seen_at: "2024-01-04T00:00:00Z".to_owned(),
            self_spoofing_count: 1,
            open_relay_count: 0,
            auth_probe_count: 0,
            illegal_domain_count: 0,
            spamhaus_count: 0,
            http_on_smtp_count: 0,
            ssh_on_smtp_count: 0,
            http_port_scanning_count: 0,
            honeypot_hit_count: 0,
            ssh_bruteforce_count: 0,
            other_count: 0,
            protocol_mismatch_count: 0,
        })
        .expect("IP must serialize");
        assert!(ip_json.get("lastDecayAt").is_none());
    }

    #[test]
    fn empty_page_matches_spring_terminal_flags() {
        let json = serde_json::to_value(ActivityPage::new(Vec::new(), 0, 50, 0))
            .expect("page must serialize");
        assert_eq!(json["last"], true);
        assert_eq!(json["first"], true);
        assert_eq!(json["empty"], true);
        assert_eq!(json["totalPages"], 0);
        assert_eq!(json["numberOfElements"], 0);
    }
}
