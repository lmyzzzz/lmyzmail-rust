use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use deadpool_postgres::{Object, Pool};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, IsolationLevel, NoTls};
use tokio_util::sync::CancellationToken;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CONTACTS: i64 = 10_000;
const CONTACT_QUERY_LIMIT: i64 = MAX_CONTACTS + 1;
const MAX_CONTACT_FIELD_BYTES: i64 = 16 * 1024 * 1024;
const MAX_CONTACT_TEXT_CHARS: usize = 255;

#[derive(Debug)]
pub enum UserDataError {
    Cancelled,
    Database(String),
    InvalidInput(String),
    LimitExceeded,
    OutcomeUnknown,
}

impl fmt::Display for UserDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("userdata operation cancelled"),
            Self::Database(_) => formatter.write_str("userdata backend unavailable"),
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::LimitExceeded => formatter.write_str("userdata limit exceeded"),
            Self::OutcomeUnknown => formatter.write_str("userdata mutation outcome unknown"),
        }
    }
}

impl std::error::Error for UserDataError {}

#[derive(Debug, Clone, Serialize)]
pub struct ContactRecord {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone)]
pub struct UserDataService {
    pool: Pool,
}

impl UserDataService {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn get_preferences(
        &self,
        mailbox: &str,
        cancellation: &CancellationToken,
    ) -> Result<Map<String, Value>, UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "preferences query",
            async {
                let transaction = connection
                    .client_mut()
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(|error| database_error("preferences transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                let row = transaction
                    .query_opt(
                        "SELECT preferences_json FROM user_preference WHERE mailbox_address=$1",
                        &[&mailbox],
                    )
                    .await
                    .map_err(|error| database_error("preferences query", error))?;
                ensure_active(&database_cancellation)?;
                transaction
                    .rollback()
                    .await
                    .map_err(|error| database_error("preferences rollback", error))?;
                Ok(row)
            },
        )
        .await;
        let row = connection.finish(outcome)?;
        let Some(raw) = row.and_then(|row| row.get::<_, Option<String>>(0)) else {
            return Ok(Map::new());
        };
        let Ok(mut value) = serde_json::from_str::<Value>(&raw) else {
            return Ok(Map::new());
        };
        strip_null_object_members(&mut value);
        match value {
            Value::Object(preferences) => Ok(preferences),
            _ => Ok(Map::new()),
        }
    }

    pub async fn save_preferences(
        &self,
        mailbox: &str,
        preferences: Map<String, Value>,
        cancellation: &CancellationToken,
    ) -> Result<(), UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let encoded = serde_json::to_string(&preferences)
            .map_err(|error| UserDataError::InvalidInput(error.to_string()))?;
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "preferences mutation",
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("preferences transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                transaction
                    .execute(
                        "INSERT INTO user_preference
                         (mailbox_address, preferences_json, created_at, updated_at)
                         VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                         ON CONFLICT (mailbox_address) DO UPDATE SET
                             preferences_json=EXCLUDED.preferences_json,
                             updated_at=CURRENT_TIMESTAMP",
                        &[&mailbox, &encoded],
                    )
                    .await
                    .map_err(|error| database_error("preferences upsert", error))?;
                start_commit(
                    deadline,
                    &database_cancellation,
                    &commit_started,
                    "preferences commit",
                )?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("preferences commit", error))?;
                Ok(())
            },
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn list_contacts(
        &self,
        mailbox: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ContactRecord>, UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "contacts snapshot",
            async {
                let transaction = connection
                    .client_mut()
                    .build_transaction()
                    .isolation_level(IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start()
                    .await
                    .map_err(|error| database_error("contacts snapshot", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                let count_row = transaction
                    .query_one(
                        "WITH bounded_contacts AS MATERIALIZED (
                             SELECT 1
                             FROM contact
                             WHERE mailbox_address=$1
                             LIMIT $2
                         )
                         SELECT COUNT(*)::BIGINT FROM bounded_contacts",
                        &[&mailbox, &CONTACT_QUERY_LIMIT],
                    )
                    .await
                    .map_err(|error| database_error("contacts count query", error))?;
                let count: i64 = count_row.get(0);
                if count > MAX_CONTACTS {
                    ensure_active(&database_cancellation)?;
                    transaction
                        .rollback()
                        .await
                        .map_err(|error| database_error("contacts snapshot rollback", error))?;
                    return Err(UserDataError::LimitExceeded);
                }
                ensure_active(&database_cancellation)?;
                let byte_row = transaction
                    .query_one(
                        "WITH bounded_contacts AS MATERIALIZED (
                             SELECT name, email, notes
                             FROM contact
                             WHERE mailbox_address=$1
                             LIMIT $2
                         )
                         SELECT COALESCE(SUM(
                                    COALESCE(octet_length(name), 0)::BIGINT
                                    + octet_length(email)::BIGINT
                                    + COALESCE(octet_length(notes), 0)::BIGINT
                                ), 0)::BIGINT FROM bounded_contacts",
                        &[&mailbox, &MAX_CONTACTS],
                    )
                    .await
                    .map_err(|error| database_error("contacts byte budget query", error))?;
                let field_bytes: i64 = byte_row.get(0);
                if field_bytes > MAX_CONTACT_FIELD_BYTES {
                    ensure_active(&database_cancellation)?;
                    transaction
                        .rollback()
                        .await
                        .map_err(|error| database_error("contacts snapshot rollback", error))?;
                    return Err(UserDataError::LimitExceeded);
                }
                ensure_active(&database_cancellation)?;
                let rows = transaction
                    .query(
                        "SELECT id, name, email, notes
                         FROM contact
                         WHERE mailbox_address=$1
                         ORDER BY name ASC, id ASC
                         LIMIT $2",
                        &[&mailbox, &MAX_CONTACTS],
                    )
                    .await
                    .map_err(|error| database_error("contacts query", error))?;
                ensure_active(&database_cancellation)?;
                transaction
                    .rollback()
                    .await
                    .map_err(|error| database_error("contacts snapshot rollback", error))?;
                Ok(rows
                    .into_iter()
                    .map(|row| ContactRecord {
                        id: row.get(0),
                        name: row.get(1),
                        email: row.get(2),
                        notes: row.get(3),
                    })
                    .collect())
            },
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn add_contact(
        &self,
        mailbox: &str,
        name: Option<&str>,
        email: Option<&str>,
        notes: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<ContactRecord, UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let name = validate_contact_text(name, "Invalid contact name")?;
        let email = validate_contact_text(email, "Invalid contact email")?.to_lowercase();
        if email.chars().count() > MAX_CONTACT_TEXT_CHARS {
            return Err(UserDataError::InvalidInput("Invalid contact email".into()));
        }
        let notes = notes.map(str::to_owned);
        let lock_key = contact_admission_lock_key(&mailbox, &email);
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "contact mutation",
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("contact transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                transaction
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])
                    .await
                    .map_err(|error| database_error("contact admission lock", error))?;
                ensure_active(&database_cancellation)?;
                let duplicate = transaction
                    .query_opt(
                        "SELECT id FROM contact WHERE mailbox_address=$1 AND email=$2 LIMIT 1",
                        &[&mailbox, &email],
                    )
                    .await
                    .map_err(|error| database_error("contact duplicate query", error))?;
                if duplicate.is_some() {
                    ensure_active(&database_cancellation)?;
                    transaction
                        .rollback()
                        .await
                        .map_err(|error| database_error("duplicate contact rollback", error))?;
                    return Err(UserDataError::InvalidInput("Contact already exists".into()));
                }
                ensure_active(&database_cancellation)?;
                let row = transaction
                    .query_one(
                        "INSERT INTO contact
                         (mailbox_address, name, email, notes, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                         RETURNING id, name, email, notes",
                        &[&mailbox, &name, &email, &notes],
                    )
                    .await
                    .map_err(|error| database_error("contact insert", error))?;
                let contact = contact_from_row(&row);
                start_commit(
                    deadline,
                    &database_cancellation,
                    &commit_started,
                    "contact commit",
                )?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("contact commit", error))?;
                Ok(contact)
            },
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn update_contact(
        &self,
        mailbox: &str,
        id: i64,
        name: Option<&str>,
        email: Option<&str>,
        notes: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<ContactRecord, UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let name = validate_contact_text(name, "Invalid contact name")?;
        let email = validate_contact_text(email, "Invalid contact email")?.to_lowercase();
        if email.chars().count() > MAX_CONTACT_TEXT_CHARS {
            return Err(UserDataError::InvalidInput("Invalid contact email".into()));
        }
        let notes = notes.map(str::to_owned);
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "contact update",
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("contact update transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                let row = transaction
                    .query_opt(
                        "UPDATE contact
                         SET name=$1, email=$2, notes=$3, updated_at=CURRENT_TIMESTAMP
                         WHERE mailbox_address=$4 AND id=$5
                         RETURNING id, name, email, notes",
                        &[&name, &email, &notes, &mailbox, &id],
                    )
                    .await
                    .map_err(|error| database_error("contact update", error))?
                    .ok_or_else(|| UserDataError::InvalidInput("Contact not found".into()))?;
                let contact = contact_from_row(&row);
                start_commit(
                    deadline,
                    &database_cancellation,
                    &commit_started,
                    "contact update commit",
                )?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("contact update commit", error))?;
                Ok(contact)
            },
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn delete_contact(
        &self,
        mailbox: &str,
        id: i64,
        cancellation: &CancellationToken,
    ) -> Result<(), UserDataError> {
        let deadline = operation_deadline();
        let mailbox = normalize_mailbox(mailbox)?;
        let mut connection = DatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            "contact delete",
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("contact delete transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                let deleted = transaction
                    .query_opt(
                        "DELETE FROM contact WHERE mailbox_address=$1 AND id=$2 RETURNING id",
                        &[&mailbox, &id],
                    )
                    .await
                    .map_err(|error| database_error("contact delete", error))?;
                if deleted.is_none() {
                    ensure_active(&database_cancellation)?;
                    transaction
                        .rollback()
                        .await
                        .map_err(|error| database_error("contact delete rollback", error))?;
                    return Err(UserDataError::InvalidInput("Contact not found".into()));
                }
                start_commit(
                    deadline,
                    &database_cancellation,
                    &commit_started,
                    "contact delete commit",
                )?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("contact delete commit", error))?;
                Ok(())
            },
        )
        .await;
        connection.finish(outcome)
    }

    async fn db(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, UserDataError> {
        bounded_pool(deadline, cancellation, self.pool.get()).await
    }
}

fn operation_deadline() -> Instant {
    Instant::now() + DATABASE_TIMEOUT
}

async fn bounded_pool<T, E, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    future: F,
) -> Result<T, UserDataError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(UserDataError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(UserDataError::Database(format!("userdata pool: {error}"))),
            Err(_) => Err(UserDataError::Database("userdata pool: deadline exceeded".into())),
        },
    }
}

struct DatabaseOutcome<T> {
    result: Result<T, UserDataError>,
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

    fn client_mut(&mut self) -> &mut Object {
        self.client
            .as_mut()
            .expect("database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client
            .as_ref()
            .expect("database connection is present")
            .cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, UserDataError> {
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

async fn database_operation<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    commit_started: &AtomicBool,
    label: &'static str,
    future: F,
) -> DatabaseOutcome<T>
where
    F: Future<Output = Result<T, UserDataError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => UserDataError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return completed_database_outcome(result),
            Err(_) => UserDataError::Database(format!("{label}: deadline exceeded")),
        },
    };

    let recovery_deadline = Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT;
    if commit_started.load(Ordering::Acquire) {
        return match timeout_at(recovery_deadline, future.as_mut()).await {
            Ok(result) => completed_database_outcome(result),
            Err(_) => DatabaseOutcome {
                result: Err(UserDataError::OutcomeUnknown),
                discard_connection: true,
            },
        };
    }

    cancellation.cancel();
    let recovery = timeout_at(recovery_deadline, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    let discard_connection = match recovery {
        Ok((Ok(()), _)) => false,
        Ok((Err(_), _)) | Err(_) => true,
    };

    DatabaseOutcome {
        result: Err(interruption),
        discard_connection,
    }
}

fn completed_database_outcome<T>(result: Result<T, UserDataError>) -> DatabaseOutcome<T> {
    let discard_connection = matches!(result, Err(UserDataError::OutcomeUnknown));
    DatabaseOutcome {
        result,
        discard_connection,
    }
}

fn start_commit(
    deadline: Instant,
    cancellation: &CancellationToken,
    commit_started: &AtomicBool,
    label: &'static str,
) -> Result<(), UserDataError> {
    ensure_active(cancellation)?;
    if Instant::now() >= deadline {
        return Err(UserDataError::Database(format!(
            "{label}: deadline exceeded"
        )));
    }
    commit_started.store(true, Ordering::Release);
    Ok(())
}

async fn configure_transaction_deadline(
    transaction: &deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), UserDataError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let server_millis = (remaining.as_millis() / 2).clamp(1, i32::MAX as u128);
    let value = format!("{server_millis}ms");
    transaction
        .query_one("SELECT set_config('statement_timeout',$1,true)", &[&value])
        .await
        .map_err(|error| database_error("userdata statement timeout", error))?;
    Ok(())
}

fn ensure_active(cancellation: &CancellationToken) -> Result<(), UserDataError> {
    if cancellation.is_cancelled() {
        Err(UserDataError::Cancelled)
    } else {
        Ok(())
    }
}

fn database_error(label: &'static str, error: impl fmt::Display) -> UserDataError {
    UserDataError::Database(format!("{label}: {error}"))
}

fn commit_error(label: &'static str, error: tokio_postgres::Error) -> UserDataError {
    if error.as_db_error().is_some() {
        database_error(label, error)
    } else {
        UserDataError::OutcomeUnknown
    }
}

fn contact_from_row(row: &tokio_postgres::Row) -> ContactRecord {
    ContactRecord {
        id: row.get(0),
        name: row.get(1),
        email: row.get(2),
        notes: row.get(3),
    }
}

fn contact_admission_lock_key(mailbox: &str, email: &str) -> i64 {
    let mut digest = Sha256::new();
    digest.update(b"lmyzmail/userdata/contact-admission/v1\0");
    digest.update(mailbox.as_bytes());
    digest.update(b"\0");
    digest.update(email.as_bytes());
    let bytes: [u8; 8] = digest.finalize()[..8]
        .try_into()
        .expect("SHA-256 prefix has a fixed length");
    i64::from_be_bytes(bytes)
}

fn validate_contact_text(value: Option<&str>, message: &str) -> Result<String, UserDataError> {
    let value = value.ok_or_else(|| UserDataError::InvalidInput(message.into()))?;
    if value.is_empty() || value.chars().count() > MAX_CONTACT_TEXT_CHARS {
        return Err(UserDataError::InvalidInput(message.into()));
    }
    Ok(value.to_owned())
}

fn normalize_mailbox(value: &str) -> Result<String, UserDataError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > MAX_CONTACT_TEXT_CHARS
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(UserDataError::InvalidInput(
            "invalid mailbox address".into(),
        ));
    }
    Ok(value)
}

fn strip_null_object_members(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, member| !member.is_null());
            for member in object.values_mut() {
                strip_null_object_members(member);
            }
        }
        Value::Array(array) => {
            for member in array {
                strip_null_object_members(member);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn preference_response_omits_object_nulls_but_preserves_array_nulls() {
        let mut value = json!({
            "top": null,
            "nested": {"drop": null, "keep": true},
            "array": [null, {"drop": null, "keep": 1}],
        });
        strip_null_object_members(&mut value);
        assert_eq!(
            value,
            json!({
                "nested": {"keep": true},
                "array": [null, {"keep": 1}],
            })
        );
    }

    #[test]
    fn contact_required_fields_use_character_not_byte_limits() {
        assert_eq!(
            validate_contact_text(Some("用户"), "invalid").unwrap(),
            "用户"
        );
        assert!(validate_contact_text(Some(""), "invalid").is_err());
        assert!(validate_contact_text(Some(&"x".repeat(255)), "invalid").is_ok());
        assert!(validate_contact_text(Some(&"x".repeat(256)), "invalid").is_err());
    }

    #[test]
    fn contact_list_budgets_are_fixed_and_nonzero() {
        assert_eq!(CONTACT_QUERY_LIMIT, MAX_CONTACTS + 1);
        assert_eq!(MAX_CONTACTS, 10_000);
        assert_eq!(MAX_CONTACT_FIELD_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn contact_admission_lock_is_pair_scoped_and_stable() {
        let first = contact_admission_lock_key("qa@example.test", "one@example.test");
        assert_eq!(first, -6_484_104_533_297_551_581);
        assert_eq!(
            first,
            contact_admission_lock_key("qa@example.test", "one@example.test")
        );
        assert_ne!(
            first,
            contact_admission_lock_key("qa@example.test", "two@example.test")
        );
        assert_ne!(
            first,
            contact_admission_lock_key("other@example.test", "one@example.test")
        );
    }

    #[test]
    fn preference_numbers_preserve_integers_beyond_u64() {
        let encoded = r#"{"large":1234567890123456789012345678901234567890}"#;
        let value: Value = serde_json::from_str(encoded).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), encoded);
    }
}
