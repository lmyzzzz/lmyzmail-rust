use std::{fmt, future::Future, time::Duration};

use chrono::NaiveDate;
use deadpool_postgres::{Object, Pool};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, NoTls};
use tokio_util::sync::CancellationToken;

use crate::config::ReportingConfig;

const DATABASE_DEADLINE: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReportDomains {
    pub dmarc: Vec<String>,
    pub tls: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DomainDataPresence {
    pub dmarc: bool,
    pub tls: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReportingError {
    Cancelled,
    Timeout,
    Database(String),
}

impl fmt::Display for ReportingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("reporting operation cancelled"),
            Self::Timeout => formatter.write_str("reporting database deadline exceeded"),
            Self::Database(_) => formatter.write_str("reporting database unavailable"),
        }
    }
}

impl std::error::Error for ReportingError {}

#[derive(Clone)]
pub struct ReportingService {
    pool: Pool,
    config: ReportingConfig,
}

impl ReportingService {
    pub fn new(pool: Pool, config: ReportingConfig) -> Self {
        Self { pool, config }
    }

    pub fn config(&self) -> &ReportingConfig {
        &self.config
    }

    pub async fn domains(
        &self,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<ReportDomains, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let minimum = i64::from(self.config.min_volume_for_report);
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let dmarc_rows = connection
                .client()
                .query(
                    "SELECT header_from_domain \
                     FROM inbound_dmarc_log \
                     WHERE report_date = $1 AND header_from_domain IS NOT NULL \
                     GROUP BY header_from_domain \
                     HAVING COALESCE(SUM(message_count), 0) >= $2",
                    &[&report_date, &minimum],
                )
                .await
                .map_err(database_error)?;
            let tls_rows = connection
                .client()
                .query(
                    "SELECT recipient_domain \
                     FROM outbound_tls_log \
                     WHERE report_date = $1 AND recipient_domain IS NOT NULL \
                     GROUP BY recipient_domain \
                     HAVING COALESCE(SUM(connection_count), 0) >= $2",
                    &[&report_date, &minimum],
                )
                .await
                .map_err(database_error)?;
            Ok(ReportDomains {
                dmarc: non_blank_domains(dmarc_rows),
                tls: non_blank_domains(tls_rows),
            })
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn domain_data_presence(
        &self,
        domain: &str,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<DomainDataPresence, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let row = connection
                .client()
                .query_one(
                    "SELECT \
                       EXISTS(SELECT 1 FROM inbound_dmarc_log \
                              WHERE report_date = $1 AND header_from_domain = $2), \
                       EXISTS(SELECT 1 FROM outbound_tls_log \
                              WHERE report_date = $1 AND recipient_domain = $2)",
                    &[&report_date, &domain],
                )
                .await
                .map_err(database_error)?;
            Ok(DomainDataPresence {
                dmarc: row.get(0),
                tls: row.get(1),
            })
        })
        .await;
        connection.finish(outcome)
    }

    async fn client(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, ReportingError> {
        wait_database(self.pool.get(), deadline, cancellation).await
    }
}

fn non_blank_domains(rows: Vec<tokio_postgres::Row>) -> Vec<String> {
    rows.into_iter()
        .map(|row| row.get::<_, String>(0))
        .filter(|domain| !domain.trim().is_empty())
        .collect()
}

fn database_error(error: tokio_postgres::Error) -> ReportingError {
    ReportingError::Database(error.to_string())
}

async fn wait_database<T, E, F>(
    future: F,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, ReportingError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ReportingError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ReportingError::Database(error.to_string())),
            Err(_) => Err(ReportingError::Timeout),
        }
    }
}

struct DatabaseOutcome<T> {
    result: Result<T, ReportingError>,
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
            .expect("reporting database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client().cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, ReportingError> {
        let client = self
            .client
            .take()
            .expect("reporting database connection is present");
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
    F: Future<Output = Result<T, ReportingError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => ReportingError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return DatabaseOutcome {
                result,
                discard_connection: false,
            },
            Err(_) => ReportingError::Timeout,
        },
    };

    let recovery = timeout_at(Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection: !matches!(recovery, Ok((Ok(()), _))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporting_error_does_not_expose_database_details() {
        let error = ReportingError::Database("password=secret".to_owned());
        assert_eq!(error.to_string(), "reporting database unavailable");
    }
}
