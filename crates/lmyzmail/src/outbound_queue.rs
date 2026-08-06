use std::{collections::BTreeMap, fmt, time::Duration};

use deadpool_redis::{Pool, redis};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

const KEY_PREFIX: &str = "botmail:mail:queue:";
const PENDING_KEY: &str = "botmail:mail:queue:pending";
const PROCESSING_KEY: &str = "botmail:mail:queue:processing";
const PROCESSING_TIME_KEY: &str = "botmail:mail:queue:processing_time";
const RETRY_KEY: &str = "botmail:mail:queue:retry";
const SEQUENCE_KEY: &str = "botmail:mail:queue:seq";
const SENT_FILE_INDEX_KEY: &str = "botmail:mail:queue:sentfile_index";
const TASK_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const POOL_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

const RESERVE_ID_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1]) or '0'
local floor = ARGV[1]
local function normalize(value)
  local normalized = string.gsub(value, '^0+', '')
  if normalized == '' then return '0' end
  return normalized
end
local function less(left, right)
  left = normalize(left)
  right = normalize(right)
  if string.len(left) ~= string.len(right) then
    return string.len(left) < string.len(right)
  end
  return left < right
end
if less(current, floor) then
  redis.call('SET', KEYS[1], floor)
end
redis.call('INCR', KEYS[1])
return redis.call('GET', KEYS[1])
"#;

const PUBLISH_SCRIPT: &str = r#"
local task_id = ARGV[1]
local task_json = ARGV[2]
local ttl = tonumber(ARGV[3])
local sent_file = ARGV[4]
local domain_count = tonumber(ARGV[5])
local existing = redis.call('GET', KEYS[1])

if existing then
  if existing ~= task_json then
    return redis.error_reply('TASK_ID_CONFLICT')
  end
end

if sent_file ~= '' then
  local indexed = redis.call('HGET', KEYS[3], sent_file)
  if indexed and indexed ~= task_id then
    return redis.error_reply('SENT_FILE_CONFLICT')
  end
end

local created = 0
if not existing then
  redis.call('SET', KEYS[1], task_json, 'EX', ttl)
  created = 1
else
  redis.call('EXPIRE', KEYS[1], ttl)
end

local domains_exist = redis.call('EXISTS', KEYS[2]) == 1
if domains_exist then
  if redis.call('HLEN', KEYS[2]) ~= domain_count then
    return redis.error_reply('DOMAIN_STATUS_CONFLICT')
  end
  local offset = 6
  for index = 1, domain_count do
    if redis.call('HGET', KEYS[2], ARGV[offset]) ~= ARGV[offset + 1] then
      return redis.error_reply('DOMAIN_STATUS_CONFLICT')
    end
    offset = offset + 2
  end
else
  local offset = 6
  for index = 1, domain_count do
    redis.call('HSET', KEYS[2], ARGV[offset], ARGV[offset + 1])
    offset = offset + 2
  end
end
if domain_count > 0 or domains_exist then
  redis.call('EXPIRE', KEYS[2], ttl)
end

if sent_file ~= '' then
  redis.call('HSET', KEYS[3], sent_file, task_id)
end

local is_processing = redis.call('SISMEMBER', KEYS[5], task_id) == 1
local is_retrying = redis.call('ZSCORE', KEYS[7], task_id) ~= false
local is_pending = redis.call('LPOS', KEYS[4], task_id) ~= false
if not is_processing and not is_retrying and not is_pending then
  redis.call('RPUSH', KEYS[4], task_id)
end
return created
"#;

const ACTIVE_IDS_SCRIPT: &str = r#"
local limit = tonumber(ARGV[1])
local result = {}
local seen = {}
local function add(value)
  if value and not seen[value] and #result < limit then
    seen[value] = true
    table.insert(result, value)
  end
end
for _, value in ipairs(redis.call('LRANGE', KEYS[1], 0, limit - 1)) do add(value) end
if #result < limit then
  local cursor = '0'
  repeat
    local remaining = math.min(limit - #result, 256)
    local scan = redis.call('SSCAN', KEYS[2], cursor, 'COUNT', remaining)
    cursor = scan[1]
    for _, value in ipairs(scan[2]) do add(value) end
  until cursor == '0' or #result >= limit
end
if #result < limit then
  for _, value in ipairs(redis.call('ZRANGE', KEYS[3], 0, limit - 1)) do add(value) end
end
return result
"#;

const RENEW_SCRIPT: &str = r#"
local task_id = ARGV[1]
local ttl = tonumber(ARGV[2])
local referenced = redis.call('LPOS', KEYS[1], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[2], task_id) == 1
  or redis.call('ZSCORE', KEYS[3], task_id) ~= false
if not referenced then return 0 end
if redis.call('EXISTS', KEYS[4]) == 0 then return -1 end
redis.call('EXPIRE', KEYS[4], ttl)
if redis.call('EXISTS', KEYS[5]) == 1 then redis.call('EXPIRE', KEYS[5], ttl) end
return 1
"#;

const COMPLETE_TASK_SCRIPT: &str = r#"
local task_id = ARGV[1]
local sent_file = ARGV[2]
local ttl = tonumber(ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('EXISTS', KEYS[2]) == 0 then return 0 end
if sent_file ~= '' and redis.call('HGET', KEYS[3], sent_file) ~= task_id then return 0 end
local referenced = redis.call('LPOS', KEYS[4], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[5], task_id) == 1
  or redis.call('ZSCORE', KEYS[6], task_id) ~= false
if not referenced then return 0 end
redis.call('EXPIRE', KEYS[1], ttl)
redis.call('EXPIRE', KEYS[2], ttl)
return 1
"#;

#[derive(Clone)]
pub struct LegacyOutboundQueue {
    pool: Pool,
}

#[derive(Debug)]
pub enum QueueError {
    InvalidTask(&'static str),
    Unavailable,
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTask(message) => formatter.write_str(message),
            Self::Unavailable => formatter.write_str("Redis outbound queue unavailable"),
        }
    }
}

impl std::error::Error for QueueError {}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskDetail {
    pub id: i64,
    pub sender_address: String,
    pub recipients_json: String,
    pub subject: String,
    pub message_id: String,
    pub max_retries: i32,
    pub retry_count: i32,
    pub sent_file_name: Option<String>,
    pub sent_subdirectory: Option<i32>,
    pub message_file_path: Option<String>,
    pub signed_content_base64: Option<String>,
    pub created_at: String,
    pub next_retry_at: Option<String>,
    pub last_error: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomainStatus {
    pub domain: String,
    pub status: String,
    pub error: Option<String>,
    pub recipients: Vec<String>,
    pub updated_at: String,
}

impl TaskDetail {
    fn validate(&self) -> Result<(), QueueError> {
        if self.id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        if self.sent_file_name.as_deref().is_none_or(str::is_empty)
            || self.sent_subdirectory.is_none_or(|value| value <= 0)
        {
            return Err(QueueError::InvalidTask(
                "task must reference its sent Maildir copy",
            ));
        }
        let has_file = self
            .message_file_path
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        let has_memory = self
            .signed_content_base64
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        if has_file == has_memory {
            return Err(QueueError::InvalidTask(
                "task must have exactly one stable message source",
            ));
        }
        if self.status != "PENDING" {
            return Err(QueueError::InvalidTask("new task must be pending"));
        }
        Ok(())
    }
}

impl LegacyOutboundQueue {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn reserve_task_id(&self, postgres_id_floor: i64) -> Result<i64, QueueError> {
        if postgres_id_floor < 0 {
            return Err(QueueError::InvalidTask("task ID floor cannot be negative"));
        }
        let mut connection = self.connection().await?;
        let id: i64 = self
            .query(
                redis::cmd("EVAL")
                    .arg(RESERVE_ID_SCRIPT)
                    .arg(1)
                    .arg(SEQUENCE_KEY)
                    .arg(postgres_id_floor),
                &mut connection,
            )
            .await?;
        if id <= postgres_id_floor {
            return Err(QueueError::Unavailable);
        }
        Ok(id)
    }

    pub async fn active_task_ids(&self, limit: usize) -> Result<Vec<String>, QueueError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .query(
                redis::cmd("EVAL")
                    .arg(ACTIVE_IDS_SCRIPT)
                    .arg(3)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(RETRY_KEY)
                    .arg(limit),
                &mut connection,
            )
            .await?;
        if values.len() > limit {
            return Err(QueueError::Unavailable);
        }
        Ok(values)
    }

    pub async fn publish(
        &self,
        task: &TaskDetail,
        domains: &BTreeMap<String, DomainStatus>,
    ) -> Result<bool, QueueError> {
        task.validate()?;
        if domains.is_empty() || domains.values().any(|status| status.domain.is_empty()) {
            return Err(QueueError::InvalidTask(
                "task domain statuses are incomplete",
            ));
        }
        let task_json = serde_json::to_string(task).map_err(|_| QueueError::Unavailable)?;
        let task_id = task.id.to_string();
        let task_key = format!("{KEY_PREFIX}task:{task_id}");
        let domain_key = format!("{KEY_PREFIX}domains:{task_id}");
        let mut command = redis::cmd("EVAL");
        command
            .arg(PUBLISH_SCRIPT)
            .arg(7)
            .arg(task_key)
            .arg(domain_key)
            .arg(SENT_FILE_INDEX_KEY)
            .arg(PENDING_KEY)
            .arg(PROCESSING_KEY)
            .arg(PROCESSING_TIME_KEY)
            .arg(RETRY_KEY)
            .arg(&task_id)
            .arg(task_json)
            .arg(TASK_TTL_SECONDS)
            .arg(task.sent_file_name.as_deref().unwrap_or_default())
            .arg(domains.len());
        for (domain, status) in domains {
            if domain != &status.domain {
                return Err(QueueError::InvalidTask("domain status key mismatch"));
            }
            command
                .arg(domain)
                .arg(serde_json::to_string(status).map_err(|_| QueueError::Unavailable)?);
        }
        let mut connection = self.connection().await?;
        let created: i64 = self.query(&mut command, &mut connection).await?;
        Ok(created == 1)
    }

    pub async fn renew_active_task(&self, task_id: i64) -> Result<i64, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let id = task_id.to_string();
        let mut connection = self.connection().await?;
        self.query(
            redis::cmd("EVAL")
                .arg(RENEW_SCRIPT)
                .arg(5)
                .arg(PENDING_KEY)
                .arg(PROCESSING_KEY)
                .arg(RETRY_KEY)
                .arg(format!("{KEY_PREFIX}task:{id}"))
                .arg(format!("{KEY_PREFIX}domains:{id}"))
                .arg(id)
                .arg(TASK_TTL_SECONDS),
            &mut connection,
        )
        .await
    }

    pub async fn is_complete_task(
        &self,
        task_id: i64,
        sent_file_name: &str,
    ) -> Result<bool, QueueError> {
        if task_id <= 0 || sent_file_name.is_empty() {
            return Err(QueueError::InvalidTask(
                "task storage reference is incomplete",
            ));
        }
        let id = task_id.to_string();
        let mut connection = self.connection().await?;
        let complete: i64 = self
            .query(
                redis::cmd("EVAL")
                    .arg(COMPLETE_TASK_SCRIPT)
                    .arg(6)
                    .arg(format!("{KEY_PREFIX}task:{id}"))
                    .arg(format!("{KEY_PREFIX}domains:{id}"))
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(RETRY_KEY)
                    .arg(id)
                    .arg(sent_file_name)
                    .arg(TASK_TTL_SECONDS),
                &mut connection,
            )
            .await?;
        Ok(complete == 1)
    }

    async fn connection(&self) -> Result<deadpool_redis::Connection, QueueError> {
        timeout(POOL_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| QueueError::Unavailable)?
            .map_err(|_| QueueError::Unavailable)
    }

    async fn query<T: redis::FromRedisValue>(
        &self,
        command: &mut redis::Cmd,
        connection: &mut deadpool_redis::Connection,
    ) -> Result<T, QueueError> {
        timeout(COMMAND_TIMEOUT, command.query_async(connection))
            .await
            .map_err(|_| QueueError::Unavailable)?
            .map_err(|_| QueueError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_task() -> TaskDetail {
        TaskDetail {
            id: 42,
            sender_address: "qa@example.test".into(),
            recipients_json: r#"{"to":["user@remote.test"],"cc":[],"bcc":[]}"#.into(),
            subject: "subject".into(),
            message_id: "<stable@example.test>".into(),
            max_retries: 5,
            retry_count: 0,
            sent_file_name: Some("sent.eml".into()),
            sent_subdirectory: Some(1),
            message_file_path: None,
            signed_content_base64: Some("RnJvbTogcWE=".into()),
            created_at: "2026-08-06T00:00:00Z".into(),
            next_retry_at: None,
            last_error: None,
            status: "PENDING".into(),
        }
    }

    #[test]
    fn task_json_matches_the_frozen_java_field_contract() {
        let json = serde_json::to_value(complete_task()).unwrap();
        assert_eq!(json["id"], 42);
        assert_eq!(json["senderAddress"], "qa@example.test");
        assert_eq!(json["sentSubdirectory"], 1);
        assert_eq!(json["signedContentBase64"], "RnJvbTogcWE=");
        assert!(json["messageFilePath"].is_null());
        assert!(json["nextRetryAt"].is_null());
        assert_eq!(json.as_object().unwrap().len(), 15);
    }

    #[test]
    fn task_requires_maildir_and_exactly_one_message_source() {
        let mut task = complete_task();
        assert!(task.validate().is_ok());
        task.message_file_path = Some("/spool/42.eml".into());
        assert!(task.validate().is_err());
        task.signed_content_base64 = None;
        assert!(task.validate().is_ok());
        task.sent_file_name = None;
        assert!(task.validate().is_err());
    }
}
