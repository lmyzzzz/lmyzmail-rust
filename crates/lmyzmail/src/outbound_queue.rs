use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

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
const LEASE_PREFIX: &str = "lmyzmail:mail:queue:lease:";
const ATTEMPT_PREFIX: &str = "lmyzmail:mail:queue:attempt:";
const TASK_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const POOL_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_LEASE_MILLIS: u64 = 1_000;
const MAX_LEASE_MILLIS: u64 = 60 * 60 * 1_000;
const MAX_LEASE_TOKEN_BYTES: usize = 256;
const MAX_TASK_ID_BYTES: usize = 19;
const MAX_PROCESSING_TIME_BYTES: usize = 20;
const MAX_TASK_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_DOMAIN_STATUSES: usize = 1_000;
const MAX_DOMAIN_RECIPIENTS: usize = 1_000;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_DOMAIN_STATUS_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_DOMAIN_STATUS_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;

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

const CLAIM_SCRIPT: &str = r#"
local attempt_key = ARGV[8] .. ARGV[1]
if redis.call('TYPE', attempt_key).ok ~= 'none' then
  return {'', '', '2'}
end

local task_id = redis.call('LPOP', KEYS[1])
if not task_id then return {} end

local lease_key = ARGV[4] .. task_id
local acquired = redis.call('SET', lease_key, ARGV[1], 'NX', 'PX', ARGV[2])
if not acquired then
  return {task_id, '', '0'}
end

redis.call('SET', attempt_key, task_id, 'PX', ARGV[2])
redis.call('SADD', KEYS[2], task_id)
redis.call('HSET', KEYS[3], task_id, ARGV[3])
local task_key = ARGV[5] .. task_id
local domain_key = ARGV[6] .. task_id
local task_json = redis.call('GET', task_key) or ''
if task_json ~= '' then redis.call('EXPIRE', task_key, ARGV[7]) end
if redis.call('EXISTS', domain_key) == 1 then redis.call('EXPIRE', domain_key, ARGV[7]) end
return {task_id, task_json, '1'}
"#;

const RENEW_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[5] .. task_id
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
local attempt_key = ARGV[9] .. ARGV[2]
if redis.call('GET', attempt_key) ~= task_id then return 0 end
if redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then return 0 end

redis.call('PEXPIRE', lease_key, ARGV[3])
redis.call('PEXPIRE', attempt_key, ARGV[3])
redis.call('HSET', KEYS[2], task_id, ARGV[4])
local task_key = ARGV[6] .. task_id
local domain_key = ARGV[7] .. task_id
if redis.call('EXISTS', task_key) == 1 then redis.call('EXPIRE', task_key, ARGV[8]) end
if redis.call('EXISTS', domain_key) == 1 then redis.call('EXPIRE', domain_key, ARGV[8]) end
return 1
"#;

const RELEASE_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[4] .. task_id
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
local attempt_key = ARGV[5] .. ARGV[2]
if redis.call('GET', attempt_key) ~= task_id then return 0 end

redis.call('DEL', lease_key, attempt_key)
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
if ARGV[3] == '1'
  and redis.call('LPOS', KEYS[1], task_id) == false
  and redis.call('ZSCORE', KEYS[4], task_id) == false then
  redis.call('RPUSH', KEYS[1], task_id)
end
return 1
"#;

const SCHEDULE_RETRY_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[6] .. task_id
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
local attempt_key = ARGV[8] .. ARGV[2]
if redis.call('GET', attempt_key) ~= task_id then return 0 end

local task_key = ARGV[7] .. task_id
redis.call('SET', task_key, ARGV[3], 'EX', ARGV[5])
redis.call('DEL', lease_key, attempt_key)
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
redis.call('LREM', KEYS[1], 0, task_id)
redis.call('ZADD', KEYS[4], tonumber(ARGV[4]) / 1000, task_id)
return 1
"#;

const ACKNOWLEDGE_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[3] .. task_id
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
local attempt_key = ARGV[5] .. ARGV[2]
if redis.call('GET', attempt_key) ~= task_id then return 0 end

redis.call('DEL', lease_key, attempt_key)
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
redis.call('LREM', KEYS[1], 0, task_id)
redis.call('ZREM', KEYS[4], task_id)
redis.call('DEL', ARGV[4] .. task_id)
return 1
"#;

const RECONCILE_CLAIM_SCRIPT: &str = r#"
local attempt_key = KEYS[1]
local attempt_type = redis.call('TYPE', attempt_key).ok
if attempt_type == 'none' then return {'NOT_FOUND'} end
if attempt_type ~= 'string' then return {'INCONSISTENT'} end

local task_id_bytes = redis.call('STRLEN', attempt_key)
if task_id_bytes < 1 or task_id_bytes > tonumber(ARGV[4]) then
  return {'INCONSISTENT'}
end
local task_id = redis.call('GET', attempt_key)
if not string.match(task_id, '^[1-9][0-9]*$') then return {'INCONSISTENT'} end

local lease_key = ARGV[2] .. task_id
if redis.call('TYPE', lease_key).ok ~= 'string'
  or redis.call('STRLEN', lease_key) > tonumber(ARGV[5])
  or redis.call('GET', lease_key) ~= ARGV[1]
  or redis.call('SISMEMBER', KEYS[2], task_id) ~= 1 then
  return {'INCONSISTENT'}
end

local processing_time_bytes = redis.call('HSTRLEN', KEYS[3], task_id)
if processing_time_bytes < 1 or processing_time_bytes > tonumber(ARGV[6]) then
  return {'INCONSISTENT'}
end
local processing_time = redis.call('HGET', KEYS[3], task_id)
if not string.match(processing_time, '^[1-9][0-9]*$') then
  return {'INCONSISTENT'}
end

local task_key = ARGV[3] .. task_id
if redis.call('TYPE', task_key).ok ~= 'string' then return {'INCONSISTENT'} end
local task_json_bytes = redis.call('STRLEN', task_key)
if task_json_bytes < 1 or task_json_bytes > tonumber(ARGV[7]) then
  return {'INCONSISTENT'}
end
local task_json = redis.call('GET', task_key)
local lease_ttl = redis.call('PTTL', lease_key)
local attempt_ttl = redis.call('PTTL', attempt_key)
if lease_ttl < 1 or attempt_ttl ~= lease_ttl then return {'INCONSISTENT'} end
return {'ACTIVE', task_id, processing_time, task_json, tostring(lease_ttl)}
"#;

const MOVE_DUE_RETRIES_SCRIPT: &str = r#"
local ids = redis.call(
  'ZRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) / 1000,
  'LIMIT', 0, ARGV[2]
)
local moved = {}
for _, task_id in ipairs(ids) do
  if redis.call('ZREM', KEYS[1], task_id) == 1 then
    if redis.call('SISMEMBER', KEYS[3], task_id) ~= 1
      and redis.call('LPOS', KEYS[2], task_id) == false then
      redis.call('RPUSH', KEYS[2], task_id)
      table.insert(moved, task_id)
    end
  end
end
return moved
"#;

const SCAN_EXPIRED_CLAIMS_SCRIPT: &str = r#"
local scan = redis.call('SSCAN', KEYS[1], ARGV[1], 'COUNT', ARGV[2])
local expired = {}
for _, task_id in ipairs(scan[2]) do
  if redis.call('EXISTS', ARGV[3] .. task_id) == 0 then
    table.insert(expired, task_id)
  end
end
return {scan[1], expired}
"#;

const RECOVER_EXPIRED_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
if redis.call('EXISTS', ARGV[3] .. task_id) == 1 then return 0 end
if redis.call('SISMEMBER', KEYS[2], task_id) ~= 1 then return 0 end

redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
if ARGV[2] == '1'
  and redis.call('LPOS', KEYS[1], task_id) == false
  and redis.call('ZSCORE', KEYS[4], task_id) == false then
  redis.call('RPUSH', KEYS[1], task_id)
end
return 1
"#;

const READ_DOMAIN_STATUSES_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[2] .. task_id
if redis.call('GET', lease_key) ~= ARGV[3]
  or redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then
  return {'STALE'}
end

local key_type = redis.call('TYPE', KEYS[2])
if key_type.ok == 'none' then return {'MISSING'} end
if key_type.ok ~= 'hash' then return {'CORRUPT'} end

local max_domains = tonumber(ARGV[4])
local max_recipients = tonumber(ARGV[5])
local max_domain_bytes = tonumber(ARGV[6])
local max_address_bytes = tonumber(ARGV[7])
local max_json_bytes = tonumber(ARGV[8])
local max_archive_bytes = tonumber(ARGV[9])
local expected_count = tonumber(ARGV[10])
if expected_count < 1 or expected_count > max_domains
  or redis.call('HLEN', KEYS[2]) ~= expected_count then
  return {'CORRUPT'}
end

local total_bytes = 0
local seen = {}
for index = 1, expected_count do
  local field = ARGV[10 + index]
  if seen[field] or string.len(field) == 0 or string.len(field) > max_domain_bytes
    or string.find(field, '[%c%s]') or redis.call('HEXISTS', KEYS[2], field) ~= 1 then
    return {'CORRUPT'}
  end
  seen[field] = true
  local value_bytes = redis.call('HSTRLEN', KEYS[2], field)
  total_bytes = total_bytes + string.len(field) + value_bytes
  if value_bytes > max_json_bytes or total_bytes > max_archive_bytes then
    return {'CORRUPT'}
  end
end

local total_recipients = 0
local result = {'OK'}
for index = 1, expected_count do
  local field = ARGV[10 + index]
  local json = redis.call('HGET', KEYS[2], field)
  local decoded_ok, decoded = pcall(cjson.decode, json)
  if not decoded_ok or type(decoded) ~= 'table'
    or decoded.domain ~= field
    or type(decoded.status) ~= 'string'
    or (decoded.status ~= 'PENDING' and decoded.status ~= 'SENDING'
      and decoded.status ~= 'SENT' and decoded.status ~= 'FAILED')
    or (decoded.error ~= nil and decoded.error ~= cjson.null
      and type(decoded.error) ~= 'string')
    or type(decoded.recipients) ~= 'table'
    or type(decoded.updatedAt) ~= 'string' or decoded.updatedAt == ''
    or string.len(decoded.updatedAt) > 128 then
    return {'CORRUPT'}
  end
  local recipient_count = 0
  for recipient_index, recipient in pairs(decoded.recipients) do
    if type(recipient_index) ~= 'number' or recipient_index < 1
      or recipient_index % 1 ~= 0 or type(recipient) ~= 'string'
      or string.len(recipient) == 0 or string.len(recipient) > max_address_bytes
      or string.find(recipient, '%c') then
      return {'CORRUPT'}
    end
    recipient_count = recipient_count + 1
  end
  if recipient_count == 0 or recipient_count ~= #decoded.recipients then
    return {'CORRUPT'}
  end
  total_recipients = total_recipients + recipient_count
  if total_recipients > max_recipients then return {'CORRUPT'} end
  table.insert(result, field)
  table.insert(result, json)
end
return result
"#;

const UPDATE_DOMAIN_STATUSES_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[2] .. task_id
if redis.call('GET', lease_key) ~= ARGV[3]
  or redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then
  return 'STALE'
end

local key_type = redis.call('TYPE', KEYS[2])
if key_type.ok == 'none' then return 'MISSING' end
if key_type.ok ~= 'hash' then return 'CORRUPT' end

local max_domains = tonumber(ARGV[4])
local max_recipients = tonumber(ARGV[5])
local max_domain_bytes = tonumber(ARGV[6])
local max_address_bytes = tonumber(ARGV[7])
local max_json_bytes = tonumber(ARGV[8])
local max_archive_bytes = tonumber(ARGV[9])
local ttl = tonumber(ARGV[10])
local expected_count = tonumber(ARGV[11])
local update_count = tonumber(ARGV[12])
if expected_count < 1 or expected_count > max_domains
  or update_count < 1 or update_count > expected_count
  or redis.call('HLEN', KEYS[2]) ~= expected_count then
  return 'CORRUPT'
end

local function validate_status(field, json)
  if string.len(field) == 0 or string.len(field) > max_domain_bytes
    or string.len(json) > max_json_bytes or string.find(field, '[%c%s]') then
    return false, 0
  end
  local decoded_ok, decoded = pcall(cjson.decode, json)
  if not decoded_ok or type(decoded) ~= 'table'
    or decoded.domain ~= field
    or type(decoded.status) ~= 'string'
    or (decoded.status ~= 'PENDING' and decoded.status ~= 'SENDING'
      and decoded.status ~= 'SENT' and decoded.status ~= 'FAILED')
    or (decoded.error ~= nil and decoded.error ~= cjson.null
      and type(decoded.error) ~= 'string')
    or type(decoded.recipients) ~= 'table'
    or type(decoded.updatedAt) ~= 'string' or decoded.updatedAt == ''
    or string.len(decoded.updatedAt) > 128 then
    return false, 0
  end
  local recipient_count = 0
  for recipient_index, recipient in pairs(decoded.recipients) do
    if type(recipient_index) ~= 'number' or recipient_index < 1
      or recipient_index % 1 ~= 0 or type(recipient) ~= 'string'
      or string.len(recipient) == 0 or string.len(recipient) > max_address_bytes
      or string.find(recipient, '%c') then
      return false, 0
    end
    recipient_count = recipient_count + 1
  end
  if recipient_count == 0 or recipient_count ~= #decoded.recipients then return false, 0 end
  return true, recipient_count
end

local total_bytes = 0
local expected = {}
for index = 1, expected_count do
  local field = ARGV[12 + index]
  if expected[field] or string.len(field) == 0 or string.len(field) > max_domain_bytes
    or string.find(field, '[%c%s]') or redis.call('HEXISTS', KEYS[2], field) ~= 1 then
    return 'CORRUPT'
  end
  expected[field] = true
  local value_bytes = redis.call('HSTRLEN', KEYS[2], field)
  total_bytes = total_bytes + string.len(field) + value_bytes
  if value_bytes > max_json_bytes or total_bytes > max_archive_bytes then
    return 'CORRUPT'
  end
end

local total_recipients = 0
local recipient_counts = {}
local current_json = {}
for index = 1, expected_count do
  local field = ARGV[12 + index]
  local json = redis.call('HGET', KEYS[2], field)
  local valid, recipient_count = validate_status(field, json)
  if not valid then return 'CORRUPT' end
  current_json[field] = json
  recipient_counts[field] = recipient_count
  total_recipients = total_recipients + recipient_count
  if total_recipients > max_recipients then return 'CORRUPT' end
end

local update_offset = 13 + expected_count
local seen = {}
local resulting_bytes = total_bytes
local resulting_recipients = total_recipients
for index = 1, update_count do
  local field = ARGV[update_offset]
  local json = ARGV[update_offset + 1]
  local valid, recipient_count = validate_status(field, json)
  if seen[field] or not expected[field] or not valid then return 'CORRUPT' end
  seen[field] = true
  local old_json = current_json[field]
  resulting_bytes = resulting_bytes - string.len(field) - string.len(old_json)
    + string.len(field) + string.len(json)
  resulting_recipients = resulting_recipients - recipient_counts[field] + recipient_count
  if resulting_bytes > max_archive_bytes or resulting_recipients > max_recipients then
    return 'CORRUPT'
  end
  update_offset = update_offset + 2
end

update_offset = 13 + expected_count
for index = 1, update_count do
  redis.call('HSET', KEYS[2], ARGV[update_offset], ARGV[update_offset + 1])
  update_offset = update_offset + 2
end
redis.call('EXPIRE', KEYS[2], ttl)
return 'OK'
"#;

#[derive(Clone)]
pub struct LegacyOutboundQueue {
    pool: Pool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidTask(&'static str),
    AttemptTokenInUse,
    StaleClaim,
    MissingDomainStatuses,
    CorruptDomainStatuses,
    Unavailable,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueClaim {
    pub task_id: i64,
    pub lease_token: String,
    pub task: Option<TaskDetail>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledClaim {
    pub claim: QueueClaim,
    pub processing_time_epoch_millis: i64,
    pub lease_ttl_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimReconciliation {
    NotFound,
    Active(Box<ReconciledClaim>),
    Inconsistent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredClaimPage {
    pub next_cursor: u64,
    pub task_ids: Vec<i64>,
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTask(message) => formatter.write_str(message),
            Self::AttemptTokenInUse => formatter.write_str("outbound attempt token is in use"),
            Self::StaleClaim => formatter.write_str("outbound queue claim is stale"),
            Self::MissingDomainStatuses => {
                formatter.write_str("outbound domain statuses are missing")
            }
            Self::CorruptDomainStatuses => {
                formatter.write_str("outbound domain statuses are corrupt")
            }
            Self::Unavailable => formatter.write_str("Redis outbound queue unavailable"),
            Self::OutcomeUnknown => formatter.write_str(
                "Redis outbound queue mutation outcome is unknown and requires reconciliation",
            ),
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
            .mutation_query(
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
        let created: i64 = self.mutation_query(&mut command, &mut connection).await?;
        Ok(created == 1)
    }

    pub async fn renew_active_task(&self, task_id: i64) -> Result<i64, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let id = task_id.to_string();
        let mut connection = self.connection().await?;
        self.mutation_query(
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
            .mutation_query(
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

    pub async fn claim_next(
        &self,
        lease_token: &str,
        lease_duration: Duration,
        now_epoch_millis: i64,
    ) -> Result<Option<QueueClaim>, QueueError> {
        validate_lease(lease_token, lease_duration, now_epoch_millis)?;
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(CLAIM_SCRIPT)
                    .arg(3)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(lease_token)
                    .arg(lease_duration.as_millis())
                    .arg(now_epoch_millis)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(format!("{KEY_PREFIX}domains:"))
                    .arg(TASK_TTL_SECONDS)
                    .arg(ATTEMPT_PREFIX),
                &mut connection,
            )
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        if values.len() != 3 {
            return Err(QueueError::OutcomeUnknown);
        }
        if values[2] == "2" {
            return Err(QueueError::AttemptTokenInUse);
        }
        let task_id = parse_task_id(&values[0]).map_err(|_| QueueError::OutcomeUnknown)?;
        if values[2] != "1" {
            return Ok(None);
        }
        let task = if values[1].is_empty() {
            None
        } else {
            let task: TaskDetail =
                serde_json::from_str(&values[1]).map_err(|_| QueueError::OutcomeUnknown)?;
            if task.id != task_id {
                return Err(QueueError::OutcomeUnknown);
            }
            Some(task)
        };
        Ok(Some(QueueClaim {
            task_id,
            lease_token: lease_token.to_owned(),
            task,
        }))
    }

    pub async fn reconcile_claim(
        &self,
        attempt_token: &str,
    ) -> Result<ClaimReconciliation, QueueError> {
        validate_lease_token(attempt_token)?;
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .query(
                redis::cmd("EVAL")
                    .arg(RECONCILE_CLAIM_SCRIPT)
                    .arg(3)
                    .arg(format!("{ATTEMPT_PREFIX}{attempt_token}"))
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(attempt_token)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(MAX_TASK_ID_BYTES)
                    .arg(MAX_LEASE_TOKEN_BYTES)
                    .arg(MAX_PROCESSING_TIME_BYTES)
                    .arg(MAX_TASK_JSON_BYTES),
                &mut connection,
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("NOT_FOUND") if values.len() == 1 => Ok(ClaimReconciliation::NotFound),
            Some("INCONSISTENT") if values.len() == 1 => Ok(ClaimReconciliation::Inconsistent),
            Some("ACTIVE") if values.len() == 5 => {
                let task_id = match parse_task_id(&values[1]) {
                    Ok(value) => value,
                    Err(_) => return Ok(ClaimReconciliation::Inconsistent),
                };
                let processing_time_epoch_millis =
                    match values[2].parse::<i64>().ok().filter(|value| *value > 0) {
                        Some(value) => value,
                        None => return Ok(ClaimReconciliation::Inconsistent),
                    };
                let task: TaskDetail = match serde_json::from_str(&values[3]) {
                    Ok(value) => value,
                    Err(_) => return Ok(ClaimReconciliation::Inconsistent),
                };
                if task.id != task_id || task.validate().is_err() {
                    return Ok(ClaimReconciliation::Inconsistent);
                }
                let lease_ttl_millis = match values[4]
                    .parse::<u64>()
                    .ok()
                    .filter(|value| *value > 0 && *value <= MAX_LEASE_MILLIS)
                {
                    Some(value) => value,
                    None => return Ok(ClaimReconciliation::Inconsistent),
                };
                Ok(ClaimReconciliation::Active(Box::new(ReconciledClaim {
                    claim: QueueClaim {
                        task_id,
                        lease_token: attempt_token.to_owned(),
                        task: Some(task),
                    },
                    processing_time_epoch_millis,
                    lease_ttl_millis,
                })))
            }
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn renew_claim(
        &self,
        claim: &QueueClaim,
        lease_duration: Duration,
        now_epoch_millis: i64,
    ) -> Result<bool, QueueError> {
        validate_claim(claim, lease_duration, now_epoch_millis)?;
        let mut connection = self.connection().await?;
        let renewed: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RENEW_CLAIM_SCRIPT)
                    .arg(2)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(lease_duration.as_millis())
                    .arg(now_epoch_millis)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(format!("{KEY_PREFIX}domains:"))
                    .arg(TASK_TTL_SECONDS)
                    .arg(ATTEMPT_PREFIX),
                &mut connection,
            )
            .await?;
        Ok(renewed == 1)
    }

    pub async fn read_domain_statuses(
        &self,
        claim: &QueueClaim,
        expected_domains: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, DomainStatus>, QueueError> {
        validate_claim_identity(claim)?;
        validate_expected_domains(expected_domains)?;
        let domain_key = format!("{KEY_PREFIX}domains:{}", claim.task_id);
        let mut command = redis::cmd("EVAL");
        command
            .arg(READ_DOMAIN_STATUSES_SCRIPT)
            .arg(2)
            .arg(PROCESSING_KEY)
            .arg(domain_key)
            .arg(claim.task_id)
            .arg(LEASE_PREFIX)
            .arg(&claim.lease_token)
            .arg(MAX_DOMAIN_STATUSES)
            .arg(MAX_DOMAIN_RECIPIENTS)
            .arg(MAX_DOMAIN_BYTES)
            .arg(MAX_ADDRESS_BYTES)
            .arg(MAX_DOMAIN_STATUS_JSON_BYTES)
            .arg(MAX_DOMAIN_STATUS_ARCHIVE_BYTES)
            .arg(expected_domains.len());
        for domain in expected_domains {
            command.arg(domain);
        }
        let mut connection = self.connection().await?;
        let values: Vec<String> = self.query(&mut command, &mut connection).await?;
        decode_domain_statuses(values, expected_domains)
    }

    pub async fn update_domain_statuses(
        &self,
        claim: &QueueClaim,
        expected_domains: &BTreeSet<String>,
        updates: &BTreeMap<String, DomainStatus>,
    ) -> Result<(), QueueError> {
        validate_claim_identity(claim)?;
        validate_expected_domains(expected_domains)?;
        if updates.is_empty() || updates.len() > MAX_DOMAIN_STATUSES {
            return Err(QueueError::InvalidTask(
                "invalid domain status update bound",
            ));
        }

        let mut serialized = Vec::with_capacity(updates.len());
        let mut total_bytes = 0_usize;
        let mut total_recipients = 0_usize;
        for (domain, status) in updates {
            if !expected_domains.contains(domain) || !valid_domain_status(domain, status) {
                return Err(QueueError::InvalidTask("invalid domain status update"));
            }
            total_recipients = total_recipients
                .checked_add(status.recipients.len())
                .ok_or(QueueError::InvalidTask("invalid domain status update"))?;
            let json = serde_json::to_string(status)
                .map_err(|_| QueueError::InvalidTask("invalid domain status update"))?;
            if json.len() > MAX_DOMAIN_STATUS_JSON_BYTES {
                return Err(QueueError::InvalidTask(
                    "domain status update exceeds its byte budget",
                ));
            }
            total_bytes = total_bytes
                .checked_add(domain.len())
                .and_then(|value| value.checked_add(json.len()))
                .ok_or(QueueError::InvalidTask(
                    "domain status update exceeds its byte budget",
                ))?;
            serialized.push((domain, json));
        }
        if total_recipients > MAX_DOMAIN_RECIPIENTS || total_bytes > MAX_DOMAIN_STATUS_ARCHIVE_BYTES
        {
            return Err(QueueError::InvalidTask(
                "domain status update exceeds its bound",
            ));
        }

        let domain_key = format!("{KEY_PREFIX}domains:{}", claim.task_id);
        let mut command = redis::cmd("EVAL");
        command
            .arg(UPDATE_DOMAIN_STATUSES_SCRIPT)
            .arg(2)
            .arg(PROCESSING_KEY)
            .arg(domain_key)
            .arg(claim.task_id)
            .arg(LEASE_PREFIX)
            .arg(&claim.lease_token)
            .arg(MAX_DOMAIN_STATUSES)
            .arg(MAX_DOMAIN_RECIPIENTS)
            .arg(MAX_DOMAIN_BYTES)
            .arg(MAX_ADDRESS_BYTES)
            .arg(MAX_DOMAIN_STATUS_JSON_BYTES)
            .arg(MAX_DOMAIN_STATUS_ARCHIVE_BYTES)
            .arg(TASK_TTL_SECONDS)
            .arg(expected_domains.len())
            .arg(serialized.len());
        for domain in expected_domains {
            command.arg(domain);
        }
        for (domain, json) in serialized {
            command.arg(domain).arg(json);
        }

        let mut connection = self.connection().await?;
        let result: String = self.mutation_query(&mut command, &mut connection).await?;
        match result.as_str() {
            "OK" => Ok(()),
            "STALE" => Err(QueueError::StaleClaim),
            "MISSING" => Err(QueueError::MissingDomainStatuses),
            "CORRUPT" => Err(QueueError::CorruptDomainStatuses),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn release_claim(
        &self,
        claim: &QueueClaim,
        requeue: bool,
    ) -> Result<bool, QueueError> {
        validate_claim_identity(claim)?;
        let mut connection = self.connection().await?;
        let released: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RELEASE_CLAIM_SCRIPT)
                    .arg(4)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(i64::from(requeue))
                    .arg(LEASE_PREFIX)
                    .arg(ATTEMPT_PREFIX),
                &mut connection,
            )
            .await?;
        Ok(released == 1)
    }

    pub async fn schedule_retry(
        &self,
        claim: &QueueClaim,
        task: &TaskDetail,
        retry_at_epoch_millis: i64,
    ) -> Result<bool, QueueError> {
        validate_claim_identity(claim)?;
        task.validate()?;
        if task.id != claim.task_id || retry_at_epoch_millis <= 0 {
            return Err(QueueError::InvalidTask("retry task does not match claim"));
        }
        let task_json = serde_json::to_string(task).map_err(|_| QueueError::Unavailable)?;
        let mut connection = self.connection().await?;
        let scheduled: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(SCHEDULE_RETRY_SCRIPT)
                    .arg(4)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(task_json)
                    .arg(retry_at_epoch_millis)
                    .arg(TASK_TTL_SECONDS)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(ATTEMPT_PREFIX),
                &mut connection,
            )
            .await?;
        Ok(scheduled == 1)
    }

    pub async fn acknowledge(&self, claim: &QueueClaim) -> Result<bool, QueueError> {
        validate_claim_identity(claim)?;
        let mut connection = self.connection().await?;
        let acknowledged: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(ACKNOWLEDGE_SCRIPT)
                    .arg(4)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(ATTEMPT_PREFIX),
                &mut connection,
            )
            .await?;
        Ok(acknowledged == 1)
    }

    pub async fn move_due_retries(
        &self,
        now_epoch_millis: i64,
        limit: usize,
    ) -> Result<Vec<i64>, QueueError> {
        if now_epoch_millis <= 0 || limit == 0 || limit > 10_000 {
            return Err(QueueError::InvalidTask("invalid retry move bound"));
        }
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(MOVE_DUE_RETRIES_SCRIPT)
                    .arg(3)
                    .arg(RETRY_KEY)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(now_epoch_millis)
                    .arg(limit),
                &mut connection,
            )
            .await?;
        values
            .into_iter()
            .map(|value| parse_task_id(&value))
            .collect()
    }

    pub async fn scan_expired_claims(
        &self,
        cursor: u64,
        count: usize,
    ) -> Result<ExpiredClaimPage, QueueError> {
        if count == 0 || count > 10_000 {
            return Err(QueueError::InvalidTask("invalid claim scan bound"));
        }
        let mut connection = self.connection().await?;
        let (next_cursor, values): (u64, Vec<String>) = self
            .query(
                redis::cmd("EVAL")
                    .arg(SCAN_EXPIRED_CLAIMS_SCRIPT)
                    .arg(1)
                    .arg(PROCESSING_KEY)
                    .arg(cursor)
                    .arg(count)
                    .arg(LEASE_PREFIX),
                &mut connection,
            )
            .await?;
        let task_ids = values
            .into_iter()
            .map(|value| parse_task_id(&value))
            .collect::<Result<_, _>>()?;
        Ok(ExpiredClaimPage {
            next_cursor,
            task_ids,
        })
    }

    pub async fn recover_expired_claim(
        &self,
        task_id: i64,
        requeue: bool,
    ) -> Result<bool, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let mut connection = self.connection().await?;
        let recovered: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RECOVER_EXPIRED_CLAIM_SCRIPT)
                    .arg(4)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(task_id)
                    .arg(i64::from(requeue))
                    .arg(LEASE_PREFIX),
                &mut connection,
            )
            .await?;
        Ok(recovered == 1)
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

    async fn mutation_query<T: redis::FromRedisValue>(
        &self,
        command: &mut redis::Cmd,
        connection: &mut deadpool_redis::Connection,
    ) -> Result<T, QueueError> {
        timeout(COMMAND_TIMEOUT, command.query_async(connection))
            .await
            .map_err(|_| QueueError::OutcomeUnknown)?
            .map_err(|_| QueueError::OutcomeUnknown)
    }
}

fn validate_lease(
    lease_token: &str,
    lease_duration: Duration,
    now_epoch_millis: i64,
) -> Result<(), QueueError> {
    validate_lease_token(lease_token)?;
    let lease_millis = u64::try_from(lease_duration.as_millis())
        .map_err(|_| QueueError::InvalidTask("invalid lease duration"))?;
    if !(MIN_LEASE_MILLIS..=MAX_LEASE_MILLIS).contains(&lease_millis) || now_epoch_millis <= 0 {
        return Err(QueueError::InvalidTask("invalid lease duration"));
    }
    Ok(())
}

fn validate_lease_token(lease_token: &str) -> Result<(), QueueError> {
    if lease_token.is_empty()
        || lease_token.len() > MAX_LEASE_TOKEN_BYTES
        || !lease_token.is_ascii()
        || lease_token.bytes().any(|value| value.is_ascii_control())
    {
        return Err(QueueError::InvalidTask("invalid lease token"));
    }
    Ok(())
}

fn validate_claim(
    claim: &QueueClaim,
    lease_duration: Duration,
    now_epoch_millis: i64,
) -> Result<(), QueueError> {
    validate_claim_identity(claim)?;
    validate_lease(&claim.lease_token, lease_duration, now_epoch_millis)
}

fn validate_claim_identity(claim: &QueueClaim) -> Result<(), QueueError> {
    if claim.task_id <= 0 {
        return Err(QueueError::InvalidTask("task ID must be positive"));
    }
    validate_lease(&claim.lease_token, Duration::from_secs(1), 1)
}

fn parse_task_id(value: &str) -> Result<i64, QueueError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(QueueError::Unavailable)
}

fn decode_domain_statuses(
    values: Vec<String>,
    expected_domains: &BTreeSet<String>,
) -> Result<BTreeMap<String, DomainStatus>, QueueError> {
    let Some(marker) = values.first().map(String::as_str) else {
        return Err(QueueError::Unavailable);
    };
    match marker {
        "STALE" => return Err(QueueError::StaleClaim),
        "MISSING" => return Err(QueueError::MissingDomainStatuses),
        "CORRUPT" => return Err(QueueError::CorruptDomainStatuses),
        "OK" => {}
        _ => return Err(QueueError::Unavailable),
    }
    if values.len() == 1 || !(values.len() - 1).is_multiple_of(2) {
        return Err(QueueError::CorruptDomainStatuses);
    }

    let mut statuses = BTreeMap::new();
    let mut total_bytes = 0_usize;
    let mut total_recipients = 0_usize;
    for pair in values[1..].chunks_exact(2) {
        let domain = &pair[0];
        let json = &pair[1];
        total_bytes = total_bytes
            .checked_add(domain.len())
            .and_then(|value| value.checked_add(json.len()))
            .ok_or(QueueError::CorruptDomainStatuses)?;
        if json.len() > MAX_DOMAIN_STATUS_JSON_BYTES
            || total_bytes > MAX_DOMAIN_STATUS_ARCHIVE_BYTES
        {
            return Err(QueueError::CorruptDomainStatuses);
        }
        let status: DomainStatus =
            serde_json::from_str(json).map_err(|_| QueueError::CorruptDomainStatuses)?;
        if !valid_domain_status(domain, &status) {
            return Err(QueueError::CorruptDomainStatuses);
        }
        total_recipients = total_recipients
            .checked_add(status.recipients.len())
            .ok_or(QueueError::CorruptDomainStatuses)?;
        if total_recipients > MAX_DOMAIN_RECIPIENTS
            || statuses.insert(domain.clone(), status).is_some()
            || statuses.len() > MAX_DOMAIN_STATUSES
        {
            return Err(QueueError::CorruptDomainStatuses);
        }
    }
    if !statuses.keys().eq(expected_domains.iter()) {
        return Err(QueueError::CorruptDomainStatuses);
    }
    Ok(statuses)
}

fn validate_expected_domains(expected_domains: &BTreeSet<String>) -> Result<(), QueueError> {
    if expected_domains.is_empty()
        || expected_domains.len() > MAX_DOMAIN_STATUSES
        || expected_domains
            .iter()
            .any(|domain| !valid_domain_name(domain))
    {
        return Err(QueueError::InvalidTask("invalid expected domain set"));
    }
    Ok(())
}

fn valid_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN_BYTES
        && !domain.chars().any(char::is_whitespace)
        && !domain.chars().any(char::is_control)
}

fn valid_domain_status(domain: &str, status: &DomainStatus) -> bool {
    valid_domain_name(domain)
        && status.domain == domain
        && matches!(
            status.status.as_str(),
            "PENDING" | "SENDING" | "SENT" | "FAILED"
        )
        && !status.recipients.is_empty()
        && status.recipients.len() <= MAX_DOMAIN_RECIPIENTS
        && status.recipients.iter().all(|recipient| {
            !recipient.is_empty()
                && recipient.len() <= MAX_ADDRESS_BYTES
                && !recipient.chars().any(char::is_control)
        })
        && !status.updated_at.is_empty()
        && status.updated_at.len() <= 128
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
