use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use deadpool_redis::{Pool, redis};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::queue_observer::{
    Operation as QueueObservedOperation, PublishFailure, Timer as QueueObserverTimer,
    record_publish_failure,
};

const KEY_PREFIX: &str = "botmail:mail:queue:";
const PENDING_KEY: &str = "botmail:mail:queue:pending";
const PROCESSING_KEY: &str = "botmail:mail:queue:processing";
const PROCESSING_TIME_KEY: &str = "botmail:mail:queue:processing_time";
const RETRY_KEY: &str = "botmail:mail:queue:retry";
const SEQUENCE_KEY: &str = "botmail:mail:queue:seq";
const SENT_FILE_INDEX_KEY: &str = "botmail:mail:queue:sentfile_index";
const STATUS_UPDATES_KEY: &str = "botmail:mail:queue:status_updates";
const ARCHIVE_KEY: &str = "botmail:mail:queue:archive";
const LEASE_PREFIX: &str = "lmyzmail:mail:queue:lease:";
const ATTEMPT_PREFIX: &str = "lmyzmail:mail:queue:attempt:";
const CLAIM_RESULT_PREFIX: &str = "lmyzmail:mail:queue:claim-result:";
const CLAIM_RESULT_INDEX_KEY: &str = "lmyzmail:mail:queue:claim-result-index";
const SETTLEMENT_PREFIX: &str = "lmyzmail:mail:queue:settlement:";
const SETTLEMENT_INDEX_KEY: &str = "lmyzmail:mail:queue:settlement-index";
const CLEANUP_RECEIPT_INDEX_KEY: &str = "lmyzmail:mail:queue:migration:cleanup-index";
const TASK_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const RECEIPT_TTL_SECONDS: u64 = 300;
const MAX_ACTIVE_TASK_REFERENCES: usize = 1_000_000;
// Five-minute outcome receipts must not throttle a queue that is otherwise
// within its active-reference bound. Redis scripts still prune expired entries
// and reject growth at this explicit ceiling.
const MAX_RECEIPT_INDEX_ENTRIES: usize = MAX_ACTIVE_TASK_REFERENCES;
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
const MAX_LEASE_TTL_SKEW_MILLIS: u64 = 10;
const MAX_SETTLEMENT_VALUE_BYTES: usize = 64;
const MAX_MIGRATION_TOKEN_BYTES: usize = 128;
const MAX_MIGRATION_REASON_BYTES: usize = 64;
const MAX_ID_RESERVATION_BLOCK: usize = 4_096;
const MAX_LEGACY_LIST_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_LEGACY_QUARANTINE_RECORDS: usize = 4_096;
const MAX_LEGACY_QUARANTINE_BYTES: usize = 64 * 1024 * 1024;
const CLEANUP_RECEIPT_PREFIX: &str = "lmyzmail:mail:queue:migration:cleanup:";
const CLEANUP_RECEIPT_TAG: &str = "CLEANED:";

const RESERVE_ID_SCRIPT: &str = r#"
local sequence_type = redis.call('TYPE', KEYS[1]).ok
if sequence_type ~= 'none' and sequence_type ~= 'string' then
  return redis.error_reply('WRONGTYPE')
end
local current = '0'
if sequence_type == 'string' then current = redis.call('GET', KEYS[1]) end
local floor = ARGV[1]
local maximum = ARGV[2]
local count = tonumber(ARGV[3])
local maximum_start = ARGV[4]
if not count or count < 1 or count > tonumber(ARGV[5]) then
  return redis.error_reply('INVALID_RESERVATION_COUNT')
end
if (current ~= '0' and not string.match(current, '^[1-9][0-9]*$'))
  or string.len(current) > string.len(maximum)
  or (string.len(current) == string.len(maximum) and current > maximum) then
  return redis.error_reply('INVALID_SEQUENCE')
end
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
if not less(floor, maximum) or less(maximum_start, floor) then
  return redis.error_reply('SEQUENCE_EXHAUSTED')
end
if not less(current, maximum) or less(maximum_start, current) then
  return redis.error_reply('SEQUENCE_EXHAUSTED')
end
if less(current, floor) then
  redis.call('SET', KEYS[1], floor)
end
local first = false
for index = 1, count do
  redis.call('INCR', KEYS[1])
  if index == 1 then first = redis.call('GET', KEYS[1]) end
end
return {first, redis.call('GET', KEYS[1])}
"#;

const PUBLISH_SCRIPT: &str = r#"
local task_id = ARGV[1]
local task_json = ARGV[2]
local ttl = tonumber(ARGV[3])
local sent_file = ARGV[4]
local domain_count = tonumber(ARGV[5])
local max_active = tonumber(ARGV[6])
local task_type = redis.call('TYPE', KEYS[1]).ok
local domain_type = redis.call('TYPE', KEYS[2]).ok
local sent_index_type = redis.call('TYPE', KEYS[3]).ok
local pending_type = redis.call('TYPE', KEYS[4]).ok
local processing_type = redis.call('TYPE', KEYS[5]).ok
local retry_type = redis.call('TYPE', KEYS[7]).ok
if (task_type ~= 'none' and task_type ~= 'string')
  or (domain_type ~= 'none' and domain_type ~= 'hash')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (retry_type ~= 'none' and retry_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end

local existing = false
if task_type == 'string' then
  existing = redis.call('GET', KEYS[1])
  if existing ~= task_json then
    return redis.error_reply('TASK_ID_CONFLICT')
  end
end

local domains_exist = domain_type == 'hash'
local domain_offset = 7
if domains_exist then
  if redis.call('HLEN', KEYS[2]) ~= domain_count then
    return redis.error_reply('DOMAIN_STATUS_CONFLICT')
  end
  for index = 1, domain_count do
    if redis.call('HGET', KEYS[2], ARGV[domain_offset]) ~= ARGV[domain_offset + 1] then
      return redis.error_reply('DOMAIN_STATUS_CONFLICT')
    end
    domain_offset = domain_offset + 2
  end
end

if sent_file ~= '' then
  local indexed = redis.call('HGET', KEYS[3], sent_file)
  if indexed and indexed ~= task_id then
    return redis.error_reply('SENT_FILE_CONFLICT')
  end
end

local is_processing = redis.call('SISMEMBER', KEYS[5], task_id) == 1
local is_retrying = redis.call('ZSCORE', KEYS[7], task_id) ~= false
local is_pending = redis.call('LPOS', KEYS[4], task_id) ~= false
if not is_processing and not is_retrying and not is_pending then
  local active_count = redis.call('LLEN', KEYS[4])
    + redis.call('SCARD', KEYS[5])
    + redis.call('ZCARD', KEYS[7])
  if active_count >= max_active then return -1 end
end

local created = 0
if not existing then
  redis.call('SET', KEYS[1], task_json, 'EX', ttl)
  created = 1
else
  redis.call('EXPIRE', KEYS[1], ttl)
end

if not domains_exist then
  local offset = 7
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

const ACTIVE_REFERENCE_UPPER_BOUND_SCRIPT: &str = r#"
local limit = tonumber(ARGV[1])
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local retry_type = redis.call('TYPE', KEYS[3]).ok
if (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (retry_type ~= 'none' and retry_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end
local references = redis.call('LLEN', KEYS[1])
  + redis.call('SCARD', KEYS[2])
  + redis.call('ZCARD', KEYS[3])
return math.min(references, limit)
"#;

const RENEW_PENDING_TTLS_SCRIPT: &str = r#"
local pending_type = redis.call('TYPE', KEYS[1]).ok
if pending_type == 'none' then return {'OK', '0', '0'} end
if pending_type ~= 'list' then return redis.error_reply('WRONGTYPE') end

local offset = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local length = redis.call('LLEN', KEYS[1])
if length == 0 then return {'OK', '0', '0'} end
if offset < 0 or offset >= length then offset = 0 end
local last = math.min(offset + limit - 1, length - 1)
local ids = redis.call('LRANGE', KEYS[1], offset, last)
local seen = {}
local tasks = {}

for _, task_id in ipairs(ids) do
  if not string.match(task_id, '^[1-9][0-9]*$') or string.len(task_id) > 19 then
    return {'INVALID', task_id}
  end
  if not seen[task_id] then
    seen[task_id] = true
    local task_key = ARGV[4] .. task_id
    local domain_key = ARGV[5] .. task_id
    local task_type = redis.call('TYPE', task_key).ok
    local domain_type = redis.call('TYPE', domain_key).ok
    if task_type == 'none' then return {'MISSING', task_id} end
    if task_type ~= 'string'
      or (domain_type ~= 'none' and domain_type ~= 'hash') then
      return redis.error_reply('WRONGTYPE')
    end
    table.insert(tasks, {task_key, domain_key, domain_type})
  end
end

for _, task in ipairs(tasks) do
  redis.call('EXPIRE', task[1], ttl)
  if task[3] == 'hash' then redis.call('EXPIRE', task[2], ttl) end
end
local next_offset = last + 1
if next_offset >= length then next_offset = 0 end
return {'OK', tostring(next_offset), tostring(#tasks)}
"#;

const CLAIM_LEGACY_LIST_RECORD_SCRIPT: &str = r#"
local token = ARGV[1]
local done_key = ARGV[3] .. token
local source_type = redis.call('TYPE', KEYS[1]).ok
local inflight_type = redis.call('TYPE', KEYS[2]).ok
local payloads_type = redis.call('TYPE', KEYS[3]).ok
local quarantine_type = redis.call('TYPE', KEYS[4]).ok
local quarantine_metadata_type = redis.call('TYPE', KEYS[5]).ok
local quarantine_bytes_type = redis.call('TYPE', KEYS[6]).ok
local done_index_type = redis.call('TYPE', KEYS[7]).ok
local done_type = redis.call('TYPE', done_key).ok
if (source_type ~= 'none' and source_type ~= 'list')
  or (inflight_type ~= 'none' and inflight_type ~= 'list')
  or (payloads_type ~= 'none' and payloads_type ~= 'hash')
  or (quarantine_type ~= 'none' and quarantine_type ~= 'list')
  or (quarantine_metadata_type ~= 'none' and quarantine_metadata_type ~= 'hash')
  or (quarantine_bytes_type ~= 'none' and quarantine_bytes_type ~= 'string')
  or (done_index_type ~= 'none' and done_index_type ~= 'zset')
  or (done_type ~= 'none' and done_type ~= 'string') then
  return {'INCONSISTENT'}
end
local now = tonumber(redis.call('TIME')[1])
local function receipt_slot_available()
  local active = redis.call('ZCOUNT', KEYS[7], '(' .. tostring(now), '+inf')
  local token_score = redis.call('ZSCORE', KEYS[7], token)
  if token_score and tonumber(token_score) > now then active = active - 1 end
  return active < tonumber(ARGV[7])
end
if done_type == 'string' then
  local done = redis.call('GET', done_key)
  if done == 'EMPTY' then
    if redis.call('ZSCORE', KEYS[7], token) == false then
      return {'INCONSISTENT'}
    end
    if redis.call('LINDEX', KEYS[1], 0) == false then
      if ARGV[8] == 'CREATE' then
        redis.call('EXPIRE', done_key, ARGV[4])
        redis.call('ZADD', KEYS[7], now + tonumber(ARGV[4]), token)
      end
      return {'EMPTY'}
    end
    redis.call('DEL', done_key)
    redis.call('ZREM', KEYS[7], token)
    done_type = 'none'
  elseif done == 'ACKED'
    and redis.call('LPOS', KEYS[2], token) == false
    and redis.call('HEXISTS', KEYS[3], token) == 0 then
    return {'SETTLED'}
  else
    local bytes, digest = string.match(done, '^QUARANTINED:([0-9]+):([0-9a-f]+)$')
    local metadata = redis.call('HGET', KEYS[5], token)
    if bytes and digest
      and redis.call('LPOS', KEYS[2], token) == false
      and redis.call('HEXISTS', KEYS[3], token) == 0
      and metadata
      and string.sub(metadata, 1, string.len(bytes) + string.len(digest) + 1)
        == bytes .. ':' .. digest then
      return {'QUARANTINED', bytes, digest}
    end
    return {'INCONSISTENT'}
  end
end
if done_type ~= 'none' then return {'INCONSISTENT'} end

local inflight_count = redis.call('LLEN', KEYS[2])
if inflight_count > 1 then return {'INCONSISTENT'} end
if inflight_count == 1 then
  local inflight_token = redis.call('LINDEX', KEYS[2], 0)
  local payload = redis.call('HGET', KEYS[3], inflight_token)
  if not payload then return {'INCONSISTENT'} end
  return {'RECORD', inflight_token, payload}
end
if redis.call('HLEN', KEYS[3]) ~= 0 then return {'INCONSISTENT'} end

local payload = redis.call('LINDEX', KEYS[1], 0)
if not payload then
  if ARGV[8] ~= 'CREATE' then
    redis.call('ZREMRANGEBYSCORE', KEYS[7], '-inf', now)
    return {'EMPTY'}
  end
  if not receipt_slot_available() then return {'RECEIPT_FULL'} end
  redis.call('ZREMRANGEBYSCORE', KEYS[7], '-inf', now)
  redis.call('ZREM', KEYS[7], token)
  redis.call('SET', done_key, 'EMPTY', 'EX', ARGV[4])
  redis.call('ZADD', KEYS[7], now + tonumber(ARGV[4]), token)
  return {'EMPTY'}
end
local payload_bytes = string.len(payload)
if payload_bytes > tonumber(ARGV[2]) then
  local digest = redis.sha1hex(payload)
  local quarantine_count = redis.call('LLEN', KEYS[4])
  local metadata_count = redis.call('HLEN', KEYS[5])
  if quarantine_count >= tonumber(ARGV[5]) or metadata_count ~= quarantine_count then
    return {'QUARANTINE_FULL'}
  end
  local current_bytes = 0
  local recorded_bytes = redis.call('GET', KEYS[6])
  if recorded_bytes then
    current_bytes = tonumber(recorded_bytes)
    if not current_bytes or current_bytes < 0 then return {'QUARANTINE_FULL'} end
  else
    for _, value in ipairs(redis.call('LRANGE', KEYS[4], 0, -1)) do
      current_bytes = current_bytes + string.len(value)
    end
    for _, value in ipairs(redis.call('HVALS', KEYS[5])) do
      current_bytes = current_bytes + string.len(value)
    end
    for _, field in ipairs(redis.call('HKEYS', KEYS[5])) do
      current_bytes = current_bytes + string.len(field)
    end
    if current_bytes > tonumber(ARGV[6]) then return {'QUARANTINE_FULL'} end
  end
  local metadata = tostring(payload_bytes) .. ':' .. digest .. ':oversized'
  local added_bytes = payload_bytes + string.len(token) + string.len(metadata)
  if current_bytes + added_bytes > tonumber(ARGV[6]) then
    return {'QUARANTINE_FULL'}
  end
  if not receipt_slot_available() then return {'RECEIPT_FULL'} end
  redis.call('ZREMRANGEBYSCORE', KEYS[7], '-inf', now)
  redis.call('ZREM', KEYS[7], token)
  redis.call('LPOP', KEYS[1])
  redis.call('RPUSH', KEYS[4], payload)
  redis.call('HSET', KEYS[5], token, metadata)
  redis.call('SET', KEYS[6], tostring(current_bytes + added_bytes))
  redis.call(
    'SET', done_key, 'QUARANTINED:' .. tostring(payload_bytes) .. ':' .. digest,
    'EX', ARGV[4]
  )
  redis.call('ZADD', KEYS[7], now + tonumber(ARGV[4]), token)
  return {'QUARANTINED', tostring(payload_bytes), digest}
end
redis.call('LPOP', KEYS[1])
redis.call('HSET', KEYS[3], token, payload)
redis.call('RPUSH', KEYS[2], token)
return {'RECORD', token, payload}
"#;

const ACK_LEGACY_LIST_RECORD_SCRIPT: &str = r#"
local done_key = ARGV[2] .. ARGV[1]
local inflight_type = redis.call('TYPE', KEYS[1]).ok
local payloads_type = redis.call('TYPE', KEYS[2]).ok
local done_index_type = redis.call('TYPE', KEYS[3]).ok
local done_type = redis.call('TYPE', done_key).ok
if (inflight_type ~= 'none' and inflight_type ~= 'list')
  or (payloads_type ~= 'none' and payloads_type ~= 'hash')
  or (done_index_type ~= 'none' and done_index_type ~= 'zset')
  or (done_type ~= 'none' and done_type ~= 'string') then
  return -2
end
local now = tonumber(redis.call('TIME')[1])
local function receipt_slot_available()
  local active = redis.call('ZCOUNT', KEYS[3], '(' .. tostring(now), '+inf')
  local token_score = redis.call('ZSCORE', KEYS[3], ARGV[1])
  if token_score and tonumber(token_score) > now then active = active - 1 end
  return active < tonumber(ARGV[4])
end
if done_type == 'string' then
  if redis.call('GET', done_key) == 'ACKED'
    and redis.call('LPOS', KEYS[1], ARGV[1]) == false
    and redis.call('HEXISTS', KEYS[2], ARGV[1]) == 0 then
    return 1
  end
  return 0
end
if done_type ~= 'none' then return 0 end
if redis.call('LLEN', KEYS[1]) ~= 1
  or redis.call('LINDEX', KEYS[1], 0) ~= ARGV[1]
  or redis.call('HEXISTS', KEYS[2], ARGV[1]) ~= 1 then
  return 0
end
if not receipt_slot_available() then return -2 end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
redis.call('ZREM', KEYS[3], ARGV[1])
redis.call('LPOP', KEYS[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('SET', done_key, 'ACKED', 'EX', ARGV[3])
redis.call('ZADD', KEYS[3], now + tonumber(ARGV[3]), ARGV[1])
return 1
"#;

const QUARANTINE_LEGACY_LIST_RECORD_SCRIPT: &str = r#"
local done_key = ARGV[3] .. ARGV[1]
local inflight_type = redis.call('TYPE', KEYS[1]).ok
local payloads_type = redis.call('TYPE', KEYS[2]).ok
local quarantine_type = redis.call('TYPE', KEYS[3]).ok
local quarantine_metadata_type = redis.call('TYPE', KEYS[4]).ok
local quarantine_bytes_type = redis.call('TYPE', KEYS[5]).ok
local done_index_type = redis.call('TYPE', KEYS[6]).ok
local done_type = redis.call('TYPE', done_key).ok
if (inflight_type ~= 'none' and inflight_type ~= 'list')
  or (payloads_type ~= 'none' and payloads_type ~= 'hash')
  or (quarantine_type ~= 'none' and quarantine_type ~= 'list')
  or (quarantine_metadata_type ~= 'none' and quarantine_metadata_type ~= 'hash')
  or (quarantine_bytes_type ~= 'none' and quarantine_bytes_type ~= 'string')
  or (done_index_type ~= 'none' and done_index_type ~= 'zset')
  or (done_type ~= 'none' and done_type ~= 'string') then
  return -2
end
local now = tonumber(redis.call('TIME')[1])
local function receipt_slot_available()
  local active = redis.call('ZCOUNT', KEYS[6], '(' .. tostring(now), '+inf')
  local token_score = redis.call('ZSCORE', KEYS[6], ARGV[1])
  if token_score and tonumber(token_score) > now then active = active - 1 end
  return active < tonumber(ARGV[8])
end
if done_type == 'string' then
  local done = redis.call('GET', done_key)
  local bytes, digest = string.match(done, '^QUARANTINED:([0-9]+):([0-9a-f]+)$')
  local metadata = redis.call('HGET', KEYS[4], ARGV[1])
  if bytes and digest
    and redis.call('LPOS', KEYS[1], ARGV[1]) == false
    and redis.call('HEXISTS', KEYS[2], ARGV[1]) == 0
    and metadata
    and string.sub(metadata, 1, string.len(bytes) + string.len(digest) + 1)
      == bytes .. ':' .. digest then
    return 1
  end
  return 0
end
if done_type ~= 'none' then return 0 end
if redis.call('LLEN', KEYS[1]) ~= 1
  or redis.call('LINDEX', KEYS[1], 0) ~= ARGV[1] then
  return 0
end
local payload = redis.call('HGET', KEYS[2], ARGV[1])
if not payload then return 0 end
local payload_bytes = string.len(payload)
if payload_bytes > tonumber(ARGV[5]) then return -2 end
local digest = redis.sha1hex(payload)
local quarantine_count = redis.call('LLEN', KEYS[3])
local metadata_count = redis.call('HLEN', KEYS[4])
if quarantine_count >= tonumber(ARGV[6]) or metadata_count ~= quarantine_count then
  return -2
end
local current_bytes = 0
local recorded_bytes = redis.call('GET', KEYS[5])
if recorded_bytes then
  current_bytes = tonumber(recorded_bytes)
  if not current_bytes or current_bytes < 0 then return -2 end
else
  for _, value in ipairs(redis.call('LRANGE', KEYS[3], 0, -1)) do
    current_bytes = current_bytes + string.len(value)
  end
  for _, value in ipairs(redis.call('HVALS', KEYS[4])) do
    current_bytes = current_bytes + string.len(value)
  end
  for _, field in ipairs(redis.call('HKEYS', KEYS[4])) do
    current_bytes = current_bytes + string.len(field)
  end
  if current_bytes > tonumber(ARGV[7]) then return -2 end
end
local metadata = tostring(payload_bytes) .. ':' .. digest .. ':' .. ARGV[2]
local added_bytes = payload_bytes + string.len(ARGV[1]) + string.len(metadata)
if current_bytes + added_bytes > tonumber(ARGV[7]) then return -2 end
if not receipt_slot_available() then return -2 end
redis.call('ZREMRANGEBYSCORE', KEYS[6], '-inf', now)
redis.call('ZREM', KEYS[6], ARGV[1])
redis.call('RPUSH', KEYS[3], payload)
redis.call(
  'HSET', KEYS[4], ARGV[1],
  metadata
)
redis.call('LPOP', KEYS[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('SET', KEYS[5], tostring(current_bytes + added_bytes))
redis.call(
  'SET', done_key, 'QUARANTINED:' .. tostring(payload_bytes) .. ':' .. digest,
  'EX', ARGV[4]
)
redis.call('ZADD', KEYS[6], now + tonumber(ARGV[4]), ARGV[1])
return 1
"#;

const CLEANUP_MIGRATED_TERMINAL_TASK_SCRIPT: &str = r#"
local task_id = ARGV[1]
local sent_file = ARGV[2]
local receipt_value = ARGV[3]
local lease_key = ARGV[4] .. task_id
local receipt_key = ARGV[5] .. task_id
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local retry_type = redis.call('TYPE', KEYS[4]).ok
local task_type = redis.call('TYPE', KEYS[5]).ok
local sent_index_type = redis.call('TYPE', KEYS[6]).ok
local receipt_index_type = redis.call('TYPE', KEYS[7]).ok
local lease_type = redis.call('TYPE', lease_key).ok
local receipt_type = redis.call('TYPE', receipt_key).ok
if (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (receipt_index_type ~= 'none' and receipt_index_type ~= 'zset')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (receipt_type ~= 'none' and receipt_type ~= 'string') then
  return -2
end
local now = tonumber(redis.call('TIME')[1])
local function receipt_slot_available()
  local active = redis.call('ZCOUNT', KEYS[7], '(' .. tostring(now), '+inf')
  local task_score = redis.call('ZSCORE', KEYS[7], task_id)
  if task_score and tonumber(task_score) > now then active = active - 1 end
  return active < tonumber(ARGV[7])
end
if receipt_type == 'string' then
  if redis.call('GET', receipt_key) ~= receipt_value then return -2 end
  if lease_type ~= 'none'
    or redis.call('EXISTS', KEYS[5]) ~= 0
    or redis.call('LPOS', KEYS[1], task_id) ~= false
    or redis.call('SISMEMBER', KEYS[2], task_id) ~= 0
    or redis.call('HEXISTS', KEYS[3], task_id) ~= 0
    or redis.call('ZSCORE', KEYS[4], task_id) ~= false
    or redis.call('HGET', KEYS[6], sent_file) ~= false then
    return -2
  end
  return 1
end
if receipt_type ~= 'none' then return -2 end
if lease_type ~= 'none' then return 0 end
local indexed = redis.call('HGET', KEYS[6], sent_file)
if indexed and indexed ~= task_id then return -1 end
if not receipt_slot_available() then return -2 end
redis.call('ZREMRANGEBYSCORE', KEYS[7], '-inf', now)
redis.call('ZREM', KEYS[7], task_id)
redis.call('LREM', KEYS[1], 0, task_id)
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
redis.call('ZREM', KEYS[4], task_id)
redis.call('DEL', KEYS[5])
redis.call('HDEL', KEYS[6], sent_file)
if redis.call('EXISTS', KEYS[5]) ~= 0
  or redis.call('LPOS', KEYS[1], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[2], task_id) ~= 0
  or redis.call('HEXISTS', KEYS[3], task_id) ~= 0
  or redis.call('ZSCORE', KEYS[4], task_id) ~= false
  or redis.call('HGET', KEYS[6], sent_file) ~= false then
  return -2
end
redis.call('SET', receipt_key, receipt_value, 'EX', ARGV[6])
redis.call('ZADD', KEYS[7], now + tonumber(ARGV[6]), task_id)
return 1
"#;

const RENEW_SCRIPT: &str = r#"
local task_id = ARGV[1]
local ttl = tonumber(ARGV[2])
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local retry_type = redis.call('TYPE', KEYS[3]).ok
local task_type = redis.call('TYPE', KEYS[4]).ok
local domain_type = redis.call('TYPE', KEYS[5]).ok
if (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (domain_type ~= 'none' and domain_type ~= 'hash') then
  return redis.error_reply('WRONGTYPE')
end
local referenced = redis.call('LPOS', KEYS[1], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[2], task_id) == 1
  or redis.call('ZSCORE', KEYS[3], task_id) ~= false
if not referenced then return 0 end
if task_type == 'none' then return -1 end
redis.call('EXPIRE', KEYS[4], ttl)
if domain_type == 'hash' then redis.call('EXPIRE', KEYS[5], ttl) end
return 1
"#;

const COMPLETE_TASK_SCRIPT: &str = r#"
local task_id = ARGV[1]
local expected_task_json = ARGV[2]
local sent_file = ARGV[3]
local ttl = tonumber(ARGV[4])
local domain_count = tonumber(ARGV[5])
local task_type = redis.call('TYPE', KEYS[1]).ok
local domain_type = redis.call('TYPE', KEYS[2]).ok
local sent_index_type = redis.call('TYPE', KEYS[3]).ok
local pending_type = redis.call('TYPE', KEYS[4]).ok
local processing_type = redis.call('TYPE', KEYS[5]).ok
local retry_type = redis.call('TYPE', KEYS[6]).ok
if (task_type ~= 'none' and task_type ~= 'string')
  or (domain_type ~= 'none' and domain_type ~= 'hash')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (retry_type ~= 'none' and retry_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end
if task_type == 'none' then
  if domain_type == 'hash' then return 'CONFLICT' end
  return 'MISSING'
end
if domain_type == 'none' then return 'MISSING' end
if redis.call('GET', KEYS[1]) ~= expected_task_json then return 'CONFLICT' end
if redis.call('HLEN', KEYS[2]) ~= domain_count then return 'CONFLICT' end
local offset = 6
for index = 1, domain_count do
  if redis.call('HGET', KEYS[2], ARGV[offset]) ~= ARGV[offset + 1] then
    return 'CONFLICT'
  end
  offset = offset + 2
end
if sent_file ~= '' then
  local indexed = redis.call('HGET', KEYS[3], sent_file)
  if not indexed then return 'MISSING' end
  if indexed ~= task_id then return 'CONFLICT' end
end
local referenced = redis.call('LPOS', KEYS[4], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[5], task_id) == 1
  or redis.call('ZSCORE', KEYS[6], task_id) ~= false
if not referenced then return 'MISSING' end
redis.call('EXPIRE', KEYS[1], ttl)
redis.call('EXPIRE', KEYS[2], ttl)
return 'EXACT'
"#;

const CLAIM_SCRIPT: &str = r#"
local attempt_key = ARGV[8] .. ARGV[1]
local settlement_key = ARGV[9] .. ARGV[1]
local claim_result_key = ARGV[10] .. ARGV[1]
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local claim_index_type = redis.call('TYPE', KEYS[4]).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local settlement_type = redis.call('TYPE', settlement_key).ok
local claim_result_type = redis.call('TYPE', claim_result_key).ok
if (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (claim_index_type ~= 'none' and claim_index_type ~= 'zset')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (settlement_type ~= 'none' and settlement_type ~= 'string')
  or (claim_result_type ~= 'none' and claim_result_type ~= 'string') then
  return redis.error_reply('WRONGTYPE')
end
if claim_result_type == 'string' then
  if redis.call('GET', claim_result_key) == 'EMPTY' then return {'', '', '3'} end
  return {'', '', '2'}
end
if attempt_type ~= 'none' or settlement_type ~= 'none' then
  return {'', '', '2'}
end

if redis.call('LLEN', KEYS[1]) == 0 then return {'', '', '3'} end
local task_id = redis.call('LINDEX', KEYS[1], 0)
if not task_id or string.len(task_id) < 1 or string.len(task_id) > tonumber(ARGV[12])
  or not string.match(task_id, '^[1-9][0-9]*$')
  or (string.len(task_id) == string.len(ARGV[14]) and task_id > ARGV[14]) then
  return redis.error_reply('INVALID_TASK_ID')
end
local lease_key = ARGV[4] .. task_id
local task_key = ARGV[5] .. task_id
local domain_key = ARGV[6] .. task_id
local lease_type = redis.call('TYPE', lease_key).ok
local task_type = redis.call('TYPE', task_key).ok
local domain_type = redis.call('TYPE', domain_key).ok
if (lease_type ~= 'none' and lease_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (domain_type ~= 'none' and domain_type ~= 'hash') then
  return redis.error_reply('WRONGTYPE')
end
if lease_type == 'string' then return {task_id, '', '0'} end
if task_type == 'string' and redis.call('STRLEN', task_key) > tonumber(ARGV[13]) then
  return redis.error_reply('TASK_TOO_LARGE')
end

local now = tonumber(redis.call('TIME')[1]) * 1000
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', now)
if redis.call('ZSCORE', KEYS[4], ARGV[1]) ~= false then
  redis.call('ZREM', KEYS[4], ARGV[1])
end
if redis.call('ZCARD', KEYS[4]) >= tonumber(ARGV[11]) then
  return {'', '', '4'}
end
local popped_task_id = redis.call('LPOP', KEYS[1])
if popped_task_id ~= task_id then return redis.error_reply('QUEUE_CHANGED') end
local acquired = redis.call('SET', lease_key, ARGV[1], 'NX', 'PX', ARGV[2])
if not acquired then return redis.error_reply('LEASE_RACE') end

redis.call('SET', attempt_key, task_id, 'PX', ARGV[2])
redis.call('SET', claim_result_key, task_id, 'PX', ARGV[2])
redis.call('ZADD', KEYS[4], now + tonumber(ARGV[2]), ARGV[1])
redis.call('SADD', KEYS[2], task_id)
redis.call('HSET', KEYS[3], task_id, ARGV[3])
local task_json = redis.call('GET', task_key) or ''
if task_json ~= '' then redis.call('EXPIRE', task_key, ARGV[7]) end
if redis.call('EXISTS', domain_key) == 1 then redis.call('EXPIRE', domain_key, ARGV[7]) end
return {task_id, task_json, '1'}
"#;

const RENEW_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[5] .. task_id
local attempt_key = ARGV[9] .. ARGV[2]
local task_key = ARGV[6] .. task_id
local domain_key = ARGV[7] .. task_id
local processing_type = redis.call('TYPE', KEYS[1]).ok
local processing_time_type = redis.call('TYPE', KEYS[2]).ok
local lease_type = redis.call('TYPE', lease_key).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local task_type = redis.call('TYPE', task_key).ok
local domain_type = redis.call('TYPE', domain_key).ok
if (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (domain_type ~= 'none' and domain_type ~= 'hash') then
  return redis.error_reply('WRONGTYPE')
end
if lease_type ~= 'string' or redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
if attempt_type ~= 'string' or redis.call('GET', attempt_key) ~= task_id then return 0 end
if processing_type ~= 'set'
  or redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then return 0 end

redis.call('PEXPIRE', lease_key, ARGV[3])
redis.call('PEXPIRE', attempt_key, ARGV[3])
redis.call('HSET', KEYS[2], task_id, ARGV[4])
if task_type == 'string' then redis.call('EXPIRE', task_key, ARGV[8]) end
if domain_type == 'hash' then redis.call('EXPIRE', domain_key, ARGV[8]) end
return 1
"#;

const REPLACE_CLAIMED_TASK_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[4] .. task_id
local attempt_key = ARGV[5] .. ARGV[2]
local task_key = ARGV[6] .. task_id
local processing_type = redis.call('TYPE', KEYS[1]).ok
local lease_type = redis.call('TYPE', lease_key).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local task_type = redis.call('TYPE', task_key).ok
if (processing_type ~= 'none' and processing_type ~= 'set')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string') then
  return redis.error_reply('WRONGTYPE')
end
if lease_type ~= 'string' or redis.call('GET', lease_key) ~= ARGV[2] then return 'STALE' end
if attempt_type ~= 'string' or redis.call('GET', attempt_key) ~= task_id then return 'STALE' end
if processing_type ~= 'set'
  or redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then return 'STALE' end
if task_type == 'none' then return 'MISSING' end
redis.call('SET', task_key, ARGV[3], 'EX', ARGV[7])
return 'OK'
"#;

const READ_CLAIMED_TASK_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[3] .. task_id
if redis.call('GET', lease_key) ~= ARGV[2] then return {'STALE'} end
local attempt_key = ARGV[4] .. ARGV[2]
if redis.call('GET', attempt_key) ~= task_id then return {'STALE'} end
if redis.call('SISMEMBER', KEYS[1], task_id) ~= 1 then return {'STALE'} end
local task_json = redis.call('GET', ARGV[5] .. task_id)
if not task_json then return {'MISSING'} end
return {'OK', task_json}
"#;

const RELEASE_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
local settlement_key = ARGV[6] .. ARGV[2]
local lease_key = ARGV[4] .. task_id
local attempt_key = ARGV[5] .. ARGV[2]
local task_key = ARGV[9] .. task_id
local settlement_type = redis.call('TYPE', settlement_key).ok
local lease_type = redis.call('TYPE', lease_key).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local task_type = redis.call('TYPE', task_key).ok
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local retry_type = redis.call('TYPE', KEYS[4]).ok
local settlement_index_type = redis.call('TYPE', KEYS[5]).ok
local claim_index_type = redis.call('TYPE', KEYS[6]).ok
if (settlement_type ~= 'none' and settlement_type ~= 'string')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (settlement_index_type ~= 'none' and settlement_index_type ~= 'zset')
  or (claim_index_type ~= 'none' and claim_index_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end
local now = tonumber(redis.call('TIME')[1])
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', now)
if settlement_type == 'string' then
  if redis.call('GET', settlement_key) == ARGV[7] then
    return 1
  end
  return 0
end
if settlement_type ~= 'none' then return 0 end
redis.call('ZREM', KEYS[5], ARGV[2])
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
if redis.call('GET', attempt_key) ~= task_id then return 0 end
if ARGV[3] == '1' then
  if task_type ~= 'string' then return 0 end
  local task_bytes = redis.call('STRLEN', task_key)
  if task_bytes < 1 or task_bytes > tonumber(ARGV[10]) then
    return 0
  end
end
if redis.call('ZCARD', KEYS[5]) >= tonumber(ARGV[11]) then return -2 end

redis.call('SET', settlement_key, ARGV[7], 'EX', ARGV[8])
redis.call('ZADD', KEYS[5], now + tonumber(ARGV[8]), ARGV[2])
redis.call('ZREM', KEYS[6], ARGV[2])
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
local settlement_key = ARGV[9] .. ARGV[2]
local lease_key = ARGV[6] .. task_id
local task_key = ARGV[7] .. task_id
local attempt_key = ARGV[8] .. ARGV[2]
local settlement_type = redis.call('TYPE', settlement_key).ok
local lease_type = redis.call('TYPE', lease_key).ok
local task_type = redis.call('TYPE', task_key).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local retry_type = redis.call('TYPE', KEYS[4]).ok
local settlement_index_type = redis.call('TYPE', KEYS[5]).ok
local claim_index_type = redis.call('TYPE', KEYS[6]).ok
if (settlement_type ~= 'none' and settlement_type ~= 'string')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (settlement_index_type ~= 'none' and settlement_index_type ~= 'zset')
  or (claim_index_type ~= 'none' and claim_index_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end
local now = tonumber(redis.call('TIME')[1])
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', now)
if settlement_type == 'string' then
  if redis.call('GET', settlement_key) == ARGV[10] then return 1 end
  return 0
end
if settlement_type ~= 'none' then return 0 end
redis.call('ZREM', KEYS[5], ARGV[2])
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
if redis.call('GET', attempt_key) ~= task_id then return 0 end
if redis.call('ZCARD', KEYS[5]) >= tonumber(ARGV[12]) then return -2 end

redis.call('SET', task_key, ARGV[3], 'EX', ARGV[5])
redis.call('SET', settlement_key, ARGV[10], 'EX', ARGV[11])
redis.call('ZADD', KEYS[5], now + tonumber(ARGV[11]), ARGV[2])
redis.call('ZREM', KEYS[6], ARGV[2])
redis.call('DEL', lease_key, attempt_key)
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
redis.call('LREM', KEYS[1], 0, task_id)
redis.call('ZADD', KEYS[4], tonumber(ARGV[4]) / 1000, task_id)
return 1
"#;

const ACKNOWLEDGE_SCRIPT: &str = r#"
local task_id = ARGV[1]
local settlement_key = ARGV[6] .. ARGV[2]
local sent_file = ARGV[9]
local lease_key = ARGV[3] .. task_id
local task_key = ARGV[4] .. task_id
local attempt_key = ARGV[5] .. ARGV[2]
local settlement_type = redis.call('TYPE', settlement_key).ok
local lease_type = redis.call('TYPE', lease_key).ok
local task_type = redis.call('TYPE', task_key).ok
local attempt_type = redis.call('TYPE', attempt_key).ok
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local retry_type = redis.call('TYPE', KEYS[4]).ok
local sent_index_type = redis.call('TYPE', KEYS[5]).ok
local settlement_index_type = redis.call('TYPE', KEYS[6]).ok
local claim_index_type = redis.call('TYPE', KEYS[7]).ok
if (settlement_type ~= 'none' and settlement_type ~= 'string')
  or (lease_type ~= 'none' and lease_type ~= 'string')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (settlement_index_type ~= 'none' and settlement_index_type ~= 'zset')
  or (claim_index_type ~= 'none' and claim_index_type ~= 'zset') then
  return redis.error_reply('WRONGTYPE')
end
local now = tonumber(redis.call('TIME')[1])
redis.call('ZREMRANGEBYSCORE', KEYS[6], '-inf', now)
if settlement_type == 'string' then
  if redis.call('GET', settlement_key) == ARGV[7]
    and redis.call('EXISTS', task_key) == 0
    and redis.call('LPOS', KEYS[1], task_id) == false
    and redis.call('SISMEMBER', KEYS[2], task_id) == 0
    and redis.call('HEXISTS', KEYS[3], task_id) == 0
    and redis.call('ZSCORE', KEYS[4], task_id) == false
    and (sent_file == '' or redis.call('HGET', KEYS[5], sent_file) == false) then
    return 1
  end
  return 0
end
if settlement_type ~= 'none' then return 0 end
redis.call('ZREM', KEYS[6], ARGV[2])
if redis.call('GET', lease_key) ~= ARGV[2] then return 0 end
if redis.call('GET', attempt_key) ~= task_id then return 0 end
if sent_file ~= '' then
  local indexed = redis.call('HGET', KEYS[5], sent_file)
  if indexed and indexed ~= task_id then return 0 end
end
if redis.call('ZCARD', KEYS[6]) >= tonumber(ARGV[10]) then return -2 end

redis.call('SET', settlement_key, ARGV[7], 'EX', ARGV[8])
redis.call('ZADD', KEYS[6], now + tonumber(ARGV[8]), ARGV[2])
redis.call('DEL', lease_key, attempt_key)
redis.call('ZREM', KEYS[7], ARGV[2])
redis.call('SREM', KEYS[2], task_id)
redis.call('HDEL', KEYS[3], task_id)
redis.call('LREM', KEYS[1], 0, task_id)
redis.call('ZREM', KEYS[4], task_id)
redis.call('DEL', task_key)
if sent_file ~= '' then redis.call('HDEL', KEYS[5], sent_file) end
return 1
"#;

const VERIFY_TERMINAL_ACKNOWLEDGEMENT_SCRIPT: &str = r#"
local task_id = ARGV[1]
local sent_file = ARGV[2]
local task_type = redis.call('TYPE', KEYS[1]).ok
local pending_type = redis.call('TYPE', KEYS[2]).ok
local processing_type = redis.call('TYPE', KEYS[3]).ok
local processing_time_type = redis.call('TYPE', KEYS[4]).ok
local retry_type = redis.call('TYPE', KEYS[5]).ok
local sent_index_type = redis.call('TYPE', KEYS[6]).ok
local lease_type = redis.call('TYPE', KEYS[7]).ok
if (task_type ~= 'none' and task_type ~= 'string')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (lease_type ~= 'none' and lease_type ~= 'string') then
  return redis.error_reply('WRONGTYPE')
end

local indexed = redis.call('HGET', KEYS[6], sent_file)
if indexed and indexed ~= task_id then return 'CONFLICT' end
if task_type ~= 'none'
  or lease_type ~= 'none'
  or redis.call('LPOS', KEYS[2], task_id) ~= false
  or redis.call('SISMEMBER', KEYS[3], task_id) ~= 0
  or redis.call('HEXISTS', KEYS[4], task_id) ~= 0
  or redis.call('ZSCORE', KEYS[5], task_id) ~= false
  or indexed ~= false then
  return 'ACTIVE'
end
return 'ACKNOWLEDGED'
"#;

const RECONCILE_SETTLEMENT_SCRIPT: &str = r#"
local settlement_type = redis.call('TYPE', KEYS[1]).ok
local attempt_type = redis.call('TYPE', KEYS[2]).ok
local processing_type = redis.call('TYPE', KEYS[3]).ok
local processing_time_type = redis.call('TYPE', KEYS[4]).ok
local pending_type = redis.call('TYPE', KEYS[5]).ok
local retry_type = redis.call('TYPE', KEYS[6]).ok
local task_type = redis.call('TYPE', KEYS[7]).ok
local sent_index_type = redis.call('TYPE', KEYS[8]).ok
local settlement_index_type = redis.call('TYPE', KEYS[9]).ok
local lease_key = ARGV[4] .. ARGV[1]
local lease_type = redis.call('TYPE', lease_key).ok
if (settlement_type ~= 'none' and settlement_type ~= 'string')
  or (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (task_type ~= 'none' and task_type ~= 'string')
  or (sent_index_type ~= 'none' and sent_index_type ~= 'hash')
  or (settlement_index_type ~= 'none' and settlement_index_type ~= 'zset')
  or (lease_type ~= 'none' and lease_type ~= 'string') then
  return redis.error_reply('WRONGTYPE')
end
local now = tonumber(redis.call('TIME')[1])
redis.call('ZREMRANGEBYSCORE', KEYS[9], '-inf', now)
if settlement_type == 'string' then
  local value_bytes = redis.call('STRLEN', KEYS[1])
  local ttl = redis.call('PTTL', KEYS[1])
  if value_bytes < 1 or value_bytes > tonumber(ARGV[5]) or ttl < 1
    or redis.call('GET', KEYS[1]) ~= ARGV[3] then
    return 'INCONSISTENT'
  end
  if redis.call('EXISTS', ARGV[4] .. ARGV[1]) ~= 0
    or redis.call('EXISTS', KEYS[2]) ~= 0
    or redis.call('SISMEMBER', KEYS[3], ARGV[1]) ~= 0
    or redis.call('HEXISTS', KEYS[4], ARGV[1]) ~= 0 then
    return 'INCONSISTENT'
  end
  local pending = redis.call('LPOS', KEYS[5], ARGV[1]) ~= false
  local retry_score = redis.call('ZSCORE', KEYS[6], ARGV[1])
  if ARGV[7] == 'ACKNOWLEDGE' then
    if pending or retry_score ~= false
      or redis.call('EXISTS', KEYS[7]) ~= 0
      or (ARGV[11] ~= '' and redis.call('HGET', KEYS[8], ARGV[11]) ~= false) then
      return 'INCONSISTENT'
    end
  elseif ARGV[7] == 'RELEASE_REQUEUE' then
    if redis.call('TYPE', KEYS[7]).ok ~= 'string' then return 'INCONSISTENT' end
    local task_bytes = redis.call('STRLEN', KEYS[7])
    if not pending or retry_score ~= false or task_bytes < 1
      or task_bytes > tonumber(ARGV[10]) then
      return 'INCONSISTENT'
    end
  elseif ARGV[7] == 'RELEASE_DROP' then
    if pending or retry_score ~= false then return 'INCONSISTENT' end
  elseif ARGV[7] == 'RETRY' then
    if pending or retry_score == false
      or tonumber(retry_score) ~= tonumber(ARGV[8]) / 1000
      or redis.call('TYPE', KEYS[7]).ok ~= 'string'
      or redis.call('GET', KEYS[7]) ~= ARGV[9] then
      return 'INCONSISTENT'
    end
  else
    return 'INCONSISTENT'
  end
  return 'APPLIED'
end
if settlement_type ~= 'none' then return 'INCONSISTENT' end
redis.call('ZREM', KEYS[9], ARGV[2])

if attempt_type == 'none' then return 'NOT_FOUND' end
if attempt_type ~= 'string' or redis.call('GET', KEYS[2]) ~= ARGV[1] then
  return 'INCONSISTENT'
end
if redis.call('TYPE', lease_key).ok ~= 'string'
  or redis.call('GET', lease_key) ~= ARGV[2]
  or redis.call('SISMEMBER', KEYS[3], ARGV[1]) ~= 1 then
  return 'INCONSISTENT'
end
local lease_ttl = redis.call('PTTL', lease_key)
local attempt_ttl = redis.call('PTTL', KEYS[2])
if lease_ttl < 1 or attempt_ttl < 1
  or math.abs(attempt_ttl - lease_ttl) > tonumber(ARGV[6]) then
  return 'INCONSISTENT'
end
return 'ACTIVE'
"#;

const RECONCILE_CLAIM_SCRIPT: &str = r#"
local attempt_key = KEYS[1]
local attempt_type = redis.call('TYPE', attempt_key).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local result_type = redis.call('TYPE', KEYS[4]).ok
local result_index_type = redis.call('TYPE', KEYS[5]).ok
if (attempt_type ~= 'none' and attempt_type ~= 'string')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (result_type ~= 'none' and result_type ~= 'string')
  or (result_index_type ~= 'none' and result_index_type ~= 'zset') then
  return {'INCONSISTENT'}
end
if attempt_type == 'none' then
  if result_type == 'none' then
    redis.call('ZREM', KEYS[5], ARGV[1])
    return {'NOT_FOUND'}
  end
  local result_ttl = redis.call('TTL', KEYS[4])
  if result_ttl < 1 then return {'INCONSISTENT'} end
  local result = redis.call('GET', KEYS[4])
  if result == 'EMPTY' then return {'EMPTY'} end
  if redis.call('STRLEN', KEYS[4]) > tonumber(ARGV[4])
    or not string.match(result, '^[1-9][0-9]*$') then
    return {'INCONSISTENT'}
  end
  return {'NOT_FOUND'}
end
if attempt_type ~= 'string' then return {'INCONSISTENT'} end

local task_id_bytes = redis.call('STRLEN', attempt_key)
if task_id_bytes < 1 or task_id_bytes > tonumber(ARGV[4]) then
  return {'INCONSISTENT'}
end
local task_id = redis.call('GET', attempt_key)
if not string.match(task_id, '^[1-9][0-9]*$') then return {'INCONSISTENT'} end
if redis.call('TYPE', KEYS[4]).ok ~= 'string'
  or redis.call('GET', KEYS[4]) ~= task_id or redis.call('TTL', KEYS[4]) < 1 then
  return {'INCONSISTENT'}
end

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
if lease_ttl < 1 or attempt_ttl < 1
  or math.abs(attempt_ttl - lease_ttl) > tonumber(ARGV[8]) then
  return {'INCONSISTENT'}
end
return {'ACTIVE', task_id, processing_time, task_json, tostring(lease_ttl)}
"#;

const MOVE_DUE_RETRIES_SCRIPT: &str = r#"
local retry_type = redis.call('TYPE', KEYS[1]).ok
local pending_type = redis.call('TYPE', KEYS[2]).ok
local processing_type = redis.call('TYPE', KEYS[3]).ok
if (retry_type ~= 'none' and retry_type ~= 'zset')
  or (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set') then
  return redis.error_reply('WRONGTYPE')
end
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

const SCAN_STALE_EXPIRED_CLAIMS_SCRIPT: &str = r#"
local scan = redis.call('SSCAN', KEYS[1], ARGV[1], 'COUNT', ARGV[2])
local expired = {}
for _, task_id in ipairs(scan[2]) do
  if redis.call('EXISTS', ARGV[4] .. task_id) == 0 then
    local processing_time = redis.call('HGET', KEYS[2], task_id)
    if not processing_time
      or not string.match(processing_time, '^[1-9][0-9]*$')
      or tonumber(processing_time) <= tonumber(ARGV[3]) then
      table.insert(expired, task_id)
    end
  end
end
return {scan[1], expired}
"#;

const RECOVER_EXPIRED_CLAIM_SCRIPT: &str = r#"
local task_id = ARGV[1]
local lease_key = ARGV[3] .. task_id
local pending_type = redis.call('TYPE', KEYS[1]).ok
local processing_type = redis.call('TYPE', KEYS[2]).ok
local processing_time_type = redis.call('TYPE', KEYS[3]).ok
local retry_type = redis.call('TYPE', KEYS[4]).ok
local lease_type = redis.call('TYPE', lease_key).ok
if (pending_type ~= 'none' and pending_type ~= 'list')
  or (processing_type ~= 'none' and processing_type ~= 'set')
  or (processing_time_type ~= 'none' and processing_time_type ~= 'hash')
  or (retry_type ~= 'none' and retry_type ~= 'zset')
  or (lease_type ~= 'none' and lease_type ~= 'string') then
  return redis.error_reply('WRONGTYPE')
end
if lease_type == 'string' then return 0 end
if processing_type ~= 'set'
  or redis.call('SISMEMBER', KEYS[2], task_id) ~= 1 then return 0 end

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

const READ_PERSISTED_DOMAIN_STATUSES_SCRIPT: &str = r#"
local key_type = redis.call('TYPE', KEYS[1]).ok
if key_type == 'none' then return {'MISSING'} end
if key_type ~= 'hash' then return {'CORRUPT'} end
local count = redis.call('HLEN', KEYS[1])
local max_domains = tonumber(ARGV[1])
if count < 1 then return {'MISSING'} end
if count > max_domains then return {'CORRUPT'} end

local cursor = '0'
local total_bytes = 0
local result = {'OK'}
repeat
  local page = redis.call('HSCAN', KEYS[1], cursor, 'COUNT', max_domains)
  cursor = page[1]
  local entries = page[2]
  for index = 1, #entries, 2 do
    local field = entries[index]
    local json = entries[index + 1]
    total_bytes = total_bytes + string.len(field) + string.len(json)
    if string.len(field) == 0 or string.len(field) > tonumber(ARGV[2])
      or string.len(json) > tonumber(ARGV[3])
      or total_bytes > tonumber(ARGV[4]) then
      return {'CORRUPT'}
    end
    table.insert(result, field)
    table.insert(result, json)
  end
until cursor == '0'
if (#result - 1) / 2 ~= count then return {'CORRUPT'} end
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
    receipt_index_capacity: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidTask(&'static str),
    AttemptTokenInUse,
    StaleClaim,
    MissingDomainStatuses,
    CorruptDomainStatuses,
    Full,
    Unavailable,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    Exact,
    Missing,
    Conflict,
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
    Empty,
    Active(Box<ReconciledClaim>),
    Inconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueSettlement<'a> {
    Release {
        requeue: bool,
    },
    Retry {
        task: &'a TaskDetail,
        retry_at_epoch_millis: i64,
    },
    Acknowledge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementReconciliation {
    Applied,
    Active,
    NotFound,
    Inconsistent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredClaimPage {
    pub next_cursor: u64,
    pub task_ids: Vec<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingTtlRenewalPage {
    pub next_offset: usize,
    pub renewed_tasks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyListKind {
    Archive,
    StatusUpdates,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmptyReceiptPolicy {
    Create,
    Suppress,
}

impl EmptyReceiptPolicy {
    fn redis_argument(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Suppress => "SUPPRESS",
        }
    }
}

impl LegacyListKind {
    fn source_key(self) -> &'static str {
        match self {
            Self::Archive => ARCHIVE_KEY,
            Self::StatusUpdates => STATUS_UPDATES_KEY,
        }
    }

    fn namespace(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::StatusUpdates => "status-updates",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyListRecord {
    pub kind: LegacyListKind,
    pub token: String,
    pub payload: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyListQuarantine {
    pub bytes: usize,
    pub sha1: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyListClaim {
    Empty,
    Settled,
    Quarantined(LegacyListQuarantine),
    Record(LegacyListRecord),
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
            Self::Full => formatter.write_str("Redis outbound queue is full"),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomainStatus {
    pub domain: String,
    pub status: String,
    pub error: Option<String>,
    pub recipients: Vec<String>,
    pub updated_at: String,
}

impl Serialize for DomainStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DomainStatus", 6)?;
        state.serialize_field("domain", &self.domain)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("error", &self.error)?;
        state.serialize_field("recipients", &self.recipients)?;
        state.serialize_field("updatedAt", &self.updated_at)?;
        state.serialize_field(
            "permanentFailure",
            &self.error.as_deref().is_some_and(permanent_domain_error),
        )?;
        state.end()
    }
}

fn permanent_domain_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "does not support smtputf8",
        "requires smtputf8",
        "smtputf8 recipient",
        "was not sent with smtputf8",
        "session was not initialized",
        "user unknown",
        "mailbox not found",
        "recipient rejected",
        "no such user",
        "address rejected",
        "relay denied",
        "relay not permitted",
        "550 ",
        "551 ",
        "552 ",
        "553 ",
        "554 ",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

fn classify_publish_failure(code: Option<&str>, detail: Option<&str>) -> PublishFailure {
    match (code, detail) {
        (Some("TASK_ID_CONFLICT"), _) | (_, Some("TASK_ID_CONFLICT")) => {
            PublishFailure::TaskIdConflict
        }
        (Some("DOMAIN_STATUS_CONFLICT"), _) | (_, Some("DOMAIN_STATUS_CONFLICT")) => {
            PublishFailure::DomainStatusConflict
        }
        (Some("SENT_FILE_CONFLICT"), _) | (_, Some("SENT_FILE_CONFLICT")) => {
            PublishFailure::SentFileConflict
        }
        (Some("WRONGTYPE"), _) => PublishFailure::WrongType,
        _ => PublishFailure::Other,
    }
}

impl TaskDetail {
    pub(crate) fn validate(&self) -> Result<(), QueueError> {
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
        Self {
            pool,
            receipt_index_capacity: MAX_RECEIPT_INDEX_ENTRIES,
        }
    }

    #[doc(hidden)]
    pub fn with_receipt_index_capacity_for_tests(pool: Pool, capacity: usize) -> Self {
        assert!((1..=MAX_RECEIPT_INDEX_ENTRIES).contains(&capacity));
        Self {
            pool,
            receipt_index_capacity: capacity,
        }
    }

    pub async fn claim_legacy_list_record(
        &self,
        kind: LegacyListKind,
        token: &str,
        max_record_bytes: usize,
    ) -> Result<LegacyListClaim, QueueError> {
        self.claim_legacy_list_record_with_policy(
            kind,
            token,
            max_record_bytes,
            EmptyReceiptPolicy::Create,
        )
        .await
    }

    pub(crate) async fn claim_legacy_list_record_with_policy(
        &self,
        kind: LegacyListKind,
        token: &str,
        max_record_bytes: usize,
        empty_receipt_policy: EmptyReceiptPolicy,
    ) -> Result<LegacyListClaim, QueueError> {
        validate_migration_token(token)?;
        if max_record_bytes == 0 || max_record_bytes > MAX_LEGACY_LIST_RECORD_BYTES {
            return Err(QueueError::InvalidTask(
                "legacy list record bound is invalid",
            ));
        }
        let namespace = kind.namespace();
        let inflight_key = format!("lmyzmail:mail:queue:migration:{namespace}:inflight");
        let payloads_key = format!("lmyzmail:mail:queue:migration:{namespace}:payloads");
        let quarantine_key = format!("lmyzmail:mail:queue:migration:{namespace}:quarantine");
        let quarantine_metadata_key =
            format!("lmyzmail:mail:queue:migration:{namespace}:quarantine-metadata");
        let quarantine_bytes_key =
            format!("lmyzmail:mail:queue:migration:{namespace}:quarantine-bytes");
        let done_prefix = format!("lmyzmail:mail:queue:migration:{namespace}:done:");
        let done_index_key = format!("lmyzmail:mail:queue:migration:{namespace}:done-index");
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(CLAIM_LEGACY_LIST_RECORD_SCRIPT)
                    .arg(7)
                    .arg(kind.source_key())
                    .arg(inflight_key)
                    .arg(payloads_key)
                    .arg(quarantine_key)
                    .arg(quarantine_metadata_key)
                    .arg(quarantine_bytes_key)
                    .arg(done_index_key)
                    .arg(token)
                    .arg(max_record_bytes)
                    .arg(done_prefix)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(MAX_LEGACY_QUARANTINE_RECORDS)
                    .arg(MAX_LEGACY_QUARANTINE_BYTES)
                    .arg(self.receipt_index_capacity)
                    .arg(empty_receipt_policy.redis_argument()),
                &mut connection,
            )
            .await?;
        decode_legacy_list_claim(values, kind, max_record_bytes)
    }

    pub async fn acknowledge_legacy_list_record(
        &self,
        record: &LegacyListRecord,
    ) -> Result<bool, QueueError> {
        validate_migration_token(&record.token)?;
        let namespace = record.kind.namespace();
        let inflight_key = format!("lmyzmail:mail:queue:migration:{namespace}:inflight");
        let payloads_key = format!("lmyzmail:mail:queue:migration:{namespace}:payloads");
        let done_prefix = format!("lmyzmail:mail:queue:migration:{namespace}:done:");
        let done_index_key = format!("lmyzmail:mail:queue:migration:{namespace}:done-index");
        let mut connection = self.connection().await?;
        let acknowledged: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(ACK_LEGACY_LIST_RECORD_SCRIPT)
                    .arg(3)
                    .arg(inflight_key)
                    .arg(payloads_key)
                    .arg(done_index_key)
                    .arg(&record.token)
                    .arg(done_prefix)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match acknowledged {
            -2 => Err(QueueError::Unavailable),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn quarantine_legacy_list_record(
        &self,
        record: &LegacyListRecord,
        reason: &str,
    ) -> Result<bool, QueueError> {
        validate_migration_token(&record.token)?;
        if reason.is_empty()
            || reason.len() > MAX_MIGRATION_REASON_BYTES
            || !reason.is_ascii()
            || reason
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(QueueError::InvalidTask(
                "legacy list quarantine reason is invalid",
            ));
        }
        let namespace = record.kind.namespace();
        let inflight_key = format!("lmyzmail:mail:queue:migration:{namespace}:inflight");
        let payloads_key = format!("lmyzmail:mail:queue:migration:{namespace}:payloads");
        let quarantine_key = format!("lmyzmail:mail:queue:migration:{namespace}:quarantine");
        let quarantine_metadata_key =
            format!("lmyzmail:mail:queue:migration:{namespace}:quarantine-metadata");
        let quarantine_bytes_key =
            format!("lmyzmail:mail:queue:migration:{namespace}:quarantine-bytes");
        let done_prefix = format!("lmyzmail:mail:queue:migration:{namespace}:done:");
        let done_index_key = format!("lmyzmail:mail:queue:migration:{namespace}:done-index");
        let mut connection = self.connection().await?;
        let quarantined: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(QUARANTINE_LEGACY_LIST_RECORD_SCRIPT)
                    .arg(6)
                    .arg(inflight_key)
                    .arg(payloads_key)
                    .arg(quarantine_key)
                    .arg(quarantine_metadata_key)
                    .arg(quarantine_bytes_key)
                    .arg(done_index_key)
                    .arg(&record.token)
                    .arg(reason)
                    .arg(done_prefix)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(MAX_LEGACY_LIST_RECORD_BYTES)
                    .arg(MAX_LEGACY_QUARANTINE_RECORDS)
                    .arg(MAX_LEGACY_QUARANTINE_BYTES)
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match quarantined {
            -2 => Err(QueueError::Unavailable),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn cleanup_migrated_terminal_task(
        &self,
        task_id: i64,
        sent_file_name: Option<&str>,
    ) -> Result<(), QueueError> {
        if task_id <= 0
            || sent_file_name
                .is_some_and(|value| value.len() > 255 || value.chars().any(char::is_control))
        {
            return Err(QueueError::InvalidTask(
                "migrated terminal task identity is invalid",
            ));
        }
        let sent_file_name = sent_file_name.unwrap_or_default();
        let receipt_value = cleanup_receipt_value(sent_file_name);
        let mut connection = self.connection().await?;
        let cleaned: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(CLEANUP_MIGRATED_TERMINAL_TASK_SCRIPT)
                    .arg(7)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(format!("{KEY_PREFIX}task:{task_id}"))
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(CLEANUP_RECEIPT_INDEX_KEY)
                    .arg(task_id)
                    .arg(sent_file_name)
                    .arg(receipt_value)
                    .arg(LEASE_PREFIX)
                    .arg(CLEANUP_RECEIPT_PREFIX)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match cleaned {
            1 => Ok(()),
            -1 => Err(QueueError::InvalidTask(
                "migrated sent-file index conflicts with task ID",
            )),
            -2 => Err(QueueError::Unavailable),
            0 => Err(QueueError::StaleClaim),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn reserve_task_id(&self, postgres_id_floor: i64) -> Result<i64, QueueError> {
        let (first, last) = self.reserve_task_id_block(postgres_id_floor, 1).await?;
        if first != last {
            return Err(QueueError::Unavailable);
        }
        Ok(first)
    }

    pub async fn reserve_task_id_block(
        &self,
        postgres_id_floor: i64,
        count: usize,
    ) -> Result<(i64, i64), QueueError> {
        if postgres_id_floor < 0 {
            return Err(QueueError::InvalidTask("task ID floor cannot be negative"));
        }
        if count == 0 || count > MAX_ID_RESERVATION_BLOCK {
            return Err(QueueError::InvalidTask(
                "task ID reservation count is invalid",
            ));
        }
        let count = i64::try_from(count)
            .map_err(|_| QueueError::InvalidTask("task ID reservation count is invalid"))?;
        let maximum_start = i64::MAX
            .checked_sub(count)
            .ok_or(QueueError::InvalidTask("task ID space is exhausted"))?;
        if postgres_id_floor > maximum_start {
            return Err(QueueError::InvalidTask("task ID space is exhausted"));
        }
        let mut connection = self.connection().await?;
        let ids: Vec<String> = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RESERVE_ID_SCRIPT)
                    .arg(1)
                    .arg(SEQUENCE_KEY)
                    .arg(postgres_id_floor)
                    .arg(i64::MAX)
                    .arg(count)
                    .arg(maximum_start)
                    .arg(MAX_ID_RESERVATION_BLOCK),
                &mut connection,
            )
            .await?;
        if ids.len() != 2 {
            return Err(QueueError::Unavailable);
        }
        let first = ids[0].parse::<i64>().map_err(|_| QueueError::Unavailable)?;
        let last = ids[1].parse::<i64>().map_err(|_| QueueError::Unavailable)?;
        let expected_last = first
            .checked_add(count - 1)
            .ok_or(QueueError::Unavailable)?;
        if first <= postgres_id_floor || last != expected_last {
            return Err(QueueError::Unavailable);
        }
        Ok((first, last))
    }

    pub async fn active_reference_upper_bound(&self, limit: usize) -> Result<usize, QueueError> {
        if limit == 0 || limit > MAX_ACTIVE_TASK_REFERENCES {
            return Err(QueueError::InvalidTask("invalid active queue bound"));
        }
        let mut connection = self.connection().await?;
        let references: i64 = self
            .query(
                redis::cmd("EVAL")
                    .arg(ACTIVE_REFERENCE_UPPER_BOUND_SCRIPT)
                    .arg(3)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(RETRY_KEY)
                    .arg(limit),
                &mut connection,
            )
            .await?;
        usize::try_from(references)
            .ok()
            .filter(|references| *references <= limit)
            .ok_or(QueueError::Unavailable)
    }

    pub async fn active_task_ids(&self, limit: usize) -> Result<Vec<String>, QueueError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let observation = QueueObserverTimer::start(QueueObservedOperation::ActiveTaskIds);
        let mut connection = match self.connection().await {
            Ok(connection) => connection,
            Err(error) => {
                observation.finish(false);
                eprintln!(
                    "lmyzmail outbound active-task scan could not acquire a Redis connection"
                );
                return Err(error);
            }
        };
        let values: Vec<String> = match self
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
            .await
        {
            Ok(values) => values,
            Err(error) => {
                observation.finish(false);
                eprintln!("lmyzmail outbound active-task scan Redis command failed");
                return Err(error);
            }
        };
        observation.finish(true);
        if values.len() > limit {
            eprintln!("lmyzmail outbound active-task scan exceeded its result bound");
            return Err(QueueError::Unavailable);
        }
        Ok(values)
    }

    pub async fn publish(
        &self,
        task: &TaskDetail,
        domains: &BTreeMap<String, DomainStatus>,
    ) -> Result<bool, QueueError> {
        self.publish_bounded(task, domains, MAX_ACTIVE_TASK_REFERENCES)
            .await
    }

    pub async fn publish_bounded(
        &self,
        task: &TaskDetail,
        domains: &BTreeMap<String, DomainStatus>,
        max_active: usize,
    ) -> Result<bool, QueueError> {
        if max_active == 0 || max_active > MAX_ACTIVE_TASK_REFERENCES {
            return Err(QueueError::InvalidTask("invalid active queue bound"));
        }
        let expectation = publication_expectation(task, domains)?;
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
            .arg(&expectation.task_json)
            .arg(TASK_TTL_SECONDS)
            .arg(task.sent_file_name.as_deref().unwrap_or_default())
            .arg(expectation.domains.len())
            .arg(max_active);
        for (domain, status_json) in &expectation.domains {
            command.arg(domain).arg(status_json);
        }
        let observation = QueueObserverTimer::start(QueueObservedOperation::Publish);
        let mut connection = match self.connection().await {
            Ok(connection) => connection,
            Err(error) => {
                record_publish_failure(PublishFailure::Connection);
                observation.finish(false);
                return Err(error);
            }
        };
        let result: Result<i64, QueueError> =
            match timeout(COMMAND_TIMEOUT, command.query_async::<i64>(&mut connection)).await {
                Ok(Ok(created)) => Ok(created),
                Ok(Err(error)) => {
                    record_publish_failure(classify_publish_failure(error.code(), error.detail()));
                    Err(QueueError::OutcomeUnknown)
                }
                Err(_) => {
                    record_publish_failure(PublishFailure::Timeout);
                    Err(QueueError::OutcomeUnknown)
                }
            };
        observation.finish(result.is_ok());
        let created: i64 = result?;
        match created {
            -1 => Err(QueueError::Full),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
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

    pub async fn renew_pending_task_ttls(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<PendingTtlRenewalPage, QueueError> {
        if offset > MAX_ACTIVE_TASK_REFERENCES || limit == 0 || limit > MAX_ACTIVE_TASK_REFERENCES {
            return Err(QueueError::InvalidTask(
                "pending TTL renewal page is invalid",
            ));
        }
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RENEW_PENDING_TTLS_SCRIPT)
                    .arg(1)
                    .arg(PENDING_KEY)
                    .arg(offset)
                    .arg(limit)
                    .arg(TASK_TTL_SECONDS)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(format!("{KEY_PREFIX}domains:")),
                &mut connection,
            )
            .await?;
        match values.as_slice() {
            [status, next_offset, renewed_tasks] if status == "OK" => {
                let next_offset = next_offset
                    .parse::<usize>()
                    .map_err(|_| QueueError::OutcomeUnknown)?;
                let renewed_tasks = renewed_tasks
                    .parse::<usize>()
                    .map_err(|_| QueueError::OutcomeUnknown)?;
                if next_offset > MAX_ACTIVE_TASK_REFERENCES || renewed_tasks > limit {
                    return Err(QueueError::OutcomeUnknown);
                }
                Ok(PendingTtlRenewalPage {
                    next_offset,
                    renewed_tasks,
                })
            }
            [status, _] if status == "MISSING" => Err(QueueError::InvalidTask(
                "pending task detail is missing during TTL renewal",
            )),
            [status, _] if status == "INVALID" => Err(QueueError::InvalidTask(
                "pending task ID is invalid during TTL renewal",
            )),
            _ => Err(QueueError::OutcomeUnknown),
        }
    }

    pub async fn publication_state(
        &self,
        task: &TaskDetail,
        domains: &BTreeMap<String, DomainStatus>,
    ) -> Result<PublicationState, QueueError> {
        let expectation = publication_expectation(task, domains)?;
        let id = task.id.to_string();
        let sent_file_name = task
            .sent_file_name
            .as_deref()
            .ok_or(QueueError::InvalidTask(
                "task storage reference is incomplete",
            ))?;
        let mut command = redis::cmd("EVAL");
        command
            .arg(COMPLETE_TASK_SCRIPT)
            .arg(6)
            .arg(format!("{KEY_PREFIX}task:{id}"))
            .arg(format!("{KEY_PREFIX}domains:{id}"))
            .arg(SENT_FILE_INDEX_KEY)
            .arg(PENDING_KEY)
            .arg(PROCESSING_KEY)
            .arg(RETRY_KEY)
            .arg(&id)
            .arg(&expectation.task_json)
            .arg(sent_file_name)
            .arg(TASK_TTL_SECONDS)
            .arg(expectation.domains.len());
        for (domain, status_json) in &expectation.domains {
            command.arg(domain).arg(status_json);
        }
        let mut connection = self.connection().await?;
        let state: String = self.mutation_query(&mut command, &mut connection).await?;
        match state.as_str() {
            "EXACT" => Ok(PublicationState::Exact),
            "MISSING" => Ok(PublicationState::Missing),
            "CONFLICT" => Ok(PublicationState::Conflict),
            _ => Err(QueueError::OutcomeUnknown),
        }
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
                    .arg(4)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(CLAIM_RESULT_INDEX_KEY)
                    .arg(lease_token)
                    .arg(lease_duration.as_millis())
                    .arg(now_epoch_millis)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(format!("{KEY_PREFIX}domains:"))
                    .arg(TASK_TTL_SECONDS)
                    .arg(ATTEMPT_PREFIX)
                    .arg(SETTLEMENT_PREFIX)
                    .arg(CLAIM_RESULT_PREFIX)
                    .arg(self.receipt_index_capacity)
                    .arg(MAX_TASK_ID_BYTES)
                    .arg(MAX_TASK_JSON_BYTES)
                    .arg(i64::MAX),
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
        if values[2] == "4" {
            return Err(QueueError::Unavailable);
        }
        if values[2] == "3" && values[0].is_empty() && values[1].is_empty() {
            return Ok(None);
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
                    .arg(5)
                    .arg(format!("{ATTEMPT_PREFIX}{attempt_token}"))
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(format!("{CLAIM_RESULT_PREFIX}{attempt_token}"))
                    .arg(CLAIM_RESULT_INDEX_KEY)
                    .arg(attempt_token)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(MAX_TASK_ID_BYTES)
                    .arg(MAX_LEASE_TOKEN_BYTES)
                    .arg(MAX_PROCESSING_TIME_BYTES)
                    .arg(MAX_TASK_JSON_BYTES)
                    .arg(MAX_LEASE_TTL_SKEW_MILLIS),
                &mut connection,
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("NOT_FOUND") if values.len() == 1 => Ok(ClaimReconciliation::NotFound),
            Some("EMPTY") if values.len() == 1 => Ok(ClaimReconciliation::Empty),
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

    pub async fn read_persisted_domain_statuses(
        &self,
        task_id: i64,
    ) -> Result<BTreeMap<String, DomainStatus>, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .query(
                redis::cmd("EVAL")
                    .arg(READ_PERSISTED_DOMAIN_STATUSES_SCRIPT)
                    .arg(1)
                    .arg(format!("{KEY_PREFIX}domains:{task_id}"))
                    .arg(MAX_DOMAIN_STATUSES)
                    .arg(MAX_DOMAIN_BYTES)
                    .arg(MAX_DOMAIN_STATUS_JSON_BYTES)
                    .arg(MAX_DOMAIN_STATUS_ARCHIVE_BYTES),
                &mut connection,
            )
            .await?;
        decode_persisted_domain_statuses(values)
    }

    pub async fn read_persisted_task(
        &self,
        task_id: i64,
    ) -> Result<Option<TaskDetail>, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let mut connection = self.connection().await?;
        let task_json: Option<Vec<u8>> = self
            .query(
                redis::cmd("GET").arg(format!("{KEY_PREFIX}task:{task_id}")),
                &mut connection,
            )
            .await?;
        let Some(task_json) = task_json else {
            return Ok(None);
        };
        if task_json.len() > MAX_TASK_JSON_BYTES {
            return Ok(None);
        }
        let Ok(task) = serde_json::from_slice::<TaskDetail>(&task_json) else {
            return Ok(None);
        };
        if !valid_persisted_status_task(&task, task_id) {
            return Ok(None);
        }
        Ok(Some(task))
    }

    /// Recovery proof must distinguish a missing key from a present but
    /// malformed payload. Treat every present invalid value as corruption so
    /// callers cannot prove absence by failing to decode durable state.
    pub(crate) async fn read_persisted_task_strict(
        &self,
        task_id: i64,
    ) -> Result<Option<TaskDetail>, QueueError> {
        if task_id <= 0 {
            return Err(QueueError::InvalidTask("task ID must be positive"));
        }
        let mut connection = self.connection().await?;
        let task_json: Option<Vec<u8>> = self
            .query(
                redis::cmd("GET").arg(format!("{KEY_PREFIX}task:{task_id}")),
                &mut connection,
            )
            .await?;
        let Some(task_json) = task_json else {
            return Ok(None);
        };
        if task_json.len() > MAX_TASK_JSON_BYTES {
            return Err(QueueError::InvalidTask(
                "persisted task payload exceeds its limit",
            ));
        }
        let task = serde_json::from_slice::<TaskDetail>(&task_json)
            .map_err(|_| QueueError::InvalidTask("persisted task payload is malformed"))?;
        if !valid_persisted_status_task(&task, task_id) {
            return Err(QueueError::InvalidTask(
                "persisted task payload is inconsistent",
            ));
        }
        Ok(Some(task))
    }

    pub async fn read_task_id_by_sent_file_name(
        &self,
        sent_file_name: &str,
    ) -> Result<Option<i64>, QueueError> {
        if sent_file_name.is_empty()
            || sent_file_name.len() > 255
            || sent_file_name.chars().any(char::is_control)
        {
            return Err(QueueError::InvalidTask("sent-file identity is invalid"));
        }
        let mut connection = self.connection().await?;
        let task_id: Option<String> = self
            .query(
                redis::cmd("HGET")
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(sent_file_name),
                &mut connection,
            )
            .await?;
        Ok(task_id.and_then(|value| parse_task_id(&value).ok()))
    }

    pub async fn replace_claimed_task_source(
        &self,
        claim: &QueueClaim,
        replacement: &TaskDetail,
    ) -> Result<(), QueueError> {
        validate_claim_identity(claim)?;
        replacement.validate()?;
        let Some(current) = claim.task.as_ref() else {
            return Err(QueueError::InvalidTask("claimed task detail is missing"));
        };
        let mut expected = current.clone();
        expected.message_file_path = replacement.message_file_path.clone();
        expected.signed_content_base64 = replacement.signed_content_base64.clone();
        if replacement.id != claim.task_id || *replacement != expected {
            return Err(QueueError::InvalidTask(
                "claimed task source replacement changed immutable metadata",
            ));
        }
        let task_json = serde_json::to_string(replacement)
            .map_err(|_| QueueError::InvalidTask("claimed task detail is invalid"))?;
        if task_json.len() > MAX_TASK_JSON_BYTES {
            return Err(QueueError::InvalidTask(
                "claimed task detail exceeds its byte budget",
            ));
        }
        let mut connection = self.connection().await?;
        let result: String = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(REPLACE_CLAIMED_TASK_SCRIPT)
                    .arg(1)
                    .arg(PROCESSING_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(task_json)
                    .arg(LEASE_PREFIX)
                    .arg(ATTEMPT_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(TASK_TTL_SECONDS),
                &mut connection,
            )
            .await?;
        match result.as_str() {
            "OK" => Ok(()),
            "STALE" => Err(QueueError::StaleClaim),
            "MISSING" => Err(QueueError::InvalidTask("claimed task detail is missing")),
            _ => Err(QueueError::OutcomeUnknown),
        }
    }

    pub async fn read_claimed_task(&self, claim: &QueueClaim) -> Result<TaskDetail, QueueError> {
        validate_claim_identity(claim)?;
        let mut connection = self.connection().await?;
        let values: Vec<String> = self
            .query(
                redis::cmd("EVAL")
                    .arg(READ_CLAIMED_TASK_SCRIPT)
                    .arg(1)
                    .arg(PROCESSING_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(LEASE_PREFIX)
                    .arg(ATTEMPT_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:")),
                &mut connection,
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("STALE") if values.len() == 1 => Err(QueueError::StaleClaim),
            Some("MISSING") if values.len() == 1 => {
                Err(QueueError::InvalidTask("claimed task detail is missing"))
            }
            Some("OK") if values.len() == 2 && values[1].len() <= MAX_TASK_JSON_BYTES => {
                let task: TaskDetail = serde_json::from_str(&values[1])
                    .map_err(|_| QueueError::InvalidTask("claimed task detail is invalid"))?;
                if task.id != claim.task_id || task.validate().is_err() {
                    return Err(QueueError::InvalidTask("claimed task detail is invalid"));
                }
                Ok(task)
            }
            _ => Err(QueueError::Unavailable),
        }
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
        let settlement = settlement_expectation(claim, QueueSettlement::Release { requeue })?;
        let mut connection = self.connection().await?;
        let released: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(RELEASE_CLAIM_SCRIPT)
                    .arg(6)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(SETTLEMENT_INDEX_KEY)
                    .arg(CLAIM_RESULT_INDEX_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(i64::from(requeue))
                    .arg(LEASE_PREFIX)
                    .arg(ATTEMPT_PREFIX)
                    .arg(SETTLEMENT_PREFIX)
                    .arg(settlement.receipt)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(MAX_TASK_JSON_BYTES)
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match released {
            -2 => Err(QueueError::Unavailable),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
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
        let settlement = settlement_expectation(
            claim,
            QueueSettlement::Retry {
                task,
                retry_at_epoch_millis,
            },
        )?;
        let mut connection = self.connection().await?;
        let scheduled: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(SCHEDULE_RETRY_SCRIPT)
                    .arg(6)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(SETTLEMENT_INDEX_KEY)
                    .arg(CLAIM_RESULT_INDEX_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(&settlement.task_json)
                    .arg(retry_at_epoch_millis)
                    .arg(TASK_TTL_SECONDS)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(ATTEMPT_PREFIX)
                    .arg(SETTLEMENT_PREFIX)
                    .arg(settlement.receipt)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match scheduled {
            -2 => Err(QueueError::Unavailable),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn acknowledge(&self, claim: &QueueClaim) -> Result<bool, QueueError> {
        validate_claim_identity(claim)?;
        let settlement = settlement_value(claim, QueueSettlement::Acknowledge)?;
        let mut connection = self.connection().await?;
        let acknowledged: i64 = self
            .mutation_query(
                redis::cmd("EVAL")
                    .arg(ACKNOWLEDGE_SCRIPT)
                    .arg(7)
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(SETTLEMENT_INDEX_KEY)
                    .arg(CLAIM_RESULT_INDEX_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(LEASE_PREFIX)
                    .arg(format!("{KEY_PREFIX}task:"))
                    .arg(ATTEMPT_PREFIX)
                    .arg(SETTLEMENT_PREFIX)
                    .arg(settlement)
                    .arg(RECEIPT_TTL_SECONDS)
                    .arg(
                        claim
                            .task
                            .as_ref()
                            .and_then(|task| task.sent_file_name.as_deref())
                            .unwrap_or_default(),
                    )
                    .arg(self.receipt_index_capacity),
                &mut connection,
            )
            .await?;
        match acknowledged {
            -2 => Err(QueueError::Unavailable),
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn terminal_acknowledgement_proven(
        &self,
        task_id: i64,
        sent_file_name: &str,
    ) -> Result<bool, QueueError> {
        if task_id <= 0
            || sent_file_name.is_empty()
            || sent_file_name.len() > 255
            || sent_file_name.chars().any(char::is_control)
        {
            return Err(QueueError::InvalidTask(
                "terminal acknowledgement identity is invalid",
            ));
        }
        let mut connection = self.connection().await?;
        let result: String = self
            .query(
                redis::cmd("EVAL")
                    .arg(VERIFY_TERMINAL_ACKNOWLEDGEMENT_SCRIPT)
                    .arg(7)
                    .arg(format!("{KEY_PREFIX}task:{task_id}"))
                    .arg(PENDING_KEY)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(RETRY_KEY)
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(format!("{LEASE_PREFIX}{task_id}"))
                    .arg(task_id)
                    .arg(sent_file_name),
                &mut connection,
            )
            .await?;
        match result.as_str() {
            "ACKNOWLEDGED" => Ok(true),
            "ACTIVE" => Ok(false),
            "CONFLICT" => Err(QueueError::InvalidTask(
                "terminal sent-file index conflicts with task ID",
            )),
            _ => Err(QueueError::Unavailable),
        }
    }

    pub async fn reconcile_settlement(
        &self,
        claim: &QueueClaim,
        settlement: QueueSettlement<'_>,
    ) -> Result<SettlementReconciliation, QueueError> {
        validate_claim_identity(claim)?;
        let expected = settlement_expectation(claim, settlement)?;
        let mut connection = self.connection().await?;
        let result: String = self
            .query(
                redis::cmd("EVAL")
                    .arg(RECONCILE_SETTLEMENT_SCRIPT)
                    .arg(9)
                    .arg(format!("{SETTLEMENT_PREFIX}{}", claim.lease_token))
                    .arg(format!("{ATTEMPT_PREFIX}{}", claim.lease_token))
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(PENDING_KEY)
                    .arg(RETRY_KEY)
                    .arg(format!("{KEY_PREFIX}task:{}", claim.task_id))
                    .arg(SENT_FILE_INDEX_KEY)
                    .arg(SETTLEMENT_INDEX_KEY)
                    .arg(claim.task_id)
                    .arg(&claim.lease_token)
                    .arg(expected.receipt)
                    .arg(LEASE_PREFIX)
                    .arg(MAX_SETTLEMENT_VALUE_BYTES)
                    .arg(MAX_LEASE_TTL_SKEW_MILLIS)
                    .arg(expected.action)
                    .arg(expected.retry_at_epoch_millis)
                    .arg(expected.task_json)
                    .arg(MAX_TASK_JSON_BYTES)
                    .arg(
                        claim
                            .task
                            .as_ref()
                            .and_then(|task| task.sent_file_name.as_deref())
                            .unwrap_or_default(),
                    ),
                &mut connection,
            )
            .await?;
        match result.as_str() {
            "APPLIED" => Ok(SettlementReconciliation::Applied),
            "ACTIVE" => Ok(SettlementReconciliation::Active),
            "NOT_FOUND" => Ok(SettlementReconciliation::NotFound),
            "INCONSISTENT" => Ok(SettlementReconciliation::Inconsistent),
            _ => Err(QueueError::Unavailable),
        }
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

    pub async fn scan_stale_expired_claims(
        &self,
        cursor: u64,
        count: usize,
        stale_before_epoch_millis: i64,
    ) -> Result<ExpiredClaimPage, QueueError> {
        if count == 0 || count > 10_000 || stale_before_epoch_millis <= 0 {
            return Err(QueueError::InvalidTask("invalid stale claim scan bound"));
        }
        let mut connection = self.connection().await?;
        let (next_cursor, values): (u64, Vec<String>) = self
            .query(
                redis::cmd("EVAL")
                    .arg(SCAN_STALE_EXPIRED_CLAIMS_SCRIPT)
                    .arg(2)
                    .arg(PROCESSING_KEY)
                    .arg(PROCESSING_TIME_KEY)
                    .arg(cursor)
                    .arg(count)
                    .arg(stale_before_epoch_millis)
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

fn decode_legacy_list_claim(
    values: Vec<String>,
    kind: LegacyListKind,
    max_record_bytes: usize,
) -> Result<LegacyListClaim, QueueError> {
    match values.first().map(String::as_str) {
        Some("EMPTY") if values.len() == 1 => Ok(LegacyListClaim::Empty),
        Some("SETTLED") if values.len() == 1 => Ok(LegacyListClaim::Settled),
        Some("QUARANTINED") if values.len() == 3 => {
            let bytes = values[1].parse().map_err(|_| QueueError::Unavailable)?;
            if bytes <= max_record_bytes || !valid_sha1(&values[2]) {
                return Err(QueueError::Unavailable);
            }
            Ok(LegacyListClaim::Quarantined(LegacyListQuarantine {
                bytes,
                sha1: values[2].clone(),
            }))
        }
        Some("QUARANTINE_FULL" | "RECEIPT_FULL") => Err(QueueError::Unavailable),
        Some("RECORD") if values.len() == 3 => {
            validate_migration_token(&values[1])?;
            if values[2].len() > max_record_bytes {
                return Err(QueueError::Unavailable);
            }
            Ok(LegacyListClaim::Record(LegacyListRecord {
                kind,
                token: values[1].clone(),
                payload: values[2].clone(),
            }))
        }
        _ => Err(QueueError::Unavailable),
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

fn validate_migration_token(token: &str) -> Result<(), QueueError> {
    if token.is_empty()
        || token.len() > MAX_MIGRATION_TOKEN_BYTES
        || !token.is_ascii()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(QueueError::InvalidTask(
            "legacy list migration token is invalid",
        ));
    }
    Ok(())
}

fn valid_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn cleanup_receipt_value(sent_file_name: &str) -> String {
    let digest = Sha256::digest(sent_file_name.as_bytes());
    let mut value = String::with_capacity(CLEANUP_RECEIPT_TAG.len() + digest.len() * 2);
    value.push_str(CLEANUP_RECEIPT_TAG);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
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

struct SettlementExpectation {
    receipt: String,
    action: &'static str,
    retry_at_epoch_millis: i64,
    task_json: String,
}

struct PublicationExpectation {
    task_json: String,
    domains: Vec<(String, String)>,
}

fn publication_expectation(
    task: &TaskDetail,
    domains: &BTreeMap<String, DomainStatus>,
) -> Result<PublicationExpectation, QueueError> {
    task.validate()?;
    if domains.is_empty() || domains.len() > MAX_DOMAIN_STATUSES {
        return Err(QueueError::InvalidTask(
            "task domain statuses are incomplete",
        ));
    }
    let task_json = serde_json::to_string(task).map_err(|_| QueueError::Unavailable)?;
    if task_json.len() > MAX_TASK_JSON_BYTES {
        return Err(QueueError::InvalidTask("task JSON exceeds its bound"));
    }
    let mut serialized = Vec::with_capacity(domains.len());
    let mut total_bytes = 0_usize;
    let mut total_recipients = 0_usize;
    for (domain, status) in domains {
        if !valid_domain_status(domain, status) {
            return Err(QueueError::InvalidTask("invalid task domain status"));
        }
        let json = serde_json::to_string(status).map_err(|_| QueueError::Unavailable)?;
        total_bytes = total_bytes
            .checked_add(domain.len())
            .and_then(|value| value.checked_add(json.len()))
            .ok_or(QueueError::InvalidTask(
                "task domain statuses exceed their bound",
            ))?;
        total_recipients = total_recipients
            .checked_add(status.recipients.len())
            .ok_or(QueueError::InvalidTask(
                "task recipients exceed their bound",
            ))?;
        if json.len() > MAX_DOMAIN_STATUS_JSON_BYTES
            || total_bytes > MAX_DOMAIN_STATUS_ARCHIVE_BYTES
            || total_recipients > MAX_DOMAIN_RECIPIENTS
        {
            return Err(QueueError::InvalidTask(
                "task domain statuses exceed their bound",
            ));
        }
        serialized.push((domain.clone(), json));
    }
    Ok(PublicationExpectation {
        task_json,
        domains: serialized,
    })
}

fn settlement_value(
    claim: &QueueClaim,
    settlement: QueueSettlement<'_>,
) -> Result<String, QueueError> {
    Ok(settlement_expectation(claim, settlement)?.receipt)
}

fn settlement_expectation(
    claim: &QueueClaim,
    settlement: QueueSettlement<'_>,
) -> Result<SettlementExpectation, QueueError> {
    let (receipt, action, retry_at_epoch_millis, task_json) = match settlement {
        QueueSettlement::Release { requeue } => (
            format!("release:{}:{}", claim.task_id, i64::from(requeue)),
            if requeue {
                "RELEASE_REQUEUE"
            } else {
                "RELEASE_DROP"
            },
            0,
            String::new(),
        ),
        QueueSettlement::Retry {
            task,
            retry_at_epoch_millis,
        } if retry_at_epoch_millis > 0 => {
            task.validate()?;
            if task.id != claim.task_id {
                return Err(QueueError::InvalidTask("retry task does not match claim"));
            }
            (
                format!("retry:{}:{retry_at_epoch_millis}", claim.task_id),
                "RETRY",
                retry_at_epoch_millis,
                serde_json::to_string(task).map_err(|_| QueueError::Unavailable)?,
            )
        }
        QueueSettlement::Retry { .. } => {
            return Err(QueueError::InvalidTask("retry deadline must be positive"));
        }
        QueueSettlement::Acknowledge => (
            format!("acknowledge:{}", claim.task_id),
            "ACKNOWLEDGE",
            0,
            String::new(),
        ),
    };
    if receipt.len() > MAX_SETTLEMENT_VALUE_BYTES {
        return Err(QueueError::InvalidTask(
            "settlement receipt exceeds its bound",
        ));
    }
    Ok(SettlementExpectation {
        receipt,
        action,
        retry_at_epoch_millis,
        task_json,
    })
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

fn decode_persisted_domain_statuses(
    values: Vec<String>,
) -> Result<BTreeMap<String, DomainStatus>, QueueError> {
    match values.first().map(String::as_str) {
        Some("MISSING") => return Ok(BTreeMap::new()),
        Some("OK") => {}
        Some("CORRUPT") => return Err(QueueError::CorruptDomainStatuses),
        _ => return Err(QueueError::Unavailable),
    }
    if values.len() == 1 || !(values.len() - 1).is_multiple_of(2) {
        return Err(QueueError::CorruptDomainStatuses);
    }
    let mut statuses = BTreeMap::new();
    for pair in values[1..].chunks_exact(2) {
        let domain = &pair[0];
        let Ok(status) = serde_json::from_str::<DomainStatus>(&pair[1]) else {
            continue;
        };
        if valid_domain_status(domain, &status) {
            statuses.insert(domain.clone(), status);
        }
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

fn valid_persisted_status_task(task: &TaskDetail, expected_id: i64) -> bool {
    task.id == expected_id
        && !task.sender_address.is_empty()
        && task.sender_address.len() <= MAX_ADDRESS_BYTES
        && !task.sender_address.chars().any(char::is_control)
        && task.recipients_json.len() <= MAX_TASK_JSON_BYTES
        && task.subject.len() <= 1_000
        && !task.subject.chars().any(char::is_control)
        && !task.message_id.is_empty()
        && task.message_id.len() <= 255
        && !task.message_id.chars().any(char::is_control)
        && task.retry_count >= 0
        && task.max_retries >= 0
        && task.retry_count <= task.max_retries
        && task.sent_file_name.as_deref().is_none_or(|value| {
            !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
        })
        && task.sent_subdirectory.is_none_or(|value| value > 0)
        && task.message_file_path.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 4_096
                && !value.contains('\0')
                && std::path::Path::new(value).is_absolute()
        })
        && task
            .signed_content_base64
            .as_deref()
            .is_none_or(|value| value.len() <= MAX_TASK_JSON_BYTES)
        && !task.created_at.is_empty()
        && task.created_at.len() <= 128
        && chrono::DateTime::parse_from_rfc3339(&task.created_at).is_ok()
        && task.next_retry_at.as_deref().is_none_or(|value| {
            value.len() <= 128 && chrono::DateTime::parse_from_rfc3339(value).is_ok()
        })
        && task
            .last_error
            .as_deref()
            .is_none_or(|value| value.len() <= 4_096 && !value.contains('\0'))
        && matches!(
            task.status.as_str(),
            "PENDING" | "PROCESSING" | "SENT" | "PARTIAL_SUCCESS" | "FAILED" | "CANCELLED"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_capacity_preserves_the_bounded_throughput_window() {
        assert_eq!(MAX_RECEIPT_INDEX_ENTRIES, MAX_ACTIVE_TASK_REFERENCES);
        assert!(
            MAX_RECEIPT_INDEX_ENTRIES / RECEIPT_TTL_SECONDS as usize >= 3_000,
            "the receipt window must not impose a sub-3000 message/s queue ceiling"
        );
    }

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

    #[test]
    fn publish_failure_codes_are_classified_without_payloads() {
        assert!(matches!(
            classify_publish_failure(Some("TASK_ID_CONFLICT"), None),
            PublishFailure::TaskIdConflict
        ));
        assert!(matches!(
            classify_publish_failure(Some("ERR"), Some("DOMAIN_STATUS_CONFLICT")),
            PublishFailure::DomainStatusConflict
        ));
        assert!(matches!(
            classify_publish_failure(Some("ERR"), Some("SENT_FILE_CONFLICT")),
            PublishFailure::SentFileConflict
        ));
        assert!(matches!(
            classify_publish_failure(Some("WRONGTYPE"), Some("wrong kind of value")),
            PublishFailure::WrongType
        ));
        assert!(matches!(
            classify_publish_failure(None, None),
            PublishFailure::Other
        ));
    }

    #[test]
    fn legacy_empty_claim_decoder_accepts_only_the_exact_marker() {
        assert_eq!(
            decode_legacy_list_claim(
                vec!["EMPTY".into()],
                LegacyListKind::Archive,
                MAX_LEGACY_LIST_RECORD_BYTES,
            )
            .unwrap(),
            LegacyListClaim::Empty
        );
        assert_eq!(
            decode_legacy_list_claim(
                vec!["EMPTY".into(), "unexpected".into()],
                LegacyListKind::Archive,
                MAX_LEGACY_LIST_RECORD_BYTES,
            )
            .unwrap_err(),
            QueueError::Unavailable
        );
    }

    #[test]
    fn domain_status_json_matches_java_permanent_failure_contract() {
        let mut status = DomainStatus {
            domain: "example.test".into(),
            status: "PENDING".into(),
            error: None,
            recipients: vec!["qa@example.test".into()],
            updated_at: "2026-08-09T00:00:00Z".into(),
        };

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["permanentFailure"], false);
        assert_eq!(json.as_object().unwrap().len(), 6);

        status.error = Some("550 5.1.1 User unknown".into());
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["permanentFailure"], true);
    }

    #[test]
    fn domain_status_deserializes_with_or_without_java_computed_field() {
        let expected = DomainStatus {
            domain: "example.test".into(),
            status: "PENDING".into(),
            error: None,
            recipients: vec!["qa@example.test".into()],
            updated_at: "2026-08-09T00:00:00Z".into(),
        };
        let without = r#"{"domain":"example.test","status":"PENDING","error":null,"recipients":["qa@example.test"],"updatedAt":"2026-08-09T00:00:00Z"}"#;
        let with = r#"{"domain":"example.test","status":"PENDING","error":null,"recipients":["qa@example.test"],"updatedAt":"2026-08-09T00:00:00Z","permanentFailure":false}"#;

        assert_eq!(
            serde_json::from_str::<DomainStatus>(without).unwrap(),
            expected
        );
        assert_eq!(
            serde_json::from_str::<DomainStatus>(with).unwrap(),
            expected
        );
    }

    #[test]
    fn persisted_domain_statuses_skip_only_malformed_entries() {
        let valid = DomainStatus {
            domain: "valid.test".into(),
            status: "SENT".into(),
            error: None,
            recipients: vec!["user@valid.test".into()],
            updated_at: "2026-08-07T00:00:00Z".into(),
        };
        let values = vec![
            "OK".into(),
            "broken.test".into(),
            "{".into(),
            "valid.test".into(),
            serde_json::to_string(&valid).unwrap(),
        ];
        assert_eq!(
            decode_persisted_domain_statuses(values).unwrap(),
            BTreeMap::from([("valid.test".into(), valid)])
        );
    }

    #[test]
    fn persisted_status_task_accepts_terminal_java_cache_shape() {
        let mut task = complete_task();
        task.status = "CANCELLED".into();
        task.sent_file_name = None;
        task.sent_subdirectory = None;
        task.next_retry_at = Some("2100-01-01T00:00:00Z".into());
        assert!(valid_persisted_status_task(&task, 42));
        assert!(!valid_persisted_status_task(&task, 43));
    }
}
