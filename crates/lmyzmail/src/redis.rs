use std::{io, time::Duration};

use deadpool_redis::{
    Config as RedisPoolConfig, ConnectionAddr, ConnectionInfo, CreatePoolError, Pool, PoolConfig,
    ProtocolVersion, RedisConnectionInfo, Runtime,
};
use tokio::time::timeout;

use crate::config::RuntimeConfig;

const POOL_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_CREATE_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECTION_RECYCLE_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

pub fn create_pool(config: &RuntimeConfig) -> Result<Pool, CreatePoolError> {
    let address = if config.redis.tls {
        ConnectionAddr::TcpTls {
            host: config.redis.host.clone(),
            port: config.redis.port,
            insecure: false,
        }
    } else {
        ConnectionAddr::Tcp(config.redis.host.clone(), config.redis.port)
    };
    let connection = ConnectionInfo {
        addr: address,
        redis: RedisConnectionInfo {
            db: i64::from(config.redis.database),
            username: config.redis.username.clone(),
            password: config.redis.password.clone(),
            protocol: ProtocolVersion::RESP2,
        },
    };
    let mut pool = PoolConfig::new(config.limits.redis_pool as usize);
    pool.timeouts.wait = Some(POOL_WAIT_TIMEOUT);
    pool.timeouts.create = Some(CONNECTION_CREATE_TIMEOUT);
    pool.timeouts.recycle = Some(CONNECTION_RECYCLE_TIMEOUT);
    let mut pool_config = RedisPoolConfig::from_connection_info(connection);
    pool_config.pool = Some(pool);
    pool_config.create_pool(Some(Runtime::Tokio1))
}

pub async fn increment(pool: &Pool, key: &str) -> io::Result<i64> {
    let mut connection = timeout(POOL_WAIT_TIMEOUT, pool.get())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Redis pool wait timeout"))?
        .map_err(|_| io::Error::other("Redis connection unavailable"))?;
    timeout(
        COMMAND_TIMEOUT,
        deadpool_redis::redis::cmd("INCR")
            .arg(key)
            .query_async(&mut connection),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Redis command timeout"))?
    .map_err(|_| io::Error::other("Redis command failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Properties;

    #[test]
    fn configured_limit_is_the_pool_limit() {
        let mut properties = Properties::default();
        properties
            .insert("lmyzmail.redis.pool.max-active".into(), "7".into())
            .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        let pool = create_pool(&config).unwrap();
        assert_eq!(pool.status().max_size, 7);
    }
}
