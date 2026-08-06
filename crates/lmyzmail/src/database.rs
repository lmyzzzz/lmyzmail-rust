use std::time::Duration;

use deadpool_postgres::{
    Config as DatabasePoolConfig, CreatePoolError, ManagerConfig, Pool, PoolConfig,
    RecyclingMethod, Runtime,
};
use tokio_postgres::NoTls;

use crate::config::RuntimeConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

pub fn create_pool(config: &RuntimeConfig) -> Result<Pool, CreatePoolError> {
    let mut pool_config = DatabasePoolConfig::new();
    pool_config.host = Some(config.postgres.host.clone());
    pool_config.port = Some(config.postgres.port);
    pool_config.dbname = Some(config.postgres.database.clone());
    pool_config.user = Some(config.postgres.username.clone());
    pool_config.password = Some(config.postgres.password.clone());
    pool_config.connect_timeout = Some(CONNECT_TIMEOUT);
    pool_config.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    pool_config.pool = Some(PoolConfig::new(config.limits.postgres_pool as usize));
    pool_config.create_pool(Some(Runtime::Tokio1), NoTls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Properties;

    #[test]
    fn configured_limit_is_the_pool_limit() {
        let mut properties = Properties::default();
        properties
            .insert("lmyzmail.postgres.pool.max-size".into(), "7".into())
            .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        let pool = create_pool(&config).unwrap();
        assert_eq!(pool.status().max_size, 7);
    }
}
