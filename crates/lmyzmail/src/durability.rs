use std::{fmt, fs::File, io, os::fd::AsFd, sync::OnceLock};

static FILESYSTEM_FSYNC_ENABLED: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemDurability {
    fsync_enabled: bool,
}

impl FilesystemDurability {
    pub const fn new(fsync_enabled: bool) -> Self {
        Self { fsync_enabled }
    }

    pub const fn fsync_enabled(self) -> bool {
        self.fsync_enabled
    }

    pub fn sync_all(self, file: &File) -> io::Result<()> {
        if self.fsync_enabled {
            file.sync_all()
        } else {
            Ok(())
        }
    }

    pub async fn sync_data(self, file: &tokio::fs::File) -> io::Result<()> {
        if self.fsync_enabled {
            file.sync_data().await
        } else {
            Ok(())
        }
    }

    pub fn fsync<Fd: AsFd>(self, descriptor: Fd) -> rustix::io::Result<()> {
        if self.fsync_enabled {
            rustix::fs::fsync(descriptor)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadyConfigured;

impl fmt::Display for AlreadyConfigured {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("filesystem durability was already configured")
    }
}

impl std::error::Error for AlreadyConfigured {}

pub fn configure_filesystem_fsync(enabled: bool) -> Result<(), AlreadyConfigured> {
    FILESYSTEM_FSYNC_ENABLED
        .set(enabled)
        .map_err(|_| AlreadyConfigured)
}

pub fn filesystem_durability() -> FilesystemDurability {
    FilesystemDurability::new(FILESYSTEM_FSYNC_ENABLED.get().copied().unwrap_or(true))
}

pub fn sync_all(file: &File) -> io::Result<()> {
    filesystem_durability().sync_all(file)
}

pub async fn sync_data(file: &tokio::fs::File) -> io::Result<()> {
    filesystem_durability().sync_data(file).await
}

pub fn fsync<Fd: AsFd>(descriptor: Fd) -> rustix::io::Result<()> {
    filesystem_durability().fsync(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_policy_skips_file_sync() {
        let file = File::open("/dev/null").unwrap();
        assert!(FilesystemDurability::new(false).sync_all(&file).is_ok());
    }

    #[test]
    fn enabled_policy_calls_file_sync_and_propagates_errors() {
        let file = File::open("/dev/null").unwrap();
        assert!(FilesystemDurability::new(true).sync_all(&file).is_err());
    }

    #[tokio::test]
    async fn disabled_policy_skips_async_file_sync() {
        let file = tokio::fs::File::open("/dev/null").await.unwrap();
        assert!(
            FilesystemDurability::new(false)
                .sync_data(&file)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn enabled_policy_calls_async_file_sync_and_propagates_errors() {
        let file = tokio::fs::File::open("/dev/null").await.unwrap();
        assert!(
            FilesystemDurability::new(true)
                .sync_data(&file)
                .await
                .is_err()
        );
    }

    #[test]
    fn disabled_policy_skips_directory_fsync() {
        let file = File::open("/dev/null").unwrap();
        assert!(FilesystemDurability::new(false).fsync(&file).is_ok());
    }

    #[test]
    fn enabled_policy_calls_directory_fsync_and_propagates_errors() {
        let file = File::open("/dev/null").unwrap();
        assert!(FilesystemDurability::new(true).fsync(&file).is_err());
    }

    #[test]
    fn unconfigured_library_default_is_durable() {
        assert!(filesystem_durability().fsync_enabled());
    }
}
