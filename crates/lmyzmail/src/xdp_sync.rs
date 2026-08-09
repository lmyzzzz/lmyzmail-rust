use std::{collections::HashSet, fmt, sync::Arc};

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{
    cringe::{CringeError, CringeService},
    xdp::{XdpError, XdpService},
};

#[derive(Debug)]
pub enum XdpSyncError {
    Cancelled,
    Database(CringeError),
    Native(XdpError),
}

impl fmt::Display for XdpSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("XDP sync cancelled"),
            Self::Database(error) => write!(formatter, "XDP sync database failure: {error}"),
            Self::Native(error) => write!(formatter, "XDP sync native failure: {error}"),
        }
    }
}

impl std::error::Error for XdpSyncError {}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XdpSyncResult {
    pub banned: usize,
    pub unbanned: usize,
    pub unchanged: usize,
    pub skipped_whitelist: usize,
    pub rebanned: usize,
    pub message: String,
}

pub struct XdpSyncService {
    xdp: Arc<XdpService>,
    cringe: CringeService,
}

impl XdpSyncService {
    pub fn new(xdp: Arc<XdpService>, cringe: CringeService) -> Self {
        Self { xdp, cringe }
    }

    pub fn xdp(&self) -> &XdpService {
        &self.xdp
    }

    pub async fn perform_full_sync(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<XdpSyncResult, XdpSyncError> {
        if cancellation.is_cancelled() {
            return Err(XdpSyncError::Cancelled);
        }
        if !self.xdp.ready() {
            return Ok(XdpSyncResult {
                banned: 0,
                unbanned: 0,
                unchanged: 0,
                skipped_whitelist: 0,
                rebanned: 0,
                message: "XDP not ready".into(),
            });
        }
        let existing = self
            .xdp
            .all_banned(cancellation)
            .await
            .map_err(XdpSyncError::Native)?;
        let candidates = self
            .cringe
            .xdp_reconcile_candidates(
                &existing,
                self.xdp.config().ban_threshold,
                self.xdp.config().unban_threshold,
                cancellation,
            )
            .await
            .map_err(|error| match error {
                CringeError::Cancelled => XdpSyncError::Cancelled,
                other => XdpSyncError::Database(other),
            })?;
        let counts = self
            .xdp
            .reconcile(
                candidates,
                existing.into_iter().collect::<HashSet<_>>(),
                cancellation,
            )
            .await
            .map_err(XdpSyncError::Native)?;
        Ok(XdpSyncResult {
            banned: counts.banned,
            unbanned: counts.unbanned,
            unchanged: counts.unchanged,
            skipped_whitelist: counts.skipped_whitelist,
            rebanned: 0,
            message: format!(
                "Sync completed: {} newly banned, {} unbanned ({} whitelist + {} score), {} unchanged ({} high + {} mid), {} skipped whitelist (thresholds: ban={}, unban={})",
                counts.banned,
                counts.unbanned,
                counts.unbanned_whitelist,
                counts.unbanned_score,
                counts.unchanged,
                counts.unchanged_high,
                counts.unchanged_mid,
                counts.skipped_whitelist,
                self.xdp.config().ban_threshold,
                self.xdp.config().unban_threshold,
            ),
        })
    }
}
