use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

pub async fn wait_for_shutdown(cancellation: CancellationToken) {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    eprintln!("lmyzmail could not install SIGTERM handler: {error}");
                    let _ = tokio::signal::ctrl_c().await;
                    cancellation.cancel();
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    cancellation.cancel();
}

pub async fn stop_with_deadline(token: &CancellationToken) {
    token.cancel();
    let _ = timeout(SHUTDOWN_DEADLINE, token.cancelled()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_token_is_observed() {
        let token = CancellationToken::new();
        let child = token.child_token();
        token.cancel();
        assert!(child.is_cancelled());
        stop_with_deadline(&child).await;
    }
}
