use std::{env, io, path::PathBuf, sync::Arc, time::Duration};

use lmyzmail::{
    config::{Properties, RuntimeConfig},
    cringe::CringeService,
    cringe_decay, database, honeypot, htcpcp, http, lifecycle, minecraft,
    outbound::OutboundService,
    outbound_worker::OutboundWorker,
    redis,
    reporting::{self, ReportingService},
    smtp,
    xdp::XdpService,
    xdp_pps,
    xdp_sync::XdpSyncService,
};
use tokio::{task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

const PROCESS_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(35);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse(env::args().skip(1))?;
    if cli.help {
        print_help();
        return Ok(());
    }
    if cli.version {
        println!("lmyzmail {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let config_path = cli.config_path.unwrap_or_else(default_config_path);
    let mut properties = Properties::from_path(&config_path)?;
    properties.overlay(cli.overrides)?;
    let config = Arc::new(RuntimeConfig::from_properties(properties)?);
    if cli.check_config {
        print_config_summary(&config, &config_path);
        return Ok(());
    }
    let database_pool = database::create_pool(&config)?;
    let redis_pool = redis::create_pool(&config)?;
    let outbound_worker =
        OutboundWorker::from_config(&config, database_pool.clone(), redis_pool.clone())?;
    let reporting_service = Arc::new(ReportingService::new(
        database_pool.clone(),
        config.reporting.clone(),
    )?);
    let outbound_service = Arc::new(OutboundService::from_config(
        &config,
        database_pool.clone(),
        redis_pool.clone(),
    )?);
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(lifecycle::wait_for_shutdown(signal_cancellation));
    if !outbound_worker.initialize(&cancellation).await? {
        let _ = signal_task.await;
        return Ok(());
    }
    let xdp_service = Arc::new(XdpService::from_config(&config.xdp)?);
    let cringe_service = CringeService::new(database_pool.clone());
    let xdp_sync = Arc::new(XdpSyncService::new(
        Arc::clone(&xdp_service),
        cringe_service.clone(),
    ));
    xdp_service.initialize(&cancellation).await;
    let xdp_startup_task = if config.xdp.sync_on_startup && xdp_service.ready() {
        let xdp_sync = Arc::clone(&xdp_sync);
        let xdp_sync_cancellation = cancellation.clone();
        Some(tokio::spawn(async move {
            if let Err(error) = xdp_sync.perform_full_sync(&xdp_sync_cancellation).await {
                eprintln!("lmyzmail XDP startup sync failed: {error}");
            }
        }))
    } else {
        None
    };
    let mut services = JoinSet::new();
    if config.xdp.enabled && config.xdp.pps_monitor.enabled {
        let monitor_xdp = Arc::clone(&xdp_service);
        let monitor_cringe = cringe_service.clone();
        let monitor_cancellation = cancellation.clone();
        services.spawn(async move {
            xdp_pps::run_pps_monitor(monitor_xdp, monitor_cringe, monitor_cancellation).await;
            ("XDP PPS monitor", Ok::<(), io::Error>(()))
        });
    }
    let decay_cringe = cringe_service.clone();
    let decay_xdp_sync = Arc::clone(&xdp_sync);
    let decay_config = config.cringe_decay.clone();
    let decay_cancellation = cancellation.clone();
    services.spawn(async move {
        cringe_decay::run_scheduler(
            decay_cringe,
            decay_xdp_sync,
            decay_config,
            decay_cancellation,
        )
        .await;
        ("cringe decay scheduler", Ok::<(), io::Error>(()))
    });
    let http_config = Arc::clone(&config);
    let http_cancellation = cancellation.clone();
    let http_pool = database_pool.clone();
    let http_reporting = Arc::clone(&reporting_service);
    let http_outbound = Arc::clone(&outbound_service);
    let http_xdp = Arc::clone(&xdp_service);
    let http_xdp_sync = Arc::clone(&xdp_sync);
    services.spawn(async move {
        (
            "HTTP",
            http::serve_http(
                http_config,
                http_pool,
                http_reporting,
                http_outbound,
                http_xdp,
                http_xdp_sync,
                http_cancellation,
            )
            .await,
        )
    });
    if config.reporting.enabled && config.reporting.auto_send_enabled {
        let scheduler_reporting = Arc::clone(&reporting_service);
        let scheduler_outbound = Arc::clone(&outbound_service);
        let scheduler_domain = config.domain.clone();
        let scheduler_cancellation = cancellation.clone();
        services.spawn(async move {
            reporting::run_scheduler(
                scheduler_reporting,
                scheduler_outbound,
                scheduler_domain,
                scheduler_cancellation,
            )
            .await;
            ("report scheduler", Ok::<(), io::Error>(()))
        });
    }
    if !config.listen.honeypots.is_empty() {
        let honeypot_config = Arc::clone(&config);
        let honeypot_cancellation = cancellation.clone();
        let honeypot_pool = database_pool.clone();
        services.spawn(async move {
            (
                "honeypot",
                honeypot::serve_honeypots(honeypot_config, honeypot_pool, honeypot_cancellation)
                    .await,
            )
        });
    }
    let smtp_config = Arc::clone(&config);
    let smtp_pool = database_pool.clone();
    let smtp_redis_pool = redis_pool.clone();
    let smtp_cancellation = cancellation.clone();
    services.spawn(async move {
        (
            "SMTP",
            smtp::serve_smtp(smtp_config, smtp_pool, smtp_redis_pool, smtp_cancellation).await,
        )
    });
    if config.htcpcp.enabled {
        let htcpcp_config = Arc::clone(&config);
        let htcpcp_cancellation = cancellation.clone();
        services.spawn(async move {
            (
                "HTCPCP",
                htcpcp::serve_htcpcp(htcpcp_config, htcpcp_cancellation).await,
            )
        });
    }
    if config.minecraft.enabled {
        let minecraft_config = Arc::clone(&config);
        let minecraft_pool = database_pool.clone();
        let minecraft_cancellation = cancellation.clone();
        services.spawn(async move {
            (
                "Minecraft",
                minecraft::serve_minecraft(
                    minecraft_config,
                    minecraft_pool,
                    minecraft_cancellation,
                )
                .await,
            )
        });
    }
    let outbound_cancellation = cancellation.clone();
    services.spawn(async move {
        (
            "outbound",
            outbound_worker
                .run(outbound_cancellation)
                .await
                .map_err(io::Error::other),
        )
    });

    let mut failure = None;
    if let Some(result) = services.join_next().await {
        match result {
            Ok((_, Ok(()))) if cancellation.is_cancelled() => {}
            Ok((name, Ok(()))) => {
                failure = Some(io::Error::other(format!(
                    "lmyzmail {name} service exited unexpectedly"
                )));
            }
            Ok((name, Err(error))) => {
                failure = Some(io::Error::other(format!(
                    "lmyzmail {name} service failed: {error}"
                )));
            }
            Err(error) => {
                failure = Some(io::Error::other(format!(
                    "lmyzmail service task failed: {error}"
                )));
            }
        }
    }
    cancellation.cancel();
    if timeout(PROCESS_SHUTDOWN_DEADLINE, async {
        while let Some(result) = services.join_next().await {
            match result {
                Ok((_, Ok(()))) => {}
                Ok((name, Err(error))) if failure.is_none() => {
                    failure = Some(io::Error::other(format!(
                        "lmyzmail {name} service failed during shutdown: {error}"
                    )));
                }
                Err(error) if failure.is_none() => {
                    failure = Some(io::Error::other(format!(
                        "lmyzmail service task failed during shutdown: {error}"
                    )));
                }
                _ => {}
            }
        }
    })
    .await
    .is_err()
    {
        services.abort_all();
        while services.join_next().await.is_some() {}
        if failure.is_none() {
            failure = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "lmyzmail services exceeded the shutdown deadline",
            ));
        }
    }
    signal_task.abort();
    let _ = signal_task.await;
    if let Some(task) = xdp_startup_task {
        let _ = task.await;
    }
    xdp_sync.shutdown().await;
    if let Err(error) = xdp_service.shutdown().await
        && failure.is_none()
    {
        failure = Some(io::Error::other(error));
    }
    match failure {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}

struct Cli {
    config_path: Option<PathBuf>,
    overrides: Vec<(String, String)>,
    check_config: bool,
    help: bool,
    version: bool,
}

impl Cli {
    fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut cli = Self {
            config_path: None,
            overrides: Vec::new(),
            check_config: false,
            help: false,
            version: false,
        };
        while let Some(argument) = arguments.next() {
            if argument == "--config" {
                if cli.config_path.is_some() {
                    return Err("--config may be specified only once".into());
                }
                cli.config_path = Some(PathBuf::from(
                    arguments.next().ok_or("--config requires a path")?,
                ));
            } else if let Some(value) = argument.strip_prefix("--config=") {
                if cli.config_path.is_some() || value.is_empty() {
                    return Err("--config must be specified once with a non-empty path".into());
                }
                cli.config_path = Some(PathBuf::from(value));
            } else if argument == "--check-config" {
                cli.check_config = true;
            } else if argument == "--help" || argument == "-h" {
                cli.help = true;
            } else if argument == "--version" || argument == "-V" {
                cli.version = true;
            } else if let Some(property) = argument.strip_prefix("--") {
                let Some((key, value)) = property.split_once('=') else {
                    return Err(format!("unknown argument: {argument}"));
                };
                if key.is_empty() {
                    return Err("property override key must not be empty".into());
                }
                cli.overrides.push((key.to_owned(), value.to_owned()));
            } else {
                return Err(format!("unknown argument: {argument}"));
            }
        }
        Ok(cli)
    }
}

fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("LMYZMAIL_CONFIG") {
        return PathBuf::from(path);
    }
    let local = PathBuf::from("application.properties");
    if local.is_file() {
        return local;
    }
    PathBuf::from("/etc/lmyzmail/application.properties")
}

fn print_config_summary(config: &RuntimeConfig, path: &std::path::Path) {
    println!(
        "config={} http={} smtp={} htcpcp={} minecraft={} maildir={} api_keys={}",
        path.display(),
        config.listen.http,
        config.listen.smtp,
        config.listen.htcpcp,
        config.listen.minecraft,
        config.maildir.display(),
        config.api_keys.len()
    );
}

fn print_help() {
    println!(
        "Usage: lmyzmail [--config PATH] [--check-config] [--property=value]\n\n\
         Configuration uses Java properties. lmyzmail.* keys take precedence over legacy botmail.* aliases.\n\
         Defaults: ./application.properties, then /etc/lmyzmail/application.properties."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_accepts_property_overrides_and_config_equals() {
        let cli = Cli::parse(
            [
                "--config=/tmp/lmyzmail.properties".to_owned(),
                "--lmyzmail.http.port=18080".to_owned(),
                "--check-config".to_owned(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            cli.config_path,
            Some(PathBuf::from("/tmp/lmyzmail.properties"))
        );
        assert_eq!(
            cli.overrides,
            vec![("lmyzmail.http.port".into(), "18080".into())]
        );
        assert!(cli.check_config);
    }

    #[test]
    fn cli_rejects_unknown_or_duplicate_config_arguments() {
        assert!(Cli::parse(["--wat".to_owned()].into_iter()).is_err());
        assert!(
            Cli::parse(
                ["--config", "a", "--config", "b"]
                    .map(str::to_owned)
                    .into_iter()
            )
            .is_err()
        );
    }
}
