use std::{env, path::PathBuf, sync::Arc};

use lmyzmail::{
    config::{Properties, RuntimeConfig},
    database, http, lifecycle, smtp,
};
use tokio_util::sync::CancellationToken;

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
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(lifecycle::wait_for_shutdown(signal_cancellation));
    let http_config = Arc::clone(&config);
    let smtp_config = Arc::clone(&config);
    let http_cancellation = cancellation.clone();
    let smtp_cancellation = cancellation.clone();
    let http_pool = database_pool.clone();
    let http_task =
        tokio::spawn(
            async move { http::serve_http(http_config, http_pool, http_cancellation).await },
        );
    let smtp_task = tokio::spawn(async move {
        smtp::serve_smtp(smtp_config, database_pool, smtp_cancellation).await
    });
    tokio::select! {
        result = http_task => result??,
        result = smtp_task => result??,
    }
    cancellation.cancel();
    signal_task.abort();
    Ok(())
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
