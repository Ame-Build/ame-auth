use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

pub(crate) fn set_tracing_subscriber(level: LogLevel) {
    let log_level = match level {
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Error => tracing::Level::ERROR,
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn default_log_level() -> LogLevel {
    LogLevel::Warn
}

#[derive(Parser)]
pub struct Args {
    #[clap(short, long, default_value = "config.toml")]
    pub config_file: String,
}

pub async fn read_config_file(path: &str) -> anyhow::Result<AuthProviderConfig> {
    let file = tokio::fs::read_to_string(path).await?;
    let config: AuthProviderConfig = toml::from_str(&file)?;
    Ok(config)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderConfig {
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,
    pub nats: String,
    pub postgres: String,

    pub email_provider: EmailAuthProviderConfig,
    pub jwt_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAuthProviderConfig {
    pub sender: String,
    pub verify_link_base: String,
    #[serde(default = "default_false")]
    pub enable_domain_whitelist: bool,
    pub domain_whitelist: Vec<String>,
    #[serde(default = "default_true")]
    pub enable_domain_blacklist: bool,
    pub domain_blacklist: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}
