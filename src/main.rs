use clap::Parser;
use futures_util::future::join_all;
use sea_orm::Database;
use std::sync::Arc;
use tracing::info;

mod auth_providers;
mod config;
mod entities;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = config::Args::parse();
    let config = config::read_config_file(&args.config_file).await?;
    config::set_tracing_subscriber(config.log_level);
    let db = Database::connect(&config.postgres).await?;
    let nats = async_nats::connect(&config.nats).await?;
    info!("Connected to NATS server at {}", config.nats);
    let state = Arc::new(auth_providers::AuthProviderState { config, nats, db });
    let error_trigger = Arc::new(tokio::sync::RwLock::new(false));
    let handlers = auth_providers::email_auth::handlers(state, error_trigger);
    join_all(handlers).await;
    Ok(())
}
