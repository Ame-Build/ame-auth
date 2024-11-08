use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::config::AuthProviderConfig;

mod email_auth;

pub struct AuthProviderState {
    config: AuthProviderConfig,
    nats: async_nats::Client,
    db: sea_orm::DatabaseConnection
}

#[async_trait]
pub trait AuthProvider<AccountInfo>
    where AccountInfo: Serialize + for <'de> Deserialize<'de>
{
    fn provider_name(&self) -> &'static str;
}