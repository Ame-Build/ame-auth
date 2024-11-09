use crate::config::AuthProviderConfig;

pub mod email_auth;

pub struct AuthProviderState {
    pub config: AuthProviderConfig,
    pub nats: async_nats::Client,
    pub db: sea_orm::DatabaseConnection,
}
