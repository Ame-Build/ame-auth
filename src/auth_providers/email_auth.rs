use crate::auth_providers::{email_auth, AuthProviderState};
use crate::config::EmailAuthProviderConfig;
use crate::entities::{email_account, email_verifying, user_auth_data};
use ame_auth::rpc::email_provider::{
    EmailLoginRequest, EmailLoginResponse, EmailRegisterRequest, EmailRegisterResponse,
    EmailVerifyLinkCallback, EmailVerifyLinkCallbackResponse,
};
use ame_auth::UserJwt;
use ame_bus::rpc::reply;
use ame_bus::simple_push::SimplestNatsMessage;
use ame_bus::NatsJsonMessage;
use ame_mail_sender::MailType;
use anyhow::Result;
use askama::Template;
use bcrypt::BcryptResult;
use email_address::EmailAddress;
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::error;

#[derive(Template)]
#[template(path = "register_email.html")]
pub struct RegisterEmail<'a> {
    pub register_link: &'a str,
}

fn domain_defender(email_address: &str, config: &EmailAuthProviderConfig) -> bool {
    if !EmailAddress::is_valid(email_address) {
        return false;
    }
    let domain = email_address.split('@').last();
    if domain.is_none() {
        return false;
    }
    let domain = domain.unwrap();
    if config.enable_domain_whitelist {
        return config.domain_whitelist.contains(&domain.to_string());
    }
    if config.enable_domain_blacklist {
        return !config.domain_blacklist.contains(&domain.to_string());
    }
    true
}

fn hash_password(password: &str) -> BcryptResult<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

fn verify_password(password: &str, hash: &str) -> BcryptResult<bool> {
    bcrypt::verify(password, hash)
}

pub async fn handle_register(
    req: EmailRegisterRequest,
    state: &AuthProviderState,
) -> Result<EmailRegisterResponse> {
    let email = req.email;
    if !EmailAddress::is_valid(&email) {
        return Ok(EmailRegisterResponse::InvalidEmail);
    }
    if !domain_defender(&email, &state.config.email_provider) {
        return Ok(EmailRegisterResponse::DomainBlocked);
    }
    let user = email_account::Model::find_by_email(&state.db, &email).await?;
    if user.is_some() {
        return Ok(EmailRegisterResponse::ConflictEmail);
    }
    let sending = email_verifying::Model::find_by_email(&state.db, &email).await?;
    let now = chrono::Utc::now().naive_utc();
    if let Some(sending) = sending {
        let send_at = sending.send_at;
        if now - send_at < chrono::Duration::seconds(60) {
            return Ok(EmailRegisterResponse::TooFrequent);
        }
    };
    let password = hash_password(&req.password)?;
    let email_verifying =
        email_verifying::Model::create_or_update(&state.db, &email, &password).await?;
    let auth_key = email_verifying.auth_key;
    let verify_email = RegisterEmail {
        register_link: &format!(
            "{}/{}",
            state.config.email_provider.verify_link_base, auth_key
        ),
    };
    let email_sending_request = ame_mail_sender::MailSend {
        send_from: state.config.email_provider.sender.to_owned(),
        send_to: email,
        subject: "Register Verify".to_string(),
        body: verify_email.render()?,
        mail_type: MailType::Html,
    };
    email_sending_request.push_message(&state.nats).await?;
    Ok(EmailRegisterResponse::Success)
}

pub async fn handle_verify_email(
    req: EmailVerifyLinkCallback,
    state: &AuthProviderState,
) -> Result<EmailVerifyLinkCallbackResponse> {
    let call_id = req.call_id;
    let email_verifying = email_verifying::Model::find_by_auth_id(&state.db, call_id).await?;
    if email_verifying.is_none() {
        return Ok(EmailVerifyLinkCallbackResponse::Failed);
    }
    let email_verifying = email_verifying.unwrap();
    let sent_at = email_verifying.send_at;
    let now = chrono::Utc::now().naive_utc();
    match now - sent_at {
        _ if now - sent_at > chrono::Duration::days(1) => {
            return Ok(EmailVerifyLinkCallbackResponse::InvalidCallId)
        }
        _ if now - sent_at > chrono::Duration::minutes(10) => {
            return Ok(EmailVerifyLinkCallbackResponse::Expired)
        }
        _ => (),
    };
    let user_auth_data = user_auth_data::Model::create(&state.db).await?;
    let email = email_verifying.email;
    let password = email_verifying.password;
    email_account::Model::create_account(&state.db, &email, &password, user_auth_data.id).await?;
    Ok(EmailVerifyLinkCallbackResponse::Success)
}

pub async fn handle_login(
    req: EmailLoginRequest,
    state: &AuthProviderState,
) -> Result<EmailLoginResponse> {
    let email = req.email;
    let password = req.password;
    let user = email_account::Model::find_auth_data_from_email(&state.db, &email).await?;
    if user.is_none() {
        return Ok(EmailLoginResponse::InvalidAccount);
    };
    let (email_account, user) = user.unwrap();
    if !verify_password(&password, &email_account.password)? {
        return Ok(EmailLoginResponse::InvalidAccount);
    };
    if user.is_banned {
        return Ok(EmailLoginResponse::AccountBlocked);
    };
    let now = chrono::Utc::now().naive_utc();
    let jwt_expire = now + chrono::Duration::days(30);
    let jwt = UserJwt {
        user_id: user.id,
        expire_at: jwt_expire,
    };
    let jwt = jwt.encode(&state.config.jwt_secret)?;
    Ok(EmailLoginResponse::Success(jwt))
}

pub(crate) fn handlers(
    state: Arc<AuthProviderState>,
    error_trigger: Arc<RwLock<bool>>,
) -> Vec<JoinHandle<()>> {
    let state_clone_1 = state.clone();
    let error_trigger_clone_1 = error_trigger.clone();
    let handler_register = tokio::spawn(async move {
        let nats_subscriber = state_clone_1
            .nats
            .subscribe(EmailRegisterRequest::subject())
            .await;
        if nats_subscriber.is_err() {
            let mut error_trigger = error_trigger_clone_1.write().await;
            *error_trigger = true;
            return;
        }
        let mut nats_subscriber = nats_subscriber.unwrap();
        while let Some(message) = nats_subscriber.next().await {
            if *error_trigger_clone_1.read().await {
                break;
            }
            let payload = EmailRegisterRequest::from_json_bytes(&message.payload);
            if payload.is_err() {
                let mut error_trigger = error_trigger_clone_1.write().await;
                *error_trigger = true;
                error!("Failed to parse payload in {}", message.subject);
                continue;
            }
            let payload = payload.unwrap();
            let response = email_auth::handle_register(payload, &state_clone_1)
                .await
                .unwrap_or_else(|_| EmailRegisterResponse::Failed);
            if reply(message.reply, response, &state_clone_1.nats)
                .await
                .is_err()
            {
                error!("Failed to reply in {}", message.subject);
            }
        }
        let mut error_trigger = error_trigger_clone_1.write().await;
        *error_trigger = true;
    });
    let state_clone_2 = state.clone();
    let error_trigger_clone_2 = error_trigger.clone();
    let handler_verify_callback = tokio::spawn(async move {
        let nats_subscriber = state_clone_2
            .nats
            .subscribe(EmailVerifyLinkCallback::subject())
            .await;
        if nats_subscriber.is_err() {
            let mut error_trigger = error_trigger_clone_2.write().await;
            *error_trigger = true;
            return;
        }
        let mut nats_subscriber = nats_subscriber.unwrap();
        while let Some(message) = nats_subscriber.next().await {
            if *error_trigger_clone_2.read().await {
                break;
            }
            let payload = EmailVerifyLinkCallback::from_json_bytes(&message.payload);
            if payload.is_err() {
                let mut error_trigger = error_trigger_clone_2.write().await;
                *error_trigger = true;
                error!("Failed to parse payload in {}", message.subject);
                continue;
            }
            let payload = payload.unwrap();
            let response = email_auth::handle_verify_email(payload, &state_clone_2)
                .await
                .unwrap_or_else(|_| EmailVerifyLinkCallbackResponse::Failed);
            if reply(message.reply, response, &state_clone_2.nats)
                .await
                .is_err()
            {
                error!("Failed to reply in {}", message.subject);
            }
        }
        let mut error_trigger = error_trigger_clone_2.write().await;
        *error_trigger = true;
    });
    let state_clone_3 = state.clone();
    let error_trigger_clone_3 = error_trigger.clone();
    let handler_login = tokio::spawn(async move {
        let nats_subscriber = state_clone_3
            .nats
            .subscribe(EmailLoginRequest::subject())
            .await;
        if nats_subscriber.is_err() {
            let mut error_trigger = error_trigger_clone_3.write().await;
            *error_trigger = true;
            return;
        }
        let mut nats_subscriber = nats_subscriber.unwrap();
        while let Some(message) = nats_subscriber.next().await {
            if *error_trigger_clone_3.read().await {
                break;
            }
            let payload = EmailLoginRequest::from_json_bytes(&message.payload);
            if payload.is_err() {
                let mut error_trigger = error_trigger_clone_3.write().await;
                *error_trigger = true;
                error!("Failed to parse payload in {}", message.subject);
                continue;
            }
            let payload = payload.unwrap();
            let response = email_auth::handle_login(payload, &state_clone_3)
                .await
                .unwrap_or_else(|_| EmailLoginResponse::Failure);
            if reply(message.reply, response, &state_clone_3.nats)
                .await
                .is_err()
            {
                error!("Failed to reply in {}", message.subject);
            }
        }
        let mut error_trigger = error_trigger_clone_3.write().await;
        *error_trigger = true;
    });

    vec![handler_register, handler_verify_callback, handler_login]
}

#[cfg(test)]
mod test {
    use askama::Template;
    #[test]
    fn test_register_email() {
        let register_email = super::RegisterEmail {
            register_link: "https://example.com/register",
        };
        register_email.render().unwrap();
    }
    #[test]
    fn test_defender_whitelist() {
        let config = crate::config::EmailAuthProviderConfig {
            sender: "".to_string(),
            verify_link_base: "https://example.com/verify".to_string(),
            enable_domain_whitelist: true,
            domain_whitelist: vec!["example.com".to_string(), "example.org".to_string()],
            enable_domain_blacklist: false,
            domain_blacklist: vec![],
        };
        assert!(!super::domain_defender("a@b.com", &config));
        assert!(!super::domain_defender("invalid", &config));
        assert!(super::domain_defender("1234@example.com", &config));
        assert!(super::domain_defender("2345@example.org", &config));
    }
    #[test]
    fn test_defender_blacklist() {
        let config = crate::config::EmailAuthProviderConfig {
            sender: "".to_string(),
            verify_link_base: "https://example.com/verify".to_string(),
            enable_domain_whitelist: false,
            domain_whitelist: vec![],
            enable_domain_blacklist: true,
            domain_blacklist: vec!["example.com".to_string(), "example.org".to_string()],
        };
        assert!(super::domain_defender("123@abc.com", &config));
        assert!(!super::domain_defender("invalid", &config));
        assert!(!super::domain_defender("a@example.com", &config));
    }
}
