use ame_bus::rpc::NatsRpcRequest;
use ame_bus::NatsJsonMessage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct EmailRegisterRequest {
    pub email: String,
    pub password: String,
}

impl NatsJsonMessage for EmailRegisterRequest {
    fn subject() -> &'static str {
        "ame-auth.email.register"
    }
}

impl NatsRpcRequest for EmailRegisterRequest {
    type Response = EmailRegisterResponse;
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EmailRegisterResponse {
    Success,
    DomainBlocked,
    InvalidEmail,
    TooFrequent,
    ConflictEmail,
    Failed,
}

impl NatsJsonMessage for EmailRegisterResponse {
    fn subject() -> &'static str {
        "ame-auth.email.register"
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EmailLoginResponse {
    Success(String),
    InvalidAccount,
    AccountBlocked,
    Failure,
}

impl NatsJsonMessage for EmailLoginResponse {
    fn subject() -> &'static str {
        "ame-auth.email.login"
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LoginTokenType {
    Jwt,
}

#[derive(Serialize, Deserialize)]
pub struct EmailLoginRequest {
    pub email: String,
    pub password: String,
    pub token_type: LoginTokenType,
}

impl NatsJsonMessage for EmailLoginRequest {
    fn subject() -> &'static str {
        "ame-auth.email.login"
    }
}

impl NatsRpcRequest for EmailLoginRequest {
    type Response = EmailLoginResponse;
}

#[derive(Serialize, Deserialize)]
pub struct EmailVerifyLinkCallback {
    pub call_id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub enum EmailVerifyLinkCallbackResponse {
    Success,
    InvalidCallId,
    Expired,
    Failed,
}

impl NatsJsonMessage for EmailVerifyLinkCallbackResponse {
    fn subject() -> &'static str {
        "ame-auth.email.verify-link"
    }
}

impl NatsJsonMessage for EmailVerifyLinkCallback {
    fn subject() -> &'static str {
        "ame-auth.email.verify-link"
    }
}

impl NatsRpcRequest for EmailVerifyLinkCallback {
    type Response = EmailVerifyLinkCallbackResponse;
}
