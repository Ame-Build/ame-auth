use ame_bus::NatsJsonMessage;
use ame_bus::rpc::NatsRpcRequest;
use serde::{Deserialize, Serialize};

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
    Success,
    InvalidAccount,
    AccountBlocked,
    Failure
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