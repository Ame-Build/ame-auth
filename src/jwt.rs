use chrono::{DateTime, NaiveDateTime, Timelike};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserJwt {
    pub user_id: i32,
    pub expire_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl From<&UserJwt> for Claims {
    fn from(user_jwt: &UserJwt) -> Self {
        Claims {
            sub: user_jwt.user_id.to_string(),
            exp: user_jwt.expire_at.num_seconds_from_midnight() as usize,
        }
    }
}

impl TryFrom<Claims> for UserJwt {
    type Error = ();

    fn try_from(claims: Claims) -> Result<Self, ()> {
        Ok(UserJwt {
            user_id: claims.sub.parse().map_err(|_| ())?,
            expire_at: DateTime::from_timestamp(claims.exp as i64, 0)
                .ok_or(())?
                .naive_utc(),
        })
    }
}

impl UserJwt {
    pub fn encode(&self, secret: &str) -> anyhow::Result<String> {
        let claims: Claims = self.into();
        let key = EncodingKey::from_secret(secret.as_ref());
        let result = encode(&Header::default(), &claims, &key)?;
        Ok(result)
    }
    pub fn decode(token: &str, secret: &str) -> anyhow::Result<UserJwt> {
        let key = DecodingKey::from_secret(secret.as_ref());
        let token = decode::<Claims>(token, &key, &Validation::default())?;
        let claims = token.claims;
        let user_jwt =
            UserJwt::try_from(claims).map_err(|_| anyhow::anyhow!("Invalid user jwt"))?;
        Ok(user_jwt)
    }
}
