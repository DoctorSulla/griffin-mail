use anyhow::anyhow;
use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;

use crate::config::AppState;
use std::{ops::Deref, sync::Arc};

const EMAIL_VERIFICATION_REQUIRED: &str =
    "Please verify your email before using permission-protected features";

#[derive(Serialize, Deserialize, Debug, FromRow)]
pub struct User {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub hashed_password: Option<String>,
    pub auth_level: String,
    pub login_attempts: i32,
    pub registration_ts: i64,
    pub identity_provider: String,
}

/// A user whose email address is verified and can therefore exercise permissions.
pub struct VerifiedEmailUser(User);

impl Deref for VerifiedEmailUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<User> for VerifiedEmailUser {
    type Error = &'static str;

    fn try_from(user: User) -> Result<Self, Self::Error> {
        if user.email_verified {
            Ok(Self(user))
        } else {
            Err(EMAIL_VERIFICATION_REQUIRED)
        }
    }
}

impl FromRequestParts<Arc<AppState>> for VerifiedEmailUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = User::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        Self::try_from(user).map_err(|message| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "response_type": "Error",
                    "message": message,
                })),
            )
                .into_response()
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Profile {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub auth_level: String,
    pub identity_provider: String,
    pub registration_ts: i64,
}

impl From<User> for Profile {
    fn from(value: User) -> Self {
        Self {
            username: value.username,
            email: value.email,
            email_verified: value.email_verified,
            auth_level: value.auth_level,
            identity_provider: value.identity_provider,
            registration_ts: value.registration_ts,
        }
    }
}

pub async fn get_user_by_email(state: Arc<AppState>, email: &str) -> Result<User, anyhow::Error> {
    sqlx::query_as::<_, User>("select * from users where email=$1")
        .bind(email)
        .fetch_optional(&state.db_connection_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))
}

pub async fn get_user_by_sub(state: Arc<AppState>, sub: &str) -> Result<User, anyhow::Error> {
    sqlx::query_as::<_, User>("select * from users where sub=$1")
        .bind(sub)
        .fetch_optional(&state.db_connection_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))
}

pub async fn get_user_by_username(
    state: Arc<AppState>,
    username: &str,
) -> Result<User, anyhow::Error> {
    sqlx::query_as::<_, User>("select * from users where username=$1")
        .bind(username)
        .fetch_optional(&state.db_connection_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))
}

pub async fn update_google_user_email(
    state: Arc<AppState>,
    new_email: &str,
    email_verified: bool,
    sub: &str,
) -> Result<(), anyhow::Error> {
    sqlx::query("update users set email=$1, email_verified=$2 where sub=$3")
        .bind(new_email)
        .bind(email_verified)
        .bind(sub)
        .execute(&state.db_connection_pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{User, VerifiedEmailUser};

    fn user(email_verified: bool) -> User {
        User {
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            email_verified,
            hashed_password: None,
            auth_level: "User".to_string(),
            login_attempts: 0,
            registration_ts: 0,
            identity_provider: "default".to_string(),
        }
    }

    #[test]
    fn verified_email_user_requires_a_verified_email() {
        assert_eq!(
            VerifiedEmailUser::try_from(user(false)).err(),
            Some("Please verify your email before using permission-protected features")
        );
        assert!(VerifiedEmailUser::try_from(user(true)).is_ok());
    }
}
