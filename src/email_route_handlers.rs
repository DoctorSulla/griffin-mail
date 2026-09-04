use crate::default_route_handlers::{AppError, ErrorList};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

use crate::{
    config::AppState,
    user::User,
    utilities::{Email, send_email},
};

enum ListPermission {
    _Read,
    Write,
    Send,
    ChangePermission,
}

impl From<ListPermission> for String {
    fn from(permission: ListPermission) -> Self {
        match permission {
            ListPermission::_Read => "read".to_string(),
            ListPermission::Write => "write".to_string(),
            ListPermission::Send => "send".to_string(),
            ListPermission::ChangePermission => "change_permission".to_string(),
        }
    }
}

enum GlobalPermission {
    ManageList,
    ManageRecipient,
    ChangePermission,
}

impl From<GlobalPermission> for String {
    fn from(permission: GlobalPermission) -> Self {
        match permission {
            GlobalPermission::ManageList => "manage_list".to_string(),
            GlobalPermission::ManageRecipient => "manage_recipient".to_string(),
            GlobalPermission::ChangePermission => "change_permission".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewList {
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct List {
    id: i32,
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewRecipient {
    email: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recipient {
    id: i32,
    email: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListWithRecipients {
    list: List,
    recipients: Vec<Recipient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPermission {
    user_email: String,
    permission: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListEmailRequest {
    pub subject: String,
    pub body: String,
    pub from: Option<String>,
    pub reply_to: Option<String>,
}

async fn user_has_list_permission(
    user: &User,
    state: Arc<AppState>,
    list_id: i32,
    permission: ListPermission,
) -> bool {
    let result = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM list_user_permissions WHERE list_id = $1 AND user_email = $2 AND permission = $3)",
        list_id,
        user.email,
        String::from(permission)
    )
    .fetch_one(&state.db_connection_pool)
    .await;

    matches!(result, Ok(Some(true)))
}

async fn user_has_global_permission(
    user: &User,
    state: Arc<AppState>,
    permission: GlobalPermission,
) -> bool {
    let result = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM global_user_permissions WHERE user_email = $1 AND permission = $2)",
        user.email,
        String::from(permission)
    )
    .fetch_one(&state.db_connection_pool)
    .await;

    matches!(result, Ok(Some(true)))
}

/// Add a new recipient who can then later be added to other lists
pub async fn add_recipients(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(new_recipients): Json<Vec<NewRecipient>>,
) -> Result<impl IntoResponse, AppError> {
    if !user_has_global_permission(&user, state.clone(), GlobalPermission::ManageRecipient).await {
        return Err(ErrorList::NoManageRecipientPermission.into());
    }

    let user_names = new_recipients
        .iter()
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();
    let user_emails = new_recipients
        .iter()
        .map(|f| f.email.clone())
        .collect::<Vec<_>>();

    sqlx::query!(
        "INSERT INTO recipients (name,email)
            SELECT name,email FROM UNNEST($1::text[], $2::text[]) AS t(name, email) ON CONFLICT (email) DO NOTHING",
        &user_names,
        &user_emails
    )
    .execute(&state.db_connection_pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Get all recipients for users who are allowed to manage the recipient directory.
pub async fn get_recipients(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<Json<Vec<Recipient>>, AppError> {
    if !user_has_global_permission(&user, state.clone(), GlobalPermission::ManageRecipient).await {
        return Err(ErrorList::NoManageRecipientPermission.into());
    }

    let recipients = sqlx::query_as!(
        Recipient,
        "SELECT id, name, email FROM recipients ORDER BY name, email"
    )
    .fetch_all(&state.db_connection_pool)
    .await?;

    Ok(Json(recipients))
}

pub async fn delete_recipient(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(recipient_email): Path<String>,
) -> Result<StatusCode, AppError> {
    if !user_has_global_permission(&user, state.clone(), GlobalPermission::ManageRecipient).await {
        return Err(ErrorList::NoManageRecipientPermission.into());
    }
    sqlx::query!("DELETE FROM recipients WHERE email = $1", recipient_email)
        .execute(&state.db_connection_pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Get lists that the user has read permission for
pub async fn get_lists(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<Json<Vec<List>>, AppError> {
    let lists = sqlx::query_as!(List, "SELECT id, name, description FROM LISTS WHERE id IN (SELECT list_id FROM list_user_permissions WHERE user_email = $1 and permission = $2)",user.email, "read")
        .fetch_all(&state.db_connection_pool) .await?;

    Ok(Json(lists))
}

/// Create a new empty list
pub async fn create_list(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(create_list): Json<NewList>,
) -> Result<Json<List>, AppError> {
    if !user_has_global_permission(&user, state.clone(), GlobalPermission::ManageList).await {
        return Err(ErrorList::NoManageListPermission.into());
    }

    let mut tx = state.db_connection_pool.begin().await?;

    let id: i32 = sqlx::query_scalar!(
        "INSERT INTO lists (name, description) VALUES ($1, $2) RETURNING id",
        create_list.name,
        create_list.description
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO list_user_permissions (list_id, user_email, permission) VALUES ($1, $2, 'read'), ($1, $2, 'write'), ($1, $2, 'send'), ($1, $2, 'change_permission')",
        id,
        user.email
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(List {
        id,
        name: create_list.name,
        description: create_list.description,
    }))
}

pub async fn get_list_by_id(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
) -> Result<Json<ListWithRecipients>, AppError> {
    let list = sqlx::query_as!(
        List,
        "SELECT id, name, description FROM LISTS WHERE id = $1 and id in (select list_id from list_user_permissions where permission = 'read' and user_email = $2)",
        id,
        user.email
    )
    .fetch_optional(&state.db_connection_pool)
    .await?.ok_or(ErrorList::ListNotFoundOrNoPermission)?;

    let recipients = sqlx::query_as!(
        Recipient,
        "SELECT re.id,re.name, re.email FROM lists_to_recipients ltr JOIN recipients re ON ltr.recipient_id = re.id WHERE ltr.list_id = $1",
        id
    )
    .fetch_all(&state.db_connection_pool)
    .await?;

    Ok(Json(ListWithRecipients { list, recipients }))
}

fn generate_unsubscribe_link(server_url: &str, email: &str, hmac_secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let expires = chrono::Utc::now().timestamp() + (30 * 24 * 60 * 60); // 30 days
    let unsubscribe_text = format!("{}|{}", expires, email);

    let mut mac =
        HmacSha256::new_from_slice(hmac_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(unsubscribe_text.as_bytes());

    let signature_bytes = mac.finalize().into_bytes();
    let unsubscribe_signature = hex::encode(signature_bytes);

    format!(
        "{}/unsubscribe?unsubscribe_text={}&unsubscribe_signature={}",
        server_url, unsubscribe_text, unsubscribe_signature
    )
}

pub async fn send_email_to_list(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
    Json(payload): Json<ListEmailRequest>,
) -> Result<StatusCode, AppError> {
    if user_has_list_permission(&user, state.clone(), id, ListPermission::Send).await {
        let recipients = sqlx::query_as!(
            Recipient,
            "SELECT re.id,re.name, re.email FROM lists_to_recipients ltr JOIN recipients re ON ltr.recipient_id = re.id WHERE ltr.list_id = $1",
            id
        )
        .fetch_all(&state.db_connection_pool)
        .await?;

        let from = payload
            .from
            .unwrap_or_else(|| state.config.email.username.clone());

        let server_url = state.config.server.server_url.clone();
        let hmac_secret = state.config.server.hmac_secret.clone().unwrap_or_default();

        for recipient in recipients {
            let body = if server_url.is_empty() || hmac_secret.is_empty() {
                payload.body.clone()
            } else {
                let unsubscribe_link =
                    generate_unsubscribe_link(&server_url, &recipient.email, &hmac_secret);
                format!(
                    "{}\n\n---\nTo unsubscribe, click here: {}",
                    payload.body, unsubscribe_link
                )
            };

            let email = Email {
                to: recipient.email,
                from: from.clone(),
                subject: payload.subject.clone(),
                body,
                reply_to: payload.reply_to.clone(),
            };
            send_email(state.clone(), email).await?;
        }

        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::Unauthorised.into())
    }
}

pub async fn delete_from_list(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
    Json(recipient_ids): Json<Vec<i32>>,
) -> Result<StatusCode, AppError> {
    if user_has_list_permission(&user, state.clone(), id, ListPermission::Write).await {
        sqlx::query!(
            "DELETE FROM lists_to_recipients WHERE list_id = $1 AND recipient_id = ANY($2)",
            id,
            &recipient_ids
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoWritePermission.into())
    }
}

pub async fn add_to_list(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
    Json(recipient_ids): Json<Vec<i32>>,
) -> Result<StatusCode, AppError> {
    if user_has_list_permission(&user, state.clone(), id, ListPermission::Write).await {
        sqlx::query!(
            "INSERT INTO lists_to_recipients (list_id, recipient_id)
            SELECT $1,recipient_id FROM UNNEST($2::integer[]) AS t(recipient_id)
            ON CONFLICT (list_id, recipient_id) DO NOTHING",
            id,
            &recipient_ids
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoWritePermission.into())
    }
}

/// Get recipients which can be added to a list.
pub async fn get_available_recipients(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
) -> Result<Json<Vec<Recipient>>, AppError> {
    if !user_has_list_permission(&user, state.clone(), id, ListPermission::Write).await {
        return Err(ErrorList::NoWritePermission.into());
    }

    let recipients = sqlx::query_as!(
        Recipient,
        "SELECT id, name, email FROM recipients
         WHERE id NOT IN (
             SELECT recipient_id FROM lists_to_recipients WHERE list_id = $1
         )
         ORDER BY name, email",
        id
    )
    .fetch_all(&state.db_connection_pool)
    .await?;

    Ok(Json(recipients))
}

pub async fn delete_list(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
) -> Result<StatusCode, AppError> {
    if user_has_global_permission(&user, state.clone(), GlobalPermission::ManageList).await {
        sqlx::query!("DELETE FROM lists WHERE id = $1", id)
            .execute(&state.db_connection_pool)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoManageListPermission.into())
    }
}

pub async fn get_list_permissions(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
) -> Result<Json<Vec<UserPermission>>, AppError> {
    if !user_has_list_permission(&user, state.clone(), id, ListPermission::_Read).await {
        return Err(ErrorList::ListNotFoundOrNoPermission.into());
    }

    let permissions = sqlx::query_as!(
        UserPermission,
        "SELECT user_email, permission FROM list_user_permissions WHERE list_id = $1",
        id
    )
    .fetch_all(&state.db_connection_pool)
    .await?;

    Ok(Json(permissions))
}

pub async fn add_list_permissions(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
    Json(payload): Json<Vec<UserPermission>>,
) -> Result<StatusCode, AppError> {
    if user_has_list_permission(&user, state.clone(), id, ListPermission::ChangePermission).await {
        let user_emails = payload
            .iter()
            .map(|p| p.user_email.clone())
            .collect::<Vec<_>>();
        let permissions = payload
            .iter()
            .map(|p| p.permission.clone())
            .collect::<Vec<_>>();

        sqlx::query!(
            "INSERT INTO list_user_permissions (list_id,user_email, permission)
            SELECT $1,user_email,permission FROM UNNEST($2::text[], $3::text[]) AS t(user_email, permission)",
            id,
            &user_emails,
            &permissions
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoWritePermission.into())
    }
}

pub async fn delete_list_permissions(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(id): Path<i32>,
    Json(payload): Json<Vec<UserPermission>>,
) -> Result<StatusCode, AppError> {
    if user_has_list_permission(&user, state.clone(), id, ListPermission::ChangePermission).await {
        let user_emails = payload
            .iter()
            .map(|p| p.user_email.clone())
            .collect::<Vec<_>>();
        let permissions = payload
            .iter()
            .map(|p| p.permission.clone())
            .collect::<Vec<_>>();

        sqlx::query!(
            "DELETE FROM list_user_permissions WHERE list_id = $1 AND (user_email,permission) IN((
            SELECT user_email,permission FROM UNNEST($2::text[], $3::text[]) AS t(user_email, permission)))",
            id,
            &user_emails,
            &permissions
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoWritePermission.into())
    }
}

pub async fn add_global_permissions(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(payload): Json<Vec<UserPermission>>,
) -> Result<StatusCode, AppError> {
    if user_has_global_permission(&user, state.clone(), GlobalPermission::ChangePermission).await {
        let user_emails = payload
            .iter()
            .map(|p| p.user_email.clone())
            .collect::<Vec<_>>();
        let permissions = payload
            .iter()
            .map(|p| p.permission.clone())
            .collect::<Vec<_>>();

        sqlx::query!(
            "INSERT INTO global_user_permissions (user_email, permission)
            SELECT user_email,permission FROM UNNEST($1::text[], $2::text[]) AS t(user_email, permission)",
            &user_emails,
            &permissions
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoManageGlobalPermission.into())
    }
}

pub async fn delete_global_permissions(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(payload): Json<Vec<UserPermission>>,
) -> Result<StatusCode, AppError> {
    if user_has_global_permission(&user, state.clone(), GlobalPermission::ChangePermission).await {
        let user_emails = payload
            .iter()
            .map(|p| p.user_email.clone())
            .collect::<Vec<_>>();
        let permissions = payload
            .iter()
            .map(|p| p.permission.clone())
            .collect::<Vec<_>>();

        sqlx::query!(
            "DELETE FROM global_user_permissions WHERE (user_email,permission) IN((
            SELECT user_email,permission FROM UNNEST($1::text[], $2::text[]) AS t(user_email, permission)))",
            &user_emails,
            &permissions
        )
        .execute(&state.db_connection_pool)
        .await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ErrorList::NoManageGlobalPermission.into())
    }
}

fn verify_unsubscribe_signature(
    unsubscribe_text: &str,
    unsubscribe_signature: &str,
    hmac_secret: &str,
) -> Result<String, ErrorList> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(hmac_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(unsubscribe_text.as_bytes());

    let signature_bytes =
        hex::decode(unsubscribe_signature).map_err(|_| ErrorList::InvalidUnsubscribeSignature)?;

    if mac.verify_slice(&signature_bytes[..]).is_err() {
        return Err(ErrorList::InvalidUnsubscribeSignature);
    }

    let parts: Vec<&str> = unsubscribe_text.split('|').collect();
    if parts.len() != 2 {
        return Err(ErrorList::InvalidUnsubscribeSignature);
    }

    let expires: i64 = parts[0].parse().unwrap_or_else(|_| 0);
    if expires > 0 && expires < chrono::Utc::now().timestamp() {
        return Err(ErrorList::UnsubscribeLinkExpired);
    }

    Ok(parts[1].to_string())
}

pub async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UnsubscribeRequest>,
) -> Result<StatusCode, AppError> {
    let hmac_secret = state.config.server.hmac_secret.clone().unwrap_or_default();
    let email = verify_unsubscribe_signature(
        &payload.unsubscribe_text,
        &payload.unsubscribe_signature,
        &hmac_secret,
    )?;

    sqlx::query!("DELETE FROM recipients WHERE email = $1", email)
        .execute(&state.db_connection_pool)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnsubscribeRequest {
    unsubscribe_text: String,
    unsubscribe_signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HMAC_SECRET: &str = "test-secret-key-12345";

    #[test]
    fn test_generate_unsubscribe_link_produces_valid_signature() {
        let server_url = "http://localhost:3000";
        let email = "test@example.com";
        let link = generate_unsubscribe_link(server_url, email, TEST_HMAC_SECRET);

        // Extract query params from the link
        let url_parts: Vec<&str> = link.split('?').collect();
        assert_eq!(url_parts.len(), 2);

        let query = url_parts[1];
        let params: Vec<&str> = query.split('&').collect();
        assert_eq!(params.len(), 2);

        let text_param = params[0];
        let sig_param = params[1];

        let unsubscribe_text = text_param.strip_prefix("unsubscribe_text=").unwrap();
        let unsubscribe_signature = sig_param.strip_prefix("unsubscribe_signature=").unwrap();

        // Verify it should succeed
        let result =
            verify_unsubscribe_signature(unsubscribe_text, unsubscribe_signature, TEST_HMAC_SECRET);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email);
    }

    #[test]
    fn test_verify_unsubscribe_signature_invalid_signature() {
        let unsubscribe_text = "9999999999|test@example.com";
        let invalid_signature = "deadbeef";

        let result =
            verify_unsubscribe_signature(unsubscribe_text, invalid_signature, TEST_HMAC_SECRET);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ErrorList::InvalidUnsubscribeSignature
        ));
    }

    #[test]
    fn test_verify_unsubscribe_signature_expired_link() {
        let email = "test@example.com";
        let expired_timestamp = chrono::Utc::now().timestamp() - 1000;
        let unsubscribe_text = format!("{}|{}", expired_timestamp, email);

        // Generate a valid signature for expired text using the test secret
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(TEST_HMAC_SECRET.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(unsubscribe_text.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let unsubscribe_signature = hex::encode(signature_bytes);

        let result = verify_unsubscribe_signature(
            &unsubscribe_text,
            &unsubscribe_signature,
            TEST_HMAC_SECRET,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ErrorList::UnsubscribeLinkExpired
        ));
    }

    #[test]
    fn test_verify_unsubscribe_signature_malformed_text() {
        let malformed_text = "no-pipe-here";
        let signature = "aabbccdd";

        let result = verify_unsubscribe_signature(malformed_text, signature, TEST_HMAC_SECRET);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ErrorList::InvalidUnsubscribeSignature
        ));
    }

    #[test]
    fn test_verify_unsubscribe_signature_empty_signature() {
        let unsubscribe_text = "9999999999|test@example.com";
        let result = verify_unsubscribe_signature(unsubscribe_text, "", TEST_HMAC_SECRET);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ErrorList::InvalidUnsubscribeSignature
        ));
    }

    #[test]
    fn test_generate_unsubscribe_link_different_emails() {
        let server_url = "https://example.com";
        let email1 = "user1@example.com";
        let email2 = "user2@example.com";

        let link1 = generate_unsubscribe_link(server_url, email1, TEST_HMAC_SECRET);
        let link2 = generate_unsubscribe_link(server_url, email2, TEST_HMAC_SECRET);

        assert_ne!(link1, link2);
        assert!(link1.contains(email1));
        assert!(link2.contains(email2));
    }
}
