use crate::default_route_handlers::{AppError, ErrorList};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{config::AppState, user::User};

enum ListPermission {
    Read,
    Write,
    Send,
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
struct NewRecipient {
    email: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Recipient {
    id: i32,
    email: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListWithRecipients {
    list: List,
    recipients: Vec<Recipient>,
}

async fn _user_has_permission(
    user: &User,
    state: Arc<AppState>,
    list_id: i32,
    permission: &str,
) -> bool {
    let result = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM list_user_permissions WHERE list_id = $1 AND user_email = $2 AND permission = $3)",
        list_id,
        user.email,
        permission
    )
    .fetch_one(&state.db_connection_pool)
    .await;

    match result {
        Ok(Some(true)) => true,
        _ => false,
    }
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
    if user.auth_level != *"admin" {
        return Err(ErrorList::OnlyAdminsCanCreateLists.into());
    }

    let id: i32 = sqlx::query_scalar!(
        "INSERT INTO LISTS (name, description) VALUES ($1, $2) RETURNING id",
        create_list.name,
        create_list.description
    )
    .fetch_one(&state.db_connection_pool)
    .await?;

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

pub async fn send_email_to_list(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Json(_payload): Json<serde_json::Value>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_from_list(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Path(_id): Path<String>,
    Json(_payload): Json<serde_json::Value>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn add_to_list(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Path(_id): Path<String>,
    Json(_payload): Json<serde_json::Value>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_list(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Path(_id): Path<String>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_list_permissions(State(_state): State<Arc<AppState>>, _user: User) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn add_list_permissions(State(_state): State<Arc<AppState>>, _user: User) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn delete_list_permissions(
    State(_state): State<Arc<AppState>>,
    _user: User,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
