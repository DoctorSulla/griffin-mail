use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;

use crate::{config::AppState, user::User};

pub async fn get_lists(State(_state): State<Arc<AppState>>, _user: User) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn create_list(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Json(_payload): Json<serde_json::Value>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_list_by_id(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Path(_id): Path<String>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
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
