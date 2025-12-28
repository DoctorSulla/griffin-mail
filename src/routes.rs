use crate::{AppState, default_route_handlers, email_route_handlers};
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use std::sync::Arc;

pub fn get_protected_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/account/verifyEmail",
            post(default_route_handlers::verify_email),
        )
        .route(
            "/account/changePassword",
            patch(default_route_handlers::change_password),
        )
        .route("/account/profile", get(default_route_handlers::get_profile))
        .route("/account/logout", get(default_route_handlers::logout))
        .route(
            "/account/verificationEmail",
            get(default_route_handlers::resend_verification_email),
        )
}

pub fn get_email_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/email/lists", post(email_route_handlers::create_list))
        .route("/email/lists", get(email_route_handlers::get_lists))
        .route(
            "/email/lists/{id}",
            get(email_route_handlers::get_list_by_id),
        )
        .route(
            "/email/lists/{id}",
            post(email_route_handlers::send_email_to_list),
        )
        .route(
            "/email/lists/{id}/recipients",
            delete(email_route_handlers::delete_from_list),
        )
        .route(
            "/email/lists/{id}/recipients",
            post(email_route_handlers::add_to_list),
        )
        .route(
            "/email/lists/{id}",
            delete(email_route_handlers::delete_list),
        )
        .route(
            "/email/lists/{id}/permissions",
            get(email_route_handlers::get_list_permissions),
        )
        .route(
            "/email/lists/{id}/permissions",
            post(email_route_handlers::add_list_permissions),
        )
        .route(
            "/email/lists/{id}/permissions",
            delete(email_route_handlers::delete_list_permissions),
        )
}

pub fn get_open_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/account/register", post(default_route_handlers::register))
        .route("/account/login", post(default_route_handlers::login))
        .route(
            "/account/login/google",
            post(default_route_handlers::google_login),
        )
        .route(
            "/account/resetPassword",
            post(default_route_handlers::password_reset_initiate),
        )
        .route(
            "/account/resetPassword",
            patch(default_route_handlers::password_reset_complete),
        )
        .route("/healthCheck", get(default_route_handlers::health_check))
        .route("/nonce", get(default_route_handlers::get_nonce))
}
