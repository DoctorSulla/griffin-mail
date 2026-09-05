#![warn(unused_extern_crates)]

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use config::AppState;
use http::StatusCode;
use middleware::ValidateSessionLayer;
use routes::*;
use rust_embed::Embed;
use sqlx::migrate;
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer};
use tracing::{Level, event, span};

use crate::config::RuntimeEnvironment;
use crate::utilities::start_session_cleaner;
pub mod auth;
pub mod config;
pub mod default_route_handlers;
pub mod email_route_handlers;
pub mod middleware;
pub mod routes;
pub mod user;
pub mod utilities;

static NONCE_STORE: LazyLock<Arc<RwLock<HashMap<String, i64>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

#[derive(Embed)]
#[folder = "frontend/build"]
pub struct Asset;

pub async fn start_app() {
    // Start tracing
    tracing_subscriber::FmtSubscriber::builder()
        .with_ansi(true)
        .init();
    let span = span!(Level::INFO, "main_span");
    let _ = span.enter();

    let app_state = get_app_state().await;

    start_session_cleaner(app_state.clone()).await;

    event!(Level::INFO, "Creating tables");

    migrations(app_state.clone())
        .await
        .expect("Couldn't complete migrations");

    let app = get_app(app_state.clone());

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", app_state.config.server.port))
        .await
        .unwrap();
    let _ = axum::serve(listener, app).await;
}

pub fn get_app(state: Arc<AppState>) -> Router {
    let protected_routes = get_protected_routes();
    let open_routes = get_open_routes();
    let email_routes = get_email_routes();

    let app = Router::new()
        .merge(protected_routes)
        .merge(email_routes)
        .layer(ServiceBuilder::new().layer(ValidateSessionLayer::new(state.clone())))
        .merge(open_routes)
        .fallback(serve_frontend)
        .with_state(state.clone())
        .layer(ServiceBuilder::new().layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(state.config.server.request_timeout),
        )));

    if state.config.environment == RuntimeEnvironment::Development {
        app.layer(ServiceBuilder::new().layer(CorsLayer::very_permissive()))
    } else {
        app
    }
}

pub async fn get_app_state() -> Arc<AppState> {
    event!(Level::INFO, "Getting config from file");
    let config = config::get_config();

    event!(Level::INFO, "Creating email connection pool");
    let email_connection_pool = config.get_email_pool();

    event!(Level::INFO, "Creating database connection pool");
    let db_connection_pool = config.get_db_pool().await;

    Arc::new(AppState {
        db_connection_pool,
        email_connection_pool,
        config,
    })
}

async fn serve_frontend(request: Request) -> Response {
    let mut path = request.uri().path().trim_start_matches('/').to_string();

    // Default to index.html for root path
    if path.is_empty() {
        path = "index.html".to_string();
    } else {
        // Check if the last segment has an extension
        let last_segment = path.split('/').next_back().unwrap_or("");
        let has_extension = last_segment.contains('.') && !last_segment.ends_with('.');

        // If no extension, treat as directory and append index.html
        if !has_extension {
            if !path.ends_with('/') {
                path.push('/');
            }
            path.push_str("index.html");
        }
    }

    event!(Level::DEBUG, "Serving frontend file: {}", path);

    if let Some(asset) = Asset::get(&path) {
        let mime_type = mime_guess::from_path(&path).first_or_octet_stream();

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .body(Body::from(asset.data))
            .unwrap_or("<h1>404 - Not found</h1>".into_response())
    } else {
        event!(Level::WARN, "Frontend file not found: {}", path);
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from("<h1>404 - Not found</h1>"))
            .unwrap_or("<h1>404 - Not found</h1>".into_response())
    }
}

pub async fn migrations(state: Arc<AppState>) -> Result<(), anyhow::Error> {
    migrate!().run(&state.db_connection_pool).await?;
    Ok(())
}
