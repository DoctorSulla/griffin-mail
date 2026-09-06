use crate::{
    AppState,
    default_route_handlers::{
        ApiResponse, AppError, ErrorList, RegistrationDetails, ResponseType,
        validations::{validate_email, validate_password, validate_username},
    },
    utilities::hash_password,
};
use axum::{Json, extract::State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{Level, event};

const ADMIN_PERMISSIONS: [&str; 3] = ["manage_list", "manage_recipient", "change_permission"];

#[derive(Debug, Serialize, Deserialize)]
pub struct SetupStatus {
    pub needs_admin: bool,
}

async fn administrator_exists(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT user_email
            FROM global_user_permissions
            WHERE permission = ANY($1)
            GROUP BY user_email
            HAVING COUNT(DISTINCT permission) = 3
        )",
    )
    .bind(&ADMIN_PERMISSIONS)
    .fetch_one(executor)
    .await
}

pub async fn get_setup_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SetupStatus>, AppError> {
    let has_admin = administrator_exists(&state.db_connection_pool).await?;
    Ok(Json(SetupStatus {
        needs_admin: !has_admin,
    }))
}

pub async fn create_administrator(
    State(state): State<Arc<AppState>>,
    Json(details): Json<RegistrationDetails>,
) -> Result<Json<ApiResponse>, AppError> {
    validate_email(&details.email)?;
    validate_username(&details.username)?;
    validate_password(&details.password)?;
    if details.password != details.confirm_password {
        return Err(ErrorList::NonMatchingPasswords.into());
    }

    // Avoid an expensive password hash once setup has already completed.
    if administrator_exists(&state.db_connection_pool).await? {
        event!(
            Level::WARN,
            email = %details.email,
            "Rejected administrator registration because setup is complete"
        );
        return Err(ErrorList::AdministratorAlreadyConfigured.into());
    }

    let hashed_password = hash_password(&details.password);
    let mut transaction = state.db_connection_pool.begin().await?;

    // Serialize setup with every insert/delete on this table so the
    // administrator check remains true until this transaction commits.
    sqlx::query("LOCK TABLE global_user_permissions IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await?;

    if administrator_exists(&mut *transaction).await? {
        event!(
            Level::WARN,
            email = %details.email,
            "Rejected concurrent administrator registration because setup completed"
        );
        return Err(ErrorList::AdministratorAlreadyConfigured.into());
    }

    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
        .bind(&details.username)
        .fetch_one(&mut *transaction)
        .await?
    {
        return Err(ErrorList::UsernameAlreadyRegistered.into());
    }

    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(&details.email)
        .fetch_one(&mut *transaction)
        .await?
    {
        return Err(ErrorList::EmailAlreadyRegistered.into());
    }

    sqlx::query(
        "INSERT INTO users (
            email, username, hashed_password, registration_ts, identity_provider
        ) VALUES ($1, $2, $3, $4, 'default')",
    )
    .bind(&details.email)
    .bind(&details.username)
    .bind(hashed_password)
    .bind(Utc::now().timestamp())
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO global_user_permissions (user_email, permission)
         SELECT $1, permission
         FROM global_permissions
         WHERE permission = ANY($2)",
    )
    .bind(&details.email)
    .bind(&ADMIN_PERMISSIONS)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    event!(
        Level::INFO,
        email = %details.email,
        username = %details.username,
        permissions = ?ADMIN_PERMISSIONS,
        "Administrator account created"
    );

    Ok(Json(ApiResponse {
        response_type: ResponseType::SetupSuccess,
        message: "Administrator account created".to_string(),
    }))
}
