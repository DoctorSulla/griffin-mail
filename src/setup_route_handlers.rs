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

const ADMIN_PERMISSIONS: [&str; 4] = [
    "manage_list",
    "manage_recipient",
    "change_permission",
    "manage_media",
];

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
            HAVING COUNT(DISTINCT permission) = $2
        )",
    )
    .bind(ADMIN_PERMISSIONS)
    .bind(ADMIN_PERMISSIONS.len() as i64)
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
    .bind(ADMIN_PERMISSIONS)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AwsConfig, Config, DatabaseConfig, MediaConfig, RuntimeEnvironment, ServerConfig,
        SmtpConfig,
    };
    use aws_config::{BehaviorVersion, Region};
    use lettre::SmtpTransport;
    use sqlx::PgPool;
    use tokio::sync::Semaphore;

    async fn test_state(pool: PgPool) -> Arc<AppState> {
        let aws = AwsConfig {
            region: "eu-west-1".to_string(),
            profile_name: "roles_anywhere".to_string(),
        };
        let aws_sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws.region.clone()))
            .profile_name(&aws.profile_name)
            .load()
            .await;

        Arc::new(AppState {
            db_connection_pool: pool,
            email_connection_pool: SmtpTransport::builder_dangerous("localhost").build(),
            config: Config {
                environment: RuntimeEnvironment::Test,
                server: ServerConfig {
                    port: 0,
                    request_timeout: 5,
                    max_unsuccessful_login_attempts: 10,
                    session_length_in_days: 1,
                    google_client_id: String::new(),
                    server_url: String::new(),
                    hmac_secret: None,
                    email_tld: String::from("tld.com"),
                    no_reply_email_prefix: String::from("no-reply"),
                    registration_email_prefix: String::from("registration"),
                },
                database: DatabaseConfig {
                    pool_size: 1,
                    username: "test".to_string(),
                    password: Some("test".to_string()),
                    connection_url: "localhost/test".to_string(),
                },
                email: SmtpConfig {
                    server_url: "localhost".to_string(),
                    username: "test".to_string(),
                    password: Some("test".to_string()),
                    pool_size: 1,
                    send_emails: false,
                },
                aws,
                media: MediaConfig {
                    bucket: "test-bucket".to_string(),
                    prefix: "media/".to_string(),
                    public_url: "https://media.example.com".to_string(),
                    max_upload_size_bytes: 10485760,
                    upload_success_redirect: "http://localhost:3000/uploadSuccess".to_string(),
                },
            },
            aws_sdk_config,
            email_token_bucket: Semaphore::new(1),
        })
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_administrator_grants_all_admin_permissions_including_manage_media(
        pool: PgPool,
    ) {
        let state = test_state(pool.clone()).await;

        assert!(!administrator_exists(&pool).await.unwrap());

        let result = create_administrator(
            State(state),
            Json(RegistrationDetails {
                username: "adminuser".to_string(),
                email: "admin@example.com".to_string(),
                password: "password123".to_string(),
                confirm_password: "password123".to_string(),
                sub: None,
            }),
        )
        .await;
        assert!(result.is_ok());

        assert!(administrator_exists(&pool).await.unwrap());

        let permissions = sqlx::query_scalar::<_, String>(
            "SELECT permission FROM global_user_permissions
             WHERE user_email = 'admin@example.com'
             ORDER BY permission",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(
            permissions,
            vec![
                "change_permission".to_string(),
                "manage_list".to_string(),
                "manage_media".to_string(),
                "manage_recipient".to_string(),
            ]
        );
    }
}
