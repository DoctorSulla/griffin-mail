use super::*;
use crate::config::{
    AwsConfig, Config, DatabaseConfig, MediaConfig, RuntimeEnvironment, ServerConfig, SmtpConfig,
};
use aws_config::{BehaviorVersion, Region};
use lettre::SmtpTransport;
use sqlx::{PgPool, Row};
use tokio::sync::Semaphore;

const TEST_HMAC_SECRET: &str = "test-secret-key-12345";

fn test_user(email: &str) -> User {
    User {
        username: email.to_string(),
        email: email.to_string(),
        email_verified: true,
        hashed_password: None,
        auth_level: "user".to_string(),
        login_attempts: 0,
        registration_ts: 0,
        identity_provider: "test".to_string(),
    }
}

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
                hmac_secret: Some(TEST_HMAC_SECRET.to_string()),
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

async fn insert_user(pool: &PgPool, email: &str) {
    sqlx::query(
        "INSERT INTO users (
                email, email_verified, username, login_attempts, auth_level,
                registration_ts, identity_provider
             ) VALUES ($1, true, $1, 0, 'user', 0, 'test')",
    )
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_list(pool: &PgPool, name: &str) -> i32 {
    sqlx::query("INSERT INTO lists (name, description) VALUES ($1, '') RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
        .get("id")
}

async fn app_error_message(error: AppError) -> String {
    let response = error.into_response();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice::<crate::default_route_handlers::ApiResponse>(&body)
        .unwrap()
        .message
}

async fn expect_ok<T>(result: Result<T, AppError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!(
            "unexpected application error: {}",
            app_error_message(error).await
        ),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn list_permissions_match_user_list_and_capability(pool: PgPool) {
    insert_user(&pool, "alice@example.com").await;
    insert_user(&pool, "bob@example.com").await;
    let first_list = insert_list(&pool, "first").await;
    let second_list = insert_list(&pool, "second").await;
    sqlx::query(
        "INSERT INTO list_user_permissions (list_id, user_email, permission)
             VALUES ($1, 'alice@example.com', 'write')",
    )
    .bind(first_list)
    .execute(&pool)
    .await
    .unwrap();

    let state = test_state(pool).await;
    let alice = test_user("alice@example.com");
    let bob = test_user("bob@example.com");

    assert!(
        user_has_list_permission(&alice, state.clone(), first_list, ListPermission::Write).await
    );
    assert!(
        !user_has_list_permission(&alice, state.clone(), first_list, ListPermission::Send).await
    );
    assert!(
        !user_has_list_permission(&alice, state.clone(), second_list, ListPermission::Write).await
    );
    assert!(!user_has_list_permission(&bob, state, first_list, ListPermission::Write).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn global_permissions_match_user_and_capability(pool: PgPool) {
    insert_user(&pool, "alice@example.com").await;
    insert_user(&pool, "bob@example.com").await;
    sqlx::query(
        "INSERT INTO global_user_permissions (user_email, permission)
             VALUES ('alice@example.com', 'manage_list')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let state = test_state(pool).await;
    let alice = test_user("alice@example.com");
    let bob = test_user("bob@example.com");

    assert!(user_has_global_permission(&alice, state.clone(), GlobalPermission::ManageList).await);
    assert!(
        !user_has_global_permission(&alice, state.clone(), GlobalPermission::ManageRecipient).await
    );
    assert!(!user_has_global_permission(&bob, state, GlobalPermission::ManageList).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_list_requires_manage_list_and_grants_creator_all_permissions(pool: PgPool) {
    insert_user(&pool, "creator@example.com").await;
    let user = test_user("creator@example.com");
    let state = test_state(pool.clone()).await;

    let denied = create_list(
        State(state.clone()),
        VerifiedEmailUser(test_user("creator@example.com")),
        Json(NewList {
            name: "denied".to_string(),
            description: String::new(),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        app_error_message(denied).await,
        ErrorList::NoManageListPermission.to_string()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lists")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    sqlx::query(
        "INSERT INTO global_user_permissions (user_email, permission)
             VALUES ('creator@example.com', 'manage_list')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let Json(created) = expect_ok(
        create_list(
            State(state),
            VerifiedEmailUser(user),
            Json(NewList {
                name: "allowed".to_string(),
                description: "description".to_string(),
            }),
        )
        .await,
    )
    .await;

    let permissions = sqlx::query_scalar::<_, String>(
        "SELECT permission FROM list_user_permissions
             WHERE list_id = $1 AND user_email = 'creator@example.com'
             ORDER BY permission",
    )
    .bind(created.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        permissions,
        vec![
            "change_permission".to_string(),
            "read".to_string(),
            "send".to_string(),
            "write".to_string(),
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_visibility_requires_explicit_read_permission(pool: PgPool) {
    insert_user(&pool, "reader@example.com").await;
    let visible_list = insert_list(&pool, "visible").await;
    let hidden_list = insert_list(&pool, "hidden").await;
    sqlx::query(
        "INSERT INTO list_user_permissions (list_id, user_email, permission)
             VALUES
                ($1, 'reader@example.com', 'read'),
                ($2, 'reader@example.com', 'write')",
    )
    .bind(visible_list)
    .bind(hidden_list)
    .execute(&pool)
    .await
    .unwrap();

    let Json(lists) = expect_ok(
        get_lists(
            State(test_state(pool).await),
            VerifiedEmailUser(test_user("reader@example.com")),
        )
        .await,
    )
    .await;

    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].id, visible_list);
}

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

    let result =
        verify_unsubscribe_signature(&unsubscribe_text, &unsubscribe_signature, TEST_HMAC_SECRET);
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

#[tokio::test]
async fn test_max_length_md() {
    let mut long_string = String::with_capacity(100000);
    let mut i = 0;
    while i < 100000 {
        long_string.push_str("a");
        i += 1;
    }
    assert!(
        md_to_html(Json(Markdown {
            markdown: long_string
        }))
        .await
        .is_ok()
    )
}

#[tokio::test]
async fn test_exceeded_max_length_md() {
    let mut long_string = String::with_capacity(100000);
    let mut i = 0;
    while i < 100001 {
        long_string.push_str("a");
        i += 1;
    }
    assert!(
        md_to_html(Json(Markdown {
            markdown: long_string
        }))
        .await
        .is_err()
    )
}

#[test]
fn media_names_must_not_escape_the_media_prefix() {
    assert!(is_valid_media_name("photo.jpg"));
    assert!(is_valid_media_name("photo 1.jpg"));
    assert!(is_valid_media_name("events/2026/photo.jpg"));

    assert!(!is_valid_media_name(""));
    assert!(!is_valid_media_name("../secret.txt"));
    assert!(!is_valid_media_name("events/../photo.jpg"));
    assert!(!is_valid_media_name("./photo.jpg"));
    assert!(!is_valid_media_name("/photo.jpg"));
    assert!(!is_valid_media_name("events//photo.jpg"));
    assert!(!is_valid_media_name("events/"));
}

#[test]
fn media_url_from_key_uses_configured_public_url() {
    let config = MediaConfig {
        bucket: "test-bucket".to_string(),
        prefix: "media/".to_string(),
        public_url: "https://d1pbjdmktpilh0.cloudfront.net/".to_string(),
        max_upload_size_bytes: 10485760,
        upload_success_redirect: "http://localhost:3000/uploadSuccess".to_string(),
    };

    assert_eq!(
        media_url_from_key(&config, "media/photo.jpg").as_deref(),
        Some("https://d1pbjdmktpilh0.cloudfront.net/photo.jpg")
    );
    assert_eq!(
        media_url_from_key(&config, "media/events/my photo (1).jpg").as_deref(),
        Some("https://d1pbjdmktpilh0.cloudfront.net/events/my%20photo%20%281%29.jpg")
    );
    assert_eq!(media_url_from_key(&config, "other/photo.jpg"), None);
    assert_eq!(media_url_from_key(&config, "media/../secret.txt"), None);
    assert_eq!(media_url_from_key(&config, "media/"), None);
}

#[sqlx::test(migrations = "./migrations")]
async fn media_upload_and_delete_require_manage_media_permission(pool: PgPool) {
    insert_user(&pool, "uploader@example.com").await;
    let state = test_state(pool.clone()).await;

    let upload_denied = get_s3_upload_details(
        State(state.clone()),
        VerifiedEmailUser(test_user("uploader@example.com")),
    )
    .await
    .unwrap_err();
    assert_eq!(
        app_error_message(upload_denied).await,
        ErrorList::NoManageMediaPermission.to_string()
    );

    let delete_denied = delete_media(
        State(state.clone()),
        VerifiedEmailUser(test_user("uploader@example.com")),
        Path("photo.jpg".to_string()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        app_error_message(delete_denied).await,
        ErrorList::NoManageMediaPermission.to_string()
    );

    sqlx::query(
        "INSERT INTO global_user_permissions (user_email, permission)
             VALUES ('uploader@example.com', 'manage_media')",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        user_has_global_permission(
            &test_user("uploader@example.com"),
            state.clone(),
            GlobalPermission::ManageMedia,
        )
        .await
    );

    let invalid_name = delete_media(
        State(state),
        VerifiedEmailUser(test_user("uploader@example.com")),
        Path("../secret.txt".to_string()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        app_error_message(invalid_name).await,
        ErrorList::InvalidMediaName.to_string()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn get_user_emails_requires_global_or_list_change_permission(pool: PgPool) {
    insert_user(&pool, "zoe@example.com").await;
    insert_user(&pool, "alice@example.com").await;
    insert_user(&pool, "bob@example.com").await;
    let list_id = insert_list(&pool, "newsletter").await;
    let state = test_state(pool.clone()).await;

    // A user with only list write permission cannot list all user emails.
    sqlx::query(
        "INSERT INTO list_user_permissions (list_id, user_email, permission)
             VALUES ($1, 'alice@example.com', 'write')",
    )
    .bind(list_id)
    .execute(&pool)
    .await
    .unwrap();

    let denied = get_user_emails(
        State(state.clone()),
        VerifiedEmailUser(test_user("alice@example.com")),
    )
    .await
    .unwrap_err();
    assert_eq!(
        app_error_message(denied).await,
        ErrorList::NoChangePermission.to_string()
    );

    // Granting list change_permission allows fetching sorted user emails.
    sqlx::query(
        "INSERT INTO list_user_permissions (list_id, user_email, permission)
             VALUES ($1, 'alice@example.com', 'change_permission')",
    )
    .bind(list_id)
    .execute(&pool)
    .await
    .unwrap();

    let Json(list_manager_emails) = expect_ok(
        get_user_emails(
            State(state.clone()),
            VerifiedEmailUser(test_user("alice@example.com")),
        )
        .await,
    )
    .await;
    assert_eq!(
        list_manager_emails,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "zoe@example.com".to_string(),
        ]
    );

    // Granting global change_permission also allows fetching sorted user emails.
    sqlx::query(
        "INSERT INTO global_user_permissions (user_email, permission)
             VALUES ('bob@example.com', 'change_permission')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let Json(global_manager_emails) = expect_ok(
        get_user_emails(State(state), VerifiedEmailUser(test_user("bob@example.com"))).await,
    )
    .await;
    assert_eq!(
        global_manager_emails,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "zoe@example.com".to_string(),
        ]
    );
}
