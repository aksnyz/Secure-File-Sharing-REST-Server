use axum::{
    extract::{Multipart, Path, State, Query},
    http::{header, HeaderMap, StatusCode},
    Json,
    response::{IntoResponse, Response},
    body::Body,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2,
    PasswordVerifier
};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use crate::models::{User, FileRecord};

// --- data structures (payloads) ---

// structure for login and registration requests
#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

// response sent back to client upon successful login
#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

// jwt claims: data embedded inside the token
// sub = subject (username), exp = expiration time
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// payload for sharing a file
#[derive(Deserialize)]
pub struct ShareRequest {
    pub file_id: i32,
    pub target_username: String,
}

// --- helper: standard token verification ---
// this function checks if the token is valid and not expired
// used for most endpoints (upload, download, list)
fn verify_token(token: &str) -> Option<String> {
    let key = DecodingKey::from_secret("my_secret_key".as_ref());
    // default validation checks expiration date automatically
    let validation = Validation::default();

    match decode::<Claims>(token, &key, &validation) {
        Ok(data) => Some(data.claims.sub), // returns username if valid
        Err(_) => None,
    }
}

// --- 1. register user ---
// creates a new user account
pub async fn register_user(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    // generate a random salt for password hashing
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // hash the password using argon2 algorithm
    // never store plain text passwords in the database
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "failed to hash password").into_response(),
    };

    // insert the new user into sqlite
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&payload.username)
        .bind(&password_hash)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "user registered successfully").into_response(),
        Err(_) => (StatusCode::CONFLICT, "username already exists").into_response(),
    }
}

// --- 2. login user ---
// verifies credentials and issues a jwt access token
pub async fn login_user(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    // try to find the user in the database
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    if let Some(u) = user {
        // verify the provided password against the stored hash
        let parsed_hash = argon2::PasswordHash::new(&u.password_hash).unwrap();
        if Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).is_ok() {

            // password matches! generate a token valid for 24 hours
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("valid timestamp")
                .timestamp();

            let claims = Claims { sub: u.username, exp: expiration as usize };
            let key = EncodingKey::from_secret("my_secret_key".as_ref());
            let token = encode(&Header::default(), &claims, &key).unwrap();

            return (StatusCode::OK, Json(LoginResponse { token })).into_response();
        }
    }
    // if user not found or password mismatch
    (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
}

// --- 3. refresh token ---
// allows renewing the session even if the token has expired
pub async fn refresh_token(headers: HeaderMap) -> impl IntoResponse {
    // extract the bearer token from the header
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing token").into_response(),
    };

    // configure validation to ignore expiration date
    let key = DecodingKey::from_secret("my_secret_key".as_ref());
    let mut validation = Validation::default();
    validation.validate_exp = false; // <--- allows expired tokens

    let username = match decode::<Claims>(token, &key, &validation) {
        Ok(data) => data.claims.sub,
        Err(_) => return (StatusCode::UNAUTHORIZED, "invalid token signature").into_response(),
    };

    // generate a brand new token for another 24 hours
    let expiration = Utc::now().checked_add_signed(Duration::hours(24)).unwrap().timestamp();
    let claims = Claims { sub: username, exp: expiration as usize };
    let key_enc = EncodingKey::from_secret("my_secret_key".as_ref());
    let new_token = encode(&Header::default(), &claims, &key_enc).unwrap();

    (StatusCode::OK, Json(LoginResponse { token: new_token })).into_response()
}

// --- 4. upload file ---
// handles multipart form data upload and saves file to disk
pub async fn upload_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // verify authentication first
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let username = match auth_header.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    // get user id from database
    let user_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    // process each part of the upload stream
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.file_name().unwrap_or("unknown").to_string();
        let data = field.bytes().await.unwrap_or_default();

        if data.is_empty() { continue; }

        // save to uploads directory
        let file_path = format!("uploads/{}", name);
        if tokio::fs::write(&file_path, &data).await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to save file to disk").into_response();
        }

        // record file in database (private by default)
        sqlx::query("INSERT INTO files (owner_id, name, disk_path, visibility) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(&name)
            .bind(&file_path)
            .bind("private")
            .execute(&pool)
            .await
            .unwrap();
    }

    (StatusCode::OK, "file uploaded successfully").into_response()
}

// --- 5. list files ---
// returns a list of files accessible to the user
pub async fn list_files(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let username = match auth_header.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    let user_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    // fetch files where user is owner OR user has permission
    let files = sqlx::query_as::<_, FileRecord>(
        "SELECT * FROM files WHERE owner_id = ? OR id IN (SELECT file_id FROM file_permissions WHERE user_id = ?)"
    )
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    (StatusCode::OK, Json(files)).into_response()
}

// --- 6. share file ---
// grants access permission to another user for a specific file
pub async fn share_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    Json(payload): Json<ShareRequest>,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let username = match auth_header.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    let owner_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    // ensure user owns the file before sharing
    // ::<_, i32> is required for sqlite type inference
    let file_exists: bool = sqlx::query_scalar::<_, i32>("SELECT 1 FROM files WHERE id = ? AND owner_id = ?")
        .bind(payload.file_id)
        .bind(owner_id)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some();

    if !file_exists {
        return (StatusCode::FORBIDDEN, "you are not the owner or file not found").into_response();
    }

    // find target user id
    let target_user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&payload.target_username)
        .fetch_optional(&pool)
        .await
        .unwrap();

    if let Some(target_id) = target_user_id {
        // insert permission record
        sqlx::query("INSERT OR IGNORE INTO file_permissions (file_id, user_id) VALUES (?, ?)")
            .bind(payload.file_id)
            .bind(target_id)
            .execute(&pool)
            .await
            .unwrap();
        (StatusCode::OK, "file shared successfully").into_response()
    } else {
        (StatusCode::NOT_FOUND, "target user not found").into_response()
    }
}

// --- 7. revoke permission ---
// removes access for a specific user
pub async fn revoke_permission(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    Path((file_id, target_username)): Path<(i32, String)>,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let username = match auth_header.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    let owner_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    // verify ownership
    let is_owner: bool = sqlx::query_scalar::<_, i32>("SELECT 1 FROM files WHERE id = ? AND owner_id = ?")
        .bind(file_id)
        .bind(owner_id)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some();

    if !is_owner {
        return (StatusCode::FORBIDDEN, "only the owner can revoke permissions").into_response();
    }

    let target_user_id: Option<i32> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&target_username)
        .fetch_optional(&pool)
        .await
        .unwrap();

    if let Some(uid) = target_user_id {
        // delete the permission row
        sqlx::query("DELETE FROM file_permissions WHERE file_id = ? AND user_id = ?")
            .bind(file_id)
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        (StatusCode::OK, "permission revoked").into_response()
    } else {
        (StatusCode::NOT_FOUND, "user not found").into_response()
    }
}

// --- 8. make public ---
// changes file visibility to 'public' so anyone can download it
pub async fn make_public(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    Path(file_id): Path<i32>,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let username = match auth_header.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "invalid token").into_response(),
    };

    let owner_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    // update the visibility column
    let result = sqlx::query("UPDATE files SET visibility = 'public' WHERE id = ? AND owner_id = ?")
        .bind(file_id)
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();

    if result.rows_affected() > 0 {
        (StatusCode::OK, "file is now public").into_response()
    } else {
        (StatusCode::FORBIDDEN, "not owner").into_response()
    }
}

// --- 9. download file (protected) ---
// serves file content if the user is owner, shared, or file is public
pub async fn download_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    Path(file_id): Path<i32>,
    query: Query<std::collections::HashMap<String, String>>,
) -> Response {
    // support token in header OR in query param (for browser downloads)
    let token_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token_query = query.get("token").map(|s| s.as_str());
    let token = token_header.or(token_query);

    let username = match token.and_then(verify_token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response().into_response(),
    };

    let user_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();

    let file: Option<FileRecord> = sqlx::query_as("SELECT * FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_optional(&pool)
        .await
        .unwrap();

    let file_record = match file {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "file not found").into_response().into_response(),
    };

    // access check logic:
    // 1. am i the owner?
    // 2. is the file public?
    // 3. do i have explicit shared permission?
    let has_permission = file_record.owner_id == user_id
        || file_record.visibility == "public"
        || sqlx::query_scalar::<_, i32>("SELECT 1 FROM file_permissions WHERE file_id = ? AND user_id = ?")
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&pool)
        .await.unwrap().is_some();

    if !has_permission {
        return (StatusCode::FORBIDDEN, "access denied").into_response().into_response();
    }

    serve_file_from_disk(&file_record.disk_path, &file_record.name).await
}

// --- 10. download public file (no token) ---
// public endpoint for downloading files without logging in
pub async fn download_public_file(
    State(pool): State<Pool<Sqlite>>,
    Path(file_id): Path<i32>,
) -> Response {
    let file: Option<FileRecord> = sqlx::query_as("SELECT * FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_optional(&pool)
        .await
        .unwrap();

    let file_record = match file {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "file not found").into_response().into_response(),
    };

    // strict check: file MUST be public
    if file_record.visibility != "public" {
        return (StatusCode::FORBIDDEN, "file is private").into_response().into_response();
    }

    serve_file_from_disk(&file_record.disk_path, &file_record.name).await
}

// --- helper: serve file from disk ---
// reads bytes from disk and streams them to the client
async fn serve_file_from_disk(path: &str, name: &str) -> Response {
    match tokio::fs::read(path).await {
        Ok(data) => {
            // set headers to force download
            let disposition = format!("attachment; filename=\"{}\"", name);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_DISPOSITION, disposition)
                .body(Body::from(data))
                .unwrap()
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "failed to read file from disk").into_response().into_response()
    }
}