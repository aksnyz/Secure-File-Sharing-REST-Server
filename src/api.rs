// 1. IMPORTS
use axum::{
    extract::{Multipart, Path, State, Query},
    http::{header, HeaderMap, StatusCode},
    Json,
    response::{IntoResponse, Response},
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


//DATA STRUCT

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

//TOKEN VERIFICATION
fn verify_token(token: &str) -> Option<String> {
    let key = DecodingKey::from_secret("moj_sekretny_klucz".as_ref());
    let validation = Validation::default();

    match decode::<Claims>(token, &key, &validation) {
        Ok(data) => Some(data.claims.sub),
        Err(_) => None,
    }
}

//REGISTER
pub async fn register_user(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response(),
    };

    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&payload.username)
        .bind(&password_hash)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "User registered successfully").into_response(),
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint failed") {
                (StatusCode::CONFLICT, "Username already exists").into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
            }
        }
    }
}

//LOGIN
pub async fn login_user(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    let user_query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&pool)
        .await;

    let user = match user_query {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let parsed_hash = match argon2::PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hash error").into_response(),
    };

    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).is_err() {
        return (StatusCode::UNAUTHORIZED, "Invalid password").into_response();
    }

    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user.username,
        exp: expiration as usize,
    };

    let key = EncodingKey::from_secret("moj_sekretny_klucz".as_ref());
    let token = encode(&Header::default(), &claims, &key).unwrap();

    (StatusCode::OK, Json(LoginResponse { token })).into_response()
}

//UPLOADING FILES
pub async fn upload_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let username = match verify_token(token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    };

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    let user_id = match user {
        Some(u) => u.id.unwrap(),
        None => return (StatusCode::UNAUTHORIZED, "User not found").into_response(),
    };

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.file_name().unwrap_or("unknown").to_string();
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.is_empty() { continue; }

        let file_path = format!("uploads/{}", name);
        if let Err(_) = tokio::fs::write(&file_path, &data).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file to disk").into_response();
        }

        let _ = sqlx::query("INSERT INTO files (owner_id, name, disk_path, visibility) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(&name)
            .bind(&file_path)
            .bind("private")
            .execute(&pool)
            .await;
    }

    (StatusCode::OK, "File uploaded successfully").into_response()
}

//FILE LIST
pub async fn list_files(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json("Missing token")).into_response(),
    };

    let username = match verify_token(token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json("Invalid token")).into_response(),
    };

    let user_query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&pool)
        .await;

    let user = match user_query {
        Ok(Some(u)) => u,
        _ => return (StatusCode::UNAUTHORIZED, Json("User not found")).into_response(),
    };

    let files_result = sqlx::query_as::<_, FileRecord>("SELECT * FROM files WHERE owner_id = ?")
        .bind(user.id)
        .fetch_all(&pool)
        .await;

    match files_result {
        Ok(files) => (StatusCode::OK, Json(files)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json("Database error")).into_response(),
    }
}

//DOWLOAD FILES
pub async fn download_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    Path(file_id): Path<i32>,
    query: Query<std::collections::HashMap<String, String>>,
) -> Response {
    let token_from_header = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let token_from_query = query.get("token").map(|s| s.as_str());

    let token = match token_from_header.or(token_from_query) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response().into_response(),
    };

    let username = match verify_token(token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response().into_response(),
    };

    let user_query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&pool)
        .await;

    let user = match user_query {
        Ok(Some(u)) => u,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "User not found").into_response().into_response(),
    };
    let user_id = user.id.unwrap();

    let file_record_query = sqlx::query_as::<_, FileRecord>("SELECT * FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_optional(&pool)
        .await;

    let file_record = match file_record_query {
        Ok(Some(f)) => f,
        _ => return (StatusCode::NOT_FOUND, "File not found").into_response().into_response(),
    };

    let is_owner = file_record.owner_id == user_id;
    let is_public = file_record.visibility == "public";

    if !is_owner && !is_public {
        return (StatusCode::FORBIDDEN, "Access denied.").into_response().into_response();
    }

    let file_data = match tokio::fs::read(&file_record.disk_path).await {
        Ok(data) => data,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file from disk").into_response().into_response(),
    };

    let filename_header = format!("attachment; filename=\"{}\"", file_record.name);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, filename_header)
        .body(file_data.into())
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response().into_response())
}