
use axum::{
    extract::{Multipart, State},
    http::{header, HeaderMap, StatusCode},
    Json,
    response::IntoResponse,
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
use crate::models::User;
use std::path::Path; // To handle file paths

//DATA STRUCTURES

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
    sub: String,  // Subject (username)
    exp: usize,   // Expiration time
}

//HELPER: VERIFY TOKEN
// Checks if the token is valid and returns the username
fn verify_token(token: &str) -> Option<String> {
    let key = DecodingKey::from_secret("moj_sekretny_klucz".as_ref());
    let validation = Validation::default();

    match decode::<Claims>(token, &key, &validation) {
        Ok(data) => Some(data.claims.sub),
        Err(_) => None,
    }
}

//REGISTRATION

pub async fn register_user(
    State(pool): State<Pool<Sqlite>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    // 1. Hash the password securely
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response(),
    };

    // 2. Insert into database
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
    // 1. Find user in DB
    let user_query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&pool)
        .await;

    let user = match user_query {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    // 2. Verify password
    let parsed_hash = match argon2::PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hash error").into_response(),
    };

    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).is_err() {
        return (StatusCode::UNAUTHORIZED, "Invalid password").into_response();
    }

    // 3. Generate JWT Token
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

//FILE UPLOAD

pub async fn upload_file(
    State(pool): State<Pool<Sqlite>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // 1. Extract and Verify Token from Header
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

    // 2. Get User ID from DB (needed to link file to owner)
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    let user_id = match user {
        Some(u) => u.id.unwrap(),
        None => return (StatusCode::UNAUTHORIZED, "User not found").into_response(),
    };

    // 3. Process the uploaded file
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.file_name().unwrap_or("unknown").to_string();

        // We read the raw bytes of the file
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.is_empty() { continue; }

        // Save to disk (e.g., ./uploads/filename.txt)
        // Warning: In production, we should use UUIDs to prevent overwriting!
        let file_path = format!("uploads/{}", name);

        if let Err(_) = tokio::fs::write(&file_path, &data).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file to disk").into_response();
        }

        // 4. Save metadata to Database
        let _ = sqlx::query("INSERT INTO files (owner_id, name, disk_path, visibility) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(&name)
            .bind(&file_path)
            .bind("private") // Default is private
            .execute(&pool)
            .await;
    }

    (StatusCode::OK, "File uploaded successfully").into_response()
}
