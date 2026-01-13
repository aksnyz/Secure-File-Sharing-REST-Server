use axum::{
    routing::{get, post, delete},
    Router,
};
use std::net::SocketAddr;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::services::ServeDir;

// import modules so we can use functions from them
mod api;
mod db;
mod models;

#[tokio::main]
async fn main() {
    // 1. database setup
    // get the database url from environment or default to a local file
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:file_share.db".to_string());

    // create a connection pool to manage database connections efficiently
    // we limit max connections to avoid overloading
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to database");

    // run table initialization script on startup
    db::init_db(&pool).await;

    println!("starting secure file sharing server...");

    // 2. router configuration
    // this defines which url triggers which function
    let app = Router::new()
        // serve static files (html/css/js) from the static folder
        .fallback_service(ServeDir::new("static"))

        // --- authentication routes ---
        .route("/register", post(api::register_user))
        .route("/login", post(api::login_user))
        .route("/token/refresh", get(api::refresh_token))

        // --- file operations ---
        .route("/file/upload", post(api::upload_file))
        .route("/file/list", get(api::list_files))
        // :file_id is a dynamic parameter in the url
        .route("/file/download/:file_id", get(api::download_file))

        // --- sharing and permissions ---
        .route("/file/share", post(api::share_file))
        .route("/file/:file_id/share/:username", delete(api::revoke_permission))

        // --- public access ---
        .route("/file/:file_id/make_public", post(api::make_public))
        .route("/file/public/:file_id", get(api::download_public_file))

        // inject the database pool into all routes so they can use it
        .with_state(pool);

    // 3. start the server
    // we listen on localhost port 3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}