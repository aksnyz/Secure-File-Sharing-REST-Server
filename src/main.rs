mod models;
mod db;
mod api;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
// NEW IMPORT: Tower-http for serving static files
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    println!("Starting Secure File Sharing Server...");

    // 1. Initialize Database Connection
    // Requirement: Database Integration
    let pool = db::init_db().await;

    // 2. Configure Routes (REST API Endpoints)
    // Requirement: Suggested REST Endpoints
    let app = Router::new()
        .fallback_service(ServeDir::new("static"))

        //register and login
        .route("/register", post(api::register_user))
        .route("/login", post(api::login_user))

        .route("/file/upload", post(api::upload_file))
        .route("/file/list", get(api::list_files))
        .route("/file/download/:file_id", get(api::download_file))

        .with_state(pool);

    // 3. Start the HTTP Server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
// The root_handler function is no longer needed since ServeDir handles the '/' route.