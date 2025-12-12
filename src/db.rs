use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};

/// Initializes the database connection pool.
/// Creates the database file if it doesn't exist.
pub async fn init_db() -> Pool<Sqlite> {
    // Connection string for SQLite. 'mode=rwc' allows reading, writing, and creating.
    let database_url = "sqlite://file_share.db?mode=rwc";

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .expect("Failed to connect to the database");

    // Ensure all tables exist before starting the server
    create_tables(&pool).await;

    pool
}

/// Runs SQL migrations to create necessary tables.
/// Requirement: Database Integration (Persistent schema) [cite: 67, 77]
async fn create_tables(pool: &Pool<Sqlite>) {
    // 1. Users Table
    // Stores credentials securely.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );"
    )
        .execute(pool)
        .await
        .expect("Failed to create users table");

    // 2. Files Table
    // Stores file metadata and ownership info.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            disk_path TEXT NOT NULL,
            visibility TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );"
    )
        .execute(pool)
        .await
        .expect("Failed to create files table");

    // 3. Permissions Table
    // Handles sharing logic (Many-to-Many relationship).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS file_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );"
    )
        .execute(pool)
        .await
        .expect("Failed to create permissions table");

    println!("Database schema initialized successfully.");
}