use sqlx::{Pool, Sqlite};

// function to initialize the database tables on server startup
pub async fn init_db(pool: &Pool<Sqlite>) {
    // 1. users table
    // stores unique usernames and their securely hashed passwords
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );"
    )
        .execute(pool)
        .await
        .expect("failed to create users table");

    // 2. files table
    // stores metadata about uploaded files including who owns them
    // the visibility column defaults to private unless changed
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            disk_path TEXT NOT NULL,
            visibility TEXT DEFAULT 'private', 
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );"
    )
        .execute(pool)
        .await
        .expect("failed to create files table");

    // 3. permissions table
    // this is a junction table connecting files to users
    // it allows sharing a specific file with a specific user
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS file_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(file_id, user_id),
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );"
    )
        .execute(pool)
        .await
        .expect("failed to create permissions table");
}