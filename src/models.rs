use serde::{Deserialize, Serialize};
use sqlx::FromRow;

//USER MODEL
// Represents a registered user in the database.
// Requirement: User Registration & Login [cite: 57, 58]
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct User {
    pub id: Option<i32>,          // Auto-incremented ID
    pub username: String,         // Unique username
    pub password_hash: String,    // Securely hashed password (Argon2)
}

//FILE MODEL
// Represents a file uploaded to the server.
// Requirement: File Upload with metadata [cite: 60]
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct FileRecord {
    pub id: Option<i32>,
    pub owner_id: i32,            // Foreign key linking to User
    pub name: String,             // Original filename
    pub disk_path: String,        // Path where the file is stored physically
    pub visibility: String,       // 'private', 'public', or 'shared'
}