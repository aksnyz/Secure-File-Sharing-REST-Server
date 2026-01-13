use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// this struct represents a single user in our database
#[derive(Debug, Serialize, FromRow)]
pub struct User {
    pub id: Option<i32>,
    pub username: String,
    // store hash not the real password for security
    pub password_hash: String,
}

#[derive(Debug, Serialize, FromRow)]
pub struct FileRecord {
    pub id: i32,
    pub owner_id: i32,
    pub name: String,
    // path where the file is actually saved on the server hard drive
    pub disk_path: String,
    // determines if file is private or public
    pub visibility: String,
}