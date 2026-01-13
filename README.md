# Secure File Sharing REST Server

This is a secure, RESTful file sharing service written in Rust using the Axum framework and SQLite database. It allows users to upload files, manage permissions (share/revoke), and make files public.

## Features 

* **User Authentication:** Secure registration and login with JWT tokens and Argon2 password hashing.
* **File Management:** Upload and download files securely.
* **Access Control:** * **Private:** Only the owner can access.
    * **Shared:** Specific users can be granted access.
    * **Public:** Anyone with a link can download without logging in.
* **Permissions:** Owners can share files with other users and revoke access at any time.
* **Web Interface:** A clean, pink-themed Web UI to interact with the API.

## Setup & Installation

1.  **Prerequisites:** Ensure you have Rust and Cargo installed.
2.  **Clone/Download** the repository.
3.  **Run the server:**
    ```bash
    cargo run
    ```
    The server will automatically create the SQLite database (`file_share.db`) and necessary tables on the first run.

4.  **Access the App:**
    Open your browser and navigate to:
    `http://127.0.0.1:3000`

## API Endpoints 

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/register` | Register a new user account |
| `POST` | `/login` | Authenticate and receive a JWT token |
| `GET` | `/token/refresh` | Refresh an expired access token |
| `POST` | `/file/upload` | Upload a file (Multipart form) |
| `GET` | `/file/list` | List all accessible files |
| `GET` | `/file/download/{id}` | Download a file (requires token) |
| `POST` | `/file/share` | Share a file with another user |
| `DELETE` | `/file/{id}/share/{user}` | Revoke a user's permission |
| `POST` | `/file/{id}/make_public` | Make a file public |
| `GET` | `/file/public/{id}` | Download a public file (no token needed) |

## Technologies Used 

* **Language:** Rust 
* **Framework:** Axum
* **Database:** SQLite (with SQLx)
* **Security:** Argon2 (hashing), JSON Web Tokens (JWT)
* **Frontend:** HTML/CSS/JS (Single Page Application)

---
*Project created for the Programming in Rust Capstone Assessment.*