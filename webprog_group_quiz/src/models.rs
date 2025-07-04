use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct BugReport {
    pub bug_id: i64,
    pub developer_id: i64,
    pub project_id: i64,
    pub bug_description: String,
    pub bug_severity: String,
    pub report_time: Option<String>, // optional if letting SQLite auto-fill
}

// Used when creating a new bug
#[derive(Debug, Deserialize)]
pub struct NewBugReport {
    pub developer_id: i64,
    pub project_id: i64,
    pub bug_description: String,
    pub bug_severity: String,
    pub report_time: Option<String>,
}

// Used for PATCH updates
#[derive(Debug, Deserialize)]
pub struct UpdateBugReport {
    pub developer_id: Option<i64>,
    pub bug_description: Option<String>,
    pub bug_severity: Option<String>,
    pub report_time: Option<String>, // time of update
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub description: String
}

#[derive(Deserialize)]
pub struct NewProject {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub status: String,
    pub token: Option<String>, 
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}
