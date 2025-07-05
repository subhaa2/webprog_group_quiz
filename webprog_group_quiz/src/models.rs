use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct BugReport {
    pub bug_id: i64,
    pub creator_id: i64 ,
    pub assignee_id: Option<i64>,
    pub assigned_by: Option<i64>,
    pub project_id: i64,
    pub bug_title: String,
    pub bug_description: String,
    pub bug_severity: String,
    pub report_time: Option<String>,
}
// Used when creating a new bug
#[derive(Debug, Deserialize)]
pub struct NewBugReport {
    pub project_id: i64,
    pub bug_title: String,
    pub bug_description: String,
    pub bug_severity: String,
}

// Used for PATCH updates
#[derive(Debug, Deserialize)]
pub struct UpdateBugReport {
    pub assignee_id: Option<i64>,
    pub bug_description: Option<String>,
    pub bug_severity: Option<String>,
    pub report_time: Option<String>, // time of update
}

#[derive(Debug, Deserialize)]
pub struct BugAssignForm {
    pub bug_id: i64, 
    pub assignee_id: i64, 
}

#[derive(Debug, Deserialize)]
pub struct CloseProjectForm {
    pub project_id: i64, 
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Project {
    pub project_id: i64,
    pub project_name: String,
    pub project_description: String,
    pub project_status: String,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct User {
    pub id: i64,                
    pub username: String,
    pub password_hash: String,
    pub role: String,           
}
#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Developer,
    QA,
}
impl Default for Role {
    fn default() -> Self {
        Role::Developer // Default role for new users
    }
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
    pub message: Option<String>,  // optional human-friendly message
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub role:Option<String>
}
