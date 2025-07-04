use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct BugReport {
    pub bug_id: u64,
    pub developer_id: u64,
    pub project_id: u64,
    pub bug_description: String,
    pub bug_severity: String,
    pub report_time: Option<String>, // optional if letting SQLite auto-fill
}

// Used when creating a new bug
#[derive(Debug, Deserialize)]
pub struct NewBugReport {
    pub developer_id: u64,
    pub project_id: u64,
    pub bug_description: String,
    pub bug_severity: String,
    pub report_time: Option<String>,
}

// Used for PATCH updates
#[derive(Debug, Deserialize)]
pub struct UpdateBugReport {
    pub developer_id: Option<u64>,
    pub bug_description: Option<String>,
    pub bug_severity: Option<String>,
    pub report_time: Option<String>, // time of update
}
