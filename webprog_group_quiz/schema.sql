
CREATE TABLE IF NOT EXISTS bugreport (
    bug_id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    assignee_id INTEGER,
    assigned_by INTEGER,
    project_id INTEGER NOT NULL,
    bug_title TEXT NOT NULL,
    bug_description TEXT NOT NULL,
    bug_severity TEXT NOT NULL,
    report_time TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(project_id),
    FOREIGN KEY (creator_id) REFERENCES users(id),
    FOREIGN KEY (assignee_id) REFERENCES users(id),
    FOREIGN KEY (assigned_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL,
    project_description TEXT NOT NULL,
    project_status TEXT NOT NULL DEFAULT 'active' CHECK (project_status IN ('active', 'closed'))
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'developer', 'qa'))
);
