CREATE TABLE IF NOT EXISTS bugreport (
    bug_id INTEGER PRIMARY KEY AUTOINCREMENT,
    developer_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    bug_description TEXT NOT NULL,
    bug_severity TEXT NOT NULL,
    report_time TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
    FOREIGN KEY (developer_id) REFERENCES developers(id)
);

CREATE TABLE IF NOT EXISTS projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL,
    project_description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS developers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

ALTER TABLE developers ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
