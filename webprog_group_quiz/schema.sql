CREATE TABLE IF NOT EXISTS bugreport (
    bug_id INTEGER PRIMARY KEY AUTOINCREMENT,
    developer_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    bug_description TEXT NOT NULL,
    bug_severity TEXT NOT NULL,
    report_time TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);

CREATE TABLE IF NOT EXISTS projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL,
    project_description TEXT NOT NULL
);
