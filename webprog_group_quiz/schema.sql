CREATE TABLE IF NOT EXISTS bugreport (
    bug_id INTEGER PRIMARY KEY AUTOINCREMENT,
    developer_id INTEGER NOT NULL,
    bug_description TEXT NOT NULL,
    bug_severity TEXT NOT NULL,
    report_time TEXT DEFAULT CURRENT_TIMESTAMP
);