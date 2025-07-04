CREATE TABLE IF NOT EXISTS bug_reports (
    bug_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bug_title TEXT NOT NULL,
    bug_description TEXT NOT NULL,
    bug_severity TEXT NOT NULL,
    time_created TEXT DEFAULT CURRENT_TIMESTAMP,
    developer_id INTEGER NOT NULL
);