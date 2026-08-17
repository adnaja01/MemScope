CREATE TABLE IF NOT EXISTS cases (
    case_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name TEXT NOT NULL,
    investigator TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dumps (
    dump_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    os_type TEXT,
    acquisition_mode TEXT,
    analyst TEXT,
    hash_sha256 TEXT,
    file_size_bytes INTEGER,
    acquired_at TEXT,
    acquisition_duration_seconds REAL,
    notes TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS analysis_sessions (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_id INTEGER NOT NULL,
    analysis_profile TEXT,
    started_at TEXT,
    duration_seconds REAL,
    suspicious_summary TEXT,
    threat_intel_summary TEXT,
    ti_risk_level TEXT,
    ti_confidence INTEGER,
    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
);

CREATE TABLE IF NOT EXISTS plugin_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL,
    plugin_name TEXT NOT NULL,
    output_text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_sessions(analysis_id)
);

CREATE TABLE IF NOT EXISTS suspicious_findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL,
    severity TEXT,
    category TEXT,
    finding_text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_sessions(analysis_id)
);

CREATE TABLE IF NOT EXISTS advanced_commands (
    command_id INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_id INTEGER NOT NULL,
    analyst TEXT,
    command_text TEXT NOT NULL,
    output_text TEXT,
    executed_at TEXT,
    FOREIGN KEY (dump_id) REFERENCES dumps(dump_id)
);