import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "database"
DB_PATH = DB_DIR / "memscope.db"
SCHEMA_PATH = DB_DIR / "schema.sql"


def init_database():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = f.read()
        conn.executescript(schema)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analysis_sessions)")
        columns = [col[1] for col in cursor.fetchall()]
        if "threat_intel_summary" not in columns:
            cursor.execute("ALTER TABLE analysis_sessions ADD COLUMN threat_intel_summary TEXT")
        if "ti_risk_level" not in columns:
            cursor.execute("ALTER TABLE analysis_sessions ADD COLUMN ti_risk_level TEXT")
        if "ti_confidence" not in columns:
            cursor.execute("ALTER TABLE analysis_sessions ADD COLUMN ti_confidence INTEGER")
        conn.commit()
    finally:
        conn.close()
