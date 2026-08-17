import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / 'database' / 'memscope.db'

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database_if_needed():
    from database.init_db import init_database
    if not DB_PATH.exists():
        init_database()

def get_or_create_default_case(investigator: str) -> int:
    init_database_if_needed()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT case_id FROM cases WHERE case_name = ?', ('Default Case',))
        row = cursor.fetchone()
        if row:
            return row['case_id']
        cursor.execute('\n            INSERT INTO cases (case_name, investigator, description)\n            VALUES (?, ?, ?)\n        ', ('Default Case', investigator, 'Automatically created default case'))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def insert_dump(case_id: int, file_name: str, file_path: str, os_type: str, acquisition_mode: str, analyst: str, hash_sha256: str, file_size_bytes: int, acquired_at: str, acquisition_duration_seconds: Optional[float], notes: str='') -> int:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            INSERT INTO dumps (\n                case_id, file_name, file_path, os_type, acquisition_mode, analyst,\n                hash_sha256, file_size_bytes, acquired_at, acquisition_duration_seconds, notes\n            )\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', (case_id, file_name, file_path, os_type, acquisition_mode, analyst, hash_sha256, file_size_bytes, acquired_at, acquisition_duration_seconds, notes))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def insert_analysis_session(dump_id: int, analysis_profile: str, started_at: str, duration_seconds: Optional[float], suspicious_summary: str, threat_intel_summary: str=None, ti_risk_level: str=None, ti_confidence: int=None) -> int:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            INSERT INTO analysis_sessions (\n                dump_id, analysis_profile, started_at, duration_seconds, suspicious_summary,\n                threat_intel_summary, ti_risk_level, ti_confidence\n            )\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?)\n        ', (dump_id, analysis_profile, started_at, duration_seconds, suspicious_summary, threat_intel_summary, ti_risk_level, ti_confidence))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def update_ti_enrichment(analysis_id: int, threat_intel_summary: str, ti_risk_level: str, ti_confidence: int):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            UPDATE analysis_sessions\n            SET threat_intel_summary = ?, ti_risk_level = ?, ti_confidence = ?\n            WHERE analysis_id = ?\n        ', (threat_intel_summary, ti_risk_level, ti_confidence, analysis_id))
        conn.commit()
    finally:
        conn.close()

def insert_plugin_result(analysis_id: int, plugin_name: str, output_text: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            INSERT INTO plugin_results (analysis_id, plugin_name, output_text)\n            VALUES (?, ?, ?)\n        ', (analysis_id, plugin_name, output_text))
        conn.commit()
    finally:
        conn.close()

def insert_suspicious_finding(analysis_id: int, severity: str, category: str, finding_text: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            INSERT INTO suspicious_findings (analysis_id, severity, category, finding_text)\n            VALUES (?, ?, ?, ?)\n        ', (analysis_id, severity, category, finding_text))
        conn.commit()
    finally:
        conn.close()

def insert_advanced_command(dump_id: int, analyst: str, command_text: str, output_text: str, executed_at: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('\n            INSERT INTO advanced_commands (\n                dump_id, analyst, command_text, output_text, executed_at\n            )\n            VALUES (?, ?, ?, ?, ?)\n        ', (dump_id, analyst, command_text, output_text, executed_at))
        conn.commit()
    finally:
        conn.close()

def get_dump_history(filename: str=None, date_from: str=None, date_to: str=None, os_type: str=None, analysis_profile: str=None, use_default_date_range: bool=True) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        if use_default_date_range:
            cursor.execute('SELECT MIN(acquired_at) as min_date FROM dumps')
            row = cursor.fetchone()
            if row and row['min_date']:
                date_from = row['min_date'][:10]
            if not date_to:
                date_to = 'today'
        query = '\n            SELECT\n                d.dump_id,\n                d.file_name,\n                d.file_path,\n                d.os_type,\n                d.acquisition_mode,\n                d.analyst,\n                d.hash_sha256,\n                d.file_size_bytes,\n                d.acquired_at,\n                d.acquisition_duration_seconds,\n                (\n                    SELECT COUNT(*)\n                    FROM analysis_sessions a\n                    WHERE a.dump_id = d.dump_id\n                ) AS analysis_count\n            FROM dumps d\n            WHERE 1=1\n        '
        params = []
        if filename:
            query += ' AND d.file_name LIKE ?'
            params.append(f'%{filename}%')
        if date_to == 'today':
            from datetime import date
            date_to = date.today().isoformat()
        if date_from:
            query += ' AND d.acquired_at >= ?'
            params.append(date_from)
        if date_to:
            query += ' AND d.acquired_at <= ?'
            params.append(date_to + ' 23:59:59')
        if os_type and os_type != 'All':
            query += ' AND d.os_type = ?'
            params.append(os_type)
        if analysis_profile and analysis_profile != 'All':
            query += '\n                AND EXISTS (\n                    SELECT 1 FROM analysis_sessions a\n                    WHERE a.dump_id = d.dump_id\n                    AND a.analysis_profile = ?\n                )\n            '
            params.append(analysis_profile)
        query += ' ORDER BY d.dump_id DESC'
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_dump_details(dump_id: int) -> Dict[str, Any]:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dumps WHERE dump_id = ?', (dump_id,))
        dump_row = cursor.fetchone()
        dump_data = dict(dump_row) if dump_row else {}
        cursor.execute('\n            SELECT *\n            FROM analysis_sessions\n            WHERE dump_id = ?\n            ORDER BY analysis_id DESC\n        ', (dump_id,))
        analysis_rows = [dict(row) for row in cursor.fetchall()]
        for analysis in analysis_rows:
            analysis_id = analysis['analysis_id']
            cursor.execute('\n                SELECT plugin_name, output_text\n                FROM plugin_results\n                WHERE analysis_id = ?\n            ', (analysis_id,))
            analysis['plugin_results'] = [dict(row) for row in cursor.fetchall()]
            cursor.execute('\n                SELECT severity, category, finding_text\n                FROM suspicious_findings\n                WHERE analysis_id = ?\n            ', (analysis_id,))
            analysis['suspicious_findings'] = [dict(row) for row in cursor.fetchall()]
        cursor.execute('\n            SELECT analyst, command_text, output_text, executed_at\n            FROM advanced_commands\n            WHERE dump_id = ?\n            ORDER BY command_id DESC\n        ', (dump_id,))
        advanced_rows = [dict(row) for row in cursor.fetchall()]
        return {'dump': dump_data, 'analyses': analysis_rows, 'advanced_commands': advanced_rows}
    finally:
        conn.close()
