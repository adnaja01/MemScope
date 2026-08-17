import sqlite3
import hashlib
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

@dataclass
class CachedResult:
    ioc_type: str
    ioc_value: str
    provider: str
    result_data: Dict[str, Any]
    cached_at: float
    expires_at: float
    is_malicious: bool
    risk_score: str
    confidence: int

class ThreatIntelCache:

    def __init__(self, db_path: str='database/threat_intel_cache.db', ttl_hours: int=24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self._ensure_db()

    def _ensure_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("\n            CREATE TABLE IF NOT EXISTS ti_cache (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                ioc_type TEXT NOT NULL,\n                ioc_hash TEXT NOT NULL,\n                ioc_value TEXT NOT NULL,\n                provider TEXT NOT NULL,\n                result_data TEXT NOT NULL,\n                cached_at REAL NOT NULL,\n                expires_at REAL NOT NULL,\n                is_malicious INTEGER DEFAULT 0,\n                risk_score TEXT DEFAULT 'UNKNOWN',\n                confidence INTEGER DEFAULT 0,\n                UNIQUE(ioc_type, ioc_hash, provider)\n            )\n        ")
        cursor.execute('\n            CREATE TABLE IF NOT EXISTS ti_lookup_log (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                ioc_type TEXT NOT NULL,\n                ioc_hash TEXT NOT NULL,\n                looked_up_at REAL NOT NULL,\n                source TEXT NOT NULL,\n                cached_hit INTEGER DEFAULT 0\n            )\n        ')
        cursor.execute('\n            CREATE INDEX IF NOT EXISTS idx_ti_cache_ioc ON ti_cache(ioc_type, ioc_hash)\n        ')
        cursor.execute('\n            CREATE INDEX IF NOT EXISTS idx_ti_cache_expires ON ti_cache(expires_at)\n        ')
        conn.commit()
        conn.close()

    def _hash_ioc(self, ioc_value: str) -> str:
        normalized = ioc_value.strip().lower()
        return hashlib.sha256(normalized.encode()).hexdigest()[:32]

    def get(self, ioc_type: str, ioc_value: str, provider: str) -> Optional[CachedResult]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        ioc_hash = self._hash_ioc(ioc_value)
        now = time.time()
        cursor.execute('\n            SELECT ioc_type, ioc_value, provider, result_data, cached_at, expires_at,\n                   is_malicious, risk_score, confidence\n            FROM ti_cache\n            WHERE ioc_type = ? AND ioc_hash = ? AND provider = ? AND expires_at > ?\n        ', (ioc_type, ioc_hash, provider, now))
        row = cursor.fetchone()
        conn.close()
        if row:
            return CachedResult(ioc_type=row[0], ioc_value=row[1], provider=row[2], result_data=json.loads(row[3]), cached_at=row[4], expires_at=row[5], is_malicious=bool(row[6]), risk_score=row[7], confidence=row[8])
        return None

    def set(self, ioc_type: str, ioc_value: str, provider: str, result_data: Dict[str, Any], is_malicious: bool=False, risk_score: str='UNKNOWN', confidence: int=0) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        ioc_hash = self._hash_ioc(ioc_value)
        now = time.time()
        expires = now + self.ttl_hours * 3600
        cursor.execute('\n            INSERT OR REPLACE INTO ti_cache\n            (ioc_type, ioc_hash, ioc_value, provider, result_data, cached_at, expires_at,\n             is_malicious, risk_score, confidence)\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', (ioc_type, ioc_hash, ioc_value, provider, json.dumps(result_data), now, expires, int(is_malicious), risk_score, confidence))
        conn.commit()
        conn.close()

    def log_lookup(self, ioc_type: str, ioc_value: str, source: str='api', cached_hit: bool=False):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        ioc_hash = self._hash_ioc(ioc_value)
        cursor.execute('\n            INSERT INTO ti_lookup_log (ioc_type, ioc_hash, looked_up_at, source, cached_hit)\n            VALUES (?, ?, ?, ?, ?)\n        ', (ioc_type, ioc_hash, time.time(), source, int(cached_hit)))
        conn.commit()
        conn.close()

    def is_recently_queried(self, ioc_type: str, ioc_value: str, provider: str, within_seconds: int=60) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        ioc_hash = self._hash_ioc(ioc_value)
        cutoff = time.time() - within_seconds
        cursor.execute('\n            SELECT COUNT(*) FROM ti_cache\n            WHERE ioc_type = ? AND ioc_hash = ? AND provider = ? AND cached_at > ?\n        ', (ioc_type, ioc_hash, provider, cutoff))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def cleanup_expired(self) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = time.time()
        cursor.execute('DELETE FROM ti_cache WHERE expires_at <= ?', (now,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

    def get_stats(self) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = time.time()
        cursor.execute('SELECT COUNT(*) FROM ti_cache WHERE expires_at > ?', (now,))
        active = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM ti_cache WHERE is_malicious = 1 AND expires_at > ?', (now,))
        malicious = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM ti_lookup_log WHERE looked_up_at > ?', (now - 86400,))
        lookups_24h = cursor.fetchone()[0]
        cursor.execute('\n            SELECT COUNT(*) FROM ti_lookup_log\n            WHERE looked_up_at > ? AND cached_hit = 1\n        ', (now - 86400,))
        cache_hits = cursor.fetchone()[0]
        conn.close()
        return {'active_cache_entries': active, 'malicious_entries': malicious, 'lookups_24h': lookups_24h, 'cache_hits_24h': cache_hits, 'cache_hit_rate': round(cache_hits / lookups_24h * 100, 1) if lookups_24h > 0 else 0}

    def clear_all(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ti_cache')
        cursor.execute('DELETE FROM ti_lookup_log')
        conn.commit()
        conn.close()
