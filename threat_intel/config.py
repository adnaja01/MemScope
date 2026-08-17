import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class ThreatIntelConfig:
    vt_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    cache_duration_hours: int = 24
    cache_db_path: str = 'database/threat_intel_cache.db'
    vt_rate_limit_per_minute: int = 4
    abuseipdb_rate_limit_per_minute: int = 10
    enable_virustotal: bool = True
    enable_abuseipdb: bool = True
    enable_otx: bool = True
    fallback_to_local: bool = True
    max_batch_ips: int = 50
    max_batch_hashes: int = 50
    request_timeout_seconds: int = 10
    max_retries: int = 2

    def __post_init__(self):
        self.vt_api_key = os.getenv('VT_API_KEY', self.vt_api_key)
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', self.abuseipdb_api_key)
        self.otx_api_key = os.getenv('OTX_API_KEY', self.otx_api_key)

    @classmethod
    def from_env(cls) -> 'ThreatIntelConfig':
        return cls(vt_api_key=os.getenv('VT_API_KEY'), abuseipdb_api_key=os.getenv('ABUSEIPDB_API_KEY'), otx_api_key=os.getenv('OTX_API_KEY'), cache_duration_hours=int(os.getenv('TI_CACHE_HOURS', '24')), cache_db_path=os.getenv('TI_CACHE_DB', 'database/threat_intel_cache.db'))

    def has_vt_key(self) -> bool:
        return bool(self.vt_api_key)

    def has_abuseipdb_key(self) -> bool:
        return bool(self.abuseipdb_api_key)

    def has_otx_key(self) -> bool:
        return bool(self.otx_api_key)

    def is_any_api_available(self) -> bool:
        return self.has_vt_key() or self.has_abuseipdb_key() or self.has_otx_key()
