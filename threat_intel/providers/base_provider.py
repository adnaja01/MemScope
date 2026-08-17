from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    UNKNOWN = 'UNKNOWN'
    TRUSTED = 'TRUSTED'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

@dataclass
class ProviderResult:
    provider: str
    ioc_type: str
    ioc_value: str
    found: bool
    is_malicious: bool
    risk_score: RiskLevel
    confidence: int
    raw_data: Dict[str, Any]
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {'provider': self.provider, 'ioc_type': self.ioc_type, 'ioc_value': self.ioc_value, 'found': self.found, 'is_malicious': self.is_malicious, 'risk_score': self.risk_score.value, 'confidence': self.confidence, 'raw_data': self.raw_data, 'error': self.error_message}

class ThreatIntelProvider(ABC):

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]]=None):
        self.api_key = api_key
        self.config = config or {}
        self.enabled = bool(api_key)

    @abstractmethod
    def query_hash(self, hash_value: str) -> ProviderResult:
        pass

    @abstractmethod
    def query_ip(self, ip_address: str) -> ProviderResult:
        pass

    @abstractmethod
    def query_domain(self, domain: str) -> ProviderResult:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_rate_limit(self) -> int:
        pass

    def normalize_hash(self, hash_value: str) -> str:
        return hash_value.strip().upper()

    def normalize_ip(self, ip_address: str) -> str:
        return ip_address.strip()

    def normalize_domain(self, domain: str) -> str:
        return domain.strip().lower()
