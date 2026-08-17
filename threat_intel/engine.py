import time
import threading
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from .config import ThreatIntelConfig
from .cache_manager import ThreatIntelCache, CachedResult
from .rate_limiter import RateLimiter, RateLimitConfig, RequestThrottler, LookupQueue
from .providers.base_provider import ThreatIntelProvider, ProviderResult, RiskLevel
from .providers.virustotal import VirusTotalProvider
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.alienvault_otx import AlienVaultOTXProvider

class LookupMode(Enum):
    CACHE_ONLY = 'cache_only'
    CACHE_FIRST = 'cache_first'
    LIVE_ONLY = 'live_only'

@dataclass
class EnrichedFinding:
    finding_type: str
    original_value: str
    risk_score: RiskLevel
    confidence: int
    providers_checked: List[str]
    provider_results: List[ProviderResult]
    local_heuristic_match: bool
    local_heuristic_severity: Optional[str] = None
    summary: str = ''

@dataclass
class EnrichmentResult:
    findings: List[EnrichedFinding]
    stats: Dict[str, Any]
    errors: List[str]
    fallback_used: bool

@dataclass
class LocalHeuristicRule:
    name: str
    patterns: List[str]
    severity: str
    description: str

class ThreatIntelligenceEngine:

    def __init__(self, config: Optional[ThreatIntelConfig]=None):
        self.config = config or ThreatIntelConfig.from_env()
        self.cache = ThreatIntelCache(db_path=self.config.cache_db_path, ttl_hours=self.config.cache_duration_hours)
        self.throttler = RequestThrottler()
        self._lookup_queue = LookupQueue(max_size=1000)
        self._active_lookups: Set[str] = set()
        self._lookup_lock = threading.Lock()
        self._providers: Dict[str, ThreatIntelProvider] = {}
        self._initialize_providers()
        self._initialize_rate_limiters()

    def _initialize_providers(self):
        if self.config.has_vt_key():
            self._providers['virustotal'] = VirusTotalProvider(self.config.vt_api_key)
        if self.config.has_abuseipdb_key():
            self._providers['abuseipdb'] = AbuseIPDBProvider(self.config.abuseipdb_api_key)
        if self.config.has_otx_key():
            self._providers['alienvault_otx'] = AlienVaultOTXProvider(self.config.otx_api_key)

    def _initialize_rate_limiters(self):
        self.throttler.register_provider('virustotal', RateLimitConfig(requests_per_minute=self.config.vt_rate_limit_per_minute))
        self.throttler.register_provider('abuseipdb', RateLimitConfig(requests_per_minute=self.config.abuseipdb_rate_limit_per_minute))

    def query_ioc(self, ioc_type: str, ioc_value: str, mode: LookupMode=LookupMode.CACHE_FIRST) -> Optional[ProviderResult]:
        if not ioc_value:
            return None
        cache_key = f'{ioc_type}:{ioc_value}'
        if mode in (LookupMode.CACHE_ONLY, LookupMode.CACHE_FIRST):
            for provider_name in self._providers:
                cached = self.cache.get(ioc_type, ioc_value, provider_name)
                if cached:
                    self.cache.log_lookup(ioc_type, ioc_value, 'cache', cached_hit=True)
                    return ProviderResult(provider=cached.provider, ioc_type=cached.ioc_type, ioc_value=cached.ioc_value, found=True, is_malicious=cached.is_malicious, risk_score=RiskLevel(cached.risk_score), confidence=cached.confidence, raw_data=cached.result_data)
        if mode == LookupMode.CACHE_ONLY:
            return None
        with self._lookup_lock:
            if cache_key in self._active_lookups:
                time.sleep(0.5)
                return self.query_ioc(ioc_type, ioc_value, LookupMode.CACHE_FIRST)
            self._active_lookups.add(cache_key)
        try:
            results = []
            for provider_name, provider in self._providers.items():
                if self._should_skip_provider(provider_name, ioc_type):
                    continue
                if self.cache.is_recently_queried(ioc_type, ioc_value, provider_name, within_seconds=60):
                    continue
                result = self._query_provider(provider, ioc_type, ioc_value)
                if result and result.found:
                    self.cache.set(ioc_type, ioc_value, provider_name, result.raw_data, is_malicious=result.is_malicious, risk_score=result.risk_score.value, confidence=result.confidence)
                    results.append(result)
                    self.cache.log_lookup(ioc_type, ioc_value, 'api', cached_hit=False)
                if 'rate limit' in (result.error_message or '').lower():
                    break
            if results:
                return self._merge_results(results)
            return None
        finally:
            with self._lookup_lock:
                self._active_lookups.discard(cache_key)

    def _should_skip_provider(self, provider: str, ioc_type: str) -> bool:
        if provider == 'abuseipdb' and ioc_type != 'ip':
            return True
        return False

    def _query_provider(self, provider: ThreatIntelProvider, ioc_type: str, ioc_value: str) -> Optional[ProviderResult]:
        method_map = {'hash': provider.query_hash, 'ip': provider.query_ip, 'domain': provider.query_domain}
        query_func = method_map.get(ioc_type)
        if not query_func:
            return None
        success, result, error = self.throttler.execute_throttled(provider.get_name().lower(), lambda: query_func(ioc_value))
        if success and result:
            return result
        return None

    def _merge_results(self, results: List[ProviderResult]) -> ProviderResult:
        if not results:
            return results[0]
        highest_risk = RiskLevel.UNKNOWN
        max_confidence = 0
        any_malicious = False
        combined_raw = {}
        risk_order = {RiskLevel.CRITICAL: 5, RiskLevel.HIGH: 4, RiskLevel.MEDIUM: 3, RiskLevel.LOW: 2, RiskLevel.TRUSTED: 1, RiskLevel.UNKNOWN: 0}
        for result in results:
            if result.is_malicious:
                any_malicious = True
            if risk_order.get(result.risk_score, 0) > risk_order.get(highest_risk, 0):
                highest_risk = result.risk_score
            if result.confidence > max_confidence:
                max_confidence = result.confidence
            for key, value in result.raw_data.items():
                if key not in combined_raw:
                    combined_raw[key] = value
        return ProviderResult(provider='MERGED', ioc_type=results[0].ioc_type, ioc_value=results[0].ioc_value, found=True, is_malicious=any_malicious, risk_score=highest_risk, confidence=min(max_confidence, 95), raw_data=combined_raw)

    def enrich_findings(self, findings: Dict[str, List[str]], mode: LookupMode=LookupMode.CACHE_FIRST) -> EnrichmentResult:
        enriched = []
        errors = []
        stats = {'total_iocs': 0, 'cached_hits': 0, 'api_calls': 0, 'malicious_found': 0, 'providers_used': []}
        for ioc_type in ['hashes', 'ips', 'domains']:
            ioc_key = ioc_type.rstrip('s')
            values = findings.get(ioc_type, [])
            for value in values:
                if not value:
                    continue
                stats['total_iocs'] += 1
                cached = None
                for provider_name in self._providers:
                    cached = self.cache.get(ioc_key, value, provider_name)
                    if cached:
                        break
                if cached:
                    stats['cached_hits'] += 1
                    enriched.append(self._cached_to_finding(cached))
                    continue
                result = self.query_ioc(ioc_key, value, mode)
                if result:
                    stats['api_calls'] += 1
                    if result.is_malicious:
                        stats['malicious_found'] += 1
                    if result.provider not in stats['providers_used']:
                        stats['providers_used'].append(result.provider)
                    enriched.append(EnrichedFinding(finding_type=ioc_key, original_value=value, risk_score=result.risk_score, confidence=result.confidence, providers_checked=[result.provider], provider_results=[result], local_heuristic_match=False))
                elif self.config.fallback_to_local:
                    local_result = self._local_heuristic_check(ioc_key, value)
                    if local_result:
                        enriched.append(local_result)
        return EnrichmentResult(findings=enriched, stats=stats, errors=errors, fallback_used=len(errors) > 0)

    def _cached_to_finding(self, cached: CachedResult) -> EnrichedFinding:
        return EnrichedFinding(finding_type=cached.ioc_type, original_value=cached.ioc_value, risk_score=RiskLevel(cached.risk_score), confidence=cached.confidence, providers_checked=[cached.provider], provider_results=[], local_heuristic_match=False)

    def _local_heuristic_check(self, ioc_type: str, value: str) -> Optional[EnrichedFinding]:
        local_rules = self._get_local_rules()
        for rule in local_rules:
            for pattern in rule.patterns:
                if pattern.lower() in value.lower():
                    return EnrichedFinding(finding_type=ioc_type, original_value=value, risk_score=self._severity_to_risk(rule.severity), confidence=40, providers_checked=[], provider_results=[], local_heuristic_match=True, local_heuristic_severity=rule.severity, summary=rule.description)
        return None

    def _get_local_rules(self) -> List[LocalHeuristicRule]:
        return [LocalHeuristicRule(name='suspicious_process', patterns=['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'wmic.exe', 'bash', 'sh', 'python', 'perl', 'nc', 'netcat'], severity='MEDIUM', description='Suspicious or dual-use process detected'), LocalHeuristicRule(name='suspicious_command', patterns=['-enc', '-encodedcommand', 'frombase64string', 'downloadstring', 'iex ', 'invoke-expression', 'http://', 'https://', '.ps1', '.bat', '.vbs', '.js'], severity='HIGH', description='Suspicious command-line indicator detected'), LocalHeuristicRule(name='suspicious_path', patterns=['appdata', '\\temp\\', '/tmp/', '\\windows\\temp'], severity='MEDIUM', description='Suspicious file path usage detected'), LocalHeuristicRule(name='encoded_powershell', patterns=['powershell.exe', '-enc', '-encodedcommand'], severity='HIGH', description='PowerShell with encoded command detected')]

    def _severity_to_risk(self, severity: str) -> RiskLevel:
        mapping = {'CRITICAL': RiskLevel.CRITICAL, 'HIGH': RiskLevel.HIGH, 'MEDIUM': RiskLevel.MEDIUM, 'LOW': RiskLevel.LOW}
        return mapping.get(severity.upper(), RiskLevel.UNKNOWN)

    def get_unified_risk_score(self, findings: List[EnrichedFinding]) -> tuple[RiskLevel, int]:
        if not findings:
            return (RiskLevel.UNKNOWN, 0)
        risk_weights = {RiskLevel.CRITICAL: 10, RiskLevel.HIGH: 7, RiskLevel.MEDIUM: 4, RiskLevel.LOW: 2, RiskLevel.TRUSTED: 0, RiskLevel.UNKNOWN: 0}
        total_score = 0
        total_confidence = 0
        max_risk = RiskLevel.UNKNOWN
        for finding in findings:
            weight = risk_weights.get(finding.risk_score, 0)
            total_score += weight * (finding.confidence / 100)
            if risk_weights.get(finding.risk_score, 0) > risk_weights.get(max_risk, 0):
                max_risk = finding.risk_score
        normalized_score = total_score / len(findings) if findings else 0
        if normalized_score >= 7:
            final_risk = RiskLevel.CRITICAL
        elif normalized_score >= 5:
            final_risk = RiskLevel.HIGH
        elif normalized_score >= 3:
            final_risk = RiskLevel.MEDIUM
        elif normalized_score >= 1:
            final_risk = RiskLevel.LOW
        else:
            final_risk = max_risk
        return (final_risk, int(normalized_score * 10))

    def get_cache_stats(self) -> Dict[str, Any]:
        return self.cache.get_stats()

    def cleanup_cache(self) -> int:
        return self.cache.cleanup_expired()

    def is_available(self) -> bool:
        return len(self._providers) > 0

    def get_enabled_providers(self) -> List[str]:
        return list(self._providers.keys())
_engine_instance: Optional[ThreatIntelligenceEngine] = None
_instance_lock = threading.Lock()

def get_engine() -> ThreatIntelligenceEngine:
    global _engine_instance
    with _instance_lock:
        if _engine_instance is None:
            _engine_instance = ThreatIntelligenceEngine()
        return _engine_instance

def reset_engine():
    global _engine_instance
    with _instance_lock:
        _engine_instance = None
