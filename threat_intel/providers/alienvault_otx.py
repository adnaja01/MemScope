import requests
from typing import Dict, Any, Optional, List
from .base_provider import ThreatIntelProvider, ProviderResult, RiskLevel

class AlienVaultOTXProvider(ThreatIntelProvider):
    BASE_URL = 'https://otx.alienvault.com/api/v1'

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]]=None):
        super().__init__(api_key, config)
        self.session = requests.Session()
        self.session.headers.update({'X-OTX-API-KEY': api_key, 'Accept': 'application/json'})
        self.rate_limit_per_minute = 30

    def get_name(self) -> str:
        return 'AlienVault OTX'

    def get_rate_limit(self) -> int:
        return self.rate_limit_per_minute

    def query_hash(self, hash_value: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_hash(hash_value)
        url = f'{self.BASE_URL}/indicators/FILE_HASH/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='hash', ioc_value=hash_value, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_indicator_result(hash_value, 'file_hash', data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def query_ip(self, ip_address: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_ip(ip_address)
        url = f'{self.BASE_URL}/indicators/IPv4/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value=ip_address, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_indicator_result(ip_address, 'ipv4', data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def query_domain(self, domain: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_domain(domain)
        url = f'{self.BASE_URL}/indicators/domain/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='domain', ioc_value=domain, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_indicator_result(domain, 'domain', data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def _parse_indicator_result(self, value: str, indicator_type: str, data: Dict) -> ProviderResult:
        try:
            pulse_info = data.get('pulse_info', {})
            pulses = pulse_info.get('pulses', [])
            count = len(pulses)
            is_malicious = count > 0
            if count >= 10:
                risk_score = RiskLevel.CRITICAL
                confidence = 90
            elif count >= 5:
                risk_score = RiskLevel.HIGH
                confidence = 80
            elif count >= 2:
                risk_score = RiskLevel.MEDIUM
                confidence = 70
            elif count == 1:
                risk_score = RiskLevel.LOW
                confidence = 60
            else:
                risk_score = RiskLevel.TRUSTED
                confidence = 50
            tags = set()
            for pulse in pulses[:5]:
                tags.update(pulse.get('tags', []))
            tags = list(tags)[:10]
            malware_families = []
            for pulse in pulses[:3]:
                for indicator in pulse.get('indicators', [])[:10]:
                    if indicator.get('type') == 'Filehash':
                        if indicator.get('metadata', {}).get('malware_family'):
                            malware_families.append(indicator['metadata']['malware_family'])
            return ProviderResult(provider=self.get_name(), ioc_type=indicator_type, ioc_value=value, found=True, is_malicious=is_malicious, risk_score=risk_score, confidence=confidence, raw_data={'pulse_count': count, 'pulse_names': [p.get('name', '') for p in pulses[:5]], 'tags': tags, 'malware_families': list(set(malware_families))[:5], 'created': pulse_info.get('create_date'), 'modified': pulse_info.get('modify_date'), 'related_indicators_count': pulse_info.get('count', 0)})
        except (KeyError, TypeError) as e:
            return self._error_result(f'Parse error: {e}')

    def _error_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='unknown', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)

    def _rate_limit_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='unknown', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)
