import requests
import ipaddress
from typing import Dict, Any, Optional
from .base_provider import ThreatIntelProvider, ProviderResult, RiskLevel

class AbuseIPDBProvider(ThreatIntelProvider):
    BASE_URL = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]]=None):
        super().__init__(api_key, config)
        self.session = requests.Session()
        self.session.headers.update({'Key': api_key, 'Accept': 'application/json'})
        self.rate_limit_per_minute = 16

    def get_name(self) -> str:
        return 'AbuseIPDB'

    def get_rate_limit(self) -> int:
        return self.rate_limit_per_minute

    def _validate_ip(self, ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def query_ip(self, ip_address: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_ip(ip_address)
        if not self._validate_ip(normalized):
            return self._error_result('Invalid IP address format')
        url = f'{self.BASE_URL}/check'
        try:
            response = self.session.get(url, params={'ipAddress': normalized, 'maxAgeInDays': 90, 'verbose': ''}, timeout=10)
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code == 422:
                return self._error_result('IP address validation failed')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_ip_result(ip_address, data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def query_hash(self, hash_value: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='hash', ioc_value=hash_value, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message='Hash lookup not supported by AbuseIPDB')

    def query_domain(self, domain: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='domain', ioc_value=domain, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message='Domain lookup not supported by AbuseIPDB')

    def _parse_ip_result(self, ip_address: str, data: Dict) -> ProviderResult:
        try:
            attrs = data.get('data', {}).get('attributes', {})
            confidence = attrs.get('abuseConfidenceScore', 0)
            total_reports = attrs.get('totalReports', 0)
            num_distinct = attrs.get('numDistinctUsers', 0)
            isp = attrs.get('isp', '')
            domain = attrs.get('domain', '')
            country_code = attrs.get('countryCode', '')
            usage_type = attrs.get('usageType', '')
            isp = attrs.get('isp', '')
            is_whitelisted = attrs.get('isWhitelisted', False)
            is_malicious = confidence >= 50
            if confidence >= 75:
                risk_score = RiskLevel.CRITICAL
                conf_score = 95
            elif confidence >= 50:
                risk_score = RiskLevel.HIGH
                conf_score = 85
            elif confidence >= 25:
                risk_score = RiskLevel.MEDIUM
                conf_score = 70
            elif confidence >= 10:
                risk_score = RiskLevel.LOW
                conf_score = 50
            else:
                risk_score = RiskLevel.TRUSTED if not is_malicious else RiskLevel.LOW
                conf_score = 40 if confidence == 0 else 60
            return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value=ip_address, found=True, is_malicious=is_malicious, risk_score=risk_score, confidence=conf_score, raw_data={'abuse_confidence_score': confidence, 'total_reports': total_reports, 'num_distinct_users': num_distinct, 'isp': isp, 'domain': domain, 'country_code': country_code, 'usage_type': usage_type, 'is_whitelisted': is_whitelisted, 'last_reported_at': attrs.get('lastReportedAt'), 'is_public': attrs.get('isPublic', True), 'ip_address_version': attrs.get('ipAddressVersion', 'IPv4')})
        except (KeyError, TypeError) as e:
            return self._error_result(f'Parse error: {e}')

    def _error_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)

    def _rate_limit_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)
