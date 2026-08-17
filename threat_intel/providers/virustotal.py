import requests
from typing import Dict, Any, Optional
from .base_provider import ThreatIntelProvider, ProviderResult, RiskLevel

class VirusTotalProvider(ThreatIntelProvider):
    BASE_URL = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]]=None):
        super().__init__(api_key, config)
        self.session = requests.Session()
        self.session.headers.update({'x-apikey': api_key, 'Accept': 'application/json'})
        self.rate_limit_per_minute = 4

    def get_name(self) -> str:
        return 'VirusTotal'

    def get_rate_limit(self) -> int:
        return self.rate_limit_per_minute

    def query_hash(self, hash_value: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_hash(hash_value)
        url = f'{self.BASE_URL}/files/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='hash', ioc_value=hash_value, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_file_result(hash_value, data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def query_ip(self, ip_address: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_ip(ip_address)
        url = f'{self.BASE_URL}/ip_addresses/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value=ip_address, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_ip_result(ip_address, data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def query_domain(self, domain: str) -> ProviderResult:
        if not self.enabled:
            return self._error_result('API key not configured')
        normalized = self.normalize_domain(domain)
        url = f'{self.BASE_URL}/domains/{normalized}'
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 404:
                return ProviderResult(provider=self.get_name(), ioc_type='domain', ioc_value=domain, found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={})
            if response.status_code == 429:
                return self._rate_limit_result('Rate limit exceeded')
            if response.status_code != 200:
                return self._error_result(f'HTTP {response.status_code}')
            data = response.json()
            return self._parse_domain_result(domain, data)
        except requests.exceptions.Timeout:
            return self._error_result('Request timeout')
        except requests.exceptions.RequestException as e:
            return self._error_result(str(e))

    def _parse_file_result(self, hash_value: str, data: Dict) -> ProviderResult:
        try:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            is_malicious = malicious > 0 or suspicious > 0
            if malicious >= 10:
                risk_score = RiskLevel.CRITICAL
                confidence = 95
            elif malicious >= 5:
                risk_score = RiskLevel.HIGH
                confidence = 85
            elif malicious >= 1:
                risk_score = RiskLevel.MEDIUM
                confidence = 70
            elif suspicious >= 1:
                risk_score = RiskLevel.LOW
                confidence = 50
            else:
                risk_score = RiskLevel.TRUSTED
                confidence = 90
            return ProviderResult(provider=self.get_name(), ioc_type='hash', ioc_value=hash_value, found=True, is_malicious=is_malicious, risk_score=risk_score, confidence=confidence, raw_data={'malicious_votes': malicious, 'suspicious_votes': suspicious, 'total_engines': total_engines, 'detection_ratio': f'{malicious}/{total_engines}' if total_engines > 0 else '0/0', 'type_etag': attrs.get('type'), 'name': attrs.get('meaningful_name', attrs.get('name', '')), 'first_submission': attrs.get('first_submission_date'), 'last_analysis_date': attrs.get('last_analysis_date')})
        except (KeyError, TypeError) as e:
            return self._error_result(f'Parse error: {e}')

    def _parse_ip_result(self, ip_address: str, data: Dict) -> ProviderResult:
        try:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            is_malicious = malicious > 0 or suspicious > 0
            if malicious >= 5:
                risk_score = RiskLevel.HIGH
                confidence = 85
            elif malicious >= 1:
                risk_score = RiskLevel.MEDIUM
                confidence = 70
            elif suspicious >= 1:
                risk_score = RiskLevel.LOW
                confidence = 50
            else:
                risk_score = RiskLevel.TRUSTED
                confidence = 80
            return ProviderResult(provider=self.get_name(), ioc_type='ip', ioc_value=ip_address, found=True, is_malicious=is_malicious, risk_score=risk_score, confidence=confidence, raw_data={'country': attrs.get('country'), 'as_owner': attrs.get('as_owner', ''), 'network': attrs.get('network', ''), 'malicious_engines': malicious, 'suspicious_engines': suspicious, 'reputation': attrs.get('reputation', 0)})
        except (KeyError, TypeError) as e:
            return self._error_result(f'Parse error: {e}')

    def _parse_domain_result(self, domain: str, data: Dict) -> ProviderResult:
        try:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            is_malicious = malicious > 0 or suspicious > 0
            if malicious >= 3:
                risk_score = RiskLevel.HIGH
                confidence = 80
            elif malicious >= 1:
                risk_score = RiskLevel.MEDIUM
                confidence = 70
            elif suspicious >= 1:
                risk_score = RiskLevel.LOW
                confidence = 50
            else:
                risk_score = RiskLevel.TRUSTED
                confidence = 80
            return ProviderResult(provider=self.get_name(), ioc_type='domain', ioc_value=domain, found=True, is_malicious=is_malicious, risk_score=risk_score, confidence=confidence, raw_data={'country': attrs.get('country'), 'registrar': attrs.get('registrar'), 'creation_date': attrs.get('creation_date'), 'malicious_engines': malicious, 'suspicious_engines': suspicious, 'categories': list(attrs.get('tags', []))[:5]})
        except (KeyError, TypeError) as e:
            return self._error_result(f'Parse error: {e}')

    def _error_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='unknown', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)

    def _rate_limit_result(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.get_name(), ioc_type='unknown', ioc_value='', found=False, is_malicious=False, risk_score=RiskLevel.UNKNOWN, confidence=0, raw_data={}, error_message=message)
