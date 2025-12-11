from typing import Dict, List, Optional

class GeoIP:
    def __init__(self, enabled=True):
        self.cache = {}
        self.enabled = enabled
        self.timeout = 2
        self.max_workers = 5

        self._init_cache()

    def _init_cache(self):
        common_ips = {
            '8.8.8.8': 'USA',
            '1.1.1.1': 'USA',
            '192.168.1.1': 'Private IP',
            '192.168.0.1': 'Private IP',
            '10.0.0.1': 'Private IP',
            '127.0.0.1': 'Localhost',
            '0.0.0.0': 'Invalid IP',
        }
        self.cache.update(common_ips)

    def get_country(self, ip_address: str) -> Optional[str]:
        if not self.enabled:
            return "GeoIP disabled"

        if not ip_address or ip_address == '*':
            return None

        if ip_address.startswith(('192.168.', '10.', '100.', '172.16.', '172.31.', '169.254.')):
            return "Private IP"

        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            return self._get_country_fast(ip_address)

        except Exception:
            self.cache[ip_address] = "Unknown"
            return "Unknown"

    def _get_country_fast(self, ip_address: str) -> str:
        if not ip_address or '.' not in ip_address:
            return "Unknown"

        first_octet = int(ip_address.split('.')[0])

        if 1 <= first_octet <= 9:
            return "USA"
        elif first_octet == 10:
            return "Private IP"
        elif 11 <= first_octet <= 126:
            return "USA/Europe"
        elif first_octet == 127:
            return "Localhost"
        elif 128 <= first_octet <= 191:
            if 128 <= first_octet <= 143:
                return "USA"
            else:
                return "Europe/Asia"
        elif 192 <= first_octet <= 223:
            if first_octet == 192:
                return "Private IP"
            elif 193 <= first_octet <= 199:
                return "USA"
            elif 200 <= first_octet <= 209:
                return "South America"
            else:
                return "Asia"
        elif 224 <= first_octet <= 239:
            return "Multicast"
        elif 240 <= first_octet <= 255:
            return "Reserved"
        else:
            return "Unknown"

    def analyze_countries(self, hops: List[Dict]) -> Dict:
        if not self.enabled:
            return {
                'hop_countries': {},
                'unique_countries': set(),
                'issues': []
            }

        countries = {}
        hop_countries = {}

        for hop in hops:
            ip = hop.get('ip_address')
            if ip and ip != '*':
                country = self.get_country(ip)
                if country:
                    countries[country] = countries.get(country, 0) + 1
                    hop_countries[hop['hop_number']] = country

        issues = []
        unique_countries = set(countries.keys())

        if len(unique_countries) > 4:
            issues.append({
                'type': 'too_many_countries',
                'hop_number': max(hop_countries.keys()) if hop_countries else 1,
                'message': f'Маршрут проходит через {len(unique_countries)} стран',
                'countries': list(unique_countries)
            })

        return {
            'hop_countries': hop_countries,
            'unique_countries': unique_countries,
            'issues': issues
        }