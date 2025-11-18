import requests
import time
from typing import Dict, List, Optional


class GeoIP:
    def __init__(self):
        self.cache = {}

    def get_country(self, ip_address: str) -> Optional[str]:
        """Получает страну по IP"""
        if not ip_address or ip_address == '*':
            return None

        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=3)

            if response.status_code == 200:
                data = response.json()
                country = data.get('country')

                self.cache[ip_address] = country
                time.sleep(0.1)
                return country

        except Exception:
            pass

        return None

    def analyze_countries(self, hops: List[Dict]) -> Dict:
        """Анализирует страны маршрута"""
        countries = {}
        hop_countries = {}

        # Собираем страны
        for hop in hops:
            ip = hop.get('ip_address')
            if ip and ip != '*':
                country = self.get_country(ip)
                if country:
                    countries[country] = countries.get(country, 0) + 1
                    hop_countries[hop['hop_number']] = country

        # Проверяем аномалии
        issues = []
        unique_countries = set(countries.keys())

        # Слишком много стран
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