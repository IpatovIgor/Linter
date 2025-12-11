from typing import List, Dict


class TracerouteAnalyzer:
    def __init__(self, enable_geo=False):
        self.issues = []
        self.geoip = None
        self.route_complexity_warnings = []

        if enable_geo:
            try:
                try:
                    from Code.Geo import GeoIP
                except ImportError:
                    from Geo import GeoIP
                self.geoip = GeoIP(enabled=True)
                print("✅ Геолокация включена")
            except ImportError as e:
                print(f"⚠️  Геолокация недоступна: {e}")
                self.geoip = None
        else:
            class DummyGeoIP:
                def analyze_countries(self, hops):
                    return {'hop_countries': {}, 'unique_countries': set(), 'issues': []}

            self.geoip = DummyGeoIP()

    def analyze(self, parser) -> List[Dict]:
        self.issues = []
        self.route_complexity_warnings = []

        self._check_high_latency(parser.hops)
        self._check_packet_loss(parser.hops)
        self._check_routing_loops(parser.hops)

        self._check_route_complexity(parser)

        if self.geoip:
            geo_result = self.geoip.analyze_countries(parser.hops)
            self.issues.extend(geo_result['issues'])

        all_issues = self.issues.copy()
        all_issues.extend(self.route_complexity_warnings)

        return all_issues

    def _check_high_latency(self, hops: List[Dict]):
        for hop in hops:
            if hop['type'] == 'timeout':
                continue

            valid_times = [t for t in hop['times'] if t is not None]
            if not valid_times:
                continue

            max_time = max(valid_times)
            if max_time > 200:
                self.issues.append({
                    'type': 'high_latency',
                    'hop_number': hop['hop_number'],
                    'message': f'Высокая задержка: {max_time:.0f} мс'
                })

    def _check_packet_loss(self, hops: List[Dict]):
        for hop in hops:
            if hop['packet_loss'] > 50:
                self.issues.append({
                    'type': 'packet_loss',
                    'hop_number': hop['hop_number'],
                    'message': f'Потери пакетов: {hop["packet_loss"]:.0f}%'
                })

    def _check_routing_loops(self, hops: List[Dict]):
        seen_ips = {}

        for hop in hops:
            ip = hop['ip_address']
            if not ip or ip == '*':
                continue

            if ip in seen_ips:
                self.issues.append({
                    'type': 'routing_loop',
                    'hop_number': hop['hop_number'],
                    'message': f'Петля: IP {ip} повторяется'
                })
            else:
                seen_ips[ip] = True

    def _check_route_complexity(self, parser):
        metrics = parser.complexity_metrics

        unique_nodes = metrics.get('unique_nodes', 0)
        total_hops = len(parser.hops)

        if total_hops > 0 and unique_nodes < total_hops * 0.5:
            self.route_complexity_warnings.append({
                'type': 'low_diversity',
                'hop_number': 0,
                'message': f'Низкое разнообразие маршрута: {unique_nodes} уникальных узлов из {total_hops} прыжков'
            })

        timeout_percentage = metrics.get('timeout_percentage', 0)
        if timeout_percentage > 30:
            self.route_complexity_warnings.append({
                'type': 'high_timeout_rate',
                'hop_number': 0,
                'message': f'Высокий процент таймаутов: {timeout_percentage:.1f}%'
            })

        avg_packet_loss = metrics.get('avg_packet_loss', 0)
        if avg_packet_loss > 20:
            self.route_complexity_warnings.append({
                'type': 'high_packet_loss',
                'hop_number': 0,
                'message': f'Высокие средние потери пакетов: {avg_packet_loss:.1f}%'
            })

        route_changes = metrics.get('route_changes', 0)
        if route_changes > 5:
            self.route_complexity_warnings.append({
                'type': 'frequent_route_changes',
                'hop_number': 0,
                'message': f'Частые изменения маршрута: {route_changes} раз'
            })

        if metrics.get('is_complex', False):
            self.route_complexity_warnings.append({
                'type': 'complex_route',
                'hop_number': 0,
                'message': 'Сложный маршрут (много повторяющихся узлов)'
            })

    def _get_warnings(self, hops):
        warnings = []

        total_time = 0
        valid_hops = 0
        for hop in hops:
            if hop['type'] != 'timeout':
                valid_times = [t for t in hop['times'] if t is not None]
                if valid_times:
                    total_time += sum(valid_times) / len(valid_times)
                    valid_hops += 1

        if valid_hops > 0:
            avg_time = total_time / valid_hops
            if avg_time > 100:
                warnings.append(f"Высокое среднее время: {avg_time:.1f} мс")

        if len(hops) > 15:
            warnings.append(f"Много прыжков: {len(hops)}")

        timeout_count = len([h for h in hops if h['type'] == 'timeout'])
        if timeout_count > 0:
            warnings.append(f"Обнаружены таймауты на {timeout_count} прыжках")

        return warnings

    def print_report(self, parser):
        print("=== АНАЛИЗ TRACEROUTE ===")

        summary = parser.get_summary()
        if summary:
            print(f"Цель: {summary['target_host']} ({summary['target_ip']})")
            print(f"Прыжков: {summary['total_hops']}")
            print(f"Средняя задержка: {summary['average_latency']:.1f} мс")
            print(f"Потери пакетов: {summary['timeout_hops']} прыжков с таймаутами")
            print(f"Сложность маршрута: {summary['route_complexity']}")

        print("\nДетали прыжков:")
        for hop in parser.hops:
            if hop['type'] == 'timeout':
                print(f"  {hop['hop_number']:2d}. Таймаут (потеряно 100% пакетов)")
            else:
                valid_times = [t for t in hop['times'] if t is not None]
                if valid_times:
                    avg_time = sum(valid_times) / len(valid_times)
                    loss_percent = hop['packet_loss']
                    status = "✅" if loss_percent == 0 else "⚠️" if loss_percent < 50 else "❌"
                    ip_display = hop['ip_address'] if hop['ip_address'] else "Unknown"
                    print(
                        f"  {hop['hop_number']:2d}. {status} {ip_display:15} - {avg_time:5.1f} мс (потерь: {loss_percent:.0f}%)")

        all_issues = self.issues + self.route_complexity_warnings
        if all_issues:
            print(f"\nОбнаружено проблем: {len(all_issues)}")
            for issue in all_issues:
                # Определяем иконку по типу проблемы
                if issue['type'] == 'routing_loop':
                    icon = "🔴"
                elif issue['type'] == 'high_latency':
                    icon = "🟡"
                elif issue['type'] == 'packet_loss':
                    icon = "🔵"
                elif 'timeout' in issue['type']:
                    icon = "⏱️"
                elif 'complex' in issue['type'] or 'diversity' in issue['type']:
                    icon = "🔄"
                else:
                    icon = "⚠️"

                hop_num = issue['hop_number']
                hop_display = f"прыжок {hop_num}" if hop_num > 0 else "весь маршрут"

                print(f"   {icon} {issue['message']} ({hop_display})")
        else:
            print(f"\n✅ Критических проблем не обнаружено!")

        warnings = self._get_warnings(parser.hops)
        if warnings:
            print(f"\nℹ️  Замечания:")
            for warning in warnings:
                print(f"   • {warning}")

        if self.geoip and hasattr(self.geoip, 'analyze_countries'):
            geo_result = self.geoip.analyze_countries(parser.hops)
            if geo_result['hop_countries']:
                print(f"\nГеография маршрута:")
                countries_hops = {}
                for hop_num, country in geo_result['hop_countries'].items():
                    if country not in countries_hops:
                        countries_hops[country] = []
                    countries_hops[country].append(hop_num)

                for country, hops_list in countries_hops.items():
                    hops_str = ", ".join(map(str, sorted(hops_list)))
                    print(f"   🌍 {country}: прыжки {hops_str}")
            elif hasattr(self.geoip, '__class__') and self.geoip.__class__.__name__ != 'DummyGeoIP':
                print(f"\nℹ️  Географическая информация недоступна")

    def get_analysis_summary(self) -> Dict:
        return {
            'total_issues': len(self.issues),
            'route_warnings': len(self.route_complexity_warnings),
            'has_high_latency': any(i['type'] == 'high_latency' for i in self.issues),
            'has_packet_loss': any(i['type'] == 'packet_loss' for i in self.issues),
            'has_routing_loops': any(i['type'] == 'routing_loop' for i in self.issues),
            'has_complex_route': any('complex' in w['type'] for w in self.route_complexity_warnings),
        }