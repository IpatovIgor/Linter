from Code.Geo import *


class TracerouteAnalyzer:
    """Основной анализатор трассировки"""

    def __init__(self):
        self.issues = []
        self.geoip = GeoIP()

    def analyze(self, parser) -> List[Dict]:
        """Анализирует трассировку"""
        self.issues = []

        # Базовые проверки
        self._check_high_latency(parser.hops)
        self._check_packet_loss(parser.hops)
        self._check_routing_loops(parser.hops)

        # География
        geo_result = self.geoip.analyze_countries(parser.hops)
        self.issues.extend(geo_result['issues'])

        return self.issues

    def _check_high_latency(self, hops: List[Dict]):
        """Проверяет высокие задержки"""
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
        """Проверяет потери пакетов"""
        for hop in hops:
            if hop['packet_loss'] > 50:
                self.issues.append({
                    'type': 'packet_loss',
                    'hop_number': hop['hop_number'],
                    'message': f'Потери пакетов: {hop["packet_loss"]:.0f}%'
                })

    def _check_routing_loops(self, hops: List[Dict]):
        """Проверяет петли маршрутизации"""
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

    def _get_warnings(self, hops):
        """Возвращает информационные замечания"""
        warnings = []

        # Проверяем общее время
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

        # Проверяем количество прыжков
        if len(hops) > 15:
            warnings.append(f"Много прыжков: {len(hops)}")

        # Проверяем есть ли таймауты (но не критические)
        timeout_count = len([h for h in hops if h['type'] == 'timeout'])
        if timeout_count > 0:
            warnings.append(f"Обнаружены таймауты на {timeout_count} прыжках")

        return warnings

    def print_report(self, parser):
        """Выводит детальный отчет"""
        print("=== АНАЛИЗ TRACEROUTE ===")

        # Всегда показываем базовую информацию
        summary = parser.get_summary()
        if summary:
            print(f"🎯 Цель: {summary['target_host']} ({summary['target_ip']})")
            print(f"📊 Прыжков: {summary['total_hops']}")
            print(f"⏱️  Средняя задержка: {summary['average_latency']:.1f} мс")
            print(f"📦 Потери пакетов: {summary['timeout_hops']} прыжков с таймаутами")

        print("\n🔍 Детали прыжков:")
        for hop in parser.hops:
            if hop['type'] == 'timeout':
                print(f"  {hop['hop_number']:2d}. ❌ Таймаут (потеряно 100% пакетов)")
            else:
                valid_times = [t for t in hop['times'] if t is not None]
                if valid_times:
                    avg_time = sum(valid_times) / len(valid_times)
                    loss_percent = hop['packet_loss']
                    status = "✅" if loss_percent == 0 else "⚠️" if loss_percent < 50 else "❌"
                    print(
                        f"  {hop['hop_number']:2d}. {status} {hop['ip_address']:15} - {avg_time:5.1f} мс (потерь: {loss_percent:.0f}%)")

        # Показываем проблемы если есть
        if self.issues:
            print(f"\n🚨 Обнаружено проблем: {len(self.issues)}")
            for issue in self.issues:
                icon = "🔴" if issue['type'] == 'routing_loop' else "🟡" if issue['type'] == 'high_latency' else "🔵"
                print(f"   {icon} {issue['message']} (прыжок {issue['hop_number']})")
        else:
            print(f"\n🎉 Критических проблем не обнаружено!")

            # Все равно покажем небольшие предупреждения
            warnings = self._get_warnings(parser.hops)
            if warnings:
                print(f"💡 Замечания:")
                for warning in warnings:
                    print(f"   📝 {warning}")

        # Показываем географическую информацию если есть
        geo_result = self.geoip.analyze_countries(parser.hops)
        if geo_result['hop_countries']:
            print(f"\n🌍 География маршрута:")
            countries_hops = {}
            for hop_num, country in geo_result['hop_countries'].items():
                if country not in countries_hops:
                    countries_hops[country] = []
                countries_hops[country].append(hop_num)

            for country, hops_list in countries_hops.items():
                hops_str = ", ".join(map(str, sorted(hops_list)))
                print(f"   🇺🇳 {country}: прыжки {hops_str}")
