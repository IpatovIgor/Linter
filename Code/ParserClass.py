import re
from typing import List, Dict
from collections import defaultdict


class TracerouteParser:
    def __init__(self):
        self.hops = []
        self.errors = []
        self.warnings = []
        self.target_host = None
        self.target_ip = None
        self.max_hops = 30
        self.complexity_metrics = {}

    def parse_output(self, traceroute_output: str) -> bool:
        lines = traceroute_output.strip().split('\n')
        parsing_success = True

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            if not line[0].isdigit() and not line.startswith('traceroute'):
                continue

            parsed = self._parse_line(line, line_num)
            if not parsed:
                self.errors.append(f"Строка {line_num}: Неизвестный формат - '{line}'")
                parsing_success = False

        if self.hops:
            self._calculate_complexity_metrics()

        return parsing_success

    def _parse_line(self, line: str, line_num: int) -> bool:
        if line.startswith('traceroute to'):
            return self._parse_header(line)

        if not line.strip():
            return True

        parts = line.split()
        if len(parts) < 2:
            return False

        if not parts[0].isdigit():
            return False

        hop_number = int(parts[0])

        if len(parts) == 2 and parts[1] == '*':
            # Формат: "5  *"
            return self._parse_simple_timeout(hop_number, line_num)
        elif len(parts) == 4 and all(p == '*' for p in parts[1:]):
            # Формат: "5  *  *  *"
            return self._parse_full_timeout(hop_number, line_num)
        else:
            # Сложный формат с IP и временами
            return self._parse_complex_format(hop_number, line_num, line)

    def _parse_header(self, line: str) -> bool:
        parts = line.split()
        if len(parts) >= 4:
            self.target_host = parts[2]
            ip_match = re.search(r'\(([\d\.]+)\)', line)
            if ip_match:
                self.target_ip = ip_match.group(1)

            hops_match = re.search(r'(\d+)\s+hops max', line)
            if hops_match:
                self.max_hops = int(hops_match.group(1))
        return True

    def _parse_simple_timeout(self, hop_number: int, line_num: int) -> bool:
        hop_data = {
            'line_number': line_num,
            'hop_number': hop_number,
            'hostname': '*',
            'ip_address': None,
            'times': [None, None, None],
            'type': 'timeout',
            'packet_loss': 100.0
        }
        self.hops.append(hop_data)
        return True

    def _parse_full_timeout(self, hop_number: int, line_num: int) -> bool:
        hop_data = {
            'line_number': line_num,
            'hop_number': hop_number,
            'hostname': '*',
            'ip_address': None,
            'times': [None, None, None],
            'type': 'timeout',
            'packet_loss': 100.0
        }
        self.hops.append(hop_data)
        return True

    def _parse_complex_format(self, hop_number: int, line_num: int, original_line: str) -> bool:
        ip_address = None
        hostname = None

        ip_match = re.search(r'\(([\d\.]+)\)', original_line)
        if ip_match:
            ip_address = ip_match.group(1)
            hostname_match = re.search(r'(\S+)\s+\([\d\.]+\)', original_line)
            if hostname_match:
                hostname = hostname_match.group(1)

        if not ip_address:
            ip_match = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', original_line)
            if ip_match and ip_match.group(1) != '0.0.0.0':
                ip_address = ip_match.group(1)
                hostname = ip_address

        times = []
        time_matches = re.findall(r'([\d\.]+)\s*ms|\*', original_line)

        if time_matches:
            times = list(time_matches)
        else:
            star_count = original_line.count('*')
            if star_count > 0:
                times = ['*'] * star_count

        while len(times) < 3:
            times.append('*')

        converted_times = []
        for time_str in times:
            if time_str == '*':
                converted_times.append(None)
            else:
                try:
                    converted_times.append(float(time_str))
                except ValueError:
                    converted_times.append(None)

        packet_loss = (converted_times.count(None) / len(converted_times)) * 100

        if packet_loss == 100:
            hop_type = 'timeout'
        elif packet_loss > 0:
            hop_type = 'partial'
        else:
            hop_type = 'standard'

        hop_data = {
            'line_number': line_num,
            'hop_number': hop_number,
            'hostname': hostname or ip_address or '*',
            'ip_address': ip_address,
            'times': converted_times,
            'type': hop_type,
            'packet_loss': packet_loss
        }

        self.hops.append(hop_data)
        return True

    def _calculate_complexity_metrics(self):
        unique_ips = set()
        country_changes = 0
        timeout_count = 0
        packet_loss_total = 0

        prev_ip = None
        for hop in self.hops:
            ip = hop.get('ip_address')
            if ip and ip != '*':
                unique_ips.add(ip)

            if hop['type'] == 'timeout':
                timeout_count += 1

            packet_loss_total += hop['packet_loss']

            if ip and prev_ip and ip != prev_ip:
                if ip.split('.')[0] != prev_ip.split('.')[0]:
                    country_changes += 1

        self.complexity_metrics = {
            'unique_nodes': len(unique_ips),
            'timeout_percentage': (timeout_count / len(self.hops)) * 100,
            'avg_packet_loss': packet_loss_total / len(self.hops),
            'route_changes': country_changes,
            'hop_count': len(self.hops),
            'is_complex': len(unique_ips) < len(self.hops) * 0.7
        }

    def validate_structure(self) -> List[str]:
        warnings = []

        if not self.hops:
            warnings.append("Не найдено данных о маршруте")
            return warnings

        hop_numbers = [hop['hop_number'] for hop in self.hops]
        expected_sequence = list(range(1, len(hop_numbers) + 1))

        if hop_numbers != expected_sequence:
            warnings.append(f"Нарушена последовательность прыжков: {hop_numbers}")

        return warnings

    def get_summary(self) -> Dict:
        if not self.hops:
            return {}

        total_hops = len(self.hops)
        timeout_hops = len([h for h in self.hops if h['packet_loss'] == 100])
        successful_hops = len([h for h in self.hops if h['packet_loss'] == 0])

        all_times = []
        for hop in self.hops:
            valid_times = [t for t in hop['times'] if t is not None]
            if valid_times:
                all_times.extend(valid_times)

        avg_latency = sum(all_times) / len(all_times) if all_times else 0

        return {
            'target_host': self.target_host,
            'target_ip': self.target_ip,
            'total_hops': total_hops,
            'successful_hops': successful_hops,
            'timeout_hops': timeout_hops,
            'average_latency': avg_latency,
            'max_latency': max(all_times) if all_times else 0,
            'parsing_errors': len(self.errors),
            'complexity_score': self.complexity_metrics.get('unique_nodes', 0),
            'route_complexity': 'высокая' if self.complexity_metrics.get('is_complex', False) else 'низкая'
        }