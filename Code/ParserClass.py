import re
from typing import List, Dict


class TracerouteParser:
    def __init__(self):
        self.hops = []
        self.errors = []
        self.target_host = None
        self.target_ip = None
        self.max_hops = 30

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

        return parsing_success

    def _parse_line(self, line: str, line_num: int) -> bool:
        # Проверяем заголовок
        if line.startswith('traceroute to'):
            return self._parse_header(line)

        # Пропускаем пустые строки
        if not line.strip():
            return True

        # Разбиваем строку на части
        parts = line.split()
        if len(parts) < 2:
            return False

        # Первая часть должна быть номером прыжка
        if not parts[0].isdigit():
            return False

        hop_number = int(parts[0])

        # Анализируем остальные части
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
            # Извлекаем IP из скобок
            ip_match = re.search(r'\(([\d\.]+)\)', line)
            if ip_match:
                self.target_ip = ip_match.group(1)

            # Ищем максимальное количество прыжков
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

        # Ищем IP адрес в скобках
        ip_match = re.search(r'\(([\d\.]+)\)', original_line)
        if ip_match:
            ip_address = ip_match.group(1)
            # Ищем hostname перед скобками
            hostname_match = re.search(r'(\S+)\s+\([\d\.]+\)', original_line)
            if hostname_match:
                hostname = hostname_match.group(1)

        # Если не нашли IP в скобках, ищем IP в строке
        if not ip_address:
            ip_match = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', original_line)
            if ip_match and ip_match.group(1) != '0.0.0.0':
                ip_address = ip_match.group(1)
                hostname = ip_address

        # Ищем времена - используем регулярное выражение для поиска чисел с 'ms'
        times = []
        time_matches = re.findall(r'([\d\.]+)\s*ms|\*', original_line)

        if time_matches:
            times = list(time_matches)
        else:
            # Если не нашли времена, проверяем звездочки
            star_count = original_line.count('*')
            if star_count > 0:
                times = ['*'] * star_count

        # Дополняем времена до 3 попыток если нужно
        while len(times) < 3:
            times.append('*')

        # Создаем данные прыжка
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

        # Определяем тип прыжка
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

    def validate_structure(self) -> List[str]:
        warnings = []

        if not self.hops:
            warnings.append("Не найдено данных о маршруте")
            return warnings

        # Проверяем последовательность номеров прыжков
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

        # Считаем среднюю задержку (игнорируя таймауты)
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
            'parsing_errors': len(self.errors)
        }
