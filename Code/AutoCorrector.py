import re
from typing import List, Tuple, Dict


class TracerouteAutoCorrector:
    def __init__(self):
        self.corrections_applied = []

    def correct(self, traceroute_output: str) -> Tuple[str, List[str]]:
        original_lines = traceroute_output.split('\n')
        corrected_lines = []
        self.corrections_applied = []

        for i, line in enumerate(original_lines, 1):
            corrected_line = self._smart_correct_line(line, i)
            corrected_lines.append(corrected_line)

        return '\n'.join(corrected_lines), self.corrections_applied

    def _smart_correct_line(self, line: str, line_num: int) -> str:
        original = line.rstrip()
        if not original:
            return line

        initial_spaces = len(line) - len(line.lstrip())

        working_line = original.strip()

        working_line = self._fix_obvious_errors(working_line, line_num)

        words = working_line.split()
        if not words:
            return line

        if words[0].isdigit() and len(words) > 1:
            working_line = self._process_hop_line(words, line_num)
        elif 'traceroute' in working_line.lower():
            working_line = self._fix_header(working_line, line_num)
        else:
            pass

        return ' ' * initial_spaces + working_line

    def _fix_obvious_errors(self, line: str, line_num: int) -> str:
        fixed = line

        if 'timeout' in fixed.lower() and '*' not in fixed:
            fixed = re.sub(r'timeout', '*', fixed, flags=re.IGNORECASE)
            self._add_fix(line_num, "Заменен 'timeout' на '*'")

        fixed = re.sub(r'^(\d+)ms\b', r'\1', fixed)
        if fixed != line:
            self._add_fix(line_num, "Удален 'ms' из номера прыжка")

        fixed = re.sub(r'\s+ms\b', 'ms', fixed)  # "30.123 ms" → "30.123ms"
        fixed = re.sub(r'\bms\s+ms', 'ms', fixed)  # "30.456ms ms" → "30.456ms"

        if 'traceroute' in fixed.lower():
            fixed = re.sub(r'(\d+)ms(\s+hops)', r'\1\2', fixed, flags=re.IGNORECASE)
            fixed = re.sub(r'(\d+)ms(\s+byte)', r'\1\2', fixed, flags=re.IGNORECASE)
            ip_match = re.search(r'\(([^)]+)\)', fixed)
            if ip_match:
                ip_text = ip_match.group(1)
                if 'ms' in ip_text:
                    clean_ip = ip_text.replace('ms', '')
                    fixed = fixed.replace(ip_text, clean_ip)
                    self._add_fix(line_num, f"Очищен IP в заголовке: {clean_ip}")

        return fixed

    def _process_hop_line(self, words: List[str], line_num: int) -> str:
        hop_number = words[0]

        if hop_number.endswith('ms'):
            hop_number = hop_number.replace('ms', '')
            self._add_fix(line_num, f"Очищен номер прыжка: {hop_number}")

        result_parts = [hop_number]
        i = 1
        if i < len(words):
            current_word = words[i]
            if self._is_valid_ip(current_word):
                ip_address = current_word
                result_parts.append(ip_address)
                i += 1

                if i < len(words) and words[i].startswith('(') and words[i].endswith(')'):
                    ip_in_brackets = words[i].strip('()')
                    if ip_in_brackets == ip_address:
                        result_parts.append(words[i])
                        i += 1
                    else:
                        result_parts.append(f"({ip_address})")
                        self._add_fix(line_num, f"Исправлены скобки для IP: {ip_address}")
                        i += 1
                else:
                    result_parts.append(f"({ip_address})")
                    self._add_fix(line_num, f"Добавлены скобки для IP: {ip_address}")
            else:
                result_parts.append(current_word)
                i += 1

        times = []
        while i < len(words):
            word = words[i]

            if word == '*':
                times.append('*')
            elif self._looks_like_time(word):
                clean_time = re.sub(r'(ms)+$', 'ms', word)
                if not clean_time.endswith('ms'):
                    clean_time += 'ms'
                    self._add_fix(line_num, f"Добавлено 'ms' к времени: {word}")
                times.append(clean_time)
            else:
                times.append(word)

            i += 1

        result_parts.extend(times)

        time_count = sum(1 for t in times if t != '*')
        if time_count < 3 and len(times) < 3:
            for _ in range(3 - len(times)):
                result_parts.append('*')
                self._add_fix(line_num, "Добавлен недостающий таймаут")

        return ' '.join(result_parts)

    def _fix_header(self, line: str, line_num: int) -> str:
        patterns_to_fix = [
            (r'(\d+)ms(\s+hops)', r'\1\2'),  # 30ms hops → 30 hops
            (r'(\d+)ms(\s+byte)', r'\1\2'),  # 60ms byte → 60 byte
        ]

        fixed = line
        for pattern, replacement in patterns_to_fix:
            new_fixed = re.sub(pattern, replacement, fixed, flags=re.IGNORECASE)
            if new_fixed != fixed:
                self._add_fix(line_num, "Исправлен заголовок")
                fixed = new_fixed

        ip_match = re.search(r'\(([^)]+)\)', fixed)
        if ip_match:
            ip_text = ip_match.group(1)
            if 'ms' in ip_text:
                clean_ip = ip_text.replace('ms', '')
                fixed = fixed.replace(ip_text, clean_ip)
                self._add_fix(line_num, f"Очищен IP в заголовке: {clean_ip}")

        return fixed

    def _is_valid_ip(self, text: str) -> bool:
        if not text or text == '*':
            return False

        clean_text = text.replace('ms', '')
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ip_pattern, clean_text):
            return False

        try:
            octets = clean_text.split('.')
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return False
            return True
        except:
            return False

    def _looks_like_time(self, text: str) -> bool:
        if not text or text == '*':
            return False

        clean_text = re.sub(r'ms$', '', text)

        clean_text = re.sub(r'[^\d.]', '', clean_text)

        if not clean_text:
            return False

        try:
            value = float(clean_text)
            return 0.01 <= value <= 5000
        except:
            return False

    def _add_fix(self, line_num: int, message: str):
        self.corrections_applied.append(f"Строка {line_num}: {message}")
