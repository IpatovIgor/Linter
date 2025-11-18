import sys
import unittest
import os
import tempfile
from Code.ParserClass import *
from Code.TracerouteAnalyzerClass import *


class TestTracerouteParser(unittest.TestCase):

    def setUp(self):
        self.parser = TracerouteParser()

    def test_parse_normal_trace(self):
        """Тест парсинга нормальной трассировки"""
        trace_output = """traceroute to google.com (142.250.150.101), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.678 ms
 2  10.10.10.1 (10.10.10.1)  5.678 ms  5.789 ms  5.901 ms
 3  72.14.215.25 (72.14.215.25)  15.234 ms  15.456 ms  15.678 ms"""

        success = self.parser.parse_output(trace_output)
        self.assertTrue(success)
        self.assertEqual(len(self.parser.hops), 3)
        self.assertEqual(self.parser.target_host, "google.com")
        self.assertEqual(self.parser.target_ip, "142.250.150.101")

    def test_parse_with_timeouts(self):
        """Тест парсинга трассировки с таймаутами"""
        trace_output = """traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  * * *
 3  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms
 4  93.184.216.34 (93.184.216.34)  25.1 ms  25.3 ms  25.5 ms"""

        success = self.parser.parse_output(trace_output)
        self.assertTrue(success)
        self.assertEqual(len(self.parser.hops), 4)

        # Проверяем что таймаут правильно распознан
        timeout_hop = self.parser.hops[1]  # Прыжок 2
        self.assertEqual(timeout_hop['type'], 'timeout')
        self.assertEqual(timeout_hop['packet_loss'], 100.0)

    def test_parse_partial_timeout(self):
        """Тест парсинга частичных таймаутов"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  *  1.8 ms
 2  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  *"""

        success = self.parser.parse_output(trace_output)
        self.assertTrue(success)

        # Проверяем частичные потери (округление до 1 знака)
        hop1 = self.parser.hops[0]
        self.assertEqual(hop1['type'], 'partial')
        self.assertAlmostEqual(hop1['packet_loss'], 33.3, places=1)  # 1 из 3 пакетов потерян

        hop2 = self.parser.hops[1]
        self.assertAlmostEqual(hop2['packet_loss'], 33.3, places=1)

    def test_parse_invalid_format(self):
        """Тест обработки некорректного формата"""
        trace_output = """invalid traceroute output
some random text
another line"""

        success = self.parser.parse_output(trace_output)
        # Парсер пропускает строки не начинающиеся с цифр или traceroute
        # поэтому он считает это успешным парсингом (но без данных)
        self.assertTrue(success)
        self.assertEqual(len(self.parser.hops), 0)
        self.assertEqual(len(self.parser.errors), 0)


    def test_validate_structure_good(self):
        """Тест валидации корректной структуры"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms
 3  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms"""

        self.parser.parse_output(trace_output)
        warnings = self.parser.validate_structure()
        self.assertEqual(len(warnings), 0)

    def test_validate_structure_bad(self):
        """Тест валидации некорректной структуры"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 1  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms  # Дублирующийся номер
 3  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms"""

        self.parser.parse_output(trace_output)
        warnings = self.parser.validate_structure()
        self.assertEqual(len(warnings), 1)
        self.assertIn("последовательность", warnings[0])


class TestTracerouteAnalyzer(unittest.TestCase):
    """Тесты для анализатора traceroute"""

    def setUp(self):
        self.parser = TracerouteParser()
        self.analyzer = TracerouteAnalyzer()

    def test_high_latency_detection(self):
        """Тест обнаружения высокой задержки"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  10.10.10.1 (10.10.10.1)  250.1 ms  251.3 ms  252.5 ms  # Высокая задержка
 3  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms"""

        self.parser.parse_output(trace_output)
        issues = self.analyzer.analyze(self.parser)

        high_latency_issues = [i for i in issues if i['type'] == 'high_latency']
        self.assertEqual(len(high_latency_issues), 1)
        self.assertEqual(high_latency_issues[0]['hop_number'], 2)


    def test_routing_loop_detection(self):
        """Тест обнаружения петель маршрутизации"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms
 3  192.168.1.1 (192.168.1.1)  15.1 ms  15.3 ms  15.5 ms  # Петля!
 4  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms"""

        self.parser.parse_output(trace_output)
        issues = self.analyzer.analyze(self.parser)

        loop_issues = [i for i in issues if i['type'] == 'routing_loop']
        self.assertEqual(len(loop_issues), 1)
        self.assertIn("Петля", loop_issues[0]['message'])
        self.assertEqual(loop_issues[0]['hop_number'], 3)

    def test_no_issues(self):
        """Тест когда проблем нет"""
        trace_output = """traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms
 3  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms"""

        self.parser.parse_output(trace_output)
        issues = self.analyzer.analyze(self.parser)

        self.assertEqual(len(issues), 0)


class TestIntegration(unittest.TestCase):
    """Интеграционные тесты"""

    def test_end_to_end_analysis(self):
        """Полный тест от парсинга до анализа"""
        trace_output = """traceroute to problem-site.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  10.10.10.1 (10.10.10.1)  5.1 ms  5.3 ms  5.6 ms
 3  10.10.10.1 (10.10.10.1)  15.1 ms  15.3 ms  15.5 ms  # Петля
 4  * * *  # Таймаут
 5  1.2.3.4 (1.2.3.4)  250.1 ms  251.3 ms  252.5 ms  # Высокая задержка"""

        parser = TracerouteParser()
        success = parser.parse_output(trace_output)
        self.assertTrue(success)

        analyzer = TracerouteAnalyzer()
        issues = analyzer.analyze(parser)

        # Должны найти 3 проблемы: петля, таймаут, высокая задержка
        self.assertEqual(len(issues), 3)

        issue_types = [issue['type'] for issue in issues]
        self.assertIn('routing_loop', issue_types)
        self.assertIn('packet_loss', issue_types)
        self.assertIn('high_latency', issue_types)


class TestFileHandling(unittest.TestCase):
    """Тесты работы с файлами"""

    def test_file_parsing(self):
        """Тест чтения и парсинга из файла"""
        # Создаем временный файл
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("""traceroute to test.com (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.2 ms  1.5 ms  1.8 ms
 2  1.2.3.4 (1.2.3.4)  25.1 ms  25.3 ms  25.5 ms""")
            temp_file = f.name

        try:
            # Читаем и парсим файл
            with open(temp_file, 'r') as f:
                content = f.read()

            parser = TracerouteParser()
            success = parser.parse_output(content)

            self.assertTrue(success)
            self.assertEqual(len(parser.hops), 2)

        finally:
            # Удаляем временный файл
            os.unlink(temp_file)


if __name__ == '__main__':
    print("🧪 Запуск тестов Traceroute Linter...")
    print("=" * 50)

    # Запускаем тесты
    unittest.main(verbosity=2)
