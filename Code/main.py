#!/usr/bin/env python3
"""
Traceroute Linter - простая версия
"""

import sys
import os
from ParserClass import TracerouteParser
from TracerouteAnalyzerClass import TracerouteAnalyzer


def main():
    file_path = '../my_traceroute'

    if not os.path.exists(file_path):
        print(f"❌ Файл '{file_path}' не существует")
        sys.exit(1)

    print(f"🔍 Анализируем: {file_path}")
    print("=" * 50)

    try:
        with open(file_path, 'r') as file:
            traceroute_output = file.read()
    except Exception as e:
        print(f"❌ Ошибка чтения: {e}")
        sys.exit(1)

    # Парсим
    parser = TracerouteParser()
    if not parser.parse_output(traceroute_output):
        print("❌ Ошибки парсинга:")
        for error in parser.errors:
            print(f"   - {error}")
        sys.exit(1)

    print("✅ Парсинг завершен")

    # Проверяем структуру
    structure_warnings = parser.validate_structure()
    if structure_warnings:
        print("⚠️  Предупреждения структуры:")
        for warning in structure_warnings:
            print(f"   - {warning}")
        print()

    # Анализируем
    analyzer = TracerouteAnalyzer()
    issues = analyzer.analyze(parser)
    analyzer.print_report(parser)

    # Итог
    total_issues = len(issues) + len(structure_warnings)
    print(f"\n🎯 Итого проблем: {total_issues}")


if __name__ == "__main__":
    main()