import sys
import os
import time
from ParserClass import TracerouteParser
from TracerouteAnalyzerClass import TracerouteAnalyzer
from AutoCorrector import TracerouteAutoCorrector
AUTOCORRECTOR_AVAILABLE = True


def main():
    print("=== Анализатор Traceroute с автокоррекцией ===")
    print()

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"\n📁 Использую файл из аргумента: {file_path}")
    else:
        print("\n📁 Файлы в текущей папке:")
        files = [f for f in os.listdir('.') if f.endswith(('.txt', '.log', '')) and not f.startswith('.')]

        for i, f in enumerate(files[:10], 1):
            print(f"  {i}. {f}")

        print("\nВыберите файл:")
        print("  1. Ввести имя файла")
        print("  2. Использовать my_traceroute")

        choice = input("\nВаш выбор [1/2]: ").strip()

        if choice == "1":
            file_path = input("Введите имя файла: ").strip()
        else:
            file_path = "my_traceroute"

    if not os.path.exists(file_path):
        print(f"❌ Файл '{file_path}' не существует!")
        return

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            original_content = file.read()
    except Exception as e:
        print(f"❌ Ошибка чтения файла: {e}")
        return

    print(f"\n{'=' * 60}")
    print(f"📄 ФАЙЛ: {file_path}")
    print(f"📏 Строк: {len(original_content.splitlines())}")
    print("=" * 60)

    use_autocorrect = False
    if AUTOCORRECTOR_AVAILABLE:
        autocorrect_choice = input("\n⚡ Применить автокоррекцию? [Y/n]: ").strip().lower()
        use_autocorrect = autocorrect_choice != 'n'
    else:
        print("\n⚠️  Автокорректор недоступен.")

    content_to_analyze = original_content
    applied_fixes = []
    corrected_file_path = None

    if use_autocorrect and AUTOCORRECTOR_AVAILABLE:
        print("\n🔧 Применяю автокоррекцию...")
        corrector = TracerouteAutoCorrector()
        content_to_analyze, applied_fixes = corrector.correct(original_content)

        if applied_fixes:
            print(f"✅ Исправлено {len(applied_fixes)} ошибок")
            for fix in applied_fixes[:3]:
                print(f"  • {fix}")
            if len(applied_fixes) > 3:
                print(f"  ... и ещё {len(applied_fixes) - 3}")

            save_choice = input("\n💾 Сохранить исправленный файл? [Y/n]: ").strip().lower()
            if save_choice != 'n':
                base_name = os.path.splitext(file_path)[0]
                extension = os.path.splitext(file_path)[1] or '.txt'
                corrected_file_path = f"{base_name}_CORRECTED{extension}"

                try:
                    with open(corrected_file_path, 'w', encoding='utf-8') as f:
                        f.write(content_to_analyze)
                    print(f"✅ Исправленный файл сохранен: {corrected_file_path}")

                    print("\n🔍 СРАВНЕНИЕ (первые 3 строки):")
                    original_lines = original_content.split('\n')
                    corrected_lines = content_to_analyze.split('\n')

                    for i in range(min(3, len(original_lines), len(corrected_lines))):
                        if original_lines[i] != corrected_lines[i]:
                            print(f"\n  Строка {i + 1}:")
                            print(f"    БЫЛО: {original_lines[i][:50]}...")
                            print(f"    СТАЛО: {corrected_lines[i][:50]}...")

                except Exception as e:
                    print(f"❌ Ошибка сохранения: {e}")
        else:
            print("✅ Ошибок не найдено")

    print(f"\n{'=' * 60}")
    print("🚀 ЗАПУСК АНАЛИЗА...")
    print("=" * 60)

    start_time = time.time()

    parser = TracerouteParser()
    parse_success = parser.parse_output(content_to_analyze)

    if not parse_success:
        print("❌ Ошибки парсинга:")
        for error in parser.errors[:5]:
            print(f"  • {error}")

        if use_autocorrect and applied_fixes:
            print("\n⚠️  Автокоррекция не помогла исправить все ошибки")
        elif AUTOCORRECTOR_AVAILABLE and not use_autocorrect:
            print("\n💡 Попробуйте включить автокоррекцию!")

        return

    parse_time = time.time() - start_time
    print(f"✅ Парсинг завершен за {parse_time:.2f} сек")
    print(f"📊 Найдено прыжков: {len(parser.hops)}")

    analyzer = TracerouteAnalyzer(enable_geo=False)
    issues = analyzer.analyze(parser)

    print("\n" + "=" * 60)
    analyzer.print_report(parser)
    print("=" * 60)

    report_choice = input("\n📄 Сохранить отчет анализа в файл? [Y/n]: ").strip().lower()
    if report_choice != 'n':
        base_name = os.path.splitext(file_path)[0]
        report_file_path = f"{base_name}_REPORT.txt"

        try:
            with open(report_file_path, 'w', encoding='utf-8') as f:
                f.write(f"ОТЧЕТ АНАЛИЗА TRACEROUTE\n")
                f.write(f"Файл: {file_path}\n")
                f.write(f"Время анализа: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                if corrected_file_path:
                    f.write(f"Исправленный файл: {corrected_file_path}\n")
                    f.write(f"Исправлений: {len(applied_fixes)}\n")

                f.write("=" * 60 + "\n\n")

                summary = parser.get_summary()
                if summary:
                    f.write("📊 СВОДКА:\n")
                    f.write(f"  Цель: {summary['target_host']} ({summary['target_ip']})\n")
                    f.write(f"  Прыжков: {summary['total_hops']}\n")
                    f.write(f"  Средняя задержка: {summary['average_latency']:.1f} мс\n")
                    f.write(f"  Таймауты: {summary['timeout_hops']} прыжков\n")
                    f.write(f"  Сложность маршрута: {summary['route_complexity']}\n\n")

                f.write("📈 ДЕТАЛИ ПРЫЖКОВ:\n")
                for hop in parser.hops:
                    if hop['type'] == 'timeout':
                        f.write(f"  {hop['hop_number']:2d}. Таймаут (потеряно 100% пакетов)\n")
                    else:
                        valid_times = [t for t in hop['times'] if t is not None]
                        if valid_times:
                            avg_time = sum(valid_times) / len(valid_times)
                            loss_percent = hop['packet_loss']
                            status = "OK" if loss_percent == 0 else "WARN" if loss_percent < 50 else "ERROR"
                            ip_display = hop['ip_address'] if hop['ip_address'] else "Unknown"
                            f.write(
                                f"  {hop['hop_number']:2d}. {status:4} {ip_display:15} - {avg_time:5.1f} мс (потерь: {loss_percent:.0f}%)\n")

                f.write("\n" + "=" * 60 + "\n")
                f.write("⚠️  ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:\n")

                if issues:
                    for issue in issues:
                        if issue['hop_number'] == 0:
                            f.write(f"  • {issue['message']}\n")
                        else:
                            f.write(f"  • {issue['message']} (прыжок {issue['hop_number']})\n")
                else:
                    f.write("  ✅ Критических проблем не обнаружено\n")

                f.write("\n" + "=" * 60 + "\n")
                f.write("📊 СТАТИСТИКА:\n")
                total_time = time.time() - start_time
                f.write(f"  Время анализа: {total_time:.2f} сек\n")
                f.write(f"  Исправлений: {len(applied_fixes)}\n")
                f.write(f"  Проблем в маршруте: {len(issues)}\n")
                f.write(f"  Успешных прыжков: {len([h for h in parser.hops if h['packet_loss'] == 0])}\n")

            print(f"✅ Отчет сохранен в файл: {report_file_path}")

        except Exception as e:
            print(f"❌ Ошибка сохранения отчета: {e}")

    total_time = time.time() - start_time

    print(f"\n📊 ФИНАЛЬНАЯ СТАТИСТИКА:")
    print(f"  ⏱️  Время анализа: {total_time:.2f} сек")
    print(f"  🔧 Исправлений: {len(applied_fixes)}")
    print(f"  🎯 Проблем в маршруте: {len(issues)}")

    if corrected_file_path:
        print(f"  💾 Исправленный файл: {corrected_file_path}")

    if issues:
        print(f"\n⚠️  Найдены проблемы в маршруте!")
    else:
        print(f"\n✅ Маршрут в порядке!")

    print("\n" + "=" * 60)
    print("🎯 АНАЛИЗ ЗАВЕРШЕН")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Прервано")
    except Exception as e:
        print(f"\n💥 Ошибка: {e}")

    input("\nНажмите Enter для выхода...")