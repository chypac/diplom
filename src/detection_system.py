"""
Система обнаружения сетевых атак

Этот модуль реализует комплексную систему для тестирования обнаружения сетевых атак.
Он объединяет анализатор трафика и симулятор атак для проверки эффективности
обнаружения различных типов сетевых атак.

Основные возможности:
1. Автоматический запуск анализатора трафика
2. Последовательная симуляция различных типов атак:
   - SYN Flood
   - UDP Flood
   - ICMP Flood
   - Port Scan
3. Мониторинг и отображение результатов в реальном времени
4. Цветной вывод для лучшей визуализации обнаруженных атак

Требования:
    - subprocess: для управления процессами
    - threading: для асинхронной работы
    - attack_simulator: для симуляции атак
    - logging: для ведения журнала
    - termcolor: для цветного вывода

Использование:
    python detection_system.py

Автор: [Агафонов Артём]
Дата создания: 2024
"""

import subprocess
import time
import sys
import threading
from attack_simulator import AttackSimulator
import logging
from termcolor import colored
import os
import datetime

# Настройка логирования
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f'detection_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DetectionSystem:
    """
    Основной класс системы обнаружения сетевых атак.
    
    Управляет процессом анализа трафика и симуляцией атак, координируя
    работу анализатора трафика и симулятора атак.
    
    Attributes:
        analyzer_process: Процесс анализатора трафика
        attack_thread: Поток для выполнения атак
        stop_flag: Флаг для остановки работы системы
    """
    
    def __init__(self):
        """Инициализация системы обнаружения."""
        self.analyzer_process = None
        self.attack_thread = None
        self.stop_flag = False

    def start_analyzer(self):
        """
        Запускает процесс анализатора трафика.
        
        Настраивает и запускает анализатор трафика в отдельном процессе,
        устанавливает потоки для мониторинга вывода и ошибок.
        
        Raises:
            Exception: При ошибке запуска анализатора
        """
        try:
            logger.info("Запуск анализатора трафика...")
            # Добавляем параметр creationflags для Windows
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            self.analyzer_process = subprocess.Popen(
                [sys.executable, "live_traffic_analyzer.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                startupinfo=startupinfo
            )
            
            time.sleep(10)  # Время на инициализацию
            logger.info("Анализатор трафика запущен")
            
            # Запуск потоков мониторинга
            threading.Thread(target=self.monitor_analyzer_output, args=(self.analyzer_process,), daemon=True).start()
            threading.Thread(target=self.monitor_analyzer_errors, args=(self.analyzer_process,), daemon=True).start()
            
        except Exception as e:
            logger.error(f"Ошибка запуска анализатора: {e}")
            sys.exit(1)

    def monitor_analyzer_output(self, process):
        """
        Мониторит и форматирует вывод анализатора трафика.
        
        Args:
            process: Процесс анализатора для мониторинга
            
        Особенности:
            - Форматирует вывод с использованием цветов
            - Специальная обработка для обнаруженных атак
            - Группировка связанной информации
        """
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.decode('utf-8', errors='replace').strip()
            if line:
                if line.startswith('[Анализатор]'):
                    logger.info(f"[Анализатор] {line[12:]}")
                elif '[!]' in line:  # Особая обработка для обнаруженных атак
                    print('\n' + '='*70)
                    print(colored(line, 'red', attrs=['bold']))
                    # Читаем следующие строки с деталями атаки
                    for _ in range(8):  # Примерное количество строк с деталями
                        detail_line = process.stdout.readline().decode('utf-8', errors='replace').strip()
                        if detail_line:
                            if 'Тип атаки:' in detail_line:
                                print(colored(detail_line, 'yellow', attrs=['bold']))
                            elif 'Уверенность:' in detail_line:
                                print(colored(detail_line, 'green', attrs=['bold']))
                            else:
                                print(detail_line)
                    print('='*70 + '\n')
                else:
                    logger.info(f"[Анализатор INFO] {line}")

    def monitor_analyzer_errors(self, process):
        """
        Мониторит и обрабатывает ошибки анализатора.
        
        Args:
            process: Процесс анализатора для мониторинга
            
        Особенности:
            - Отдельная обработка сообщений о CUDA
            - Форматирование сообщений об ошибках
        """
        while True:
            line = process.stderr.readline()
            if not line:
                break
            line = line.decode('utf-8', errors='replace').strip()
            if line:
                if "cuda" in line.lower() or "device" in line.lower():
                    logger.info(f"[Анализатор INFO] {line}")
                else:
                    logger.error(f"[Анализатор ERROR] {line}")

    def start_attack(self, attack_type, duration=10, intensity='medium'):
        """
        Запускает симуляцию выбранной атаки.
        
        Args:
            attack_type (str): Тип атаки для симуляции
            duration (int): Продолжительность атаки в секундах
            intensity (str): Интенсивность атаки ('low', 'medium', 'high')
            
        Raises:
            Exception: При ошибке запуска атаки
        """
        try:
            logger.info(f"Начало {attack_type} атаки...")
            simulator = AttackSimulator("127.0.0.1")  # Используем localhost
            self.attack_thread = simulator.start_attack(attack_type, duration, intensity)
            
        except Exception as e:
            logger.error(f"Ошибка запуска атаки: {e}")

    def run_detection(self):
        """
        Запускает полный цикл тестирования системы обнаружения.
        
        Последовательность действий:
        1. Запуск анализатора трафика
        2. Последовательная симуляция различных атак
        3. Мониторинг результатов
        4. Корректное завершение работы
        
        Особенности:
        - Увеличенная длительность и интенсивность атак для localhost
        - Паузы между атаками для лучшего анализа
        - Корректная обработка прерывания работы
        """
        try:
            # Запускаем анализатор
            self.start_analyzer()
            
            # Ждем полной инициализации
            logger.info("Ожидание инициализации анализатора...")
            time.sleep(15)
            
            # Последовательно запускаем разные типы атак
            attack_scenarios = [
                ("syn_flood", 30, "high"),
                ("udp_flood", 30, "high"),
                ("icmp_flood", 30, "high"),
                ("port_scan", 30, "high")
            ]
            
            for attack_type, duration, intensity in attack_scenarios:
                logger.info(f"\n=== Симуляция {attack_type} атаки ===")
                logger.info(f"Интенсивность: {intensity}, Продолжительность: {duration}с")
                
                self.start_attack(attack_type, duration, intensity)
                
                if self.attack_thread:
                    self.attack_thread.join()
                
                logger.info("Пауза между атаками...")
                time.sleep(10)
            
            logger.info("\nСимуляция завершена")
            
            logger.info("Нажмите Ctrl+C для завершения...")
            while True:
                time.sleep(1)
            
        except KeyboardInterrupt:
            logger.info("\nПрерывание работы...")
        finally:
            self.cleanup()

    def cleanup(self):
        """
        Выполняет корректное завершение работы системы.
        
        Особенности:
        - Установка флага остановки
        - Корректное завершение процесса анализатора
        - Обработка таймаута при завершении
        """
        self.stop_flag = True
        if self.analyzer_process:
            logger.info("Завершение работы анализатора...")
            self.analyzer_process.terminate()
            try:
                self.analyzer_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.analyzer_process.kill()

def main():
    """
    Точка входа в программу.
    
    Выводит приветственное сообщение и запускает систему обнаружения.
    """
    print("\n=== Система обнаружения сетевых атак ===")
    print("1. Будет запущен анализатор трафика")
    print("2. Последовательно будут выполнены различные типы атак")
    print("3. Результаты анализа будут выводиться в реальном времени")
    print("\nНажмите Enter для начала работы или Ctrl+C для выхода")
    
    input()
    
    system = DetectionSystem()
    system.run_detection()

if __name__ == "__main__":
    main()
