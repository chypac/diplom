import subprocess
import time
import sys
import threading
from attack_simulator import AttackSimulator
import logging
from termcolor import colored
import os
from networc_interface import load_model, preprocess_packet, classify_packet_detection
from scapy.all import sniff
import queue
import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Определение базовых путей
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Словарь с описаниями типов атак и их параметрами
ATTACK_TYPES = {
    'syn_flood': {
        'name': 'SYN Flood',
        'duration': 30,
        'intensity': 'high',
        'description': 'SYN флуд атака для перегрузки сервера',
        'model': 'syn_dos_model.pth'  # Используем существующую модель
    },
    'udp_flood': {
        'name': 'UDP Flood',
        'duration': 30,
        'intensity': 'high',
        'description': 'UDP флуд атака для перегрузки сети',
        'model': 'ssdp_flood_model.pth'  # Используем похожую модель
    },
    'icmp_flood': {
        'name': 'ICMP Flood',
        'duration': 30,
        'intensity': 'high',
        'description': 'ICMP флуд атака (ping flood)',
        'model': 'mirai_botnet_model.pth'  # Используем модель ботнета
    },
    'port_scan': {
        'name': 'Port Scan',
        'duration': 30,
        'intensity': 'medium',
        'description': 'Сканирование портов целевой системы',
        'model': 'os_scan_model.pth'  # Используем модель сканирования
    },
    'arp_spoof': {
        'name': 'ARP Spoofing',
        'duration': 30,
        'intensity': 'high',
        'description': 'ARP-спуфинг атака для перехвата трафика',
        'model': 'arp_mitm_model.pth'  # Используем модель ARP MitM
    }
}

class DetectionSystem:
    def __init__(self):
        self.stop_flag = False
        self.current_attack = None
        self.packet_queue = queue.Queue()
        self.detector_thread = None
        self.current_model = None
        self.current_scaler = None
        
    def load_attack_model(self, attack_type):
        """Загрузка модели для определенного типа атаки"""
        try:
            model_path = os.path.join(MODELS_DIR, ATTACK_TYPES[attack_type]['model'])
            if os.path.exists(model_path):
                logger.info(f"Загрузка модели для атаки {ATTACK_TYPES[attack_type]['name']}...")
                model, scaler = load_model(model_path)
                self.current_model = model
                self.current_scaler = scaler
                return True
            else:
                logger.warning(f"Модель для атаки {attack_type} не найдена")
                return False
        except Exception as e:
            logger.error(f"Ошибка загрузки модели: {e}")
            return False
            
    def packet_callback(self, packet):
        """Callback для обработки перехваченных пакетов"""
        self.packet_queue.put(packet)
        
    def analyze_packets(self):
        """Анализ пакетов на наличие аномалий"""
        while not self.stop_flag:
            try:
                packet = self.packet_queue.get(timeout=1)
                if self.current_model and self.current_scaler:
                    features = preprocess_packet(packet)
                    if features is not None:
                        is_anomaly = classify_packet_detection(features, self.current_model, self.current_scaler)
                        if is_anomaly:
                            logger.warning(colored(f"[!] Обнаружен аномальный пакет:", 'red'))
                            logger.warning(colored(f"    Тип атаки: {ATTACK_TYPES[self.current_attack]['name']}", 'yellow'))
                            logger.warning(colored(f"    Детали пакета: {packet.summary()}", 'yellow'))
                            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Ошибка при анализе пакета: {e}")
                
    def start_attack(self, attack_type, duration=30, intensity='high'):
        """Запуск симулированной атаки"""
        try:
            if attack_type not in ATTACK_TYPES:
                logger.error(f"Неизвестный тип атаки: {attack_type}")
                return
                
            attack_info = ATTACK_TYPES[attack_type]
            logger.info(f"\n=== Симуляция атаки {attack_info['name']} ===")
            logger.info(f"Описание: {attack_info['description']}")
            logger.info(f"Интенсивность: {intensity}")
            logger.info(f"Продолжительность: {duration}с")
            
            # Загружаем модель для обнаружения атаки
            if self.load_attack_model(attack_type):
                # Запускаем поток анализа пакетов
                self.current_attack = attack_type
                self.detector_thread = threading.Thread(target=self.analyze_packets)
                self.detector_thread.start()
                
                # Запускаем сниффер пакетов
                sniffer_thread = threading.Thread(
                    target=lambda: sniff(
                        prn=self.packet_callback,
                        store=0,
                        timeout=duration
                    ),
                    daemon=True
                )
                sniffer_thread.start()
                
                # Запускаем атаку
                simulator = AttackSimulator("127.0.0.1")
                if attack_type in simulator.supported_attacks:
                    attack_func = simulator.supported_attacks[attack_type]
                    attack_func(duration=duration, intensity=intensity)
                    logger.info(f"Пауза между атаками...")
                else:
                    logger.error(f"Неподдерживаемый тип атаки. Поддерживаемые типы: {list(simulator.supported_attacks.keys())}")
                
                # Ждем завершения снифферa
                sniffer_thread.join()
                
            else:
                logger.error(f"Не удалось загрузить модель для атаки {attack_type}")
            
        except Exception as e:
            logger.error(f"Ошибка запуска атаки: {e}")
        finally:
            self.current_attack = None
            self.current_model = None
            self.current_scaler = None

    def run_detection(self, selected_attacks=None):
        """Запуск системы обнаружения атак"""
        try:
            if selected_attacks is None:
                selected_attacks = list(ATTACK_TYPES.keys())
                
            for attack_type in selected_attacks:
                if self.stop_flag:
                    break
                    
                if attack_type in ATTACK_TYPES:
                    self.start_attack(attack_type)
                    if not self.stop_flag:
                        time.sleep(5)  # Пауза между атаками
                else:
                    logger.error(f"Неизвестный тип атаки: {attack_type}")
                    
            logger.info("\nСимуляция завершена")
            
        except KeyboardInterrupt:
            logger.info("\nПрерывание работы...")
        finally:
            self.cleanup()

    def cleanup(self):
        """Очистка ресурсов"""
        self.stop_flag = True
        if self.current_attack:
            logger.info(f"Остановка текущей атаки: {self.current_attack}")
            self.current_attack = None
        if self.detector_thread and self.detector_thread.is_alive():
            self.detector_thread.join()

def main():
    """Основная функция"""
    detection_system = DetectionSystem()
    
    print("\n=== Система обнаружения сетевых атак ===")
    print("Доступные типы атак:")
    for attack_id, attack_info in ATTACK_TYPES.items():
        print(f"- {attack_info['name']}: {attack_info['description']}")
    
    while True:
        print("\nВыберите действие:")
        print("1. Запустить все доступные атаки")
        print("2. Выбрать конкретные атаки")
        print("3. Выход")
        
        choice = input("\nВаш выбор (1-3): ")
        
        if choice == "1":
            detection_system.run_detection()
        elif choice == "2":
            print("\nДоступные атаки:")
            for i, (attack_id, attack_info) in enumerate(ATTACK_TYPES.items(), 1):
                print(f"{i}. {attack_info['name']}")
            
            try:
                selected_nums = input("\nВведите номера атак через пробел: ").split()
                selected_attacks = [list(ATTACK_TYPES.keys())[int(num) - 1] for num in selected_nums]
                detection_system.run_detection(selected_attacks)
            except (ValueError, IndexError):
                print("Ошибка: введите корректные номера атак")
        elif choice == "3":
            print("Выход из программы")
            break
        else:
            print("Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()
