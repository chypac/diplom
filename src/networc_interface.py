import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import logging
from scapy.all import sniff, IP, TCP, UDP
import psutil
import torch.serialization
import numpy.core.multiarray as multiarray
import sklearn.preprocessing._data
import time

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,  
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('anomaly_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Проверка доступности GPU
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f'Используется устройство: {device}')

# Добавляем безопасные глобальные переменные для загрузки модели
torch.serialization.add_safe_globals([
    ('numpy.core.multiarray._reconstruct', multiarray._reconstruct),
    ('numpy', np),
    ('numpy.core.multiarray', multiarray),
    ('_codecs', __import__('_codecs')),
    ('sklearn.preprocessing._data', sklearn.preprocessing._data),
    ('numpy.random', __import__('numpy.random')),
    ('numpy.core.numeric', __import__('numpy.core.numeric')),
    ('sklearn.preprocessing._data.MinMaxScaler', MinMaxScaler)
])

# Архитектура автоэнкодера
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        # Размеры слоев из сохраненной модели
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU()
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Функция загрузки модели
def load_model(model_path):
    try:
        logging.info(f"Загрузка модели из {model_path}")
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Загружаем модель
        checkpoint = torch.load(model_path, map_location=device)
        
        # Создаем новую модель
        model = Autoencoder(input_dim=114).to(device)
        
        # Загружаем веса в зависимости от формата сохранения
        if isinstance(checkpoint, dict):
            if 'model_state_dict' in checkpoint:
                model.load_state_dict(checkpoint['model_state_dict'])
            elif 'state_dict' in checkpoint:
                model.load_state_dict(checkpoint['state_dict'])
            else:
                model.load_state_dict(checkpoint)
        elif isinstance(checkpoint, tuple):
            model.load_state_dict(checkpoint[0])
        else:
            model.load_state_dict(checkpoint)
            
        model.eval()
        
        # Создаем новый скейлер
        scaler = MinMaxScaler(feature_range=(-1, 1))
        
        # Генерируем случайные данные для инициализации скейлера
        dummy_data = np.random.randn(100, 114)
        scaler.fit(dummy_data)
        
        return model, scaler
    except Exception as e:
        logging.error(f"Ошибка при загрузке модели: {str(e)}")
        raise

# Функция предварительной обработки пакетов
def preprocess_packet(packet):
    try:
        # Проверяем наличие IP слоя
        if not packet.haslayer('IP'):
            logger.debug("Пакет не содержит IP слой")
            return None

        # Получаем IP слой
        ip = packet.getlayer('IP')
        
        # Базовые IP признаки
        features = {
            'ip_version': float(ip.version),
            'ip_ihl': float(ip.ihl),
            'ip_tos': float(ip.tos),
            'ip_len': float(ip.len),
            'ip_id': float(ip.id),
            'ip_flags': float(int(ip.flags)),
            'ip_frag': float(ip.frag),
            'ip_ttl': float(ip.ttl),
            'ip_proto': float(ip.proto),
            'ip_chksum': float(ip.chksum),
            'ip_payload_len': float(len(ip.payload)),
            'ip_header_len': float(ip.ihl * 4)
        }
        
        # IP флаги
        ip_flags = int(ip.flags)
        features.update({
            'ip_flag_mf': float(ip_flags & 0x01),  # More Fragments
            'ip_flag_df': float((ip_flags & 0x02) >> 1),  # Don't Fragment
            'ip_flag_reserved': float((ip_flags & 0x04) >> 2)  # Reserved bit
        })
        
        # TCP признаки
        if packet.haslayer('TCP'):
            tcp = packet.getlayer('TCP')
            features.update({
                'tcp_sport': float(tcp.sport),
                'tcp_dport': float(tcp.dport),
                'tcp_seq': float(tcp.seq),
                'tcp_ack': float(tcp.ack),
                'tcp_dataofs': float(tcp.dataofs),
                'tcp_flags': float(int(tcp.flags)),
                'tcp_window': float(tcp.window),
                'tcp_chksum': float(tcp.chksum),
                'tcp_urgptr': float(tcp.urgptr),
                'tcp_payload_len': float(len(tcp.payload)),
                'tcp_header_len': float(tcp.dataofs * 4)
            })
            
            # TCP флаги
            tcp_flags = int(tcp.flags)
            features.update({
                'tcp_flag_fin': float(tcp_flags & 0x01),
                'tcp_flag_syn': float((tcp_flags & 0x02) >> 1),
                'tcp_flag_rst': float((tcp_flags & 0x04) >> 2),
                'tcp_flag_psh': float((tcp_flags & 0x08) >> 3),
                'tcp_flag_ack': float((tcp_flags & 0x10) >> 4),
                'tcp_flag_urg': float((tcp_flags & 0x20) >> 5),
                'tcp_flag_ece': float((tcp_flags & 0x40) >> 6),
                'tcp_flag_cwr': float((tcp_flags & 0x80) >> 7)
            })
            
            # Дополнительные TCP признаки
            features.update({
                'tcp_window_scale': float(tcp.window) / 65535,  # Нормализованный размер окна
                'tcp_has_payload': float(len(tcp.payload) > 0),
                'tcp_payload_size_ratio': float(len(tcp.payload)) / float(len(packet)) if len(packet) > 0 else 0.0
            })
        else:
            tcp_features = [
                'tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_dataofs',
                'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_payload_len',
                'tcp_header_len', 'tcp_flag_fin', 'tcp_flag_syn', 'tcp_flag_rst',
                'tcp_flag_psh', 'tcp_flag_ack', 'tcp_flag_urg', 'tcp_flag_ece',
                'tcp_flag_cwr', 'tcp_window_scale', 'tcp_has_payload', 'tcp_payload_size_ratio'
            ]
            features.update({key: 0.0 for key in tcp_features})
            
        # UDP признаки
        if packet.haslayer('UDP'):
            udp = packet.getlayer('UDP')
            features.update({
                'udp_sport': float(udp.sport),
                'udp_dport': float(udp.dport),
                'udp_len': float(udp.len),
                'udp_chksum': float(udp.chksum),
                'udp_payload_len': float(len(udp.payload)),
                'udp_header_len': 8.0,  # UDP header всегда 8 байт
                'udp_payload_size_ratio': float(len(udp.payload)) / float(len(packet)) if len(packet) > 0 else 0.0
            })
        else:
            udp_features = [
                'udp_sport', 'udp_dport', 'udp_len', 'udp_chksum',
                'udp_payload_len', 'udp_header_len', 'udp_payload_size_ratio'
            ]
            features.update({key: 0.0 for key in udp_features})
            
        # Общие признаки пакета
        features.update({
            'packet_size': float(len(packet)),
            'packet_payload_size': float(len(packet.payload)),
            'has_tcp': float(packet.haslayer('TCP')),
            'has_udp': float(packet.haslayer('UDP')),
            'has_icmp': float(packet.haslayer('ICMP')),
            'has_dns': float(packet.haslayer('DNS')),
            'has_http': float(packet.haslayer('HTTP')),
            'header_length_ratio': float(ip.ihl * 4) / float(len(packet)) if len(packet) > 0 else 0.0,
            'payload_length_ratio': float(len(packet.payload)) / float(len(packet)) if len(packet) > 0 else 0.0
        })
        
        # Признаки портов
        src_port = features.get('tcp_sport', 0.0) or features.get('udp_sport', 0.0)
        dst_port = features.get('tcp_dport', 0.0) or features.get('udp_dport', 0.0)
        features.update({
            'is_well_known_port_src': float(src_port < 1024),
            'is_well_known_port_dst': float(dst_port < 1024),
            'is_registered_port_src': float(1024 <= src_port < 49152),
            'is_registered_port_dst': float(1024 <= dst_port < 49152),
            'is_private_port_src': float(src_port >= 49152),
            'is_private_port_dst': float(dst_port >= 49152)
        })
        
        # Добавляем нулевые признаки до 114
        current_features = len(features)
        if current_features < 114:
            for i in range(current_features, 114):
                features[f'padding_feature_{i}'] = 0.0
                
        # Преобразуем словарь в numpy массив
        feature_names = sorted(features.keys())  # Сортируем ключи для консистентности
        feature_vector = np.array([features[name] for name in feature_names]).reshape(1, -1)
        
        logger.debug(f"Извлечено признаков: {len(feature_names)}")
        return feature_vector
        
    except Exception as e:
        logger.error(f"Ошибка при обработке пакета: {str(e)}")
        if hasattr(packet, 'summary'):
            logger.debug(f"Информация о пакете: {packet.summary()}")
        return None

# Функция классификации пакетов
def classify_packet(features, model, scaler):
    """
    Классифицирует пакет как нормальный или аномальный
    
    Args:
        features (dict): Словарь признаков пакета
        model (torch.nn.Module): Модель для классификации
        scaler (sklearn.preprocessing.StandardScaler): Нормализатор данных
        
    Returns:
        bool: True если пакет аномальный, False если нормальный
    """
    try:
        # Преобразуем признаки в numpy массив
        features_array = np.array(list(features.values())).reshape(1, -1)
        # Нормализуем данные
        features_normalized = scaler.transform(features_array)
        # Конвертируем в тензор
        device = next(model.parameters()).device
        features_tensor = torch.FloatTensor(features_normalized).to(device)
        
        # Создаем "нормальный" образец
        normal_sample = torch.zeros_like(features_tensor)
        
        # Вычисляем отклонение
        criterion = nn.L1Loss(reduction='mean')
        with torch.no_grad():
            output = model(features_tensor)
            loss = criterion(output, normal_sample)
            loss_value = float(loss.item())
            
            # Определяем аномалию
            threshold = 0.1
            return loss_value > threshold
            
    except Exception as e:
        logger.error(f"Ошибка при классификации пакета: {e}")
        return False

def classify_packet_live(packet, model, scaler):
    """
    Классифицирует пакет для live_traffic_analyzer.py
    Возвращает тип атаки и значение отклонения
    """
    try:
        features = preprocess_packet(packet)
        if features is None:
            return None, None

        # features уже numpy массив, просто меняем форму
        features_array = np.array(features).reshape(1, -1)
        features_array = np.clip(features_array, -1e6, 1e6)
        
        features_normalized = scaler.transform(features_array)
        features_tensor = torch.FloatTensor(features_normalized).to(next(model.parameters()).device)
        
        normal_sample = torch.zeros_like(features_tensor)
        criterion = nn.L1Loss(reduction='mean')
        
        with torch.no_grad():
            output = model(features_tensor)
            loss = criterion(output, normal_sample)
            loss_value = float(loss.item())
            loss_value = np.clip(loss_value, 0, 10) / 10
            
            if loss_value > 0.1:
                logging.warning(f"Аномалия обнаружена! Потеря: {loss_value:.4f}")
            else:
                logging.info(f"Нормальный трафик. Потеря: {loss_value:.4f}")
            
        return "Active Wiretap", loss_value

    except Exception as e:
        logging.error(f"Ошибка при классификации пакета: {str(e)}")
        return None, None

def classify_packet_detection(features, model, scaler):
    """
    Классифицирует пакет для detection_system.py
    Возвращает True если пакет аномальный, False если нормальный
    """
    try:
        # features уже numpy массив, просто меняем форму
        features_array = np.array(features).reshape(1, -1)
        features_normalized = scaler.transform(features_array)
        device = next(model.parameters()).device
        features_tensor = torch.FloatTensor(features_normalized).to(device)
        
        normal_sample = torch.zeros_like(features_tensor)
        criterion = nn.L1Loss(reduction='mean')
        
        with torch.no_grad():
            output = model(features_tensor)
            loss = criterion(output, normal_sample)
            loss_value = float(loss.item())
            
            threshold = 0.1
            return loss_value > threshold
            
    except Exception as e:
        logger.error(f"Ошибка при классификации пакета: {e}")
        return False

def format_packet_info(packet):
    """
    Форматирует информацию о пакете в читаемый вид
    
    Args:
        packet: Пакет scapy
        
    Returns:
        str: Отформатированная строка с информацией о пакете
    """
    try:
        if packet.haslayer('IP'):
            info = f"IP {packet[IP].src:15} -> {packet[IP].dst:15}"
            if packet.haslayer('TCP'):
                info += f" TCP {packet[TCP].sport:5} -> {packet[TCP].dport:5}"
            elif packet.haslayer('UDP'):
                info += f" UDP {packet[UDP].sport:5} -> {packet[UDP].dport:5}"
            return info
        return None
    except Exception as e:
        logger.error(f"Ошибка при форматировании информации о пакете: {e}")
        return None

# Реальный мониторинг трафика
def monitor_traffic(interface, model, scaler):
    """
    Мониторит сетевой трафик на указанном интерфейсе
    
    Args:
        interface (str): Имя сетевого интерфейса
        model (torch.nn.Module): Модель для классификации
        scaler (sklearn.preprocessing.StandardScaler): Нормализатор данных
    """
    # Статистика
    stats = {
        'total_packets': 0,
        'anomaly_packets': 0,
        'last_loss': 0.0,
        'start_time': time.time()
    }
    
    def update_stats(loss, is_anomaly):
        stats['total_packets'] += 1
        if is_anomaly:
            stats['anomaly_packets'] += 1
        stats['last_loss'] = loss
        
        # Каждые 100 пакетов выводим статистику
        if stats['total_packets'] % 100 == 0:
            elapsed_time = time.time() - stats['start_time']
            packets_per_second = stats['total_packets'] / elapsed_time if elapsed_time > 0 else 0
            anomaly_ratio = (stats['anomaly_packets'] / stats['total_packets']) * 100
            
            logger.info(f"\n=== Статистика ===")
            logger.info(f"Всего пакетов: {stats['total_packets']}")
            logger.info(f"Аномальных пакетов: {stats['anomaly_packets']} ({anomaly_ratio:.2f}%)")
            logger.info(f"Пакетов в секунду: {packets_per_second:.2f}")
            logger.info(f"Последнее отклонение: {stats['last_loss']:.4f}")
            logger.info("================\n")
    
    def process_sniffed_packet(packet):
        try:
            if packet.haslayer('IP'):
                packet_info = format_packet_info(packet)
                logger.debug(f"Пакет: {packet_info}")
                
                result = classify_packet_live(packet, model, scaler)
                if result is not None:
                    attack_type, loss = result
                    if loss is not None:
                        is_anomaly = loss > 0.1
                        update_stats(loss, is_anomaly)
                        
                        if is_anomaly:
                            logger.warning(f"[!] АНОМАЛИЯ {packet_info} | Отклонение: {loss:.4f}")
                        else:
                            logger.info(f"[+] НОРМА    {packet_info} | Отклонение: {loss:.4f}")
                    
        except Exception as e:
            logger.error(f'Ошибка при обработке пакета: {str(e)}')
            
    logger.info(f"Начинаем захват пакетов на интерфейсе {interface}")
    sniff(iface=interface, prn=process_sniffed_packet, store=False)

# Укажите параметры для мониторинга
if __name__ == "__main__":
    try:
        # Автоматическое определение интерфейсов с описанием
        interfaces = psutil.net_if_addrs()
        interface_map = {}

        logger.info("Доступные интерфейсы:")
        for i, (iface, addresses) in enumerate(interfaces.items()):
            description = iface
            for addr in addresses:
                if addr.family.name == 'AF_INET':
                    description += f" (IP: {addr.address})"
            interface_map[i] = iface
            logger.info(f"[{i}] {description}")

        while True:
            try:
                choice = int(input("Выберите интерфейс по номеру: "))
                if choice in interface_map:
                    interface = interface_map[choice]
                    break
                else:
                    logger.error("Некорректный номер. Попробуйте снова.")
            except ValueError:
                logger.error("Введите числовое значение.")

        # Загрузка моделей из папок
        models_dir = r"C:\Users\agaar\PycharmProjects\pythonProject\diplom_2\dataset\archive (1)"  # Укажите путь к папке с моделями
        # Загрузка моделей из папок
        models = []
        for folder_name in os.listdir(models_dir):
            folder_path = os.path.join(models_dir, folder_name)
            if os.path.isdir(folder_path):
                for model_file in os.listdir(folder_path):
                    if model_file.endswith('.pth'):
                        model_path = os.path.join(folder_path, model_file)
                        try:
                            model, scaler = load_model(model_path)
                            models.append({
                                'name': f"{folder_name}/{model_file}",
                                'model': model,
                                'scaler': scaler
                            })
                        except Exception as e:
                            logger.error(f"Ошибка загрузки модели {model_path}: {e}")

        logger.info("Доступные модели:")
        for i, model_info in enumerate(models):
            logger.info(f"[{i}] {model_info['name']}")

        while True:
            try:
                model_choice = int(input("Выберите модель по номеру: "))
                if 0 <= model_choice < len(models):
                    selected_model = models[model_choice]
                    break
                else:
                    logger.error("Некорректный номер. Попробуйте снова.")
            except ValueError:
                logger.error("Введите числовое значение.")

        # Запуск мониторинга
        monitor_traffic(interface, selected_model['model'], selected_model['scaler'])

    except KeyboardInterrupt:
        logger.info("Мониторинг завершён пользователем.")
    except Exception as e:
        logger.error(f'Ошибка: {e}')
