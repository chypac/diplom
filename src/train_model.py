import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import logging
from sklearn.model_selection import train_test_split
import psutil
import gc
from datetime import datetime
import shutil
from collections import OrderedDict

# Определение базовых путей относительно корня проекта
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# Типы атак и их директории в порядке алфавита
ATTACK_TYPES = OrderedDict([
    ('active_wiretap', 'Active Wiretap'),
    ('arp_mitm', 'ARP MitM'),
    ('fuzzing', 'Fuzzing'),
    ('mirai_botnet', 'Mirai Botnet'),
    ('os_scan', 'OS Scan'),
    ('ssdp_flood', 'SSDP Flood'),
    ('ssl_renegotiation', 'SSL Renegotiation'),
    ('syn_dos', 'SYN DoS'),
    ('video_injection', 'Video Injection')
])

# Словарь соответствия имен файлов и типов атак
FILE_TO_ATTACK_TYPE = OrderedDict([
    ('Active_Wiretap', 'active_wiretap'),
    ('ARP_MitM', 'arp_mitm'),
    ('Fuzzing', 'fuzzing'),
    ('Mirai', 'mirai_botnet'),
    ('OS_Scan', 'os_scan'),
    ('SSDP_Flood', 'ssdp_flood'),
    ('SSL_Renegotiation', 'ssl_renegotiation'),
    ('SYN_DoS', 'syn_dos'),
    ('Video_Injection', 'video_injection')
])

# Создаем необходимые директории
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

def get_attack_dir(attack_type):
    """Получить путь к директории атаки с учетом пробелов в названии"""
    return os.path.join(DATA_DIR, ATTACK_TYPES[attack_type])

def organize_data_files():
    """Организация файлов данных по папкам атак"""
    logger.info("Организация файлов данных...")
    
    # Проверяем все файлы в корневой директории данных
    for file in os.listdir(DATA_DIR):
        if not file.endswith('.csv'):
            continue
            
        file_path = os.path.join(DATA_DIR, file)
        if not os.path.isfile(file_path):
            continue
            
        # Определяем тип атаки из имени файла
        attack_type = None
        
        # Сначала проверяем прямое соответствие из словаря
        for file_prefix, attack in FILE_TO_ATTACK_TYPE.items():
            if file.startswith(file_prefix):
                attack_type = attack
                break
        
        # Если не нашли в словаре, ищем по имени директории
        if attack_type is None:
            for attack, dir_name in ATTACK_TYPES.items():
                if dir_name.lower() in file.lower():
                    attack_type = attack
                    break
        
        if attack_type:
            # Создаем директорию если нужно
            attack_dir = get_attack_dir(attack_type)
            os.makedirs(attack_dir, exist_ok=True)
            
            # Перемещаем файл
            new_path = os.path.join(attack_dir, file)
            if not os.path.exists(new_path):
                shutil.move(file_path, new_path)
                logger.info(f"Перемещен файл {file} в {ATTACK_TYPES[attack_type]}/")
            else:
                logger.warning(f"Файл {file} уже существует в {ATTACK_TYPES[attack_type]}/")
        else:
            logger.warning(f"Не удалось определить тип атаки для файла: {file}")

def process_and_train(attack_type):
    """Обработка данных и обучение модели для конкретного типа атаки"""
    logger.info(f'Начало обучения модели для атаки: {ATTACK_TYPES[attack_type]}')
    data_dir = get_attack_dir(attack_type)
    model_save_path = os.path.join(MODELS_DIR, f'{attack_type}_model.pth')
    
    # Проверяем наличие данных
    if not os.path.exists(data_dir):
        logger.error(f"Директория данных не найдена: {data_dir}")
        return None
        
    # Получаем только файлы с данными, исключая файлы меток
    csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv') and not f.lower().endswith('_labels.csv')]
    if not csv_files:
        logger.error(f"CSV файлы с данными не найдены в директории: {data_dir}")
        return None
        
    logger.info(f"Найдено CSV файлов с данными: {len(csv_files)}")
    log_memory_usage()

    # Инициализация scaler
    scaler = MinMaxScaler()
    
    # Первый проход: определение размерности и подготовка scaler
    logger.info("Первый проход: анализ данных и подготовка scaler")
    input_dim = None
    total_normal_samples = 0
    feature_names = None
    
    for file in csv_files:
        file_path = os.path.join(data_dir, file)
        logger.info(f'Анализ файла: {file}')
        
        try:
            # Читаем файл чанками
            for chunk in pd.read_csv(file_path, chunksize=10000):
                if 'Unnamed: 0' in chunk.columns:
                    chunk = chunk.drop('Unnamed: 0', axis=1)
                
                # Определяем размерность из первого чанка
                if input_dim is None:
                    input_dim = chunk.shape[1] - 1  # -1 для метки
                    feature_names = chunk.columns[:-1].tolist()
                    logger.info(f'Определена размерность входных данных: {input_dim}')
                
                # Проверяем формат данных
                if chunk.shape[1] - 1 != input_dim:
                    logger.warning(f'Файл {file} имеет неверное количество признаков, пропуск')
                    break
                
                # Отделяем метки
                features = chunk.iloc[:, :-1]
                labels = chunk.iloc[:, -1]
                
                # Подсчет нормального трафика
                normal_samples = (labels == 0).sum()
                total_normal_samples += normal_samples
                
                # Частичное обучение scaler только на нормальном трафике
                normal_traffic = features[labels == 0]
                if len(normal_traffic) > 0:
                    scaler.partial_fit(normal_traffic)
                
                del chunk, features, labels, normal_traffic
                gc.collect()
            
            logger.info(f'Файл {file} обработан')
            
        except Exception as e:
            logger.error(f'Ошибка при обработке файла {file}: {e}')
            continue
    
    if total_normal_samples == 0:
        logger.error("Не найдено образцов нормального трафика")
        return None
        
    logger.info(f'Всего найдено нормальных образцов: {total_normal_samples}')
    
    # Инициализация модели
    model = Autoencoder(input_dim).to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # Параметры обучения
    min_batch_size = 32  # Минимальный размер батча для BatchNorm
    batch_size = min(256, max(min_batch_size, total_normal_samples // 1000))
    best_val_loss = float('inf')
    patience = 5
    patience_counter = 0
    
    logger.info(f"Начало обучения модели (batch_size={batch_size})")
    
    for epoch in range(50):
        model.train()
        train_loss = 0
        batches_processed = 0
        
        for file in csv_files:
            file_path = os.path.join(data_dir, file)
            
            try:
                for chunk in pd.read_csv(file_path, chunksize=10000):
                    if 'Unnamed: 0' in chunk.columns:
                        chunk = chunk.drop('Unnamed: 0', axis=1)
                    
                    features = chunk.iloc[:, :-1]
                    labels = chunk.iloc[:, -1]
                    
                    # Обрабатываем только нормальный трафик
                    normal_traffic = features[labels == 0]
                    if len(normal_traffic) < min_batch_size:
                        continue
                    
                    # Нормализация данных
                    normal_traffic_scaled = scaler.transform(normal_traffic)
                    
                    # Создание датасета
                    tensor_x = torch.FloatTensor(normal_traffic_scaled).to(device)
                    dataset = TensorDataset(tensor_x, tensor_x)
                    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)  # drop_last=True отбрасывает неполные батчи
                    
                    # Обучение на батчах
                    for batch_x, _ in loader:
                        if len(batch_x) < min_batch_size:  # Пропускаем слишком маленькие батчи
                            continue
                            
                        optimizer.zero_grad()
                        outputs = model(batch_x)
                        loss = criterion(outputs, batch_x)
                        loss.backward()
                        optimizer.step()
                        
                        train_loss += loss.item()
                        batches_processed += 1
                    
                    del normal_traffic, normal_traffic_scaled, tensor_x, dataset, loader
                    gc.collect()
                    
            except Exception as e:
                logger.error(f'Ошибка при обучении на файле {file}: {e}')
                continue
        
        if batches_processed == 0:
            logger.warning(f"Эпоха {epoch+1}: Нет обработанных батчей")
            continue
            
        # Вычисляем среднюю ошибку
        avg_loss = train_loss / batches_processed if batches_processed > 0 else float('inf')
        logger.info(f'Эпоха {epoch+1}, Средняя ошибка: {avg_loss:.6f}')
        
        # Early stopping
        if avg_loss < best_val_loss:
            best_val_loss = avg_loss
            patience_counter = 0
            # Сохраняем модель и scaler
            torch.save({
                'model_state_dict': model.state_dict(),
                'scaler_state': scaler,
                'input_dim': input_dim,
                'feature_names': feature_names,
                'attack_type': attack_type,
                'best_loss': best_val_loss
            }, model_save_path)
            logger.info(f'Сохранена лучшая модель (loss={avg_loss:.6f})')
        else:
            patience_counter += 1
            if patience_counter >= patience:
                logger.info('Early stopping')
                break
    
    logger.info(f'Обучение модели для {ATTACK_TYPES[attack_type]} завершено')
    return model

def log_memory_usage():
    """Логирование использования памяти"""
    process = psutil.Process(os.getpid())
    mem_usage = process.memory_info().rss / 1024 / 1024  # в МБ
    logger.info(f'Использование памяти: {mem_usage:.2f} MB')

class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        # Encoder с BatchNorm и Dropout
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
        
        # Decoder с BatchNorm и Dropout
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

# Настройка логирования
log_file = os.path.join(LOG_DIR, f'training_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Проверка доступности GPU
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f'Используется устройство: {device}')

def main():
    """Основная функция для обучения моделей"""
    logger.info("Начало обучения моделей")
    log_memory_usage()

    # Организуем файлы по папкам
    organize_data_files()

    # Обучаем модель для каждого типа атаки
    for attack_type in ATTACK_TYPES.keys():
        logger.info("="*50)
        logger.info(f"Обработка атаки: {ATTACK_TYPES[attack_type]}")
        
        try:
            model = process_and_train(attack_type)
            if model is not None:
                logger.info(f"Модель для {ATTACK_TYPES[attack_type]} успешно обучена")
            else:
                logger.warning(f"Не удалось обучить модель для {ATTACK_TYPES[attack_type]}")
        except Exception as e:
            logger.error(f"Ошибка при обучении модели для {ATTACK_TYPES[attack_type]}: {e}")
            continue
        
        log_memory_usage()
        
    logger.info("="*50)
    logger.info("Обучение всех моделей завершено")

if __name__ == "__main__":
    main()
