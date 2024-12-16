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

# Настройка логирования
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f'training_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Проверка доступности GPU
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f'Используется устройство: {device}')

# Изменяем путь к директории с данными и моделями
root_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')

# Создаем директории, если они не существуют
os.makedirs(root_dir, exist_ok=True)
os.makedirs(models_dir, exist_ok=True)

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
            nn.Sigmoid()  # Для нормализованных значений
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def process_and_train(folder_path, model_save_path):
    logger.info(f'Начало обработки папки: {folder_path}')
    log_memory_usage()

    # Инициализация scaler
    scaler = MinMaxScaler()
    
    # Первый проход: определение размерности и подготовка scaler
    logger.info("Первый проход: анализ данных и подготовка scaler")
    input_dim = None  # Определим размерность из данных
    total_normal_samples = 0
    feature_names = None
    
    for file in os.listdir(folder_path):
        if not file.endswith('.csv'):
            continue
            
        file_path = os.path.join(folder_path, file)
        logger.info(f'Анализ файла: {file_path}')
        
        try:
            # Читаем файл чанками
            for chunk in pd.read_csv(file_path, chunksize=10000):
                # Удаляем столбец 'Unnamed: 0' если он есть
                if 'Unnamed: 0' in chunk.columns:
                    chunk = chunk.drop('Unnamed: 0', axis=1)
                
                # Определяем размерность из первого чанка
                if input_dim is None:
                    input_dim = chunk.shape[1] - 1  # -1 для метки
                    logger.info(f'Определена размерность входных данных: {input_dim}')
                    
                # Проверяем формат данных
                if chunk.shape[1] - 1 != input_dim:  # -1 для метки
                    logger.warning(f'Файл {file_path} имеет неверное количество признаков ({chunk.shape[1]-1} != {input_dim}), пропуск.')
                    break
                
                if feature_names is None:
                    feature_names = chunk.columns[:-1].tolist()  # Сохраняем имена признаков
                    logger.info(f'Определены имена признаков, всего {len(feature_names)}')
                
                # Отделяем метки
                features = chunk.iloc[:, :-1]
                labels = chunk.iloc[:, -1]
                
                # Проверяем соответствие признаков
                if not all(feat in features.columns for feat in feature_names):
                    logger.warning(f'Несоответствие признаков в файле {file_path}, пропуск.')
                    break
                
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
            log_memory_usage()
            
        except Exception as e:
            logger.error(f'Ошибка при обработке файла {file_path}: {e}')
            continue
    
    logger.info(f'Всего найдено нормальных образцов: {total_normal_samples}')
    
    # Инициализация модели
    model = Autoencoder(input_dim).to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # Параметры обучения
    best_val_loss = float('inf')
    patience = 5
    patience_counter = 0
    min_batch_size = 32  # Минимальный размер батча
    max_batch_size = 256  # Максимальный размер батча
    batch_size = min(max_batch_size, max(min_batch_size, total_normal_samples // 1000))
    validation_size = min(10000, total_normal_samples // 5)
    
    # Второй проход: обучение модели
    logger.info(f"Второй проход: обучение модели с размером батча {batch_size}")
    
    for epoch in range(50):
        model.train()
        train_loss = 0
        samples_processed = 0
        batches_processed = 0
        
        for file in os.listdir(folder_path):
            if not file.endswith('.csv'):
                continue
                
            file_path = os.path.join(folder_path, file)
            
            try:
                for chunk in pd.read_csv(file_path, chunksize=10000):
                    # Удаляем столбец 'Unnamed: 0' если он есть
                    if 'Unnamed: 0' in chunk.columns:
                        chunk = chunk.drop('Unnamed: 0', axis=1)
                    
                    features = chunk.iloc[:, :-1]
                    labels = chunk.iloc[:, -1]
                    
                    # Проверяем соответствие признаков
                    if not all(feat in features.columns for feat in feature_names):
                        continue
                    
                    # Обрабатываем только нормальный трафик
                    normal_traffic = features[labels == 0]
                    if len(normal_traffic) < min_batch_size:
                        continue
                    
                    # Нормализация
                    normal_traffic_normalized = scaler.transform(normal_traffic)
                    
                    # Создаем батчи
                    data_tensor = torch.FloatTensor(normal_traffic_normalized).to(device)
                    dataset = TensorDataset(data_tensor)
                    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)
                    
                    # Обучение на батчах
                    for batch in dataloader:
                        if len(batch[0]) < min_batch_size:
                            continue
                            
                        inputs = batch[0]
                        optimizer.zero_grad()
                        outputs = model(inputs)
                        loss = criterion(outputs, inputs)
                        loss.backward()
                        optimizer.step()
                        
                        train_loss += loss.item()
                        samples_processed += len(inputs)
                        batches_processed += 1
                    
                    del normal_traffic, normal_traffic_normalized, data_tensor, dataset, dataloader
                    gc.collect()
                    
            except Exception as e:
                logger.error(f'Ошибка при обучении на файле {file_path}: {e}')
                continue
        
        if batches_processed == 0:
            logger.warning(f'Эпоха {epoch + 1}: нет данных для обучения')
            continue
            
        train_loss /= batches_processed
        logger.info(f'Эпоха {epoch + 1}, Средняя ошибка: {train_loss:.6f}, Обработано образцов: {samples_processed}')
        
        # Сохранение модели
        if train_loss < best_val_loss:
            best_val_loss = train_loss
            patience_counter = 0
            torch.save({
                'model_state_dict': model.state_dict(),
                'scaler': scaler,
                'input_dim': input_dim,
                'feature_names': feature_names,
                'best_loss': best_val_loss
            }, model_save_path)
            logger.info(f'Модель сохранена с ошибкой {best_val_loss:.6f}')
        else:
            patience_counter += 1
            
        if patience_counter >= patience:
            logger.info('Раннее остановка: нет улучшений')
            break
            
        log_memory_usage()

# Обработка каждой папки с атаками
for folder in os.listdir(root_dir):
    folder_path = os.path.join(root_dir, folder)
    if os.path.isdir(folder_path):
        logger.info(f'='*50)
        logger.info(f'Обработка папки: {folder}')
        model_save_path = os.path.join(models_dir, f'{folder}_autoencoder_model.pth')
        process_and_train(folder_path, model_save_path)

logger.info('Обучение завершено для всех типов атак')
log_memory_usage()
