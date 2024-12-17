import os
import logging
import argparse
from networc_interface import load_model, monitor_traffic
import psutil
import keyboard
import threading
from time import sleep

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('anomaly_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Определение базовых путей относительно корня проекта
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Глобальные переменные для управления моделью
current_model = None
model_info = None
should_reload_model = threading.Event()

def get_network_interfaces():
    """Получение списка доступных сетевых интерфейсов"""
    interfaces = []
    stats = psutil.net_if_stats()
    
    for iface, stat in stats.items():
        if stat.isup:
            interfaces.append(iface)
    return interfaces

def get_available_models():
    """Получение списка доступных моделей"""
    models = []
    for file in os.listdir(MODELS_DIR):
        if file.endswith('_model.pth'):
            model_name = file[:-10]  # Убираем '_model.pth'
            models.append(model_name)
    return models

def select_model():
    """Выбор модели для использования"""
    global current_model, model_info
    
    available_models = get_available_models()
    if not available_models:
        logger.error("Нет доступных моделей для анализа трафика")
        return False
        
    print("\nДоступные модели:")
    for i, model_name in enumerate(available_models, 1):
        print(f"{i}. {model_name}")
        
    try:
        choice = int(input("\nВыберите модель (номер): "))
        if 1 <= choice <= len(available_models):
            model_name = available_models[choice - 1]
            model_path = os.path.join(MODELS_DIR, f"{model_name}_model.pth")
            
            logger.info(f"Загрузка модели: {model_name}")
            model_info = load_model(model_path)  # Теперь это кортеж (model, scaler)
            current_model = model_name
            return True
    except ValueError:
        pass
        
    logger.error("Неверный выбор модели")
    return False

def model_switch_listener():
    """Поток для отслеживания нажатия клавиш"""
    global should_reload_model
    
    while True:
        if keyboard.is_pressed('m'):
            logger.info("Запрошена смена модели")
            should_reload_model.set()
            sleep(0.5)  # Предотвращение множественных нажатий

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Анализатор сетевого трафика")
    parser.add_argument("--interface", type=str, help="Сетевой интерфейс для мониторинга")
    args = parser.parse_args()
    
    # Получаем список интерфейсов
    interfaces = get_network_interfaces()
    if not interfaces:
        logger.error("Не найдены активные сетевые интерфейсы")
        return
        
    # Выбор интерфейса
    interface = args.interface
    if not interface:
        print("\nДоступные сетевые интерфейсы:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
            
        try:
            choice = int(input("\nВыберите интерфейс (номер): "))
            if 1 <= choice <= len(interfaces):
                interface = interfaces[choice - 1]
            else:
                logger.error("Неверный выбор интерфейса")
                return
        except ValueError:
            logger.error("Неверный ввод")
            return
            
    if interface not in interfaces:
        logger.error(f"Интерфейс {interface} не найден или неактивен")
        return
        
    # Выбор начальной модели
    if not select_model():
        return
        
    # Запуск потока для отслеживания смены модели
    threading.Thread(target=model_switch_listener, daemon=True).start()
    
    logger.info(f"Начало мониторинга трафика на интерфейсе: {interface}")
    logger.info("Нажмите 'M' для смены модели или 'Ctrl+C' для выхода")
    
    try:
        while True:
            if should_reload_model.is_set():
                if select_model():
                    logger.info(f"Модель успешно изменена на: {current_model}")
                should_reload_model.clear()
                
            if model_info:
                model, scaler = model_info  # Распаковываем кортеж
                monitor_traffic(interface, model, scaler)
            else:
                logger.error("Модель не загружена")
                break
                
    except KeyboardInterrupt:
        logger.info("\nЗавершение работы анализатора...")
    except Exception as e:
        logger.error(f"Ошибка при анализе трафика: {e}")

if __name__ == "__main__":
    main()
