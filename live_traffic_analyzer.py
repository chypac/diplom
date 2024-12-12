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
    base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset', 'archive (1)')
    models = []
    
    # Проходим по всем папкам с моделями
    for model_dir in os.listdir(base_path):
        model_path = os.path.join(base_path, model_dir, 'autoencoder_model.pth')
        if os.path.exists(model_path):
            models.append((model_dir, model_path))
    
    return models

def select_model():
    """Интерактивный выбор модели"""
    models = get_available_models()
    
    print("\nДоступные модели:")
    print("-" * 50)
    for i, (name, _) in enumerate(models, 1):
        print(f"{i}. {name}")
    
    while True:
        try:
            choice = int(input("\nВыберите номер модели: ")) - 1
            if 0 <= choice < len(models):
                return models[choice][1]
            print("Неверный номер. Попробуйте снова.")
        except ValueError:
            print("Пожалуйста, введите число.")

def model_switch_listener():
    """Поток для отслеживания нажатия клавиш"""
    global should_reload_model
    
    def on_key_event(e):
        if e.name == 'm':
            logger.info("Запрошена смена модели...")
            should_reload_model.set()
    
    keyboard.on_press(on_key_event)

def main():
    global current_model, model_info, should_reload_model
    
    parser = argparse.ArgumentParser(description='Анализ реального трафика на аномалии с использованием предобученной модели')
    parser.add_argument('--interface', type=str, 
                       default='Беспроводная сеть 2',
                       help='Сетевой интерфейс для мониторинга')
    parser.add_argument('--threshold', type=float, default=0.1, 
                       help='Порог для определения аномалий (по умолчанию: 0.1)')
    args = parser.parse_args()

    # Получение списка доступных интерфейсов
    available_interfaces = get_network_interfaces()
    
    if not available_interfaces:
        logger.error("Не найдено активных сетевых интерфейсов")
        return

    if args.interface not in available_interfaces:
        logger.error(f"Интерфейс {args.interface} не найден или неактивен")
        logger.info("Доступные интерфейсы: " + ", ".join(available_interfaces))
        return

    # Запуск потока отслеживания клавиш
    keyboard_thread = threading.Thread(target=model_switch_listener, daemon=True)
    keyboard_thread.start()

    try:
        while True:
            # Выбор модели
            if current_model is None or should_reload_model.is_set():
                model_path = select_model()
                if not os.path.exists(model_path):
                    logger.error(f"Файл модели не найден: {model_path}")
                    return

                # Загрузка модели
                model_info = load_model(model_path)
                if model_info is None:
                    logger.error("Не удалось загрузить модель")
                    return

                model, scaler = model_info  # Распаковываем кортеж
                current_model = model_path
                should_reload_model.clear()
                logger.info(f"Модель успешно загружена из {model_path}")
                logger.info(f"Для смены модели нажмите клавишу 'M'")

            logger.info(f"Начинаем мониторинг трафика на интерфейсе {args.interface}")
            logger.info(f"Порог определения аномалий: {args.threshold}")

            # Запуск мониторинга с правильными аргументами
            monitor_thread = threading.Thread(
                target=monitor_traffic,
                args=(args.interface, model, scaler),
                daemon=True
            )
            monitor_thread.start()

            # Ожидание запроса на смену модели
            while not should_reload_model.is_set():
                sleep(1)

            logger.info("Перезагрузка модели...")

    except KeyboardInterrupt:
        logger.info("Мониторинг остановлен пользователем")
    except Exception as e:
        logger.error(f"Произошла ошибка: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
