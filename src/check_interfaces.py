import psutil
import os

def list_network_interfaces():
    print("\nДоступные сетевые интерфейсы:")
    print("-" * 50)
    for iface, stats in psutil.net_if_stats().items():
        if stats.isup:
            print(f"Интерфейс: {iface}")
            print(f"Статус: {'Активен' if stats.isup else 'Неактивен'}")
            print("-" * 50)

def find_model_file():
    print("\nПоиск файлов модели (.pth):")
    print("-" * 50)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for file in os.listdir(current_dir):
        if file.endswith('.pth'):
            print(f"Найден файл модели: {file}")
            print(f"Полный путь: {os.path.join(current_dir, file)}")

if __name__ == "__main__":
    print("Проверка системной конфигурации")
    print("=" * 50)
    list_network_interfaces()
    find_model_file()
