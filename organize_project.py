import os
import shutil
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProjectOrganizer:
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.src_dir = self.project_root / 'src'
        self.tests_dir = self.project_root / 'tests'
        self.docs_dir = self.project_root / 'docs'
        self.data_dir = self.project_root / 'data'
        self.models_dir = self.project_root / 'models'
        self.logs_dir = self.project_root / 'logs'
        self.config_dir = self.project_root / 'config'

    def create_directory_structure(self):
        """Создание основной структуры директорий"""
        directories = [
            self.src_dir,
            self.tests_dir,
            self.docs_dir,
            self.data_dir,
            self.models_dir,
            self.logs_dir,
            self.config_dir
        ]

        for directory in directories:
            if not directory.exists():
                directory.mkdir(parents=True)
                logger.info(f"Создана директория: {directory}")
            else:
                logger.info(f"Директория уже существует: {directory}")

    def move_python_files(self):
        """Перемещение Python файлов в src"""
        python_files = [
            'attack_simulator.py',
            'check_interfaces.py',
            'detection_system.py',
            'live_traffic_analyzer.py',
            'networc_interface.py'
        ]

        for file_name in python_files:
            src_file = self.project_root / file_name
            dst_file = self.src_dir / file_name
            
            if src_file.exists():
                if not dst_file.exists():
                    shutil.move(str(src_file), str(dst_file))
                    logger.info(f"Перемещен файл: {file_name} в src/")
                else:
                    logger.warning(f"Файл уже существует в src/: {file_name}")
            else:
                logger.warning(f"Файл не найден: {file_name}")

    def clean_pycache(self):
        """Удаление файлов кэша Python"""
        pycache_dirs = list(self.project_root.rglob("__pycache__"))
        for pycache_dir in pycache_dirs:
            shutil.rmtree(pycache_dir)
            logger.info(f"Удалена директория кэша: {pycache_dir}")

    def organize_project(self):
        """Основная функция организации проекта"""
        logger.info("Начало организации проекта...")
        
        # Создаем структуру директорий
        self.create_directory_structure()
        
        # Перемещаем Python файлы
        self.move_python_files()
        
        # Очищаем кэш
        self.clean_pycache()
        
        logger.info("Организация проекта завершена")

    def print_project_structure(self):
        """Вывод структуры проекта"""
        logger.info("\nСтруктура проекта:")
        for path in sorted(self.project_root.rglob("*")):
            # Пропускаем скрытые файлы и директории
            if any(part.startswith('.') for part in path.parts):
                continue
            
            # Вычисляем относительный путь
            relative_path = path.relative_to(self.project_root)
            depth = len(relative_path.parts) - 1
            prefix = "    " * depth + ("└── " if depth > 0 else "")
            
            # Выводим информацию о файле/директории
            if path.is_file():
                size = path.stat().st_size
                size_str = f"({size:,} bytes)" if size < 1024 else f"({size/1024:.1f} KB)"
                print(f"{prefix}{path.name} {size_str}")
            else:
                print(f"{prefix}{path.name}/")

if __name__ == "__main__":
    # Путь к корню проекта
    project_root = Path(__file__).parent
    
    # Создаем организатор проекта
    organizer = ProjectOrganizer(project_root)
    
    # Выводим текущую структуру
    print("\nТекущая структура проекта:")
    organizer.print_project_structure()
    
    # Спрашиваем пользователя о продолжении
    response = input("\nХотите организовать проект? (y/n): ")
    if response.lower() == 'y':
        organizer.organize_project()
        print("\nОбновленная структура проекта:")
        organizer.print_project_structure()
    else:
        print("Операция отменена")
