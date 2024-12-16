import os
import shutil
from pathlib import Path
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProjectOrganizer:
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        
        # Определяем структуру директорий
        self.structure = {
            'src': ['*.py'],  # Исходный код
            'models': ['*.pth', '*.pt', '*.h5'],  # Модели
            'data': ['*.csv', '*.json', '*.txt', '*.pcap', '*.pcapng'],  # Данные
            'logs': ['*.log'],  # Логи
            'tests': ['test_*.py'],  # Тесты
            'docs': ['*.md', '*.txt', 'LICENSE'],  # Документация
            'config': ['*.yml', '*.yaml', '*.json', '*.ini'],  # Конфигурационные файлы
        }
        
        # Файлы, которые должны остаться в корневой директории
        self.root_files = [
            'README.md',
            'requirements.txt',
            '.gitignore',
            'LICENSE',
            'setup.py'
        ]
        
        # Директории, которые нужно игнорировать
        self.ignore_dirs = [
            '__pycache__',
            '.git',
            '.pytest_cache',
            'venv',
            '.env'
        ]

    def scan_directory(self):
        """Сканирование директории и вывод текущей структуры"""
        logger.info("Сканирование директории проекта...")
        
        for item in self.project_root.rglob('*'):
            if item.is_file():
                rel_path = item.relative_to(self.project_root)
                logger.info(f"Файл: {rel_path}")
            elif item.is_dir() and item.name not in self.ignore_dirs:
                rel_path = item.relative_to(self.project_root)
                logger.info(f"Директория: {rel_path}")

    def create_directory_structure(self):
        """Создание структуры директорий"""
        logger.info("Создание структуры директорий...")
        
        for directory in self.structure.keys():
            dir_path = self.project_root / directory
            if not dir_path.exists():
                dir_path.mkdir(parents=True)
                logger.info(f"Создана директория: {directory}")

    def should_move_file(self, file_path):
        """Проверка, нужно ли перемещать файл"""
        # Игнорируем текущий скрипт
        if file_path.name == os.path.basename(__file__):
            return False
            
        # Проверяем, должен ли файл остаться в корне
        if file_path.name in self.root_files:
            return False
            
        return True

    def get_target_directory(self, file_path):
        """Определение целевой директории для файла"""
        file_name = file_path.name
        file_ext = file_path.suffix.lower()
        
        # Проверяем каждую директорию и её паттерны
        for directory, patterns in self.structure.items():
            for pattern in patterns:
                if pattern.startswith('*'):
                    if file_ext == pattern[1:]:
                        return directory
                elif pattern.endswith('*'):
                    if file_name.startswith(pattern[:-1]):
                        return directory
                elif file_name == pattern:
                    return directory
        
        return 'src'  # По умолчанию помещаем в src

    def organize_files(self, dry_run=True):
        """Организация файлов по директориям"""
        logger.info("Начало организации файлов...")
        logger.info(f"Режим: {'тестовый' if dry_run else 'реальный'}")
        
        # Сначала создаём структуру директорий
        self.create_directory_structure()
        
        # Перебираем все файлы в директории
        for item in self.project_root.rglob('*'):
            # Пропускаем директории и игнорируемые папки
            if item.is_dir() or any(ignore in str(item) for ignore in self.ignore_dirs):
                continue
                
            # Проверяем, нужно ли перемещать файл
            if not self.should_move_file(item):
                continue
            
            # Определяем целевую директорию
            target_dir = self.get_target_directory(item)
            target_path = self.project_root / target_dir / item.name
            
            # Проверяем, не находится ли файл уже в правильной директории
            if item.parent.name == target_dir:
                continue
            
            if dry_run:
                logger.info(f"[ТЕСТ] Перемещение {item.relative_to(self.project_root)} -> {target_dir}/{item.name}")
            else:
                try:
                    # Создаём директорию, если её нет
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Перемещаем файл
                    shutil.move(str(item), str(target_path))
                    logger.info(f"Перемещено: {item.relative_to(self.project_root)} -> {target_dir}/{item.name}")
                except Exception as e:
                    logger.error(f"Ошибка при перемещении {item}: {e}")

def main():
    # Получаем абсолютный путь к директории проекта
    project_root = Path(__file__).parent.absolute()
    
    # Создаём организатор проекта
    organizer = ProjectOrganizer(project_root)
    
    # Сначала показываем текущую структуру
    logger.info("=== Текущая структура проекта ===")
    organizer.scan_directory()
    
    # Спрашиваем пользователя, хочет ли он продолжить
    response = input("\nПоказать предлагаемые изменения? (y/n): ")
    if response.lower() == 'y':
        logger.info("\n=== Предлагаемые изменения ===")
        organizer.organize_files(dry_run=True)
        
        response = input("\nПрименить изменения? (y/n): ")
        if response.lower() == 'y':
            logger.info("\n=== Применение изменений ===")
            organizer.organize_files(dry_run=False)
            logger.info("Организация проекта завершена!")
        else:
            logger.info("Операция отменена.")
    else:
        logger.info("Операция отменена.")

if __name__ == "__main__":
    main()
