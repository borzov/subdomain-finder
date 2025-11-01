"""
Вспомогательные функции для работы с поддоменами.
"""

import json
import csv
import re
import time
import ipaddress
from typing import Set, Dict, List, Optional
from pathlib import Path
from config import Config


def validate_domain(domain: str) -> bool:
    """
    Валидация имени домена.
    
    Args:
        domain: Имя домена для проверки
        
    Returns:
        True если домен валидный
    """
    if not domain or len(domain) > 253:  # RFC 1035 максимальная длина
        return False
    
    # Базовая проверка формата домена
    # Допускаем буквы, цифры, точки, дефисы, подчеркивания
    # Должен содержать хотя бы одну точку и TLD минимум 2 символа
    if '.' not in domain:
        return False
    
    # Проверяем что нет двойных точек подряд
    if '..' in domain:
        return False
    
    # Проверяем что нет запрещенных символов
    if not re.match(r'^[a-z0-9._-]+$', domain, re.IGNORECASE):
        return False
    
    # Проверяем что домен не начинается и не заканчивается точкой или дефисом
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if domain.startswith('-') or domain.endswith('-'):
        return False
    
    # Проверяем что есть TLD (минимум 2 символа после последней точки)
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    
    return True


def sanitize_output_path(output_path: str, domain: str) -> str:
    """
    Очистка пути выходного файла от path traversal атак.
    
    Args:
        output_path: Путь к выходному файлу
        domain: Имя домена (для проверки)
        
    Returns:
        Очищенный путь
    """
    # Убираем опасные символы и path traversal
    path = Path(output_path)
    
    # Если это абсолютный путь, проверяем что он в results/
    if path.is_absolute():
        resolved = path.resolve()
        cwd = Path.cwd()
        results_dir = cwd / 'results'
        
        # Проверяем что путь ведет в папку results/
        try:
            resolved.relative_to(results_dir)
        except ValueError:
            # Путь не в results/ - запрещаем
            raise ValueError(
                f"Выходной путь должен быть в папке results/: {output_path}"
            )
    
    # Убираем .. и другие опасные элементы из относительного пути
    if '..' in str(path):
        # Если есть path traversal, берем только имя файла
        sanitized = path.name
    else:
        # Используем путь как есть, но очищаем имя файла
        sanitized = str(path)
    
    # Убираем опасные символы из пути
    sanitized = re.sub(r'[^\w\-_./]', '_', sanitized)
    
    return sanitized


def load_wordlist(filepath: str) -> Set[str]:
    """
    Загрузка словаря с дедупликацией
    
    Args:
        filepath: Путь к файлу словаря
        
    Returns:
        Множество уникальных поддоменов
    """
    subdomains = set()
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                subdomain = line.strip().lower()
                
                # Пропускаем пустые строки и комментарии
                if not subdomain or subdomain.startswith('#'):
                    continue
                
                # Базовая валидация
                if subdomain and len(subdomain) < 64:  # RFC ограничение
                    # Удаляем недопустимые символы
                    if all(c.isalnum() or c in '-_' for c in subdomain):
                        subdomains.add(subdomain)
                        
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
        return set()
    
    return subdomains


def ensure_output_dir(output_file: str) -> Path:
    """
    Создает директорию для выходного файла, если её нет.
    
    Args:
        output_file: Путь к выходному файлу
        
    Returns:
        Path объект выходной директории
    """
    output_path = Path(output_file)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_path


def save_results(results: Dict[str, List[str]], 
                output_file: str,
                format: str = 'txt') -> str:
    """
    Сохранение результатов в файл.
    
    Args:
        results: Словарь {subdomain: [ips]}
        output_file: Путь к выходному файлу (может быть относительным или абсолютным)
        format: Формат вывода (txt, json, csv)
    
    Returns:
        Абсолютный путь к созданному файлу
    """
    # Создаем директорию если нужно
    output_path = ensure_output_dir(output_file)
    
    # Сортировка результатов
    sorted_results = sorted(results.items())
    
    if format == 'txt':
        with open(output_path, 'w', encoding='utf-8') as f:
            for subdomain, ips in sorted_results:
                f.write(f"{subdomain}\n")
                for ip in ips:
                    f.write(f"  -> {ip}\n")
                f.write("\n")
    
    elif format == 'json':
        data = [
            {
                'subdomain': subdomain,
                'ips': ips
            }
            for subdomain, ips in sorted_results
        ]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    elif format == 'csv':
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'IP Addresses'])
            
            for subdomain, ips in sorted_results:
                writer.writerow([subdomain, ', '.join(ips)])
    
    return str(output_path.resolve())


def generate_keenetic_routes(results: Dict[str, List[str]], 
                            domain: str,
                            output_file: Optional[str] = None) -> str:
    """
    Генерация файла маршрутов для роутеров Keenetic в формате DAT.
    
    Собирает все уникальные IP из результатов, конвертирует их в сети /24
    и генерирует команды route add для Keenetic.
    
    Args:
        results: Словарь найденных поддоменов и их IP
        domain: Имя домена (используется для имени файла и папки)
        output_file: Путь к выходному файлу (по умолчанию results/{domain}/{domain}.dat)
    
    Returns:
        Путь к созданному файлу
    """
    if output_file is None:
        output_file = f"results/{domain}/{domain}.dat"
    
    # Создаем директорию если нужно
    output_path = ensure_output_dir(output_file)
    
    # Собираем все уникальные IP
    all_ips: Set[str] = set()
    for ips in results.values():
        all_ips.update(ips)
    
    if not all_ips:
        return str(output_path.resolve())
    
    # Конвертируем IP в сети /24
    networks: Set[str] = set()
    for ip_str in all_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            # Создаем сеть /24 для этого IP
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            networks.add(str(network.network_address))
        except (ValueError, ipaddress.AddressValueError):
            continue
    
    # Сортируем сети
    sorted_networks = sorted(networks, key=lambda x: ipaddress.ip_address(x))
    
    # Генерируем DAT файл
    with open(output_path, 'w', encoding='utf-8') as f:
        for network_ip in sorted_networks:
            # Формат: route add IP mask 255.255.255.0 0.0.0.0
            f.write(f"route add {network_ip} mask 255.255.255.0 0.0.0.0\n")
    
    return str(output_path.resolve())


def print_banner():
    """Вывод баннера"""
    print(Config.BANNER)


def format_time(seconds: float) -> str:
    """
    Форматирование времени
    
    Args:
        seconds: Время в секундах
        
    Returns:
        Отформатированная строка
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


class ProgressTracker:
    """Трекер прогресса сканирования"""
    
    def __init__(self, total: int):
        self.total = total
        self.checked = 0
        self.start_time = None
        self.last_update = 0
        
    def start(self):
        """Запуск трекера"""
        self.start_time = time.time()
        self.checked = 0
        
    def increment(self):
        """Увеличение счетчика"""
        self.checked += 1
        
        # Обновляем прогресс каждые N запросов
        if self.checked - self.last_update >= Config.PROGRESS_UPDATE_INTERVAL:
            self.print_progress()
            self.last_update = self.checked
    
    def print_progress(self):
        """Вывод прогресса"""
        if not self.start_time:
            return
        
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return
        
        rate = self.checked / elapsed
        percent = (self.checked / self.total) * 100
        
        # Оценка оставшегося времени
        if rate > 0:
            remaining = (self.total - self.checked) / rate
            eta = format_time(remaining)
        else:
            eta = "N/A"
        
        print(f"[*] Progress: {self.checked}/{self.total} ({percent:.1f}%) | "
              f"Rate: {rate:.0f} req/s | ETA: {eta}")
    
    def stop(self):
        """Остановка трекера"""
        if self.checked < self.total:
            self.print_progress()
