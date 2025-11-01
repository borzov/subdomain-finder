"""
Конфигурация для subdomain finder.

Содержит настройки по умолчанию для DNS-серверов, параметры
производительности и другие конфигурационные константы.
"""

from typing import List


class Config:
    """Настройки по умолчанию для subdomain finder."""
    
    # DNS серверы по умолчанию (быстрые и надежные)
    DEFAULT_NAMESERVERS: List[str] = [
        '8.8.8.8',          # Google Primary
        '8.8.4.4',          # Google Secondary
        '1.1.1.1',          # Cloudflare Primary
        '1.0.0.1',          # Cloudflare Secondary
        '208.67.222.222',   # OpenDNS Primary
        '208.67.220.220',   # OpenDNS Secondary
    ]
    
    # Параметры производительности
    DEFAULT_CONCURRENT: int = 150
    DEFAULT_TIMEOUT: float = 2.0
    BATCH_SIZE: int = 10000
    
    # Прогресс
    PROGRESS_UPDATE_INTERVAL: int = 100  # Обновлять каждые N запросов
    
    # Вывод
    BANNER: str = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           Fast Asynchronous Subdomain Finder             ║
║                     Version 2.0                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
