#!/usr/bin/env python3
"""
Optimized Subdomain Finder.

Асинхронный сканер поддоменов с высокой производительностью.
Использует несколько методов поиска: SSL-сертификаты (crt.sh), OSINT (Sublist3r),
и DNS brute forcing для максимального покрытия.
"""

import asyncio
import argparse
import logging
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

import dns.asyncresolver
import dns.exception
import dns.resolver
import requests

from config import Config
from utils import (
    format_time,
    generate_keenetic_routes,
    load_wordlist,
    print_banner,
    ProgressTracker,
    save_results,
    validate_domain,
    sanitize_output_path,
)


class SubdomainFinder:
    """Основной класс для поиска поддоменов"""
    
    def __init__(self, 
                 domain: str,
                 wordlist: Optional[str],
                 nameservers: Optional[List[str]] = None,
                 max_concurrent: int = 150,
                 timeout: float = 2.0,
                 verbose: bool = False):
        """
        Инициализация сканера
        
        Args:
            domain: Целевой домен
            wordlist: Путь к файлу со словарем (опционально)
            nameservers: Список DNS-серверов
            max_concurrent: Максимальное количество одновременных запросов
            timeout: Таймаут для DNS-запросов
            verbose: Подробный вывод
        """
        # Валидация и нормализация домена
        domain = domain.lower().strip()
        if not validate_domain(domain):
            raise ValueError(f"Некорректное имя домена: {domain}")
        
        self.domain = domain
        self.wordlist = wordlist
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.verbose = verbose
        
        # Результаты
        self.found_subdomains: Dict[str, List[str]] = {}  # {subdomain: [ips]}
        self.wildcard_detected = False
        self.wildcard_ips: Set[str] = set()
        
        # Настройка резолвера
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            self.resolver.nameservers = Config.DEFAULT_NAMESERVERS
        
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def get_subdomains_from_crtsh(self) -> Set[str]:
        """
        Получение поддоменов из SSL-сертификатов через crt.sh
        
        Returns:
            Множество найденных поддоменов
        """
        print("[*] Запрос к crt.sh для поиска поддоменов из SSL-сертификатов...")
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                except (ValueError, requests.exceptions.JSONDecodeError) as e:
                    print(f"[-] Ошибка парсинга JSON от crt.sh: {e}")
                    return subdomains
                for entry in json_data:
                    name_value = entry.get('name_value', '')
                    # Разбиваем по переносам строк
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name:
                            # Убираем wildcard
                            if name.startswith('*.'):
                                name = name[2:]
                            # Проверяем, что это поддомен целевого домена
                            if name == self.domain:
                                continue  # Пропускаем сам домен
                            elif name.endswith(f'.{self.domain}'):
                                # Это поддомен, извлекаем префикс
                                subdomain = name[:-len(f'.{self.domain}')].strip()
                                if subdomain:
                                    subdomains.add(subdomain)
                            elif self.domain in name:
                                # Может быть случай типа "subdomain.example.com" или "example.com.subdomain"
                                parts = name.split('.')
                                try:
                                    domain_idx = -1
                                    for i, part in enumerate(parts):
                                        if '.'.join(parts[i:]) == self.domain or \
                                           (i < len(parts) - 1 and '.'.join(parts[i:i+2]) == self.domain):
                                            domain_idx = i
                                            break
                                    
                                    if domain_idx > 0:
                                        # Есть префикс перед доменом
                                        subdomain = '.'.join(parts[:domain_idx])
                                        if subdomain:
                                            subdomains.add(subdomain)
                                except (IndexError, ValueError) as e:
                                    if self.verbose:
                                        logging.debug(f"Ошибка обработки домена {name}: {e}")
                                    continue
                
                print(f"[+] Найдено {len(subdomains)} уникальных поддоменов из crt.sh")
            else:
                print(f"[-] Не удалось получить данные с crt.sh (HTTP {response.status_code})")
        except Exception as e:
            print(f"[-] Ошибка при запросе к crt.sh: {e}")
        
        return subdomains
    
    def get_subdomains_from_sublist3r(self) -> Set[str]:
        """
        Получение поддоменов через Sublist3r (если установлен)
        
        Returns:
            Множество найденных поддоменов
        """
        print("[*] Попытка запуска Sublist3r для поиска поддоменов...")
        subdomains = set()
        
        try:
            # Проверяем наличие sublist3r
            result = subprocess.run(['which', 'sublist3r'], capture_output=True, text=True)
            if result.returncode != 0:
                print("[*] Sublist3r не установлен, пропускаем этот метод")
                return subdomains
            
            output_file = f'sublist3r_output_{int(time.time())}.txt'
            result = subprocess.run(
                ['sublist3r', '-d', self.domain, '-o', output_file],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as file:
                    for line in file:
                        subdomain = line.strip().lower()
                        if subdomain and subdomain != self.domain:
                            # Убираем домен, оставляем только поддомен
                            if subdomain.endswith(f'.{self.domain}'):
                                subdomain_name = subdomain.replace(f'.{self.domain}', '').strip()
                                if subdomain_name:
                                    subdomains.add(subdomain_name)
                            elif subdomain == self.domain:
                                continue
                            else:
                                subdomains.add(subdomain)
                
                os.remove(output_file)
                print(f"[+] Найдено {len(subdomains)} уникальных поддоменов из Sublist3r")
            else:
                print("[-] Sublist3r не смог найти поддомены или завершился с ошибкой")
        except subprocess.TimeoutExpired:
            print("[-] Sublist3r превысил время ожидания (5 минут)")
        except Exception as e:
            print(f"[-] Ошибка при запуске Sublist3r: {e}")
        
        return subdomains
    
    async def check_wildcard(self) -> bool:
        """
        Проверка на wildcard DNS
        
        Returns:
            True если обнаружен wildcard
        """
        print("[*] Checking for wildcard DNS...")
        
        # Генерируем несколько случайных поддоменов
        test_subdomains = [
            f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=20))}.{self.domain}"
            for _ in range(5)
        ]
        
        wildcard_responses = []
        
        for test_domain in test_subdomains:
            try:
                answers = await self.resolver.resolve(test_domain, 'A')
                ips = {str(rdata) for rdata in answers}
                wildcard_responses.append(ips)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                # Это нормально для случайных доменов
                continue
            except Exception as e:
                if self.verbose:
                    logging.debug(f"Ошибка при проверке wildcard для {test_domain}: {e}")
                continue
        
        # Если хотя бы 3 из 5 случайных доменов резолвятся
        if len(wildcard_responses) >= 3:
            # Проверяем, что они резолвятся в одинаковые IP
            if len(wildcard_responses) > 0:
                first_ips = wildcard_responses[0]
                if all(ips == first_ips for ips in wildcard_responses[1:]):
                    self.wildcard_detected = True
                    self.wildcard_ips = first_ips
                    print(f"[!] Wildcard DNS detected! IPs: {', '.join(first_ips)}")
                    print("[*] Will filter out wildcard responses")
                    return True
        
        print("[+] No wildcard DNS detected")
        return False
    
    async def resolve_subdomain(self, subdomain: str) -> Optional[List[str]]:
        """
        Резолв одного поддомена через DNS.
        
        Проверяет существование поддомена через DNS A-запрос.
        Возвращает список IP-адресов только если поддомен действительно существует
        и резолвится в IP.
        
        Args:
            subdomain: Имя поддомена (без домена)
            
        Returns:
            Список IP-адресов или None если поддомен не существует
        """
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            answers = await self.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Фильтрация wildcard
            if self.wildcard_detected:
                ips_set = set(ips)
                if ips_set == self.wildcard_ips:
                    return None  # Это wildcard ответ
            
            # Поддомен существует и резолвится - возвращаем IP
            return ips
            
        except dns.resolver.NXDOMAIN:
            # Домен не существует - это нормально
            return None
        except dns.resolver.NoAnswer:
            # Нет A-записи
            return None
        except dns.resolver.NoNameservers:
            # Все nameservers failed
            if self.verbose:
                logging.warning(f"No nameservers responded for {full_domain}")
            return None
        except dns.exception.Timeout:
            # Таймаут
            if self.verbose:
                logging.warning(f"Timeout for {full_domain}")
            return None
        except Exception as e:
            if self.verbose:
                logging.warning(f"Error resolving {full_domain}: {e}")
            return None
    
    async def check_subdomain(self, 
                             subdomain: str,
                             semaphore: asyncio.Semaphore,
                             progress: ProgressTracker) -> None:
        """
        Проверка поддомена с семафором и прогрессом
        
        Args:
            subdomain: Имя поддомена
            semaphore: Семафор для ограничения конкурентности
            progress: Трекер прогресса
        """
        async with semaphore:
            full_domain = f"{subdomain}.{self.domain}"
            
            try:
                ips = await self.resolve_subdomain(subdomain)
                
                if ips:
                    self.found_subdomains[full_domain] = ips
                    print(f"[+] Found: {full_domain} -> {', '.join(ips)}")
                    
            finally:
                progress.increment()
    
    async def scan_batch(self, 
                        subdomains: List[str],
                        semaphore: asyncio.Semaphore,
                        progress: ProgressTracker) -> None:
        """
        Сканирование батча поддоменов
        
        Args:
            subdomains: Список поддоменов для проверки
            semaphore: Семафор для ограничения конкурентности
            progress: Трекер прогресса
        """
        tasks = [
            self.check_subdomain(subdomain, semaphore, progress)
            for subdomain in subdomains
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def run(self) -> Dict[str, List[str]]:
        """
        Запуск сканирования
        
        Returns:
            Словарь найденных поддоменов и их IP
        """
        start_time = time.time()
        
        # Собираем поддомены из разных источников
        all_subdomains = set()
        
        # 1. crt.sh (SSL сертификаты)
        crtsh_subdomains = self.get_subdomains_from_crtsh()
        all_subdomains.update(crtsh_subdomains)
        print()
        
        # 2. Sublist3r (OSINT)
        sublist3r_subdomains = self.get_subdomains_from_sublist3r()
        all_subdomains.update(sublist3r_subdomains)
        print()
        
        # 3. Загрузка словаря для DNS brute forcing
        if self.wordlist and Path(self.wordlist).exists():
            print(f"[*] Загрузка словаря из {self.wordlist}")
            wordlist_subdomains = load_wordlist(self.wordlist)
            all_subdomains.update(wordlist_subdomains)
            print(f"[*] Загружено {len(wordlist_subdomains)} поддоменов из словаря")
        else:
            print("[*] Словарь не указан или не найден, пропускаем DNS brute forcing")
            wordlist_subdomains = set()
        
        print()
        print(f"[*] Всего собрано {len(all_subdomains)} уникальных поддоменов для проверки")
        print(f"[*] - Из crt.sh: {len(crtsh_subdomains)}")
        print(f"[*] - Из Sublist3r: {len(sublist3r_subdomains)}")
        print(f"[*] - Из словаря: {len(wordlist_subdomains)}")
        print()
        
        if not all_subdomains:
            print("[!] Не найдено поддоменов для проверки!")
            return {}
        
        print(f"[*] Целевой домен: {self.domain}")
        print(f"[*] Используется {len(self.resolver.nameservers)} DNS-серверов: {', '.join(self.resolver.nameservers)}")
        print(f"[*] Параллельность: {self.max_concurrent}")
        print(f"[*] Таймаут: {self.timeout}s")
        print()
        
        # Проверка wildcard
        await self.check_wildcard()
        print()
        
        # Инициализация прогресса
        progress = ProgressTracker(total=len(all_subdomains))
        progress.start()
        
        # Создание семафора
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Разбивка на батчи для больших списков
        batch_size = 10000
        subdomain_list = list(all_subdomains)
        
        print(f"[*] Начало DNS-проверки найденных поддоменов...")
        print()
        
        for i in range(0, len(subdomain_list), batch_size):
            batch = subdomain_list[i:i + batch_size]
            await self.scan_batch(batch, semaphore, progress)
        
        # Завершение
        elapsed = time.time() - start_time
        progress.stop()
        
        print()
        print("=" * 60)
        print(f"[*] Сканирование завершено за {format_time(elapsed)}")
        if elapsed > 0:
            print(f"[*] Средняя скорость: {len(all_subdomains)/elapsed:.0f} запросов/секунду")
        print(f"[*] Найдено {len(self.found_subdomains)} активных поддоменов")
        print("=" * 60)
        
        return self.found_subdomains


async def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Fast asynchronous subdomain finder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com -w wordlists/subdomains.txt
  %(prog)s -d example.com -w wordlists/subdomains.txt -c 200 -t 3
  %(prog)s -d example.com -w wordlists/subdomains.txt -o results.json --format json
  %(prog)s -d example.com -w wordlists/subdomains.txt --dns 8.8.8.8 1.1.1.1
        """
    )
    
    parser.add_argument('-d', '--domain', 
                       required=True,
                       help='Target domain')
    
    parser.add_argument('-w', '--wordlist',
                       required=False,
                       help='Path to wordlist file (optional, для DNS brute forcing)')
    
    parser.add_argument('-o', '--output',
                       default=None,
                       help='Output file name (default: results.{format} in results/{domain}/)')
    
    parser.add_argument('-f', '--format',
                       choices=['txt', 'json', 'csv'],
                       default='txt',
                       help='Output format (default: txt)')
    
    parser.add_argument('-c', '--concurrent',
                       type=int,
                       default=150,
                       help='Max concurrent requests (default: 150)')
    
    parser.add_argument('-t', '--timeout',
                       type=float,
                       default=2.0,
                       help='DNS timeout in seconds (default: 2.0)')
    
    parser.add_argument('--dns',
                       nargs='+',
                       help='Custom DNS servers (space separated)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output')
    
    parser.add_argument('--no-banner',
                       action='store_true',
                       help='Disable banner')
    
    parser.add_argument('--keenetic',
                       action='store_true',
                       help='Generate Keenetic router routes file (.dat)')
    
    args = parser.parse_args()
    
    # Баннер
    if not args.no_banner:
        print_banner()
    
    # Валидация домена
    try:
        if not validate_domain(args.domain):
            print(f"[!] Ошибка: Некорректное имя домена: {args.domain}")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Ошибка при валидации домена: {e}")
        sys.exit(1)
    
    # Проверка файла словаря (если указан)
    if args.wordlist and not Path(args.wordlist).exists():
        print(f"[!] Ошибка: Файл словаря не найден: '{args.wordlist}'")
        sys.exit(1)
    
    # Проверка параметров
    if args.concurrent < 1:
        print("[!] Ошибка: Параметр --concurrent должен быть больше 0")
        sys.exit(1)
    
    if args.timeout < 0.1:
        print("[!] Ошибка: Параметр --timeout должен быть больше 0.1")
        sys.exit(1)
    
    # Создание сканера
    try:
        finder = SubdomainFinder(
            domain=args.domain,
            wordlist=args.wordlist,
            nameservers=args.dns,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            verbose=args.verbose
        )
    except ValueError as e:
        print(f"[!] Ошибка: {e}")
        sys.exit(1)
    
    # Запуск сканирования
    try:
        results = await finder.run()
        
        # Сохранение результатов
        if results:
            print()
            
            # Формируем путь для результатов с защитой от path traversal
            if args.output is None:
                # По умолчанию: results/{domain}/results.{format}
                output_file = f"results/{args.domain}/results.{args.format}"
            else:
                # Защита от path traversal
                sanitized_output = sanitize_output_path(args.output, args.domain)
                if '/' not in args.output or args.output.startswith('results/'):
                    # Относительный путь или уже в results/
                    if args.output.startswith('results/'):
                        output_file = sanitized_output
                    else:
                        output_file = f"results/{args.domain}/{sanitized_output}"
                else:
                    # Абсолютный путь - используем как есть (но с проверкой)
                    output_file = sanitized_output
            
            print(f"[*] Сохранение результатов в {output_file}")
            saved_path = save_results(results, output_file, args.format)
            print(f"[+] Результаты успешно сохранены: {saved_path}")
            
            # Генерация файла маршрутов для Keenetic
            if args.keenetic:
                dat_file = generate_keenetic_routes(results, args.domain)
                print(f"[+] Файл маршрутов для Keenetic создан: {dat_file}")
        else:
            print()
            print("[!] Поддомены не найдены")
            
    except KeyboardInterrupt:
        print()
        print("[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print()
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
