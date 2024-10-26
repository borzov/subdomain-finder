import requests
import subprocess
import os
import logging
from dns import resolver, exception
import argparse
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_subdomains_from_sublist3r(domain):
    logging.info("Запуск Sublist3r для поиска поддоменов...")
    try:
        result = subprocess.run(['sublist3r', '-d', domain, '-o', 'sublist3r_output.txt'], capture_output=True, text=True)
        if result.returncode == 0:
            with open('sublist3r_output.txt', 'r') as file:
                subdomains = file.read().splitlines()
            os.remove('sublist3r_output.txt')
            logging.info(f"Найдено {len(subdomains)} поддоменов с помощью Sublist3r.")
            return subdomains
        else:
            logging.error("Sublist3r не удалось запустить.")
            return []
    except Exception as e:
        logging.error(f"Ошибка при запуске Sublist3r: {e}")
        return []

def get_subdomains_from_crtsh(domain):
    logging.info("Запрос к crt.sh для поиска поддоменов...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            json_data = response.json()
            subdomains = set()
            for entry in json_data:
                name_value = entry['name_value']
                subdomains.update(name_value.split('\n'))
            logging.info(f"Найдено {len(subdomains)} поддоменов с помощью crt.sh.")
            return list(subdomains)
        else:
            logging.error("Не удалось получить данные с crt.sh.")
            return []
    except Exception as e:
        logging.error(f"Ошибка при запросе к crt.sh: {e}")
        return []

def get_subdomains_from_dns(domain):
    logging.info("Начало DNS brute forcing...")
    subdomains = []
    common_subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'staging', 'api', 'blog', 'shop', 'support']
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(subdomain, 'A')
            for _ in answers:
                subdomains.append(subdomain)
        except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
            continue
    logging.info(f"Найдено {len(subdomains)} поддоменов с помощью DNS brute forcing.")
    return subdomains

def main(domain):
    subdomains = set()

    # Use ThreadPoolExecutor for parallel execution
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(get_subdomains_from_sublist3r, domain),
            executor.submit(get_subdomains_from_crtsh, domain),
            executor.submit(get_subdomains_from_dns, domain)
        ]
        for future in futures:
            subdomains.update(future.result())

    logging.info(f"Всего найдено {len(subdomains)} поддоменов для {domain}.")

    # Save subdomains to a file
    with open('subdomains.txt', 'w') as file:
        for subdomain in sorted(subdomains):
            file.write(subdomain + '\n')

    logging.info("Список поддоменов сохранен в файл subdomains.txt.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find subdomains for a given domain.')
    parser.add_argument('domain', type=str, help='The domain to find subdomains for.')
    args = parser.parse_args()
    main(args.domain)
