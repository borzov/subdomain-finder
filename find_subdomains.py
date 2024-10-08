import requests
import subprocess
from dns import resolver, exception
import argparse

def get_subdomains_from_sublist3r(domain):
    try:
        # Run sublist3r as a subprocess
        result = subprocess.run(['sublist3r', '-d', domain, '-o', 'subdomains.txt'], capture_output=True, text=True)
        if result.returncode == 0:
            with open('subdomains.txt', 'r') as file:
                subdomains = file.read().splitlines()
            os.remove('subdomains.txt')
            return subdomains
        else:
            print("Sublist3r failed to run.")
            return []
    except Exception as e:
        print(f"Error running Sublist3r: {e}")
        return []

def get_subdomains_from_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            json_data = response.json()
            subdomains = set()
            for entry in json_data:
                name_value = entry['name_value']
                subdomains.update(name_value.split('\n'))
            return list(subdomains)
        else:
            print("Failed to fetch data from crt.sh")
            return []
    except Exception as e:
        print(f"Error fetching data from crt.sh: {e}")
        return []

def get_subdomains_from_dns(domain):
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
    return subdomains

def main(domain):
    subdomains = set()

    # Get subdomains from Sublist3r
    print("Fetching subdomains using Sublist3r...")
    subdomains.update(get_subdomains_from_sublist3r(domain))

    # Get subdomains from crt.sh
    print("Fetching subdomains from crt.sh...")
    subdomains.update(get_subdomains_from_crtsh(domain))

    # Get subdomains from DNS brute forcing
    print("Fetching subdomains using DNS brute forcing...")
    subdomains.update(get_subdomains_from_dns(domain))

    print(f"\nFound {len(subdomains)} subdomains for {domain}:")
    for subdomain in sorted(subdomains):
        print(subdomain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find subdomains for a given domain.')
    parser.add_argument('domain', type=str, help='The domain to find subdomains for.')
    args = parser.parse_args()
    main(args.domain)
