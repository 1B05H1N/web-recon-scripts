import os
import re
import socket
import subprocess
from pathlib import Path
import argparse
from concurrent.futures import ThreadPoolExecutor

try:
    import shodan
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'your_shodan_api_key_here')
    api = shodan.Shodan(SHODAN_API_KEY)
    use_shodan = True
    print("Shodan API initialized successfully.")
except ImportError:
    use_shodan = False
    print("Shodan module not found, proceeding without Shodan API features.")

def sanitize_filename(name):
    """Remove problematic characters from filenames."""
    return re.sub(r'[\\/*?:"<>|]', "", name)

def create_output_directory(path):
    """Ensure the output directory exists."""
    path.mkdir(parents=True, exist_ok=True)
    print(f"Output directory created: {path}")

def enumerate_subdomains(domain):
    """Use amass for subdomain enumeration."""
    output_file = Path(f"{sanitize_filename(domain)}_subdomains.txt")
    command = f"amass enum -d {domain} -o {output_file}"
    try:
        print(f"Starting enumeration for domain: {domain}")
        subprocess.run(command, shell=True, check=True)
        subdomains = output_file.read_text().splitlines()
        output_file.unlink()  # Clean up output file
        print(f"Enumeration completed for domain: {domain}. Found subdomains: {subdomains}")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"Error executing amass command for {domain}: {e}")
        return []
    except FileNotFoundError:
        print(f"Output file not found: {output_file}")
        return []

def get_shodan_info(ip):
    """Retrieve information on a given IP from Shodan."""
    if not use_shodan:
        print("Shodan lookup is skipped because Shodan is not available.")
        return "Shodan is not available or IP not found"
    try:
        print(f"Retrieving Shodan information for IP: {ip}")
        host_info = api.host(ip)
        info = f"IP: {host_info['ip_str']}\n" + "\n".join(
            f"Port: {item['port']} | Data: {item.get('data', 'No data')}" for item in host_info.get('data', [])
        )
        print(f"Shodan information retrieved successfully for IP: {ip}")
        return info
    except Exception as e:
        print(f"Shodan API error for IP {ip}: {e}")
        return f"Shodan API error: {e}"

def process_subdomain(subdomain):
    """Process a single subdomain to get IP and Shodan info."""
    try:
        print(f"Resolving IP for subdomain: {subdomain}")
        ip = socket.gethostbyname(subdomain)
        print(f"IP resolved for subdomain {subdomain}: {ip}")
    except socket.gaierror:
        ip = "IP not found"
        print(f"Failed to resolve IP for subdomain: {subdomain}")
    shodan_info = get_shodan_info(ip)
    return f"Subdomain: {subdomain}\nIP Address: {ip}\nShodan Info:\n{shodan_info}\n\n"

def process_domains(domains, output_dir):
    """Process a list of domains to enumerate subdomains and gather info."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        for domain in domains:
            output_file = output_dir / f"{sanitize_filename(domain)}_info.txt"
            print(f"Processing domain: {domain}")
            subdomains = enumerate_subdomains(domain)
            results = list(executor.map(process_subdomain, subdomains))
            with output_file.open('w', encoding='utf-8') as file:
                file.writelines(results)
            print(f"Results saved to file: {output_file}")
            print(f"Completed processing for domain: {domain}")

def main():
    """Main function to parse arguments and handle file processing."""
    parser = argparse.ArgumentParser(description="Process known hosts.")
    parser.add_argument("-f", "--file", help="Path to a text file containing known hosts.")
    parser.add_argument("hosts", nargs="*", help="List of known hosts.")
    args = parser.parse_args()

    known_hosts = []
    if args.file:
        with open(args.file, "r") as f:
            known_hosts.extend(f.read().splitlines())
    known_hosts.extend(args.hosts)

    if not known_hosts:
        print("No known hosts provided. Exiting.")
        return

    output_dir = Path('output')
    create_output_directory(output_dir)
    process_domains(known_hosts, output_dir)

if __name__ == "__main__":
    main()
