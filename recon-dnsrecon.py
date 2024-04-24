import os
import re
import socket
import subprocess
import json
from pathlib import Path
import argparse
from datetime import datetime

try:
    import shodan
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'your_shodan_api_key_here')  # Use environment variable
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

def enumerate_subdomains(domain, dictionary_path):
    """Use dnsrecon for subdomain enumeration."""
    json_file = Path(f"{sanitize_filename(domain)}_subdomains.json")
    command = f"dnsrecon -d {domain} -t brt -D {dictionary_path} -j {json_file}"
    try:
        subprocess.run(command, shell=True, check=True)
        results = json.loads(json_file.read_text())
        subdomains = [result['name'] for result in results if 'name' in result]
        json_file.unlink()  # Clean up the JSON file
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"Error executing dnsrecon command: {e}")
        return []
    except json.JSONDecodeError:
        print("Failed to decode dnsrecon output.")
        return []
    except FileNotFoundError:
        print(f"JSON file not found: {json_file}")
        return []

def get_shodan_info(ip):
    """Retrieve information on a given IP from Shodan."""
    if not use_shodan:
        print("Shodan API features are not available.")
        return "Shodan is not available"
    try:
        host_info = api.host(ip)
        info = f"IP: {host_info['ip_str']}\n" + "\n".join(
            f"Port: {item['port']} | Data: {item.get('data', 'No data')}" for item in host_info.get('data', [])
        )
        return info
    except shodan.APIError as e:
        return f"Shodan API error: {str(e)}"

def process_domains(domains, output_dir, dictionary_path):
    """Process a list of domains to enumerate subdomains and gather info."""
    for domain in domains:
        subdomains = enumerate_subdomains(domain, dictionary_path)
        subdomains_file = output_dir / f"{sanitize_filename(domain)}_subdomains{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
        subdomain_info = ", ".join(subdomains)
        subdomains_file.write_text(subdomain_info, encoding='utf-8')
        print(f"Subdomains for {domain} saved to: {subdomains_file}")

        proceed = input(f"Do you want to proceed with Shodan checks for {domain}? (y/n): ")
        if proceed.lower() == 'y':
            shodan_file = output_dir / f"{sanitize_filename(domain)}_shodan_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
            with shodan_file.open('w', encoding='utf-8') as file:
                for subdomain in subdomains:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        shodan_info = get_shodan_info(ip) if ip != "IP not found" else "IP not found"
                        file.write(f"Subdomain: {subdomain}\nIP Address: {ip}\nShodan Info:\n{shodan_info}\n\n")
                    except socket.gaierror:
                        file.write(f"Subdomain: {subdomain}\nIP Address: IP not found\nShodan Info: IP not found\n\n")
            print(f"Shodan results for {domain} saved to: {shodan_file}")
        else:
            print("Skipping Shodan checks.")
            
def choose_dictionary():
    """Choose a dictionary file from the 'lists' folder."""
    lists_dir = Path('lists')
    if not lists_dir.exists():
        print("Lists directory not found.")
        return ""
    files = [f for f in lists_dir.iterdir() if f.is_file()]
    if not files:
        print("No dictionary files found in the 'lists' directory.")
        return ""
    print("Choose a dictionary file:")
    for i, file in enumerate(files):
        print(f"{i + 1}. {file.name}")
    while True:
        try:
            choice = int(input("Enter the number of the dictionary file: "))
            if 1 <= choice <= len(files):
                return str(files[choice - 1])
            else:
                print("Invalid choice. Please enter a number between 1 and", len(files))
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    """Main function to parse arguments and handle file processing."""
    parser = argparse.ArgumentParser(description="Process known hosts.")
    parser.add_argument("hosts", nargs="*", help="List of known hosts.")
    args = parser.parse_args()

    if not args.hosts:
        print("No known hosts provided.")
        return

    output_dir = Path('output')
    create_output_directory(output_dir)
    dictionary_path = choose_dictionary()  # Ensure you add a dictionary path
    if dictionary_path:
        process_domains(args.hosts, output_dir, dictionary_path)

if __name__ == "__main__":
    main()