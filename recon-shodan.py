import sys
import os
import datetime
import socket
import json
import shodan

def nslookup(domain):
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(domain)
        return ip_addresses
    except socket.gaierror:
        print(f"NS lookup failed for {domain}")
        return []

def setup_shodan():
    shodan_api_key = os.environ.get('SHODAN_API_KEY')
    if not shodan_api_key:
        print("Shodan API key not found in environment variables. Set it up as 'SHODAN_API_KEY'.")
        sys.exit(1)
    return shodan.Shodan(shodan_api_key)

def load_domains(filename):
    if not os.path.exists(filename):
        print(f"File '{filename}' not found.")
        sys.exit(1)
    with open(filename, 'r') as file:
        return [line.strip().rstrip(',') for line in file if line.strip()]

def run_searches(api, domains):
    all_results = {}
    for domain in domains:
        domain_results = {'results_by_ip': {}}
        ip_addresses = nslookup(domain)

        for ip in ip_addresses:
            try:
                host_result = api.host(ip)
                domain_results['results_by_ip'][ip] = {'host': host_result}
            except shodan.APIError as e:
                print(f"Shodan API Error for IP {ip}: {e}")

        try:
            domain_search_result = api.search(f'hostname:"{domain}"')
            domain_results['domain_search'] = domain_search_result
        except shodan.APIError as e:
            print(f"Shodan search error for {domain}: {e}")

        all_results[domain] = domain_results
        print(f"Completed searches for domain: {domain}")
    return all_results

def save_results(all_results):
    output_folder = "output"
    os.makedirs(output_folder, exist_ok=True)
    filename = os.path.join(output_folder, f"shodan_results_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json")
    with open(filename, 'w') as f:
        json.dump(all_results, f, indent=4)
    print(f"All results have been saved to {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    api = setup_shodan()
    domains = load_domains(filename)
    results = run_searches(api, domains)
    save_results(results)
