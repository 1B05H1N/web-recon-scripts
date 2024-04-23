# Web Recon Scripts

## Description
This repository contains some Python scripts designed to automate the process of reconnaissance for web security assessments. This aren't the exact scripts that I use daily, but were written/generated as a fun excercise. These scripts utilize various techniques for subdomain enumeration and interacting with APIs like Shodan to gather intelligence on specified targets.

## Tools Included
1. **Recon-Shodan**: This script performs domain intelligence using the Shodan API to find related information and services.
2. **Recon-Amass**: Leverages the Amass tool to perform extensive subdomain enumeration.
3. **Recon-DNSRecon**: Utilizes DNSRecon for detailed DNS gathering and subdomain discovery.

## Prerequisites
- Python 3.x
- Required Python packages: `scrapy`, `requests`, `shodan` (if using Shodan scripts)
- Tools: Amass, DNSRecon (ensure these are installed and accessible from your command line)
- Proper API keys where needed (e.g., Shodan API key)

## Installation
Clone this repository using:
```bash
git clone https://your-repository-url-here
```
Install required Python packages:
```bash
pip install -r requirements.txt
```
Create a `lists` directory for any dictionary files used for DNSRecon or similar tools.

## Usage
Each script can be run independently, based on the needs of the reconnaissance process. For example, to run the Shodan reconnaissance script:
```bash
python recon-shodan.py <input-file-with-domains>
```

Replace `<input-file-with-domains>` with your file containing a list of domains to analyze.

## Legal Disclaimer
The scripts provided in this repository are for educational purposes only. Using these scripts to attack targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by these programs.

## Contributing
Contributions to this repository are welcome. Please ensure that any pull requests or issues adhere to the existing coding standards and fulfill a purposeful enhancement or bug fix.