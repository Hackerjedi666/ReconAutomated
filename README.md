# Company Reconnaissance Tool

This is an open-source reconnaissance tool designed to help companies protect their assets by identifying potential vulnerabilities and security weaknesses. The tool performs various reconnaissance techniques to gather information about a target company and its infrastructure.

## Features

- WHOIS lookup
- DNS lookup
- Ping sweep
- Nmap scanning
- Nikto web server scanning
- RustScan port scanning
- Bettercap network scanning
- Web application scanning
- Social media reconnaissance
- Email harvesting
- Subdomain enumeration
- Google dorking
- VoIP reconnaissance
- Wireless network reconnaissance

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `scapy` library
- Various external tools (e.g., Nmap, Nikto, RustScan, Bettercap, TheHarvester, Sublist3r, Amass)

## Installation

1. Clone the repository:

```git clone https://github.com/Hackerjedi666/ReconAutomated.git```

2. Install the required Python libraries:

```pip install -r requirements.txt```

3. Install the necessary external tools:

- Nmap: `apt-get install nmap` (Linux) or download from [https://nmap.org](https://nmap.org) (Windows)
- Nikto: `apt-get install nikto` (Linux) or download from [https://cirt.net/Nikto2](https://cirt.net/Nikto2) (Windows)
- RustScan: Download from [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan)
- Bettercap: Download from [https://www.bettercap.org](https://www.bettercap.org)
- TheHarvester: `pip install theHarvester`
- Sublist3r: `pip install sublist3r`
- Amass: Download from [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)

## Usage

To use the Company Reconnaissance Tool, run the following command:

```python 
python3 automationRecon.py target
```

Replace `target` with the IP address or domain of the target company you want to perform reconnaissance on.

The tool will perform various reconnaissance techniques and display the results in the console. Each technique is executed in a separate thread to improve performance.

## Customization

You can customize the tool by modifying the code to suit your specific needs. Here are a few possible customizations:

- Add or remove reconnaissance techniques by modifying the `main` function and creating corresponding functions.
- Customize the output format by modifying the print statements in each technique's function.
- Integrate additional external tools or APIs by modifying the respective functions.

## Disclaimer

This tool is intended for educational and ethical purposes only. Use it responsibly and with proper authorization. The authors and contributors are not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.
















