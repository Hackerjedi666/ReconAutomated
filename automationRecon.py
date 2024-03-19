import socket
import os
import subprocess
import threading
import argparse
import requests
from bs4 import BeautifulSoup
from scapy.all import *

def perform_whois(ip):
   try:
       output = subprocess.check_output(["whois", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] WHOIS lookup failed")

def perform_dns_lookup(ip):
   try:
       hostname = socket.gethostbyaddr(ip)
       print("[+] Hostname:", hostname[0])
   except socket.herror:
       print("[-] Reverse DNS lookup failed")

def perform_ping(ip):
   try:
       subprocess.check_output(["ping", "-c", "4", ip])
       print("[+] Host is alive")
   except subprocess.CalledProcessError:
       print("[-] Host is unreachable")

def nmap_scan(ip):
   try:
       output = subprocess.check_output(["nmap", "-sV", "-vvv", "-Pn", "-A", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] Nmap scan failed")

def nikto_scan(ip):
   try:
       output = subprocess.check_output(["nikto", "-h", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] Nikto scan failed")

def rustscan(ip):
   try:
       output = subprocess.check_output(["rustscan", "-a", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] RustScan failed")

def bettercap(ip):
   try:
       output = subprocess.check_output(["bettercap", "-t", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] Bettercap failed")

def web_app_scan(url):
   try:
       response = requests.get(url)
       soup = BeautifulSoup(response.text, "html.parser")
       forms = soup.find_all("form")
       print(f"[+] Found {len(forms)} forms on {url}")
       for form in forms:
           print(form)
       
       # Check for common vulnerabilities
       if "password" in response.text.lower():
           print("[!] Potential password disclosure vulnerability")
       if "error" in response.text.lower():
           print("[!] Potential error message disclosure")
       if "sql" in response.text.lower():
           print("[!] Potential SQL injection vulnerability")
       if "xss" in response.text.lower():
           print("[!] Potential Cross-Site Scripting (XSS) vulnerability")
   except requests.exceptions.RequestException:
       print("[-] Web application scan failed")

def social_media_recon(company):
   try:
       print(f"[+] Searching for {company} on social media...")
       
       # Search on Twitter
       twitter_url = f"https://twitter.com/search?q={company}"
       response = requests.get(twitter_url)
       soup = BeautifulSoup(response.text, "html.parser")
       tweets = soup.find_all("div", {"class": "tweet"})
       print(f"[+] Found {len(tweets)} tweets mentioning {company}")
       
       # Search on LinkedIn
       linkedin_url = f"https://www.linkedin.com/search/results/companies/?keywords={company}"
       response = requests.get(linkedin_url)
       soup = BeautifulSoup(response.text, "html.parser")
       profiles = soup.find_all("div", {"class": "search-result__info"})
       print(f"[+] Found {len(profiles)} LinkedIn profiles mentioning {company}")
   except Exception as e:
       print("[-] Social media reconnaissance failed")
       print(str(e))

def email_harvesting(domain):
   try:
       print(f"[+] Harvesting emails for {domain}...")
       
       # Harvest emails using TheHarvester
       output = subprocess.check_output(["theHarvester", "-d", domain, "-b", "all"])
       print(output.decode())
       
       # Harvest emails using Hunter.io
       api_key = "YOUR_HUNTER_IO_API_KEY"
       url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
       response = requests.get(url)
       data = response.json()
       emails = [item["value"] for item in data["data"]["emails"]]
       print(f"[+] Found {len(emails)} emails using Hunter.io")
   except Exception as e:
       print("[-] Email harvesting failed")
       print(str(e))

def subdomain_enumeration(domain):
   try:
       print(f"[+] Enumerating subdomains for {domain}...")
       
       # Enumerate subdomains using Sublist3r
       output = subprocess.check_output(["sublist3r", "-d", domain])
       print(output.decode())
       
       # Enumerate subdomains using Amass
       output = subprocess.check_output(["amass", "enum", "-d", domain])
       print(output.decode())
   except Exception as e:
       print("[-] Subdomain enumeration failed")
       print(str(e))

def google_dorking(company):
   try:
       print(f"[+] Performing Google dorking for {company}...")
       
       # Perform Google search using dorks
       dorks = [
           f"site:{company}.com filetype:pdf",
           f"site:{company}.com intitle:index.of",
           f"site:{company}.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
           f"site:{company}.com ext:sql | ext:dbf | ext:mdb",
           f"site:{company}.com inurl:http | inurl:https"
       ]
       
       for dork in dorks:
           url = f"https://www.google.com/search?q={dork}"
           response = requests.get(url)
           soup = BeautifulSoup(response.text, "html.parser")
           search_results = soup.find_all("div", {"class": "g"})
           print(f"[+] Found {len(search_results)} results for dork: {dork}")
   except Exception as e:
       print("[-] Google dorking failed")
       print(str(e))

def voip_recon(ip):
   try:
       output = subprocess.check_output(["svmap", ip])
       print(output.decode())
   except subprocess.CalledProcessError:
       print("[-] VoIP reconnaissance failed")

def wireless_recon():
   try:
       print("[+] Performing wireless network reconnaissance...")
       
       # Put the wireless interface in monitor mode
       subprocess.call(["airmon-ng", "start", "wlan0"])
       
       # Perform packet sniffing and analysis
       sniff(iface="wlan0mon", prn=lambda x: x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PwrMgmt%}"))
   except Exception as e:
       print("[-] Wireless network reconnaissance failed")
       print(str(e))
   finally:
       # Stop monitor mode
       subprocess.call(["airmon-ng", "stop", "wlan0mon"])

def main():
   parser = argparse.ArgumentParser(description="Reconnaissance Tool")
   parser.add_argument("target", help="Target IP address or domain")
   args = parser.parse_args()

   ip = args.target

   threads = []

   whois_thread = threading.Thread(target=perform_whois, args=(ip,))
   dns_thread = threading.Thread(target=perform_dns_lookup, args=(ip,))
   ping_thread = threading.Thread(target=perform_ping, args=(ip,))
   nmap_thread = threading.Thread(target=nmap_scan, args=(ip,))
   nikto_thread = threading.Thread(target=nikto_scan, args=(ip,))
   rustscan_thread = threading.Thread(target=rustscan, args=(ip,))
   bettercap_thread = threading.Thread(target=bettercap, args=(ip,))
   web_app_thread = threading.Thread(target=web_app_scan, args=(f"http://{ip}",))
   social_media_thread = threading.Thread(target=social_media_recon, args=("CompanyName",))
   email_harvesting_thread = threading.Thread(target=email_harvesting, args=("company.com",))
   subdomain_thread = threading.Thread(target=subdomain_enumeration, args=("company.com",))
   google_dorking_thread = threading.Thread(target=google_dorking, args=("CompanyName",))
   voip_thread = threading.Thread(target=voip_recon, args=(ip,))
   wireless_thread = threading.Thread(target=wireless_recon)

   threads.extend([
       whois_thread, dns_thread, ping_thread, nmap_thread, nikto_thread,
       rustscan_thread, bettercap_thread, web_app_thread, social_media_thread,
       email_harvesting_thread, subdomain_thread, google_dorking_thread,
       voip_thread, wireless_thread
   ])

   for thread in threads:
       thread.start()

   for thread in threads:
       thread.join()

if __name__ == "__main__":
   main()