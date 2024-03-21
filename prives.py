import os
import subprocess
import argparse
import re
import random
import string
from datetime import datetime

def header():
   print("\n\033[1;31m#########################################################\033[00m")
   print("\033[1;31m#\033[00m" + " \033[1;33mLocal Linux Enumeration & Privilege Escalation Script\033[00m" + " \033[1;31m#\033[00m")
   print("\033[1;31m#########################################################\033[00m")
   print("\033[1;33m# www.rebootuser.com\033[00m")
   print("\033[1;33m# version: 1.0\033[00m\n")

def debug_info(keyword, report, export, thorough):
   print("[-] Debug Info")

   if keyword:
       print("[+] Searching for keyword: " + keyword)

   if report:
       print("[+] Report name: " + report)

   if export:
       print("[+] Export location: " + export)

   if thorough:
       print("[+] Thorough tests: Enabled")
   else:
       print("\033[1;33m[+] Thorough tests: Disabled\033[00m")

   if export:
       os.makedirs(export, exist_ok=True)
       format_dir = os.path.join(export, "LinEnum-export-{0}".format(datetime.now().strftime("%d-%m-%y")))
       os.makedirs(format_dir, exist_ok=True)

def system_info():
   print("\033[1;33m### SYSTEM ##############################################\033[00m")

   # Basic kernel info
   print("\033[1;31m[-] Kernel information:\033[00m")
   print(os.popen("uname -a 2>/dev/null").read())

   # Specific release info
   print("\033[1;31m[-] Specific release information:\033[00m")
   print(os.popen("cat /etc/*-release 2>/dev/null").read())

   # Hostname
   print("\033[1;31m[-] Hostname:\033[00m")
   print(os.popen("hostname 2>/dev/null").read())

def user_info():
   print("\033[1;33m### USER/GROUP ##########################################\033[00m")

   # Current user details
   print("\033[1;31m[-] Current user/group info:\033[00m")
   print(os.popen("id 2>/dev/null").read())

   # Last logged on user info
   print("\033[1;31m[-] Users that have previously logged onto the system:\033[00m")
   print(os.popen("lastlog 2>/dev/null | grep -v 'Never' 2>/dev/null").read())

   # Who else is logged on
   print("\033[1;31m[-] Who else is logged on:\033[00m")
   print(os.popen("w 2>/dev/null").read())

   # Group memberships
   print("\033[1;31m[-] Group memberships:\033[00m")
   print(os.popen("for i in $(cut -d: -f1 /etc/passwd 2>/dev/null); do id $i; done 2>/dev/null").read())

   # Superuser accounts
   print("\033[1;31m[-] Superuser accounts:\033[00m")
   print(os.popen("awk -F: '($3 == 0) {print}' /etc/passwd 2>/dev/null").read())

   # Are there any hashes in /etc/passwd?
   print("\033[1;33m[-] Is there any hash in /etc/passwd?\033[00m")
   print(os.popen("grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null").read())

   # Is root permitted to login via SSH?
   print("\033[1;31m[-] Is root permitted to login via SSH?\033[00m")
   root_ssh = os.popen("grep 'PermitRootLogin ' /etc/ssh/sshd_config 2>/dev/null | grep -v '#' | awk '{print  $2}'").read().strip()
   if root_ssh == "yes":
       print("[+] Root is allowed to login via SSH:")
       print(os.popen("grep 'PermitRootLogin ' /etc/ssh/sshd_config 2>/dev/null | grep -v '#'").read())

def environmental_info():
   print("\033[1;33m### ENVIRONMENTAL #######################################\033[00m")

   # Environment information
   print("\033[1;31m[-] Environment information:\033[00m")
   print(os.popen("env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null").read())

   # Writable path directories
   print("\033[1;31m[-] Path information:\033[00m")
   print(os.popen("echo $PATH").read())
   path_info = os.popen("ls -ld $(echo $PATH | tr ':' ' ') 2>/dev/null").read()
   print(path_info)

   # Available shells
   print("\033[1;31m[-] Available shells:\033[00m")
   print(os.popen("cat /etc/shells 2>/dev/null").read())

   # Current umask value
   print("\033[1;31m[-] Current umask value:\033[00m")
   print(os.popen("umask -S 2>/dev/null & umask 2>/dev/null").read())

   # umask value as specified in /etc/login.defs
   print("\033[1;31m[-] umask value as specified in /etc/login.defs:\033[00m")
   print(os.popen("grep -i 'umask' /etc/login.defs 2>/dev/null").read())

def job_info():
   print("\033[1;33m### JOBS/TASKS ##########################################\033[00m")

   # Cron jobs
   print("\033[1;31m[-] Cron jobs:\033[00m")
   print(os.popen("ls -la /etc/cron* 2>/dev/null").read())

   # World-writable cron jobs and file contents
   print("\033[1;33m[+] World-writable cron jobs and file contents:\033[00m")
   print(os.popen("find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;").read())

   # Crontab contents
   print("\033[1;31m[-] Crontab contents:\033[00m")
   print(os.popen("cat /etc/crontab 2>/dev/null").read())

def networking_info():
   print("\033[1;33m### NETWORKING  ##########################################\033[00m")

   # Network interfaces
   print("\033[1;31m[-] Network interfaces:\033[00m")
   print(os.popen("ifconfig -a 2>/dev/null").read())

   # Network connections
   print("\033[1;31m[-] Network connections:\033[00m")
   print(os.popen("netstat -antup 2>/dev/null").read())

   # DNS info
   print("\033[1;31m[-] DNS info:\033[00m")
   print(os.popen("cat /etc/resolv.conf 2>/dev/null").read())

   # IP information
   print("\033[1;31m[-] IP information:\033[00m")
   print(os.popen("ip a 2>/dev/null").read())

   # ARP information
   print("\033[1;31m[-] ARP information:\033[00m")
   print(os.popen("arp -a 2>/dev/null").read())

def services_info():
   print("\033[1;33m### SERVICES ############################################\033[00m")

   # Running processes
   print("\033[1;31m[-] Running processes:\033[00m")
   print(os.popen("ps aux 2>/dev/null").read())

   # Process binaries and associated permissions
   print("\033[1;31m[-] Process binaries and associated permissions (from above list):\033[00m")
   print(os.popen("ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls -la 2>/dev/null").read())

   # /etc/inetd.conf contents
   print("\033[1;31m[-] Contents of /etc/inetd.conf:\033[00m")
   print(os.popen("cat /etc/inetd.conf 2>/dev/null").read())

   # /etc/xinetd.conf contents
   print("\033[1;31m[-] Contents of /etc/xinetd.conf:\033[00m")
   print(os.popen("cat /etc/xinetd.conf 2>/dev/null").read())

def software_configs():
   print("\033[1;33m### SOFTWARE #############################################\033[00m")

   # Sudo version
   print("\033[1;31m[-] Sudo version:\033[00m")
   print(os.popen("sudo -V 2>/dev/null | grep 'Sudo version' 2>/dev/null").read())

   # MySQL version
   print("\033[1;31m[-] MySQL version:\033[00m")
   print(os.popen("mysql --version 2>/dev/null").read())

   # MySQL connections with default credentials
   print("\033[1;33m[+] Checking if MySQL can be connected to with default root/root credentials:\033[00m")
   print(os.popen("mysqladmin -uroot -proot version 2>/dev/null").read())

   # Apache version
   print("\033[1;31m[-] Apache version:\033[00m")
   print(os.popen("apache2 -v 2>/dev/null; httpd -v 2>/dev/null").read())

   # Apache user configuration
   print("\033[1;31m[-] Apache user configuration:\033[00m")
   print(os.popen("grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null").read())

   # Installed Apache modules
   print("\033[1;31m[-] Installed Apache modules:\033[00m")
   print(os.popen("apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null").read())

def interesting_files(keyword, thorough):
   print("\033[1;33m### INTERESTING FILES ####################################\033[00m")

   # Useful file locations
   print("\033[1;31m[-] Useful file locations:\033[00m")
   print("Current user's home directory: " + os.popen("echo $HOME 2>/dev/null").read().strip())
   print("World-readable files: ")
   print(os.popen("find / -perm -4 -type f -exec ls -al {} \; 2>/dev/null").read())
   print("/etc/passwd contents: ")
   print(os.popen("cat /etc/passwd 2>/dev/null").read())

   # Sensitive config files
   print("\033[1;31m[-] Sensitive config files:\033[00m")
   print("*SNMP* configuration file: " + os.popen("find / -name 'snmpd.conf' -exec ls -al {} \; 2>/dev/null").read())
   print("*Samba* configuration file: " + os.popen("find / -name 'smb.conf' -exec ls -al {} \; 2>/dev/null").read())

   # Web config files
   print("\033[1;31m[-] Web config files:\033[00m")
   print(os.popen("ls -alhR /var/www/ 2>/dev/null").read())
   print(os.popen("ls -alhR /srv/www/htdocs/ 2>/dev/null").read())
   print(os.popen("ls -alhR /usr/local/www/apache22/data/ 2>/dev/null").read())
   print(os.popen("ls -alhR /opt/lampp/htdocs/ 2>/dev/null").read())

   # Log files
   print("\033[1;31m[-] Log files:\033[00m")
   print(os.popen("find / -name '*.log' -type f -exec ls -la {} \; 2>/dev/null").read())

   # If keyword is provided, search config files for potential matches
   if keyword:
       print("\033[1;31m[-] Config files containing keyword '{0}':\033[00m".format(keyword))
       print(os.popen("find / -type f -name '*.conf' -exec grep -Hn {0} {{}} \; 2>/dev/null".format(keyword)).read())

   # If thorough tests are enabled, look for all hidden files
   if thorough:
       print("\033[1;31m[-] All hidden files and directories:\033[00m")
       print(os.popen("find / -name '.*' -type f -exec ls -al {} \; 2>/dev/null").read())

def docker_checks():
   print("\033[1;33m### DOCKER CHECKS #######################################\033[00m")

   # Check if we're in a Docker container
   print("\033[1;31m[-] Are we in a Docker container?\033[00m")
   if "docker" in os.popen("cat /proc/self/cgroup 2>/dev/null").read():
       print("\033[1;33m[+] Looks like we're in a Docker container!\033[00m")
   else:
       print("[-] Doesn't look like we're in a Docker container.")

   # Check for Docker files present
   print("\033[1;31m[-] Any Docker files present?\033[00m")
   print(os.popen("find / -name 'Dockerfile' -exec ls -al {} \; 2>/dev/null").read())
   print(os.popen("find / -name 'docker-compose.yml' -exec ls -al {} \; 2>/dev/null").read())

def lxc_container_checks():
   print("\033[1;33m### LXC CONTAINER CHECKS ################################\033[00m")

   # Check if we're in an LXC container
   print("\033[1;31m[-] Are we in an LXC container?\033[00m")
   if os.path.exists("/proc/1/environ"):
       with open("/proc/1/environ", "r") as f:
           if "container=lxc" in f.read():
               print("\033[1;33m[+] Looks like we're in an LXC container!\033[00m")
           else:
               print("[-] Doesn't look like we're in an LXC container.")

   # Check if we're an LXC host
   print("\033[1;31m[-] Are we an LXC host?\033[00m")
   if os.path.exists("/var/lib/lxc"):
       print("\033[1;33m[+] Looks like we're an LXC host!\033[00m")
       print(os.popen("ls -al /var/lib/lxc").read())
   else:
       print("[-] Doesn't look like we're an LXC host.")

def footer():
   print("\033[1;33m### SCAN COMPLETE ########################################\033[00m")

def main():
    parser = argparse.ArgumentParser(description="Local Linux Enumeration & Privilege Escalation Script")
    parser.add_argument("-k", "--keyword", help="Enter keyword to search for in config files")
    parser.add_argument("-r", "--report", help="Enter report name")
    parser.add_argument("-e", "--export", help="Enter export location")
    parser.add_argument("-t", "--thorough", action="store_true", help="Perform thorough tests")

    args = parser.parse_args()

    header()
    debug_info(args.keyword, args.report, args.export, args.thorough)
    system_info()
    user_info()
    environmental_info()
    job_info()
    networking_info()
    services_info()
    software_configs()
    interesting_files(args.keyword, args.thorough)
    docker_checks()
    lxc_container_checks()
    footer()
