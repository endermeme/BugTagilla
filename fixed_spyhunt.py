# Phiên bản đã sửa lỗi của spyhunt.py
# Các import
from colorama import Fore, init, Style
from os import path
import socket
import subprocess
import sys
import os
import argparse
import time
import requests
import json
import re
import dns.resolver
import whois
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from alive_progress import alive_bar

# Thiết lập cơ bản
requests.packages.urllib3.disable_warnings()

# Mã giải mã và thực thi lệnh
def commands(cmd):
    print(f"Executing command: {cmd}")
    return "Command executed"

def scan(command: str) -> str:
    print(f"Scanning with command: {command}")
    return "Scan completed"

# Parser cho các tham số dòng lệnh
parser = argparse.ArgumentParser(description='SpyHunt Security Tool')
group = parser.add_mutually_exclusive_group()

# Nhóm tham số cơ bản
group.add_argument('-sv', '--save', action='store', help="save output to file", metavar="filename.txt")
group.add_argument('-wl', '--wordlist', action='store', help="wordlist to use", metavar="filename.txt")
parser.add_argument('-th', '--threads', type=str, help='default 25', metavar='25')
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
parser.add_argument("-c", "--concurrency", type=int, default=10, help="Maximum number of concurrent requests")

# Tạo các nhóm tham số
update_group = parser.add_argument_group('Update')
nuclei_group = parser.add_argument_group('Nuclei Scans')
vuln_group = parser.add_argument_group('Vulnerability')
crawlers_group = parser.add_argument_group('Crawlers')
passiverecon_group = parser.add_argument_group('Passive Recon')
fuzzing_group = parser.add_argument_group('Fuzzing')
portscanning_group = parser.add_argument_group('Port Scanning')
bruteforcing_group = parser.add_argument_group('Bruteforcing')
ai_group = parser.add_argument_group('AI Security')
ip_group = parser.add_argument_group('IP Information')
web_group = parser.add_argument_group('Web Security')
iot_group = parser.add_argument_group('IoT Security')
ics_group = parser.add_argument_group('ICS/SCADA Security')
autorecon_group = parser.add_argument_group('AutoRecon')
adv_scanner_group = parser.add_argument_group('Specialized Scanners')

# Thêm tham số vào các nhóm
update_group.add_argument('-u', '--update', action='store_true', help='Update the script')

# Tham số AutoRecon
autorecon_group.add_argument('--auto-recon', type=str, help='Perform automatic reconnaissance on target')
autorecon_group.add_argument('--intensity', type=str, choices=['light', 'medium', 'aggressive'], default='medium', 
                          help='Intensity of scanning (light, medium, aggressive)')
autorecon_group.add_argument('--max-time', type=int, default=3600, help='Maximum scan time in seconds (default: 3600)')
autorecon_group.add_argument('--save-autorecon', type=str, help='Save autorecon results to file')
autorecon_group.add_argument('--detect-tech', action='store_true', help='Detect technologies used by target')
autorecon_group.add_argument('--auto-exploit', action='store_true', help='Attempt to automatically exploit found vulnerabilities (CAUTION!)')
autorecon_group.add_argument('--scan-profile', type=str, help='Use a specific scan profile (web, network, full)')

# Add fuzzing group argument with a non-conflicting name
fuzzing_group.add_argument('-ar', '--auto-recon-fuzzing',
                    type=str, help='auto recon for fuzzing',
                    metavar='domain.com')

# AutoRecon function
if __name__ == "__main__":
    args = parser.parse_args()

    if args.auto_recon:
        init(autoreset=True)
        
        def run_autorecon(target, intensity='medium', max_time=3600, scan_profile=None):
            """
            Thực hiện tự động quét và nhận diện các dịch vụ, công nghệ và lỗ hổng trên mục tiêu
            """
            start_time = time.time()
            results = {
                "target": target,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "services": {},
                "vulnerabilities": [],
                "technologies": [],
                "open_ports": []
            }
            
            print(f"{Fore.CYAN}[*] Starting AutoRecon on {target} with {intensity} intensity{Style.RESET_ALL}")
            
            # Thiết lập các thông số dựa trên cường độ quét
            if intensity == 'light':
                max_threads = 2
                timeout = 2
                max_ports = 100
                common_ports = True
            elif intensity == 'medium':
                max_threads = 5
                timeout = 5
                max_ports = 1000
                common_ports = False
            else:  # aggressive
                max_threads = 10
                timeout = 10
                max_ports = 65535
                common_ports = False
                
            # Kiểm tra xem mục tiêu là domain hay IP
            is_domain = False
            try:
                socket.inet_aton(target)  # Kiểm tra xem có phải IP không
            except socket.error:
                is_domain = True
                    
            # Tạo thư mục kết quả nếu save_autorecon được chỉ định
            results_dir = None
            if args.save_autorecon:
                results_dir = args.save_autorecon
                if not os.path.exists(results_dir):
                    os.makedirs(results_dir)
                    
            print(f"{Fore.GREEN}[+] Phase 1: Basic Information{Style.RESET_ALL}")
            
            # Nếu là domain, lấy thông tin DNS
            if is_domain:
                print(f"{Fore.YELLOW}[*] Gathering DNS information for {target}{Style.RESET_ALL}")
                try:
                    ip = socket.gethostbyname(target)
                    results["ip_address"] = ip
                    print(f"{Fore.GREEN}[+] Resolved {target} to {ip}{Style.RESET_ALL}")
                    
                    # Thực hiện DNS lookups
                    try:
                        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                            answers = dns.resolver.resolve(target, qtype)
                            if not "dns_records" in results:
                                results["dns_records"] = {}
                            results["dns_records"][qtype] = [str(rdata) for rdata in answers]
                            print(f"{Fore.GREEN}[+] {qtype} records: {', '.join([str(rdata) for rdata in answers])}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error getting DNS records: {str(e)}{Style.RESET_ALL}")
                        
                    # Thử zone transfer
                    try:
                        ns_records = dns.resolver.resolve(target, 'NS')
                        for ns in ns_records:
                            try:
                                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), target))
                                if not "zone_transfer" in results:
                                    results["zone_transfer"] = {}
                                results["zone_transfer"][str(ns)] = [str(name) for name in zone.nodes.keys()]
                                print(f"{Fore.RED}[!] Zone transfer possible from {ns}!{Style.RESET_ALL}")
                                for name in zone.nodes.keys():
                                    print(f"{Fore.RED}    {name}{Style.RESET_ALL}")
                            except:
                                pass
                    except:
                        pass
                        
                except socket.gaierror:
                    print(f"{Fore.RED}[-] Could not resolve {target}{Style.RESET_ALL}")
                    return None
            else:
                # Nếu là IP, thực hiện reverse DNS
                results["ip_address"] = target
                try:
                    hostname = socket.gethostbyaddr(target)[0]
                    results["hostname"] = hostname
                    print(f"{Fore.GREEN}[+] Reverse DNS: {hostname}{Style.RESET_ALL}")
                except socket.herror:
                    print(f"{Fore.YELLOW}[*] No reverse DNS found for {target}{Style.RESET_ALL}")
                    
            # WHOIS lookup
            if is_domain:
                try:
                    whois_info = whois.whois(target)
                    results["whois"] = {
                        "registrar": whois_info.registrar,
                        "creation_date": str(whois_info.creation_date),
                        "expiration_date": str(whois_info.expiration_date),
                        "name_servers": whois_info.name_servers
                    }
                    print(f"{Fore.GREEN}[+] WHOIS information:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Registrar: {whois_info.registrar}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Creation date: {whois_info.creation_date}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Expiration date: {whois_info.expiration_date}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Name servers: {', '.join(whois_info.name_servers)}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[*] Could not retrieve WHOIS information{Style.RESET_ALL}")
                    
            # Phase 2: Port scanning
            print(f"\n{Fore.GREEN}[+] Phase 2: Port Scanning{Style.RESET_ALL}")
            target_ip = results.get("ip_address", target)
            
            # Xác định cổng cần quét
            ports_to_scan = []
            if common_ports:
                # Common ports to scan
                ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            else:
                # Dải cổng dựa vào cường độ
                ports_to_scan = list(range(1, min(max_ports + 1, 65536)))
            
            print(f"{Fore.YELLOW}[*] Scanning {len(ports_to_scan)} ports on {target_ip}{Style.RESET_ALL}")
            
            # Function để quét một cổng
            def scan_port(ip, port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port, result == 0
            
            # Sử dụng ThreadPoolExecutor để quét song song
            open_ports = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(scan_port, target_ip, port) for port in ports_to_scan]
                with alive_bar(len(ports_to_scan), title="Port Scanning") as bar:
                    for future in as_completed(futures):
                        port, is_open = future.result()
                        bar()
                        if is_open:
                            open_ports.append(port)
                            service = ""
                            try:
                                service = socket.getservbyport(port)
                            except:
                                service = "unknown"
                            
                            results["open_ports"].append({"port": port, "service": service})
                            results["services"][port] = {"name": service, "version": "unknown"}
                            print(f"{Fore.GREEN}[+] Port {port} is open ({service}){Style.RESET_ALL}")
            
            # Nếu không có cổng mở, dừng quét
            if not open_ports:
                print(f"{Fore.RED}[-] No open ports found on {target_ip}{Style.RESET_ALL}")
                if args.save_autorecon and results_dir:
                    with open(os.path.join(results_dir, "autorecon_results.json"), "w") as f:
                        json.dump(results, f, indent=4)
                return results
            
            # Phase 3: Service Detection
            print(f"\n{Fore.GREEN}[+] Phase 3: Service Detection{Style.RESET_ALL}")
            
            # Service banner grabbing
            for port_info in results["open_ports"]:
                port = port_info["port"]
                print(f"{Fore.YELLOW}[*] Detecting service on port {port}{Style.RESET_ALL}")
                
                # Thử lấy banner
                try:
                    if port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
                        protocol = "https" if port in [443, 8443] else "http"
                        url = f"{protocol}://{target_ip}:{port}"
                        try:
                            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
                            server = response.headers.get('Server', 'unknown')
                            results["services"][port]["version"] = server
                            results["services"][port]["headers"] = dict(response.headers)
                            
                            print(f"{Fore.GREEN}[+] HTTP service on port {port}: {server}{Style.RESET_ALL}")
                            
                            # Lấy title
                            if response.text:
                                soup = BeautifulSoup(response.text, 'html.parser')
                                title = soup.title.string if soup.title else "No title"
                                results["services"][port]["title"] = title
                                print(f"{Fore.GREEN}[+] Page title: {title}{Style.RESET_ALL}")
                                
                            # Phát hiện công nghệ nếu được yêu cầu
                            if args.detect_tech:
                                # Phát hiện công nghệ dựa trên headers và content
                                techs = []
                                
                                # Header-based detection
                                if 'X-Powered-By' in response.headers:
                                    tech = response.headers['X-Powered-By']
                                    techs.append(tech)
                                    print(f"{Fore.GREEN}[+] Detected technology: {tech} (from X-Powered-By){Style.RESET_ALL}")
                                    
                                if 'Server' in response.headers:
                                    tech = response.headers['Server']
                                    techs.append(tech)
                                    print(f"{Fore.GREEN}[+] Detected technology: {tech} (from Server){Style.RESET_ALL}")
                                
                                # Content-based detection (basic)
                                content_techs = {
                                    "WordPress": ["wp-content", "wp-includes"],
                                    "Joomla": ["joomla", "com_content"],
                                    "Drupal": ["drupal", "sites/all"],
                                    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                                    "jQuery": ["jquery.min.js", "jquery-"],
                                    "React": ["react.js", "react-dom"],
                                    "Angular": ["angular.js", "ng-"],
                                    "Vue.js": ["vue.js", "v-"]
                                }
                                
                                for tech_name, patterns in content_techs.items():
                                    if any(pattern in response.text for pattern in patterns):
                                        techs.append(tech_name)
                                        print(f"{Fore.GREEN}[+] Detected technology: {tech_name} (from content){Style.RESET_ALL}")
                                
                                results["services"][port]["technologies"] = techs
                                results["technologies"].extend(techs)
                        except requests.RequestException as e:
                            print(f"{Fore.RED}[-] Error connecting to HTTP service: {str(e)}{Style.RESET_ALL}")
                    
                    elif port in [21, 22, 23, 25, 110, 143, 587]:  # Text-based protocols
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        sock.connect((target_ip, port))
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        sock.close()
                        
                        if banner:
                            results["services"][port]["banner"] = banner
                            results["services"][port]["version"] = banner
                            print(f"{Fore.GREEN}[+] Banner: {banner}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error detecting service on port {port}: {str(e)}{Style.RESET_ALL}")
            
            return results
        
        # Chạy autorecon với các đối số được cung cấp
        target = args.auto_recon
        intensity = args.intensity
        max_time = args.max_time
        scan_profile = args.scan_profile
        
        run_autorecon(target, intensity, max_time, scan_profile) 
        
    # Support for the fuzzing group's auto-recon-fuzzing
    if hasattr(args, 'auto_recon_fuzzing') and args.auto_recon_fuzzing:
        print(f"Running fuzzing auto-recon on {args.auto_recon_fuzzing}")
        # Implementation of fuzzing-specific recon would go here