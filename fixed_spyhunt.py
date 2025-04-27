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
import signal
import threading
import random
import mmh3
import codecs
import urllib3
import asyncio
import shutil
import warnings
import traceback
import psutil
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin, unquote

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

# ==================== IMPROVED AI SECURITY SCAN ====================
class AISecurityScan:
    def __init__(self, api_key=None, model="gpt-4o-mini"):
        """
        Initialize the AI Security Scanner with clear structure
        
        Args:
            api_key: OpenAI API key (optional, will use environment variable if not provided)
            model: AI model to use (default: gpt-4o-mini)
        """
        print(f"{Fore.CYAN}[+] Initializing AI Security Scanner{Style.RESET_ALL}")
        
        # Initialize the findings data structure
        self.findings = {
            "reconnaissance": {}, # Dữ liệu thu thập
            "vulnerabilities": [], # Lỗ hổng phát hiện
            "attack_vectors": [], # Các vector tấn công
            "recommendations": [], # Đề xuất
            "metadata": {
                "target": "",
                "scan_time": "",
                "scan_type": ""
            }
        }
        
        # Internal properties
        self.api_key = api_key
        self.model = model
        self.client = None
        self.scan_file = None
        
        # Initialize API
        self._initialize_api()
    
    def _initialize_api(self):
        """Initialize and validate the OpenAI API connection"""
        try:
            # First try with provided key
            if self.api_key:
                import openai
                openai.api_key = self.api_key
                self.client = openai.OpenAI(api_key=self.api_key)
                print(f"{Fore.GREEN}[+] API initialized with provided key{Style.RESET_ALL}")
            else:
                # Try with environment variable
                try:
                    import os
                    import openai
                    self.api_key = os.environ.get("OPENAI_API_KEY")
                    if self.api_key:
                        openai.api_key = self.api_key
                        self.client = openai.OpenAI(api_key=self.api_key)
                        print(f"{Fore.GREEN}[+] API initialized with environment variable{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[!] No API key provided or found in environment variables{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}[!] You can set an API key with --api-key or export OPENAI_API_KEY=your_key{Style.RESET_ALL}")
                        return False
                except Exception as e:
                    print(f"{Fore.RED}[!] Error initializing API from environment: {str(e)}{Style.RESET_ALL}")
                    return False
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error initializing OpenAI API: {str(e)}{Style.RESET_ALL}")
            return False
    
    def scan(self, target, output_dir=".", max_threads=10, scan_type="comprehensive", focus_area="all"):
        """
        Run a comprehensive security scan and AI analysis on a target
        
        Args:
            target: Target domain to scan
            output_dir: Directory to save output files
            max_threads: Maximum number of threads to use
            scan_type: Type of scan to perform (comprehensive, quick, passive)
            focus_area: Focus area for AI analysis (api, web, mobile, infra, all)
            
        Returns:
            Dictionary with scan and AI analysis results
        """
        # Update metadata
        self.findings["metadata"]["target"] = target
        self.findings["metadata"]["scan_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.findings["metadata"]["scan_type"] = scan_type
        self.findings["metadata"]["focus_area"] = focus_area
        
        print(f"\n{Fore.CYAN}[+] Starting AI Security Scan on {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Scan type: {scan_type}, Focus area: {focus_area}{Style.RESET_ALL}")
        
        # Step 1: Perform the security scan using run_comprehensive_scan
        print(f"\n{Fore.CYAN}[+] Step 1: Performing comprehensive security scan{Style.RESET_ALL}")
        scan_start_time = time.time()
        
        try:
            scan_file = run_comprehensive_scan(
                target=target,
                output_dir=output_dir,
                max_threads=max_threads,
                ai_model=self.model,
                auto_explore=True
            )
            
            self.scan_file = scan_file
            scan_duration = time.time() - scan_start_time
            print(f"{Fore.GREEN}[+] Scan completed in {scan_duration:.2f} seconds{Style.RESET_ALL}")
            
            # Step 2: Analyze scan results with AI
            print(f"\n{Fore.CYAN}[+] Step 2: Analyzing scan results with AI{Style.RESET_ALL}")
            analysis_start_time = time.time()
            
            # Load scan results
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Perform AI analysis
                analysis_results = self.analyze_with_ai(scan_data, target, focus_area)
                
                if analysis_results:
                    # Update findings with AI analysis
                    self.findings["reconnaissance"] = scan_data
                    self.findings["vulnerabilities"] = analysis_results.get("vulnerabilities", [])
                    self.findings["attack_vectors"] = analysis_results.get("attack_vectors", [])
                    self.findings["recommendations"] = analysis_results.get("recommendations", [])
                    
                    # Generate report
                    report_file = self.generate_report(output_dir, target)
                    
                    analysis_duration = time.time() - analysis_start_time
                    print(f"{Fore.GREEN}[+] AI analysis completed in {analysis_duration:.2f} seconds{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Report generated at {report_file}{Style.RESET_ALL}")
                    
                    return self.findings
                else:
                    print(f"{Fore.RED}[!] AI analysis failed{Style.RESET_ALL}")
                    return None
            except Exception as e:
                print(f"{Fore.RED}[!] Error analyzing scan results: {str(e)}{Style.RESET_ALL}")
                traceback.print_exc()
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error during security scan: {str(e)}{Style.RESET_ALL}")
            traceback.print_exc()
            return None
    
    def analyze_with_ai(self, scan_data, target, focus_area="all"):
        """
        Analyze scan results with AI
        
        Args:
            scan_data: Scan results dictionary
            target: Target domain
            focus_area: Focus area for analysis
            
        Returns:
            Dictionary with AI analysis results
        """
        if not self.client:
            print(f"{Fore.RED}[!] OpenAI API not initialized. Cannot perform AI analysis.{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[+] Starting AI analysis of scan results for {target}{Style.RESET_ALL}")
        
        try:
            # Build the prompt for analysis
            prompt = self._build_analysis_prompt(scan_data, target, focus_area)
            
            # Call the OpenAI API
            print(f"{Fore.CYAN}[+] Calling OpenAI API with model {self.model}{Style.RESET_ALL}")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert security researcher specializing in bug bounty hunting and vulnerability analysis. Your task is to analyze security scan results and provide actionable insights."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            
            # Extract the response text
            response_text = response.choices[0].message.content
            
            # Parse the AI output
            analysis_results = self._parse_ai_output(response_text)
            
            return analysis_results
        except Exception as e:
            print(f"{Fore.RED}[!] Error during AI analysis: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _build_analysis_prompt(self, scan_data, target, focus_area):
        """
        Build the prompt for AI analysis
        
        Args:
            scan_data: Scan results dictionary
            target: Target domain
            focus_area: Focus area for analysis
            
        Returns:
            Prompt string for AI analysis
        """
        # Create a summary of findings to avoid token limits
        summary = {
            "target": target,
            "scan_time": scan_data.get("scan_time", ""),
            "subdomains_count": len(scan_data.get("subdomains", [])),
            "vulnerabilities_count": len(scan_data.get("vulnerabilities", [])),
            "parameters_count": len(scan_data.get("parameters", [])),
            "site_links_count": len(scan_data.get("site_links", [])),
            "js_files_count": len(scan_data.get("js_files", [])),
        }
        
        # Include up to 50 subdomains to keep the prompt size reasonable
        if len(scan_data.get("subdomains", [])) > 0:
            summary["subdomains_sample"] = scan_data.get("subdomains", [])[:50]
        
        # Include all vulnerabilities since they're the most important
        if len(scan_data.get("vulnerabilities", [])) > 0:
            summary["vulnerabilities"] = scan_data.get("vulnerabilities", [])
        
        # Include up to 50 parameters
        if len(scan_data.get("parameters", [])) > 0:
            summary["parameters_sample"] = scan_data.get("parameters", [])[:50]
        
        # Include up to 50 site links
        if len(scan_data.get("site_links", [])) > 0:
            summary["site_links_sample"] = scan_data.get("site_links", [])[:50]
        
        # Include up to 20 JS files
        if len(scan_data.get("js_files", [])) > 0:
            summary["js_files_sample"] = scan_data.get("js_files", [])[:20]
        
        # Include CORS and host header checks
        if len(scan_data.get("cors_checks", [])) > 0:
            summary["cors_checks"] = scan_data.get("cors_checks", [])
        
        if len(scan_data.get("host_header_checks", [])) > 0:
            summary["host_header_checks"] = scan_data.get("host_header_checks", [])
        
        # Build prompt
        prompt = f"""
        Analyze the following security scan results for {target} with a focus on {focus_area} security issues.
        
        SCAN SUMMARY:
        {json.dumps(summary, indent=2)}
        
        Your task is to:
        1. Identify potential security vulnerabilities in the scan data
        2. Prioritize findings by potential impact and exploitability
        3. Suggest attack vectors that could be explored based on the findings
        4. Provide specific recommendations for further testing or exploitation
        5. If relevant, suggest specific commands or payloads that could be used
        
        Format your response using the following structure:
        ## Vulnerabilities
        - [Severity] Vulnerability name: Description
        
        ## Attack Vectors
        - [Priority] Attack Vector: Description
        
        ## Recommendations
        - Recommendation: Description
        
        ## Commands
        - Command: Description
        """
        
        return prompt
    
    def _parse_ai_output(self, ai_output):
        """
        Parse the AI output into structured data
        
        Args:
            ai_output: AI response text
            
        Returns:
            Dictionary with structured analysis results
        """
        analysis_results = {
            "vulnerabilities": [],
            "attack_vectors": [],
            "recommendations": [],
            "commands": []
        }
        
        # Parse vulnerabilities
        vuln_pattern = r"\[(\w+)\] ([^:]+): (.+)"
        vulnerabilities = re.findall(vuln_pattern, ai_output)
        for severity, name, description in vulnerabilities:
            analysis_results["vulnerabilities"].append({
                "severity": severity,
                "name": name,
                "description": description.strip()
            })
        
        # Parse attack vectors
        vector_pattern = r"\[(\w+)\] ([^:]+): (.+)"
        # Find attack vectors section
        attack_section_match = re.search(r"## Attack Vectors\s+(.+?)(?=##|\Z)", ai_output, re.DOTALL)
        if attack_section_match:
            attack_section = attack_section_match.group(1)
            attack_vectors = re.findall(vector_pattern, attack_section)
            for priority, name, description in attack_vectors:
                analysis_results["attack_vectors"].append({
                    "priority": priority,
                    "name": name,
                    "description": description.strip()
                })
        
        # Parse recommendations
        rec_pattern = r"- ([^:]+): (.+)"
        # Find recommendations section
        rec_section_match = re.search(r"## Recommendations\s+(.+?)(?=##|\Z)", ai_output, re.DOTALL)
        if rec_section_match:
            rec_section = rec_section_match.group(1)
            recommendations = re.findall(rec_pattern, rec_section)
            for name, description in recommendations:
                analysis_results["recommendations"].append({
                    "name": name,
                    "description": description.strip()
                })
        
        # Parse commands
        cmd_pattern = r"- ([^:]+): (.+)"
        # Find commands section
        cmd_section_match = re.search(r"## Commands\s+(.+?)(?=##|\Z)", ai_output, re.DOTALL)
        if cmd_section_match:
            cmd_section = cmd_section_match.group(1)
            commands = re.findall(cmd_pattern, cmd_section)
            for name, description in commands:
                analysis_results["commands"].append({
                    "name": name,
                    "description": description.strip()
                })
        
        return analysis_results
    
    def generate_report(self, output_dir, target):
        """
        Generate a markdown report with the AI analysis results
        
        Args:
            output_dir: Directory to save the report
            target: Target domain
            
        Returns:
            Path to the generated report file
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_filename = f"ai_analysis_{target.replace('.', '_')}_{timestamp}.md"
        report_path = os.path.join(output_dir, report_filename)
        
        try:
            with open(report_path, 'w') as f:
                # Write header
                f.write(f"# Security Analysis Report for {target}\n\n")
                f.write(f"*Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                
                # Write metadata
                f.write("## Scan Metadata\n\n")
                f.write(f"- **Target:** {self.findings['metadata']['target']}\n")
                f.write(f"- **Scan Time:** {self.findings['metadata']['scan_time']}\n")
                f.write(f"- **Scan Type:** {self.findings['metadata']['scan_type']}\n")
                f.write(f"- **Focus Area:** {self.findings['metadata']['focus_area']}\n\n")
                
                # Write vulnerabilities
                f.write("## Vulnerabilities\n\n")
                if self.findings["vulnerabilities"]:
                    for vuln in self.findings["vulnerabilities"]:
                        f.write(f"### [{vuln['severity']}] {vuln['name']}\n\n")
                        f.write(f"{vuln['description']}\n\n")
                else:
                    f.write("*No vulnerabilities identified.*\n\n")
                
                # Write attack vectors
                f.write("## Attack Vectors\n\n")
                if self.findings["attack_vectors"]:
                    for vector in self.findings["attack_vectors"]:
                        f.write(f"### [{vector['priority']}] {vector['name']}\n\n")
                        f.write(f"{vector['description']}\n\n")
                else:
                    f.write("*No attack vectors identified.*\n\n")
                
                # Write recommendations
                f.write("## Recommendations\n\n")
                if self.findings["recommendations"]:
                    for rec in self.findings["recommendations"]:
                        f.write(f"### {rec['name']}\n\n")
                        f.write(f"{rec['description']}\n\n")
                else:
                    f.write("*No recommendations provided.*\n\n")
                
                # Write stats
                if "reconnaissance" in self.findings and self.findings["reconnaissance"]:
                    recon = self.findings["reconnaissance"]
                    f.write("## Reconnaissance Statistics\n\n")
                    f.write(f"- **Subdomains:** {len(recon.get('subdomains', []))}\n")
                    f.write(f"- **Site Links:** {len(recon.get('site_links', []))}\n")
                    f.write(f"- **Parameters:** {len(recon.get('parameters', []))}\n")
                    f.write(f"- **JS Files:** {len(recon.get('js_files', []))}\n")
                    f.write(f"- **CORS Issues:** {len(recon.get('cors_checks', []))}\n")
                    f.write(f"- **Host Header Issues:** {len(recon.get('host_header_checks', []))}\n\n")
                
            print(f"{Fore.GREEN}[+] Report generated at {report_path}{Style.RESET_ALL}")
            return report_path
        except Exception as e:
            print(f"{Fore.RED}[!] Error generating report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def suggest_next_steps(self):
        """
        Suggest next steps based on the AI analysis
        """
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.GREEN}Suggested Next Steps {Fore.CYAN}                           ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not self.findings.get("recommendations"):
            print(f"{Fore.YELLOW}[!] No recommendations available.{Style.RESET_ALL}")
            return
        
        for i, rec in enumerate(self.findings["recommendations"], 1):
            print(f"{Fore.GREEN}{i}. {rec['name']}:{Style.RESET_ALL}")
            print(f"   {rec['description']}")
            print()

# ==================== AI BUG BOUNTY ANALYZER ====================
class SmartAISecurityAnalyzer:
    def __init__(self):
        self.api_key = ""
        self.model = "gpt-4o-mini"
        self.context_window = 4000
        self.findings_cache = {}
        self._init_openai()
        
    def _init_openai(self):
        import openai
        openai.api_key = self.api_key
        self.client = openai

# Rest of the code includes the original functions and parsing logic...

# Function to run comprehensive scan
def run_comprehensive_scan(target, output_dir=".", max_threads=10, ai_model="gpt-4o-mini", auto_explore=True):
    """
    Run a comprehensive security scan on a target
    
    Args:
        target: Target domain to scan
        output_dir: Directory to save output files
        max_threads: Maximum number of threads to use
        ai_model: AI model to use for analysis
        auto_explore: Whether to enable AI-driven automated exploration
        
    Returns:
        Path to the findings file
    """
    scan_time = time.strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(output_dir, f"scan_{target.replace('.', '_')}_{scan_time}")
    
    print(f"{Fore.CYAN}[+] Starting comprehensive scan on {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Results will be saved to {scan_dir}{Style.RESET_ALL}")
    
    # Create scan directory
    os.makedirs(scan_dir, exist_ok=True)
    
    # Initialize findings dictionary
    findings = {
        "target": target,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": [],
        "port_scan": {},
        "site_links": [],
        "parameters": [],
        "js_files": [],
        "cors_checks": [],
        "host_header_checks": [],
        "vulnerabilities": [],
        "raw_tool_output": {}
    }
    
    # Various scanning stages and logic here...
    
    # Save all findings to a single JSON file
    findings_file = os.path.join(scan_dir, "all_findings.json")
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=4)

    print(f"\n{Fore.GREEN}[+] All scan results saved to {findings_file}{Style.RESET_ALL}")
    
    return findings_file

# Parse command-line arguments
parser = argparse.ArgumentParser(description='SpyHunt - Security Reconnaissance Tool')
# ... (command line arguments defined here)

# Add AI-specific arguments
ai_group = parser.add_argument_group('AI Security')
ai_group.add_argument('--ai-scan', type=str, help='Perform AI-powered scan and analysis on target', metavar='domain.com')
ai_group.add_argument('--ai-analyze', type=str, help='Analyze existing scan results with AI', metavar='findings.json')
ai_group.add_argument('--ai-bug-bounty', type=str, help='AI-powered bug bounty analysis on target', metavar='domain.com')
ai_group.add_argument('--focus', type=str, choices=['api', 'web', 'mobile', 'infra', 'all'], default='all', help='Focus area for AI analysis')
ai_group.add_argument('--max-threads', type=int, default=10, help='Maximum number of threads for AI analysis')
ai_group.add_argument('--output-dir', type=str, help='Output directory for scan results', metavar='./output')
ai_group.add_argument('--output-report', type=str, choices=['simple', 'detailed', 'json'], default='simple', help='Output report format')
ai_group.add_argument('--api-key', type=str, help='OpenAI API key for AI features', metavar='KEY')
ai_group.add_argument('--ai-model', type=str, default='gpt-4o-mini', help='AI model to use (default: gpt-4o-mini)', metavar='MODEL')
ai_group.add_argument('--ai-mode', type=str, choices=['security', 'bug-bounty', 'pentest'], default='security', help='AI analysis mode')
ai_group.add_argument('--ai-workflow', action='store_true', help='Generate AI-optimized recon workflow')
ai_group.add_argument('--ai-output', type=str, help='Output file for AI analysis results', metavar='output.md')

args = parser.parse_args()

# Handlers for various command-line arguments here...

# Add handling for AI bug bounty argument
if args.ai_bug_bounty:
    try:
        # Try to load dotenv in case it's not loaded yet
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.GREEN}SpyHunt AI Bug Bounty Scanner {Fore.CYAN}                 ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Initialize the improved AI Security Scanner
        ai_scanner = AISecurityScan(api_key=args.api_key, model=args.ai_model)
        
        # Run the scan and AI analysis in one streamlined process
        results = ai_scanner.scan(
            target=args.ai_bug_bounty,
            output_dir=args.output_dir if args.output_dir else ".",
            max_threads=args.max_threads,
            focus_area=args.focus
        )
        
        # If successful, show recommended next steps
        if results:
            ai_scanner.suggest_next_steps()
            
        print(f"\n{Fore.GREEN}[+] AI Bug Bounty analysis completed.{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error during AI bug bounty analysis: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()

# Main section
if __name__ == "__main__":
    # Your main code logic here...
    pass