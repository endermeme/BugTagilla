from colorama import Fore, init, Style
from os import path
from modules.favicon import *
from bs4 import BeautifulSoup
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote_plus
from modules import useragent_list
from modules import sub_output
from googlesearch import search
from alive_progress import alive_bar
from queue import Queue
from shutil import which
from collections import defaultdict
from threading import Semaphore
from ratelimit import limits, sleep_and_retry
from modules.jwt_analyzer import JWTAnalyzer
from modules.ss3sec import S3Scanner
from datetime import datetime
from modules.heap_dump import HeapdumpAnalyzer
from fake_useragent import UserAgent
import waybackpy
import threading
import os.path
import concurrent.futures
import multiprocessing
import dns.resolver
import os.path
import whois
import socket
import subprocess
import sys
import socket
import os
import argparse
import time
import codecs
import requests
import mmh3
import urllib3
import warnings
import re
import json
import shodan
import ipaddress
import random
import string
import html
import asyncio
import aiohttp
import hashlib
import urllib
import nmap3
import ssl
import shutil
import dns.zone
import dns.query
import ipinfo
import uuid
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm
from itertools import cycle

# Import AI Support Functions
try:
    from ai_support_functions import AISupportFunctions
except ImportError:
    # Create a simple placeholder if the module is not available
    class AISupportFunctions:
        def __init__(self, api_key=None):
            pass
        def run_ai_bug_bounty(self, target, focus="all", max_threads=10, output_format="detailed"):
            print("AI Support Functions module not found. Please create the ai_support_functions.py file.")
            return False

warnings.filterwarnings(action='ignore',module='bs4')

requests.packages.urllib3.disable_warnings()

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
        
    def _prioritize_findings(self, all_findings):
        """Phân loại và ưu tiên phát hiện trước khi gửi cho AI"""
        priority_data = {
            "high_priority": {},
            "medium_priority": {},
            "low_priority": {},
            "metadata": {}
        }
        
        # Phân loại các phát hiện theo mức độ ưu tiên
        # HIGH: Dữ liệu nghi ngờ có lỗ hổng nghiêm trọng
        high_value_patterns = [
            "admin", "api", "token", "key", "password", "auth", "jwt", 
            "graphql", "firebase", "s3", "test", "dev", "staging", "oauth"
        ]
        
        # Phân loại các endpoints
        if "site_links" in all_findings:
            priority_data["metadata"]["total_links"] = len(all_findings["site_links"])
            
            # Chỉ lấy mẫu 25 links có giá trị cao nhất
            high_value_links = []
            for link in all_findings["site_links"]:
                if any(pattern in link.lower() for pattern in high_value_patterns):
                    high_value_links.append(link)
                    if len(high_value_links) >= 25:
                        break
                        
            priority_data["high_priority"]["valuable_links"] = high_value_links
            
            # Phân tích các tham số URL
            if "parameters" in all_findings:
                params_analysis = self._analyze_parameters(all_findings["parameters"])
                priority_data["high_priority"]["interesting_parameters"] = params_analysis
        
        # Tương tự xử lý các loại dữ liệu khác...
        # (...) Thêm code phân loại cho JS files, headers, v.v.
        
        return priority_data
    
    def _optimize_token_usage(self, data):
        """Tối ưu hoá dữ liệu để giảm số token gửi đến API"""
        import json
        
        # Ước tính kích thước ban đầu
        initial_json = json.dumps(data)
        token_estimate = len(initial_json.split()) * 1.3  # Ước tính thô
        
        # Nếu vượt quá 80% context window, cắt giảm dữ liệu
        if token_estimate > 0.8 * self.context_window:
            # Cắt giảm dữ liệu với các chiến lược khác nhau
            if "high_priority" in data and "valuable_links" in data["high_priority"]:
                # Giảm số lượng links nếu nhiều quá
                if len(data["high_priority"]["valuable_links"]) > 10:
                    data["high_priority"]["valuable_links"] = data["high_priority"]["valuable_links"][:10]
            
            # Loại bỏ hoàn toàn dữ liệu low_priority nếu cần
            if token_estimate > 0.9 * self.context_window:
                data.pop("low_priority", None)
                
        return data
    
    def _analyze_parameters(self, params_data):
        """Phân tích các tham số URL để tìm tham số nhạy cảm"""
        # Logic để tìm các tham số có giá trị cao (ví dụ: id, token, redirect, v.v.)
        high_value_params = []
        sensitive_params = ["id", "token", "key", "redirect", "file", "path", "url", "auth"]
        
        for url, params in params_data.items():
            for param_name, values in params.items():
                if any(s_param in param_name.lower() for s_param in sensitive_params):
                    high_value_params.append({
                        "url": url,
                        "param": param_name,
                        "value_sample": values[0] if values and len(values) > 0 else ""
                    })
        
        return high_value_params
        
    def analyze_for_bug_bounty(self, all_findings, target_domain):
        """Phân tích thông minh tập trung vào bug bounty"""
        # Bước 1: Phân loại và ưu tiên dữ liệu
        prioritized_data = self._prioritize_findings(all_findings)
        
        # Bước 2: Tối ưu hóa sử dụng token
        optimized_data = self._optimize_token_usage(prioritized_data)
        
        # Bước 3: Xây dựng prompt thông minh
        prompt = self._build_targeted_prompt(optimized_data, target_domain)
        
        # Bước 4: Gọi API với prompt được tối ưu
        try:
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": """Bạn là chuyên gia bảo mật cấp cao trong lĩnh vực bug bounty. 
Nhiệm vụ của bạn là phân tích dữ liệu đã được ưu tiên và tập trung vào:
1. Lỗ hổng có giá trị cao (RCE, SSRF, SQLi, Auth Bypass, XSS có impact cao)
2. Xác định các điểm yếu trong chuỗi bảo mật
3. Sắp xếp hành động tiếp theo theo thứ tự ưu tiên
4. Đề xuất các payload thông minh để kiểm tra nhưng phải đúng context

Trả lời ngắn gọn, rõ ràng và tập trung vào giá trị bug bounty."""},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000  # Giới hạn đầu ra để tiết kiệm tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi khi phân tích AI: {str(e)}"
    
    def _build_targeted_prompt(self, data, target_domain):
        """Xây dựng prompt thông minh tập trung vào bug bounty"""
        import json
        
        prompt = f"""
# Phân tích bảo mật bug bounty cho {target_domain}

## Dữ liệu ưu tiên cao:
```json
{json.dumps(data.get('high_priority', {}), indent=2)}
```

## Dữ liệu ưu tiên trung bình (nếu cần tham khảo):
```json
{json.dumps(data.get('medium_priority', {}), indent=2)}
```

## Thông tin tổng quan:
```json
{json.dumps(data.get('metadata', {}), indent=2)}
```

Hãy phân tích dữ liệu bảo mật trên và:

1. Xác định 3-5 vector tấn công TIỀM NĂNG NHẤT có giá trị cao trong bug bounty
2. Cho mỗi vector, đưa ra:
   - Mô tả ngắn gọn về lỗ hổng
   - Mức độ nghiêm trọng (CVSS và giá trị bug bounty)
   - Payload cụ thể để kiểm tra
   - Lệnh cụ thể để kiểm tra sâu hơn

3. Xác định các tham số, endpoints hoặc tính năng CẦN TẬP TRUNG nhất

4. Đưa ra 3 kỹ thuật test nâng cao phù hợp với target này, tập trung vào BUSINESS LOGIC

TẬP TRUNG VÀO CÁC LỖ HỔNG CÓ GIÁ TRỊ CAO TRONG BUG BOUNTY THAY VÌ LỖ HỔNG PHỔ BIẾN.
"""
        return prompt
        
    def generate_targeted_commands(self, findings, target_domain, focus_area="all"):
        """Sinh ra các lệnh cụ thể dựa vào focus area"""
        # Tạo prompt dựa vào focus area
        prompt_map = {
            "ssrf": "Tập trung vào lỗ hổng SSRF - đề xuất các lệnh và payload để kiểm tra SSRF",
            "injection": "Tập trung vào các loại injection (SQL, command, v.v.) - đề xuất lệnh và payload",
            "auth": "Tập trung vào xác thực và phân quyền - đề xuất các kỹ thuật kiểm tra",
            "all": "Đề xuất các lệnh toàn diện nhất để kiểm tra tất cả các lỗ hổng"
        }
        
        # Trích xuất dữ liệu liên quan đến focus area
        relevant_data = self._extract_relevant_data(findings, focus_area)
        
        # Tạo prompt
        prompt = f"""
Mục tiêu: {target_domain}
Focus area: {focus_area}

{prompt_map.get(focus_area, prompt_map["all"])}

Dữ liệu liên quan:
```
{json.dumps(relevant_data, indent=2)}
```

Hãy đề xuất 5 lệnh cụ thể, chi tiết và thực tế để kiểm tra. 
Mỗi lệnh nên là câu lệnh cụ thể có thể chạy ngay (không phải mô tả). 
Thêm chú thích ngắn về mục đích của từng lệnh.
"""
        
        try:
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Bạn là chuyên gia bảo mật giỏi về các công cụ hacking. Đưa ra các lệnh cụ thể, chính xác và hiệu quả."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi khi sinh lệnh: {str(e)}"
    
    def _extract_relevant_data(self, findings, focus_area):
        """Trích xuất dữ liệu liên quan đến focus area cụ thể"""
        # Logic để lấy dữ liệu phù hợp với từng focus area
        relevant_data = {}
        
        if focus_area == "ssrf" or focus_area == "all":
            # Lấy các endpoint có khả năng SSRF
            ssrf_params = ["url", "uri", "link", "redirect", "return", "next", "target", "to", "out", "view", "dir"]
            ssrf_candidates = []
            
            if "parameters" in findings:
                for url, params in findings.get("parameters", {}).items():
                    for param_name in params:
                        if any(s in param_name.lower() for s in ssrf_params):
                            ssrf_candidates.append({"url": url, "param": param_name})
            
            relevant_data["ssrf_candidates"] = ssrf_candidates[:10]  # Giới hạn số lượng
        
        # Tương tự cho các focus area khác
        # (...)
        
        return relevant_data
        
    def create_recon_workflow(self, target_domain, initial_findings=None):
        """Tạo quy trình recon tự động thích ứng"""
        if not initial_findings:
            initial_findings = {}
            
        # Xác định loại target (web app, API, microservice, etc.)
        target_type = self._detect_target_type(target_domain, initial_findings)
        
        # Tạo quy trình recon thích ứng
        prompt = f"""
Tạo quy trình recon thông minh cho {target_domain} (loại: {target_type}).

Thông tin đã biết:
```
{json.dumps(initial_findings, indent=2)}
```

Hãy tạo quy trình recon TỰ ĐỘNG THÍCH ỨNG:
1. Giai đoạn 1: Discovery cơ bản (5 lệnh/công cụ)
2. Giai đoạn 2: Tùy chỉnh dựa vào kết quả (3-5 lệnh)
3. Giai đoạn 3: Deep dive (3-5 lệnh)
4. Giai đoạn 4: Khai thác (3-5 kỹ thuật)

MỖI bước phải có ĐIỀU KIỆN để quyết định bước tiếp theo. 
Tạo quy trình THÍCH ỨNG, không phải danh sách cố định.
"""
        
        try:
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Bạn là chuyên gia tự động hóa quá trình recon trong bảo mật. Tạo quy trình thích ứng và thông minh để tối đa hóa kết quả với ít lệnh nhất."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi khi tạo quy trình: {str(e)}"
    
    def _detect_target_type(self, domain, findings):
        """Phát hiện loại mục tiêu dựa vào các thông tin sơ bộ"""
        # Logic phát hiện loại mục tiêu (web app, API, microservice)
        is_api = False
        is_webapp = False
        
        # Kiểm tra dựa vào các endpoints
        if "site_links" in findings:
            for link in findings["site_links"]:
                if "/api/" in link or "/v1/" in link or "/v2/" in link:
                    is_api = True
                if ".html" in link or ".php" in link or ".jsp" in link:
                    is_webapp = True
        
        # Kiểm tra dựa vào headers
        if "headers" in findings:
            headers = findings["headers"]
            if "Content-Type" in headers and "application/json" in headers["Content-Type"]:
                is_api = True
        
        if is_api and not is_webapp:
            return "API"
        elif is_webapp and not is_api:
            return "WebApp"
        elif is_api and is_webapp:
            return "Hybrid"
        else:
            return "Unknown"

# Lớp quản lý việc sử dụng AI Analyzer trong các modules khác nhau
class AISecurityManager:
    def __init__(self):
        self.analyzer = SmartAISecurityAnalyzer()
        self.scan_results = {}
        self.recommendations = {}
        self.context_memory = {}
    
    def update_scan_results(self, module_name, results):
        """Cập nhật kết quả quét từ một module cụ thể"""
        self.scan_results[module_name] = results
        
    def analyze_current_state(self, target_domain):
        """Phân tích trạng thái hiện tại và đề xuất hành động tiếp theo"""
        analysis = self.analyzer.analyze_for_bug_bounty(self.scan_results, target_domain)
        self.recommendations["current"] = analysis
        return analysis
    
    def get_next_commands(self, target_domain, focus_area="all"):
        """Lấy các lệnh tiếp theo dựa trên kết quả hiện tại"""
        commands = self.analyzer.generate_targeted_commands(
            self.scan_results, target_domain, focus_area
        )
        self.recommendations["commands"] = commands
        return commands
    
    def get_recon_workflow(self, target_domain):
        """Tạo quy trình recon tự động thích ứng"""
        workflow = self.analyzer.create_recon_workflow(target_domain, self.scan_results)
        self.recommendations["workflow"] = workflow
        return workflow
    
    def save_analysis(self, filename="ai_bug_bounty_analysis.md"):
        """Lưu toàn bộ phân tích vào file"""
        import datetime
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# AI Bug Bounty Analysis\n\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if "current" in self.recommendations:
                f.write("## Current Analysis\n\n")
                f.write(self.recommendations["current"])
                f.write("\n\n")
                
            if "commands" in self.recommendations:
                f.write("## Recommended Commands\n\n")
                f.write(self.recommendations["commands"])
                f.write("\n\n")
                
            if "workflow" in self.recommendations:
                f.write("## Recon Workflow\n\n")
                f.write(self.recommendations["workflow"])
                f.write("\n\n")
        
        print(f"{Fore.GREEN}Đã lưu phân tích AI vào {filename}{Style.RESET_ALL}")

# Khởi tạo một instance toàn cục
ai_security_manager = AISecurityManager()

banner = f"""


  ██████  ██▓███ ▓██   ██▓ ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓
▒██    ▒ ▓██░  ██▒▒██  ██▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    
░  ░  ░  ░░       ▒ ▒ ░░   ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      
      ░           ░ ░      ░  ░  ░   ░              ░         
{Fore.WHITE}V 3.3
{Fore.WHITE}By c0deninja
{Fore.RESET}
"""

print(Fore.MAGENTA + banner)
print(Fore.WHITE)

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def scan(command: str) -> str:
    cmd = command
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode() 
    return out

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

update_group = parser.add_argument_group('Update')
nuclei_group = parser.add_argument_group('Nuclei Scans')
vuln_group = parser.add_argument_group('Vulnerability')
crawlers_group = parser.add_argument_group('Crawlers')
passiverecon_group = parser.add_argument_group('Passive Recon')
fuzzing_group = parser.add_argument_group('Fuzzing')
portscanning_group = parser.add_argument_group('Port Scanning')
bruteforcing_group = parser.add_argument_group('Bruteforcing')
ai_group = parser.add_argument_group('AI Security')

group.add_argument('-sv', '--save', action='store',
                   help="save output to file",
                   metavar="filename.txt")

group.add_argument('-wl', '--wordlist', action='store',
                   help="wordlist to use",
                   metavar="filename.txt")

parser.add_argument('-th', '--threads',
                    type=str, help='default 25',
                    metavar='25')

passiverecon_group.add_argument('-s',
                    type=str, help='scan for subdomains',
                    metavar='domain.com')

passiverecon_group.add_argument('-d', '--dns',
                    type=str, help='scan a list of domains for dns records',
                    metavar='domains.txt')

parser.add_argument('-p', '--probe',
                    type=str, help='probe domains.',
                    metavar='domains.txt')

parser.add_argument('-r', '--redirects',
                    type=str, help='links getting redirected',
                    metavar='domains.txt')

vuln_group.add_argument('-b', '--brokenlinks',
                    type=str, help='search for broken links',
                    metavar='domains.txt')

crawlers_group.add_argument('-pspider', '--paramspider',
                    type=str, help='extract parameters from a domain',
                    metavar='domain.com')

crawlers_group.add_argument('-w', '--waybackurls',
                    type=str, help='scan for waybackurls',
                    metavar='https://domain.com')

crawlers_group.add_argument('-j',
                    type=str, help='find javascript files',
                    metavar='domain.com')

crawlers_group.add_argument('-wc', '--webcrawler',
                    type=str, help='scan for urls and js files',
                    metavar='https://domain.com')

parser.add_argument('-fi', '--favicon',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-fm', '--faviconmulti',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

passiverecon_group.add_argument('-na', '--networkanalyzer',
                    type=str, help='net analyzer',
                    metavar='https://domain.com')

parser.add_argument('-ri', '--reverseip',
                    type=str, help='reverse ip lookup',
                    metavar='IP')

parser.add_argument('-rim', '--reverseipmulti',
                    type=str, help='reverse ip lookup for multiple ips',
                    metavar='IP')

parser.add_argument('-sc', '--statuscode',
                    type=str, help='statuscode',
                    metavar='domain.com')

vuln_group.add_argument('-ph', '--pathhunt',
                    type=str, help='check for directory traversal',
                    metavar='domain.txt')

vuln_group.add_argument('-co', '--corsmisconfig',
                    type=str, help='cors misconfiguration',
                    metavar='domains.txt')

vuln_group.add_argument('-hh', '--hostheaderinjection',
                    type=str, help='host header injection',
                    metavar='domain.com')

parser.add_argument('-sh', '--securityheaders',
                    type=str, help='scan for security headers',
                    metavar='domain.com')

parser.add_argument('-ed', '--enumeratedomain',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

vuln_group.add_argument('-smu', '--smuggler',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

passiverecon_group.add_argument('-ips', '--ipaddresses',
                    type=str, help='get the ips from a list of domains',
                    metavar='domain list')

passiverecon_group.add_argument('-dinfo', '--domaininfo',
                    type=str, help='get domain information like codes,server,content length',
                    metavar='domain list')

parser.add_argument('-isubs', '--importantsubdomains',
                    type=str, help='extract interesting subdomains from a list like dev, admin, test and etc..',
                    metavar='domain list')

fuzzing_group.add_argument('-nft', '--not_found',
                    type=str, help='check for 404 status code',
                    metavar='domains.txt')

portscanning_group.add_argument('-n', '--nmap',
                    type=str, help='Scan a target with nmap',
                    metavar='domain.com or IP')

fuzzing_group.add_argument('-api', '--api_fuzzer',
                    type=str, help='Look for API endpoints',
                    metavar='domain.com')

passiverecon_group.add_argument('-sho', '--shodan_',
                    type=str, help='Recon with shodan',
                    metavar='domain.com')

vuln_group.add_argument('-fp', '--forbiddenpass',
                    type=str, help='Bypass 403 forbidden',
                    metavar='domain.com')

fuzzing_group.add_argument('-db', '--directorybrute',
                    type=str, help='Brute force filenames and directories',
                    metavar='domain.com')

portscanning_group.add_argument('-cidr', '--cidr_notation',
                    type=str, help='Scan an ip range to find assets and services',
                    metavar='IP/24')

portscanning_group.add_argument('-ps', '--ports',
                    type=str, help='Port numbers to scan',
                    metavar='80,443,8443')

portscanning_group.add_argument('-pai', '--print_all_ips',
                    type=str, help='Print all ips',
                    metavar='IP/24')

vuln_group.add_argument('-xss', '--xss_scan',
                 type=str, help='scan for XSS vulnerabilities',
                 metavar='https://example.com/page?param=value')

vuln_group.add_argument('-sqli', '--sqli_scan',
                 type=str, help='scan for SQLi vulnerabilities',
                 metavar='https://example.com/page?param=value')

passiverecon_group.add_argument('-shodan', '--shodan_api',
                    type=str, help='shodan api key',
                    metavar='KEY')

parser.add_argument('-webserver', '--webserver_scan',
                    type=str, help='webserver scan',
                    metavar='domain.com')

crawlers_group.add_argument('-javascript', '--javascript_scan',
                    type=str, help='scan for sensitive info in javascript files',
                    metavar='domain.com')

crawlers_group.add_argument('-dp', '--depth',
                          type=int,           # Make sure this is int
                          default=2,
                          help='Crawling depth (default: 2)',
                          metavar='DEPTH')

crawlers_group.add_argument('-je', '--javascript_endpoints',
                    type=str, help='extract javascript endpoints',
                    metavar='file.txt')

crawlers_group.add_argument('-hibp', '--haveibeenpwned',
                    type=str, help='check if the password has been pwned',
                    metavar='password')

fuzzing_group.add_argument('-pm', '--param_miner',
                    type=str, help='param miner',
                    metavar='domain.com')

fuzzing_group.add_argument('-ch', '--custom_headers',
                    type=str, help='custom headers',
                    metavar='domain.com')

vuln_group.add_argument('-or', '--openredirect',
                    type=str, help='open redirect',
                    metavar='domain.com')

fuzzing_group.add_argument('-asn', '--automoussystemnumber',
                    type=str, help='asn',
                    metavar='AS55555')

vuln_group.add_argument('-st', '--subdomaintakeover', 
                    type=str, help='subdomain takeover',
                    metavar='subdomains.txt')

fuzzing_group.add_argument('-ar', '--auto-recon-fuzzing',
                    type=str, help='auto recon',
                    metavar='domain.com')

vuln_group.add_argument('-jwt', '--jwt_scan',
                     type=str, help='analyze JWT token for vulnerabilities',
                     metavar='token')

vuln_group.add_argument('-jwt-modify', '--jwt_modify',
                     type=str, help='modify JWT token',
                     metavar='token')

vuln_group.add_argument('-heapds', '--heapdump_file',
                     type=str, help='file for heapdump scan',
                     metavar='heapdump.txt')

vuln_group.add_argument('-heapts', '--heapdump_target',
                     type=str, help='target for heapdump scan',
                     metavar='domain.com')

fuzzing_group.add_argument('-f_p', '--forbidden_pages',
                     type=str, help='forbidden pages',
                     metavar='domain.com')


nuclei_group.add_argument('-nl', '--nuclei_lfi', action='store_true', help="Find Local File Inclusion with nuclei")
nuclei_group.add_argument("-nc", "--nuclei", type=str, help="scan nuclei on a target", metavar="domain.com")
nuclei_group.add_argument("-nct", "--nuclei_template", type=str, help="use a nuclei template", metavar="template.yaml")


parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

parser.add_argument("-c", "--concurrency", type=int, default=10, help="Maximum number of concurrent requests")

passiverecon_group.add_argument('-gs', '--google', action='store_true', help='Google Search')

fuzzing_group.add_argument("-e", "--extensions", help="Comma-separated list of file extensions to scan", default="")

fuzzing_group.add_argument("-x", "--exclude", help="Comma-separated list of status codes to exclude", default="")

update_group.add_argument('-u', '--update', action='store_true', help='Update the script')

parser.add_argument('--shodan-api', help='Shodan API key for subdomain enumeration')

parser.add_argument('--proxy', help='Use a proxy (e.g., http://proxy.com:8080)')

parser.add_argument('--proxy-file', help='Load proxies from file')

parser.add_argument('--heapdump', help='Analyze Java heapdump file')

parser.add_argument('--output-dir', help='Output directory', default='.')

# AI Security arguments
ai_group.add_argument('--ai-scan', type=str, help='Perform AI-powered scan and analysis on target', metavar='domain.com')
ai_group.add_argument('--ai-analyze', type=str, help='Analyze existing scan results with AI', metavar='results.json')
ai_group.add_argument('--ai-bug-bounty', type=str, help='AI-powered bug bounty analysis on target', metavar='domain.com')
ai_group.add_argument('--focus', type=str, choices=['api', 'web', 'mobile', 'infra', 'all'], default='all', help='Focus area for AI analysis')
ai_group.add_argument('--max-threads', type=int, default=10, help='Maximum number of threads for AI analysis')
ai_group.add_argument('--output-report', type=str, choices=['simple', 'detailed', 'json'], default='simple', help='Output report format')
ai_group.add_argument('--api-key', type=str, help='OpenAI API key for AI features', metavar='KEY')
ai_group.add_argument('--ai-model', type=str, default='gpt-4o-mini', help='AI model to use (default: gpt-4o-mini)', metavar='MODEL')
ai_group.add_argument('--ai-mode', type=str, choices=['security', 'bug-bounty', 'pentest'], default='security', help='AI analysis mode')
ai_group.add_argument('--ai-workflow', action='store_true', help='Generate AI-optimized recon workflow')
ai_group.add_argument('--ai-output', type=str, help='Output file for AI analysis results', metavar='output.md')

# Cloud Security arguments
cloud_group = parser.add_argument_group('Cloud Security')
cloud_group.add_argument('--cloud-scan', action='store_true', help='Scan cloud infrastructure for vulnerabilities')
cloud_group.add_argument('--aws-scan', action='store_true', help='Scan AWS infrastructure')
cloud_group.add_argument('--aws-profile', type=str, help='AWS profile to use')
cloud_group.add_argument('--aws-region', type=str, help='AWS region to scan')
cloud_group.add_argument('--azure-scan', action='store_true', help='Scan Azure infrastructure')
cloud_group.add_argument('--azure-tenant', type=str, help='Azure tenant ID')
cloud_group.add_argument('--azure-subscription', type=str, help='Azure subscription ID')
cloud_group.add_argument('--gcp-scan', action='store_true', help='Scan GCP infrastructure')
cloud_group.add_argument('--gcp-project', type=str, help='GCP project ID')
cloud_group.add_argument('--gcp-credentials', type=str, help='Path to GCP credentials file')
cloud_group.add_argument('--iam-scan', action='store_true', help='Scan IAM configurations')
cloud_group.add_argument('--s3-scan', action='store_true', help='Scan S3 buckets for misconfigurations')
cloud_group.add_argument('--serverless-scan', action='store_true', help='Scan serverless functions')
cloud_group.add_argument('--terraform-scan', action='store_true', help='Scan Terraform files')
cloud_group.add_argument('--terraform-dir', type=str, help='Directory containing Terraform files')
cloud_group.add_argument('--cloudformation-scan', action='store_true', help='Scan CloudFormation templates')
cloud_group.add_argument('--cloudformation-dir', type=str, help='Directory containing CloudFormation templates')

# Container Security arguments
container_group = parser.add_argument_group('Container Security')
container_group.add_argument('--docker-scan', action='store_true', help='Scan Docker containers for vulnerabilities')
container_group.add_argument('--docker-host', type=str, help='Docker host to connect to', metavar='tcp://host:port')
container_group.add_argument('--docker-registry-scan', action='store_true', help='Scan Docker registry for vulnerable images')
container_group.add_argument('--registry-url', type=str, help='Docker registry URL', metavar='registry.example.com')
container_group.add_argument('--registry-user', type=str, help='Docker registry username', metavar='USERNAME')
container_group.add_argument('--registry-pass', type=str, help='Docker registry password', metavar='PASSWORD')
container_group.add_argument('--k8s-scan', action='store_true', help='Scan Kubernetes cluster for misconfigurations')
container_group.add_argument('--k8s-context', type=str, help='Kubernetes context to use')
container_group.add_argument('--k8s-namespace', type=str, help='Kubernetes namespace to scan')
container_group.add_argument('--kubeconfig', type=str, help='Path to kubeconfig file', metavar='~/.kube/config')
container_group.add_argument('--trivy-scan', action='store_true', help='Use Trivy scanner for container vulnerabilities')
container_group.add_argument('--grype-scan', action='store_true', help='Use Grype scanner for container vulnerabilities')

# Add to argument groups
vuln_group.add_argument('-zt', '--zone-transfer', 
                    type=str, help='Test for DNS zone transfer vulnerability',
                    metavar='domain.com')
                    
                                       
# Add to argument groups
ip_group = parser.add_argument_group('IP Information')
ip_group.add_argument('--ipinfo', type=str, help='Get IP info for a company domain/IP', metavar='TARGET')
ip_group.add_argument('--token', type=str, help='IPinfo API token', metavar='TOKEN')
ip_group.add_argument('--save-ranges', type=str, help='Save IP ranges to file', metavar='FILENAME')
parser.add_argument('--forbidden_domains', help='File containing list of domains to scan for forbidden bypass')

# Bruteforcing groups
bruteforcing_group.add_argument('--brute-user-pass', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')
bruteforcing_group.add_argument('--username_wordlist', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')
bruteforcing_group.add_argument('--password_wordlist', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')

# Web Security arguments
web_group = parser.add_argument_group('Web Security')
web_group.add_argument('--web-scan', action='store_true', help='Scan web applications for vulnerabilities')
web_group.add_argument('--url', type=str, help='Target URL to scan', metavar='https://example.com')
web_group.add_argument('--crawler', action='store_true', help='Enable web crawler')
web_group.add_argument('--crawler-depth', type=int, default=3, help='Web crawler depth', metavar='DEPTH')
web_group.add_argument('--xss-scan', action='store_true', help='Scan for XSS vulnerabilities')
web_group.add_argument('--sqli-scan', action='store_true', help='Scan for SQL injection vulnerabilities')
web_group.add_argument('--auth-scan', action='store_true', help='Scan for authentication issues')
web_group.add_argument('--headers-scan', action='store_true', help='Scan for security header issues')
web_group.add_argument('--csrf-scan', action='store_true', help='Scan for CSRF vulnerabilities')
web_group.add_argument('--api-scan', action='store_true', help='Scan API endpoints')
web_group.add_argument('--openapi-file', type=str, help='OpenAPI specification file', metavar='swagger.json')
web_group.add_argument('--login-url', type=str, help='Login URL for authenticated scanning', metavar='https://example.com/login')
web_group.add_argument('--username', type=str, help='Username for authenticated scanning')
web_group.add_argument('--password', type=str, help='Password for authenticated scanning')

# IoT Security arguments
iot_group = parser.add_argument_group('IoT Security')
iot_group.add_argument('--iot-scan', action='store_true', help='Scan IoT devices for vulnerabilities')
iot_group.add_argument('--bluetooth-scan', action='store_true', help='Scan Bluetooth devices')
iot_group.add_argument('--zigbee-scan', action='store_true', help='Scan ZigBee devices')
iot_group.add_argument('--zwave-scan', action='store_true', help='Scan Z-Wave devices')
iot_group.add_argument('--wifi-scan', action='store_true', help='Scan Wi-Fi networks for IoT devices')
iot_group.add_argument('--iot-ip-range', type=str, help='IP range for IoT device scanning')
iot_group.add_argument('--iot-protocols', type=str, help='Protocols to scan (comma-separated: mqtt,coap,amqp)')
iot_group.add_argument('--mqtt-broker', type=str, help='MQTT broker address')
iot_group.add_argument('--mqtt-port', type=int, default=1883, help='MQTT broker port (default: 1883)')
iot_group.add_argument('--coap-server', type=str, help='CoAP server address')
iot_group.add_argument('--coap-port', type=int, default=5683, help='CoAP server port (default: 5683)')
iot_group.add_argument('--ble-device', type=str, help='Bluetooth device address')
iot_group.add_argument('--firmware-analysis', action='store_true', help='Analyze IoT firmware for vulnerabilities')
iot_group.add_argument('--firmware-file', type=str, help='Path to firmware file')
iot_group.add_argument('--pcap-analysis', action='store_true', help='Analyze network PCAP files for IoT traffic')
iot_group.add_argument('--pcap-file', type=str, help='Path to PCAP file')

# ICS/SCADA Security arguments
ics_group = parser.add_argument_group('ICS/SCADA Security')
ics_group.add_argument('--ics-scan', action='store_true', help='Scan Industrial Control Systems for vulnerabilities')
ics_group.add_argument('--modbus-scan', action='store_true', help='Scan Modbus devices and protocols')
ics_group.add_argument('--modbus-port', type=int, default=502, help='Modbus TCP port (default: 502)')
ics_group.add_argument('--s7-scan', action='store_true', help='Scan Siemens S7 devices')
ics_group.add_argument('--s7-port', type=int, default=102, help='Siemens S7 port (default: 102)')
ics_group.add_argument('--dnp3-scan', action='store_true', help='Scan DNP3 devices')
ics_group.add_argument('--dnp3-port', type=int, default=20000, help='DNP3 port (default: 20000)')
ics_group.add_argument('--bacnet-scan', action='store_true', help='Scan BACnet devices')
ics_group.add_argument('--bacnet-port', type=int, default=47808, help='BACnet port (default: 47808)')
ics_group.add_argument('--profinet-scan', action='store_true', help='Scan PROFINET devices')
ics_group.add_argument('--protocol-detection', action='store_true', help='Detect industrial protocols in network traffic')
ics_group.add_argument('--plc-scan', action='store_true', help='Scan Programmable Logic Controllers (PLCs)')
ics_group.add_argument('--hmi-scan', action='store_true', help='Scan Human Machine Interfaces (HMIs)')
ics_group.add_argument('--scada-components', action='store_true', help='Identify SCADA components on the network')
ics_group.add_argument('--ics-pcap', type=str, help='Analyze ICS/SCADA traffic from PCAP file')
ics_group.add_argument('--opcua-scan', action='store_true', help='Scan OPC UA servers')
ics_group.add_argument('--opcua-port', type=int, default=4840, help='OPC UA port (default: 4840)')

# AutoRecon arguments
autorecon_group = parser.add_argument_group('AutoRecon')
autorecon_group.add_argument('--auto-recon', type=str, help='Perform automatic reconnaissance on target')
autorecon_group.add_argument('--intensity', type=str, choices=['light', 'medium', 'aggressive'], default='medium', 
                            help='Intensity of scanning (light, medium, aggressive)')
autorecon_group.add_argument('--max-time', type=int, default=3600, help='Maximum scan time in seconds (default: 3600)')
autorecon_group.add_argument('--save-autorecon', type=str, help='Save autorecon results to file')
autorecon_group.add_argument('--detect-tech', action='store_true', help='Detect technologies used by target')
autorecon_group.add_argument('--auto-exploit', action='store_true', help='Attempt to automatically exploit found vulnerabilities (CAUTION!)')
autorecon_group.add_argument('--scan-profile', type=str, help='Use a specific scan profile (web, network, full)')

# Advanced Specialized Scanners
adv_scanner_group = parser.add_argument_group('Specialized Scanners')
adv_scanner_group.add_argument('--ldap-scan', type=str, help='Scan LDAP directory for vulnerabilities and misconfigurations')
adv_scanner_group.add_argument('--ldap-port', type=int, default=389, help='LDAP port (default: 389)')
adv_scanner_group.add_argument('--ldaps-port', type=int, default=636, help='LDAPS port (default: 636)')
adv_scanner_group.add_argument('--kerberos-scan', type=str, help='Scan Kerberos for vulnerabilities like AS-REP Roasting')
adv_scanner_group.add_argument('--smb-scan', type=str, help='Scan SMB shares for vulnerabilities and misconfigurations')
adv_scanner_group.add_argument('--smb-port', type=int, default=445, help='SMB port (default: 445)')
adv_scanner_group.add_argument('--smb-brute', action='store_true', help='Brute force SMB credentials (Use with caution!)')
adv_scanner_group.add_argument('--windows-scan', type=str, help='Scan Windows-specific vulnerabilities and misconfigurations')
adv_scanner_group.add_argument('--rdp-scan', type=str, help='Scan RDP for vulnerabilities (BlueKeep, etc.)')
adv_scanner_group.add_argument('--rdp-port', type=int, default=3389, help='RDP port (default: 3389)')
adv_scanner_group.add_argument('--voip-scan', type=str, help='Scan VoIP/SIP for vulnerabilities')
adv_scanner_group.add_argument('--sip-port', type=int, default=5060, help='SIP port (default: 5060)')
adv_scanner_group.add_argument('--db-scan', type=str, help='Scan databases for vulnerabilities (MySQL, MSSQL, PostgreSQL, etc.)')
adv_scanner_group.add_argument('--mysql-port', type=int, default=3306, help='MySQL port (default: 3306)')
adv_scanner_group.add_argument('--mssql-port', type=int, default=1433, help='MSSQL port (default: 1433)')
adv_scanner_group.add_argument('--postgres-port', type=int, default=5432, help='PostgreSQL port (default: 5432)')
adv_scanner_group.add_argument('--oracle-port', type=int, default=1521, help='Oracle DB port (default: 1521)')
adv_scanner_group.add_argument('--redis-scan', type=str, help='Scan Redis for vulnerabilities')
adv_scanner_group.add_argument('--redis-port', type=int, default=6379, help='Redis port (default: 6379)')
adv_scanner_group.add_argument('--ftp-scan', type=str, help='Scan FTP for vulnerabilities and misconfigurations')
adv_scanner_group.add_argument('--ftp-port', type=int, default=21, help='FTP port (default: 21)')
adv_scanner_group.add_argument('--snmp-scan', type=str, help='Scan SNMP for vulnerabilities and information disclosure')
adv_scanner_group.add_argument('--snmp-port', type=int, default=161, help='SNMP port (default: 161)')
adv_scanner_group.add_argument('--iot-device-scan', type=str, help='Deep scan for specific IoT device vulnerabilities')
adv_scanner_group.add_argument('--medical-device-scan', type=str, help='Scan for medical device vulnerabilities (DICOM, HL7)')
adv_scanner_group.add_argument('--dicom-port', type=int, default=104, help='DICOM port (default: 104)')
adv_scanner_group.add_argument('--hl7-port', type=int, default=2575, help='HL7 port (default: 2575)')

args = parser.parse_args()

# Add new function for IP info scanning
def scan_ip_info(target, token):
    """Get IP ranges and ASN information using IPinfo API"""
    try:
        # First resolve domain to IP if target is a domain
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f"{Fore.CYAN}Resolved {target} to {ip}{Style.RESET_ALL}\n")
        except socket.gaierror:
            print(f"{Fore.RED}Could not resolve {target} to IP address{Style.RESET_ALL}")
            return None

        handler = ipinfo.getHandler(token)
        print(f"{Fore.MAGENTA}Gathering IP information for {Fore.CYAN}{target}{Style.RESET_ALL}\n")
        
        # Get initial IP info using resolved IP
        details = handler.getDetails(ip)
        
        # Print findings
        print(f"{Fore.GREEN}IP Information:{Style.RESET_ALL}")
        print(f"IP: {Fore.CYAN}{details.ip}{Style.RESET_ALL}")
        if hasattr(details, 'hostname') and details.hostname:
            print(f"Hostname: {Fore.CYAN}{details.hostname}{Style.RESET_ALL}")
        if hasattr(details, 'org') and details.org:
            print(f"Organization: {Fore.CYAN}{details.org}{Style.RESET_ALL}")
        if hasattr(details, 'country') and details.country:
            print(f"Country: {Fore.CYAN}{details.country}{Style.RESET_ALL}")
        if hasattr(details, 'city') and details.city:
            print(f"City: {Fore.CYAN}{details.city}{Style.RESET_ALL}")

        # Get ASN information
        if hasattr(details, 'org') and details.org:
            try:
                org_parts = details.org.split()
                if org_parts:
                    asn = org_parts[0]  # Get ASN number
                    org_name = ' '.join(org_parts[1:])  # Get organization name
                    
                    print(f"\n{Fore.GREEN}ASN Information:{Style.RESET_ALL}")
                    print(f"ASN: {Fore.CYAN}{asn}{Style.RESET_ALL}")
                    print(f"Organization: {Fore.CYAN}{org_name}{Style.RESET_ALL}")
                    
                    # Try to get IP ranges for this ASN
                    try:
                        ranges = []
                        print(f"\n{Fore.GREEN}IP Ranges:{Style.RESET_ALL}")
                        
                        # Use a separate request to get ranges
                        response = requests.get(f"https://ipinfo.io/{asn}/prefixes?token={token}")
                        if response.status_code == 200:
                            prefixes_data = response.json()
                            if 'prefixes' in prefixes_data:
                                for prefix in prefixes_data['prefixes']:
                                    try:
                                        netw = prefix.get('netblock', '')
                                        if netw:
                                            network = ip_network(netw)
                                            ranges.append({
                                                'range': str(network),
                                                'num_ips': network.num_addresses
                                            })
                                            print(f"{Fore.CYAN}{network}{Fore.YELLOW} ({network.num_addresses} IPs){Style.RESET_ALL}")
                                    except ValueError as e:
                                        print(f"{Fore.RED}Error parsing network {netw}: {e}{Style.RESET_ALL}")
                        
                        # Save ranges if requested
                        if args.save_ranges and ranges:
                            try:
                                with open(args.save_ranges, 'w') as f:
                                    f.write(f"# IP Ranges for {target}\n")
                                    f.write(f"# ASN: {asn}\n")
                                    f.write(f"# Organization: {org_name}\n\n")
                                    for r in ranges:
                                        f.write(f"{r['range']} # {r['num_ips']} IPs\n")
                                print(f"\n{Fore.GREEN}IP ranges saved to {args.save_ranges}{Style.RESET_ALL}")
                            except Exception as e:
                                print(f"{Fore.RED}Error saving IP ranges: {e}{Style.RESET_ALL}")
                    
                    except Exception as e:
                        print(f"{Fore.RED}Error getting IP ranges: {e}{Style.RESET_ALL}")
                        
            except Exception as e:
                print(f"{Fore.RED}Error processing ASN information: {e}{Style.RESET_ALL}")

        return details

    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return None

# Add to main argument handling
if args.ipinfo:
    if not args.token:
        print(f"{Fore.RED}Error: IPinfo API token required. Use --token to provide it.{Style.RESET_ALL}")
        sys.exit(1)
    scan_ip_info(args.ipinfo, args.token)


user_agent = useragent_list.get_useragent()
header = {"User-Agent": user_agent}

async def update_script():
    try:
        # Store current version
        current_version = "1.0.0"  # Replace with your version tracking system
        backup_dir = "backups"
        
        print(f"{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
        
        # Create backups directory if it doesn't exist
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Create backup of current version
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"spyhunt_backup_{timestamp}")
        
        print(f"{Fore.YELLOW}Creating backup...{Style.RESET_ALL}")
        try:
            shutil.copytree(".", backup_path, ignore=shutil.ignore_patterns(
                '.git*', '__pycache__', 'backups', '*.pyc'
            ))
            print(f"{Fore.GREEN}Backup created at: {backup_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Backup failed: {str(e)}{Style.RESET_ALL}")
            return False

        # Check remote repository for updates
        print(f"{Fore.CYAN}Checking remote repository...{Style.RESET_ALL}")
        try:
            # Fetch without merging
            subprocess.run(["git", "fetch"], check=True, capture_output=True)
            
            # Get current and remote commit hashes
            current = subprocess.run(["git", "rev-parse", "HEAD"], 
                                   check=True, capture_output=True, text=True).stdout.strip()
            remote = subprocess.run(["git", "rev-parse", "@{u}"], 
                                  check=True, capture_output=True, text=True).stdout.strip()
            
            if current == remote:
                print(f"{Fore.GREEN}SpyHunt is already up to date!{Style.RESET_ALL}")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")
            return False

        # Perform update
        print(f"{Fore.CYAN}Updating SpyHunt...{Style.RESET_ALL}")
        try:
            # Pull changes
            result = subprocess.run(["git", "pull"], check=True, capture_output=True, text=True)
            
            if "Already up to date" in result.stdout:
                print(f"{Fore.GREEN}SpyHunt is already up to date!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}Update successful!{Style.RESET_ALL}")
                
                # Check for dependency updates
                requirements_path = "requirements.txt"
                if os.path.exists(requirements_path):
                    print(f"{Fore.CYAN}Updating dependencies...{Style.RESET_ALL}")
                    subprocess.run(["pip", "install", "-r", requirements_path, "--upgrade"], 
                                 check=True)
                    print(f"{Fore.GREEN}Dependencies updated!{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}SpyHunt has been updated successfully!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please restart SpyHunt to apply the updates.{Style.RESET_ALL}")
            
            return True

        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Update failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Restoring from backup...{Style.RESET_ALL}")
            
            # Restore from backup
            try:
                shutil.rmtree(".", ignore_errors=True)
                shutil.copytree(backup_path, ".", dirs_exist_ok=True)
                print(f"{Fore.GREEN}Restore successful!{Style.RESET_ALL}")
            except Exception as restore_error:
                print(f"{Fore.RED}Restore failed: {str(restore_error)}{Style.RESET_ALL}")
                print(f"{Fore.RED}Please restore manually from: {backup_path}{Style.RESET_ALL}")
            
            return False

    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        return False

# In your argument handler:
if args.update:
    if asyncio.run(update_script()):
        sys.exit(0)
    else:
        sys.exit(1)

def process_domain(domain, save_file=None, shodan_api=None):
    """Process a single domain for subdomain enumeration"""
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    spotter_path = os.path.join(current_script_dir, 'scripts', 'spotter.sh')
    certsh_path = os.path.join(current_script_dir, 'scripts', 'certsh.sh')
    
    results = []
    
    # Subfinder
    cmd = f"subfinder -d {domain} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = p.communicate()
    results.extend(out.decode().splitlines())
    
    # Spotter
    cmd = f"{spotter_path} {domain} | uniq | sort"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    spotterout, _ = p.communicate()
    results.extend(spotterout.decode().splitlines())
    
    # Cert.sh
    cmd = f"{certsh_path} {domain} | uniq | sort"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    certshout, _ = p.communicate()
    results.extend(certshout.decode().splitlines())
    
    # Shodan
    if shodan_api:
        try:
            api = shodan.Shodan(shodan_api)
            results = api.search(f'hostname:*.{domain}')
            for result in results['matches']:
                hostnames = result.get('hostnames', [])
                for hostname in hostnames:
                    if hostname.endswith(domain) and hostname != domain:
                        results.append(hostname)
        except shodan.APIError as e:
            print(Fore.RED + f"Error querying Shodan for {domain}: {e}")
    
    # Remove duplicates and sort
    results = sorted(set(results))
    
    if save_file:
        with open(save_file, "a") as f:
            for subdomain in results:
                if "www" in subdomain:
                    pass
                else:
                    f.write(f"{subdomain}\n")
        print(Fore.GREEN + f"Found {len(results)} subdomains for {domain}")
    else:
        print(Fore.CYAN + f"\nSubdomains for {domain}:\n")
        for subdomain in results:
            print(Fore.GREEN + f"{subdomain}")

# Modify the argument parser to accept either a single domain or a file
if args.s:
    if os.path.isfile(args.s):
        # Reading domains from file
        print(Fore.CYAN + f"Reading domains from {args.s}")
        with open(args.s) as f:
            domains = [line.strip() for line in f if line.strip()]
        
        for domain in domains:
            print(Fore.YELLOW + f"\nProcessing {domain}...")
            process_domain(domain, args.save, args.shodan_api)
    else:
        # Single domain
        process_domain(args.s, args.save, args.shodan_api)

if args.forbidden_pages:
    def save_forbidden_pages(url):
        with open(f"forbidden_pages.txt", "a") as f:
            f.write(f"{url}\n")
    try:
        s = requests.Session()
        with open(f"{args.forbidden_pages}") as f:
            pages = [x.strip() for x in f.readlines()]

        for page in pages:
            r = s.get(page, verify=False, timeout=10)
            if r.status_code == 403:
                print(f"{Fore.RED}{page} [{r.status_code}]{Style.RESET_ALL}")
                save_forbidden_pages(page)
            else:
                pass
    except requests.exceptions.ReadTimeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.RequestException:
        pass

if args.reverseip:
    domain = socket.gethostbyaddr(args.reverseip)
    print(f"{Fore.CYAN}Domain: {Fore.GREEN} {domain[0]}")

if args.reverseipmulti:
    try:
        with open(f"{args.reverseipmulti}") as f:
            ipadd = [x.strip() for x in f.readlines()]
            for ips in ipadd:
                print(f"{socket.gethostbyaddr(ips)}\n")
    except socket.herror:
        pass
    except FileNotFoundError:
        print(f"{Fore.RED} File not found!")


if args.webcrawler:
    def is_same_domain(url: str, base_domain: str) -> bool:
        """Check if URL belongs to the same domain"""
        return urlparse(url).netloc == urlparse(base_domain).netloc

    def get_links(domain: str, visited: set = None) -> set:
        """Extract links from a webpage"""
        if visited is None:
            visited = set()
        
        if domain in visited:
            return set()
            
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            r = requests.get(domain, headers=headers, verify=False, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            links = set()
            
            for tag in soup.find_all("a", href=True):
                href = tag.get("href")
                if href:
                    if not href.startswith(("https://", "http://")):
                        link = urljoin(domain, href)
                    else:
                        link = href
                        
                    if is_same_domain(link, domain):
                        links.add(link)
                        
            return links
            
        except Exception as e:
            print(f"{Fore.RED}Error crawling {domain}: {str(e)}{Fore.WHITE}")
            return set()

    def crawl_recursive(domain: str, depth: int, visited: set = None) -> set:
        """Recursively crawl pages up to specified depth"""
        if visited is None:
            visited = set()
            
        if depth <= 0 or domain in visited:
            return set()
            
        visited.add(domain)
        all_links = set()
        
        # Get links from current page
        links = get_links(domain)
        all_links.update(links)
        
        # Recursively crawl discovered links
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for link in links:
                if link not in visited:
                    futures.append(executor.submit(crawl_recursive, link, depth - 1, visited))
            
            # Process results from recursive crawls
            for future in as_completed(futures):
                try:
                    sub_links = future.result()
                    all_links.update(sub_links)
                except Exception as e:
                    print(f"{Fore.RED}Error processing results: {str(e)}{Fore.WHITE}")
                    
        return all_links

    if __name__ == "__main__":
        domain = args.webcrawler
        depth = int(args.depth)  # Convert to integer explicitly
        
        print(f"{Fore.CYAN}Starting crawl of {domain} with depth {depth}...{Fore.WHITE}")
        
        # Start recursive crawl
        all_urls = crawl_recursive(domain, depth)
        
        # Print results
        print(f"\n{Fore.GREEN}Found {len(all_urls)} unique URLs:{Fore.WHITE}")
        for url in sorted(all_urls):
            print(url)


if args.statuscode:
    commands(f"echo '{args.statuscode}' | httpx -silent -status-code")

if args.favicon:
        response = requests.get(f'{args.favicon}/favicon.ico', verify=False)
        favicon = codecs.encode(response.content,"base64")
        hash = mmh3.hash(favicon)
        print(hash)

if args.enumeratedomain:
    try:
        server = []
        r = requests.get(f"{args.enumeratedomain}", verify=False, headers=header) 
        domain = args.enumeratedomain
        if "https://" in domain:
            domain = domain.replace("https://", "")
        if "http://" in domain:
            domain = domain.replace("http://", "")
        ip = socket.gethostbyname(domain)
        for value, key in r.headers.items():
            if value == "Server" or value == "server":
                server.append(key)
        if server:
            print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}] {Fore.WHITE}Server:{Fore.GREEN} {server}")
        else:
            print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}]")
    except requests.exceptions.MissingSchema as e:
        print(e)
    

if args.faviconmulti:
    print(f"{Fore.MAGENTA}\t\t\t FavIcon Hashes\n")
    with open(f"{args.faviconmulti}") as f:
        domains = [x.strip() for x in f.readlines()]
        try:
            for domainlist in domains:
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=60, headers=header)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    hashes = {}
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=5, headers=header)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    if "https" in domainlist:
                        domainlist = domainlist.replace("https://", "")
                    if "http" in domainlist:
                        domainlist = domainlist.replace("http://", "")
                    ip = socket.gethostbyname(domainlist)
                    if hash == "0":
                        pass
                    for value, item in fingerprint.items():
                        if hash == value:
                            hashes[hash].append(item)
                            print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW} [{item}]")  
                    print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW}")
                    for v,i in hashes.items():
                        print(f"{Fore.MAGENTA}Servers Found")
                        print()
                        print(f"{v}:{i}")
                    else:
                        print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}{hash} {Fore.GREEN}{ip}")
                else:
                    pass
        except TimeoutError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except urllib3.exceptions.ProtocolError:
            pass
        except requests.exceptions.ReadTimeout:
            pass
        except KeyError:
            pass

if args.corsmisconfig:
    print(f"\\t\\t\\t{Fore.CYAN}CORS {Fore.MAGENTA}Misconfiguration {Fore.GREEN}Module\\n\\n")

    try:    
        with open(args.corsmisconfig, "r") as f:
            domains = [x.strip() for x in f.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}File {args.corsmisconfig} not found!")
        sys.exit(1)

    def check_cors(domainlist):
        try:
            payload = [domainlist, "evil.com"]
            header = {'Origin': ', '.join(payload)}
            session = requests.Session()
            session.max_redirects = 10
            resp = session.get(domainlist, verify=False, headers=header, timeout=(5, 10))

            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            allowed_methods = resp.headers.get("Access-Control-Allow-Credentials", "")
            if allow_origin == "evil.com" and allowed_methods == "true":
                print(f"{Fore.YELLOW}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")
                return
            print(f"{Fore.CYAN}NOT VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.LIGHTBLACK_EX}Error processing {domainlist}: {e}{Fore.RESET}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_cors, domain) for domain in domains]

    for future in futures:
        try:
            future.result()
        except Exception as e:
            print(f"An error occurred: {e}")


if args.hostheaderinjection:
    def setup_proxies(proxy=None, proxy_file=None):
        """Setup proxy configuration"""
        proxies = []
        if proxy:
            if not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                proxy = f"http://{proxy}"
            proxies.append({'http': proxy, 'https': proxy})
            
        if proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            proxy = line.strip()
                            if not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                                proxy = f"http://{proxy}"
                            proxies.append({'http': proxy, 'https': proxy})
            except Exception as e:
                print(f"{Fore.RED}Error loading proxy file: {str(e)}{Style.RESET_ALL}")
        return proxies

    def check_host_header_injection(domainlist):
        session = requests.Session()
        headers = {
            "X-Forwarded-Host": "evil.com",
            "Host": "evil.com",
            "X-Forwarded-For": "evil.com",
            "X-Client-IP": "evil.com",
            "X-Remote-IP": "evil.com",
            "X-Remote-Addr": "evil.com",
            "X-Host": "evil.com"
        }

        # Get proxy list
        proxies = setup_proxies(args.proxy, args.proxy_file)
        current_proxy = None

        try:
            # Select proxy if available
            if proxies:
                current_proxy = random.choice(proxies)

            # Normal request with proxy
            normal_resp = session.get(
                domainlist, 
                verify=False, 
                timeout=5,
                proxies=current_proxy
            )
            normal_content = normal_resp.text

            for header_name, header_value in headers.items():
                try:
                    resp = session.get(
                        domainlist, 
                        verify=False, 
                        headers={header_name: header_value}, 
                        timeout=5,
                        proxies=current_proxy
                    )
                    
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        location = resp.headers.get('Location', '').lower()
                        if location == "evil.com":
                            print(f"{Fore.RED}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.YELLOW}(Redirect to evil.com in Location header)")
                            return
                        
                    if resp.text != normal_content:
                        if 'evil.com' in resp.text.lower():
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            title = soup.title.string
                            if "Evil.Com" in title:
                                print(f"{Fore.RED}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.YELLOW}(evil.com found in response body)")
                                print(f"{Fore.YELLOW}Title: {Fore.GREEN}{title}")
                                return
                            else:
                                pass

                except requests.exceptions.ProxyError:
                    if proxies:
                        current_proxy = random.choice(proxies)
                    continue
                except requests.exceptions.ConnectTimeout:
                    print(f"{Fore.RED}Proxy connection timeout{Style.RESET_ALL}")
                    continue

            print(f"{Fore.CYAN}Not Vulnerable: {Fore.GREEN}{domainlist}")

        except requests.exceptions.RequestException as e:
            if "proxy" in str(e).lower():
                pass
            pass

    def main(args):
        print(f"{Fore.MAGENTA}\t\t Host Header Injection \n")
        print(f"{Fore.WHITE}Checking for {Fore.CYAN}X-Forwarded-Host {Fore.WHITE}and {Fore.CYAN}Host {Fore.WHITE}injections.....\n")

        if args.proxy:
            print(f"{Fore.YELLOW}Using proxy: {args.proxy}{Style.RESET_ALL}")
        elif args.proxy_file:
            print(f"{Fore.YELLOW}Loading proxies from: {args.proxy_file}{Style.RESET_ALL}")

        with open(args.hostheaderinjection, "r") as f:
            domains = [x.strip() for x in f.readlines()]

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_host_header_injection, domains)
