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

fuzzing_group.add_argument('-ar', '--auto-recon',
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

    if __name__ == "__main__":
        if args.hostheaderinjection:
            main(args)


if args.securityheaders:
    print(f"{Fore.MAGENTA}\t\t Security Headers\n")
    security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
    session = requests.Session()
    no_sec = []
    found_hd = []
    no_dup = []
    no_dup_found = []
    lower = [x.lower() for x in security_headers]
    capital = [x.upper() for x in security_headers]
    resp = session.get(f"{args.securityheaders}", verify=False)
    print(f"{Fore.CYAN}Domain: {Fore.GREEN}{args.securityheaders}\n")
    for item, key in resp.headers.items():
        for sec_headers in security_headers:
            if sec_headers  == item or lower == item or capital == item:
                found_hd.append(sec_headers)
                [no_dup_found.append(x) for x in found_hd if x not in no_dup_found]
        print(f"{Fore.CYAN}{item}: {Fore.YELLOW}{key}")
    no_dup = ", ".join(no_dup)
    print(lower)
    print("\n")
    print(f"{Fore.GREEN} Found Security Headers: {Fore.YELLOW} {len(no_dup_found)}\n")
    no_dup_found = ", ".join(no_dup_found)
    print(f"{Fore.YELLOW} {no_dup_found}\n")
    no_headers = [item for item in security_headers if item not in no_dup_found]
    print(f"{Fore.RED} Found Missing headers: {Fore.YELLOW} {len(no_headers)}\n")
    no_headers = ", ".join(no_headers)
    print(f"{Fore.YELLOW} {no_headers}")


if args.networkanalyzer:
    print(f"{Fore.MAGENTA}\t\t Analyzing Network Vulnerabilities \n")
    print(f"{Fore.CYAN}IP Range: {Fore.GREEN}{args.networkanalyzer}\n")
    print(f"{Fore.WHITE}")
    commands(f"shodan stats --facets port net:{args.networkanalyzer}")
    commands(f"shodan stats --facets vuln net:{args.networkanalyzer}")


if args.waybackurls:
    if args.save:
        print(Fore.CYAN + f"Saving output to {args.save}")
        commands(f"waybackurls {args.waybackurls} | anew >> {args.save}")
        print(Fore.GREEN + "DONE!")
    else:
        commands(f"waybackurls {args.waybackurls}")

if args.j:
    init(autoreset=True)

    async def fetch(session, url):
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.text()
                elif response.status == 404:
                    # Silently ignore 404 errors
                    return None
                else:
                    print(f"{Fore.YELLOW}Warning: {url} returned status code {response.status}{Style.RESET_ALL}")
                    return None
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
        except asyncio.TimeoutError:
            print(f"{Fore.RED}Timeout error fetching {url}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error fetching {url}: {e}{Style.RESET_ALL}")
        return None

    def is_valid_url(url):
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except Exception as e:
            print(f"{Fore.RED}Error parsing URL {url}: {e}{Style.RESET_ALL}")
            return False

    def is_same_domain(url, domain):
        try:
            return urlparse(url).netloc == domain
        except Exception as e:
            print(f"{Fore.RED}Error comparing domains for {url}: {e}{Style.RESET_ALL}")
            return False

    async def get_js_links(session, url, domain):
        js_links = set()
        new_links = set()
        html = await fetch(session, url)
        if html:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                
                for script in soup.find_all('script', src=True):
                    script_url = urljoin(url, script['src'])
                    if is_valid_url(script_url) and is_same_domain(script_url, domain):
                        js_links.add(script_url)
                
                for script in soup.find_all('script'):
                    if script.string:
                        js_urls = re.findall(r'[\'"]([^\'"]*\.js)[\'"]', script.string)
                        for js_url in js_urls:
                            full_js_url = urljoin(url, js_url)
                            if is_valid_url(full_js_url) and is_same_domain(full_js_url, domain):
                                js_links.add(full_js_url)
                
                new_links = set(urljoin(url, link['href']) for link in soup.find_all('a', href=True))
            except Exception as e:
                print(f"{Fore.RED}Error parsing HTML from {url}: {e}{Style.RESET_ALL}")
        
        return js_links, new_links

    async def crawl_website(url, max_depth, concurrency):
        try:
            domain = urlparse(url).netloc
            visited = set()
            to_visit = {url}
            js_files = set()
            semaphore = asyncio.Semaphore(concurrency)

            async def bounded_get_js_links(session, url, domain):
                async with semaphore:
                    return await get_js_links(session, url, domain)

            async with aiohttp.ClientSession() as session:
                for depth in range(int(max_depth) + 1):
                    if not to_visit:
                        break

                    tasks = [bounded_get_js_links(session, url, domain) for url in to_visit]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    visited.update(to_visit)
                    to_visit = set()

                    for result in results:
                        if isinstance(result, Exception):
                            print(f"{Fore.RED}Error during crawl: {result}{Style.RESET_ALL}")
                            continue
                        js_links, new_links = result
                        js_files.update(js_links)
                        to_visit.update(link for link in new_links 
                                        if is_valid_url(link) and is_same_domain(link, domain) and link not in visited)

                    print(f"{Fore.CYAN}Depth {depth}: Found {len(js_files)} JS files, {len(to_visit)} new URLs to visit{Style.RESET_ALL}")

            return js_files
        except Exception as e:
            print(f"{Fore.RED}Unexpected error during crawl: {e}{Style.RESET_ALL}")
            return set()

    async def main():
        try:
            print(f"{Fore.CYAN}Crawling {Fore.GREEN}{args.j}{Fore.CYAN} for JavaScript files...{Style.RESET_ALL}\n")
            js_files = await crawl_website(args.j, args.depth, args.concurrency)

            if js_files:
                print(f"\n{Fore.YELLOW}Found {len(js_files)} JavaScript files:{Style.RESET_ALL}")
                for js_file in sorted(js_files):
                    print(js_file)

                if args.save:
                    try:
                        with open(args.save, 'w') as f:
                            for js_file in sorted(js_files):
                                f.write(f"{js_file}\n")
                        print(f"\n{Fore.GREEN}Results saved to {args.save}{Style.RESET_ALL}")
                    except IOError as e:
                        print(f"{Fore.RED}Error saving results to file: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}No JavaScript files found.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error in main function: {e}{Style.RESET_ALL}")

    if __name__ == "__main__":
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}Crawl interrupted by user.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
            sys.exit(1)

if args.dns:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f"cat {args.dns} | dnsx -silent -a -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -ns -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -cname -resp >> {args.save}")
    else:
        print(Fore.CYAN + "Printing A records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -a -resp\n")
        print(Fore.CYAN + "Printing NS Records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -ns -resp\n")
        print(Fore.CYAN + "Printing CNAME records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -cname -resp\n")            

if args.probe:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f'cat {args.probe} | httprobe -c 100 | anew >> {args.save}')
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f'sudo cat {args.probe} | httprobe | anew')    


if args.redirects:
    if args.save:
        print(Fore.CYAN + "Saving output to {}}..".format(args.save))
        if which("httpx"):
            print("Please uninstall httpx and install httpx-toolkit from https://github.com/projectdiscovery/httpx-toolkit")
            sys.exit()
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302 | anew >> redirects.txt")
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302")   


if args.brokenlinks:
    if args.save:
        print(Fore.CYAN + "Saving output to {}".format(args.save))
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")
        if path.exists(f"{args.save}"):
            print(Fore.CYAN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.CYAN + "ERROR!")
    else:
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")

if args.smuggler:
    smug_path = os.path.abspath(os.getcwd())
    commands(f"python3 {smug_path}/tools/smuggler/smuggler.py -u {args.smuggler} -q")

if args.ipaddresses:
    ip_list = []

    with open(f"{args.ipaddresses}", "r") as f:
        domains = [x.strip() for x in f.readlines()]

    def scan(domain: str):
        try:
            ips = socket.gethostbyname(domain)
            ip_list.append(ips)
            print(f"{Fore.GREEN} {domain} {Fore.WHITE}- {Fore.CYAN}{ips}")
        except socket.gaierror:
            pass
        except UnicodeError:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan, domain) for domain in domains]
        
        for future in futures:
            future.result()
    
    with open("ips.txt", "w") as file:
        ip_list = list(dict.fromkeys(ip_list))
        for iplist in ip_list:
            file.write(f"{iplist}\n")


if args.domaininfo:
    with open(f"{args.domaininfo}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
    ip_list = []
    server = []
    new_server = set()
    for domain_list in domains:
        try:
            sessions = requests.Session()
            r = sessions.get(domain_list, verify=False, headers=header)
            if "https://" in domain_list:
                domain_list = domain_list.replace("https://", "")
            if "http://" in domain_list:
                domain_list = domain_list.replace("https://", "")
            for v, k in r.headers.items():
                if "Server" in v:
                    server.append(k)
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            ips = socket.gethostbyname(domain_list)
            ip_check = os.system(f"ping -c1 -W1 {ips} > /dev/null")
            if ip_check == 0:
                ip_list.append(ips)
            else:
                pass
            with open(f"ips.txt", "w") as f:
                for ipaddresses in ip_list:
                    f.writelines(f"{ipaddresses}\n")
            new_server.update(server)
            if r.status_code == 200:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.GREEN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
            if r.status_code == 403:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.RED}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
            else:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.CYAN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
        except socket.gaierror:
            pass
        except requests.exceptions.MissingSchema:
            print(f"{Fore.RED} Please use http:// or https://")
        except requests.exceptions.SSLError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except AttributeError:
            print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[No title]{Fore.CYAN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
        except UnicodeDecodeError:
            pass
        except requests.exceptions.InvalidURL:
            pass
        except KeyboardInterrupt:
            sys.exit()
        except:
            pass

if args.importantsubdomains:
    with open(f"{args.importantsubdomains}", "r") as f:
        important_subs = []
        subdomains = [x.strip() for x in f.readlines()]
        for subdomain_list in subdomains:
            if "admin" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "dev" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "test" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "api" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "staging" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "prod" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "beta" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "manage" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "jira" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "github" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
        for pos, value in enumerate(important_subs):
            print(f"{Fore.CYAN}{pos}: {Fore.GREEN}{value}")
        with open("juice_subs.txt", "w") as f:
            for goodsubs in important_subs:
                f.writelines(f"{goodsubs}\n")


if args.not_found:
    session = requests.Session()
    session.headers.update(header)

    def check_status(domain):
        try:
            r = session.get(domain, verify=False, headers=header, timeout=10)
            if r.status_code == 404:
                return domain
        except requests.exceptions.RequestException:
            pass

    def get_results(links, output_file):
        pool = ThreadPool(processes=multiprocessing.cpu_count())
        results = pool.imap_unordered(check_status, links)
        with open(output_file, "w") as f:
            for result in results:
                if result:
                    f.write(f"{result}\n")
                    print(result)
        pool.close()
        pool.join()

    with open(args.not_found, "r") as f:
        links = (f"{x.strip()}" for x in f.readlines())
        output_file = "results.txt"
        get_results(links, output_file)

if args.paramspider:
    commands(f"paramspider -d {args.paramspider}")

if args.pathhunt:
    def commands(cmd):
        try:
            subprocess.check_call(cmd, shell=True)
        except:
            pass
    pathhunt_path = os.path.abspath(os.getcwd())
    commands(f"python3 {pathhunt_path}/tools/pathhunt.py -t {args.pathhunt}")   
    
if args.nmap:
    print(f"{Fore.WHITE}Scanning {Fore.CYAN}{args.nmap}\n")
    nmap = nmap3.Nmap()
    results = nmap.nmap_version_detection(f"{args.nmap}")

    with open("nmap_results.json", "w") as f:
        json.dump(results, f, indent=4)

    with open('nmap_results.json', 'r') as file:
        data = json.load(file)

    for host, host_data in data.items():
        if host != "runtime" and host != "stats" and host != "task_results":
            ports = host_data.get("ports", [])
            for port in ports:
                portid = port.get("portid")
                service = port.get("service", {})
                product = service.get("product")
                print(f"{Fore.WHITE}Port: {Fore.CYAN}{portid}, {Fore.WHITE}Product: {Fore.CYAN}{product}")

if args.api_fuzzer:
    error_patterns = [
        "404",
        "Page Not Found",
        "Not Found",
        "Error 404",
        "404 Not Found",
        "The page you requested was not found",
        "The requested URL was not found",
        "This page does not exist",
        "The requested page could not be found",
        "Sorry, we couldn't find that page",
        "Page doesn't exist"
    ]
    s = requests.Session()
    with open("payloads/api-endpoints.txt", "r") as file:
        api_endpoints = [x.strip() for x in file.readlines()]
    
    def check_endpoint(endpoint):
        url = f"{args.api_fuzzer}/{endpoint}"
        try:
            r = s.get(url, verify=False, headers=header, timeout=5)

            # Check response text for error patterns
            page_text = r.text.lower()
            found_patterns = []
            for pattern in error_patterns:
                if pattern.lower() in page_text:
                    found_patterns.append(pattern)
            if found_patterns:
                return f"{Fore.RED}{url} - {', '.join(found_patterns)}"

            # Check beautifulsoup for error patterns
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.find("title") and "404" in soup.find("title").text.lower():
                pass
            elif soup.find("title") and "Page Not Found" in soup.find("title").text.lower():
                pass
            elif r.status_code == 403:
                pass
            elif r.status_code == 200:
                return f"{Fore.GREEN}{url}"
            elif r.status_code == 404:
                pass
            else:
                return f"{Fore.RED}{url} [{r.status_code}]"
        except requests.RequestException:
            return f"{Fore.YELLOW}{url} [Error]"
    
    print(f"Scanning {len(api_endpoints)} endpoints for {args.api_fuzzer}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_endpoint, endpoint) for endpoint in api_endpoints]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                if result.startswith(Fore.GREEN):
                    print(result)
            else:
                pass
            

if args.shodan_:
    key = input("Shodan Key: ")
    print("\n")
    api = shodan.Shodan(str(key))
    try:
        results = api.search(args.shodan)
        results_ = []
        results_5 = []
        for result in results['matches']:
            results_.append(result['ip_str'])
        results_5.append(results_[0:50])
        if results_5:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shodan IPs: {Fore.GREEN}{', '.join(map(str,results_5))}")
        if not results_5:
            pass
    except shodan.APIError:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.YELLOW} Shodan Key: {Fore.GREEN} Invalid Key")
    except socket.herror:
        pass


if args.forbiddenpass or args.forbidden_domains:
    def word_list(wordlist: str) -> str:
        try:
            with open(wordlist, "r") as f:
                data = [x.strip() for x in f.readlines()] 
            return data
        except FileNotFoundError as e:
            print(f"File not found: {e}")

    current_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist = word_list(os.path.join(current_dir, "payloads", "bypasses.txt"))

    def header_bypass():
        headers = [
            {'User-Agent': user_agent},
            {'User-Agent': str(user_agent), 'X-Custom-IP-Authorization': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-For': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-For': '127.0.0.1:80'},
            {'User-Agent': str(user_agent), 'X-Originally-Forwarded-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Originating-': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Originating-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'True-Client-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-WAP-Profile': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Arbitrary': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-HTTP-DestinationURL': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Proto': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'Destination': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Remote-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Client-IP': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Host': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Host': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '4443'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '80'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8080'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8443'},
            {'User-Agent': str(user_agent), 'X-ProxyUser-Ip': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'Client-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Real-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Original-URL': '/admin'},
            {'User-Agent': str(user_agent), 'X-Rewrite-URL': '/admin'},
            {'User-Agent': str(user_agent), 'X-Originating-URL': '/admin'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Server': 'localhost'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Scheme': 'http'},
            {'User-Agent': str(user_agent), 'X-Original-Remote-Addr': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Protocol': 'http'},
            {'User-Agent': str(user_agent), 'X-Original-Host': 'localhost'},
            {'User-Agent': str(user_agent), 'Proxy-Host': 'localhost'},
            {'User-Agent': str(user_agent), 'Request-Uri': '/admin'},
            {'User-Agent': str(user_agent), 'X-Server-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-SSL': 'off'},
            {'User-Agent': str(user_agent), 'X-Original-URL': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Client-Port': '443'},
            {'User-Agent': str(user_agent), 'X-Backend-Host': 'localhost'},
            {'User-Agent': str(user_agent), 'X-Remote-Addr': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Remote-Port': '443'},
            {'User-Agent': str(user_agent), 'X-Host-Override': 'localhost'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Server': 'localhost:80'},
            {'User-Agent': str(user_agent), 'X-Host-Name': 'localhost'},
            {'User-Agent': str(user_agent), 'X-Proxy-URL': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'Base-Url': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'HTTP-X-Forwarded-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'HTTP-Client-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'HTTP-X-Real-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'Proxy-Url': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forward-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Originally-Forwarded-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'Forwarded-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'Forwarded-For-Ip': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-By': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-For-Original': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Host-Original': 'localhost'},
            {'User-Agent': str(user_agent), 'X-Pwnage': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Bypass': '127.0.0.1'},

        ]
        return headers
    
    def save_forbidden_bypass(url):
        with open("forbidden_bypass.txt", "a") as f:
            f.write(f"{url}\n")
    
    def do_request(url: str, stream=False):
        headers = header_bypass()
        try:
            for header in headers:
                if stream:
                    s = requests.Session()
                    r = s.get(url, stream=True, headers=header, verify=False, timeout=10)
                else:
                    s = requests.Session()
                    r = s.get(url, headers=header, verify=False, timeout=10)
                if r.status_code == 200:
                    print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.GREEN + " [{}]".format(r.status_code))
                    save_forbidden_bypass(url)
                elif r.status_code == 403:
                    print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.RED + " [{}]".format(r.status_code))
                else:
                    print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.RED + " [{}]".format(r.status_code))
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass

    def load_domains(filename: str) -> list:
        try:
            with open(filename, "r") as f:
                return [x.strip() for x in f.readlines()]
        except FileNotFoundError as e:
            print(f"{Fore.RED}Domain file not found: {e}{Style.RESET_ALL}")
            return []

    def scan_domain(domain: str, wordlist: list):
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        print(f"\n{Fore.YELLOW}Scanning domain: {domain}{Style.RESET_ALL}")
        for bypass in wordlist:
            links = f"{domain}{bypass}"
            do_request(links)

    def main():
        if args.forbidden_domains:
            domains = load_domains(args.forbidden_domains)
            print(f"{Fore.CYAN}Starting scan of {len(domains)} domains...{Style.RESET_ALL}\n")
            for domain in domains:
                scan_domain(domain, wordlist)
        
        if args.forbiddenpass:
            scan_domain(args.forbiddenpass, wordlist)

    if __name__ == "__main__":
        main()

if args.directorybrute:
    if args.wordlist:
        if args.threads:
            def filter_wordlist(wordlist, extensions):
                if not extensions:
                    return wordlist
                ext_list = [ext.strip() for ext in extensions.split(',')]
                return [word for word in wordlist if any(word.endswith(ext) for ext in ext_list)]

            def dorequests(wordlist: str, base_url: str, headers: dict, is_file_only: bool, excluded_codes: set, bar, print_lock):
                s = requests.Session()
                
                def check_and_print(url, type_str):
                    try:
                        r = s.get(url, verify=False, headers=headers, timeout=10)
                        if r.status_code not in excluded_codes:
                            if r.status_code == 200 and "Welcome" in r.text:
                                color = Fore.GREEN
                            elif r.status_code == 301 or r.status_code == 302:
                                color = Fore.YELLOW
                            else:
                                color = Fore.BLUE
                            with print_lock:
                                print(f"\n{url} - {color}{type_str} Found (Status: {r.status_code}){Fore.RESET}\n")
                    except requests.RequestException:
                        pass
                    finally:
                        bar()

                if is_file_only:
                    url = f"{base_url}/{wordlist}"
                    check_and_print(url, "File")
                else:
                    dir_url = f"{base_url}/{wordlist}/"
                    check_and_print(dir_url, "Directory")
                    
            def main():
                with open(args.wordlist, "r") as f:
                    wordlist_ = [x.strip() for x in f.readlines()]
                
                is_file_only = bool(args.extensions)
                
                filtered_wordlist = filter_wordlist(wordlist_, args.extensions)
                
                excluded_codes = set(int(code.strip()) for code in args.exclude.split(',') if code.strip())
                
                print(f"Target: {Fore.CYAN}{args.directorybrute}{Fore.RESET}\n"
                    f"Wordlist: {Fore.CYAN}{args.wordlist}{Fore.RESET}\n"
                    f"Extensions: {Fore.CYAN}{args.extensions or 'All'}{Fore.RESET}\n"
                    f"Excluded Status Codes: {Fore.CYAN}{', '.join(map(str, excluded_codes)) or 'None'}{Fore.RESET}\n")

                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

                print_lock = threading.Lock()

                with alive_bar(len(filtered_wordlist), title="Scanning", bar="classic", spinner="classic") as bar:
                    with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                        futures = [executor.submit(dorequests, wordlist, args.directorybrute, headers, is_file_only, excluded_codes, bar, print_lock) 
                                for wordlist in filtered_wordlist]
                        
                        for future in as_completed(futures):
                            future.result()

            if __name__ == "__main__":
                main()

if args.nuclei_lfi:
    vulnerability = []
    FileOrTarget = str(input("Do you want to scan a file or a single target?? Ex: F or T:  "))
    if FileOrTarget == "F" or FileOrTarget == "f":
        File = str(input("Filename: "))
        print(f"Scanning File {File} ..... \n")
        results = scan(f"nuclei -l {File} -tags lfi -c 100")
        vulnerability.append(results)
        if vulnerability:
            for vulns in vulnerability:
                print(vulns)
    elif FileOrTarget == "T" or FileOrTarget == "t":
        Target = str(input("Target: "))
        print(f"Scanning Target {Target} ..... \n")
        results = scan(f"nuclei -u {Target} -tags lfi -c 100")
        vulnerability.append(results)
        if vulnerability:
            for vulns in vulnerability:
                print(vulns)
    else:
        print("Enter either T or F")


if args.google:
    def search_google(dorks: str, page) -> str:
        for url in search(dork, num_results=int(page)):
            return url
    try: 
        dork = input("Enter Dork: ")
        numpage = input("Enter number of links to display: ")
        print ("\n")
        search_google(dork, numpage)
        print("\n")
        print ("Found: {} links".format(numpage))
    except Exception as e:
        print(str(e))

    save = input("Save results to a file (y/n)?: ").lower()
    if save == "y":
        dorklist = input("Filename: ")
        with open(dorklist, "w") as f:
            for url in search(dork, num_results=int(numpage)):
                f.writelines(url)
                f.writelines("\n")
        if path.exists(dorklist):
            print ("File saved successfully")
        if not path.exists(dorklist):
            print ("File was not saved")
    elif save == "n":
        pass        
            
if args.cidr_notation:
    if args.ports:
        if args.threads:
            def scan_ip(ip, ports):
                open_ports = []
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return ip, open_ports

            def scan_subnet(subnet, ports, max_threads=100):
                network = ipaddress.ip_network(subnet, strict=False)
                
                with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                    futures = [executor.submit(scan_ip, ip, ports) for ip in network.hosts()]
                    
                    for future in as_completed(futures):
                        ip, open_ports = future.result()
                        if open_ports:
                            print(f"IP: {Fore.GREEN}{ip}:{Fore.CYAN}{','.join(map(str, open_ports))}{Fore.RESET}")

            def parse_ports(ports):
                if isinstance(ports, list):
                    return [int(p) for p in ports]
                return [int(p.strip()) for p in ports.split(',')]
            
            def main():
                ports = parse_ports(args.ports)
                scan_subnet(args.cidr_notation, ports, args.threads)

            if __name__ == "__main__":
                main()
    
if args.print_all_ips:
    def extract_ip(ip):
        return str(ip)

    def extract_ips(subnet, max_workers=100):
        network = ipaddress.ip_network(subnet, strict=False)
        ips = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(extract_ip, ip) for ip in network.hosts()]
            for future in as_completed(futures):
                ips.append(future.result())
        return ips

    print(f"Extracting IPs from {args.print_all_ips}...")
    ips = extract_ips(args.print_all_ips)
    
    print(f"\nExtracted IPs from {args.print_all_ips}:")
    for ip in ips:
        print(f"{Fore.GREEN}{ip}{Fore.RESET}")
    
    print(f"\nTotal IPs: {len(ips)}")

    save = input("Do you want to save these IPs to a file? (y/n): ").lower()
    if save == 'y':
        filename = input("Enter filename to save IPs: ")
        with open(filename, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"IPs saved to {filename}")


if args.xss_scan:
    # Define rate limit: 5 calls per second
    CALLS = 5
    RATE_LIMIT = 1

    @sleep_and_retry
    @limits(calls=CALLS, period=RATE_LIMIT)
    def rate_limited_request(url, headers, timeout):
        return requests.get(url, verify=False, headers=headers, timeout=timeout)

    def generate_random_string(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encode_payload(payload):
        encodings = [
            lambda x: x,  # No encoding
            lambda x: quote_plus(x),  # URL encoding
            lambda x: html.escape(x),  # HTML entity encoding
            lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
            lambda x: ''.join(f'&#x{ord(c):02X};' for c in x),  # Hex entity encoding
            lambda x: ''.join(f'\\u{ord(c):04X}' for c in x),  # Unicode escape
        ]
        return random.choice(encodings)(payload)

    def print_vulnerability(vuln):
        if vuln['execution_likelihood'] == 'High':
            print(f"\n{Fore.RED}High likelihood XSS vulnerability found:{Fore.RESET}")
            print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
            print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
            print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
            print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")

    def xss_scan_url(url, payloads, bar):
        print(f"{Fore.CYAN}Scanning for XSS vulnerabilities: {Fore.GREEN}{url}{Fore.RESET}")
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        vulnerabilities = []
        
        for param in params:
            for payload in payloads:
                random_string = generate_random_string()
                test_payload = payload.replace("XSS", random_string)
                encoded_payload = encode_payload(test_payload)
                
                test_params = params.copy()
                test_params[param] = [encoded_payload]
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                try:
                    response = rate_limited_request(test_url, headers=header, timeout=10)
                    response_text = response.text.lower()
                    
                    if random_string.lower() in response_text:
                        vulnerability = {
                            "url": url,
                            "parameter": param,
                            "payload": encoded_payload,
                            "test_url": test_url
                        }
                        pattern_script = r'<script>.*?alert\([\'"]{}[\'"]\).*?</script>'.format(re.escape(random_string))
                        pattern_event = r'on\w+\s*=.*?alert\([\'"]{}[\'"]\)'.format(re.escape(random_string))
                        if re.search(pattern_script, response_text, re.IGNORECASE | re.DOTALL) or \
                           re.search(pattern_event, response_text, re.IGNORECASE):
                            vulnerability["execution_likelihood"] = "High"
                            vulnerabilities.append(vulnerability)
                            print_vulnerability(vulnerability)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
                finally:
                    bar()  # Increment the progress bar for each payload scanned
        
        return vulnerabilities

    def xss_scanner(target):
        if os.path.isfile(target):
            with open(target, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
            
            with open("payloads/xss.txt", "r") as f:
                payloads = [x.strip() for x in f.readlines()]
            
            total_payloads = 0
            # Calculate total payloads based on number of URLs and number of payloads per URL
            for url in urls:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                total_payloads += len(params) * len(payloads)
            
            all_vulnerabilities = []
            with alive_bar(total_payloads, title="Scanning XSS Vulnerabilities") as bar:
                with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                    future_to_url = {executor.submit(xss_scan_url, url, payloads, bar): url for url in urls}
                    for future in as_completed(future_to_url):
                        url = future_to_url[future]
                        try:
                            vulnerabilities = future.result()
                            all_vulnerabilities.extend(vulnerabilities)
                        except Exception as exc:
                            print(f'{Fore.RED}Error scanning {url}: {exc}{Fore.RESET}')
            
            return all_vulnerabilities
        else:
            target_url = target
            with open("payloads/xss.txt", "r") as f:
                payloads = [x.strip() for x in f.readlines()]
            
            params = parse_qs(urlparse(target_url).query)
            total_payloads = len(params) * len(payloads)
            
            all_vulnerabilities = []
            with alive_bar(total_payloads, title="Scanning XSS Vulnerabilities") as bar:
                vulnerabilities = xss_scan_url(target_url, payloads, bar)
                all_vulnerabilities.extend(vulnerabilities)
            
            return all_vulnerabilities

    if __name__ == "__main__":
        vulnerabilities = xss_scanner(args.xss_scan)
        if not vulnerabilities:
            print(f"\n{Fore.GREEN}No XSS vulnerabilities found.{Fore.RESET}")
        else:
            print(f"\n{Fore.RED}Total XSS vulnerabilities found: {len(vulnerabilities)}{Fore.RESET}")


if args.sqli_scan:
    init(autoreset=True)

    # Rate Limiting Configuration
    RATE_LIMIT = 5  # Maximum number of requests per second
    REQUEST_INTERVAL = 1 / RATE_LIMIT  # Interval between requests in seconds

    def generate_random_string(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encode_payload(payload):
        encodings = [
            lambda x: x,  # No encoding
            lambda x: quote_plus(x),  # URL encoding
            lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
        ]
        return random.choice(encodings)(payload)

    def print_vulnerability(vuln):
        print(f"\n{Fore.RED}SQL Injection vulnerability found:{Fore.RESET}")
        print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
        print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
        print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
        print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")
        print(f"Type: {Fore.GREEN}{vuln['type']}{Fore.RESET}")

    def sqli_scan_url(url, print_queue, bar, rate_limiter):
        print_queue.put(f"{Fore.CYAN}Scanning for SQL injection vulnerabilities: {url}{Fore.RESET}")
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for param in params:
            # Error-based SQLi
            error_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL, NULL, NULL --",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1 UNION SELECT NULL, NULL, NULL --",
            ]
            
            for payload in error_payloads:
                rate_limiter.acquire()
                encoded_payload = encode_payload(payload)
                test_params = params.copy()
                test_params[param] = [encoded_payload]
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                                      'Chrome/58.0.3029.110 Safari/537.3'
                    }
                    response = requests.get(test_url, verify=False, headers=headers, timeout=10)
                    
                    sql_errors = [
                        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
                        r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
                        r"valid PostgreSQL result", r"Npgsql\.", r"Driver.*SQL SERVER",
                        r"OLE DB.*SQL SERVER", r"SQL Server.*Driver", r"Warning.*mssql_.*",
                        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
                        r"ODBC SQL Server Driver", r"SQLServer JDBC Driver", r"Oracle error",
                        r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"
                    ]
                    
                    for error in sql_errors:
                        if re.search(error, response.text, re.IGNORECASE):
                            vulnerability = {
                                "url": url,
                                "parameter": param,
                                "payload": encoded_payload,
                                "test_url": test_url,
                                "type": "Error-based SQLi"
                            }
                            print_queue.put(vulnerability)
                            bar()  # Increment progress bar upon finding a vulnerability
                            return  # Exit after finding a vulnerability
                    
                except requests.RequestException as e:
                    print_queue.put(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
                finally:
                    bar()  # Increment the progress bar for each payload scanned
            
            # Boolean-based blind SQLi
            rate_limiter.acquire()
            original_params = params.copy()
            original_params[param] = ["1 AND 1=1"]
            true_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
            
            original_params[param] = ["1 AND 1=2"]
            false_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
            
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/58.0.3029.110 Safari/537.3'
                }
                true_response = requests.get(true_url, verify=False, headers=headers, timeout=10)
                false_response = requests.get(false_url, verify=False, headers=headers, timeout=10)
                
                if true_response.text != false_response.text:
                    vulnerability = {
                        "url": url,
                        "parameter": param,
                        "payload": "1 AND 1=1 / 1 AND 1=2",
                        "test_url": f"{true_url} / {false_url}",
                        "type": "Boolean-based blind SQLi"
                    }
                    print_queue.put(vulnerability)
                    bar()  # Increment progress bar upon finding a vulnerability
            except requests.RequestException as e:
                print_queue.put(f"{Fore.YELLOW}Error during boolean-based test for {url}: {str(e)}{Fore.RESET}")
            finally:
                bar()  # Increment the progress bar even if vulnerability is found
                
            # Time-based blind SQLi
            rate_limiter.acquire()
            time_payload = "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1"
            encoded_time_payload = encode_payload(time_payload)
            time_params = params.copy()
            time_params[param] = [encoded_time_payload]
            time_url = parsed_url._replace(query=urlencode(time_params, doseq=True)).geturl()
            
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/58.0.3029.110 Safari/537.3'
                }
                start_time = time.time()
                response = requests.get(time_url, verify=False, headers=headers, timeout=10)
                end_time = time.time()
                
                if end_time - start_time >= 5:
                    vulnerability = {
                        "url": url,
                        "parameter": param,
                        "payload": time_payload,
                        "test_url": time_url,
                        "type": "Time-based blind SQLi"
                    }
                    print_queue.put(vulnerability)
            except requests.RequestException as e:
                print_queue.put(f"{Fore.YELLOW}Error during time-based test for {url}: {str(e)}{Fore.RESET}")
            finally:
                bar()  # Increment the progress bar for each payload scanned

    def print_worker(print_queue):
        while True:
            item = print_queue.get()
            if item is None:
                break
            if isinstance(item, dict):
                print_vulnerability(item)
            else:
                print(item)
            print_queue.task_done()

    def sqli_scanner(target):
        print_queue = Queue()
        print_thread = threading.Thread(target=print_worker, args=(print_queue,))
        print_thread.start()

        if os.path.isfile(target):
            with open(target, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        else:
            urls = [target]

        try:
            with open("payloads/sqli.txt", "r") as f:
                payloads = [x.strip() for x in f.readlines()]
        except FileNotFoundError:
            print(f"{Fore.RED}Payload file 'payloads/sqli.txt' not found.{Fore.RESET}")
            return []

        total_payloads = 0
        # Calculate total payloads based on number of URLs and number of payloads per URL
        for url in urls:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if params:
                # Error-based payloads
                error_payloads = [
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' UNION SELECT NULL, NULL, NULL --",
                    "1' ORDER BY 1--+",
                    "1' ORDER BY 2--+",
                    "1' ORDER BY 3--+",
                    "1 UNION SELECT NULL, NULL, NULL --",
                ]
                total_payloads += len(params) * len(error_payloads)
                
                # Boolean-based payloads (1 per parameter)
                total_payloads += len(params) * 1
                
                # Time-based payloads (1 per parameter)
                total_payloads += len(params) * 1

        if total_payloads == 0:
            print(f"{Fore.YELLOW}No parameters found in the target URL(s) to perform SQLi scanning.{Fore.RESET}")
            return []

        all_vulnerabilities = []
        # Initialize the rate limiter
        rate_limiter = threading.Semaphore(RATE_LIMIT)

        def release_rate_limiter():
            while True:
                time.sleep(REQUEST_INTERVAL)
                rate_limiter.release()

        # Start a thread to release the semaphore at the defined rate
        rate_thread = threading.Thread(target=release_rate_limiter, daemon=True)
        rate_thread.start()

        with alive_bar(total_payloads, title="Scanning SQL Injection Vulnerabilities") as bar:
            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                future_to_url = {executor.submit(sqli_scan_url, url, print_queue, bar, rate_limiter): url for url in urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulnerabilities = future.result()
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as exc:
                        print_queue.put(f'{Fore.RED}Error scanning {url}: {exc}{Fore.RESET}')

        print_queue.put(None)
        print_thread.join()

        return all_vulnerabilities

    if __name__ == "__main__":
        vulnerabilities = sqli_scanner(args.sqli_scan)
        if vulnerabilities:
            print(f"\n{Fore.RED}Total SQL Injection vulnerabilities found: {len(vulnerabilities)}{Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}No SQL Injection vulnerabilities found.{Fore.RESET}")


if args.webserver_scan:
    init(autoreset=True)

    def get_server_info(url, path=''):
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, allow_redirects=False, timeout=10)
            return response.headers, response.status_code, response.text
        except requests.RequestException:
            return {}, None, ''

    def analyze_headers(headers):
        server_info = {}
        for header, value in headers.items():
            if header.lower() == 'server':
                server_info['Server'] = value
            elif header.lower() == 'x-powered-by':
                server_info['X-Powered-By'] = value
            elif header.lower() == 'x-aspnet-version':
                server_info['ASP.NET'] = value
            elif header.lower() == 'x-generator':
                server_info['Generator'] = value
        return server_info

    def check_specific_files(url):
        files_to_check = {
            '/favicon.ico': {'Apache': 'Apache', 'Nginx': 'Nginx'},
            '/server-status': {'Apache': 'Apache Status'},
            '/nginx_status': {'Nginx': 'Nginx Status'},
            '/web.config': {'IIS': 'IIS Config'},
            '/phpinfo.php': {'PHP': 'PHP Version'}
        }
        
        results = {}
        for file, signatures in files_to_check.items():
            headers, status, content = get_server_info(url, file)
            if status == 200:
                for server, signature in signatures.items():
                    if signature in content:
                        results[server] = f"Detected via {file}"
        return results

    def detect_web_server(url):
        if not url.startswith('http'):
            url = 'http://' + url

        print(f"Scanning {Fore.GREEN}{url}{Fore.WHITE}...{Style.RESET_ALL}")

        headers, status, content = get_server_info(url)
        
        if status is None:
            print(f"{Fore.RED}Error: Unable to connect to the server{Style.RESET_ALL}")
            return

        server_info = analyze_headers(headers)
        
        if 'Server' not in server_info:
            if 'Set-Cookie' in headers and 'ASPSESSIONID' in headers['Set-Cookie']:
                server_info['Likely'] = 'IIS'
            elif 'Set-Cookie' in headers and 'PHPSESSID' in headers['Set-Cookie']:
                server_info['Likely'] = 'PHP'
        
        file_results = check_specific_files(url)
        server_info.update(file_results)

        if server_info:
            for key, value in server_info.items():
                print(f"{Fore.GREEN}{key}:{Style.RESET_ALL} {Fore.YELLOW}{value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Unable to determine web server{Style.RESET_ALL}")

        if 'CF-RAY' in headers:
            print(f"{Fore.GREEN}Cloudflare detected{Style.RESET_ALL}")
        
        if 'X-Varnish' in headers:
            print(f"{Fore.GREEN}Varnish Cache detected{Style.RESET_ALL}")

    def main():
        detect_web_server(args.webserver_scan)

    if __name__ == "__main__":
        main()

if args.javascript_scan:
    init(autoreset=True)

    def is_valid_url(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def get_js_files(url):
        js_files = set()
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find <script> tags with src attribute
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                if is_valid_url(script_url):
                    js_files.add(script_url)
            
            # Find JavaScript files in <link> tags
            for link in soup.find_all('link', rel='stylesheet'):
                if 'href' in link.attrs:
                    css_url = urljoin(url, link['href'])
                    if is_valid_url(css_url):
                        css_response = requests.get(css_url, timeout=10)
                        js_urls = re.findall(r'url\([\'"]?(.*?\.js)[\'"]?\)', css_response.text)
                        for js_url in js_urls:
                            full_js_url = urljoin(css_url, js_url)
                            if is_valid_url(full_js_url):
                                js_files.add(full_js_url)
            
            # Find JavaScript files mentioned in inline scripts
            for script in soup.find_all('script'):
                if script.string:
                    js_urls = re.findall(r'[\'"]([^\'"]*\.js)[\'"]', script.string)
                    for js_url in js_urls:
                        full_js_url = urljoin(url, js_url)
                        if is_valid_url(full_js_url):
                            js_files.add(full_js_url)
            
        except requests.RequestException as e:
            print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
        
        return js_files

    def analyze_js_file(js_url):
        try:
            response = requests.get(js_url, timeout=10)
            content = response.text
            size = len(content)
            
            # Analysis patterns
            interesting_patterns = {
                'API Keys': r'(?i)(?:api[_-]?key|apikey)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])',
                'Passwords': r'(?i)(?:password|passwd|pwd)["\s:=]+(["\'][^"\']{8,}["\'])',
                'Tokens': r'(?i)(?:token|access_token|auth_token)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])',
                'Sensitive Functions': r'(?i)(eval|setTimeout|setInterval)\s*\([^)]+\)',
            }
            
            findings = {}
            for name, pattern in interesting_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings[name] = matches
            
            return js_url, size, findings
        except requests.RequestException as e:
            return js_url, None, f"Error: {e}"

    def main():
        print(f"Scanning {Fore.GREEN}{args.javascript_scan} {Fore.WHITE}for JavaScript files...{Style.RESET_ALL}")
        
        js_files = get_js_files(args.javascript_scan)
        if not js_files:
            print(f"{Fore.YELLOW}No JavaScript files found.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Found {len(js_files)} JavaScript files. Analyzing...{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            results = list(executor.map(analyze_js_file, js_files))
        
        for url, size, findings in results:
            print(f"{Fore.MAGENTA}File: {url}{Style.RESET_ALL}")
            if size is not None:
                print(f"Size: {size} bytes")
                if findings:
                    print("Potential sensitive information:")
                    for name, matches in findings.items():
                        print(f"  - {name}:")
                        for match in matches[:5]:  # Limit to first 5 matches to avoid overwhelming output
                            print(f"    {match}")
                        if len(matches) > 5:
                            print(f"    ... and {len(matches) - 5} more")
                else:
                    print("No potential sensitive information found.")
            else:
                print(f"{Fore.RED}{findings}{Style.RESET_ALL}")
            print()

    if __name__ == "__main__":
        main()

if args.javascript_endpoints:

    init(autoreset=True)

    async def fetch(session, url):
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    pass
                    return None
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
        except asyncio.TimeoutError:
            print(f"{Fore.RED}Timeout error fetching {url}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error fetching {url}: {e}{Style.RESET_ALL}")
        return None

    def find_endpoints(js_content):
        # This regex pattern looks for common endpoint patterns in JavaScript
        endpoint_pattern = r'(?:"|\'|\`)(/(?:api/)?[\w-]+(?:/[\w-]+)*(?:\.\w+)?)'
        endpoints = set(re.findall(endpoint_pattern, js_content))
        return endpoints

    async def analyze_js_file(session, js_url):
        js_content = await fetch(session, js_url)
        if js_content:
            endpoints = find_endpoints(js_content)
            return js_url, endpoints
        return js_url, set()

    async def process_js_files(file_path, concurrency):
        js_files = {}
        
        try:
            with open(file_path, 'r') as file:
                js_urls = [line.strip() for line in file if line.strip()]

            async with aiohttp.ClientSession() as session:
                semaphore = asyncio.Semaphore(concurrency)
                
                async def bounded_analyze_js_file(js_url):
                    async with semaphore:
                        return await analyze_js_file(session, js_url)
                
                tasks = [bounded_analyze_js_file(js_url) for js_url in js_urls]
                results = await asyncio.gather(*tasks)

                for js_url, endpoints in results:
                    js_files[js_url] = endpoints

        except Exception as e:
            print(f"{Fore.RED}Error processing JS file list: {e}{Style.RESET_ALL}")

        return js_files

    async def main():
        print(f"{Fore.CYAN}Analyzing JavaScript files from {Fore.GREEN}{args.javascript_endpoints}{Style.RESET_ALL}\n")
        js_files = await process_js_files(args.javascript_endpoints, args.concurrency)

        if js_files:
            print(f"\n{Fore.YELLOW}Analyzed {len(js_files)} JavaScript files:{Style.RESET_ALL}")
            for js_url, endpoints in js_files.items():
                print(f"\n{Fore.CYAN}{js_url}{Style.RESET_ALL}")
                if endpoints:
                    print(f"{Fore.GREEN}Endpoints found:{Style.RESET_ALL}")
                    for endpoint in sorted(endpoints):
                        print(f"  {endpoint}")
                else:
                    print(f"{Fore.YELLOW}No endpoints found{Style.RESET_ALL}")

            if args.save:
                try:
                    with open(args.save, 'w') as f:
                        for js_url, endpoints in js_files.items():
                            f.write(f"{js_url}\n")
                            if endpoints:
                                f.write("Endpoints:\n")
                                for endpoint in sorted(endpoints):
                                    f.write(f"  {endpoint}\n")
                            else:
                                f.write("No endpoints found\n")
                            f.write("\n")
                    print(f"\n{Fore.GREEN}Results saved to {args.save}{Style.RESET_ALL}")
                except IOError as e:
                    print(f"{Fore.RED}Error saving results to file: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No JavaScript files were successfully analyzed.{Style.RESET_ALL}")

    if __name__ == "__main__":
        asyncio.run(main()) 

if args.param_miner:
    def generate_random_string(length=10):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def detect_reflection(response, payload):
        return payload in response.text or payload in response.headers.values()

    def analyze_response_difference(original_response, modified_response):
        if abs(len(original_response.content) - len(modified_response.content)) > 50:
            return True
        return False

    def brute_force_parameter(url, param, original_response):
        try:
            payload = generate_random_string()
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            
            if detect_reflection(response, payload):
                print(f"{Fore.GREEN}[+] Reflected parameter found: {param}{Style.RESET_ALL}")
                return param, "reflected"
            
            if analyze_response_difference(original_response, response):
                print(f"{Fore.WHITE}[*] Potential parameter found (response changed): {Fore.YELLOW}{param}{Style.RESET_ALL}")
                return param, "potential"
            
            if response.status_code != original_response.status_code:
                print(f"{Fore.WHITE}[*] Status code changed for parameter: {Fore.CYAN}{param} {Fore.YELLOW}({original_response.status_code} -> {response.status_code}){Style.RESET_ALL}")
                return param, "status_changed"
            
        except requests.RequestException:
            pass
        return None, None

    def scan_common_parameters(url):
        common_params = ['id', 'page', 'search', 'q', 'query', 'file', 'filename', 'path', 'dir']
        found_params = []
        for param in common_params:
            result, _ = brute_force_parameter(url, param, requests.get(url, timeout=5))
            if result:
                found_params.append(result)
        return found_params

    def extract_parameters_from_html(url):
        try:
            response = requests.get(url, timeout=5)
            form_params = re.findall(r'name=["\']([^"\']+)["\']', response.text)
            js_params = re.findall(r'(?:get|post)\s*\(\s*["\'][^"\']*\?([^"\'&]+)=', response.text)
            return list(set(form_params + js_params))
        except requests.RequestException:
            return []

    def main(url, wordlist, threads):
        print(f"{Fore.BLUE}[*] Starting parameter mining on: {url}{Style.RESET_ALL}")
        
        original_response = requests.get(url, timeout=5)
        
        print(f"{Fore.MAGENTA}[*] Scanning for common parameters...{Style.RESET_ALL}")
        common_params = scan_common_parameters(url)
        
        print(f"{Fore.MAGENTA}[*] Extracting parameters from HTML and JavaScript...{Style.RESET_ALL}")
        extracted_params = extract_parameters_from_html(url)
        
        with open(wordlist, 'r') as file:
            wordlist_params = [line.strip() for line in file]
        all_params = list(set(wordlist_params + extracted_params + common_params))
        
        print(f"{Fore.BLUE}[*] Testing {len(all_params)} unique parameters...{Style.RESET_ALL}")
        
        reflected_params = []
        potential_params = []
        status_changed_params = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(brute_force_parameter, url, param, original_response) for param in all_params]
            for future in as_completed(futures):
                result, category = future.result()
                if result:
                    if category == "reflected":
                        reflected_params.append(result)
                    elif category == "potential":
                        potential_params.append(result)
                    elif category == "status_changed":
                        status_changed_params.append(result)
        
        print(f"\n{Fore.GREEN}[+] Reflected parameters: {', '.join(reflected_params)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}[*] Potential parameters: {Fore.YELLOW}{', '.join(potential_params)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}[*] Status-changing parameters: {Fore.CYAN}{', '.join(status_changed_params)}{Style.RESET_ALL}")

    if __name__ == "__main__":
        try:
            main(args.param_miner, args.wordlist, args.concurrency)
        except KeyboardInterrupt:
            print(f"{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        
if args.custom_headers:
    def print_headers(headers):
        print(f"{Fore.CYAN}Headers:{Style.RESET_ALL}")
        for key, value in headers.items():
            print(f"{Fore.GREEN}{key}: {Fore.YELLOW}{value}{Style.RESET_ALL}")

    def extract_links(content, base_url):
        soup = BeautifulSoup(content, 'html.parser')
        links = [urljoin(base_url, link.get('href')) for link in soup.find_all('a', href=True)]
        return links

    def send_request(url, method='GET', custom_headers=None, data=None, params=None, auth=None, proxies=None, allow_redirects=True, verbose=False):
        try:
            start_time = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=custom_headers,
                data=data,
                params=params,
                auth=auth,
                proxies=proxies,
                allow_redirects=allow_redirects,
                timeout=10
            )
            end_time = time.time()

            print(f"\n{Fore.MAGENTA}Status Code: {response.status_code}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Response Time: {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}Response Size: {len(response.content)} bytes{Style.RESET_ALL}")
            
            print("\n--- Request Details ---")
            print(f"{Fore.CYAN}Method: {method}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}URL: {url}{Style.RESET_ALL}")
            print_headers(response.request.headers)
            
            if data:
                print(f"\n{Fore.CYAN}Request Data:{Style.RESET_ALL}")
                print(json.dumps(data, indent=2))
            
            print("\n--- Response Details ---")
            print_headers(response.headers)
            
            if verbose:
                print(f"\n{Fore.CYAN}Response Content:{Style.RESET_ALL}")
                print(response.text)
            
            links = extract_links(response.text, url)
            print(f"\n{Fore.CYAN}Links found in the response:{Style.RESET_ALL}")
            for link in links:
                print(link)

            return response
        except requests.RequestException as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            return None

    def load_headers_from_file(filename):
        with open(filename, 'r') as f:
            return json.load(f)

    def main(initial_url, verbose):
        url = initial_url
        session = requests.Session()
        
        while True:
            print(f"\n{Fore.YELLOW}Current URL: {url}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
            print("1. Send GET request with default headers")
            print("2. Send GET request with custom headers")
            print("3. Send POST request")
            print("4. Send request with custom method and headers")
            print("5. Change URL")
            print("6. Load headers from file")
            print("7. Set authentication")
            print("8. Set proxy")
            print("9. Toggle redirect following")
            print("10. Save last response to file")
            print("11. Exit")
            
            choice = input(f"{Fore.CYAN}Enter your choice (1-11): {Style.RESET_ALL}")
            
            if choice == '1':
                send_request(url, verbose=verbose)
            elif choice == '2':
                custom_headers = {}
                print(f"{Fore.YELLOW}Enter custom headers (one per line, format 'Key: Value'). Type 'done' when finished.{Style.RESET_ALL}")
                while True:
                    header = input()
                    if header.lower() == 'done':
                        break
                    key, value = header.split(': ', 1)
                    custom_headers[key] = value
                send_request(url, custom_headers=custom_headers, verbose=verbose)
            elif choice == '3':
                data = input(f"{Fore.CYAN}Enter POST data (JSON format): {Style.RESET_ALL}")
                send_request(url, method='POST', data=json.loads(data), verbose=verbose)
            elif choice == '4':
                method = input(f"{Fore.CYAN}Enter HTTP method: {Style.RESET_ALL}").upper()
                custom_headers = {}
                print(f"{Fore.YELLOW}Enter custom headers (one per line, format 'Key: Value'). Type 'done' when finished.{Style.RESET_ALL}")
                while True:
                    header = input()
                    if header.lower() == 'done':
                        break
                    key, value = header.split(': ', 1)
                    custom_headers[key] = value
                send_request(url, method=method, custom_headers=custom_headers, verbose=verbose)
            elif choice == '5':
                url = input(f"{Fore.CYAN}Enter the new URL to check: {Style.RESET_ALL}")
            elif choice == '6':
                filename = input(f"{Fore.CYAN}Enter the filename to load headers from: {Style.RESET_ALL}")
                custom_headers = load_headers_from_file(filename)
                send_request(url, custom_headers=custom_headers, verbose=verbose)
            elif choice == '7':
                username = input(f"{Fore.CYAN}Enter username: {Style.RESET_ALL}")
                password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
                send_request(url, auth=(username, password), verbose=verbose)
            elif choice == '8':
                proxy = input(f"{Fore.CYAN}Enter proxy URL: {Style.RESET_ALL}")
                send_request(url, proxies={'http': proxy, 'https': proxy}, verbose=verbose)
            elif choice == '9':
                allow_redirects = input(f"{Fore.CYAN}Allow redirects? (y/n): {Style.RESET_ALL}").lower() == 'y'
                send_request(url, allow_redirects=allow_redirects, verbose=verbose)
            elif choice == '10':
                filename = input(f"{Fore.CYAN}Enter filename to save response: {Style.RESET_ALL}")
                response = send_request(url, verbose=verbose)
                if response:
                    with open(filename, 'w') as f:
                        json.dump(response.json(), f, indent=2)
                    print(f"{Fore.GREEN}Response saved to {filename}{Style.RESET_ALL}")
            elif choice == '11':
                print(f"{Fore.GREEN}Exiting. Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    if args.custom_headers:
        if args.verbose:
            print(f"{Fore.CYAN}Verbose mode enabled{Style.RESET_ALL}")
        main(args.custom_headers, args.verbose)


if args.openredirect:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    TEST_DOMAIN = "google.com"

    PAYLOADS = [
        f"//{TEST_DOMAIN}",
        f"//www.{TEST_DOMAIN}",
        f"https://{TEST_DOMAIN}",
        f"https://www.{TEST_DOMAIN}",
        f"//{TEST_DOMAIN}/%2f..",
        f"https://{TEST_DOMAIN}/%2f..",
        f"////{TEST_DOMAIN}",
        f"https:////{TEST_DOMAIN}",
        f"/\\/\\{TEST_DOMAIN}",
        f"/.{TEST_DOMAIN}",
        f"///\\;@{TEST_DOMAIN}",
        f"///{TEST_DOMAIN}@{TEST_DOMAIN}",
        f"///{TEST_DOMAIN}%40{TEST_DOMAIN}",
        f"////{TEST_DOMAIN}//",
        f"/https://{TEST_DOMAIN}",
        f"{TEST_DOMAIN}",
    ]

    def test_single_payload(url, payload, original_netloc):
        try:
            full_url = f"{url}{payload}"
            response = requests.get(full_url, allow_redirects=False, verify=False, timeout=5)
            if args.verbose:
                print(f"Testing: {full_url}")
                print(f"Status Code: {response.status_code}")
                print(f"Location: {response.headers.get('Location', 'N/A')}")
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    parsed_location = urllib.parse.urlparse(location)
                    # If 'location' is a relative URL, resolve it against the original URL
                    if not parsed_location.netloc:
                        location = urllib.parse.urljoin(full_url, location)
                        parsed_location = urllib.parse.urlparse(location)
                    # Now compare the netloc of the location with the original netloc
                    if parsed_location.netloc and parsed_location.netloc != original_netloc:
                        # Check if the TEST_DOMAIN is in the netloc
                        if TEST_DOMAIN in parsed_location.netloc:
                            print(f"{RED}VULNERABLE: Redirects to {location}{RESET}")
                            return (full_url, location)
            elif response.status_code == 403:
                print(f"{url}: {RED}FORBIDDEN{RESET}")
        except requests.RequestException as e:
            if args.verbose:
                print(f"Error testing {full_url}: {str(e)}")
        return None

    def test_open_redirect(url):
        vulnerable_urls = []
        parsed_original_url = urllib.parse.urlparse(url)
        original_netloc = parsed_original_url.netloc
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_payload = {
                executor.submit(test_single_payload, url, payload, original_netloc): payload
                for payload in PAYLOADS
            }
            for future in concurrent.futures.as_completed(future_to_payload):
                result = future.result()
                if result:
                    vulnerable_urls.append(result)
        return vulnerable_urls

    def process_url(url):
        print(f"{YELLOW}Testing: {url}{RESET}")
        vulnerabilities = test_open_redirect(url)
        if vulnerabilities:
            print(f"{RED}[VULNERABLE] {url}{RESET}")
            for vuln_url, redirect_url in vulnerabilities:
                print(f"  Payload URL: {vuln_url}")
                print(f"  Redirects to: {redirect_url}")
            print()
        else:
            print(f"{GREEN}[NOT VULNERABLE] {url}{RESET}\n")

    def main():
        if args.openredirect:
            process_url(args.openredirect)

    if __name__ == "__main__":
        main()


if args.automoussystemnumber:
    def get_ip_ranges(asn):
        asn = args.automoussystemnumber
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data and 'prefixes' in data['data']:
                return asn, [prefix['prefix'] for prefix in data['data']['prefixes']]
            else:
                return asn, []
        except requests.RequestException as e:
            print(f"Error fetching data for {asn}: {e}", file=sys.stderr)
            return asn, []

    def process_asn(asn):
        print(f"Fetching IP ranges for AS{asn}...")
        return get_ip_ranges(asn)

    def main():
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_asn = {executor.submit(process_asn, asn): asn for asn in args.automoussystemnumber}
            for future in concurrent.futures.as_completed(future_to_asn):
                asn, ip_ranges = future.result()
                results[asn] = ip_ranges

        total_ranges = sum(len(ranges) for ranges in results.values())
        print(f"\nFound a total of {total_ranges} IP ranges across {len(args.automoussystemnumber)} ASNs:")

        if args.save:
            with open(args.save, 'w') as f:
                for asn, ranges in results.items():
                    if ranges:
                        f.write(f"AS{asn}:\n")
                        for range in ranges:
                            f.write(f"{range}\n")
                        f.write("\n")
            print(f"Results saved to {args.save}")
        else:
            for asn, ranges in results.items():
                if ranges:
                    print(f"\nAS{asn}:")
                    for range in ranges:
                        print(range)
    if __name__ == "__main__":
        main()


if args.haveibeenpwned:
    print(f"{Fore.CYAN}HAVE I BEEN PWNED!{Style.RESET_ALL}\n")
    print(f"Checking password: {Fore.GREEN}{args.haveibeenpwned}{Style.RESET_ALL}\n")
    def check_password_pwned(password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url)
            response.raise_for_status()

            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    print(f"The password {Fore.GREEN}'{password}'{Fore.RESET} has been seen {Fore.RED}{count} times.{Fore.RESET}")
                    return

            print(f"The password {Fore.GREEN}'{password}'{Fore.RESET} has not been found in any breaches.")

        except requests.exceptions.HTTPError as err:
            print(f"Error checking password: {err}")
        except Exception as e:
            print(f"An error occurred: {e}")

    if __name__ == "__main__":
        password_to_check = args.haveibeenpwned
        check_password_pwned(password_to_check)

if args.subdomaintakeover:
    COMMON_SERVICES = [
        "GitHub, Inc.", "GitLab Inc.", "Bitbucket", "Heroku, Inc.",
        "Firebase", "Netlify, Inc.", "Surge", "Automattic Inc.",
        "Amazon CloudFront", "Microsoft Azure", "Google LLC"
    ]

    def check_subdomain(subdomain):
        potential_takeover = set()
        url = f"https://{subdomain}"
        try:
            response = requests.get(url)
            if response.status == 404:
                print(f"[Potential Takeover] {subdomain} - 404 Not Found")
                potential_takeover.add(subdomain)
                # Save potential takeovers to a file for further analysis
                with open('potential_takeover.txt', 'w') as f:
                    for sub in potential_takeover:
                        f.write(f"{sub}\n")
            elif response.status == 200:
                print(f"[Active] {subdomain} - 200 OK")
            else:
                print(f"[Other] {subdomain} - Status Code: {response.status}")
        except requests.RequestException:
            pass

    def check_dns(subdomain):
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                target = str(rdata.target).rstrip('.')
                print(f"{Fore.MAGENTA}[CNAME] {Fore.CYAN}{subdomain}{Style.RESET_ALL} points to {Fore.GREEN}{target}{Style.RESET_ALL}")
                check_whois(target)  # Check WHOIS for the CNAME target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # No CNAME record found
        except Exception as e:
            print(f"{Fore.RED}[DNS Error] {Fore.CYAN}{subdomain} - {Fore.RED}{e}{Style.RESET_ALL}")

    def check_whois(target):
        vuln_subs = set()
        try:
            w = whois.whois(target)
            org_name = w.org if w.org else "Unknown"
            print(f"{Fore.MAGENTA}[WHOIS] {Fore.CYAN}{target}{Style.RESET_ALL} - Organization: {Fore.GREEN}{org_name}{Style.RESET_ALL}")
            for service in COMMON_SERVICES:
                if service.lower() in org_name.lower():
                    vuln_subs.add(target)
                    print(f"{Fore.YELLOW}[Potential Takeover] {Fore.CYAN}{target} is associated with {Fore.GREEN}{org_name} - Common service{Style.RESET_ALL}")
                    break
            with open(f'{args.save}', 'w') as f:
                for sub in vuln_subs:
                    f.write(f"{sub}\n")
        except Exception as e:
            print(f"{Fore.RED}[WHOIS Error] {Fore.CYAN}{target} - {Fore.RED}{e}{Style.RESET_ALL}")

    def check_subdomain_takeover(subdomain):
        check_dns(subdomain)  
        check_subdomain(subdomain)  

    def load_subdomains(file_path):
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[Error] {Fore.CYAN}{file_path} - {Fore.RED}File not found{Style.RESET_ALL}")
            return []

    def main():
        subdomains = load_subdomains(args.subdomaintakeover)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            executor.map(check_subdomain_takeover, subdomains)

    if __name__ == "__main__":
        main()   



if args.auto_recon:
    init(autoreset=True)
    
    def run_autorecon(target, intensity='medium', max_time=3600, scan_profile=None):
        """
        Thực hiện tự động quét và nhận diện các dịch vụ, công nghệ và lỗ hổng trên mục tiêu
        """
        start_time = time.time()
        results = {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
                
        # Phase 4: Vulnerability Scanning (simple)
        if scan_profile in ['full', 'web'] or scan_profile is None:
            print(f"\n{Fore.GREEN}[+] Phase 4: Basic Vulnerability Scanning{Style.RESET_ALL}")
            
            # Check for HTTP vulnerabilities on web ports
            web_ports = [port for port in open_ports if port in [80, 443, 8080, 8443]]
            
            if web_ports:
                for port in web_ports:
                    protocol = "https" if port in [443, 8443] else "http"
                    url = f"{protocol}://{target_ip}:{port}"
                    print(f"{Fore.YELLOW}[*] Checking for common web vulnerabilities on {url}{Style.RESET_ALL}")
                    
                    # Check for directory listing
                    try:
                        common_dirs = ["images", "uploads", "backup", "admin", "assets", "config", "data", "logs"]
                        for directory in common_dirs:
                            dir_url = f"{url}/{directory}/"
                            response = requests.get(dir_url, timeout=timeout, verify=False)
                            if response.status_code == 200 and "Index of" in response.text:
                                vuln = {
                                    "type": "Directory Listing",
                                    "url": dir_url,
                                    "severity": "Medium",
                                    "description": f"Directory listing is enabled on {dir_url}"
                                }
                                results["vulnerabilities"].append(vuln)
                                print(f"{Fore.RED}[!] Directory listing enabled on {dir_url}{Style.RESET_ALL}")
                    except:
                        pass
                    
                    # Check for common misconfigurations
                    try:
                        check_files = [
                            "/robots.txt", 
                            "/.git/HEAD", 
                            "/.env", 
                            "/wp-config.php", 
                            "/config.php",
                            "/.htaccess",
                            "/server-status",
                            "/phpinfo.php"
                        ]
                        
                        for file in check_files:
                            file_url = f"{url}{file}"
                            response = requests.get(file_url, timeout=timeout, verify=False)
                            if response.status_code == 200:
                                content_preview = response.text[:100] if response.text else ""
                                vuln = {
                                    "type": "Sensitive File Exposure",
                                    "url": file_url,
                                    "severity": "High",
                                    "description": f"Sensitive file {file} is accessible",
                                    "content_preview": content_preview
                                }
                                results["vulnerabilities"].append(vuln)
                                print(f"{Fore.RED}[!] Sensitive file accessible: {file_url}{Style.RESET_ALL}")
                    except:
                        pass
                    
                    # Quét các lỗ hổng XSS và SQLi cơ bản nếu ở chế độ aggressive
                    if intensity == 'aggressive':
                        try:
                            response = requests.get(url, timeout=timeout, verify=False)
                            soup = BeautifulSoup(response.text, 'html.parser')
                            forms = soup.find_all('form')
                            
                            if forms:
                                print(f"{Fore.YELLOW}[*] Found {len(forms)} forms to test for vulnerabilities{Style.RESET_ALL}")
                                for i, form in enumerate(forms):
                                    print(f"{Fore.YELLOW}[*] Testing form #{i+1}{Style.RESET_ALL}")
                                    
                                    # Đơn giản chỉ báo cáo forms, cài đặt thực tế sẽ kiểm tra chi tiết hơn
                                    vuln = {
                                        "type": "Potential Form Vulnerability",
                                        "url": url,
                                        "severity": "Info",
                                        "description": f"Form found that may be vulnerable to XSS/SQLi",
                                        "form_action": form.get('action', '')
                                    }
                                    results["vulnerabilities"].append(vuln)
                        except:
                            pass
            
            # Check SSH version if available
            if 22 in open_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((target_ip, 22))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                    
                    # Kiểm tra SSH version
                    if "SSH-1" in banner:
                        vuln = {
                            "type": "Outdated SSH Version",
                            "port": 22,
                            "severity": "High",
                            "description": "Server is running SSH version 1 which has known vulnerabilities",
                            "banner": banner
                        }
                        results["vulnerabilities"].append(vuln)
                        print(f"{Fore.RED}[!] Outdated SSH version detected: {banner}{Style.RESET_ALL}")
                except:
                    pass
                    
        # Phase 5: ICS/SCADA Scanning nếu được chỉ định trong profile
        if scan_profile == 'full' or 'ics' in scan_profile or target_ip.startswith('192.168.') or target_ip.startswith('10.'):
            print(f"\n{Fore.GREEN}[+] Phase 5: Checking for ICS/SCADA components{Style.RESET_ALL}")
            
            # Kiểm tra các cổng ICS/SCADA phổ biến
            ics_ports = {
                502: "Modbus TCP",
                102: "Siemens S7",
                20000: "DNP3",
                47808: "BACnet",
                44818: "EtherNet/IP",
                18245: "GE SRTP",
                1911: "Niagara Fox Protocol",
                2404: "IEC 60870-5-104",
                4840: "OPC UA"
            }
            
            # Chỉ kiểm tra các cổng ICS/SCADA chưa được thấy trong open_ports
            for port, service in ics_ports.items():
                if port not in open_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)  # Timeout ngắn hơn cho quét ICS
                        result = sock.connect_ex((target_ip, port))
                        sock.close()
                        
                        if result == 0:
                            results["open_ports"].append({"port": port, "service": service})
                            results["services"][port] = {"name": service, "version": "unknown"}
                            print(f"{Fore.RED}[!] ICS/SCADA service detected: {service} on port {port}{Style.RESET_ALL}")
                    except:
                        pass
        
        # Lưu kết quả nếu được yêu cầu
        if args.save_autorecon and results_dir:
            results_file = os.path.join(results_dir, f"autorecon_{target.replace('.', '_')}.json")
            with open(results_file, "w") as f:
                json.dump(results, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Results saved to {results_file}{Style.RESET_ALL}")
            
            # Tạo báo cáo HTML
            html_report = os.path.join(results_dir, f"autorecon_{target.replace('.', '_')}.html")
            with open(html_report, "w") as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>AutoRecon Report for {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .section {{ margin-bottom: 30px; background: #f5f7fa; padding: 15px; border-radius: 5px; }}
        .danger {{ color: #e74c3c; }}
        .warning {{ color: #f39c12; }}
        .success {{ color: #27ae60; }}
        .info {{ color: #2980b9; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AutoRecon Report for {target}</h1>
        <p>Scan performed on {results['scan_time']}</p>
        
        <div class="section">
            <h2>Basic Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Target</td><td>{target}</td></tr>
                <tr><td>IP Address</td><td>{results.get('ip_address', 'Unknown')}</td></tr>
                <tr><td>Hostname</td><td>{results.get('hostname', 'Unknown')}</td></tr>
            </table>
        </div>
""")

                # WHOIS section
                if "whois" in results:
                    f.write(f"""
        <div class="section">
            <h2>WHOIS Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Registrar</td><td>{results['whois'].get('registrar', 'Unknown')}</td></tr>
                <tr><td>Creation Date</td><td>{results['whois'].get('creation_date', 'Unknown')}</td></tr>
                <tr><td>Expiration Date</td><td>{results['whois'].get('expiration_date', 'Unknown')}</td></tr>
                <tr><td>Name Servers</td><td>{', '.join(results['whois'].get('name_servers', ['Unknown']))}</td></tr>
            </table>
        </div>
""")

                # DNS section
                if "dns_records" in results:
                    f.write(f"""
        <div class="section">
            <h2>DNS Records</h2>
            <table>
                <tr><th>Record Type</th><th>Value</th></tr>
""")
                    for record_type, values in results["dns_records"].items():
                        f.write(f"<tr><td>{record_type}</td><td>{', '.join(values)}</td></tr>")
                    f.write("""
            </table>
        </div>
""")

                # Open Ports section
                f.write(f"""
        <div class="section">
            <h2>Open Ports</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Version</th></tr>
""")
                for port_info in results["open_ports"]:
                    port = port_info["port"]
                    service = port_info["service"]
                    version = results["services"][port].get("version", "Unknown")
                    f.write(f"<tr><td>{port}</td><td>{service}</td><td>{version}</td></tr>")
                f.write("""
            </table>
        </div>
""")

                # Technologies section
                if results["technologies"]:
                    f.write(f"""
        <div class="section">
            <h2>Detected Technologies</h2>
            <ul>
""")
                    for tech in set(results["technologies"]):
                        f.write(f"<li>{tech}</li>")
                    f.write("""
            </ul>
        </div>
""")

                # Vulnerabilities section
                if results["vulnerabilities"]:
                    f.write(f"""
        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <tr><th>Type</th><th>Severity</th><th>Description</th><th>Location</th></tr>
""")
                    for vuln in results["vulnerabilities"]:
                        severity_class = "info"
                        if vuln["severity"] == "High":
                            severity_class = "danger"
                        elif vuln["severity"] == "Medium":
                            severity_class = "warning"
                        
                        location = vuln.get("url", vuln.get("port", "N/A"))
                        f.write(f"<tr><td>{vuln['type']}</td><td class='{severity_class}'>{vuln['severity']}</td><td>{vuln['description']}</td><td>{location}</td></tr>")
                    f.write("""
            </table>
        </div>
""")

                f.write("""
    </div>
</body>
</html>
""")
            print(f"{Fore.GREEN}[+] HTML report saved to {html_report}{Style.RESET_ALL}")
        
        # Tính thời gian quét
        elapsed_time = time.time() - start_time
        results["elapsed_time"] = elapsed_time
        print(f"\n{Fore.GREEN}[+] AutoRecon completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
        
        return results
    
    # Chạy autorecon với các đối số được cung cấp
    target = args.auto_recon
    intensity = args.intensity
    max_time = args.max_time
    scan_profile = args.scan_profile
    
    run_autorecon(target, intensity, max_time, scan_profile)

if args.jwt_scan:
    analyzer = JWTAnalyzer()
    analyzer.analyze_token(args.jwt_scan)
elif args.jwt_modify:
    analyzer = JWTAnalyzer()
    analyzer.modify_token(args.jwt_modify)

async def handle_s3_scan(target):
    print(f"\n{Fore.MAGENTA}Starting S3 bucket scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
    scanner = S3Scanner()
    with alive_bar(1, title='Scanning S3 buckets') as bar:
        results = await scanner.scan(target)
        scanner.save_results(target)
        bar()
    return results

if args.s3_scan:
    asyncio.run(handle_s3_scan(args.s3_scan))

if args.heapdump:
    analyzer = HeapdumpAnalyzer()
    analyzer.analyze(args.heapdump, args.output_dir)

if args.heapdump_file:
    commands(f"python3 modules/heapdump_scan.py --file {args.heapdump_file}")

if args.heapdump_target:
    commands(f"python3 modules/heapdump_scan.py --url {args.heapdump_target} --timeout 10")

if args.aws_scan:
    init(autoreset=True)
    
    def check_aws_services(domain):
        aws_endpoints = {
            'S3': [f'http://{domain}.s3.amazonaws.com', f'https://{domain}.s3.amazonaws.com'],
            'CloudFront': [f'https://{domain}.cloudfront.net'],
            'ELB': [f'{domain}.elb.amazonaws.com', f'{domain}.elb.us-east-1.amazonaws.com'],
            'API Gateway': [f'https://{domain}.execute-api.us-east-1.amazonaws.com'],
            'Lambda': [f'https://{domain}.lambda-url.us-east-1.amazonaws.com'],
            'ECR': [f'https://{domain}.dkr.ecr.us-east-1.amazonaws.com'],
            'ECS': [f'https://{domain}.ecs.us-east-1.amazonaws.com'],
        }
        
        findings = []
        with alive_bar(len(aws_endpoints), title='Scanning AWS Services') as bar:
            for service, urls in aws_endpoints.items():
                for url in urls:
                    try:
                        response = requests.get(url, timeout=10, verify=False)
                        if response.status_code != 404:
                            findings.append({
                                'service': service,
                                'url': url,
                                'status': response.status_code,
                                'headers': dict(response.headers)
                            })
                    except requests.RequestException:
                        pass
                bar()
        return findings

    def check_iam_exposure(domain):
        iam_endpoints = [
            f'https://iam.{domain}',
            f'https://sts.{domain}',
            f'https://signin.{domain}'
        ]
        findings = []
        
        print(f"\n{Fore.CYAN}Checking for exposed IAM endpoints...{Style.RESET_ALL}")
        for endpoint in iam_endpoints:
            try:
                response = requests.get(endpoint, timeout=5, verify=False)
                if response.status_code != 404:
                    findings.append({
                        'endpoint': endpoint,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        return findings

    target = args.aws_scan
    print(f"\n{Fore.MAGENTA}Starting AWS Security Scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
    
    # Scan AWS services
    aws_findings = check_aws_services(target)
    if aws_findings:
        print(f"\n{Fore.RED}Found exposed AWS services:{Style.RESET_ALL}")
        for finding in aws_findings:
            print(f"\nService: {Fore.YELLOW}{finding['service']}{Style.RESET_ALL}")
            print(f"URL: {Fore.CYAN}{finding['url']}{Style.RESET_ALL}")
            print(f"Status: {finding['status']}")
            
    # Check IAM exposure
    iam_findings = check_iam_exposure(target)
    if iam_findings:
        print(f"\n{Fore.RED}Found exposed IAM endpoints:{Style.RESET_ALL}")
        for finding in iam_findings:
            print(f"Endpoint: {Fore.CYAN}{finding['endpoint']}{Style.RESET_ALL}")
            print(f"Status: {finding['status']}")
            
    # Save results
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f'aws_scan_{timestamp}.json', 'w') as f:
        json.dump({
            'aws_services': aws_findings,
            'iam_endpoints': iam_findings
        }, f, indent=4)
    print(f"\n{Fore.GREEN}Results saved to aws_scan_{timestamp}.json{Style.RESET_ALL}")

if args.azure_scan:
    init(autoreset=True)
    
    def check_azure_services(domain):
        azure_endpoints = {
            'Storage': [f'https://{domain}.blob.core.windows.net',
                       f'https://{domain}.file.core.windows.net',
                       f'https://{domain}.queue.core.windows.net'],
            'WebApps': [f'https://{domain}.azurewebsites.net'],
            'Functions': [f'https://{domain}.azurewebsites.net/api'],
            'KeyVault': [f'https://{domain}.vault.azure.net'],
            'Database': [f'https://{domain}.database.windows.net'],
            'ServiceBus': [f'https://{domain}.servicebus.windows.net']
        }
        
        findings = []
        with alive_bar(len(azure_endpoints), title='Scanning Azure Services') as bar:
            for service, urls in azure_endpoints.items():
                for url in urls:
                    try:
                        response = requests.get(url, timeout=10, verify=False)
                        if response.status_code != 404:
                            findings.append({
                                'service': service,
                                'url': url,
                                'status': response.status_code,
                                'headers': dict(response.headers)
                            })
                    except requests.RequestException:
                        pass
                bar()
        return findings

    def check_management_endpoints(domain):
        mgmt_endpoints = [
            f'https://management.{domain}',
            f'https://portal.{domain}',
            f'https://scm.{domain}'
        ]
        findings = []
        
        print(f"\n{Fore.CYAN}Checking for exposed management endpoints...{Style.RESET_ALL}")
        for endpoint in mgmt_endpoints:
            try:
                response = requests.get(endpoint, timeout=5, verify=False)
                if response.status_code != 404:
                    findings.append({
                        'endpoint': endpoint,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        return findings

    target = args.azure_scan
    print(f"\n{Fore.MAGENTA}Starting Azure Security Scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
    
    # Scan Azure services
    azure_findings = check_azure_services(target)
    if azure_findings:
        print(f"\n{Fore.RED}Found exposed Azure services:{Style.RESET_ALL}")
        for finding in azure_findings:
            print(f"\nService: {Fore.YELLOW}{finding['service']}{Style.RESET_ALL}")
            print(f"URL: {Fore.CYAN}{finding['url']}{Style.RESET_ALL}")
            print(f"Status: {finding['status']}")
            
    # Check management endpoints
    mgmt_findings = check_management_endpoints(target)
    if mgmt_findings:
        print(f"\n{Fore.RED}Found exposed management endpoints:{Style.RESET_ALL}")
        for finding in mgmt_findings:
            print(f"Endpoint: {Fore.CYAN}{finding['endpoint']}{Style.RESET_ALL}")
            print(f"Status: {finding['status']}")
            
    # Save results
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f'azure_scan_{timestamp}.json', 'w') as f:
        json.dump({
            'azure_services': azure_findings,
            'management_endpoints': mgmt_findings
        }, f, indent=4)
    print(f"\n{Fore.GREEN}Results saved to azure_scan_{timestamp}.json{Style.RESET_ALL}")

# Add implementation
if args.zone_transfer:
    print(f"{Fore.MAGENTA}Testing DNS Zone Transfer for {Fore.CYAN}{args.zone_transfer}{Style.RESET_ALL}\n")
    
    def get_nameservers(domain):
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception as e:
            print(f"{Fore.RED}Error getting nameservers: {e}{Style.RESET_ALL}")
            return []

    def test_zone_transfer(domain, nameserver):
        try:
            # Attempt zone transfer
            z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            names = z.nodes.keys()
            records = []
            
            # Get all records
            for n in names:
                record = z[n].to_text(n)
                records.append(record)
                print(f"{Fore.GREEN}[+] {Fore.CYAN}{record}{Style.RESET_ALL}")
            
            # Save results if vulnerable
            if records:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                with open(f'zone_transfer_{domain}_{timestamp}.txt', 'w') as f:
                    f.write(f"DNS Zone Transfer Results for {domain}\n")
                    f.write(f"Nameserver: {nameserver}\n\n")
                    for record in records:
                        f.write(f"{record}\n")
                print(f"\n{Fore.RED}[!] Zone Transfer VULNERABLE!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Results saved to zone_transfer_{domain}_{timestamp}.txt{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Zone transfer failed for {nameserver}: {e}{Style.RESET_ALL}")

    domain = args.zone_transfer
    nameservers = get_nameservers(domain)
    
    if nameservers:
        print(f"{Fore.MAGENTA}Found nameservers:{Style.RESET_ALL}")
        for ns in nameservers:
            print(f"{Fore.CYAN}[*] {ns}{Style.RESET_ALL}")
        
        print(f"\n{Fore.MAGENTA}Testing zone transfer on each nameserver...{Style.RESET_ALL}\n")
        for ns in nameservers:
            print(f"{Fore.CYAN}Testing {ns}...{Style.RESET_ALL}")
            test_zone_transfer(domain, ns)
    else:
        print(f"{Fore.RED}No nameservers found for {domain}{Style.RESET_ALL}")

if args.ipinfo:
    if not args.token:
        print(f"{Fore.RED}Error: IPinfo API token required. Use --token to provide it.{Style.RESET_ALL}")
        sys.exit(1)
    scan_ip_info(args.ipinfo, args.token)

async def handle_gcp_scan(target):
    """
    Scan for exposed Google Cloud Platform storage buckets and resources
    
    Args:
        target: Domain or organization name to scan
    """
    try:
        # Clean up the target to extract just the domain
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            target = parsed_url.netloc
        target = target.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Scanning for exposed GCP Storage resources for {target}{Style.RESET_ALL}")
        
        # Common GCP bucket naming patterns
        bucket_patterns = [
            f"{target}",
            f"{target}-storage",
            f"{target}-bucket",
            f"{target}-data",
            f"{target}-assets",
            f"{target}-media",
            f"{target}-backup",
            f"{target}-archive",
            f"{target}-files",
            f"{target}-public",
            f"{target}-private",
            f"{target}-dev",
            f"{target}-prod",
            f"{target}-stage",
            f"{target}-staging",
            f"{target}-test",
            f"{target}-uat",
            f"{target}-content",
            f"{target}-static",
            f"{target}-images",
            f"{target}-docs",
            f"{target}-documents",
            f"{target}-logs",
            f"{target.replace('.', '-')}",
            f"{target.split('.')[0]}"
        ]
        
        # Add variations with company name
        company_name = target.split('.')[0]
        bucket_patterns.extend([
            f"gcp-{company_name}",
            f"storage-{company_name}",
            f"bucket-{company_name}",
            f"{company_name}-gcp"
        ])
        
        found_buckets = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for pattern in bucket_patterns:
                futures.append(executor.submit(check_gcp_bucket, pattern))
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Checking GCP buckets"):
                result = future.result()
                if result:
                    found_buckets.append(result)
        
        if found_buckets:
            print(f"{Fore.GREEN}[+] Found {len(found_buckets)} potentially exposed GCP Storage buckets:{Style.RESET_ALL}")
            for bucket in found_buckets:
                print(f"  - {bucket}")
        else:
            print(f"{Fore.YELLOW}[!] No exposed GCP Storage buckets found{Style.RESET_ALL}")
        
        # Check for other GCP services
        await check_gcp_services(target)
    except Exception as e:
        print(f"{Fore.RED}[!] Error during GCP scan: {str(e)}{Style.RESET_ALL}")

def check_gcp_bucket(bucket_name):
    """
    Check if a GCP Storage bucket exists and is publicly accessible
    
    Args:
        bucket_name: Name of the bucket to check
        
    Returns:
        Bucket URL if found and accessible, None otherwise
    """
    try:
        bucket_url = f"https://storage.googleapis.com/{bucket_name}/"
        
        response = requests.get(bucket_url, timeout=10)
        
        # Check if bucket exists
        if response.status_code == 200:
            # Check if we can list bucket contents
            if "ListBucketResult" in response.text:
                print(f"{Fore.RED}[!] Found publicly accessible GCP bucket: {bucket_url}{Style.RESET_ALL}")
                return bucket_url
            else:
                print(f"{Fore.YELLOW}[!] Found GCP bucket but cannot list contents: {bucket_url}{Style.RESET_ALL}")
                return bucket_url
        
        # Check for access denied (bucket exists but is not public)
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}[!] Found GCP bucket but access is denied: {bucket_url}{Style.RESET_ALL}")
            return None
            
    except requests.exceptions.RequestException:
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP bucket {bucket_name}: {str(e)}{Style.RESET_ALL}")
        return None
    
    return None

async def check_gcp_services(domain):
    """
    Check for exposed GCP services related to the domain
    
    Args:
        domain: Domain to check
    """
    try:
        # Clean up the domain to extract just the domain name
        if domain.startswith(('http://', 'https://')):
            parsed_url = urlparse(domain)
            domain = parsed_url.netloc
        domain = domain.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Checking for exposed GCP services for {domain}{Style.RESET_ALL}")
        
        # Common GCP service endpoints to check
        gcp_services = [
            {"name": "Cloud Run", "url_pattern": f"https://{domain.split('.')[0]}-[a-z0-9]{{16}}.run.app", "regex": True},
            {"name": "App Engine", "url_pattern": f"https://{domain.split('.')[0]}.appspot.com", "regex": False},
            {"name": "Firebase", "url_pattern": f"https://{domain.split('.')[0]}.firebaseapp.com", "regex": False},
            {"name": "Cloud Functions", "url_pattern": f"https://{domain.split('.')[0]}.cloudfunctions.net", "regex": False},
            {"name": "GCP Load Balancer", "url_pattern": f"https://{domain}", "header": "Via", "value": "google"}
        ]
        
        for service in gcp_services:
            if service.get("regex", False):
                # For regex patterns, we need to do DNS enumeration or other techniques
                # This is a simplified placeholder
                print(f"{Fore.YELLOW}[!] Regex-based detection for {service['name']} requires additional enumeration{Style.RESET_ALL}")
                continue
            
            try:
                url = service["url_pattern"]
                response = requests.get(url, timeout=10)
                
                if service.get("header"):
                    # Check for specific header
                    if service["header"] in response.headers and service["value"].lower() in response.headers[service["header"]].lower():
                        print(f"{Fore.GREEN}[+] Found {service['name']}: {url}{Style.RESET_ALL}")
                        continue
                
                # Check based on status code
                if response.status_code < 400:
                    print(f"{Fore.GREEN}[+] Found {service['name']}: {url}{Style.RESET_ALL}")
                
            except requests.exceptions.RequestException:
                # Service endpoint not found or not accessible
                pass
            except Exception as e:
                print(f"{Fore.RED}[!] Error checking {service['name']}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP services: {str(e)}{Style.RESET_ALL}")

def check_gcp_exposure(domain):
    """
    Check for GCP resource exposure for a domain
    
    Args:
        domain: Domain to check
    """
    try:
        # Clean up the domain to extract just the domain name
        if domain.startswith(('http://', 'https://')):
            parsed_url = urlparse(domain)
            domain = parsed_url.netloc
        domain = domain.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Checking for GCP resource exposure for {domain}{Style.RESET_ALL}")
        
        # Check for common GCP project naming patterns
        project_patterns = [
            f"{domain.split('.')[0]}-project",
            f"{domain.split('.')[0]}-prod",
            f"{domain.split('.')[0]}-dev",
            f"{domain.split('.')[0]}-test",
            f"{domain.split('.')[0]}-staging",
            domain.split('.')[0]
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for pattern in project_patterns:
                futures.append(executor.submit(check_gcp_project, pattern))
            
            for future in tqdm(concurrent.futures.as_completed(futures), 
                             total=len(futures), 
                             desc="Checking GCP projects"):
                try:
                    future.result(timeout=15)  # 15 second timeout per project check
                except concurrent.futures.TimeoutError:
                    print(f"{Fore.YELLOW}[!] Timeout while checking a GCP project{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error checking GCP project: {str(e)}{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP resource exposure: {str(e)}{Style.RESET_ALL}")

def check_gcp_project(pattern):
    """
    Check a single GCP project pattern
    
    Args:
        pattern: Project pattern to check
    """
    try:
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{pattern}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            print(f"{Fore.RED}[!] Found publicly accessible GCP project: {pattern}{Style.RESET_ALL}")
            try:
                project_data = response.json()
                print(f"  - Project Number: {project_data.get('projectNumber', 'N/A')}")
                print(f"  - Project ID: {project_data.get('projectId', 'N/A')}")
                print(f"  - Name: {project_data.get('name', 'N/A')}")
                print(f"  - Labels: {project_data.get('labels', {})}")
            except ValueError:
                print(f"  - Unable to parse project data")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}[!] Found GCP project but access is denied: {pattern}{Style.RESET_ALL}")
            
    except requests.exceptions.Timeout:
        print(f"{Fore.YELLOW}[!] Timeout while checking project: {pattern}{Style.RESET_ALL}")
    except requests.exceptions.RequestException:
        pass  # Silently ignore connection errors for non-existent projects
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking project {pattern}: {str(e)}{Style.RESET_ALL}")

    
if args.gcp_scan:
    asyncio.run(handle_gcp_scan(args.gcp_scan))
    check_gcp_exposure(args.gcp_scan)


# Bruteforcing username and password input fields

def test_proxy(proxy, test_url="https://www.google.com", timeout=3):
    """Test if a proxy works with both HTTP and HTTPS - optimized for speed"""
    try:
        # Reduce timeout for faster testing
        if proxy.startswith('http'):
            proxies = {'http': proxy, 'https': proxy}
        else:
            proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
            
        # Use HEAD request instead of GET for faster response
        response = requests.head(
            test_url, 
            proxies=proxies, 
            timeout=timeout,
            # Don't verify SSL to speed up connection
            verify=False,
            # Don't follow redirects to save time
            allow_redirects=False
        )
        
        # Accept any 2xx, 3xx status code as success
        if 200 <= response.status_code < 400:
            return True
    except Exception:
        # If that fails, try with explicit HTTP for HTTPS
        try:
            if not proxy.startswith('http'):
                proxy = f'http://{proxy}'
            proxies = {'http': proxy, 'https': proxy}
            
            # Use HEAD request for speed
            response = requests.head(
                test_url, 
                proxies=proxies, 
                timeout=timeout,
                verify=False,
                allow_redirects=False
            )
            
            if 200 <= response.status_code < 400:
                return True
        except Exception:
            pass
    return False

def load_proxies(proxy_file=None, test=True, max_workers=50):
    """Load proxies from a file and optionally test them in parallel"""
    if not proxy_file or not os.path.exists(proxy_file):
        return []
    with open(proxy_file, 'r') as f:
        proxies = [x.strip() for x in f.readlines() if x.strip()]
    
    print(f"{Fore.WHITE}[*] Loaded {Fore.MAGENTA}{len(proxies)} proxies from file{Style.RESET_ALL}")
    
    if test:
        print(f"{Fore.WHITE}[*] Testing proxies with {max_workers} concurrent workers...{Style.RESET_ALL}")
        working_proxies = []
        completed = 0
        print_lock = threading.Lock()
        
        # Try to import tqdm for progress bar
        try:
            from tqdm import tqdm
            progress_bar = tqdm(total=len(proxies), desc="Testing proxies", 
                               unit="proxy", ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
            has_tqdm = True
        except ImportError:
            progress_bar = None
            has_tqdm = False
        
        def test_proxy_task(proxy):
            nonlocal completed
            result = test_proxy(proxy)
            
            with print_lock:
                completed += 1
                if has_tqdm:
                    progress_bar.update(1)
                else:
                    if completed % 10 == 0 or completed == len(proxies):
                        print(f"{Fore.WHITE}[*] Tested {completed}/{len(proxies)} proxies ({(completed/len(proxies))*100:.1f}%){Style.RESET_ALL}", end='\r')
                
                if result:
                    working_proxies.append(proxy)
                    if not has_tqdm:
                        print(f"\n{Fore.GREEN}[+] Working proxy: {proxy}{Style.RESET_ALL}")
            
            return result
        
        # Use ThreadPoolExecutor for parallel testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(test_proxy_task, proxy): proxy for proxy in proxies}
            
            # Wait for all futures to complete
            concurrent.futures.wait(futures)
        
        if has_tqdm:
            progress_bar.close()
        
        print(f"\n{Fore.WHITE}[*] Found {Fore.MAGENTA}{len(working_proxies)}/{len(proxies)} working proxies{Style.RESET_ALL}")
        return working_proxies
    
    return proxies

def get_random_user_agent():
    """Generate a random user agent"""
    try:
        ua = UserAgent()
        return ua.random
    except:
        # Fallback user agents if fake_useragent fails
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
        ]
        return random.choice(user_agents)

def password_wordlist(file: str) -> list:
    with open(file, 'r') as f:
        passwords = [x.strip() for x in f.readlines()]
    return passwords

def username_wordlist(file: str) -> list:
    with open(file, 'r') as f:
        usernames = [x.strip() for x in f.readlines()]
    return usernames

def randomize_cookies(base_cookies=None):
    """Generate randomized cookies"""
    # Start with required cookies or empty dict
    cookies = base_cookies.copy() if base_cookies else {}
    
    # Add random tracking-like cookies
    random_cookies = {
        f"_ga_{random.randint(1000, 9999)}": f"{uuid.uuid4()}",
        f"visitor_id{random.randint(100, 999)}": f"{random.randint(10000, 999999)}",
        "session_depth": str(random.randint(1, 5)),
        "last_visit": str(int(time.time()) - random.randint(3600, 86400))
    }
    
    # Randomly select some of these cookies
    for k, v in random_cookies.items():
        if random.random() > 0.6:  # 40% chance to include each cookie
            cookies[k] = v
            
    return cookies


def detect_2fa(response_text, response_url):
    """
    Detect if the response indicates a 2FA challenge
    Returns True if 2FA is detected, False otherwise
    """
    # Convert to lowercase for case-insensitive matching
    text_lower = response_text.lower()
    url_lower = response_url.lower()
    
    # Common 2FA indicators in response text
    text_indicators = [
        'two-factor', 'two factor', '2fa', 'second factor', 
        'verification code', 'security code', 'authenticator app',
        'authentication code', 'one-time password', 'otp', 
        'sms code', 'text message code', 'enter code',
        'google authenticator', 'authy', 'duo', 'yubikey',
        'multi-factor', 'mfa', 'additional verification',
        'confirm your identity', 'additional security',
        'security key', 'authentication token', 'Two-factor authentication',
        'Authentication code'
    ]
    
    # Common 2FA indicators in URL
    url_indicators = [
        '2fa', 'two-factor', 'twofactor', 'mfa', 'otp', 
        'verification', 'verify', 'authenticator', 'security-code',
        'second-step', 'second_step', 'challenge', 'sms'
    ]
    
    # Check for 2FA indicators in response text
    for indicator in text_indicators:
        if indicator in text_lower:
            return True
    
    # Check for 2FA indicators in URL
    for indicator in url_indicators:
        if indicator in url_lower:
            return True
    
    # Check for input fields that might indicate 2FA
    soup = BeautifulSoup(response_text, 'html.parser')
    
    # Look for verification code input fields
    code_inputs = soup.find_all('input', {
        'type': ['text', 'number', 'tel'],
        'name': lambda x: x and any(term in x.lower() for term in [
            'code', 'token', 'otp', 'verification', 'auth', 'factor'
        ])
    })
    
    if code_inputs:
        return True
    
    # Look for 2FA-related form labels or text
    labels = soup.find_all(['label', 'div', 'p', 'h1', 'h2', 'h3', 'h4', 'span'])
    for label in labels:
        if label.text and any(term in label.text.lower() for term in text_indicators):
            return True
    
    return False

def try_login_task(username, password, url, form_data, initial_url, success_indicators, verbose, proxy=None, user_agent=None, username_field=None, password_field=None):
    """Helper function for threaded login attempts with proxy and user agent support"""
    try:
        # Set up headers with random user agent
        headers = {'User-Agent': user_agent or get_random_user_agent()}
        
        # Set up proxy if provided
        proxies = None
        if proxy:
            if proxy.startswith('http'):
                proxies = {'http': proxy, 'https': proxy}
            else:
                proxies = {'http': f'http://{proxy}', 'https': f'https://{proxy}'}
        
        # Add a small random delay to further avoid detection
        time.sleep(random.uniform(0.1, 0.5))

        # Add random cookies technique, Makes requests appear to come from real browsers with history
        cookies = randomize_cookies()
        session = requests.Session()
        session.cookies.update(cookies)
        
        # Make the request with proxy and custom headers
        response = session.post(
            url, 
            data=form_data, 
            headers=headers,
            proxies=proxies,
            allow_redirects=True,
            cookies=cookies,
            timeout=10  # Increased timeout for proxy connections
        )
        
        response_text_lower = response.text.lower()

        print_lock = threading.Lock()
        # Check for 2FA before proceeding
        if detect_2fa(response.text, response.url):
            # Use print_lock to avoid garbled output in multithreaded context
            with print_lock:
                print(f"\n{Fore.YELLOW}[!] 2FA/MFA detected after login attempt with username: {Fore.MAGENTA}{username}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Password may be correct, but 2FA is preventing access{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Bruteforcing halted as 2FA cannot be automatically bypassed{Style.RESET_ALL}")
                
                # If verbose, provide more details
                if verbose:
                    print(f"{Fore.WHITE}[*] Response URL: {Fore.GREEN}{response.url}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}[*] Potential valid credentials: {Fore.MAGENTA}{username} : {password}{Style.RESET_ALL}")
                
                # Return a special value to indicate 2FA was detected
                return ("2FA_DETECTED", username, password, response.url)
        
        # Quick check for obvious failures
        if any(neg in response_text_lower for neg in success_indicators['negative']):
            return None
            
        success = False
        
        # Check 1: URL change
        if response.url != initial_url:
            if any(indicator in response.url.lower() for indicator in success_indicators['url_change']):
                success = True
        
        # Check 2: Content check
        if any(indicator in response_text_lower for indicator in success_indicators['content']):
            success = True
            
        # Check 3: Redirect check
        if response.history and response.url != url and 'login' not in response.url.lower():
            success = True
            
        if success:
            return (username, password, response.url)
    
    except requests.exceptions.ProxyError as e:
        if verbose:
            # If it's an HTTP/HTTPS mismatch, provide more specific information
            if "Your proxy appears to only use HTTP and not HTTPS" in str(e):
               pass
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}[!] Request error with proxy {proxy}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.YELLOW}[!] Error: {str(e)}{Style.RESET_ALL}")
    return None

def bruteforce_login(url, username_file, password_file, proxy_file=None, verbose=False):
    try:
        # Validate input files first
        if not username_file or not password_file:
            print(f"{Fore.RED}[!] Both username and password wordlists are required{Style.RESET_ALL}")
            return
            
        if not os.path.exists(username_file):
            print(f"{Fore.RED}[!] Username wordlist not found: {username_file}{Style.RESET_ALL}")
            return
            
        if not os.path.exists(password_file):
            print(f"{Fore.RED}[!] Password wordlist not found: {password_file}{Style.RESET_ALL}")
            return

        # Parse the target URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        print(f"{Fore.WHITE}[*] Testing login form at {Fore.GREEN}{url}{Style.RESET_ALL}")
        
        # Check if the target URL is accessible
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            if verbose:
                print(f"{Fore.WHITE}[*] Successfully connected to target URL{Style.RESET_ALL}")
                print(f"{Fore.WHITE}[*] Response status code: {Fore.GREEN}{response.status_code}{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Could not access {url}: {str(e)}{Style.RESET_ALL}")
            return
        
        # Check if the target URL has a login form
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        if not form:
            print(f"{Fore.YELLOW}[!] No login form found on {url}{Style.RESET_ALL}")
            return
        
        if verbose:
            print(f"{Fore.WHITE}[*] Found login form with action: {Fore.MAGENTA}{form.get('action', 'default')}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Form method: {Fore.MAGENTA}{form.get('method', 'POST')}{Style.RESET_ALL}")
        
        # Find all input fields in the login form
        input_fields = form.find_all('input')
        if not input_fields:
            print(f"{Fore.YELLOW}[!] No input fields found in form on {url}{Style.RESET_ALL}")
            return
        
        # Create a dictionary of input field names and values
        input_data = {}
        for field in input_fields:
            name = field.get('name')
            if name:
                input_data[name] = field.get('value', '')
                if verbose:
                    print(f"{Fore.WHITE}[*] Found form field: {Fore.MAGENTA}{name} (type: {field.get('type', 'text')}){Style.RESET_ALL}")

        # Create a dictionary of username and password input fields
        username_field = None
        password_field = None
        
        for name, value in input_data.items():
            if name.lower() in [
                'username', 'email', 'user', 'login', 'userid', 'user_id', 'user_name', 
                'loginid', 'login_id', 'account', 'accountname', 'account_name', 'identity',
                'uid', 'uname', 'nickname', 'handle', 'screen_name', 'member', 'memberid',
                'member_id', 'customer', 'customerid', 'customer_id', 'auth', 'authentication',
                'identifier', 'signin', 'sign_in', 'j_username', 'usr', 'usrname', 'username',
                'user', 'userid', 'user_id', 'user_name', 'loginid', 'login_id', 'account',
                'accountname', 'account_name', 'identity', 'uid', 'uname', 'nickname', 'handle',
                'screen_name', 'member', 'memberid', 'member_id', 'customer', 'customerid',
                'customer_id', 'auth', 'authentication', 'identifier', 'signin', 'sign_in',
                'j_username', 'usr', 'usrname', 'username', 'user', 'userid', 'user_id',
                'user_name', 'loginid', 'login_id', 'account', 'accountname', 'account_name', 'name']:
                username_field = name
            elif name.lower() in [
                'password', 'pass', 'pwd', 'passwd', 'passphrase', 'passkey',
                'password', 'pass', 'pwd', 'passwd', 'passphrase', 'secret', 'secretkey',
                'secret_key', 'credentials', 'cred', 'userpass', 'user_pass', 'passcode',
                'pass_code', 'pin', 'pincode', 'pin_code', 'p_word', 'pword', 'p_phrase',
                'pphrase', 'authkey', 'auth_key', 'security_key', 'securitykey', 'j_password',
                'pswd', 'pswrd', 'pw']:
                password_field = name

        if not username_field or not password_field:
            print(f"{Fore.YELLOW}[!] Could not identify username/password fields on {url}{Style.RESET_ALL}")
            return
            
        print(f"{Fore.WHITE}[*] Found login form fields - Username: {Fore.MAGENTA}{username_field}, {Fore.WHITE}Password: {Fore.MAGENTA}{password_field}{Style.RESET_ALL}")
        
        # Load wordlists
        try:
            usernames = password_wordlist(username_file)
            passwords = password_wordlist(password_file)
            
            print(f"{Fore.WHITE}[*] Loaded {Fore.MAGENTA}{len(usernames)} usernames and {Fore.MAGENTA}{len(passwords)} passwords{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading wordlists: {str(e)}{Style.RESET_ALL}")
            return

        # Load and test proxies ONCE at the beginning
        proxies = load_proxies(proxy_file, test=True, max_workers=50) if proxy_file else []
        proxy_cycle = cycle(proxies) if proxies else None
        
        if proxies:
            print(f"{Fore.WHITE}[*] Using {Fore.MAGENTA}{len(proxies)} working proxies{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No working proxies found or proxy file not provided. Running without proxies.{Style.RESET_ALL}")

        success_indicators = {
            'url_change': [
                'my-account', 'dashboard', 'home', 'welcome', 'profile', 'account',
                'admin', 'panel', 'control', 'console', 'manage',
                'user', 'member', 'portal', 'secure', 'private',
                'overview', 'summary', 'main', 'index.php', 'default.aspx',
                'authenticated', 'session', 'loggedin', 'authorized'
            ],
            'content': [
                'log out', 'sign out', 'logout', 'signout', 'sign off', 'logoff',
                'welcome back', 'welcome,', 'hello,', 'hi,', 'greetings',
                'my account', 'your account', 'your profile', 'account settings',
                'dashboard', 'control panel', 'admin panel', 'user panel',
                'session', 'you are logged in', 'authenticated', 'authorized',
                'edit profile', 'change password', 'update details', 'account info',
                'menu', 'navigation', 'sidebar', 'settings', 'preferences',
                'two-factor', '2fa', 'security settings', 'activity log'
            ],
            'negative': [
                'invalid', 'incorrect', 'failed', 'error', 'try again', 'wrong',
                'authentication failed', 'login failed', 'access denied', 'denied',
                'invalid username', 'invalid password', 'invalid credentials',
                'incorrect username', 'incorrect password', 'wrong username', 'wrong password',
                'captcha', 'recaptcha', 'verification', 'locked', 'suspended',
                'too many attempts', 'rate limited', 'try later', 'timeout',
                'does not exist', 'not recognized', 'not found', 'please try',
                'sign in', 'log in', 'login form', 'remember me', 'forgot password'
            ]
        }
        
        # Get initial state
        initial_url = response.url
        if verbose:
            print(f"{Fore.WHITE}[*] Initial URL: {Fore.GREEN}{initial_url}{Style.RESET_ALL}")
        
        # Set up progress tracking
        total_combinations = len(usernames) * len(passwords)
        print(f"{Fore.WHITE}[*] Starting bruteforce with {Fore.MAGENTA}{total_combinations} combinations{Style.RESET_ALL}")
        
        # Use ThreadPoolExecutor for faster performance
        max_workers = min(50, os.cpu_count() * 5)  # Adjust based on your system
        print(f"{Fore.WHITE}[*] Using {Fore.MAGENTA}{max_workers} concurrent workers{Style.RESET_ALL}")
        
        # Create a counter for progress tracking
        completed = 0
        found_credentials = False
        print_lock = threading.Lock()
        
        # Try to import tqdm for progress bar
        try:
            from tqdm import tqdm
            progress_bar = tqdm(total=total_combinations, desc="Testing combinations", 
                               unit="combo", ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
            has_tqdm = True
        except ImportError:
            progress_bar = None
            has_tqdm = False
            print(f"{Fore.WHITE}[*] tqdm not installed, using simple progress updates{Style.RESET_ALL}")
        
        # Function to update progress
        def update_progress():
            nonlocal completed
            completed += 1
            if has_tqdm:
                progress_bar.update(1)
            elif completed % 10 == 0:
                print(f"{Fore.WHITE}[*] Progress: {Fore.MAGENTA}{completed}/{total_combinations} ({(completed/total_combinations)*100:.1f}%){Style.RESET_ALL}", end='\r')
        
        # Function to process a single login attempt
        def process_login(username, password):
            nonlocal found_credentials, proxy_cycle
            
            # Skip if we already found credentials
            if found_credentials:
                return None
                
            # Create form data for this attempt
            form_data = input_data.copy()
            form_data[username_field] = username.strip()
            form_data[password_field] = password.strip()
            
            # Get a random user agent
            user_agent = get_random_user_agent()
            
            # Get a proxy if available - use the existing proxy_cycle
            proxy = next(proxy_cycle) if proxy_cycle else None
            
            # Try login with proxy and user agent
            result = try_login_task(username, password, url, form_data, initial_url, 
                                   success_indicators, verbose, proxy, user_agent,
                                   username_field, password_field)  # Pass the field names
            
            # Update progress
            with print_lock:
                update_progress()
                
            # Check if we found valid credentials or detected 2FA
            if result:
                if isinstance(result, tuple) and len(result) >= 3:
                    if result[0] == "2FA_DETECTED":
                        # 2FA was detected, handle specially
                        _, username, password, final_url = result
                        with print_lock:
                            if has_tqdm:
                                progress_bar.close()
                            print(f"\n{Fore.YELLOW}[!] 2FA detected with credentials - Username: {Fore.MAGENTA}{username} {Fore.WHITE}Password: {Fore.MAGENTA}{password}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}[+] Final URL: {Fore.GREEN}{final_url}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}[!] Bruteforcing stopped as 2FA cannot be automatically bypassed{Style.RESET_ALL}")
                    else:
                        # Normal successful login
                        username, password, final_url = result
                        with print_lock:
                            if has_tqdm:
                                progress_bar.close()
                            print(f"\n{Fore.GREEN}[+] Success! {Fore.WHITE}Username: {Fore.MAGENTA}{username} {Fore.WHITE}Password: {Fore.MAGENTA}{password}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}[+] Final URL: {Fore.GREEN}{final_url}{Style.RESET_ALL}")
                
                found_credentials = True
                return result
                
            return None
        
        # Create all work items
        work_items = []
        for username in usernames:
            for password in passwords:
                work_items.append((username, password))
        
        # Process in batches
        batch_size = 1000
        for i in range(0, len(work_items), batch_size):
            if found_credentials:
                break
                
            batch = work_items[i:i+batch_size]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(process_login, username, password): (username, password) for username, password in batch}
                
                for future in concurrent.futures.as_completed(futures):
                    if found_credentials:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                        
                    try:
                        result = future.result()
                        if result:
                            # We found valid credentials or detected 2FA
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                    except Exception as e:
                        if verbose:
                            with print_lock:
                                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        
        # Close progress bar if it exists
        if has_tqdm and progress_bar and not found_credentials:
            progress_bar.close()
        
        if not found_credentials:
            print(f"\n{Fore.YELLOW}[!] No valid credentials found after {completed} attempts{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error during bruteforce attempt: {str(e)}{Style.RESET_ALL}")
        if verbose:
            import traceback
            traceback.print_exc()

# Update the argument handling
if args.brute_user_pass:
    if not args.username_wordlist:
        print(f"{Fore.RED}[!] Error: Username wordlist is required. Use --username-wordlist to specify the file{Style.RESET_ALL}")
    elif not args.password_wordlist:
        print(f"{Fore.RED}[!] Error: Password wordlist is required. Use --password-wordlist to specify the file{Style.RESET_ALL}")
    else:
        bruteforce_login(args.brute_user_pass, args.username_wordlist, args.password_wordlist, 
                            proxy_file=args.proxy_file, verbose=args.verbose)

if args.nuclei:
    def nuclei_scan(template: str, url: str) -> str:
        print(f"Scanning {Fore.GREEN}{url} {Fore.WHITE}with {Fore.MAGENTA}{template}{Fore.WHITE}..\n")
        nuclei_output = sub_output.subpro_scan(f"nuclei -u {url} -t {template} -silent -c 20 -j -o vulnerable.json")
        return nuclei_output
    
    def nuclei_parser(nuclei_output: str) -> str:
        try:
            with open("vulnerable.json", "r") as f:
                data = [x.strip() for x in f.readlines()]
            
            if not data:
                print(f"{Fore.YELLOW}No vulnerabilities found.{Fore.WHITE}")
                return
                
            results = []
            for data_item in data:
                try:
                    json_result = json.loads(data_item)
                    
                    template_id = json_result.get("template-id", "N/A")
                    matched_at = json_result.get("matched-at", "N/A")
                    info = json_result.get("info", {})
                    
                    name = info.get("name", "Unknown Vulnerability")
                    description = info.get("description", "No description available")
                    severity = info.get("severity", "unknown")
                    
                    # Print findings
                    print(f"{Fore.MAGENTA}Template ID: {Fore.GREEN}{template_id}")
                    print(f"{Fore.MAGENTA}PoC: {Fore.GREEN}{matched_at}")
                    print(f"{Fore.MAGENTA}Vulnerability: {Fore.GREEN}{name}")
                    print(f"{Fore.MAGENTA}Description: {Fore.GREEN}{description}")
                    print(f"{Fore.MAGENTA}Severity: {Fore.RED}{severity}")
                    print("-" * 60)
                    
                    # Append to results
                    results.append({
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "name": name,
                        "description": description,
                        "severity": severity
                    })
                except json.JSONDecodeError as e:
                    print(f"{Fore.RED}Error parsing JSON result: {e}{Fore.WHITE}")
                    continue
                
            return results
        except FileNotFoundError:
            print(f"{Fore.RED}Error: vulnerable.json file not found. Nuclei scan may have failed.{Fore.WHITE}")
            return []
        except Exception as e:
            print(f"{Fore.RED}Error processing nuclei output: {str(e)}{Fore.WHITE}")
            return []
    
    def main():
        template = args.nuclei_template
        url = args.nuclei
        if not template or not url:
            print(f"{Fore.RED}Error: Both template and URL are required for nuclei scanning.{Fore.WHITE}")
            print(f"Usage: python spyhunt.py --nuclei [URL] --nuclei-template [TEMPLATE_PATH]")
            return
            
        results = nuclei_scan(template, url)
        nuclei_parser(results)
    
    if __name__ == "__main__":
        main()

        

if __name__ == "__main__":
        main()


if args.ics_scan:
    init(autoreset=True)
    
    def ics_scan(target):
        print(f"{Fore.CYAN}[*] Starting ICS/SCADA scanning on {target}{Style.RESET_ALL}")
        
        # Xác định các giao thức cần quét
        supported_protocols = []
        if args.modbus_scan:
            supported_protocols.append({"name": "Modbus", "port": args.modbus_port})
        if args.s7_scan:
            supported_protocols.append({"name": "Siemens S7", "port": args.s7_port})
        if args.dnp3_scan:
            supported_protocols.append({"name": "DNP3", "port": args.dnp3_port})
        if args.bacnet_scan:
            supported_protocols.append({"name": "BACnet", "port": args.bacnet_port})
        if args.profinet_scan:
            supported_protocols.append({"name": "PROFINET", "default_ports": [34962, 34963, 34964]})
        if args.opcua_scan:
            supported_protocols.append({"name": "OPC UA", "port": args.opcua_port})
            
        # Nếu không có giao thức nào được chỉ định, quét tất cả
        if not supported_protocols:
            print(f"{Fore.YELLOW}[!] No specific protocol selected, scanning for all common ICS protocols{Style.RESET_ALL}")
            supported_protocols = [
                {"name": "Modbus", "port": 502},
                {"name": "Siemens S7", "port": 102},
                {"name": "DNP3", "port": 20000},
                {"name": "BACnet", "port": 47808},
                {"name": "PROFINET", "default_ports": [34962, 34963, 34964]},
                {"name": "OPC UA", "port": 4840}
            ]
        
        # Quét từng giao thức
        results = []
        for protocol in supported_protocols:
            print(f"{Fore.GREEN}[*] Scanning for {protocol['name']} protocol{Style.RESET_ALL}")
            
            if protocol['name'] == "PROFINET" and 'default_ports' in protocol:
                for port in protocol['default_ports']:
                    try:
                        # Kiểm tra kết nối đến port
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            print(f"{Fore.GREEN}[+] {protocol['name']} port {port} is open{Style.RESET_ALL}")
                            results.append(f"{protocol['name']} detected on port {port}")
                        sock.close()
                    except socket.error:
                        print(f"{Fore.RED}[-] Error connecting to {target}:{port}{Style.RESET_ALL}")
            else:
                port = protocol.get('port', 0)
                try:
                    # Kiểm tra kết nối đến port
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        print(f"{Fore.GREEN}[+] {protocol['name']} port {port} is open{Style.RESET_ALL}")
                        results.append(f"{protocol['name']} detected on port {port}")
                        
                        # Thực hiện thêm thăm dò giao thức cụ thể
                        if protocol['name'] == "Modbus":
                            modbus_probe(target, port)
                        elif protocol['name'] == "Siemens S7":
                            s7_probe(target, port)
                    sock.close()
                except socket.error:
                    print(f"{Fore.RED}[-] Error connecting to {target}:{port}{Style.RESET_ALL}")
        
        # Quét các thiết bị PLC nếu được yêu cầu
        if args.plc_scan:
            plc_scan(target)
            
        # Quét các HMI nếu được yêu cầu
        if args.hmi_scan:
            hmi_scan(target)
            
        # Phát hiện các thành phần SCADA nếu được yêu cầu
        if args.scada_components:
            scan_scada_components(target)
            
        # Phân tích PCAP nếu được cung cấp
        if args.ics_pcap:
            analyze_ics_pcap(args.ics_pcap)
            
        # Phát hiện protocol nếu được yêu cầu
        if args.protocol_detection:
            detect_ics_protocols(target)
        
        return results
    
    def modbus_probe(target, port):
        """Kiểm tra cụ thể cho giao thức Modbus"""
        print(f"{Fore.CYAN}[*] Performing detailed Modbus protocol scan on {target}:{port}{Style.RESET_ALL}")
        try:
            # Gửi Modbus read device ID request
            modbus_packet = bytes.fromhex("00010000000601010000")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            sock.send(modbus_packet)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 0:
                print(f"{Fore.GREEN}[+] Received Modbus response: {response.hex()}{Style.RESET_ALL}")
                # Phân tích response
                if len(response) > 7 and response[7] == 1:
                    print(f"{Fore.GREEN}[+] Modbus device confirmed!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Modbus probe error: {str(e)}{Style.RESET_ALL}")
    
    def s7_probe(target, port):
        """Kiểm tra cụ thể cho giao thức Siemens S7"""
        print(f"{Fore.CYAN}[*] Performing detailed Siemens S7 protocol scan on {target}:{port}{Style.RESET_ALL}")
        # Thực hiện kiểm tra S7 communication setup request
        try:
            print(f"{Fore.YELLOW}[!] S7 detailed scanning requires additional libraries{Style.RESET_ALL}")
            # Ở đây sẽ thêm code kiểm tra S7 nếu có thư viện hỗ trợ
        except Exception as e:
            print(f"{Fore.RED}[-] S7 probe error: {str(e)}{Style.RESET_ALL}")
    
    def opcua_probe(target, port):
        """Kiểm tra cụ thể cho giao thức OPC UA"""
        print(f"{Fore.CYAN}[*] Performing detailed OPC UA protocol scan on {target}:{port}{Style.RESET_ALL}")
        try:
            print(f"{Fore.YELLOW}[!] OPC UA detailed scanning requires additional libraries{Style.RESET_ALL}")
            # Thực hiện truy vấn cơ bản đến OPC UA server
            # Cần thư viện asyncua hoặc opcua để thực hiện đầy đủ
            opcua_hello = bytes.fromhex("4f50454e")  # "OPEN" in hex as a basic hello
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            sock.send(opcua_hello)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 0:
                print(f"{Fore.GREEN}[+] Received response from possible OPC UA server: {response.hex()[:30]}...{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] OPC UA probe error: {str(e)}{Style.RESET_ALL}")
    
    def plc_scan(target):
        """Quét các Programmable Logic Controllers (PLCs)"""
        print(f"{Fore.CYAN}[*] Scanning for PLCs on {target}{Style.RESET_ALL}")
        # Common PLC ports and services
        plc_ports = [
            {"port": 102, "name": "Siemens S7"},
            {"port": 502, "name": "Modbus TCP"},
            {"port": 44818, "name": "Allen Bradley EtherNet/IP"},
            {"port": 1911, "name": "Niagara Fox Protocol (Tridium)"},
            {"port": 9600, "name": "OMRON FINS"},
            {"port": 1962, "name": "PCWorx"}
        ]
        
        for plc in plc_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, plc["port"]))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Potential PLC detected: {plc['name']} on port {plc['port']}{Style.RESET_ALL}")
                sock.close()
            except:
                pass
    
    def hmi_scan(target):
        """Quét các Human Machine Interfaces (HMIs)"""
        print(f"{Fore.CYAN}[*] Scanning for HMIs on {target}{Style.RESET_ALL}")
        # Common HMI ports and services
        hmi_ports = [
            {"port": 80, "name": "Web HMI"},
            {"port": 443, "name": "Secure Web HMI"},
            {"port": 102, "name": "Siemens HMI"},
            {"port": 789, "name": "Redlion HMI"},
            {"port": 2455, "name": "CODESYS HMI"},
            {"port": 8080, "name": "Alternative Web HMI"}
        ]
        
        for hmi in hmi_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, hmi["port"]))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Potential HMI detected: {hmi['name']} on port {hmi['port']}{Style.RESET_ALL}")
                sock.close()
            except:
                pass
        
        # Kiểm tra web-based HMIs với các đường dẫn và signature phổ biến
        if socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((target, 80)) == 0:
            try:
                hmi_paths = [
                    "/hmi/", "/scada/", "/visualization/", "/runtime/", 
                    "/webvisu/", "/webaccess/", "/weintek/", "/ignition/"
                ]
                for path in hmi_paths:
                    try:
                        response = requests.get(f"http://{target}{path}", timeout=3)
                        if response.status_code == 200:
                            print(f"{Fore.GREEN}[+] Potential Web HMI found at http://{target}{path}{Style.RESET_ALL}")
                    except:
                        pass
            except:
                pass
    
    def scan_scada_components(target):
        """Quét các thành phần SCADA"""
        print(f"{Fore.CYAN}[*] Scanning for SCADA components on {target}{Style.RESET_ALL}")
        components = [
            {"port": 20000, "name": "DNP3"},
            {"port": 47808, "name": "BACnet"},
            {"port": 1911, "name": "Niagara Fox Protocol"},
            {"port": 18245, "name": "GE SRTP"},
            {"port": 1962, "name": "PCWorx"},
            {"port": 2404, "name": "IEC 60870-5-104"},
            {"port": 20547, "name": "ProConOS"},
            {"port": 5006, "name": "Mitsubishi MELSEC-Q"},
            {"port": 5007, "name": "Mitsubishi MELSEC-Q"},
            {"port": 10001, "name": "Mitsubishi MELSEC ASCII"},
            {"port": 9600, "name": "OMRON FINS"}
        ]
        
        for comp in components:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, comp["port"]))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Potential SCADA component detected: {comp['name']} on port {comp['port']}{Style.RESET_ALL}")
                sock.close()
            except:
                pass
    
    def analyze_ics_pcap(pcap_file):
        """Phân tích tệp PCAP chứa lưu lượng ICS/SCADA"""
        print(f"{Fore.CYAN}[*] Analyzing ICS/SCADA traffic in PCAP file: {pcap_file}{Style.RESET_ALL}")
        # Kiểm tra tệp tồn tại
        if not os.path.exists(pcap_file):
            print(f"{Fore.RED}[-] PCAP file not found: {pcap_file}{Style.RESET_ALL}")
            return
        
        # Kiểm tra xem tshark có sẵn không
        tshark_path = which("tshark")
        if not tshark_path:
            print(f"{Fore.RED}[-] tshark not found. Please install Wireshark/tshark to analyze PCAP files.{Style.RESET_ALL}")
            return
        
        # Phân tích các giao thức ICS
        protocols = ["modbus", "s7comm", "dnp3", "bacnet", "opcua", "ethernetip", "iec104"]
        
        for protocol in protocols:
            try:
                cmd = ["tshark", "-r", pcap_file, "-Y", f"{protocol}", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.port"]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if stdout:
                    print(f"{Fore.GREEN}[+] {protocol.upper()} traffic detected in PCAP file{Style.RESET_ALL}")
                    lines = stdout.decode().strip().split("\n")
                    unique_connections = set()
                    
                    for line in lines:
                        if line.strip():
                            unique_connections.add(line.strip())
                    
                    for conn in list(unique_connections)[:10]:  # Hiển thị 10 kết nối đầu tiên
                        print(f"{Fore.CYAN}    {conn}{Style.RESET_ALL}")
                    
                    if len(unique_connections) > 10:
                        print(f"{Fore.CYAN}    ... and {len(unique_connections) - 10} more connections{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error analyzing {protocol} traffic: {str(e)}{Style.RESET_ALL}")
    
    def detect_ics_protocols(target):
        """Phát hiện các giao thức ICS trong lưu lượng mạng"""
        print(f"{Fore.CYAN}[*] Detecting industrial protocols on {target}{Style.RESET_ALL}")
        
        # Common ICS protocol signatures (hex)
        signatures = [
            {"name": "Modbus TCP", "hex": "0000000000060101", "port": 502},
            {"name": "Siemens S7", "hex": "0300001611e00000", "port": 102},
            {"name": "DNP3", "hex": "0564", "port": 20000},
            {"name": "BACnet", "hex": "810b001c", "port": 47808},
            {"name": "EtherNet/IP", "hex": "6500", "port": 44818},
            {"name": "PROFINET", "hex": "fefe", "port": 34962}
        ]
        
        for sig in signatures:
            try:
                # Kiểm tra port có mở không
                port_open = False
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target, sig["port"])) == 0:
                    port_open = True
                sock.close()
                
                if port_open:
                    print(f"{Fore.GREEN}[+] Port {sig['port']} open for {sig['name']}, sending probe...{Style.RESET_ALL}")
                    
                    # Gửi signature probe
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((target, sig["port"]))
                    sock.send(bytes.fromhex(sig["hex"]))
                    response = sock.recv(1024)
                    sock.close()
                    
                    if len(response) > 0:
                        print(f"{Fore.GREEN}[+] {sig['name']} protocol detected! Response: {response.hex()[:20]}...{Style.RESET_ALL}")
            except:
                pass
    
    # Bắt đầu quét với target được chỉ định
    target = args.ics_scan
    if not target:
        print(f"{Fore.RED}[!] Please specify a target IP address with --ics-scan <target_ip>{Style.RESET_ALL}")
    else:
        results = ics_scan(target)
        if results:
            print(f"\n{Fore.GREEN}[+] ICS/SCADA scan completed. Found {len(results)} potential services:{Style.RESET_ALL}")
            for result in results:
                print(f"{Fore.CYAN}    - {result}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] ICS/SCADA scan completed. No industrial services detected.{Style.RESET_ALL}")

# Sử dụng scanner SMB chuyên dụng nếu đối số được chỉ định
if args.smb_scan:
    try:
        from modules.scanners.smb_scanner import scan_smb, save_results
        print(f"{Fore.CYAN}[*] Running specialized SMB scanner on {args.smb_scan}{Style.RESET_ALL}")
        smb_results = scan_smb(args.smb_scan, args.smb_port, args.smb_brute)
        
        # Lưu kết quả nếu có đối số save_autorecon
        if args.save_autorecon:
            save_results(smb_results, args.save_autorecon)
    except Exception as e:
        print(f"{Fore.RED}[-] Error running SMB scanner: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Tip: Make sure the file modules/scanners/smb_scanner.py exists and is accessible{Style.RESET_ALL}")

if args.redis_scan:
    try:
        print(f"\n{Fore.MAGENTA}Starting Redis scanner for {Fore.CYAN}{args.redis_scan}{Style.RESET_ALL}")
        
        try:
            # Import Redis scanner module
            from modules.scanners.redis_scanner import scan_redis, save_results
            
            # Run Redis scanner
            brute_force = False  # Default to False, could add a separate argument for this
            results = scan_redis(args.redis_scan, args.redis_port, brute_force)
            
            # Save results if requested
            if args.save_autorecon:
                save_dir = "results" if args.save_autorecon is True else args.save_autorecon
                save_results(results, save_dir)
                
        except ImportError:
            print(f"{Fore.RED}[!] Error: Redis scanner module not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Make sure the modules/scanners/redis_scanner.py file exists{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during Redis scan: {str(e)}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Redis scan interrupted by user{Style.RESET_ALL}")

if args.ftp_scan:
    try:
        print(f"\n{Fore.MAGENTA}Starting FTP scanner for {Fore.CYAN}{args.ftp_scan}{Style.RESET_ALL}")
        
        try:
            # Import FTP scanner module
            from modules.scanners.ftp_scanner import scan_ftp, save_results
            
            # Load username and password lists if provided
            username_list = None
            password_list = None
            
            if args.username_wordlist:
                try:
                    with open(args.username_wordlist, 'r') as f:
                        username_list = [line.strip() for line in f if line.strip()]
                    print(f"{Fore.BLUE}[*] Loaded {len(username_list)} usernames from {args.username_wordlist}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error loading username list: {str(e)}{Style.RESET_ALL}")
            
            if args.password_wordlist:
                try:
                    with open(args.password_wordlist, 'r') as f:
                        password_list = [line.strip() for line in f if line.strip()]
                    print(f"{Fore.BLUE}[*] Loaded {len(password_list)} passwords from {args.password_wordlist}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error loading password list: {str(e)}{Style.RESET_ALL}")
            
            # Run FTP scanner
            brute_force = True if args.username_wordlist or args.password_wordlist else False
            results = scan_ftp(args.ftp_scan, args.ftp_port, brute_force, username_list, password_list)
            
            # Save results if requested
            if args.save_autorecon:
                save_dir = "results" if args.save_autorecon is True else args.save_autorecon
                save_results(results, save_dir)
                
        except ImportError:
            print(f"{Fore.RED}[!] Error: FTP scanner module not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Make sure the modules/scanners/ftp_scanner.py file exists{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during FTP scan: {str(e)}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] FTP scan interrupted by user{Style.RESET_ALL}")


