#!/usr/bin/env python3

import os
import sys
import json
import time
import random
import requests
import re
import argparse
import subprocess
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Try to load dotenv for API keys
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print(f"{Fore.YELLOW}[!] python-dotenv not installed. Environment variables from .env file will not be loaded.{Style.RESET_ALL}")

# Import AI Support Functions
try:
    from ai_support_functions import AISupportFunctions
except ImportError:
    print(f"{Fore.RED}[!] AI Support Functions module not found. Please ensure ai_support_functions.py exists.{Style.RESET_ALL}")
    sys.exit(1)

def run_command(cmd):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{Fore.YELLOW}[!] Command failed: {e.stderr.strip()}{Style.RESET_ALL}")
        return None

def run_simplified_scan(target, output_dir=".", max_threads=10, ai_model="gpt-4o-mini", auto_explore=True):
    """
    Run a simplified security scan on a target
    
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
    
    print(f"{Fore.CYAN}[+] Starting simplified scan on {target}{Style.RESET_ALL}")
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
        "vulnerabilities": [],
    }
    
    # Basic domain info
    try:
        print(f"{Fore.CYAN}[+] Basic domain information{Style.RESET_ALL}")
        host_info = subprocess.run(['nslookup', target], capture_output=True, text=True)
        if host_info.returncode == 0:
            findings["host_info"] = host_info.stdout
            print(f"{Fore.GREEN}[+] Successfully gathered basic domain info{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Failed to get domain info{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error gathering domain info: {str(e)}{Style.RESET_ALL}")
    
    # Basic web info
    try:
        print(f"{Fore.CYAN}[+] Getting basic web information{Style.RESET_ALL}")
        try:
            response = requests.get(f"https://{target}", timeout=10, verify=False)
            findings["web_info"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content)
            }
            print(f"{Fore.GREEN}[+] Successfully gathered web info (HTTPS){Style.RESET_ALL}")
        except requests.RequestException:
            try:
                response = requests.get(f"http://{target}", timeout=10)
                findings["web_info"] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content_length": len(response.content)
                }
                print(f"{Fore.GREEN}[+] Successfully gathered web info (HTTP){Style.RESET_ALL}")
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}[!] Failed to connect to website: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error gathering web info: {str(e)}{Style.RESET_ALL}")
    
    # Use common directories for discovery
    try:
        print(f"{Fore.CYAN}[+] Testing common web directories{Style.RESET_ALL}")
        common_paths = [
            "/admin", "/login", "/wp-admin", "/wp-login.php", "/phpmyadmin",
            "/api", "/v1", "/v2", "/api/v1", "/dashboard", "/console",
            "/backup", "/test", "/dev", "/staging", "/robots.txt", "/.git",
            "/config", "/settings", "/upload", "/uploads"
        ]
        
        findings["directory_checks"] = []
        
        for protocol in ["https", "http"]:
            for path in common_paths:
                try:
                    url = f"{protocol}://{target}{path}"
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    
                    if response.status_code != 404:
                        findings["directory_checks"].append({
                            "url": url,
                            "status_code": response.status_code,
                            "content_length": len(response.content)
                        })
                        print(f"{Fore.GREEN}[+] Found: {url} (Status: {response.status_code}){Style.RESET_ALL}")
                except requests.RequestException:
                    pass
        
        print(f"{Fore.GREEN}[+] Directory check completed. Found {len(findings['directory_checks'])} interesting paths{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during directory checks: {str(e)}{Style.RESET_ALL}")
    
    # Save all findings to a single JSON file
    findings_file = os.path.join(scan_dir, "findings.json")
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=4)

    print(f"\n{Fore.GREEN}[+] All scan results saved to {findings_file}{Style.RESET_ALL}")
    
    return findings_file

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run a simplified security scan and AI analysis")
    parser.add_argument("target", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--output-dir", default=".", help="Directory to save output files")
    parser.add_argument("--max-threads", type=int, default=10, help="Maximum number of threads to use")
    parser.add_argument("--ai-model", default="gpt-4o-mini", help="AI model to use (default: gpt-4o-mini)")
    parser.add_argument("--output-format", choices=["simple", "detailed", "json"], default="detailed", help="Output format")
    parser.add_argument("--focus", choices=["api", "web", "mobile", "infra", "all"], default="all", help="Focus area for AI analysis")
    parser.add_argument("--api-key", help="OpenAI API key (if not set in environment)")
    args = parser.parse_args()

    # Display banner
    print(f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.GREEN}SpyHunt Simplified Security Scanner {Fore.CYAN}              ║
{Fore.CYAN}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    # Run the comprehensive scan
    print(f"{Fore.CYAN}[+] Starting simplified scan on {args.target}{Style.RESET_ALL}")
    try:
        findings_file = run_simplified_scan(
            target=args.target,
            output_dir=args.output_dir,
            max_threads=args.max_threads,
            ai_model=args.ai_model,
            auto_explore=True
        )
        
        if not findings_file or not os.path.exists(findings_file):
            print(f"{Fore.RED}[!] Scan failed to produce valid results. Check for errors above.{Style.RESET_ALL}")
            sys.exit(1)
            
        print(f"{Fore.GREEN}[+] Scan completed successfully.{Style.RESET_ALL}")
        
        # Load the findings data
        with open(findings_file, 'r') as f:
            findings_data = json.load(f)
        
        # Initialize AI support functions
        ai_support = AISupportFunctions(api_key=args.api_key)
        
        # Run AI analysis
        print(f"{Fore.CYAN}[+] Running AI analysis with {args.ai_model} model...{Style.RESET_ALL}")
        ai_support.run_ai_bug_bounty(
            target=args.target,
            focus=args.focus,
            max_threads=args.max_threads,
            output_format=args.output_format,
            ai_model=args.ai_model,
            findings_data=findings_data
        )
        
        print(f"{Fore.GREEN}[+] AI analysis completed. Check the output for details.{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan or analysis: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 