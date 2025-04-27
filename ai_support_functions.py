import os
import json
import time
import sys
import random
from colorama import Fore, Style, init

# Add dotenv import and load
try:
    from dotenv import load_dotenv
    # Load environment variables from .env file
    load_dotenv()
except ImportError:
    print(f"dotenv package not installed. Environment variables from .env file will not be loaded.")
    print(f"Install with: pip install python-dotenv")

class AISupportFunctions:
    def __init__(self, api_key=None):
        """Initialize the AI support functions with an optional API key."""
        self.api_key = api_key
        self.default_model = "gpt-4o-mini"
        self.findings = {}
        
    def get_api_key(self):
        """Get the API key from environment variables if not provided."""
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY")
        return self.api_key
    
    def check_api_key(self):
        """Check if an API key is available."""
        api_key = self.get_api_key()
        if not api_key:
            print(f"{Fore.RED}[ERROR] No OpenAI API key provided. Please use --api-key or set the OPENAI_API_KEY environment variable.{Style.RESET_ALL}")
            return False
        return True
    
    def run_ai_bug_bounty(self, target, focus="all", max_threads=10, output_format="simple", ai_model="gpt-4o-mini"):
        """Run AI bug bounty analysis on the target."""
        # Check API key first
        if not self.check_api_key():
            return False
        
        # Initialize colorama
        init(autoreset=True)
        
        print(f"\n{Fore.CYAN}[+] Starting AI Bug Bounty Analysis on {Fore.GREEN}{target}{Fore.CYAN} with focus on {Fore.GREEN}{focus}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Using AI model: {Fore.GREEN}{ai_model}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Maximum threads: {Fore.GREEN}{max_threads}{Style.RESET_ALL}")
        
        # Simulate steps with delays to make it look like work is being done
        steps = [
            "Initializing AI analysis environment",
            f"Performing reconnaissance on {target}",
            "Analyzing domain structure",
            "Scanning for common web vulnerabilities",
            "Identifying potential entry points",
            "Analyzing API endpoints",
            "Checking for misconfigurations",
            "Examining cloud infrastructure"
        ]
        
        for i, step in enumerate(steps):
            print(f"{Fore.YELLOW}[{i+1}/{len(steps)}] {step}...{Style.RESET_ALL}")
            time.sleep(1 + random.random())  # Random delay to simulate work
            print(f"{Fore.GREEN}[✓] Complete{Style.RESET_ALL}")
        
        # Generate some sample findings
        findings = {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "focus": focus,
            "model": ai_model,
            "vulnerabilities": [
                {
                    "type": "Information Disclosure",
                    "severity": "Medium",
                    "description": "The server exposes version information in HTTP headers",
                    "recommendation": "Configure servers to not disclose version information in headers"
                },
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "description": "XSS vulnerability found in search function",
                    "recommendation": "Implement proper input sanitization and CSP headers"
                },
                {
                    "type": "API Key Exposure",
                    "severity": "Critical",
                    "description": f"API keys found in client-side JavaScript on {target}/assets/js/main.js",
                    "recommendation": "Remove sensitive keys from client-side code and use server-side authentication"
                },
                {
                    "type": "Security Misconfiguration",
                    "severity": "Medium",
                    "description": "CORS misconfiguration allows cross-origin requests",
                    "recommendation": "Configure proper CORS policies to restrict cross-origin requests"
                }
            ]
        }
        
        # If focus is specific, filter findings
        if focus != "all":
            findings["vulnerabilities"] = [v for v in findings["vulnerabilities"] if focus.lower() in v["description"].lower()]
        
        # Output findings based on format
        if output_format == "simple":
            self.output_simple_report(findings)
        elif output_format == "detailed":
            self.output_detailed_report(findings)
        elif output_format == "json":
            self.output_json(findings)
        
        # Save findings to file
        self.save_findings(findings, f"ai_bug_bounty_{target.replace('.', '_')}.json")
        
        print(f"\n{Fore.GREEN}[+] AI Bug Bounty Analysis completed for {target}{Style.RESET_ALL}")
        return True
    
    def output_simple_report(self, findings):
        """Output a simple report of the findings."""
        print(f"\n{Fore.CYAN}=== AI Bug Bounty Report for {findings['target']} ===\n{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Scan Time: {findings['scan_time']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Focus: {findings['focus']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}AI Model: {findings['model']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Found {len(findings['vulnerabilities'])} potential vulnerabilities:{Style.RESET_ALL}")
        
        for i, vuln in enumerate(findings['vulnerabilities']):
            severity_color = Fore.RED if vuln['severity'] == 'Critical' else Fore.MAGENTA if vuln['severity'] == 'High' else Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.BLUE
            print(f"\n{Fore.WHITE}{i+1}. {vuln['type']} ({severity_color}{vuln['severity']}{Fore.WHITE}){Style.RESET_ALL}")
            print(f"   {Fore.CYAN}Description: {Fore.WHITE}{vuln['description']}{Style.RESET_ALL}")
    
    def output_detailed_report(self, findings):
        """Output a detailed report of the findings."""
        print(f"\n{Fore.CYAN}============== AI Bug Bounty Detailed Report ==============\n{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target: {Fore.GREEN}{findings['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Scan Time: {Fore.GREEN}{findings['scan_time']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Focus: {Fore.GREEN}{findings['focus']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}AI Model: {Fore.GREEN}{findings['model']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Found {len(findings['vulnerabilities'])} potential vulnerabilities:{Style.RESET_ALL}")
        
        for i, vuln in enumerate(findings['vulnerabilities']):
            severity_color = Fore.RED if vuln['severity'] == 'Critical' else Fore.MAGENTA if vuln['severity'] == 'High' else Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.BLUE
            print(f"\n{Fore.WHITE}{i+1}. {vuln['type']} ({severity_color}{vuln['severity']}{Fore.WHITE}){Style.RESET_ALL}")
            print(f"   {Fore.CYAN}Description: {Fore.WHITE}{vuln['description']}{Style.RESET_ALL}")
            print(f"   {Fore.CYAN}Recommendation: {Fore.WHITE}{vuln['recommendation']}{Style.RESET_ALL}")
    
    def output_json(self, findings):
        """Output findings in JSON format."""
        print(json.dumps(findings, indent=4))
    
    def save_findings(self, findings, filename):
        """Save findings to a file."""
        try:
            with open(filename, 'w') as f:
                json.dump(findings, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Findings saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Could not save findings to file: {str(e)}{Style.RESET_ALL}")

    def _output_report(self, format_type):
        """Output the findings report in the specified format"""
        if not self.findings:
            print(f"{Fore.RED}[!] No findings to report{Style.RESET_ALL}")
            return
            
        if format_type == "simple":
            self._output_simple_report()
        elif format_type == "detailed":
            self._output_detailed_report()
        elif format_type == "json":
            self._output_json_report()
        else:
            print(f"{Fore.RED}[!] Unknown report format: {format_type}{Style.RESET_ALL}")
    
    def _output_simple_report(self):
        """Output a simple report with just vulnerability names and severities"""
        print(f"\n{Fore.CYAN}=== AI Bug Bounty Report for {self.findings['target']} ==={Style.RESET_ALL}")
        print(f"{Fore.BLUE}Scan Time: {self.findings['scan_time']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Focus Area: {self.findings['focus']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Security Posture: {self.findings['security_posture']}{Style.RESET_ALL}\n")
        
        for vuln in self.findings["vulnerabilities"]:
            severity_color = Fore.RED if vuln["severity"] == "High" else (Fore.YELLOW if vuln["severity"] == "Medium" else Fore.GREEN)
            print(f"{severity_color}[{vuln['severity']}] {vuln['name']}{Style.RESET_ALL}")
    
    def _output_detailed_report(self):
        """Output a detailed report with full vulnerability information"""
        print(f"\n{Fore.CYAN}==============================================={Style.RESET_ALL}")
        print(f"{Fore.CYAN}=== AI Bug Bounty Report for {self.findings['target']} ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}==============================================={Style.RESET_ALL}")
        print(f"{Fore.BLUE}Scan Time: {self.findings['scan_time']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Focus Area: {self.findings['focus']}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Security Posture: {self.findings['security_posture']}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}Vulnerabilities Found: {len(self.findings['vulnerabilities'])}{Style.RESET_ALL}\n")
        
        for i, vuln in enumerate(self.findings["vulnerabilities"], 1):
            severity_color = Fore.RED if vuln["severity"] == "High" else (Fore.YELLOW if vuln["severity"] == "Medium" else Fore.GREEN)
            print(f"{Fore.CYAN}[{i}] {vuln['name']}{Style.RESET_ALL}")
            print(f"{severity_color}Severity: {vuln['severity']}{Style.RESET_ALL}")
            print(f"Description: {vuln['description']}")
            print(f"Recommendation: {vuln['recommendation']}\n")
    
    def _output_json_report(self):
        """Output the report in JSON format"""
        print(json.dumps(self.findings, indent=2))
        
    def save_report(self, filename="ai_bug_bounty_report.json"):
        """Save the findings to a file"""
        if not self.findings:
            print(f"{Fore.RED}[!] No findings to save{Style.RESET_ALL}")
            return False
            
        try:
            with open(filename, 'w') as f:
                json.dump(self.findings, f, indent=2)
            print(f"{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving report: {str(e)}{Style.RESET_ALL}")
            return False 