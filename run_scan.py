#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init()

# Import AI support functions
try:
    from ai_support_functions import AISupportFunctions
except ImportError:
    print(f"{Fore.RED}[!] AI Support Functions module not found. Please ensure ai_support_functions.py exists.{Style.RESET_ALL}")
    sys.exit(1)

# Import the comprehensive scan function
try:
    # This might take a while as it loads many modules
    print(f"{Fore.CYAN}[+] Loading SpyHunt modules...{Style.RESET_ALL}")
    from spyhunt import run_comprehensive_scan
except ImportError as e:
    print(f"{Fore.RED}[!] Error importing SpyHunt modules: {str(e)}{Style.RESET_ALL}")
    missing_module = str(e).split("'")[1] if "'" in str(e) else str(e)
    print(f"{Fore.YELLOW}[!] Try installing the missing module: pip install {missing_module}{Style.RESET_ALL}")
    sys.exit(1)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run a comprehensive security scan and AI analysis")
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
{Fore.CYAN}║ {Fore.GREEN}SpyHunt Security Scanner with AI Analysis {Fore.CYAN}        ║
{Fore.CYAN}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    # Run the comprehensive scan
    print(f"{Fore.CYAN}[+] Starting comprehensive scan on {args.target}{Style.RESET_ALL}")
    try:
        findings_file = run_comprehensive_scan(
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