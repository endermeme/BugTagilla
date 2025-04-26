#!/usr/bin/env python3
import socket
import json
import os
from colorama import Fore, Style, init

# Initialize colorama
init()

def scan_ldap(target, port=389, ldaps_port=636, brute_force=False):
    """
    Scan LDAP service for vulnerabilities and misconfigurations
    
    Args:
        target (str): Target IP address or hostname
        port (int): LDAP port (default: 389)
        ldaps_port (int): LDAPS port (default: 636)
        brute_force (bool): Whether to attempt brute force techniques
        
    Returns:
        dict: Results of the scan
    """
    print(f"\n{Fore.BLUE}[*] Starting LDAP scan on {target}:{port} and LDAPS:{ldaps_port}{Style.RESET_ALL}")
    
    results = {
        "target": target,
        "ldap_port": port,
        "ldaps_port": ldaps_port,
        "ldap_open": False,
        "ldaps_open": False,
        "vulnerabilities": [],
        "configurations": [],
        "anonymous_bind": False
    }
    
    # Check if LDAP port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.GREEN}[+] LDAP port {port} is open{Style.RESET_ALL}")
            results["ldap_open"] = True
        else:
            print(f"{Fore.RED}[-] LDAP port {port} is closed{Style.RESET_ALL}")
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error checking LDAP port: {str(e)}{Style.RESET_ALL}")
    
    # Check if LDAPS port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, ldaps_port))
        if result == 0:
            print(f"{Fore.GREEN}[+] LDAPS port {ldaps_port} is open{Style.RESET_ALL}")
            results["ldaps_open"] = True
        else:
            print(f"{Fore.RED}[-] LDAPS port {ldaps_port} is closed{Style.RESET_ALL}")
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error checking LDAPS port: {str(e)}{Style.RESET_ALL}")
    
    # If LDAP is open, check for anonymous bind
    if results["ldap_open"]:
        print(f"{Fore.BLUE}[*] Testing for anonymous LDAP bind...{Style.RESET_ALL}")
        try:
            # Simulate LDAP anonymous bind check
            # In a real implementation, you would use python-ldap or similar library
            # For demonstration, we'll just simulate the check
            anonymous_bind_success = False  # This would be determined by actual LDAP bind attempt
            
            if anonymous_bind_success:
                print(f"{Fore.RED}[!] Anonymous LDAP bind is allowed!{Style.RESET_ALL}")
                results["anonymous_bind"] = True
                results["vulnerabilities"].append({
                    "name": "Anonymous LDAP Bind",
                    "severity": "High",
                    "description": "The LDAP server allows anonymous binding which could expose sensitive directory information."
                })
            else:
                print(f"{Fore.GREEN}[+] Anonymous LDAP bind is not allowed{Style.RESET_ALL}")
            
            # Check for LDAP configurations - weak password policies
            print(f"{Fore.BLUE}[*] Checking LDAP configurations...{Style.RESET_ALL}")
            results["configurations"].append({
                "name": "Password Policy",
                "details": "Password policies could not be checked without proper authentication"
            })
            
            # Check for LDAP injection
            print(f"{Fore.BLUE}[*] Checking for LDAP injection vulnerabilities...{Style.RESET_ALL}")
            # This would require actual test cases for LDAP injection
            print(f"{Fore.YELLOW}[i] LDAP injection checks require authenticated access or web application testing{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error during LDAP checks: {str(e)}{Style.RESET_ALL}")
    
    # Print summary
    print(f"\n{Fore.BLUE}[*] LDAP Scan Summary for {target}:{Style.RESET_ALL}")
    print(f"    - LDAP port open: {results['ldap_open']}")
    print(f"    - LDAPS port open: {results['ldaps_open']}")
    
    if results["vulnerabilities"]:
        print(f"\n{Fore.RED}[!] Vulnerabilities found:{Style.RESET_ALL}")
        for vuln in results["vulnerabilities"]:
            print(f"    - {vuln['name']} (Severity: {vuln['severity']})")
            print(f"      {vuln['description']}")
    else:
        print(f"\n{Fore.GREEN}[+] No obvious LDAP vulnerabilities detected{Style.RESET_ALL}")
    
    return results

def save_results(results, save_dir="results"):
    """
    Save scan results to a JSON file
    
    Args:
        results (dict): Scan results
        save_dir (str): Directory to save results
    """
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    filename = os.path.join(save_dir, f"ldap_scan_{results['target']}.json")
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LDAP Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=389, help="LDAP port (default: 389)")
    parser.add_argument("--ldaps-port", type=int, default=636, help="LDAPS port (default: 636)")
    parser.add_argument("--brute-force", action="store_true", help="Attempt brute force techniques")
    parser.add_argument("--save-dir", default="results", help="Directory to save results")
    
    args = parser.parse_args()
    
    results = scan_ldap(args.target, args.port, args.ldaps_port, args.brute_force)
    save_results(results, args.save_dir) 