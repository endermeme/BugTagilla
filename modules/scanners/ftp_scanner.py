#!/usr/bin/env python3
import socket
import ftplib
import json
import os
import re
from colorama import Fore, Style, init

# Initialize colorama
init()

def scan_ftp(target, port=21, brute_force=False, username_list=None, password_list=None):
    """
    Scan FTP service for vulnerabilities and misconfigurations
    
    Args:
        target (str): Target IP address or hostname
        port (int): FTP port (default: 21)
        brute_force (bool): Whether to attempt brute force techniques
        username_list (list): List of usernames for brute force
        password_list (list): List of passwords for brute force
        
    Returns:
        dict: Results of the scan
    """
    print(f"\n{Fore.BLUE}[*] Starting FTP scan on {target}:{port}{Style.RESET_ALL}")
    
    results = {
        "target": target,
        "port": port,
        "port_open": False,
        "banner": None,
        "version": None,
        "vulnerabilities": [],
        "configurations": [],
        "anonymous_access": False,
        "directory_listing": [],
        "authentication_attempts": []
    }
    
    # Check if FTP port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.GREEN}[+] FTP port {port} is open{Style.RESET_ALL}")
            results["port_open"] = True
        else:
            print(f"{Fore.RED}[-] FTP port {port} is closed{Style.RESET_ALL}")
            return results
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error checking FTP port: {str(e)}{Style.RESET_ALL}")
        return results
    
    # Get FTP banner
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        print(f"{Fore.BLUE}[*] FTP Banner: {banner}{Style.RESET_ALL}")
        results["banner"] = banner
        
        # Try to extract version information from banner
        version_match = re.search(r'(v[0-9.]+|[0-9.]+)', banner)
        if version_match:
            results["version"] = version_match.group(0)
            print(f"{Fore.BLUE}[*] FTP Version: {results['version']}{Style.RESET_ALL}")
        
        # Check for vulnerable FTP servers based on banner
        known_vulns = {
            'wu-ftpd': {'CVE-2001-0550': 'Remote root vulnerability'},
            'ProFTPD 1.3.3': {'CVE-2010-4221': 'Remote command execution via TELNET IAC buffer overflow'},
            'ProFTPD 1.3.5': {'CVE-2015-3306': 'Unauthenticated copy command vulnerability (mod_copy)'},
            'vsftpd 2.3.4': {'CVE-2011-2523': 'Backdoor vulnerability'},
            'FileZilla Server 0.9.4': {'CVE-2019-9670': 'Directory traversal vulnerability'}
        }
        
        for server, vulns in known_vulns.items():
            if server.lower() in banner.lower():
                for cve, desc in vulns.items():
                    print(f"{Fore.RED}[!] Potentially vulnerable FTP server: {server} - {cve}: {desc}{Style.RESET_ALL}")
                    results["vulnerabilities"].append({
                        "name": f"{server} - {cve}",
                        "severity": "High",
                        "description": desc
                    })
        
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error retrieving FTP banner: {str(e)}{Style.RESET_ALL}")
    
    # Try anonymous login
    print(f"{Fore.BLUE}[*] Checking anonymous access...{Style.RESET_ALL}")
    anonymous_login = False
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port)
        ftp.login('anonymous', 'anonymous@example.com')
        print(f"{Fore.RED}[!] Anonymous FTP login allowed!{Style.RESET_ALL}")
        results["anonymous_access"] = True
        anonymous_login = True
        results["vulnerabilities"].append({
            "name": "Anonymous FTP Access",
            "severity": "Medium",
            "description": "FTP server allows anonymous logins which can lead to information disclosure."
        })
        
        # Try to list directories
        print(f"{Fore.BLUE}[*] Listing directories accessible with anonymous login:{Style.RESET_ALL}")
        dirs = []
        try:
            ftp.retrlines('LIST', lambda x: dirs.append(x))
            if dirs:
                for d in dirs[:10]:  # Limit to first 10 entries to avoid flooding output
                    print(f"{Fore.YELLOW}    {d}{Style.RESET_ALL}")
                if len(dirs) > 10:
                    print(f"{Fore.YELLOW}    ... and {len(dirs) - 10} more entries{Style.RESET_ALL}")
            results["directory_listing"] = dirs
        except Exception as e:
            print(f"{Fore.RED}[-] Error listing directories: {str(e)}{Style.RESET_ALL}")
        
        # Check if we can write to the directory
        try:
            test_file_name = "test_access.txt"
            with open(test_file_name, "w") as test_file:
                test_file.write("FTP write access test")
            
            try:
                with open(test_file_name, "rb") as test_file:
                    try:
                        ftp.storbinary(f"STOR {test_file_name}", test_file)
                        print(f"{Fore.RED}[!] Anonymous FTP write access allowed!{Style.RESET_ALL}")
                        results["vulnerabilities"].append({
                            "name": "Anonymous FTP Write Access",
                            "severity": "Critical",
                            "description": "FTP server allows anonymous users to upload files, which can lead to arbitrary code execution."
                        })
                        
                        # Try to delete the test file
                        try:
                            ftp.delete(test_file_name)
                        except:
                            pass
                    except Exception as e:
                        # Write not allowed, which is good
                        pass
            finally:
                if os.path.exists(test_file_name):
                    os.remove(test_file_name)
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing write access: {str(e)}{Style.RESET_ALL}")
        
        ftp.quit()
    except Exception as e:
        print(f"{Fore.GREEN}[+] Anonymous FTP login not allowed{Style.RESET_ALL}")
        results["configurations"].append({
            "name": "Anonymous Access",
            "value": "Disabled",
            "secure": True
        })
    
    # If brute_force is enabled, check for weak credentials
    if brute_force and not anonymous_login:
        print(f"{Fore.BLUE}[*] Attempting FTP brute force (limited to common credentials){Style.RESET_ALL}")
        
        if not username_list:
            username_list = ["admin", "root", "user", "ftp", "ftpuser", "administrator"]
        
        if not password_list:
            password_list = ["admin", "password", "123456", "ftp", "ftpuser", "pass123", ""]
        
        successful_login = False
        for username in username_list:
            for password in password_list:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port)
                    ftp.login(username, password)
                    print(f"{Fore.RED}[!] Successful login with credentials: {username}:{password}{Style.RESET_ALL}")
                    results["authentication_attempts"].append({
                        "username": username,
                        "password": password,
                        "success": True
                    })
                    results["vulnerabilities"].append({
                        "name": "Weak FTP Credentials",
                        "severity": "High",
                        "description": f"FTP server allows login with weak credentials: {username}:{password}"
                    })
                    successful_login = True
                    ftp.quit()
                    break
                except Exception as e:
                    results["authentication_attempts"].append({
                        "username": username,
                        "password": password,
                        "success": False
                    })
            if successful_login:
                break
    
    # Print summary
    print(f"\n{Fore.BLUE}[*] FTP Scan Summary for {target}:{port}{Style.RESET_ALL}")
    print(f"    - Port open: {results['port_open']}")
    print(f"    - Banner: {results['banner'] or 'None'}")
    print(f"    - Version: {results['version'] or 'Unknown'}")
    print(f"    - Anonymous access: {results['anonymous_access']}")
    
    if results["vulnerabilities"]:
        print(f"\n{Fore.RED}[!] Vulnerabilities found:{Style.RESET_ALL}")
        for vuln in results["vulnerabilities"]:
            print(f"    - {vuln['name']} (Severity: {vuln['severity']})")
            print(f"      {vuln['description']}")
    else:
        print(f"\n{Fore.GREEN}[+] No obvious FTP vulnerabilities detected{Style.RESET_ALL}")
    
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
    
    filename = os.path.join(save_dir, f"ftp_scan_{results['target']}.json")
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="FTP Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
    parser.add_argument("--brute-force", action="store_true", help="Attempt brute force techniques")
    parser.add_argument("--userlist", type=str, help="File containing usernames for brute force")
    parser.add_argument("--passlist", type=str, help="File containing passwords for brute force")
    parser.add_argument("--save-dir", default="results", help="Directory to save results")
    
    args = parser.parse_args()
    
    # Load username and password lists if provided
    username_list = None
    password_list = None
    
    if args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                username_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading username list: {str(e)}{Style.RESET_ALL}")
    
    if args.passlist:
        try:
            with open(args.passlist, 'r') as f:
                password_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading password list: {str(e)}{Style.RESET_ALL}")
    
    results = scan_ftp(args.target, args.port, args.brute_force, username_list, password_list)
    save_results(results, args.save_dir) 