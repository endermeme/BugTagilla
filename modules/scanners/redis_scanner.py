#!/usr/bin/env python3
import socket
import json
import os
import time
from colorama import Fore, Style, init

# Initialize colorama
init()

def scan_redis(target, port=6379, brute_force=False):
    """
    Scan Redis service for vulnerabilities and misconfigurations
    
    Args:
        target (str): Target IP address or hostname
        port (int): Redis port (default: 6379)
        brute_force (bool): Whether to attempt brute force techniques
        
    Returns:
        dict: Results of the scan
    """
    print(f"\n{Fore.BLUE}[*] Starting Redis scan on {target}:{port}{Style.RESET_ALL}")
    
    results = {
        "target": target,
        "port": port,
        "port_open": False,
        "version": None,
        "vulnerabilities": [],
        "configurations": [],
        "auth_required": None,
        "commands_executed": []
    }
    
    # Check if Redis port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.GREEN}[+] Redis port {port} is open{Style.RESET_ALL}")
            results["port_open"] = True
        else:
            print(f"{Fore.RED}[-] Redis port {port} is closed{Style.RESET_ALL}")
            return results
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error checking Redis port: {str(e)}{Style.RESET_ALL}")
        return results
    
    # Check if authentication is required
    print(f"{Fore.BLUE}[*] Checking if Redis requires authentication...{Style.RESET_ALL}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        
        # Send INFO command
        sock.send(b"INFO\r\n")
        response = sock.recv(1024)
        
        if b"-NOAUTH" in response:
            print(f"{Fore.GREEN}[+] Redis requires authentication{Style.RESET_ALL}")
            results["auth_required"] = True
            results["configurations"].append({
                "name": "Authentication",
                "value": "Required",
                "secure": True
            })
        else:
            print(f"{Fore.RED}[!] Redis does NOT require authentication!{Style.RESET_ALL}")
            results["auth_required"] = False
            results["configurations"].append({
                "name": "Authentication",
                "value": "Not Required",
                "secure": False
            })
            results["vulnerabilities"].append({
                "name": "No Authentication",
                "severity": "High",
                "description": "Redis server does not require authentication, allowing anyone to access the database."
            })
            
            # Extract version from INFO response
            if b"redis_version" in response:
                try:
                    version_line = response.split(b"\r\n")[1]
                    version = version_line.decode().split(":")[1]
                    results["version"] = version
                    print(f"{Fore.BLUE}[*] Redis version: {version}{Style.RESET_ALL}")
                except:
                    pass
            
            # Check for config command availability
            print(f"{Fore.BLUE}[*] Checking if CONFIG command is available...{Style.RESET_ALL}")
            sock.send(b"CONFIG GET dir\r\n")
            response = sock.recv(1024)
            
            if not b"-ERR" in response:
                print(f"{Fore.RED}[!] CONFIG command is available without authentication!{Style.RESET_ALL}")
                results["vulnerabilities"].append({
                    "name": "CONFIG Command Available",
                    "severity": "Critical",
                    "description": "The CONFIG command is available without authentication, which can be used for data exfiltration or remote code execution."
                })
                results["commands_executed"].append("CONFIG GET dir")
            
            # Check for potentially dangerous commands
            print(f"{Fore.BLUE}[*] Checking for potentially dangerous commands...{Style.RESET_ALL}")
            dangerous_commands = [
                b"FLUSHALL\r\n",  # We don't actually execute this, just check if available
                b"KEYS *\r\n",
                b"CLIENT LIST\r\n"
            ]
            
            dangerous_command_results = []
            for cmd in dangerous_commands:
                cmd_name = cmd.decode().strip()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                
                # Don't execute FLUSHALL, just check if it's available
                if cmd == b"FLUSHALL\r\n":
                    sock.send(b"COMMAND INFO FLUSHALL\r\n")
                else:
                    sock.send(cmd)
                
                response = sock.recv(4096)
                
                if not b"-ERR" in response:
                    dangerous_command_results.append(cmd_name)
                    # Add KEYS and CLIENT LIST to executed commands
                    if cmd != b"FLUSHALL\r\n":
                        results["commands_executed"].append(cmd_name)
                
                sock.close()
            
            if dangerous_command_results:
                print(f"{Fore.RED}[!] Dangerous commands available: {', '.join(dangerous_command_results)}{Style.RESET_ALL}")
                results["vulnerabilities"].append({
                    "name": "Dangerous Commands Available",
                    "severity": "High",
                    "description": f"The following dangerous commands are available without authentication: {', '.join(dangerous_command_results)}"
                })
            
            # Check for Redis RCE via master-slave replication
            if brute_force:
                print(f"{Fore.BLUE}[*] Checking for Redis RCE via master-slave replication...{Style.RESET_ALL}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                # Only simulate this check - don't actually exploit!
                print(f"{Fore.YELLOW}[i] This check would attempt the master-slave replication technique but is only simulated for safety{Style.RESET_ALL}")
                sock.close()
        
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error during Redis checks: {str(e)}{Style.RESET_ALL}")
    
    # Print summary
    print(f"\n{Fore.BLUE}[*] Redis Scan Summary for {target}:{port}{Style.RESET_ALL}")
    print(f"    - Port open: {results['port_open']}")
    print(f"    - Authentication required: {results['auth_required']}")
    print(f"    - Redis version: {results['version'] or 'Unknown'}")
    
    if results["vulnerabilities"]:
        print(f"\n{Fore.RED}[!] Vulnerabilities found:{Style.RESET_ALL}")
        for vuln in results["vulnerabilities"]:
            print(f"    - {vuln['name']} (Severity: {vuln['severity']})")
            print(f"      {vuln['description']}")
    else:
        print(f"\n{Fore.GREEN}[+] No obvious Redis vulnerabilities detected{Style.RESET_ALL}")
    
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
    
    filename = os.path.join(save_dir, f"redis_scan_{results['target']}.json")
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Redis Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=6379, help="Redis port (default: 6379)")
    parser.add_argument("--brute-force", action="store_true", help="Attempt brute force techniques")
    parser.add_argument("--save-dir", default="results", help="Directory to save results")
    
    args = parser.parse_args()
    
    results = scan_redis(args.target, args.port, args.brute_force)
    save_results(results, args.save_dir) 