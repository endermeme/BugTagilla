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