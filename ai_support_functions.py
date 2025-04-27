import os
import json
import time
import sys
import random
import requests
from colorama import Fore, Style, init
import openai

# Add dotenv import and load
try:
    from dotenv import load_dotenv
    # Load environment variables from .env file
    load_dotenv()
except ImportError:
    print(f"dotenv package not installed. Environment variables from .env file will not be loaded.")
    print(f"Install with: pip install python-dotenv")

class AISupportFunctions:
    """Class to handle all AI-related functionality"""
    
    def __init__(self, api_key=None):
        """Initialize the API key and validate it"""
        self.api_key = api_key
        self.api_initialized = False
        
        # Validate the API key
        try:
            if self.api_key:
                import openai
                openai.api_key = self.api_key
                self.client = openai.OpenAI(api_key=self.api_key)
                self.api_initialized = True
                print(f"{Fore.GREEN}[+] API key validated and initialized{Style.RESET_ALL}")
            else:
                # Try to get API key from environment if not provided
                try:
                    import os
                    import openai
                    self.api_key = os.environ.get("OPENAI_API_KEY")
                    if self.api_key:
                        openai.api_key = self.api_key
                        self.client = openai.OpenAI(api_key=self.api_key)
                        self.api_initialized = True
                        print(f"{Fore.GREEN}[+] Using API key from environment{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[!] No API key provided. AI features will be limited.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error initializing API from environment: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error validating API key: {str(e)}{Style.RESET_ALL}")
    
    def analyze_scan(self, target, scan_data, focus="all", max_threads=10):
        """Analyze scan data with AI"""
        if not self.api_initialized:
            print(f"{Fore.RED}[!] API not initialized. Cannot perform AI analysis.{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[+] Analyzing scan data for {target} with AI...{Style.RESET_ALL}")
        # To be implemented
        
    def run_ai_security_scan(self, target, focus="all", max_threads=10):
        """Run a security-focused AI scan"""
        if not self.api_initialized:
            print(f"{Fore.RED}[!] API not initialized. Cannot perform AI scan.{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[+] Running AI security scan on {target}...{Style.RESET_ALL}")
        # To be implemented
    
    def generate_workflow(self, target, focus="all"):
        """Generate an AI-optimized workflow for pentesting"""
        if not self.api_initialized:
            print(f"{Fore.RED}[!] API not initialized. Cannot generate workflow.{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[+] Generating AI-optimized workflow for {target}...{Style.RESET_ALL}")
        # To be implemented
        
    def run_ai_bug_bounty(self, target, focus="all", max_threads=10, output_format="simple", ai_model="gpt-4o-mini", findings_data=None):
        """Run AI-powered bug bounty analysis on a target"""
        if not self.api_initialized:
            print(f"{Fore.RED}[!] API not initialized. Cannot perform bug bounty analysis.{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[+] Running AI bug bounty analysis on {target}...{Style.RESET_ALL}")
        
        # Check if we have real findings data
        if findings_data is None:
            print(f"{Fore.YELLOW}[!] No findings data provided. Running scan first...{Style.RESET_ALL}")
            
            try:
                # Import here to avoid circular imports
                from spyhunt import run_comprehensive_scan
                import os
                import json
                
                # Run comprehensive scan to gather data
                print(f"{Fore.CYAN}[+] Starting comprehensive scan for bug bounty analysis on {target}{Style.RESET_ALL}")
                
                # Run the scan
                findings_file = run_comprehensive_scan(
                    target=target,
                    output_dir=".",
                    max_threads=max_threads,
                    ai_model=ai_model,
                    auto_explore=True
                )
                
                # Load the findings data
                if findings_file and os.path.exists(findings_file):
                    with open(findings_file, 'r') as f:
                        findings_data = json.load(f)
                    print(f"{Fore.GREEN}[+] Scan completed successfully. Analyzing results...{Style.RESET_ALL}")
                else:
                    return {"error": "Scan failed to produce valid results. Please check for errors."}
            except Exception as e:
                print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
                return {"error": f"Error while running scan: {str(e)}"}
        
        # Run AI analysis on the real findings data
        results = self.analyze_with_ai(target, findings_data, focus, ai_model)
        
        # Format and return results
        if output_format == "simple":
            return self.format_simple_output(results)
        elif output_format == "json":
            return results
        else:
            return self.format_detailed_output(results)
    
    def analyze_with_ai(self, target, findings_data, focus="all", ai_model="gpt-4o-mini"):
        """Analyze security posture with AI"""
        print(f"{Fore.CYAN}[+] Creating AI prompt based on findings...{Style.RESET_ALL}")
        
        # Create prompt for AI analysis
        prompt = f"""Analyze the following security reconnaissance data for {target} for bug bounty hunting purposes.
Focus on identifying high-value vulnerabilities and security issues that would be relevant in a bug bounty context.
For each vulnerability or finding, provide:
1. Severity (Critical, High, Medium, Low)
2. Description of the issue
3. Potential impact
4. Steps to exploit or confirm
5. Remediation advice

Here is the collected data:
"""
        
        # Add subdomain information
        if findings_data.get("subdomains") and len(findings_data["subdomains"]) > 0:
            prompt += "\n## Subdomains Found:\n"
            for subdomain in findings_data["subdomains"][:30]:  # Limit to first 30 to avoid token limits
                prompt += f"- {subdomain}\n"
            if len(findings_data["subdomains"]) > 30:
                prompt += f"- ... and {len(findings_data['subdomains']) - 30} more subdomains\n"
        
        # Add port scan information
        if findings_data.get("port_scan") and len(findings_data["port_scan"]) > 0:
            prompt += "\n## Open Ports and Services:\n"
            for host, ports in list(findings_data["port_scan"].items())[:10]:  # Limit to first 10 hosts
                prompt += f"### {host}:\n"
                for port_info in ports[:10]:  # Limit to first 10 ports per host
                    prompt += f"- {port_info}\n"
        
        # Add vulnerability information
        if findings_data.get("vulnerabilities") and len(findings_data["vulnerabilities"]) > 0:
            prompt += "\n## Detected Vulnerabilities:\n"
            for vuln in findings_data["vulnerabilities"]:
                prompt += f"- {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'Unknown')}): {vuln.get('description', 'No description')} at {vuln.get('url', 'No URL')}\n"
        
        # Add summary of other findings
        prompt += f"\n## Additional Information:\n"
        prompt += f"- Number of URLs crawled: {len(findings_data.get('site_links', []))}\n"
        prompt += f"- Number of parameters discovered: {len(findings_data.get('parameters', []))}\n"
        prompt += f"- Number of JavaScript files: {len(findings_data.get('js_files', []))}\n"
        prompt += f"- CORS issues detected: {len(findings_data.get('cors_checks', []))}\n"
        prompt += f"- Host header injection issues: {len(findings_data.get('host_header_checks', []))}\n"
        
        # Add final instructions
        prompt += """
Based on this data, provide the following:
1. A prioritized list of security findings that would be valuable in a bug bounty context
2. Additional attack vectors that should be explored based on the findings
3. Specific recommendations for further testing and exploitation
4. Suggested tools or commands to run next for maximum bug bounty success
"""
        
        print(f"{Fore.CYAN}[+] Sending data to AI for analysis...{Style.RESET_ALL}")
        
        try:
            response = self.client.chat.completions.create(
                model=ai_model,
                messages=[
                    {"role": "system", "content": "You are an elite bug bounty hunter and security professional. Your job is to analyze reconnaissance data and identify high-value security vulnerabilities. Be thorough, practical and focus on actionable findings."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )
            
            ai_analysis = response.choices[0].message.content
            
            # Process the AI output to extract structured information
            return self.analyze_scan_data(ai_analysis, findings_data, target)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during AI analysis: {str(e)}{Style.RESET_ALL}")
            return {"error": str(e)}
    
    def analyze_scan_data(self, ai_analysis, original_findings, target):
        """Process AI output and merge with original findings data"""
        print(f"{Fore.CYAN}[+] Processing AI analysis results...{Style.RESET_ALL}")
        
        # Start with a structured result that includes original data summaries
        results = {
            "target": target,
            "scan_time": original_findings.get("scan_time", time.strftime("%Y-%m-%d %H:%M:%S")),
            "findings_summary": {
                "total_subdomains": len(original_findings.get("subdomains", [])),
                "total_urls": len(original_findings.get("site_links", [])),
                "total_parameters": len(original_findings.get("parameters", [])),
                "total_js_files": len(original_findings.get("js_files", [])),
                "total_vulnerabilities": len(original_findings.get("vulnerabilities", [])),
            },
            "ai_analysis": {
                "security_findings": [],
                "attack_vectors": [],
                "recommendations": [],
                "suggested_tools": []
            },
            "raw_ai_output": ai_analysis
        }
        
        # Extract structured data from AI analysis
        try:
            # First try to extract findings
            import re
            
            # Look for security findings section
            findings_section = re.search(r"(?:SECURITY FINDINGS|PRIORITIZED.*?FINDINGS):?.*?(?:\n\d+\.|\n#|\n-)(.*?)(?:\n\n\d+\.|\n\n#|\n\nADDITIONAL|$)", ai_analysis, re.DOTALL | re.IGNORECASE)
            if findings_section:
                findings_text = findings_section.group(1)
                # Extract individual findings
                findings_items = re.findall(r"(?:\n\d+\.|\n-)(.*?)(?=\n\d+\.|\n-|\n\n|$)", findings_text, re.DOTALL)
                for item in findings_items:
                    # Try to extract severity
                    severity_match = re.search(r"(?:severity|priority):\s*(\w+)", item, re.IGNORECASE)
                    severity = severity_match.group(1) if severity_match else "Unknown"
                    
                    # Extract the main finding text
                    finding = item.strip()
                    
                    # Add to structured results
                    results["ai_analysis"]["security_findings"].append({
                        "severity": severity,
                        "finding": finding
                    })
            
            # Look for attack vectors section
            vectors_section = re.search(r"(?:ADDITIONAL ATTACK VECTORS|ATTACK VECTORS):?.*?(?:\n\d+\.|\n#|\n-)(.*?)(?:\n\n\d+\.|\n\n#|\n\nRECOMMENDATIONS|$)", ai_analysis, re.DOTALL | re.IGNORECASE)
            if vectors_section:
                vectors_text = vectors_section.group(1)
                # Extract individual vectors
                vector_items = re.findall(r"(?:\n\d+\.|\n-)(.*?)(?=\n\d+\.|\n-|\n\n|$)", vectors_text, re.DOTALL)
                for item in vector_items:
                    results["ai_analysis"]["attack_vectors"].append(item.strip())
            
            # Look for recommendations section
            recommendations_section = re.search(r"(?:SPECIFIC RECOMMENDATIONS|RECOMMENDATIONS):?.*?(?:\n\d+\.|\n#|\n-)(.*?)(?:\n\n\d+\.|\n\n#|\n\nSUGGESTED|$)", ai_analysis, re.DOTALL | re.IGNORECASE)
            if recommendations_section:
                recommendations_text = recommendations_section.group(1)
                # Extract individual recommendations
                recommendation_items = re.findall(r"(?:\n\d+\.|\n-)(.*?)(?=\n\d+\.|\n-|\n\n|$)", recommendations_text, re.DOTALL)
                for item in recommendation_items:
                    results["ai_analysis"]["recommendations"].append(item.strip())
            
            # Look for suggested tools section
            tools_section = re.search(r"(?:SUGGESTED TOOLS|TOOLS):?.*?(?:\n\d+\.|\n#|\n-)(.*?)(?:\n\n\d+\.|\n\n#|$)", ai_analysis, re.DOTALL | re.IGNORECASE)
            if tools_section:
                tools_text = tools_section.group(1)
                # Extract individual tools
                tool_items = re.findall(r"(?:\n\d+\.|\n-)(.*?)(?=\n\d+\.|\n-|\n\n|$)", tools_text, re.DOTALL)
                for item in tool_items:
                    # Try to extract command
                    command_match = re.search(r"```(.+?)```", item, re.DOTALL)
                    command = command_match.group(1).strip() if command_match else None
                    
                    tool_item = {
                        "description": item.strip(),
                        "command": command
                    }
                    
                    results["ai_analysis"]["suggested_tools"].append(tool_item)
            
            # If we couldn't extract structured data properly, provide a fallback
            if not results["ai_analysis"]["security_findings"] and not results["ai_analysis"]["attack_vectors"]:
                print(f"{Fore.YELLOW}[!] Couldn't extract structured data from AI output. Using raw output.{Style.RESET_ALL}")
                # Add some basic structure
                results["ai_analysis"]["security_findings"] = [{"severity": "Unknown", "finding": "See raw AI output"}]
                results["ai_analysis"]["attack_vectors"] = ["See raw AI output"]
                results["ai_analysis"]["recommendations"] = ["See raw AI output"]
                results["ai_analysis"]["suggested_tools"] = [{"description": "See raw AI output", "command": None}]
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error processing AI analysis: {str(e)}{Style.RESET_ALL}")
            # Add error information
            results["processing_error"] = str(e)
        
        # Add select original findings for context
        results["vulnerable_endpoints"] = self.extract_relevant_data(original_findings)
        
        return results
    
    def extract_relevant_data(self, findings):
        """Extract relevant data from findings for bug bounty purposes"""
        
        # Initialize data structure
        relevant_data = {
            "vulnerable_urls": [],
            "interesting_parameters": [],
            "sensitive_endpoints": [],
            "interesting_technologies": []
        }
        
        # Extract vulnerable URLs from findings
        if findings.get("vulnerabilities"):
            for vuln in findings["vulnerabilities"]:
                url = vuln.get("url")
                if url and url not in relevant_data["vulnerable_urls"]:
                    relevant_data["vulnerable_urls"].append({
                        "url": url,
                        "vulnerability": vuln.get("name", "Unknown"),
                        "severity": vuln.get("severity", "Unknown")
                    })
        
        # Extract interesting parameters
        if findings.get("parameters"):
            for param_url in findings["parameters"]:
                # Look for interesting parameter names
                interesting_params = ["token", "key", "api", "pass", "user", "admin", "auth", "jwt", "id", "file", 
                                    "path", "dir", "name", "load", "upload", "redirect", "url", "callback"]
                
                for param in interesting_params:
                    if param in param_url.lower():
                        relevant_data["interesting_parameters"].append({
                            "url": param_url,
                            "reason": f"Contains potential {param} parameter"
                        })
                        break
        
        # Extract sensitive endpoints
        if findings.get("site_links"):
            sensitive_patterns = ["/api/", "/admin", "/dashboard", "/console", "/manage", "/upload", "/login", 
                                "/logout", "/register", "/auth", "/oauth", "/settings", "/config", 
                                "/backup", "/dev", "/debug", "/test"]
            
            for url in findings["site_links"]:
                for pattern in sensitive_patterns:
                    if pattern in url:
                        relevant_data["sensitive_endpoints"].append({
                            "url": url,
                            "pattern": pattern
                        })
                        break
        
        # Extract technologies from port scan data
        if findings.get("port_scan"):
            for host, ports in findings["port_scan"].items():
                for port_info in ports:
                    # Check for interesting services
                    interesting_techs = ["jenkins", "tomcat", "jboss", "weblogic", "websphere", "iis", "apache", 
                                        "nginx", "php", "wordpress", "drupal", "joomla", "django", "rails", 
                                        "laravel", "spring", "nodejs", "docker", "kubernetes", "mqtt", "ftp", 
                                        "telnet", "ssh", "postgresql", "mysql", "mongodb", "redis", "memcached"]
                    
                    for tech in interesting_techs:
                        if tech in port_info.lower():
                            relevant_data["interesting_technologies"].append({
                                "host": host,
                                "technology": tech,
                                "port_info": port_info
                            })
                            break
        
        return relevant_data
    
    def format_simple_output(self, results):
        """Format the results as a simple output format"""
        if "error" in results:
            return results
        
        simple_output = {
            "target": results.get("target", ""),
            "scan_time": results.get("scan_time", ""),
            "high_value_findings": [],
            "suggested_next_steps": [],
            "raw_ai_available": True
        }
        
        # Extract high value findings
        for finding in results.get("ai_analysis", {}).get("security_findings", []):
            if finding.get("severity", "").lower() in ["critical", "high"]:
                simple_output["high_value_findings"].append(finding)
        
        # If no high value findings, include medium ones or all
        if not simple_output["high_value_findings"]:
            for finding in results.get("ai_analysis", {}).get("security_findings", []):
                if finding.get("severity", "").lower() == "medium":
                    simple_output["high_value_findings"].append(finding)
            
            # If still no findings, include all
            if not simple_output["high_value_findings"]:
                simple_output["high_value_findings"] = results.get("ai_analysis", {}).get("security_findings", [])
        
        # Add suggested next steps (tools and recommendations)
        for tool in results.get("ai_analysis", {}).get("suggested_tools", []):
            if tool.get("command"):
                simple_output["suggested_next_steps"].append({
                    "type": "command",
                    "description": tool.get("description", ""),
                    "command": tool.get("command")
                })
        
        for rec in results.get("ai_analysis", {}).get("recommendations", [])[:3]:  # Limit to top 3
            simple_output["suggested_next_steps"].append({
                "type": "recommendation",
                "description": rec
            })
        
        return simple_output
    
    def format_detailed_output(self, results):
        """Format the results as a detailed output format"""
        if "error" in results:
            return results
        
        # The detailed output includes everything
        return results
    
    def save_to_file(self, results, output_file=None):
        """Save results to a file"""
        if not output_file:
            # Generate a filename if not provided
            if "target" in results:
                target = results["target"].replace(".", "_")
                output_file = f"ai_bug_bounty_{target}.json"
            else:
                output_file = f"ai_bug_bounty_results.json"
        
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
            return output_file
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results to file: {str(e)}{Style.RESET_ALL}")
            return None 