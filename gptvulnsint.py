import re
import asyncio
import aiohttp
import requests
import webbrowser
import socket
import time
import logging
import os
from datetime import datetime
from urllib.parse import quote, urljoin
from ipaddress import ip_address
from collections import defaultdict
from colorama import init, Fore, Back, Style
from bs4 import BeautifulSoup
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

init(autoreset=True)
logging.basicConfig(
    filename='gptvulnsint.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def print_banner():
    print(Fore.YELLOW + "="*11)
    print(Fore.GREEN + r"GPTVULNSINT")
    print(Fore.YELLOW + "="*11)
    print()
    print(Fore.CYAN + "GPTVULNSINT v5.5 - Professional OSINT Framework")
    print(Fore.RED + "Author: ANONUM228 | For educational purposes only!")
    print()

def safe_open_url(url, description="url"):
    try:
        print(Fore.YELLOW + f"Opening {description}...")
        webbrowser.open(url)
        logging.info(f"Opened {description}: {url}")
        time.sleep(0.3)
        return True
    except Exception as e:
        logging.error(f"Error opening {description}: {e}")
        print(Fore.RED + f"Error opening {description}: {e}")
        return False

def is_global_ip(url):
    try:
        parsed_url = url.replace('https://', '').replace('http://', '')
        hostname = parsed_url.split('/')[0].split(':')[0]
        
        if hostname.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return False
            
        internal_domains = ['.local', '.internal', '.corp', '.lan', '.home']
        if any(hostname.lower().endswith(domain) for domain in internal_domains):
            return False
            
        ip = socket.gethostbyname(hostname)
        ip_obj = ip_address(ip)
        
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            print(Fore.RED + f"[-] BLOCKED: Private/reserved IP {ip}")
            return False
            
        return True
        
    except (socket.gaierror, ValueError):
        return True  
    except Exception:
        return True
    
async def fetch_url_async(session, url, timeout=10):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            if response.status == 200:
                return await response.text()
            return None
    except Exception as e:
        print(Fore.RED + f"Failed to fetch {url[:50]}...: {e}")
        return None

async def scan_js_files_async(base_url, js_urls, max_files=5):
    all_js_content = []
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for js_url in js_urls[:max_files]:
            if js_url.startswith('//'):
                js_url = 'https:' + js_url
            elif js_url.startswith('/'):
                js_url = urljoin(base_url, js_url)
            elif not js_url.startswith('http'):
                continue
                
            tasks.append(fetch_url_async(session, js_url, 5))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, content in enumerate(results):
            if content and isinstance(content, str):
                all_js_content.append(content)
                
    return all_js_content

class GPTVULNSINT:
    def __init__(self):
        self.scan_results = []
        print(Fore.GREEN + "[+] Framework initialized successfully!")
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        
    def freecampdev(self):
        url = "https://freecamp.dev/tools/network/subdomains"
        self.scan_results.append("FreeCampDev: Subdomain search opened")
        safe_open_url(url, "FreeCampDev")
        
    def scan(self):
        target_url = input(Fore.CYAN + "Enter url: ").strip()
        
        if not target_url.startswith('http'):
            target_url = 'https://' + target_url
            
        if not is_global_ip(target_url):
            print(Fore.RED + "SECURITY BLOCK: Target is internal/local")
            self.scan_results.append(f"URL Scan: {target_url} - BLOCKED")
            return
            
        try:
            response = requests.get(target_url, timeout=10)
            links = re.findall(r'href=["\'](https?://[^"\']+)', response.text)
            clean_links = [link for link in links if re.match(r'^https?://', link)]
            
            print(Fore.GREEN + f"\n[+] Found {len(clean_links)} external links:")
            for i, link in enumerate(sorted(set(clean_links))[:15], 1):
                print(Fore.CYAN + f"  {i:2}. {link}")
                
            if len(clean_links) > 15:
                print(Fore.YELLOW + f"  ... and {len(clean_links) - 15} more")
                
            self.scan_results.append(f"URL Scan: {target_url} - Found {len(clean_links)} links")
            
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def publicwww(self):
        try:
            dork = input(Fore.CYAN + "Enter search dork: ").strip()
            encoded = quote(dork)
            url = f"https://publicwww.com/websites/{encoded}"
            self.scan_results.append(f"PublicWWW Search: {dork}")
            safe_open_url(url, "PublicWWW")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def censys(self):
        try:
            query = input(Fore.CYAN + "Enter Censys query: ").strip()
            encoded = quote(query)
            url = f"https://search.censys.io/search?q={encoded}"
            self.scan_results.append(f"Censys Search: {query}")
            safe_open_url(url, "Censys")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def intelx(self):
        try:
            query = input(Fore.CYAN + "Enter IntelX query: ").strip()
            encoded = quote(query)
            url = f"https://intelx.io/?s={encoded}"
            self.scan_results.append(f"IntelX Search: {query}")
            safe_open_url(url, "IntelX")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def crt(self):
        try:
            domain = input(Fore.CYAN + "Enter domain: ").strip()
            url = f"https://crt.sh/?q=%.{domain}"
            self.scan_results.append(f"crt.sh Search: {domain}")
            safe_open_url(url, "crt.sh")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def suip(self):
        try:
            target = input(Fore.CYAN + "Enter domain/IP: ").strip()
            url = f"https://suip.biz/ru/?act=hostmap&host={target}"
            self.scan_results.append(f"suip Search: {target}")
            safe_open_url(url, "suip.biz")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def whois(self):
        try:
            domain = input(Fore.CYAN + "Enter domain: ").strip()
            url = f"https://www.reg.ru/whois/?dname={domain}"
            self.scan_results.append(f"Whois Lookup: {domain}")
            safe_open_url(url, "Whois")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def headers(self):
        try:
            url = input(Fore.CYAN + "Enter url: ").strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            response = requests.get(url, timeout=10)
            print(Fore.GREEN + f"\n[+] Headers for {url} (Status: {response.status_code}):")
            
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options',
                              'Strict-Transport-Security', 'Content-Security-Policy',
                              'X-XSS-Protection', 'Referrer-Policy']
            
            for header, value in response.headers.items():
                if header in security_headers:
                    print(Fore.CYAN + f"{header}: {value}")
                else:
                    print(Fore.WHITE + f"{header}: {value}")
                    
            missing = [h for h in security_headers if h not in response.headers]
            if missing:
                print(Fore.RED + f"\nMissing security headers: {', '.join(missing)}")
                
            self.scan_results.append(f"Header Analysis: {url} - Status {response.status_code}")
            
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def vulners(self):
        try:
            query = input(Fore.CYAN + "Enter vuln query: ").strip()
            encoded = quote(query)
            url = f"https://vulners.com/search?query={encoded}"
            self.scan_results.append(f"Vulners Search: {query}")
            safe_open_url(url, "Vulners")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def wp_scanner(self):
        url = "https://hackertarget.com/wordpress-security-scan/"
        print(Fore.YELLOW + "Note: Paste target URL manually in the browser")
        self.scan_results.append("WordPress Scanner opened")
        safe_open_url(url, "WordPress Scanner")
        
    def phind(self):
        url = "https://www.phind.com/"
        self.scan_results.append("Phind AI Search opened")
        safe_open_url(url, "Phind")
        
    async def sensitive_data_scan_async(self):
        
        target_url = input(Fore.CYAN + "Enter URL to scan: ").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        print(Fore.YELLOW + f"\n[⚡] Starting FAST sensitive data scan for: {target_url}")
        
        patterns = {
            "AWS_ACCESS_KEY": r'AKIA[0-9A-Z]{16}',
            "AWS_SECRET_KEY": r'aws[^"\']*["\']([0-9a-zA-Z/+]{40})["\']',
            "STRIPE_SECRET_KEY": r'sk_live_[0-9a-zA-Z]{24}',
            "DATABASE_URL": r'(postgres|mysql|mongodb)://[^:]+:[^@]+@',
            "GITHUB_TOKEN": r'gh(p|o|u|s|r)_[0-9a-zA-Z]{36}',
            "TWILIO_API_KEY": r'SK[0-9a-fA-F]{32}',
            "JWT_TOKEN": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}',
            "API_KEY_GENERIC": r'["\'][0-9a-zA-Z\-_]{20,50}["\']',
            "PASSWORD": r'password["\']?\s*[=:]\s*["\']([^"\']{8,50})["\']',
            "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        }
        
        try:
            print(Fore.YELLOW + "[+] Fetching main page...")
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=15) as response:
                    if response.status != 200:
                        print(Fore.RED + f"[-] HTTP Error: {response.status}")
                        return
                    
                    html_content = await response.text()
            
            print(Fore.YELLOW + "[+] Parsing for JavaScript files...")
            soup = BeautifulSoup(html_content, 'html.parser')
            
            text_content = soup.get_text()
            lines = [line.strip() for line in text_content.splitlines() if line.strip()]
            text_to_scan = "\n".join(lines[:500])  
            
            js_urls = []
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = urljoin(target_url, src)
                    elif not src.startswith('http'):
                        continue
                    js_urls.append(src)
            
            print(Fore.YELLOW + f"Found {len(js_urls)} JavaScript files")
            
            js_contents = []
            if js_urls:
                js_contents = await scan_js_files_async(target_url, js_urls, max_files=3)
                print(Fore.YELLOW + f"Loaded {len(js_contents)} JS files")
            
            all_content = text_to_scan
            for js_content in js_contents:
                all_content += "\n" + js_content[:1000]
            
            print(Fore.YELLOW + f"Total content to scan: {len(all_content):,} characters")
            
            print(Fore.YELLOW + "Scanning for secrets (timeout: 10 seconds)...")
            
            results = defaultdict(list)
            start_time = time.time()
            
            for name, pattern in patterns.items():
                if time.time() - start_time > 10:  
                    print(Fore.YELLOW + "Scan timeout reached, stopping...")
                    break
                
                try:
                    matches = re.finditer(pattern, all_content, re.IGNORECASE)
                    count = 0
                    for match in matches:
                        if count >= 10:  
                            break
                        
                        value = match.group(0)
                        if match.lastindex:
                            value = match.group(match.lastindex)
                        
                        if self._is_test_data(value):
                            continue
                        
                        display_val = value[:30] + "..." if len(value) > 30 else value
                        results[name].append(display_val)
                        count += 1
                        
                except Exception as e:
                    continue
            
            print(Fore.GREEN + "\n" + "="*60)
            print(Fore.YELLOW + "🔐 Scan results:")
            print(Fore.GREEN + "="*60)
            
            total_found = sum(len(v) for v in results.values())
            
            if total_found == 0:
                print(Fore.GREEN + "No secrets found (scan completed in 10s)")
            else:
                critical = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "STRIPE_SECRET_KEY", "DATABASE_URL"]
                high = ["GITHUB_TOKEN", "TWILIO_API_KEY"]
                medium = ["JWT_TOKEN", "API_KEY_GENERIC", "PASSWORD"]
                
                for risk_level, pattern_names in [("🔴 CRITICAL", critical), 
                                                 ("🟠 HIGH", high), 
                                                 ("🟡 MEDIUM", medium)]:
                    found_items = []
                    for name in pattern_names:
                        if name in results:
                            found_items.extend(results[name])
                    
                    if found_items:
                        color = {"🔴 CRITICAL": Fore.RED, "🟠 HIGH": Fore.YELLOW, "🟡 MEDIUM": Fore.MAGENTA}[risk_level]
                        print(color + f"\n{risk_level} ({len(found_items)} found):")
                        for i, item in enumerate(found_items[:3], 1):
                            print(color + f"  {i}. {item}")
                        if len(found_items) > 3:
                            print(color + f"  ... and {len(found_items)-3} more")
                
                print(Fore.RED + f"\nTotal secrets found: {total_found}")
                print(Fore.YELLOW + f"Scan completed in {time.time() - start_time:.1f} seconds")
            
            print(Fore.GREEN + "="*60)
            
            self.scan_results.append(f"Fast Secrets Scan: {target_url} - Found {total_found} secrets")
            
            if results:
                self._quick_save_results(target_url, results)
                
        except asyncio.TimeoutError:
            print(Fore.RED + "[-] Scan timeout: Operation took too long")
        except Exception as e:
            print(Fore.RED + f"[-] Scan error: {str(e)[:100]}")
    
    def sensitive_data_scan(self):
        asyncio.run(self.sensitive_data_scan_async())
    
    def _is_test_data(self, value):
        test_words = ['test', 'example', 'demo', 'fake', 'placeholder', 'xxx', 'aaa']
        return any(word in value.lower() for word in test_words)
    
    def _quick_save_results(self, url, results):
        try:
            filename = f"scan_{datetime.now().strftime('%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(f"Scan: {url}\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n")
                
                for name, items in results.items():
                    if items:
                        f.write(f"\n{name} ({len(items)}):\n")
                        for item in items:
                            f.write(f"  - {item}\n")
            
            print(Fore.GREEN + f"Quick report saved: {filename}")
        except:
            pass
    
    def kaspersky(self):
        try:
            query = input(Fore.CYAN + "Enter hash/IP/domain: ").strip()
            url = f"https://opentip.kaspersky.com/{query}/"
            self.scan_results.append(f"Kaspersky Check: {query}")
            safe_open_url(url, "Kaspersky")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def metadefender(self):
        try:
            query = input(Fore.CYAN + "Enter hash/url: ").strip()
            url = f"https://metadefender.opswat.com/results?input={query}"
            self.scan_results.append(f"MetaDefender Check: {query}")
            safe_open_url(url, "MetaDefender")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def malwarebazaar(self):
        url = "https://bazaar.abuse.ch/browse/"
        self.scan_results.append("MalwareBazaar opened")
        safe_open_url(url, "MalwareBazaar")
        
    def virustotal(self):
        url = "https://www.virustotal.com/gui/home/search"
        self.scan_results.append("VirusTotal opened")
        safe_open_url(url, "VirusTotal")
        
    def epieos(self):
    
        url = "https://epieos.com/"
        self.scan_results.append("EpieOS opened")
        safe_open_url(url, "Epieos")
        
    def email_parse(self):
        url = input(Fore.CYAN + "Enter website url: ").strip()
        if not url.startswith('http'):
            url = 'https://' + url
            
        print(Fore.YELLOW + f"\nExtracting emails from: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                if link['href'].startswith('mailto:'):
                    email = link['href'][7:].split('?')[0]
                    if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email):
                        emails.append(email)
            
            unique_emails = sorted(set([e.lower() for e in emails]))
            
            if unique_emails:
                print(Fore.GREEN + f"\nFound {len(unique_emails)} email(s):")
                for email in unique_emails:
                    print(Fore.CYAN + f"  • {email}")
            else:
                print(Fore.YELLOW + "No emails found")
                
            self.scan_results.append(f"Email Parse: {url} - Found {len(unique_emails)} emails")
            
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def securelist(self):
        url = "https://securelist.com/"
        self.scan_results.append("SecureList opened")
        safe_open_url(url, "SecureList")
        
    def mitre(self):
        url = "https://attack.mitre.org/"
        self.scan_results.append("MITRE ATT&CK opened")
        safe_open_url(url, "MITRE ATT&CK")
        
    def misp(self):
        """MISP Threat Sharing"""
        url = "https://www.misp-project.org/"
        self.scan_results.append("MISP opened")
        safe_open_url(url, "MISP")
        
    def cell_id(self):
        url = "https://infocelltowers.ru/ymaps"
        print(Fore.YELLOW + "[!] Russian cell tower database")
        self.scan_results.append("Cell Tower DB opened")
        safe_open_url(url, "Cell Tower DB")
        
    def usgs(self):
        url = "https://earthexplorer.usgs.gov/"
        print(Fore.YELLOW + "USGS may be slow to load")
        self.scan_results.append("USGS opened")
        safe_open_url(url, "USGS")
        
    def google_search(self):
        try:
            query = input(Fore.CYAN + "Enter search query: ").strip()
            encoded = quote(query)
            url = f"https://www.google.com/search?q={encoded}"
            self.scan_results.append(f"Google Search: {query}")
            safe_open_url(url, "Google")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            
    def generate_pdf(self):
        if not self.scan_results:
            print(Fore.RED + "No scan results to report")
            return
            
        filename = input(Fore.CYAN + "Enter report name (without .pdf): ").strip()
        if not filename:
            filename = f"gptvulnsint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        filename += '.pdf'
        
        try:
            c = canvas.Canvas(filename, pagesize=A4)
            width, height = A4
            
            c.setFont("Helvetica-Bold", 20)
            c.drawString(50, height - 50, "GPTVULNSINT Security Report")
            
            c.setFont("Helvetica", 10)
            c.drawString(50, height - 80, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, height - 100, f"Total scans: {len(self.scan_results)}")
            
            y = height - 130
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "Scan Results:")
            
            c.setFont("Helvetica", 10)
            y -= 20
            
            for i, result in enumerate(self.scan_results, 1):
                if y < 50:
                    c.showPage()
                    y = height - 50
                    c.setFont("Helvetica", 10)
                    
                c.drawString(60, y, f"{i}. {result[:100]}")
                y -= 15
            
            c.save()
            
            print(Fore.GREEN + f"\nPDF saved: {filename}")
            print(Fore.YELLOW + f"Total entries: {len(self.scan_results)}")
            
            self.scan_results = []
            
        except Exception as e:
            print(Fore.RED + f"PDF generation error: {e}")
            
    def show_stats(self):
        if not self.scan_results:
            print(Fore.YELLOW + "No scans performed yet")
            return
            
        print(Fore.CYAN + "\n" + "="*50)
        print(Fore.YELLOW + "Current Statistic")
        print(Fore.CYAN + "="*50)
        print(Fore.GREEN + f"Total scans performed: {len(self.scan_results)}")
        
        categories = defaultdict(int)
        for result in self.scan_results:
            if "Scan" in result:
                categories["Scans"] += 1
            elif "Search" in result:
                categories["Searches"] += 1
            else:
                categories["Other"] += 1
                
        for category, count in categories.items():
            print(Fore.CYAN + f"  {category}: {count}")
            
        print(Fore.CYAN + "="*50)
        
    def clear_results(self):
        confirm = input(Fore.YELLOW + "Clear all results? (y/n): ").lower()
        if confirm == 'y':
            self.scan_results = []
            print(Fore.GREEN + "Results cleared")
            
def print_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    menu_sections = [
        ("WEBSITE OSINT", [
            ("1", "FreeCampDev (Subdomains)"),
            ("2", "URL Scan (Extract Links)"),
            ("3", "PublicWWW Search"),
            ("4", "Censys Search"),
            ("5", "IntelX Search"),
            ("8", "crt.sh Certificates"),
            ("9", "SUIP.biz Tools"),
            ("10", "WHOIS Lookup")
        ]),
        
        ("VULNERABILITY SCANNING", [
            ("11", "HTTP Headers Analysis"),
            ("12", "Vulners Database"),
            ("13", "WordPress Scanner"),
            ("14", "Phind AI Search"),
            ("15", "Sensitive Data Scan (FAST)")
        ]),
        
        ("MALWARE ANALYSIS", [
            ("16", "Kaspersky TI"),
            ("17", "MetaDefender"),
            ("18", "MalwareBazaar"),
            ("19", "VirusTotal")
        ]),
        
        ("EMAIL OSINT", [
            ("20", "EpieOS Tools"),
            ("21", "Email Parser")
        ]),
        
        ("THREAT INTELLIGENCE", [
            ("22", "SecureList (Kaspersky)"),
            ("23", "MITRE ATT&CK"),
            ("24", "MISP Platform")
        ]),
        
        ("MOBILE & GEO", [
            ("25", "Cell Tower Info"),
            ("26", "USGS Earth Explorer")
        ]),
        
        ("UTILITIES", [
            ("7", "Google Search"),
            ("6", "Generate PDF Report"),
            ("27", "Show Statistics"),
            ("28", "Clear Results"),
            ("0", "Exit")
        ])
    ]
    
    for section_title, options in menu_sections:
        print(Fore.RED + f"\n{section_title}")
        print(Fore.RED + "-" * len(section_title))
        for num, desc in options:
            print(Fore.GREEN + f"  {num:>2}. {desc}")
            
    print(Fore.YELLOW + "\n" + "="*50)

def main():
    tool = GPTVULNSINT()
    
    while True:
        print_menu()
        choice = input(Fore.CYAN + "\nSelect option (0-28): ").strip()
        
        if choice == "0":
            print(Fore.YELLOW + "\nExiting GPTVULNSINT. Stay secure!")
            break
            
        elif choice == "1":
            tool.freecampdev()
        elif choice == "2":
            tool.scan()
        elif choice == "3":
            tool.publicwww()
        elif choice == "4":
            tool.censys()
        elif choice == "5":
            tool.intelx()
        elif choice == "6":
            tool.generate_pdf()
        elif choice == "7":
            tool.google_search()
        elif choice == "8":
            tool.crt()
        elif choice == "9":
            tool.suip()
        elif choice == "10":
            tool.whois()
        elif choice == "11":
            tool.headers()
        elif choice == "12":
            tool.vulners()
        elif choice == "13":
            tool.wp_scanner()
        elif choice == "14":
            tool.phind()
        elif choice == "15":
            tool.sensitive_data_scan()
        elif choice == "16":
            tool.kaspersky()
        elif choice == "17":
            tool.metadefender()
        elif choice == "18":
            tool.malwarebazaar()
        elif choice == "19":
            tool.virustotal()
        elif choice == "20":
            tool.epieos()
        elif choice == "21":
            tool.email_parse()
        elif choice == "22":
            tool.securelist()
        elif choice == "23":
            tool.mitre()
        elif choice == "24":
            tool.misp()
        elif choice == "25":
            tool.cell_id()
        elif choice == "26":
            tool.usgs()
        elif choice == "27":
            tool.show_stats()
        elif choice == "28":
            tool.clear_results()
        else:
            print(Fore.RED + "Invalid option")
            
        input(Fore.YELLOW + "\nPress Enter to continue...")

if __name__ == "__main__":
    main()
