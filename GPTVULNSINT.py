import re
import requests
from colorama import init, Fore
import webbrowser
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import io
import os
from datetime import datetime
from urllib.parse import quote 
import socket 
from ipaddress import ip_address
import requests.exceptions

init()
print(Fore.YELLOW + "===========")
print(Fore.GREEN + "GPTVULNSINT")
print(Fore.YELLOW + "===========")
print()

# --- ФУНКЦИЯ SSRF-ЗАЩИТЫ (Вне класса) ---
def is_global_ip(url):
    try:
        hostname = url.split('//')[-1].split('/')[0].split('?')[0]
        if not hostname:
            return False

        ip_addr = socket.gethostbyname(hostname)
        ip = ip_address(ip_addr)

        return not (ip.is_private or ip.is_reserved or ip.is_loopback)
    except Exception:
        return False

class GPTVULNSINT:
    def __init__(self):  # ИСПРАВЛЕНО: init вместо init
        self.scan_results = []
        print(Fore.YELLOW + "DEBUG: Framework initialized.")

    def crt(self):
        query = input("Enter query for CRT.sh: ").strip()
        encoded_query = quote(query)
        url1 = f"https://crt.sh/?q=%{encoded_query}"
        try:
            print(Fore.YELLOW + "Connecting to CRT.sh...")
            response = requests.get(url1, timeout=15)

            if response.status_code != 200:
                print(Fore.RED + f"[-] HTTP Error: {response.status_code}")
                self.scan_results.append(f"CRT Search: {query} - HTTP Error {response.status_code}")
                return

            # ПАРСИНГ СУБДОМЕНОВ БЕЗ HTML-МУСОРА
            subdomains = set(re.findall(r'<TD[^>]*>\s*([^\s]+)\s*</TD>', response.text, re.IGNORECASE))

            clean_subdomains = [d.strip() for d in subdomains if f'.{query}' in d and not d.startswith('<')]

            print(Fore.GREEN + f"\n[+] Found {len(clean_subdomains)} unique subdomains for {query}:")
            for sub in sorted(clean_subdomains):
                print(Fore.CYAN + f" {sub}")

            self.scan_results.append(f"CRT Search: {query} - Found {len(clean_subdomains)} subdomains")
            print(Fore.GREEN + "[+] CRT search completed")

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Connection Error (CRT.sh): {e.__class__.__name__}")  # ИСПРАВЛЕНО
            self.scan_results.append(f"CRT Search: {query} - Connection Error")
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")
            self.scan_results.append(f"CRT Search: {query} - Error: {e}")

    def scan(self):
        target_url = input("Enter url: ").strip()

        if not target_url.startswith('http'):
            target_url = 'https://' + target_url

        # SSRF-ПРОВЕРКА
        if not is_global_ip(target_url):
            print(Fore.RED + "[-] SECURITY WARNING: Target IP is internal or reserved. Blocking request to prevent SSRF.")
            self.scan_results.append(f"URL Scan: {target_url} - BLOCKED (SSRF Risk)")
            return

        try:
            response = requests.get(target_url, timeout=10)

            raw_links = set(re.findall(r'href=["\'](.*?)(?=["\'])', response.text))

            # ФИЛЬТРАЦИЯ: только полные HTTP/HTTPS ссылки
            clean_links = [
                link for link in raw_links 
                if link.startswith('http://') or link.startswith('https://')
            ]

            print(Fore.GREEN + f"\n[+] Found {len(clean_links)} clean links:")
            for link in sorted(clean_links):
                print(Fore.CYAN + f" {link}")

            self.scan_results.append(f"URL Scan: {target_url} - Found {len(clean_links)} clean links")

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] Connection Error (Scan): {e.__class__.__name__}")  # ИСПРАВЛЕНО
            self.scan_results.append(f"URL Scan: {target_url} - Connection Error")
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")
            self.scan_results.append(f"URL Scan: {target_url} - Error: {e}")

            def publicwww(self):
                target2_domain = input("Enter dork: ").strip()
                encoded_dork = quote(target2_domain)
                url5 = f"https://publicwww.com/websites/{encoded_dork}"
                self.scan_results.append(f"PublicWWW Search: {target2_domain}")

                try:
                    webbrowser.open(url5) 
                    print(Fore.GREEN + "[+] Opening search results in your default browser...")
                except Exception as e:
                    print(Fore.RED + f"[-] Error opening browser: {e}")

    def censys(self):
        target6 = input("Enter dork: ").strip()
        encoded_dork = quote(target6)
        url7 = f"https://platform.censys.io/search?q={encoded_dork}"
        self.scan_results.append(f"Censys Search: {target6}")
        webbrowser.open(url7)
        print(Fore.GREEN + f"[+] Opening Censys search results in browser: {url7}")

    def intelx(self):
        search = input(Fore.YELLOW + "Enter query: ").strip()
        encoded_query = quote(search)
        url9 = f"https://intelx.io/?s={encoded_query}"
        self.scan_results.append(f"Intelx Search: {search}")
        webbrowser.open(url9)
        print(Fore.GREEN + f"[+] Opening Intelx search results in browser: {url9}")

    def exploitdb(self):
        query8 = input("Enter query: ").strip()
        encoded_query = quote(query8)
        url11 = f"https://www.exploit-db.com/search?q={encoded_query}"
        self.scan_results.append(f"ExploitDB Search: {query8}")
        webbrowser.open(url11)
        print(Fore.GREEN + f"[+] Opening ExploitDB search results in browser: {url11}")

    def generate_pdf(self):
        if not self.scan_results:
            print(Fore.RED + "[-] No scan results to generate PDF")
            return

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)

        p.setFont("Helvetica-Bold", 16)
        p.drawString(100, 800, "GPTVULNSINT Security Report")

        p.setFont("Helvetica", 10)
        p.drawString(100, 780, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        y_position = 750
        for i, result in enumerate(self.scan_results):
            p.drawString(100, y_position, f"{i+1}. {result}")
            y_position -= 20

        p.showPage()
        p.save()
        buffer.seek(0)

        name_pdf = input("Enter PDF file name (will be saved on Desktop): ").strip()
        if not name_pdf.lower().endswith('.pdf'):
            name_pdf += '.pdf'

        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", name_pdf)

        with open(desktop_path, 'wb') as f:
            f.write(buffer.getvalue())

        print(f"✅ PDF saved: {desktop_path}")
        self.scan_results = []
        return desktop_path

tool = GPTVULNSINT()

while True:
    print(Fore.RED + "=============")
    print(Fore.GREEN + "1. CRT SH")
    print(Fore.GREEN + "2. URL SCAN") 
    print(Fore.GREEN + "3. PUBLICWWW")
    print(Fore.GREEN + "4. CENSYS")
    print(Fore.GREEN + "5. INTELX")
    print(Fore.GREEN + "6. EXPLOIT DB")
    print(Fore.GREEN + "7. GENERATE PDF REPORT")
    print(Fore.RED + "==============")
    print()
    choice = input(Fore.GREEN + "Enter choice(1-7): ")

    if choice == "1":
        tool.crt()
    elif choice == "2":
        tool.scan()
    elif choice == "3":
        tool.publicwww()
    elif choice == "4":
        tool.censys()
    elif choice == "5":
        tool.intelx()
    elif choice == "6":
        tool.exploitdb()
    elif choice == "7":
        tool.generate_pdf()
    else:
        print(Fore.RED + "[-] Invalid choice")
