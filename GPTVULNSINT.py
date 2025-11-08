import re
import requests
from colorama import init, Fore
import webbrowser
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import io
import os
from datetime import datetime
from urllib.parse import quote, urljoin
import socket 
from ipaddress import ip_address
import requests.exceptions
from bs4 import BeautifulSoup
import time
init()
print(Fore.YELLOW + "============= ")
print(Fore.GREEN + "GPTVULNSINT")
print(Fore.GREEN + "version 2.9.0")
print(Fore.YELLOW + "============= ")
print()
print(Fore.BLUE + "======= information =======")
print()
print( Fore.GREEN + "Author: ANONUM228")
print()

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
  def __init__(self): 
    self.scan_results = []
    print(Fore.YELLOW + "DEBUG: Framework initialized.")

  def freecampdev(self):
    url = "https://freecamp.dev/tools/network/subdomains"
    print(Fore.YELLOW + f"Attempting to open URL: {url}")
    try:
      webbrowser.open(url) 
      print(Fore.GREEN + "[+] Opening search results in your default browser...")

    except Exception as e:
       print(Fore.RED + f"[-] Error opening browser: {e}")
       self.scan_results.append(f"FreecampDev: Opened {url}")

  def scan(self):
    target_url = input("Enter url: ").strip()

    if not target_url.startswith('http'):
      target_url = 'https://' + target_url

    if not is_global_ip(target_url):
      print(Fore.RED + "[-] SECURITY WARNING: Target IP is internal or reserved. Blocking request to prevent SSRF.")
      self.scan_results.append(f"URL Scan: {target_url} - BLOCKED (SSRF Risk)")
      return

    try:
      response = requests.get(target_url, timeout=10)
      response.raise_for_status() 

      raw_links = set(re.findall(r'href=["\'](.*?)(?=["\'])', response.text))

      clean_links = [
        link for link in raw_links 
        if link.startswith('http://') or link.startswith('https://')
      ]

      print(Fore.GREEN + f"\n[+] Found {len(clean_links)} clean links:")
      for link in sorted(clean_links):

        print(Fore.CYAN + f" {link}")

      self.scan_results.append(f"URL Scan: {target_url} - Found {len(clean_links)} clean links")

    except requests.exceptions.RequestException as e:
      print(Fore.RED + f"[-] Connection Error (Scan): {e}") 
      self.scan_results.append(f"URL Scan: {target_url} - Connection Error")

    except Exception as e:
      print(Fore.RED + f"[-] Error: {e}")
      self.scan_results.append(f"URL Scan: {target_url} - Error: {e}")
      time.sleep(0.3)

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

  def generate_pdf(__self__):
    if not __self__.scan_results:
      print(Fore.RED + "[-] No scan results to generate PDF")
      return

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)

    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 800, "GPTVULNSINT Security Report")

    p.setFont("Helvetica", 10)
    p.drawString(100, 780, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y_position = 750
    for i, result in enumerate(__self__.scan_results):
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
    __self__.scan_results = []
    time.sleep(0.3)
    return desktop_path

  def google_search(self):
    try:
      search222 = input("Enter search: ")
      url99 = f"https://www.google.com/search?q={search222}"
      webbrowser.open(url99)

    except Exception as e:
       print(url99 + "--> Opening error")

  def kaspersky(self):
    try:
      query15 = input("Enter request: ")
      url22 = f"https://opentip.kaspersky.com/{query15}/?tab=lookup"
      webbrowser.open(url22)

    except Exception as e:
      print(url22 + "--> Opening error")

  def metadefender(self):
    try:
      query110 = input("Enter query: ")
      url20 = f"https://metadefender.com/results/url/{query110}"
      webbrowser.open(url20)

    except Exception as e:
      print(url20 + "--> Opening error")

  def malwarebazaar(self):
    try:
      url00 = f"https://bazaar.abuse.ch/browse/"
      webbrowser.open(url00)

    except Exception as e:
      print(url00 + "--> ERROR")
      pass

  def virustotal(self):
    try:
      search22 = input("Search: ")
      url11 = f"https://www.virustotal.com/gui/home/search/?q={search22}"
      webbrowser.open(url11)

    except Exception as e:
      print(url11 + "--> ERROR")

  def email_parse(self, url): 
   emails = set()
   try:
     headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.2000.0 Safari/537.36'
     }
     response = requests.get(url, headers=headers, timeout=10)
     response.raise_for_status() 
     html_content = response.text
     soup = BeautifulSoup(html_content, 'html.parser') 

     text_content = soup.get_text()
     email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

     found_emails_in_text = re.findall(email_regex, text_content)
     for email in found_emails_in_text:
      emails.add(email.lower())

     for link in soup.find_all('a', href=True):
      href = link['href']
      if href.startswith('mailto:'):
        email_in_mailto = href[7:].split('?')[0] 
        if re.match(email_regex, email_in_mailto):
          emails.add(email_in_mailto.lower())
     return list(emails) 

   except requests.exceptions.RequestException as e:
     print(Fore.YELLOW + f"[-] Error when requesting to {url}: {e}")
     return [] 
   
   except Exception as e:
    print(Fore.YELLOW + f"[-] An unexpected error has occurred: {e}")
    return []

if __name__ == "__main__":
   tool = GPTVULNSINT()

while True:
  print(Fore.RED + "Menu:")
  print(Fore.RED + "============= Website OSINT-tool =======")
  print(Fore.GREEN + "1. FREECAMPDEV")
  print(Fore.GREEN + "2. URL SCAN") 
  print(Fore.GREEN + "3. PUBLICWWW")
  print(Fore.GREEN + "4. CENSYS")
  print(Fore.GREEN + "5. INTELX")
  print(Fore.GREEN + "6. EXPLOIT DB")
  print(Fore.GREEN + "7. GENERATE PDF REPORT")
  print(Fore.GREEN + "8. GOOGLE SEARCH")
  print()
  print(Fore.RED + "=========== Malware Analytics OSINT-tool ===========")
  print(Fore.GREEN + "9. Kaspersky")
  print(Fore.GREEN + "10. Metadefender")
  print(Fore.GREEN + "11. MalwareBazaar")
  print(Fore.GREEN + "12. VirusTotal")
  print()
  print(Fore.RED + "=========== Email OSINT-tool ============")
  print(Fore.GREEN + "13. Email parse")
  print()
  print(Fore.YELLOW + "=========== Disclaimer =============")
  print(Fore.GREEN + "Attention! GPTVULNSINT is strictly for legal testing only!")
  print()

  choice = input(Fore.GREEN + "Enter choice(1-13): ") 

  if choice == "1":
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
    tool.exploitdb()
  elif choice == "7":
    tool.generate_pdf()
  elif choice == "8":
    tool.google_search()
  elif choice == "9":
    tool.kaspersky()
  elif choice == "10":
    tool.metadefender()
  elif choice == "11":
    tool.malwarebazaar()
  elif choice == "12":
    tool.virustotal()
  elif choice == "13":
    website_url = input(Fore.GREEN + "Enter url for email parsing: ").strip()
    if not website_url.startswith('http'):
      website_url = 'https://' + website_url

    print(Fore.GREEN + f"\n[*] Parsing email addresses: {website_url}")
    time.sleep(0.3)
    found_emails = tool.email_parse(website_url) 

    print("\n" + "="*30)
    time.sleep(0.3)
    print("Email addresses found:")
    
    if found_emails:
      for email in sorted(found_emails):
        print(Fore.GREEN + f"- {email}")
    else:
      print(Fore.GREEN + "Email-addresses not found")
      print(Fore.GREEN + "="*30) 
  else:
    print(Fore.RED + "[-] Invalid choice")
