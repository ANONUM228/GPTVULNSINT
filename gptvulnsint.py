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
from bs4 import BeautifulSoup
import time
import logging

init()
print(Fore.YELLOW + "============= ")
print(Fore.GREEN + "GPTVULNSINT")
print(Fore.GREEN + "version 3.0.0")
print(Fore.YELLOW + "============= ")
print()
print(Fore.RED + "======= information =======")
print( Fore.GREEN + "Author: ANONUM228")
print()

logging.basicConfig(filename='gptvulnsint.log', level=logging.DEBUG)

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
    print()

  def freecampdev(self):
    url = f"https://freecamp.dev/tools/network/subdomains"
    print(Fore.YELLOW + f"Attempting to open URL: {url}")
    try:
      time.sleep(0.3)
      print(Fore.YELLOW + "Opening...")
      logging.info(f'Opened {url}')
      webbrowser.open(url)
      print(Fore.GREEN + "[+] Opening search results in your default browser...")

    except Exception as e:
       logging.error(f'Opened {url} error')
       print(Fore.RED + f"[-] Error opening browser: {e}")
       self.scan_results.append(f"FreecampDev: Opened {url}")

  def scan(self):
    target_url = input(Fore.GREEN + "Enter url: ").strip()

    if not target_url.startswith('http'):
      target_url = 'https://' + target_url

    if not is_global_ip(target_url):
      print(Fore.RED + "[-] SECURITY WARNING: Target IP is internal or reserved. Blocking request to prevent SSRF.")
      self.scan_results.append(f"URL Scan: {target_url} - BLOCKED (SSRF Risk)")
      return

    try:
      response = requests.get(target_url, timeout=1)
      response.raise_for_status() 

      raw_links = set(re.findall(r'href=["\'](.*?)(?=["\'])', response.text))

      clean_links = [
        link for link in raw_links 
        if link.startswith('http://') or link.startswith('https://')
      ]
      time.sleep(0.3)
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
    try:
       target2_domain = input(Fore.GREEN + "Enter dork: ").strip()
       encoded_dork = quote(target2_domain)
       url5 = f"https://publicwww.com/websites/{encoded_dork}"
       self.scan_results.append(f"PublicWWW Search: {target2_domain}")
       webbrowser.open(url5)
       time.sleep(0.3)
       logging.info(f'Opened {url5}')
       print(Fore.GREEN + "[+] Opening search results in your default browser...")

    except Exception as e:
      logging.error(f'Opened {url5}')
      print(Fore.RED + f"[-] Error opening browser: {e}")

  def censys(self):
    try:
      target6 = input(Fore.GREEN + "Enter dork: ").strip()
      encoded_dork = quote(target6)
      url7 = f"https://platform.censys.io/search?q={encoded_dork}"
      self.scan_results.append(f"Censys Search: {target6}")
      webbrowser.open(url7)
      logging.info(f'Opened {url7}')
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)

    except Exception as e:
      logging.error(f'Opened {url7}')
      print(Fore.GREEN + f"[+] Opening Censys search results in browser: {url7}")

  def intelx(self):
    try:
      search = input(Fore.YELLOW + "Enter query: ").strip()
      encoded_query = quote(search)
      url9 = f"https://intelx.io/?s={encoded_query}"
      self.scan_results.append(f"Intelx Search: {search}")
      webbrowser.open(url9)
      logging.info(f'Opened {url9}')
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)

    except Exception as e:
      logging.error(f'Opened {url9} error')
      print(Fore.GREEN + f"IntelX {url9} open")

  def headers(self):
    try:
      url77 = input(Fore.GREEN + "Enter url: ")

      if not url77.startswith(('http://', 'https://')):
        print(Fore.YELLOW + "--> The URL must start with 'http://' or 'https://'")
        return
      
      response_object = requests.get(url77, timeout=10)
      self.scan_results.append(f"Request to {url77} Status: {response_object.status_code}")
      logging.info(f'REquest to {url77} Status: {response_object.status_code}')
      time.sleep(0.3)
      
      header_data = response_object.headers
      print(header_data)

    except Exception as e:
      logging.error(f'Requested {url77} error')
      print(url77 + Fore.YELLOW + f"--> Request Error {e}")

  def vulners(self):
    try:
      query8 = input(Fore.GREEN + "Enter query: ").strip()
      encoded_query = quote(query8)
      url11 = f"https://vulners.com/search?query={encoded_query}"
      self.scan_results.append(f"Vulners Search: {query8}")
      logging.info(f'Opened {url11}')
      webbrowser.open(url11)
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)
      print(Fore.GREEN + f"[+] Opening Vulners search results in browser: {url11}")

    except Exception as e:
      logging.error(f'Opened {url11} error')
      print(Fore.GREEN + "--> ERROR Open!")

  def wp_scanner(self):
    try:
      url44 = f"https://hackertarget.com/wordpress-security-scan/"
      self.scan_results.append(f"HackerTarget {url44} open")
      logging.info(f'Opened {url44}')
      print(Fore.CYAN + "NOTE: You must manually paste the target URL into the opened browser window.")
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.5)
      webbrowser.open(url44)

    except Exception as e:
      logging.error(f'Opened {url44} error')
      print(url44 + "--> ERROR Opening!")

  def phind(self):
    try:
      url33 = f"https://www.phind.com/"
      self.scan_results.append(f"Phind {url33} opened")
      logging.error(f'Opened {url33}')
      time.sleep(0.3)
      webbrowser.open(url33)

    except Exception as e:
      logging.error(f'Opened {url33} error')
      print(url33 + Fore.YELLOW + "Open Error!")

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
      time.sleep(0.3)
      print(Fore.YELLOW + "Opening...")
      webbrowser.open(url99)
      self.scan_results.append(f"Google search {search222}")
      logging.info(f'Opened {url99}')

    except Exception as e:
       logging.error(f'Opened {url99} error')
       print(url99 + Fore.GREEN + "--> Opening error")

  def crt(self):
    try:
        query = input("request: ")
        url4 = f"https://crt.sh/?q=%.{query}"
        time.sleep(0.3)
        webbrowser.open(url4)
        logging.info(f'Opened {url4}')
        self.scan_results.append(f"Crt {query}")

    except Exception as e:
        logging.error(f'Opened {url4} error')
        print(url4 + Fore.GREEN + "--> ERROR")

  def suip(self):
    try:
       query = input(Fore.GREEN + "Enter: ")
       url = f"https://suip.biz/ru/?act=hostmap&host={query}"
       time.sleep(0.3)
       print(Fore.YELLOW + "Opening...")
       webbrowser.open(url)
       logging.info(f'Opened {url}')
       self.scan_results.append(f"request {query}, {url} opened")

    except Exception as e:
        logging.error(f'Opened {url} error')
        print(url, Fore.GREEN + "--> ERROR")

  def whois(self):
      try:
          q = input(Fore.GREEN + "Enter url: ")
          url1 = f"https://www.reg.ru/whois/?dname={q}"
          time.sleep(0.3)
          print(Fore.YELLOW + "Opening...")
          webbrowser.open(url1)
          logging.info(f'Opened {url1}')
          self.scan_results.append(f"request {url1}, {q} opened")

      except Exception as e:
          logging.error(f'Opened {url1}')
          print(url1, Fore.GREEN + "--> ERROR")

  def kaspersky(self):
      try:
          query15 = input(Fore.GREEN + "Enter request: ")
          url22 = f"https://opentip.kaspersky.com/{query15}/?tab=lookup"
          time.sleep(0.3)
          print(Fore.YELLOW + "Opening...")
          webbrowser.open(url22)
          logging.info(f'Opened {url22}')
          self.scan_results.append(f"Kaspersky {query15}")

      except Exception as e:
          logging.error(f'Opened {url22} error')
          print(url22 + Fore.GREEN + "--> Opening error")

  def metadefender(self):
    try:
      query110 = input(Fore.GREEN + "Enter query: ")
      url20 = f"https://metadefender.com/results/url/{query110}"
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)
      webbrowser.open(url20)
      logging.info(f'Opened {url20}')
      self.scan_results.append(f"Metadefender {query110}")

    except Exception as e:
      logging.error(f'Opened {url20} error')
      print(url20 + Fore.GREEN + "--> Opening error")

  def malwarebazaar(self):
    try:
      url00 = f"https://bazaar.abuse.ch/browse/"
      self.scan_results.append(f"MalwareBaaZaar {url00} Opened")
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)
      webbrowser.open(url00)
      self.scan_results.append(f"MalwareBazaar {url00}")
      logging.info(f'Opened {url00}')

    except Exception as e:
      logging.error(f'Opened {url00} error')
      print(url00 + Fore.GREEN + "--> ERROR")
      pass

  def virustotal(self):
    try:
      url11 = f"https://www.virustotal.com/gui/home/search/"
      print(Fore.YELLOW + "Opening...")
      time.sleep(0.3)
      webbrowser.open(url11)
      logging.info(f'Opened {url11}')
      self.scan_results.append(f"VirusTotal {url11}")

    except Exception as e:
      logging.error(f'Opened {url11} error')
      print(url11 + Fore.GREEN + "--> ERROR")

  def epieos(self):
    try:
        url106 = f"https://epieos.com/"
        print(Fore.YELLOW + "Opening...")
        time.sleep(0.3)
        webbrowser.open(url106)
        logging.info(f'Opened {url106}')
        self.scan_results.append(f"Epieos {url106} Opened")

    except Exception as e:
        logging.error(f'Opened {url106} error')
        print(url106 + Fore.GREEN + "--> ERROR")

  def email_parse(self, url): 
   emails = set()
   try:
     headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.2000.0 Safari/537.36'
     }
     response = requests.get(url, headers=headers, timeout=3)
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
  
  def securelist(self):
    try:
       url2 = f"https://securelist.com/"
       logging.info(f'Opened {url2}')
       self.scan_results.append(f"SecureList {url2} Opened")
       print(Fore.YELLOW + "Opening...")
       time.sleep(0.3)
       webbrowser.open(url2)

    except Exception as e:
        logging.info(f'Opened {url2} error')
        print(url2 + Fore.GREEN + "--> Open Error") 

  def mitre(self):
      try:
          url16 = f"https://attack.mitre.org/"
          print(Fore.YELLOW + "Opening...")
          time.sleep(0.3)
          webbrowser.open(url16)
          logging.info(f'Opened {url16}')
          self.scan_results.append(f"Mitre {url16} Opened")

      except Exception as e:
          logging.error(f'Opened {url16} error')
          print(url16 + Fore.GREEN + "--> Open Error") 

  def misp(self):
      try:
          url3 = f"https://www.misp-project.org/"
          print(Fore.YELLOW + "Opening...")
          time.sleep(0.3)
          webbrowser.open(url3)
          logging.info(f'Opened {url3}')
          self.scan_results.append(f"Misp {url3} Opened")

      except Exception as e:
          logging.error(f'Opened {url3} error')
          print(url3 + Fore.GREEN + "--> Open Error")

  def cell_id(self):
      try:
         url220 = f"https://infocelltowers.ru/ymaps"
         print(Fore.YELLOW + "Opening...")
         time.sleep(0.3)
         webbrowser.open(url220)
         logging.info(f'Opened {url220}')
         self.scan_results.append(f"CellTowers {url220} Opened")

      except Exception as e:
         logging.error(f'Opened {url220} error')
         print(url220 + Fore.GREEN + "--> ERROR Opening")

  def usgs(self):
      try:
         url222 = f"https://earthexplorer.usgs.gov/"
         print(Fore.YELLOW + "ATTENTION! The page may take a long time to load or may not work!")
         print(Fore.YELLOW + "Opening...")
         time.sleep(2)
         webbrowser.open(url222)
         logging.info(f'Opened {url222}')
         self.scan_results.append(f"USGS {url222} Opened")

      except Exception as e:
         logging.debug(f'Opened {url222} error')
         print(url222 + Fore.GREEN + "--> ERROR Opening")

if __name__ == "__main__":
   tool = GPTVULNSINT()

while True:
  print(Fore.BLUE + "Menu:")
  print()
  print(Fore.RED + "============= Website OSINT-tool =======")
  print(Fore.GREEN + "1. FreeCampDev")
  print(Fore.GREEN + "2. Url Scan") 
  print(Fore.GREEN + "3. Publicwww")
  print(Fore.GREEN + "4. Censys")
  print(Fore.GREEN + "5. IntelX")
  print(Fore.GREEN + "6. Generate pdf report")
  print(Fore.GREEN + "7. Google search")
  print(Fore.GREEN + "8. Crt")
  print(Fore.GREEN + "9. Suip")
  print(Fore.GREEN + "10. Whois")
  print()
  print(Fore.RED + "=========== Search Vulnerabilities-tool ============")
  print(Fore.GREEN + "11. Headers")
  print(Fore.GREEN + "12. Vulners")
  print(Fore.GREEN + "13. WP Scanner")
  print(Fore.GREEN + "14. Phind")
  print()
  print(Fore.RED + "=========== Malware Analytics OSINT-tool ===========")
  print(Fore.GREEN + "14. Kaspersky")
  print(Fore.GREEN + "15. Metadefender")
  print(Fore.GREEN + "16. MalwareBazaar")
  print(Fore.GREEN + "17. VirusTotal")
  print()
  print(Fore.RED + "=========== Email OSINT-tool ============")
  print(Fore.GREEN + "18. Epieos")
  print(Fore.GREEN + "19. Email parse")
  print()
  print(Fore.RED + "=========== Threat Intelligence OSINT-tool")
  print(Fore.GREEN + "20. Securelist")
  print(Fore.GREEN + "21. Mitre")
  print(Fore.GREEN + "22. Misp")
  print()
  print(Fore.RED + "========== Mobile Network OSINT-tool")
  print(Fore.GREEN + "23. CellID")
  print(Fore.GREEN + "24. Usgs")
  print()
  print(Fore.YELLOW + "=========== Disclaimer =============")
  print(Fore.GREEN + "Attention! GPTVULNSINT is strictly for legal testing only!")
  print()

  choice = input(Fore.GREEN + "Enter choice(1-24): ") 

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
    tool.kaspersky()
  elif choice == "16":
    tool.metadefender()
  elif choice == "17":
    tool.malwarebazaar()
  elif choice == "18":
    tool.virustotal()
  elif choice == "19":
    tool.epieos()
  elif choice == "20":
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
  elif choice == "21":
    tool.securelist()
  elif choice == "22":
    tool.mitre()
  elif choice == "21":
    tool.misp()
  elif choice == "23":
    tool.cell_id()
  elif choice == "24":
    tool.usgs()
  else:
    print(Fore.RED + "[-] Invalid choice")
