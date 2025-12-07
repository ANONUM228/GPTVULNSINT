Professional OSINT & Vulnerability Research Platform
GPTVULNSINT is an advanced and high-performance framework for Open Source Intelligence (OSINT) and vulnerability research, developed by a 15-year-old security enthusiast. Focused on transforming raw data into actionable insights, GPTVULNSINT includes an extensive set of tools for reconnaissance, analysis, and reporting.

Version: v5.5

Asynchronous Operations: Built with asyncio and aiohttp for incredibly fast and efficient network request processing.

Broad OSINT Integration: Supports over 21 data sources for comprehensive intelligence gathering (see list below).

SSRF Protection: Built-in IP address validation safeguards against Server-Side Request Forgery attacks during URL scanning.

Sensitive Data Scan (FAST): A rapid asynchronous scanner for identifying critical secrets (API keys, tokens, passwords) in HTML and JavaScript, utilizing strict patterns and filtering test data.

Rich Visualization: Beautifully structured and color-coded reports of discovered secrets using the rich library, categorized by risk levels (CRITICAL, HIGH, MEDIUM).

Deep URL Analysis: Extracts links and analyzes HTTP headers for common security misconfigurations.

Email OSINT: Parses email addresses from webpages and leverages specialized OSINT tools.

PDF Reporting: Generates detailed PDF reports of all conducted scans.

Logging: Detailed logging of all operations and findings for post-analysis.

Interactive Menu: User-friendly console interface for navigating through functions.

Automatic Saving: Quick saving of sensitive data scan results to text files.


Integrated Sources (21+)

Subdomains: freecamp.dev

Website Source Code: PublicWWW

IoT Search Engines: Censys

Data Breach & Leak Aggregation: IntelligenceX

Vulnerability Databases: Vulners

WP Scanners: HackerTarget (WordPress Security Scanner)

AI Search: Phind

General Search: Google

Certificates: crt.sh

Host Mapping Tools: Suip.biz

Domain Information: Whois

Threat Intelligence Platforms: Kaspersky TI, MetaDefender, MalwareBazaar, VirusTotal, Securelist

Email OSINT: Epieos, Email Parser

TI Frameworks: MITRE ATT&CK, MISP

Mobile & Geo Data: CellID (Cell Tower Info), USGS Earth Explorer

Screenshot:

<img width="627" height="863" alt="Снимок экрана 2025-12-07 191141" src="https://github.com/user-attachments/assets/00da76a8-cc04-4b34-8e17-a22beb03f417" />

Installation:

For Termux:
pkg update && pkg upgrade -y
pkg install git python -y
git clone https://github.com/ANONUM228/GPTVULNSINT.git
cd GPTVULNSINT
pip install -r requirements.txt
python3 gptvulnsint.py


For Linux / macOS / Windows (with Python 3.9+):

1. Clone the repository:
  git clone https://github.com/ANONUM228/GPTVULNSINT.git
  cd GPTVULNSINT

2. Create and activate a virtual environment (recommended):
  python3 -m venv venv
  source venv/bin/activate # For Linux/macOS
  .\venv\Scripts\activate # For Windows

3. Install dependencies:
  pip install -r requirements.txt

4. Run the framework:
  python3 gptvulnsint.py


Usage simply run the script and select an option from the interactive menu:

python3 gptvulnsint.py

Example:

... (GPTVULNSINT Menu) ...

Select option (0-28): 15

WARNING:

GPTVULNSINT is designed exclusively for educational purposes, ethical security testing, and conducting authorized OSINT research.

The author bears no responsibility for any unlawful actions undertaken using this framework.

Active scanning modules (such as URL scanning, email analysis, header analysis, sensitive data scanning) MAY ONLY be used with explicit, written permission from the owner of the target system.

Violation of this principle is illegal and unethical.
