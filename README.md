# GPTVULNSINT: OSINT & Threat Intelligence Platform

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

Automated OSINT collection, vulnerability correlation, and secrets detection in one framework. Built for security researchers and threat hunters who need to turn scattered data into clear insights.

> Core Idea: One tool to query 21+ intelligence sources, scan for exposed secrets, and generate actionable reports — fast.

## Why GPTVULNSINT?

*   Async Speed: Scans multiple targets and sources simultaneously using asyncio.
*   Unified OSINT: Single interface for Censys, VirusTotal, MITRE ATT&CK, Shodan, and 17+ other sources.
*   Secrets Detection: Finds API keys, tokens, passwords in code with risk-level assessment.
*   Professional Reporting: Console output with rich library + automatic PDF reports.
*   Built Safely: SSRF protection, input validation, and ethical-use safeguards.

## Get Started in 60 Seconds

git clone https://github.com/ANONUM228/GPTVULNSINT.git
cd GPTVULNSINT
pip install -r requirements.txt
python3 gptvulnsint.py
Then: Use the interactive menu. No config needed for basic scans.

📸 See It in Action

images/screenshot.png

What's Inside? (Key Modules)

Module Description
Sensitive Data Scan Fast async scanner for secrets in HTML/JS.
URL & Header Analysis Security checks and link extraction.
Email OSINT Parse and investigate email addresses.
Vulnerability Lookup Query Vulners, MITRE ATT&CK for CVE data.
Threat Intel Feed Pull data from VirusTotal, MalwareBazaar, etc.
Report Generator Create PDF summaries of findings.

Responsible Use

This tool is for authorized security testing and education only.
You must have explicit permission to scan any target you do not own.
The author is not responsible for misuse.

Contribute

Found a bug? Have an idea?
Open an Issue or submit a Pull Request.
See CONTRIBUTING.md for guidelines (you can create this file later).

License

MIT. See the LICENSE file.

Built by a security researcher focused on automation and actionable intelligence.
Project maintained under a legacy GitHub handle. Professional alias: dev-researcher.
