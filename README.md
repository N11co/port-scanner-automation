# Port Scanner Automation

## What this does:
This Python script scans one or more IP addresses to identify open network ports and flags any that represent known security risks. Results are saved as both JSON and CSV reports for easy review.

## Why it matters:
Open ports are like unlocked doors into a system. Ports running outdated or insecure services (like Telnet on port 23 or FTP on port 21) are commonly knwon targets for attackers because they transmit data without any encyption. This tool automates the detection of these risks across multiple targets.

## Tools used:
- Python
- socket (A Python standard library)
- json and csv (Another Python standard library)

## How to run it:
1. Clone this repository
2. Run: python scanner.py
3. Review the output in scan_report.json or scan_report.csv

## Context:
Port scanning is one of the first steps in both defensive and offensive security. This script automates the defensive approach to port scanning by identifying misconfigured or unnecessarily exposed services across a network and producing an auditable report. In a real enterprise environment, this kidn of script would be scheduled to run nightly and feed the results into a SIEM platform for continuous monitoring.