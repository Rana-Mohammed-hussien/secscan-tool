# Secscan - Automated Security Assessment Tool

Secscan is a simple Bash script designed to automate initial penetration testing and security assessment steps. Instead of running multiple tools manually, this script takes a target IP, checks for open ports, and automatically runs specific checks based on the discovered services.

At the end of the scan, it gathers all logs into text files and creates a clean HTML report to view the findings easily.

## Features
- **Host Check:** Checks if the target is online using ping before running any heavy tools.
- **Port Scanning:** Scans all TCP ports and detects service versions using Nmap.
- **Automated Service Checking:** It reads the open ports and decides what to test:
  - **FTP:** Tries to log in with an anonymous account.
  - **SSH:** Grabs the banner and gives recommendations about version disclosure.
  - **Telnet:** Detects cleartext telnet access and flags it as a risk.
  - **SMTP:** Checks for valid usernames (via `smtp-user-enum`) and tests for Open Relay.
  - **DNS:** Tries to perform a Zone Transfer (`axfr`).
  - **HTTP:** Grabs response headers and checks for a `robots.txt` file.
  - **SMB:** Looks for accessible network shares using anonymous login.
- **Error Handling:** Verifies required tools are installed first, handles missing arguments, and stops if the target is offline.
- **HTML Reporting:** Generates a structured HTML file showing open ports and evidence.

## Prerequisites
Make sure you have these tools installed on your system (tested on Kali Linux):
- `nmap`, `ping`, `arp`, `curl`, `nc`, `dig`, `smbclient`, `smtp-user-enum`

## How to Run

### 1. Show Help Menu
```bash
./secscan.sh --help
```

### 2. Show Version Information
```bash
./secscan.sh --version
```

### 3. Run a Scan Against a Target VM
```bash
chmod +x secscan.sh
./secscan.sh <TARGET_IP>
```

## Generated Reports
All results are saved inside a new `report/` folder:
- `recon.txt`: Basic network info, hostname, and ARP logs.
- `scan.txt`: Full raw output from the Nmap scan.
- `open_ports.txt`: Clean list of open ports and services found.
- `findings.txt`: Specific test results and evidence collected from the services.
- `summary.txt`: A quick text wrap-up of the target and open ports.
- `report.html`: A visual HTML webpage summarizing everything.

---
*Project developed for the Instant Software Solutions Security Track.*
