#!/bin/bash
check_ftp() {
   local target=$1
   local port=$2
   echo "Starting FTP anonymous login check..."
   echo "--- FTP Anonymous Login ---" | tee -a report/findings.txt
   ftp_output=$(curl -s --connect-timeout 5 --ftp-pasv "ftp://$target:$port/" 2>&1)
   echo "$ftp_output" | tee -a report/findings.txt
   if echo "$ftp_output" | grep -qiE "230|anonymous|login successful|^drwx|^\-rw-"; then
      echo "FTP anonymous access appears to be allowed." | tee -a report/findings.txt
      echo "Risk: Anonymous FTP access may expose files to unauthenticated users." | tee -a report/findings.txt
      echo "Recommendation: Disable anonymous FTP access or restrict its permissions." | tee -a report/findings.txt
   else
      echo "Anonymous FTP access was not confirmed." | tee -a report/findings.txt
   fi
}

check_ssh() {
   local target=$1
   local port=$2
   echo "Extracting SSH banner..."
   echo "--- SSH Banner ---" | tee -a report/findings.txt
   ssh_output=$(nc -w 2 "$target" "$port" </dev/null 2>&1)
   echo "$ssh_output" | head -n 3 | tee -a report/findings.txt
      if echo "$ssh_output" | grep -q "SSH-"; then
      echo "SSH service and banner were successfully identified." | tee -a report/findings.txt
      echo "Risk: Exposed SSH banners can reveal the exact OS and software version to potential attackers." | tee -a report/findings.txt
      echo "Recommendation: Consider hiding or modifying the SSH banner configuration to minimize information disclosure." | tee -a report/findings.txt
    fi

}

check_telnet() {
   local target=$1
   local port=$2
   echo "Extracting Telnet banner..."
   echo "--- Telnet Banner ---" | tee -a report/findings.txt
   telnet_output=$(echo "" | nc -w 2 "$target" "$port" 2>&1)
   echo "$telnet_output" | head -n 5 | tee -a report/findings.txt
   echo "Telnet service detected on port $port." | tee -a report/findings.txt
   echo "Risk: Telnet communication is not strongly encrypted." | tee -a report/findings.txt
   echo "Recommendation: Replace Telnet with SSH where possible." | tee -a report/findings.txt
}

check_smtp() {
   local target=$1
   echo "Starting SMTP checks..."
   echo "--- SMTP User Enumeration ---" | tee -a report/findings.txt
   if command -v smtp-user-enum &> /dev/null; then
      smtp_output=$(smtp-user-enum -t "$target" -M VRFY -u root 2>&1)
      echo "$smtp_output" | tee -a report/findings.txt
      if echo "$smtp_output" | grep -qiE "found|exists|valid"; then
         echo "SMTP user enumeration returned a valid user." | tee -a report/findings.txt
         echo "Risk: User enumeration can help identify valid accounts." | tee -a report/findings.txt
         echo "Recommendation: Disable or restrict VRFY/EXPN where possible." | tee -a report/findings.txt
      else
         echo "No valid user was identified." | tee -a report/findings.txt
      fi
   else
      echo "smtp-user-enum is not installed." | tee -a report/findings.txt
   fi
   echo "" | tee -a report/findings.txt
   echo "--- SMTP Open Relay Check ---" | tee -a report/findings.txt
   smtp_relay=$(nc -w 3 "$target" 25 <<EOF
HELO test
MAIL FROM:<test@test.com>
RCPT TO:<test@example.com>
QUIT
EOF
)
   echo "$smtp_relay" | tee -a report/findings.txt
   if echo "$smtp_relay" | grep -q "250"; then
      echo "SMTP accepted the test command. Manual verification is recommended." | tee -a report/findings.txt
   else
      echo "Open relay was not confirmed." | tee -a report/findings.txt
   fi
}

check_dns() {
   local target=$1
   echo "Starting DNS zone transfer check..."
   echo "--- DNS Zone Transfer ---" | tee -a report/findings.txt
   dns_output=$(dig axfr @"$target" 2>&1)
   echo "$dns_output" | tee -a report/findings.txt
   if echo "$dns_output" | grep -q "XFR size"; then
      echo "DNS zone transfer may be allowed." | tee -a report/findings.txt
      echo "Risk: Zone transfer can expose DNS records and internal information." | tee -a report/findings.txt
      echo "Recommendation: Allow zone transfers only to authorized DNS servers." | tee -a report/findings.txt
   else
      echo "DNS zone transfer was not confirmed." | tee -a report/findings.txt
   fi
}

check_http() {
   local target=$1
   local port=$2
   echo "Starting HTTP enumeration..."
   echo "--- HTTP Headers ---" | tee -a report/findings.txt
   http_headers=$(curl -s -I --connect-timeout 5 "http://$target:$port/")
   echo "$http_headers" | tee -a report/findings.txt
   echo "" | tee -a report/findings.txt
   echo "--- robots.txt ---" | tee -a report/findings.txt
   robots_output=$(curl -s --connect-timeout 5 "http://$target:$port/robots.txt")
   echo "$robots_output" | tee -a report/findings.txt
   if echo "$http_headers" | grep -qi "Server:"; then
      echo "HTTP server information was disclosed in response headers." | tee -a report/findings.txt
      echo "Risk: Server information can help reconnaissance." | tee -a report/findings.txt
      echo "Recommendation: Minimize unnecessary server/version information." | tee -a report/findings.txt
   fi
}

check_smb() {
   local target=$1
   echo "Starting SMB enumeration..."
   echo "--- SMB Anonymous Share Enumeration ---" | tee -a report/findings.txt
   smb_output=$(smbclient -L "$target" -N 2>&1)
   echo "$smb_output" | tee -a report/findings.txt
   if echo "$smb_output" | grep -qi "Anonymous login successful"; then
      echo "Anonymous SMB access is allowed." | tee -a report/findings.txt
      echo "Risk: Anonymous access may expose shared resources." | tee -a report/findings.txt
      echo "Recommendation: Disable anonymous SMB access and restrict share permissions." | tee -a report/findings.txt
   else
      echo "Anonymous SMB login was not confirmed." | tee -a report/findings.txt
   fi
}

Target=$1

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "=================================================="
    echo "   Automated Security Assessment Tool (Secscan)   "
    echo "=================================================="
    echo "Usage:"
    echo "  ./secscan.sh <target_ip>   Start the security scan on target"
    echo "  ./secscan.sh --help        Show this help message"
    echo "  ./secscan.sh --version     Show tool version information"
    echo "=================================================="
    exit 0
fi

if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "Secscan Tool - Version 1.0.0 (Stable)"
    echo "Developed for Instant Software Solutions Project Brief."
    exit 0
fi

if [[ -z "$Target" ]]; then
   echo "Usage: ./secscan.sh <target>"
   exit 1
fi

for tool in nmap ping arp curl nc dig smbclient
do
   if ! command -v "$tool" &> /dev/null; then
      echo "warning $tool is not installed. Please install it before running the script."
      exit 1
   fi
done

if ! ping -c 1 "$Target" &> /dev/null; then
   echo "Target is unreachable"
   exit 1
fi

echo "Target $Target is online and ready for scanning"
echo "======================================"
echo "Gathering Target Information"
echo "====================================="

mkdir -p report
> report/findings.txt
> report/summary.txt
> report/open_ports.txt
> report/recon.txt
> report/scan.txt

echo "Target: $Target" | tee report/summary.txt
echo "Scan Date: $(date)" | tee -a report/summary.txt
echo "" | tee -a report/summary.txt

echo "--- Basic Network Information ---" | tee report/recon.txt
echo "IP Address: $Target" | tee -a report/recon.txt
echo "Hostname Information:" | tee -a report/recon.txt
getent hosts "$Target" | tee -a report/recon.txt
echo "ARP Information:" | tee -a report/recon.txt
arp -an | grep "$Target" | tee -a report/recon.txt

echo ""
echo "Starting Nmap Scan..."
echo "====================="
nmap -sV -p- "$Target" | tee report/scan.txt

echo ""
echo "Required Services"
echo "================="

grep -E "^[0-9]+/tcp[[:space:]]+open[[:space:]]+(ftp|ssh|telnet|smtp|domain|http|netbios-ssn)" report/scan.txt | \
awk '{print "Port: "$1"  Service: "$3"  Version: "$4" "$5" "$6}' \
| tee report/open_ports.txt

echo "" >> report/summary.txt
echo "Open Ports:" >> report/summary.txt
cat report/open_ports.txt >> report/summary.txt

smb_checked=0

while read -r port service
do
   echo ""
   echo "$service detected on port $port"

   if [[ "$service" == "netbios-ssn" || "$service" == "microsoft-ds" ]]; then
      if [[ "$smb_checked" -eq 1 ]]; then
         continue
      fi
      smb_checked=1
      check_smb "$Target"
   elif [[ "$service" == "smtp" ]]; then
      check_smtp "$Target"
   elif [[ "$service" == "domain" ]]; then
      check_dns "$Target"
   elif [[ "$service" == "ftp" ]]; then
      check_ftp "$Target" "$port"
   elif [[ "$service" == "ssh" ]]; then
      check_ssh "$Target" "$port"
   elif [[ "$service" == "telnet" ]]; then
      check_telnet "$Target" "$port"
   elif [[ "$service" == "http" ]]; then
      check_http "$Target" "$port"
   fi
done < <(grep -E "^[0-9]+/tcp[[:space:]]+open[[:space:]]+(ftp|ssh|telnet|smtp|domain|http|netbios-ssn|microsoft-ds)" report/scan.txt | awk '{print $1, $3}' | sed 's/\/tcp//')
echo ""
echo "======================================"
echo "Security Assessment Completed"
echo "======================================"
echo "Security Assessment Summary" > report/summary.txt
echo "================================" >> report/summary.txt
echo "Target: $Target" >> report/summary.txt
echo "Scan Date: $(date)" >> report/summary.txt
echo "" >> report/summary.txt
echo "Open Ports:" >> report/summary.txt
cat report/open_ports.txt >> report/summary.txt
echo "" >> report/summary.txt
echo "Findings:" >> report/summary.txt
cat report/findings.txt >> report/summary.txt
echo ""
echo "Reports generated:"
echo "report/recon.txt"
echo "report/scan.txt"
echo "report/open_ports.txt"
echo "report/findings.txt"
echo "report/summary.txt"

html_report="report/report.html"
echo "<html>" > "$html_report"
echo "<head>" >> "$html_report"
echo "<meta charset=\"UTF-8\">" >> "$html_report"
echo "<title>Security Assessment Report</title>" >> "$html_report"
echo "<style>" >> "$html_report"
echo "body { font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; color: #333; }" >> "$html_report"
echo "h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }" >> "$html_report"
echo "h2 { margin-top: 25px; }" >> "$html_report"
echo ".section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }" >> "$html_report"
echo ".finding { background: #ffffff; border-left: 5px solid #555; padding: 15px; margin: 15px 0; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.08); }" >> "$html_report"
echo ".finding-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #222; }" >> "$html_report"
echo ".finding-content { background: #f7f7f7; padding: 12px; border-radius: 5px; white-space: pre-wrap; overflow-x: auto; }" >> "$html_report"
echo "pre { background: #eee; padding: 15px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }" >> "$html_report"
echo "</style>" >> "$html_report"
echo "</head>" >> "$html_report"
echo "<body>" >> "$html_report"
echo "<h1>Security Assessment Report</h1>" >> "$html_report"
echo "<h2>Scan Information</h2>" >> "$html_report"
echo "<div class=\"section\">" >> "$html_report"
echo "Target: $Target<br>" >> "$html_report"
echo "Scan Date: $(date)" >> "$html_report"
echo "</div>" >> "$html_report"
echo "<h2>Open Ports</h2>" >> "$html_report"
echo "<div class=\"section\">" >> "$html_report"
echo "<pre>" >> "$html_report"
cat report/open_ports.txt >> "$html_report"
echo "</pre>" >> "$html_report"
echo "</div>" >> "$html_report"
echo "<h2>Detailed Findings</h2>" >> "$html_report"
echo "<div class=\"section\">" >> "$html_report"
current_title=""
while IFS= read -r line
do
   if [[ "$line" == ---*--- ]]; then
      if [[ -n "$current_title" ]]; then
         echo "</div>" >> "$html_report"
         echo "</div>" >> "$html_report"
      fi
      current_title="${line#--- }"
      current_title="${current_title% ---}"
      echo "<div class=\"finding\">" >> "$html_report"
      echo "<div class=\"finding-title\">$current_title</div>" >> "$html_report"
      echo "<div class=\"finding-content\">" >> "$html_report"
   else
      if [[ -n "$current_title" ]]; then
         echo "$line" >> "$html_report"
      fi
   fi
done < report/findings.txt

if [[ -n "$current_title" ]]; then
   echo "</div>" >> "$html_report"
   echo "</div>" >> "$html_report"
fi
echo "</div>" >> "$html_report"
echo "</body>" >> "$html_report"
echo "</html>" >> "$html_report"
echo "[+] HTML Report generated successfully at: $html_report"
