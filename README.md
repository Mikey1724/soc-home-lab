# 🛡️ SOC Home Lab - Junior Analyst Portfolio

**Author:** Mik TINIGO
**Status:** 🟢 Active - updated monthly
**Goal:** Become a job-ready SOC Analyst through hands-on projects

---

## About This Repository

This repo documents my self-directed training as an aspiring SOC Analyst.
Every project is built on open-source tools used in real Security Operations Centers.
No paid certifications - just practical work, real malware samples, and structured reporting.

Each month covers a new layer of the SOC analyst skillset, from Linux fundamentals to SIEM deployment, incident response, and threat intelligence.

---

## Portfolio Overview

| Month | Focus Area | Tools | Projects | Status |
|-------|-----------|-------|----------|--------|
| 1 | Linux CLI · Network Analysis · IDS | Wireshark, tshark, Suricata | 3 | ✅ Complete |
| 2 | SIEM & Log Management | Wazuh, Kibana, OpenSearch | 3 | ✅ Complete |
| 3 | Incident Response & Forensics | Zeek, TheHive, Volatility | 3 | ✅ Complete |
| 4 | Threat Intelligence | MISP, YARA, VirusTotal API | 3 | 🔄 In progress |
| 5 | SOC Automation & SOAR | Shuffle, Python, TheHive API | 3 | ⏳ Planned |
| 6 | Full Lab + CTF + Job Prep | All tools | 3 | ⏳ Planned |

---

## Month 1 - Foundations

### Project 1.1 - Linux SOC Lab
> Simulated security events on Ubuntu Server and detected them using native CLI tools.

- Brute-force SSH detection with `grep`, `awk`, `journalctl`
- Custom Bash detection script with threshold-based alerting
- Auditd configuration for file integrity monitoring

📁 [`M-1-linux/`](./M-1-linux/)

---

### Project 1.2 - Malware Traffic Analysis (Wireshark)
> Analyzed real-world PCAP files from malware-traffic-analysis.net.
> Identified compromised hosts, C2 traffic, and extracted IOCs.

| Exercise | Malware | Victim IP | C2 Server | IOCs |
|----------|---------|-----------|-----------|------|
| 2026-01-31 | Lumma Stealer | 10.1.21.58 | 153.92.1.49 | 10 |
| 2026-02-28 | NetSupport RAT | 10.2.28.88 | 45.131.214.85 | 5 |

📁 [`M-1-wireshark/`](./M-1-wireshark/)

---

### Project 1.3 - IDS Deployment with Suricata
> Deployed Suricata as a network IDS, wrote 10 custom detection rules,
> simulated real attacks from Kali Linux, and validated each rule via eve.json alerts.

- Custom rules: ICMP, Nmap scans, SSH brute-force, 6 SQL injection variants
- Emerging Threats ruleset integration
- Threshold-based behavioral detection (TCP SYN rates)

📁 [`M-1-suricata/`](./M-1-suricata/)

---

## Month 2 - SIEM Deployment, Dashboards & Alert Correlation

### Project 2.1 - Wazuh SIEM + Suricata Integration
> Installed Wazuh 4.14 from scratch on Ubuntu Server (no pre-built VM).
> Configured Wazuh Agent to ingest Suricata eve.json into OpenSearch in real time.

- Full pipeline: Suricata alert -> Wazuh Agent -> OpenSearch -> Threat Hunting
- OpenSearch DSL queries to confirm raw alert ingestion
- Wazuh auto-detected system events (PAM, sudo, AppArmor) without extra config
- Production issue resolved: port 1514/tcp blocked by UFW

📁 [`month-2-wazuh/`](./month-2-wazuh/)

---

### Project 2.2 - Kibana Dashboard + Brute-Force Detection
> Built 4 Kibana visualizations and assembled a SOC monitoring dashboard.
> Wrote a custom Wazuh XML rule detecting SSH brute-force via behavioral analysis.

| Visualization | Type | SOC Value |
|---|---|---|
| Top 10 Alert Types | Bar chart | Identify dominant threats |
| Alert Timeline | Line chart | Detect temporal anomalies |
| Alert Sources Distribution | Donut | Log source breakdown |
| Top Attacker IPs | Data table | Identify hostile sources |

Custom rule 100002 (level 10), 5× SSH failures in 120s -> alert triggered ✅

📁 [`month-2-wazuh/kibana-dashboard-report.pdf`](./month-2-wazuh/kibana-dashboard-report.pdf)

---

### Project 2.3 - Multi-Source Alert Correlation
> Built a 4-rule Wazuh correlation chain reconstructing a complete attack sequence across two independent log sources (Suricata IDS + Linux auth logs).

```
21:17:55  Nmap SYN scan       ->  rule 100003  level 5
21:19:04  SSH brute-force     ->  rule 100005  level 12  <- CORRELATION
21:20:09  sudo privilege esc. ->  rule 100006  level 14  <- CRITICAL
```

| Technique | Name | Rule |
|---|---|---|
| T1595.001 | Active Scanning | 100003 |
| T1110.001 | Password Guessing | 100005 |
| T1078 | Valid Accounts | 100006 |

📁 [`month-2-wazuh/multi-source-correlation.md`](./month-2-wazuh/multi-source-correlation.md)

---

## Month 3 - Incident Response & Forensics *(In progress)*

### Project 3.1 - Zeek Network Analysis + MITRE ATT&CK
> Deployed Zeek 8.2.0 in cluster mode to investigate a confirmed attack chain.
> Answered 7 forensic investigation questions using only Zeek logs.

- 2009 connections from attacker IP, scan confirmed via S0 conn_state
- SSH brute-force sessions identified via ssh.log (auth_success field)
- Suricata vs Zeek: alert perspective vs full network context (3 events compared)
- Deployed in production cluster mode (Logger / Manager / Proxy / Worker)

| Technique | Name | Zeek Evidence |
|---|---|---|
| T1595.002 | Port Scanning | 2028× conn_state S0 |
| T1110.001 | Password Guessing | ssh.log auth_success: false |
| T1078 | Valid Accounts | ssh.log auth_success: true |
| T1571 | Non-Standard Port | Connections to unusual ports |

📁 [`month-3-zeek-thehive/zeek-network-analysis.md`](./month-3-zeek-thehive/zeek-network-analysis.md)

---
 
### Project 3.2 - TheHive : Full Incident Lifecycle
> Deployed TheHive 5.5 via Docker and handled the complete SOC incident
> lifecycle for case SOC-2026-001 (Lateral Movement Attempt).
 
- L1 triage -> L2 investigation -> L3 closure : all roles demonstrated
- 3 IOC observables attached (attacker IP, victim IP, Wazuh rule)
- 4 investigation tasks with Zeek evidence, impact assessment, recommendations
- Case closed: TRUE POSITIVE - MEDIUM impact, no breach achieved
| Task | Outcome |
|---|---|
| Initial Triage | TRUE POSITIVE confirmed |
| Network Investigation | 2009 connections, SSH brute-force failed |
| Impact Assessment | No exfiltration, no lateral movement |
| Containment Recommendations | Firewall block, fail2ban, SSH hardening |
 
📁 [`month-3-zeek-thehive/thehive-incident-management.md`](./month-3-zeek-thehive/thehive-incident-management.md)
 
---
 
### Project 3.3 - Memory Forensics with Volatility
> Analyzed a real Windows 7 memory dump (MemLabs Lab 1) using Volatility2.
> Completed a 3-flag CTF through structured forensic investigation.
 
- imageinfo -> Windows 7 SP1 x64 identified
- pslist / psscan -> cmd.exe, mspaint.exe, explorer.exe flagged
- cmdline -> WinRAR compressing "Important" files discovered
- hashdump -> NTLM hash extracted, used as RAR password
- consoles -> Base64-encoded string decoded to flag
- memdump + GIMP Raw RGB -> pixel data reveals final flag
**Flags recovered: 3/3** ✅
 
| Technique ID | Name | Evidence |
|---|---|---|
| T1059.003 | Windows Command Shell | cmd.exe in psscan, commands in cmdscan |
| T1560.001 | Archive via Utility | WinRAR compressing Important files |
| T1003.001 | OS Credential Dumping | NTLM hash via hashdump plugin |
| T1027 | Obfuscated Files or Information | Base64-encoded string in console |
| T1005 | Data from Local System | Files collected and archived |
 
📁 [`month-3-zeek-thehive/memory-forensics-with-volatility.md`](./month-3-zeek-thehive/memory-forensics-with-volatility.md)
 
---
 
## Month 4 - Threat Intelligence *(In progress)*
 
### Project 4.1 - MISP Platform + IOC Enrichment *(coming soon)*
### Project 4.2 - YARA Rules + Static Malware Analysis *(coming soon)*
### Project 4.3 - Threat Intelligence Report *(coming soon)*
 
---

## Skills Demonstrated

```
Network Analysis    ████████░░  Wireshark · tshark · PCAP forensics · Zeek
Linux / CLI         ████████░░  Log analysis · Bash scripting · auditd
Intrusion Detection ████████░░  Suricata · custom rules · eve.json
Threat Detection    ████████░░  IOC extraction · MITRE ATT&CK mapping
SIEM                ███████░░░  Wazuh · Kibana · OpenSearch DSL · correlation
Incident Management ████████░░  TheHive · case lifecycle · TLP/PAP · observables
Network Forensics   ████████░░  Zeek cluster · conn_state · investigation
Memory Forensics    ███████░░░  Volatility2 · hashdump · memdump · GIMP
Investigation       ███████░░░  Zeek logs · conn_state analysis · SSH forensics
Reporting           ████████░░  Installation · monitoring · investigation formats
```

---

## Tools Used

![Linux](https://img.shields.io/badge/Linux-Ubuntu_24.04-E95420?style=flat&logo=ubuntu&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?style=flat&logo=wireshark&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-8.0-orange?style=flat)
![Wazuh](https://img.shields.io/badge/Wazuh-4.14-blue?style=flat)
![Zeek](https://img.shields.io/badge/Zeek-8.2-005571?style=flat)
![TheHive](https://img.shields.io/badge/TheHive-5.5-F3A922?style=flat)
![Volatility](https://img.shields.io/badge/Volatility-2-4A4A4A?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Kibana](https://img.shields.io/badge/Kibana-OpenSearch-005571?style=flat)

---

## Repository Structure

```
soc-home-lab/
├── README.md                          <- You are here
├── M-1-linux/
│   ├── README.md
│   ├── detect_bruteforce.sh
│   └── analysis-report.md
├── M-1-wireshark/
│   ├── README.md
│   ├── lumma-stealer-2026-01-31-report.md
│   └── netsuport-rat-2026-02-28-report.md
├── M-1-suricata/
│   ├── README.md
│   ├── local.rules
│   └── Rapport_Suricata.pdf
├── month-2-wazuh/
│   ├── README.md
│   ├── screenshots/
│   ├── wazuh-suricata-integration.md
│   ├── kibana-dashboard-report.pdf
│   └── multi-source-correlation.md
├── month-3-zeek-thehive/
│   ├── README.md              
|   ├── screenshots/
|   ├── zeek-network-analysis.md
|   └── thehive-incident-management.md
├── month-4-threat-intel/

```

---

## Methodology

Every analysis follows a structured 8-phase workflow:

```
1. Overview         -> packet count, duration, protocol mix
2. Host mapping     -> identify victim, gateway, external IPs
3. DNS analysis     -> suspicious domains, DGA patterns
4. HTTP analysis    -> POST requests, User-Agents, C2 URIs
5. Beaconing        -> intervals, repeated connections
6. Internal traffic -> SMB, LDAP, lateral movement indicators
7. IOC validation   -> VirusTotal, AbuseIPDB, WHOIS
8. Reporting        -> timeline, MITRE ATT&CK, recommendations
```

---

## Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jean-mik-c-tinigo)

*Open to remote SOC Analyst Junior opportunities.*