# 🛡️ SOC Home Lab — Junior Analyst Portfolio

**Author:** Mik TINIGO
**Status:** 🟢 Active — updated monthly
**Goal:** Become a job-ready SOC Analyst through hands-on projects

---

## About This Repository

This repo documents my self-directed training as an aspiring SOC Analyst.
Every project is built on open-source tools used in real Security Operations Centers.
No paid certifications — just practical work, real malware samples, and structured reporting.

Each month covers a new layer of the SOC analyst skillset, from Linux fundamentals
to SIEM deployment, incident response, and threat intelligence.

---

## Portfolio Overview

| Month | Focus Area | Tools | Projects | Status |
|-------|-----------|-------|----------|--------|
| 1 | Linux CLI · Network Analysis · IDS | Wireshark, tshark, Suricata | 3 | ✅ Complete |
| 2 | SIEM & Log Management | Wazuh, ELK Stack, Kibana | 3 | 🔄 In progress |
| 3 | Incident Response & Forensics | Zeek, TheHive, Volatility | 3 | ⏳ Planned |
| 4 | Threat Intelligence | MISP, YARA, VirusTotal API | 3 | ⏳ Planned |
| 5 | SOC Automation & SOAR | Shuffle, Python, TheHive API | 3 | ⏳ Planned |
| 6 | Full Lab + CTF + Job Prep | All tools | 3 | ⏳ Planned |

---

## Month 1 — Foundations

### Project 1.1 — Linux SOC Lab
> Simulated security events on Ubuntu Server and detected them using native CLI tools.

- Brute-force SSH detection with `grep`, `awk`, `journalctl`
- Custom Bash detection script with threshold-based alerting
- Auditd configuration for file integrity monitoring

📁 [`month-1-linux/`](./M-1-linux/)

---

### Project 1.2 — Malware Traffic Analysis (Wireshark)
> Analyzed real-world PCAP files from malware-traffic-analysis.net.
> Identified compromised hosts, C2 traffic, and extracted IOCs.

| Exercise | Malware | Victim IP | C2 Server | IOCs |
|----------|---------|-----------|-----------|------|
| 2026-01-31 | Lumma Stealer | 10.1.21.58 | 153.92.1.49 | 10 |
| 2026-02-28 | NetSupport RAT | 10.2.28.88 | 45.131.214.85 | 5 |

📁 [`month-1-wireshark/`](./M-1-wireshark/)

---

### Project 1.3 — IDS Deployment with Suricata
> Deployed Suricata as a network IDS and wrote custom detection rules
> simulate real attacks from a Kali Linux machine, and validate each rule by analyzing Suricata alert logs.

- Custom rules targeting classic attacks patterns (ICMP,NMAP,SSH brute-force,SQLi)
- Emerging Threats ruleset integration
- Alert analysis via eve.json

📁 [`month-1-suricata/`](./M-1-suricata/) 

---

## Skills Demonstrated

```
Network Analysis    ████████░░  Wireshark · tshark · PCAP forensics
Linux / CLI         ████████░░  Log analysis · Bash scripting · auditd
Intrusion Detection ███████░░░  Suricata · custom rules · eve.json
Threat Detection    ███████░░░  IOC extraction · MITRE ATT&CK mapping
Reporting           ████████░░  Executive summary · technical detail
SIEM                ░░░░░░░░░░  Starting Month 2
```

---

## Tools Used

![Linux](https://img.shields.io/badge/Linux-Ubuntu_22.04-E95420?style=flat&logo=ubuntu&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?style=flat&logo=wireshark&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS-orange?style=flat)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)

---

## Repository Structure

```
soc-home-lab/
├── README.md                  ← You are here
├── month-1-linux/
│   ├── README.md
│   ├── detect_bruteforce.sh
│   └── analysis-report.md
├── month-1-wireshark/
│   ├── README.md
│   ├── lumma-stealer-2026-01-31-report.md
│   └── netsuport-rat-2026-02-28-report.md
├── month-1-suricata/   
|   ├── README.md
│   ├── local.rules
│   └── Rapport_Suricata.pdf      
├── month-2-wazuh/             ← coming soon
└── ...
```

---

## Methodology

Every analysis follows a structured 8-phase workflow :

```
1. Overview        → packet count, duration, protocol mix
2. Host mapping    → identify victim, gateway, external IPs
3. DNS analysis    → suspicious domains, DGA patterns
4. HTTP analysis   → POST requests, User-Agents, C2 URIs
5. Beaconing       → intervals, repeated connections
6. Internal traffic→ SMB, LDAP, lateral movement indicators
7. IOC validation  → VirusTotal, AbuseIPDB, WHOIS
8. Reporting       → timeline, MITRE ATT&CK, recommendations
```

---

## Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jean-mik-c-tinigo)

*Open to remote SOC Analyst Junior opportunities.*
