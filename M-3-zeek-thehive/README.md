# Month 3 - Incident Response & Forensics

**Analyst:** Jean Mik C. TINIGO
**Period:** May - July 2026
**Status:** ✅ Complete

---

## Overview

Month 3 moves from detection and monitoring into **active investigation and incident response**, the core of what a SOC analyst does daily.

Three projects cover the full incident response lifecycle:
network forensics with Zeek, structured case management with TheHive, and memory forensics with Volatility. Each project builds on the previous one, forming a complete investigation chain.

---

## Projects

| # | Project | Tools | Format | Status |
|---|---------|-------|--------|--------|
| 3.1 | Zeek Network Analysis + MITRE ATT&CK | Zeek 8.2.0 - zeek-cut - Ubuntu | `.md` | ✅ |
| 3.2 | TheHive + Full Incident Lifecycle | TheHive 5.5 - Docker - Wazuh | `.md` | ✅ |
| 3.3 | Memory Forensics with Volatility | Volatility2 - Python2.7 - GIMP | `.md` | ✅ |

---

## Project 3.1 - Zeek Network Analysis + MITRE ATT&CK

> *"Suricata tells you WHAT happened. Zeek tells you EVERYTHING that happened."*


Deployed Zeek 8.2.0 in **cluster mode** (Logger / Manager / Proxy / Worker) on Ubuntu Desktop and investigated a confirmed attack chain from Project 2.3 using only Zeek logs, answering 7 forensic
investigation questions.

**Key findings:**

| Question | Finding |
|---|---|
| Most active source IP | 10.209.119.114, 2009 connections |
| Scan confirmed | 2028 × conn_state S0 (SYN, no response) |
| SSH brute-force | auth_success: false on all attempts |
| Data exfiltration | None detected |
| Lateral movement | None, single machine targeted |
| DNS abuse | No suspicious domains or TLDs |

**Suricata vs Zeek, 3 events compared:**

| Event | Suricata | Zeek |
|---|---|---|
| Nmap scan | Alert: rule fired | 2028 S0 conn_states, ports mapped |
| SSH brute-force | Alert: threshold triggered | Burst pattern, auth_success: false |
| ICMP ping | Alert: ICMP Ping | Count, timestamps, conn duration |

**MITRE ATT&CK:**

| Technique | Name | Evidence |
|---|---|---|
| T1595.002 | Active Scanning: Port Scanning | 2028 × S0 conn_state |
| T1110.001 | Password Guessing | ssh.log auth_success: false |
| T1078 | Valid Accounts | ssh.log auth_success: true |
| T1571 | Non-Standard Port | Connections to unusual ports |

**Technical decision:** Deployed in cluster mode rather than standalone to reflect production environment practices. Used `zeek-cut` exclusively over `awk` for field extraction, more reliable across Zeek versions.

📄 [`zeek-network-analysis.md`](./zeek-network-analysis.md)

---

## Project 3.2 - TheHive : Full Incident Lifecycle

> *"Detecting a threat is step one. Managing the incident is the real job."*

Deployed TheHive 5.5 via Docker on Ubuntu Server and handled the complete SOC incident lifecycle for case **SOC-2026-001** (Lateral Movement Attempt), from case creation to formal closure.

**Case details:**

| Field | Value |
|---|---|
| Case ID | SOC-2026-001 |
| Title | Lateral Movement Attempt - Scan + SSH Brute-Force |
| Severity | High (3) |
| TLP | TLP:AMBER |
| Resolution | TRUE POSITIVE - no breach achieved |
| Duration | 21:17:55 -> 21:20:10 UTC (2m15s) |

**4 investigation tasks completed:**

| Task | Analyst Role | Outcome |
|---|---|---|
| Initial Triage | L1 | TRUE POSITIVE confirmed |
| Network Investigation (Zeek) | L2 | 2009 connections, S0 scan, SSH failed |
| Impact Assessment | L2 | No exfiltration, no lateral movement |
| Containment Recommendations | L2/L3 | Firewall block, fail2ban, SSH hardening |

**3 Observables attached:**

| Type | Value | Tags |
|---|---|---|
| ip | 10.209.119.114 | attacker, scanner, brute-force-source |
| ip | 10.209.119.127 | victim, target |
| other | rule:100005 level:12 | wazuh-rule, correlation |

**Production challenges resolved:**
- Official TheHive GitHub repo archived Dec 2025, located new installation source
- Elasticsearch OOM Killer crash, diagnosed via system logs, resolved by reallocating VM resources across both machines

📄 [`thehive-incident-management.md`](./thehive-incident-management.md)

---

## Project 3.3 - Memory Forensics with Volatility

> *"RAM is not just running programs - it's credentials, commands, open files, encoded strings, and 
> pixel art, all waiting to be found before the machine shuts down."*

Analyzed a real Windows 7 memory dump (MemLabs Lab 1) using Volatility2 on Ubuntu Desktop. Completed a 3-flag CTF challenge through structured forensic investigation, no hints, methodology-first.

**Investigation approach:**

```
Initial Thoughts -> clues from context
        │
        
imageinfo -> OS: Windows 7 SP1 x64
        │
        
pslist / psscan / pstree -> 3 suspect processes identified -> cmd.exe · mspaint.exe · explorer.exe
        │
        
cmdline -> WinRAR compressing "Important" files -> username: Alissa Simpson discovered
        │
        
filescan + dumpfiles -> Important.rar extracted
        │
        
hashdump -> NTLM hash extracted -> used as RAR password -> Flag 3 found in PNG file
        │
        
cmdscan + consoles -> Base64 string in stdout -> decoded -> Flag 1 found
        │
        
memdump (mspaint PID) -> .dmp -> .data -> GIMP Raw RGB -> Flag 2 found in pixel data
```

**Flags recovered: 3/3** ✅

**MITRE ATT&CK:**

| Technique ID | Name | Evidence |
|---|---|---|
| T1059.003 | Windows Command Shell | cmd.exe in psscan, commands in cmdscan |
| T1560.001 | Archive via Utility | WinRAR compressing Important files |
| T1003.001 | OS Credential Dumping: LSASS | NTLM hash via hashdump plugin |
| T1027 | Obfuscated Files or Information | Base64-encoded string in console output |
| T1005 | Data from Local System | Important files collected and archived |

**Key technical decisions:**
- Switched from Volatility3 to Volatility2 : missing plugins in V3 (`hashdump`, `cmdscan`, `consoles`) were essential for this investigation
- Installed `pycryptodome` and `distorm3` manually for full plugin support
- Used Python `upper()` locally to format NTLM hash, no external services

📄 [`memory-forensics-with-volatility.md`](./memory-forensics-with-volatility.md)

---

## Skills Demonstrated

```
Network Forensics    ████████░░  Zeek cluster · zeek-cut · conn_state analysis
Incident Management  ████████░░  TheHive · case lifecycle · TLP/PAP · observables
Memory Forensics     ███████░░░  Volatility2 · pslist/psscan · hashdump · GIMP
MITRE ATT&CK         ████████░░  Technique mapping across all 3 project types
Investigation        ████████░░  Methodology-first · clue-based reasoning
Reporting            ████████░░  Network · incident · forensics formats
```

---

## Repository Structure

```
month-3-zeek-thehive/
├── README.md                          <- This file
├── zeek-network-analysis.md           <- Project 3.1
├── thehive-incident-management.md     <- Project 3.2
├── memory-forensics-with-volatility.md <- Project 3.3
└── screenshots/

```

---

## Resources Used

- [Zeek Documentation](https://docs.zeek.org/en/master/)
- [TheHive Documentation](https://docs.thehive-project.org)
- [MemLabs Lab 1](https://github.com/stuxnet999/MemLabs)
- [Volatility2](https://github.com/volatilityfoundation/volatility)
- [MITRE ATT&CK](https://attack.mitre.org)
- [TLP Standard](https://www.first.org/tlp/)
- [OpenClassrooms — Investigation d'incident numérique forensic](https://openclassrooms.com)