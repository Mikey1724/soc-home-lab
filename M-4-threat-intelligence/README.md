# Month 4 : Threat Intelligence

**Analyst:** Jean Mik C. TINIGO
**Period:** September 2026
**Status:** ✅ Complete

---

## Overview

Month 4 moves from detection and investigation into **understanding the adversary**. Three projects build a complete Threat Intelligence capability: a CTI platform for IOC management, behavioral detection
rules that survive infrastructure changes, and a professional TI report that compiles everything into an actionable intelligence deliverable.

The core shift from previous months: instead of asking *"what happened?"*, the analyst now asks *"who did this, why, and what will they do next?"*

---

## Projects

| # | Project | Tools | Format | Status |
|---|---------|-------|--------|--------|
| 4.1 | MISP CTI Platform + IOC Enrichment | MISP 2.5.45 - Docker - VirusTotal API | `.md` | ✅ |
| 4.2 | YARA Rules + Static Malware Analysis | YARA 4.5.0 - Python - yara-python | `.md` | ✅ |
| 4.3 | Threat Intelligence Report - Simulated APT | All Month 4 tools | `.pdf` | ✅ |

---

## Project 4.1 : MISP CTI Platform + IOC Enrichment

> *"VirusTotal tells you if an IOC is malicious.
> MISP tells you who used it, in which campaign,
> what other IOCs are linked, and what technique was used.
> That is the difference between verification and intelligence."*

Deployed MISP 2.5.45 via Docker on Ubuntu Server and created two MISP events from real malware campaigns analyzed in Month 1. Built a Python enrichment pipeline querying the VirusTotal API for all IOCs automatically, then connected MISP to the VT public module for in-platform enrichment.

**MISP Events created:**

| Event | Malware | IOCs | TLP |
|---|---|---|---|
| 2026-01-31 | Lumma Stealer C2 activity - credential theft | 7 | TLP:AMBER |
| 2026-02-28 | NetSupport RAT C2 beaconing - POST /fakeurl.htm | 4 | TLP:AMBER |

**IOC classification : shared vs private:**

| Shared (TLP:AMBER) | Private (Org Only) |
|---|---|
| 153.92.1.49 (C2 IP) | 10.1.21.58 (victim IP) |
| whitepepper.su (C2 domain) | DESKTOP-ES9F3ML (hostname) |
| /api/set_agent (URI pattern) | - |

**Python enrichment script:**
Automated VirusTotal API queries for all IOCs with rate limiting (20s sleep between requests — adjusted from 15s after hitting the 4 req/min limit on the free tier).

**Production issue resolved:**
`ForbiddenError` from MISP enrichment, diagnosed via Docker logs, identified wrong VT plugin (`virustotal` vs `virustotal_public`). Standard plugin requires higher rate limits than free account. Fixed by enabling `Plugin.Enrichment_virustotal_public_enabled`.

📄 [`misp_plateforme-cti-+-enrichissement-ioc(s).md`](./misp_plateforme-cti-+-enrichissement-ioc(s).md)
📄 [`vt_enrichment.py`](./vt_enrichment.py)

---

## Project 4.2 : YARA Rules + Static Malware Analysis

> *"An IP address lasts 24 hours. A C2 domain lasts a few days.
> A behavioral pattern lasts years. That's why YARA exists."*

Wrote 3 YARA rules to detect Lumma Stealer and NetSupport RAT based on behavioral patterns extracted from Month 1 PCAP analysis rules that survive C2 infrastructure changes.

**Rules written:**

| Rule | Target | Key Detection Logic |
|---|---|---|
| `Lumma_Stealer_C2_Pattern` | Lumma Stealer | `/api/set_agent` + `agent=Chrome/Edge` + `act=log` |
| `NetSupport_RAT_C2` | NetSupport RAT | `/fakeurl.htm` + `NetSupport Manager` UA |
| `Suspicious_PE_Strings_v2` | Generic malware | 5 branches: credential theft, HTTP C2, obfuscated PS, PE injection imports, persistence |

**Rule 3 : key technical decisions:**

The first version used `"VirtualAllocEx"` as an ASCII string match. Replaced with `pe.imports("kernel32.dll", "VirtualAllocEx")`, checks the actual PE import table instead of searching for string occurrences. More precise, far fewer false positives.

**False positive analysis documented:**
- `$cred1 = "password"` -> matches every browser and email client
- `$http1 = "POST"` -> matches every HTTP library
- API names as strings -> appear in debug symbols of legitimate binaries

**MITRE ATT&CK:**

| Technique ID | Name | Rule |
|---|---|---|
| T1071.001 | Application Layer Protocol: HTTP | Lumma_Stealer_C2_Pattern |
| T1555.003 | Credentials from Web Browsers | Lumma_Stealer_C2_Pattern |
| T1219 | Remote Access Software | NetSupport_RAT_C2 |
| T1059.001 | PowerShell | Suspicious_PE_Strings_v2 |
| T1055.001 | Process Injection: DLL Injection | Suspicious_PE_Strings_v2 |
| T1547.001 | Registry Run Keys | Suspicious_PE_Strings_v2 |
| T1053.005 | Scheduled Task | Suspicious_PE_Strings_v2 |

📄 [`yara_rules_static_malware_analysis.md`](./yara_rules_static_malware_analysis.md)
📄 [`local_rules.yar`](./local_rules.yar)
📄 [`yara_scanner.py`](./yara_scanner.py)

---

## Project 4.3 : Threat Intelligence Report: Simulated APT Campaign

> *"An IOC has a lifespan of hours. A behavioral rule lasts years.
> A TI report gives the full picture : who, why, how, and what's next."*

Compiled all Month 1 and Month 4 findings into a professional 14-page Threat Intelligence report covering two coordinated malware campaigns targeting Windows endpoints in West Africa.

**Report structure:**

| Section | Audience | Content |
|---|---|---|
| Executive Summary | CISO / Management | Non-technical overview, 4 immediate actions |
| Threat Actor Profile | L3 / TI team | Attribution, motivation, capability level |
| Campaign Overview | L2 / L3 | Timeline, geographic targeting, infrastructure overlap |
| Technical Analysis | L2 | C2 protocols, victim fingerprints, MITRE mapping |
| Detection & Hunting | L1 / L2 | Suricata rules, YARA rules, OpenSearch DSL queries |
| Recommendations | Management | 3 horizons: 0-24h, 1-7 days, 7-30 days |

**Key findings:**

```
Campaign 1 : Lumma Stealer (2026-01-27)
  -> Credential theft: Chrome + Edge browser databases
  -> C2: whitepepper.su via /api/set_agent
  -> 4h21 active exfiltration before detection
  -> Victim: DESKTOP-ES9F3ML (Gabriel Wyatt / gwyatt)

Campaign 2 : NetSupport RAT (2026-02-28)
  -> Persistent remote access via /fakeurl.htm
  -> 60-second beaconing interval for 4h21
  -> Post-compromise: SMB (1528 pkts) + LDAP (1138 pkts)
  -> AD enumeration: easyas123.tech domain discovered
```

**Network Indicators to Block (Priority):**

| Type | Value | Priority |
|---|---|---|
| IP | 153.92.1.49 | CRITICAL |
| IP | 45.131.214.85 | CRITICAL |
| Domain | whitepepper.su | HIGH |
| Domain | whooptm.cyou | HIGH |
| URI | /api/set_agent | HIGH |
| URI | /fakeurl.htm | HIGH |
| User-Agent | NetSupport Manager/* | HIGH |
| Domain | vadusa.xyz | MEDIUM |

📄 [`threat_intelligence_report_simulated_APT_campaign.pdf`](./threat_intelligence_report_simulated_APT_campaign.pdf)

---

## Skills Demonstrated

```
Threat Intelligence   ████████░░  MISP - IOC management - TLP classification
IOC Enrichment        ████████░░  VirusTotal API - Python automation - rate limiting
YARA Rules            ████████░░  Behavioral detection - PE analysis - FP reduction
Static Analysis       ███████░░░  PE structure - import tables - string analysis
TI Reporting          ████████░░  Executive summary - CISO communication - recommendations
MITRE ATT&CK          █████████░  8 techniques mapped across 2 campaigns
```

---

## Repository Structure

```
month-4-threat-intel/
├── README.md                                                       <- This file
├── misp_plateforme-cti-+-enrichissement-ioc(s).md                  <- Project 4.1
├── vt_enrichment.py                                                <- VT API enrichment script
├── yara_rules_static_malware_analysis.md                           <- Project 4.2
├── local_rules.yar                                                 <- 3 YARA rules
├── yara_scanner.py                                                 <- YARA automation script
├── threat_intelligence_report_simulated_APT_campaign.pdf           <- Project 4.3 TI report
└── screenshots/
    ├── port_4433_in_docker_compose.png
    ├── event_1_main.png
    ├── event_2_main.png
    ├── event_2_ioc.png
    ├── public_api_options.png
    ├── ioc_enrichment_python_script.png
    ├── enrichment_api_key.png
    ├── ioc_enrichment_result_on_misp.png
    ├── event_1_after_enrichment.png
    ├── shared_vs_private_ioc.png
    ├── enable_tlp.png
    ├── yara_rule_test.png
    └── yara_scanner_script_result.png
```

---

## Resources Used

- [MISP Documentation](https://www.misp-project.org/documentation/)
- [MISP VT Public Module](https://misp.github.io/misp-modules/expansion/#virustotal-public-api-lookup)
- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [YARA Documentation](https://yara.readthedocs.io/en/stable/)
- [MITRE ATT&CK](https://attack.mitre.org)
- [TLP Standard](https://www.first.org/tlp/)