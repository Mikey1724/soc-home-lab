# Month 1 — Project 1.2 : Network Traffic Analysis with Wireshark

**Analyst:** Mik TINIGO
**Date:** 2026-05-03
**Difficulty:** Beginner
**Tools:** Wireshark, tshark

---

## Objective

Practice network traffic analysis by examining real-world PCAP files from
malware-traffic-analysis.net. The goal is to identify compromised hosts,
malicious activity, and document Indicators of Compromise (IOCs) using
a structured SOC analyst methodology.

---

## Environment

| Component     | Details                                      |
|---------------|----------------------------------------------|
| Analysis OS   | Ubuntu 22.04 (VirtualBox)                    |
| Tools used    | Wireshark 4.x, tshark                        |
| PCAP Source   | malware-traffic-analysis.net                 |
| Methodology   | 8-phase PCAP analysis workflow               |

---

## Files in this folder

| File | Description |
|------|-------------|
| `lumma-stealer-2026-01-31-report.md` | Full analysis report — Lumma Stealer infection |
| `README.md` | This file |

---

## Summary of Findings

| Exercise Date | Malware Identified | Victim IP   | C2 Server      | IOCs Found |
|---------------|--------------------|-------------|----------------|------------|
| 2026-01-31    | Lumma Stealer      | 10.1.21.58  | 153.92.1.49    | 10         |
| [next one]    | [...]              | [...]       | [...]          | [...]      |

> This table grows as you analyze more PCAPs. One row per exercise.

---

## Methodology Used

Every PCAP was analyzed following this 8-phase workflow:

```
Phase 1 — Overview          : packet count, duration, protocol mix
Phase 2 — Host mapping      : identify victim, gateway, external IPs
Phase 3 — DNS analysis      : suspicious domains, DGA patterns
Phase 4 — HTTP analysis     : POST requests, User-Agents, URIs
Phase 5 — Beaconing detect  : intervals, repeated connections
Phase 6 — Internal traffic  : SMB, LDAP, lateral movement
Phase 7 — IOC validation    : VirusTotal, AbuseIPDB, WHOIS
Phase 8 — Report writing    : timeline, MITRE mapping, recommendations
```

---

## Key Skills Demonstrated

- Network protocol analysis (TCP/IP, DNS, HTTP, SMB)
- Malware traffic identification (C2 beaconing, data exfiltration)
- IOC extraction and documentation
- MITRE ATT&CK framework mapping
- Threat reporting (executive summary + technical details)

---

## Resources Used

- [Malware Traffic Analysis](https://malware-traffic-analysis.net) — PCAP exercises
- [MITRE ATT&CK](https://attack.mitre.org) — Technique mapping
- [VirusTotal](https://virustotal.com) — IOC validation
- [AbuseIPDB](https://abuseipdb.com) — IP reputation
- [Wireshark Docs](https://www.wireshark.org/docs/) — Filter reference
