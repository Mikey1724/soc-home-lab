# Month 1 — Project 1.3 : Suricata IDS Intrusion Detection Lab

**Analyst:** Jean-Mik C. TINIGO
**Date:** March 2026
**Difficulty:** Intermediate
**Tools:** Suricata 8.0.2, Kali Linux 2025.3, Ubuntu 24.04, Apache2, Hydra, Nmap

---

## Objective

Deploy and configure Suricata as a Network IDS in a controlled lab environment.
Write custom detection rules, simulate real attacks from a Kali Linux machine,
and validate each rule by analyzing Suricata alert logs.

---

## Lab Architecture

| Component  | Role              | OS                  | IP             |
|------------|-------------------|---------------------|----------------|
| Ubuntu VM  | Target + IDS      | Ubuntu 24.04 Desktop| 10.218.45.127  |
| Kali VM    | Attacker          | Kali Linux 2025.3   | 10.218.45.94   |
| Hypervisor | Host              | Oracle VirtualBox 7.2.4 | —          |

Both machines communicate over a VirtualBox **Bridged** internal network.
Ubuntu hosts Suricata (IDS), Apache2 (web server for SQLi tests), and OpenSSH.

---

## Attack Scenarios & Custom Rules

All rules are stored in `/var/lib/suricata/rules/local.rules`.

| SID      | Attack Type              | Detection Method  | Result  |
|----------|--------------------------|-------------------|---------|
| 1000001  | ICMP Ping                | Protocol match    | ✅ Detected |
| 1000002  | Nmap SYN Scan (fast)     | Threshold (50 SYN / 3s) | ✅ Detected |
| 1000003  | Nmap Slow Scan           | Threshold (20 SYN / 30s) | ✅ Detected |
| 1000004  | SSH Brute-Force (Hydra)  | Threshold (5 SYN / 5s) | ✅ Detected |
| 1000005  | SQLi — Single Quote      | HTTP URI content  | ✅ Detected |
| 1000006  | SQLi — Single Quote (TCP)| TCP payload       | ✅ Detected |
| 1000007  | SQLi — UNION SELECT      | HTTP URI + distance | ✅ Detected |
| 1000008  | SQLi — OR 1=1            | HTTP URI + PCRE   | ✅ Detected |
| 1000009  | SQLi — SQL Comment (--)  | HTTP URI content  | ✅ Detected |
| 1000010  | SQLi — Numeric AND       | HTTP URI content  | ✅ Detected |

**10/10 rules successfully triggered. 0 false negatives on tested scenarios.**

---

## Key Technical Decisions

**Threshold-based detection for SSH & Nmap**
SSH traffic is encrypted — signature-based detection (payload inspection)
is not possible. Behavioral detection via connection rate thresholds
is the industry-standard approach for encrypted protocols.

**Two scan detection rules instead of one**
A single threshold tuned for fast scans (50 SYN/3s) would miss slow scans
(`nmap --T1`). Two complementary rules cover both aggressive and stealthy
reconnaissance patterns.

**PCRE for OR 1=1 variants**
Simple string matching would miss variations like `OR '1'='1'` or `OR 1 =1`.
A PCRE expression handles whitespace and quote variations in a single rule,
reducing both false negatives and rule count.

---

## Logs Analyzed

```bash
# Real-time alert monitoring (human-readable)
sudo tail -f /var/log/suricata/fast.log

# Full JSON log (SIEM-ready — used for Wazuh integration in Month 2)
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

---

## Challenges & Lessons Learned

- Initial threshold of 5 SYN / 10s failed to trigger on Nmap scans —
  adjusted to 50 SYN / 3s after analyzing raw packets with `tcpdump`
- SQLi rules required Apache2 to be running on port 80 —
  Suricata cannot decode HTTP without an active service on the monitored port
- URL encoding (`%27` instead of `'`) is required when testing with `curl`
  to properly transmit special characters through HTTP

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Rule |
|---|---|---|
| T1595.001 | Active Scanning: Scanning IP Blocks | SID 1000002, 1000003 |
| T1110.001 | Brute Force: Password Guessing | SID 1000004 |
| T1190 | Exploit Public-Facing Application (SQLi) | SID 1000005–1000010 |

---

## Files in This Folder

| File | Description |
|------|-------------|
| `README.md` | This file |
| `Rapport_Suricata.pdf` | Full technical report with screenshots |
| `local.rules` | All 10 custom Suricata detection rules |

---

## Next Step — Month 2

The `eve.json` output from Suricata will be ingested by **Wazuh SIEM**
in the next project. Alerts generated here will be centralized, correlated,
and visualized in a Kibana dashboard — closing the loop between
network detection and security monitoring.

---

## UPDATES
The `sid` of icmp rules detect is been changed from `1` to `1000001` in this `local.rules` file contrary to the pdf. It's to respect custom rules conventions.

## Resources Used

- [Suricata Documentation](https://docs.suricata.io)
- [Emerging Threats Rules](https://rules.emergingthreats.net)
- [MITRE ATT&CK](https://attack.mitre.org)