# Network Traffic Analysis Report
## Malware Traffic Analysis — 2026-02-28 Exercise

**Analyst:** Mik TINIGO  
**Date:** 2026-04-28  
**PCAP Source:** malware-traffic-analysis.net (2026-02-28)  
**Tools Used:** Wireshark, tshark  
**Classification:** TLP:WHITE (exercise)


---

## 1. Environment Identification

| Field              | Value                         |
|--------------------|-------------------------------|
| Victim IP          | 10.2.28.88                    |
| Gateway / DNS      | 10.2.28.2                     |
| Active Directory   | easyas123.tech (EASYAS123-DC) |
| Capture Start      | 2026-02-28 19:55:06 UTC       |
| Capture End        | 2026-03-01 00:16:35 UTC       |
| Duration           | 4 hours 21 minutes            |
| Total Packets      | 15,512                        |

---

## 2. Suspicious Activity Identified

### 2.1 NetSupport RAT — C2 Beaconing

**What it is:** NetSupport Manager is a legitimate IT remote support tool.
Threat actors repurpose it as a RAT (Remote Access Trojan) because it
blends into corporate environments and bypasses many AV signatures.

**How it appears in this capture:**
The infected host (10.2.28.88) repeatedly sends HTTP POST requests to
an external IP, using the NetSupport Manager User-Agent string.
The destination URL (`/fakeurl.htm`) is a known NetSupport RAT C2 pattern.

|| POST http://45.131.214.85/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded ||

**Red flags:**
- HTTP traffic tunneled over port 443 (normally HTTPS) — bypass attempt
- 273 NetSupport-related packets over 4+ hours — persistent beaconing
- `/fakeurl.htm` — not a legitimate NetSupport endpoint
- Server responds: `NetSupport Gateway/1.92 (Windows NT)`

### 2.2 SMB Traffic (Possible Lateral Movement)

1,528 packets on port 445 (SMB) between internal hosts.
Combined with 1,138 LDAP packets, this may indicate Active Directory
enumeration or lateral movement attempts post-compromise.

### 2.3 Suspicious Domain Resolution

The victim queried `vadusa.xyz` — a .xyz TLD domain with no apparent
legitimate business purpose. Requires further investigation (WHOIS + VirusTotal).

---

## 3. Indicators of Compromise (IOCs)

| IOC Type      | Value                              | Confidence |
|---------------|------------------------------------|------------|
| IP (C2)       | 45.131.214.85                      | HIGH       |
| URL           | http://45.131.214.85/fakeurl.htm   | HIGH       |
| User-Agent    | NetSupport Manager/1.3             | HIGH       |
| Domain        | vadusa.xyz                         | MEDIUM     |
| Victim IP     | 10.2.28.88                         | HIGH       |

---

## 4. MITRE ATT&CK Mapping

| Technique ID  | Technique Name                        | Evidence                        |
|---------------|---------------------------------------|---------------------------------|
| T1219         | Remote Access Software                | NetSupport RAT on 45.131.214.85 |
| T1071.001     | Application Layer Protocol: HTTP      | C2 over HTTP POST /fakeurl.htm  |
| T1571         | Non-Standard Port                     | HTTP traffic on port 443        |
| T1018         | Remote System Discovery (suspected)   | SMB + LDAP enumeration          |

---

## 5. Timeline

| Time (UTC)       | Event                                          |
|------------------|------------------------------------------------|
| 19:55:06         | Capture begins                                 |
| 19:55:51         | First NetSupport C2 contact → 45.131.214.85    |
| 19:55:51–00:16   | Persistent beaconing every ~60 seconds         |
| Throughout       | SMB/LDAP activity on internal network          |

---

## 6. Recommendations

1. **Isolate** host 10.2.28.88 immediately from the network
2. **Block** IP `45.131.214.85` at the perimeter firewall
3. **Block** domain `vadusa.xyz` at the DNS resolver
4. **Add** Suricata/Snort rule detecting `NetSupport Manager` User-Agent
5. **Investigate** SMB activity — check for lateral movement to other hosts
6. **Audit** how NetSupport was installed (phishing? drive-by download?)
7. **Hunt** for the same User-Agent across all endpoints in the SIEM

---

## 7. Wireshark Filters Used

**NetSupport RAT traffic**
http.user_agent contains "NetSupport"
**C2 IP filter**
ip.addr == 45.131.214.85
**SMB traffic**
tcp.port == 445
**vadusa.xyz DNS query**
dns.qry.name contains "vadusa"

---

## References

- [Malware Traffic Analysis Exercise](https://malware-traffic-analysis.net/2026/02/28/index.html)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [NetSupport RAT analysis — Any.run](https://any.run/malware-trends/netsupportrat)
