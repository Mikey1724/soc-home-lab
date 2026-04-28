# SOC Home Lab — Month 1: Linux Fundamentals for SOC Analysts

**Author:** TINIGO Mik 
**Date:** 28-04-2026  
**Environment:** Ubuntu Server 22.04 (VirtualBox)  
**Difficulty:** Beginner  

---

## Objective

Set up a Linux-based SOC analyst workstation and simulate basic security
events to practice log analysis and threat detection using native CLI tools.

---

## Environment

| Component     | Details                             |
|---------------|-------------------------------------|
| OS            | Ubuntu Server 22.04 LTS             |
| Hypervisor    | VirtualBox 7.x                      |
| RAM / CPU     | 4 GB / 2 vCPU                       |
| Tools used    | bash, grep, awk, journalctl, auditd |

---

## Scenarios Simulated

### Scenario 1 — SSH Brute-Force Detection
**Description:** Simulated 15 failed SSH login attempts from localhost
to generate auth.log entries, then analyzed the logs to identify
the attack pattern.

**Commands used:**
```bash
for i in {1..15}; do ssh wronguser@localhost 2>/dev/null; done
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c
```

**Finding:** 25 failed attempts from 127.0.0.1 targeting user "wronguser".
Threshold alert triggered at 5+ attempts.

**Screenshot:**
![image alt](https://github.com/Mikey1724/soc-home-lab/blob/2f5cb90cfdc0969cf4872a7ef5c2d461537c128a/images/M1_1_1_filtrage_des_logs_pour_analyse.png)

---

### Scenario 2 — Suspicious File Modification Detection
...

---

## Detection Script

**File:** `detect_bruteforce.sh`  
**Description:** Bash script that parses auth.log and raises alerts
when a source IP exceeds the defined threshold.

[Link to script in repo]

---

## Key Takeaways

- Auth logs record every SSH attempt with source IP, username, and timestamp
- `grep + awk + sort + uniq` is the core SOC parsing pipeline in Linux
- Auditd tracks file-level changes, useful for detecting tampering

---

**Test Screenshot:** [attach screenshot here]

---

## Resources Used

- [Ubuntu auditd documentation](https://linux.die.net/man/8/auditd)
- [TryHackMe SOC Level 1 path](https://tryhackme.com/path/outline/soclevel1)
