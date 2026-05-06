# Month 1 — Project 1.1 : Linux SOC Lab

**Analyst:** Mik TINIGO
**Date:** 2026-05-03
**Difficulty:** Beginner
**Tools:** Ubuntu Server 22.04, bash, grep, awk, auditd, journalctl

---

## Objective

Set up a Linux-based SOC analyst workstation and simulate common security
events to practice log analysis and threat detection using native CLI tools.
No external tools — just the Linux command line, exactly as used in real SOC environments.

---

## Environment

| Component   | Details                          |
|-------------|----------------------------------|
| OS          | Ubuntu Server 22.04 LTS          |
| Hypervisor  | VirtualBox 7.x                   |
| RAM / CPU   | 4 GB / 2 vCPU                    |
| Network     | NAT + Host-Only adapter          |
| Tools used  | bash, grep, awk, sed, journalctl, auditd, find, netstat |

---

## Files in This Folder

| File | Description |
|------|-------------|
| `README.md` | This file |
| `detect_bruteforce.sh` | Bash script — SSH brute-force detection |
| `analysis-report.md` | Full incident simulation report |

---

## Scenarios Simulated

### Scenario 1 — SSH Brute-Force Detection

**Context:** Simulated 15 failed SSH login attempts to generate
auth.log entries, then analyzed the logs to identify the attack pattern
and extract the source IP.

**Key commands:**
```bash
# Generate failed attempts
for i in {1..15}; do ssh wronguser@localhost 2>/dev/null; done

# Detect brute-force pattern
grep "Failed password" /var/log/auth.log \
  | awk '{print $11}' | sort | uniq -c | sort -nr
```

**Finding:** 25 failed attempts detected from 127.0.0.1
targeting user `wronguser`. Alert threshold set at 5 attempts.

---

### Scenario 2 — Suspicious File Modification

**Context:** Used auditd to monitor sensitive system files and
detect unauthorized modifications in real time.

**Key commands:**
```bash
# Watch for changes to sensitive files
sudo auditctl -w /etc/passwd -p wa -k passwd_changes

# Check audit log for events
sudo ausearch -k passwd_changes
```

**Finding:** Auditd correctly logged file access events
with timestamp, user, and process details.

---

### Scenario 3 — Active Connection Monitoring

**Context:** Identified active network connections and
flagged processes listening on unexpected ports.

**Key commands:**
```bash
# List all listening services
ss -tulnp

# Monitor new connections in real time
watch -n 2 'ss -tnp | grep ESTABLISHED'

# Check open files per process
sudo lsof -i -n -P | grep LISTEN
```

---

## Detection Script

**File:** `detect_bruteforce.sh`

Parses `/var/log/auth.log` and raises an alert when a source IP
exceeds the defined failed login threshold. Outputs a timestamped
report to `~/soc-reports/`.

```bash
# Usage
chmod +x detect_bruteforce.sh
./detect_bruteforce.sh
```

---

## Key Takeaways

- Auth logs record every SSH attempt with source IP, username, and timestamp
- `grep + awk + sort + uniq` is the core log parsing pipeline in Linux SOC work
- Auditd tracks file-level changes — essential for detecting tampering
- `ss` and `lsof` reveal active connections and suspicious listening processes
- Bash scripting automates repetitive detection tasks

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Scenario |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Scenario 1 — SSH brute-force |
| T1083 | File and Directory Discovery | Scenario 2 — File monitoring |
| T1049 | System Network Connections Discovery | Scenario 3 — Connection monitoring |

---

## Resources Used

- [Ubuntu auditd documentation](https://linux.die.net/man/8/auditd)
- [TryHackMe — SOC Level 1 path](https://tryhackme.com/path/outline/soclevel1)
- [MITRE ATT&CK](https://attack.mitre.org)