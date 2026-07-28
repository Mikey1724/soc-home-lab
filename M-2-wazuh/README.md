# Month 2 - SIEM Deployment, Dashboards & Alert Correlation

**Analyst:** Jean Mik C. TINIGO
**Period:** May 2026
**Status:** ✅ Complete

---

## Overview

Month 2 builds the centralization and visibility layer on top of the IDS
deployed in Month 1. Three projects take the lab from "alerts in a local
text file" to a fully operational SIEM pipeline with custom dashboards,
behavioral detection rules, and multi-source correlation logic.

---

## Projects

| # | Project | Tools | Format | Status |
|---|---------|-------|--------|--------|
| 2.1 | Wazuh SIEM deployment + Suricata integration | Wazuh 4.14 · OpenSearch · Ubuntu Server | `.md` | ✅ |
| 2.2 | Kibana dashboard + SSH brute-force detection | Kibana · Hydra · Wazuh XML rules | `.pdf` | ✅ |
| 2.3 | Multi-source alert correlation | Wazuh · Suricata · auditd · OpenSearch DSL | `.md` | ✅ |

---

## Project 2.1 - Wazuh SIEM + Suricata Integration

> *"An IDS that writes alerts to a local file has zero operational value in a real SOC. Everything must be centralized."*

Installed Wazuh 4.14 from scratch on Ubuntu Server (no pre-built VM),
deployed the Wazuh Agent on the Ubuntu Desktop running Suricata, and
configured the agent to ingest `eve.json` in real time into OpenSearch.

**Key results:**
- Full pipeline validated: Suricata alert -> Wazuh Agent -> OpenSearch -> Threat Hunting
- OpenSearch DSL query used to confirm raw alert ingestion
- Wazuh automatically detected system-level events (PAM, sudo, AppArmor) from native Linux logs without additional configuration

**Production issue solved:** port 1514/tcp blocked by UFW, diagnosed via `tail -f /var/ossec/logs/ossec.log`, fixed with `ufw allow 1514/tcp`

📄 [`wazuh-suricata-integration.md`](./wazuh-suricata-integration.md)

---

## Project 2.2 - Kibana Dashboard + Brute-Force Detection Rule

> *"A SIEM without a dashboard is just a log database."*

Built 4 Kibana visualizations from scratch and assembled them into a SOC monitoring dashboard with a Suricata-only filtered view. Wrote a custom Wazuh XML rule detecting SSH brute-force via behavioral analysis.

**Dashboard visualizations:**

| Visualization | Type | Field | SOC Value |
|---|---|---|---|
| Top 10 Alert Types | Bar chart | `rule.description` | Identify dominant threats |
| Alert Timeline | Line chart | `timestamp` | Detect temporal anomalies |
| Alert Sources Distribution | Donut | `rule.groups` | Log source breakdown |
| Top Attacker IPs | Data table | `data.src_ip` | Identify hostile sources |

**Custom rule validated:**

| Rule ID | Level | Trigger | Result |
|---|---|---|---|
| 100002 | 10 | 5× SID 5760 in 120s | ✅ Detected |

**Key lesson:** SID values differ by environment, always verify in your own dashboard before writing correlation rules.

📄 [`kibana-dashboard-report.pdf`](./kibana-dashboard-report.pdf)

---

## Project 2.3 - Multi-Source Alert Correlation

> *"Individually: 3 low-level alerts. Together: a confirmed attack chain."*

Built a 4-rule Wazuh correlation chain that reconstructs a complete attack sequence across two independent log sources (Suricata IDS + Linux authentication logs).

**Attack chain reconstructed:**

```
21:17:55  Nmap SYN scan        ->  rule 100003  level 5
21:19:04  SSH brute-force      ->  rule 100005  level 12  <- CORRELATION
21:20:09  sudo privilege esc.  ->  rule 100006  level 14  <- CRITICAL
```

**MITRE ATT&CK coverage:**

| Technique | Name | Rule |
|---|---|---|
| T1595.001 | Active Scanning | 100003 |
| T1110.001 | Password Guessing | 100005 |
| T1078 | Valid Accounts | 100006 |

**Technical decision documented:** `<same_source_ip />` replaced by `<same_agent />` due to field normalization mismatch between `data.src_ip` (Suricata JSON) and `data.srcip` (Wazuh normalized field).
Full analysis in the report.

📄 [`multi-source-correlation.md`](./multi-source-correlation.md)

---

## Skills Demonstrated

```
SIEM Deployment      ████████░░  Wazuh install · agent config · indexer
Log Ingestion        ████████░░  eve.json · auth.log · audit.log
Kibana / OpenSearch  ████████░░  Visualizations · dashboards · DSL queries
Custom Rules (XML)   ████████░░  Behavioral · frequency · correlation chains
MITRE ATT&CK         ███████░░░  Technique mapping across full attack chain
Troubleshooting      ████████░░  UFW · port 1514 · field normalization
```

---

## Repository Structure

```
month-2-wazuh/
├── README.md                          <- This file
├── wazuh-suricata-integration.md      <- Project 2.1 report
├── kibana-dashboard-report.pdf        <- Project 2.2 report
├── multi-source-correlation.md        <- Project 2.3 report
└── screenshots/

```

---

## Resources Used

- [Wazuh Documentation](https://documentation.wazuh.com)
- [OpenSearch DSL Reference](https://opensearch.org/docs/latest/query-dsl/)
- [MITRE ATT&CK](https://attack.mitre.org)