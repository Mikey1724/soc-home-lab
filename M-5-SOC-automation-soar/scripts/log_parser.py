#!/usr/bin/env python3
# log_parser.py — Universal Wazuh/Suricata log parser
# SOC Home Lab — Month 5

import json
from collections import Counter
from pathlib import Path

def parse_wazuh_alerts(filepath):
    """Parse Wazuh alerts.json — one JSON object per line."""
    alerts = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append({
                    "timestamp": alert.get("timestamp", ""),
                    "rule_id":   alert.get("rule", {}).get("id", ""),
                    "level":     alert.get("rule", {}).get("level", 0),
                    "desc":      alert.get("rule", {}).get("description", ""),
                    "src_ip":    alert.get("data", {}).get("src_ip", ""),
                    "agent":     alert.get("agent", {}).get("name", ""),
                })
            except json.JSONDecodeError:
                continue
    return alerts

def parse_suricata_eve(filepath):
    """Parse Suricata eve.json — alerts only."""
    alerts = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") != "alert":
                    continue
                alerts.append({
                    "timestamp": event.get("timestamp", ""),
                    "src_ip":    event.get("src_ip", ""),
                    "dst_ip":    event.get("dest_ip", ""),
                    "dst_port":  event.get("dest_port", 0),
                    "signature": event.get("alert", {}).get("signature", ""),
                    "severity":  event.get("alert", {}).get("severity", 0),
                    "proto":     event.get("proto", ""),
                })
            except json.JSONDecodeError:
                continue
    return alerts

def generate_summary(alerts, source="wazuh"):
    """Generate a quick summary of parsed alerts."""
    print(f"\n{'='*55}")
    print(f"LOG PARSER SUMMARY — {source.upper()}")
    print(f"Total alerts parsed : {len(alerts)}")
    print(f"{'='*55}")

    if source == "wazuh":
        # Top alert levels
        levels = Counter(a["level"] for a in alerts)
        print("\nTop alert levels:")
        for level, count in sorted(levels.items(), reverse=True)[:5]:
            bar = "█" * min(count, 40)
            print(f"  Level {level:2d} : {count:4d}  {bar}")

        # Top source IPs
        ips = Counter(a["src_ip"] for a in alerts if a["src_ip"])
        print("\nTop source IPs:")
        for ip, count in ips.most_common(5):
            print(f"  {ip:<20} {count} alerts")

        # Top rules
        rules = Counter(a["desc"] for a in alerts if a["desc"])
        print("\nTop triggered rules:")
        for desc, count in rules.most_common(5):
            print(f"  [{count:4d}] {desc[:55]}")

    elif source == "suricata":
        sigs = Counter(a["signature"] for a in alerts)
        print("\nTop signatures:")
        for sig, count in sigs.most_common(5):
            print(f"  [{count:4d}] {sig[:55]}")

        ports = Counter(a["dst_port"] for a in alerts)
        print("\nTop destination ports:")
        for port, count in ports.most_common(5):
            print(f"  Port {port:<6} : {count} alerts")

if __name__ == "__main__":
    # Test with your actual log files
    WAZUH_LOG    = "/var/ossec/logs/alerts/alerts.json"
    SURICATA_LOG = "/var/log/suricata/eve.json"

    if Path(WAZUH_LOG).exists():
        alerts = parse_wazuh_alerts(WAZUH_LOG)
        generate_summary(alerts, "wazuh")

    if Path(SURICATA_LOG).exists():
        alerts = parse_suricata_eve(SURICATA_LOG)
        generate_summary(alerts, "suricata")