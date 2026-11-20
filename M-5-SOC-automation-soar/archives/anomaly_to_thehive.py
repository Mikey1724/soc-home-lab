#!/usr/bin/env python3
# anomaly_to_thehive.py — Push anomalies to TheHive automatically
# SOC Home Lab — Month 5

import requests
import json
import time
from datetime import datetime

THEHIVE_URL   = "http://192.168.1.114:9000"
THEHIVE_TOKEN = "your_thehive_api_key"

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_TOKEN}",
    "Content-Type": "application/json"
}

def create_thehive_alert(finding):
    """Create a TheHive alert from an anomaly finding."""

    severity_map = {
        "SLOW_PORT_SCAN":     2,  # Medium
        "DNS_SPIKE":          2,  # Medium
        "OFF_HOURS_ACTIVITY": 1,  # Low
    }

    alert = {
        "type":        "anomaly",
        "source":      "Python Anomaly Detector",
        "sourceRef":   f"anomaly-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "title":       f"[AUTO] {finding['type']} — {finding.get('src_ip', 'Unknown')}",
        "description": f"Automated anomaly detected by Python script.\n\n"
                       f"Type: {finding['type']}\n"
                       f"Source IP: {finding.get('src_ip', 'N/A')}\n"
                       f"Details: {json.dumps(finding, indent=2, default=str)}",
        "severity":    severity_map.get(finding["type"], 1),
        "tags":        ["automated", "python", "anomaly", finding["type"].lower()],
        "tlp":         2,
    }

    response = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers=HEADERS,
        json=alert,
        verify=False
    )

    if response.status_code == 201:
        alert_id = response.json().get("_id", "unknown")
        print(f"  ✅ TheHive alert created: {alert_id}")
        return alert_id
    else:
        print(f"  ❌ Failed: {response.status_code} — {response.text[:100]}")
        return None

if __name__ == "__main__":
    # Load findings from anomaly detector
    with open("anomaly_report.json") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    print(f"[*] Pushing {len(findings)} anomalies to TheHive...")

    for finding in findings:
        create_thehive_alert(finding)
        # To prevent to much request at the same time 
        time.sleep(20)