#!/usr/bin/env python3
# anomaly_to_thehive.py — Push anomalies to TheHive automatically
# SOC Home Lab — Month 5

import requests
import json
import sys
import os


# Load configuration from environment variables
THEHIVE_URL   = os.getenv("THEHIVE_URL", "http://192.168.1.114:9000")
THEHIVE_TOKEN = os.getenv("THEHIVE_API_KEY")

if not THEHIVE_TOKEN:
    print("[-] ERROR: THEHIVE_API_KEY environment variable is not set.")
    print("[*] Run: export THEHIVE_API_KEY='your_api_key_here'")
    sys.exit(1)

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

     # Get the unique timeframe for this finding (window for Port Scan, hour for DNS, etc)
    time_context = finding.get("window", finding.get("hour", "unknown"))

    observables = [{
        "dataType": "ip",
        "data": finding.get("src_ip", "0.0.0.0"),
        "message": f"Source IP for {finding['type']}",
        "tlp": 2,
        "tags": ["automated", "anomaly", finding["type"].lower()]
    }]

    alert = {
        "type":        "anomaly",
        "source":      "Python Anomaly Detector",
        # FIX: Added time_context to make sourceRef unique
        "sourceRef":   f"anomaly-{finding['type']}-{finding.get('src_ip')}-{time_context}", 
        "title":       f"[AUTO] {finding['type']} — {finding.get('src_ip', 'Unknown')}",
        "description": f"Automated anomaly detected by Python.\n\n"
                       f"**Timeframe:** {time_context}\n"
                       f"**Details:**\n```json\n{json.dumps(finding, indent=2, default=str)}\n```",
        "severity":    severity_map.get(finding["type"], 1),
        "tags":        ["automated", "python", "anomaly", finding["type"].lower()],
        "tlp":         2,
        "observables":   observables 
    }

    response = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers=HEADERS,
        json=alert,
        verify=False,
        timeout=10
    )

    if response.status_code == 201:
        alert_id = response.json().get("_id", "unknown")
        print(f"  ✅ TheHive alert created: {alert_id} (with Observables)")
        return alert_id
    else:
        print(f"  ❌ Failed: {response.status_code} — {response.text[:100]}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <report.json>")
        sys.exit(1)

    report_file = sys.argv[1]

    with open(report_file) as f:
        report = json.load(f)

    findings = report.get("findings", [])
    print(f"[*] Pushing {len(findings)} anomalies to TheHive...")

    for finding in findings:
        create_thehive_alert(finding)
