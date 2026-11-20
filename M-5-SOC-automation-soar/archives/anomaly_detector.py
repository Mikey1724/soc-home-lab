#!/usr/bin/env python3
# anomaly_detector.py — Statistical anomaly detection on logs
# SOC Home Lab — Month 5

import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

def load_suricata_alerts(filepath):
    """Load Suricata eve.json alerts."""
    alerts = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("event_type") == "alert":
                    alerts.append(e)
            except:
                continue
    return alerts

def detect_port_scan_slow(alerts, threshold_ports=15, window_minutes=60):
    """
    Detect slow port scans that bypass threshold-based rules.
    An attacker scanning 1 port per minute over 2 hours won't
    trigger a rule looking for 50 SYN in 3 seconds.
    """
    print(f"\n[*] Slow Port Scan Detection (>{threshold_ports} unique ports in {window_minutes}min)")

    # Group connections by source IP and time window
    ip_ports = defaultdict(lambda: defaultdict(set))

    for alert in alerts:
        src = alert.get("src_ip", "")
        dst_port = alert.get("dest_port", 0)
        ts_str = alert.get("timestamp", "")
        if not src or not dst_port or not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str[:19])
            window_key = ts.strftime(f"%Y-%m-%d %H:{(ts.minute // window_minutes) * window_minutes:02d}")
            ip_ports[src][window_key].add(dst_port)
        except:
            continue

    findings = []
    for ip, windows in ip_ports.items():
        for window, ports in windows.items():
            if len(ports) >= threshold_ports:
                findings.append({
                    "type": "SLOW_PORT_SCAN",
                    "src_ip": ip,
                    "window": window,
                    "unique_ports": len(ports),
                    "ports_sample": sorted(list(ports))[:10]
                })

    if findings:
        for f in findings:
            print(f"  🔴 ANOMALY DETECTED")
            print(f"     Source IP     : {f['src_ip']}")
            print(f"     Time window   : {f['window']}")
            print(f"     Unique ports  : {f['unique_ports']}")
            print(f"     Ports (sample): {f['ports_sample']}")
    else:
        print(f"  ✅ No slow port scan detected")
    return findings

def detect_dns_anomaly(eve_file, multiplier=3.0):
    """
    Detect DNS spikes — compare each IP's DNS query rate
    to its own baseline. More precise than a fixed threshold.
    """
    print(f"\n[*] DNS Anomaly Detection (spike > {multiplier}x personal baseline)")

    ip_dns_by_hour = defaultdict(lambda: defaultdict(int))

    with open(eve_file, 'r', errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("event_type") != "dns":
                    continue
                src = e.get("src_ip", "")
                ts_str = e.get("timestamp", "")
                if not src or not ts_str:
                    continue
                hour = ts_str[:13]  # "2026-05-16T21"
                ip_dns_by_hour[src][hour] += 1
            except:
                continue

    findings = []
    for ip, hourly in ip_dns_by_hour.items():
        counts = list(hourly.values())
        if len(counts) < 3:  # Need baseline of at least 3 hours
            continue
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 0
        for hour, count in hourly.items():
            if count > mean * multiplier and count > mean + 2 * stdev:
                findings.append({
                    "type": "DNS_SPIKE",
                    "src_ip": ip,
                    "hour": hour,
                    "count": count,
                    "baseline_mean": round(mean, 1),
                    "multiplier": round(count / mean, 1)
                })

    if findings:
        for f in findings:
            print(f"  🔴 DNS SPIKE DETECTED")
            print(f"     Source IP     : {f['src_ip']}")
            print(f"     Hour          : {f['hour']}")
            print(f"     Queries       : {f['count']} ({f['multiplier']}x baseline of {f['baseline_mean']}/hr)")
    else:
        print(f"  ✅ No DNS anomaly detected")
    return findings

def detect_off_hours_connections(alerts, business_start=8, business_end=18):
    """
    Detect connections outside business hours.
    A connection at 3am from an internal IP is inherently suspicious.
    """
    print(f"\n[*] Off-Hours Detection (outside {business_start}h-{business_end}h)")

    off_hours = defaultdict(list)
    for alert in alerts:
        ts_str = alert.get("timestamp", "")
        src = alert.get("src_ip", "")
        sig = alert.get("alert", {}).get("signature", "")
        if not ts_str or not src:
            continue
        try:
            hour = int(ts_str[11:13])
            if hour < business_start or hour >= business_end:
                off_hours[src].append({
                    "hour": hour,
                    "signature": sig,
                    "timestamp": ts_str[:19]
                })
        except:
            continue

    findings = []
    for ip, events in off_hours.items():
        if len(events) >= 5:  # Minimum threshold to avoid noise
            findings.append({
                "type": "OFF_HOURS_ACTIVITY",
                "src_ip": ip,
                "event_count": len(events),
                "sample": events[:3]
            })

    if findings:
        for f in findings:
            print(f"  🟡 OFF-HOURS ACTIVITY")
            print(f"     Source IP    : {f['src_ip']}")
            print(f"     Event count  : {f['event_count']}")
            for s in f["sample"]:
                print(f"     [{s['timestamp']}] h{s['hour']:02d}h — {s['signature'][:45]}")
    else:
        print(f"  ✅ No suspicious off-hours activity")
    return findings

if __name__ == "__main__":
    EVE_FILE = "/var/log/suricata/eve.json"

    print("="*55)
    print("ANOMALY DETECTION REPORT")
    print(f"Source: {EVE_FILE}")
    print("="*55)

    if not Path(EVE_FILE).exists():
        print(f"[!] File not found: {EVE_FILE}")
        print("[*] Run: sudo chmod o+r /var/log/suricata/eve.json")
        sys.exit(1)

    alerts = load_suricata_alerts(EVE_FILE)
    print(f"[+] Loaded {len(alerts)} alerts from eve.json")

    all_findings = []
    all_findings += detect_port_scan_slow(alerts)
    all_findings += detect_dns_anomaly(EVE_FILE)
    all_findings += detect_off_hours_connections(alerts)

    print(f"\n{'='*55}")
    print(f"SUMMARY: {len(all_findings)} anomalies detected")

    # Save to JSON
    import json as _json
    report = {
        "generated": datetime.now().isoformat(),
        "total_alerts_analyzed": len(alerts),
        "anomalies_found": len(all_findings),
        "findings": all_findings
    }
    report_file = f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        _json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved: {report_file}")