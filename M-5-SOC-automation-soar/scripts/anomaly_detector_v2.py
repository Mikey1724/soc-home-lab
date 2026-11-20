#!/usr/bin/env python3
# anomaly_detector.py — Statistical anomaly detection on logs
# SOC Home Lab — Month 5

import ipaddress
import json
import statistics
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

def detect_dns_anomaly_v2(eve_file, multiplier=3.0, history_window=6):
    """
    Detect DNS spikes using a rolling historical baseline.
    - history_window: Number of previous hours to use as baseline (min 6 for valid stdev).
    """
    print(f"\n[*] DNS Anomaly Detection (Spike > {multiplier}x baseline, using prior {history_window} hours)")
    
    # Structure: ip_dns_by_hour[src_ip] = [(datetime, count), (datetime, count), ...]
    ip_dns_data = defaultdict(list)
    
    # 1. Parse the logs
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
                
                # Convert string to datetime for chronological sorting
                dt = datetime.fromisoformat(ts_str[:19])
                hour_dt = dt.replace(minute=0, second=0, microsecond=0)
                ip_dns_data[src].append(hour_dt)
            except (json.JSONDecodeError, ValueError):
                continue

    findings = []
    
    # 2. Process each IP's timeline
    for ip, timestamps in ip_dns_data.items():
        # Count queries per hour
        hourly_counts = Counter(timestamps)
        
        # Sort the hours chronologically
        sorted_hours = sorted(hourly_counts.keys())
        
        # We need enough history to calculate a valid standard deviation
        if len(sorted_hours) <= history_window:
            continue # Not enough data for this IP
            
        # 3. Rolling Baseline Evaluation
        for i in range(history_window, len(sorted_hours)):
            current_hour = sorted_hours[i]
            current_count = hourly_counts[current_hour]
            
            # Get the previous N hours to calculate the baseline
            history_counts = [hourly_counts[sorted_hours[j]] for j in range(i - history_window, i)]
            
            # Calculate stats on HISTORY ONLY (prevents self-inclusion bias)
            mean = statistics.mean(history_counts)
            stdev = statistics.stdev(history_counts)
            
            # We need a minimum baseline to avoid triggering on 0 -> 1 queries
            if mean < 5:
                continue
                
            # The Math: Must exceed multiplier AND be statistically significant
            if current_count > (mean * multiplier) and current_count > (mean + 2 * stdev):
                findings.append({
                    "type": "DNS_SPIKE",
                    "src_ip": ip,
                    "hour": current_hour.strftime("%Y-%m-%d %H:00"),
                    "count": current_count,
                    "baseline_mean": round(mean, 1),
                    "multiplier": round(current_count / mean, 1)
                })

                #print(f"    [!] Investigating spike for {ip} at {current_hour}...")
                # (Requires parsing the specific hour's logs to extract .dns.rrname)

    # Print results
    if findings:
        for f in findings:
            print(f"  🔴 DNS SPIKE DETECTED")
            print(f"     Source IP     : {f['src_ip']}")
            print(f"     Hour          : {f['hour']}")
            print(f"     Queries       : {f['count']} ({f['multiplier']}x historical baseline of {f['baseline_mean']}/hr)")
    else:
        print(f"  ✅ No DNS anomaly detected")
    return findings


def is_noise_source(src):
    """
    True for sources that are never worth reporting as a host:
    unparsable, unspecified (:: / 0.0.0.0), link-local (fe80::/10, 169.254/16), multicast.
    NOTE: Suricata logs IPv6 in EXPANDED form (fe80:0000:...), so string tests such as
    src.startswith("fe80::") or "::" in src never match. Parse the address instead.
    """
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return True
    return ip.is_unspecified or ip.is_link_local or ip.is_multicast


def detect_off_hours_connections_v2(flows, business_start=8, business_end=18):
    """
    Detect connections outside business hours based on network FLOWS, 
    not just signature alerts.
    """
    print(f"\n[*] Off-Hours Detection (outside {business_start}h-{business_end}h)")

    off_hours = defaultdict(list)

    # Define ports that are just background noise (mDNS, SSDP, DHCP, NetBIOS)
    NOISE_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
    
    for flow in flows:
        ts_str = flow.get("timestamp", "")
        src = flow.get("src_ip", "")
        dst_port = flow.get("dest_port", 0)
        proto = flow.get("proto", "")

        # FILTER 1: Ignore empty, unspecified, link-local and multicast sources
        if not ts_str or not src or is_noise_source(src):
            continue
            
        # FILTER 2: Ignore background noise ports
        if dst_port in NOISE_PORTS:
            continue
            
        try:
            # Extract the hour (e.g., "2026-10-26T21:00:00" -> 21)
            hour = int(ts_str[11:13])
            if hour < business_start or hour >= business_end:
                off_hours[(src, ts_str[:10])].append({ 
                    "hour": hour,
                    "dst_port": dst_port,
                    "proto": proto,
                    "timestamp": ts_str[:19]
                })
        except (json.JSONDecodeError, ValueError):
            continue

    findings = []
    for (ip, day), events in off_hours.items():
        # We only care about internal IPs making weird connections
        if len(events) >= 5: # Threshold to avoid noise
            # Calculate unique destination ports to give context
            unique_ports = set(e['dst_port'] for e in events)
            
            findings.append({
                "type": "OFF_HOURS_ACTIVITY",
                "src_ip": ip,
                "window": day,  
                "event_count": len(events),
                "unique_ports_contacted": len(unique_ports),
                "sample": events[:3]
            })

    if findings:
        for f in findings:
            print(f"  🟡 OFF-HOURS ACTIVITY")
            print(f"     Source IP    : {f['src_ip']}")
            print(f"     Event count  : {f['event_count']} flows")
            print(f"     Unique Ports : {f['unique_ports_contacted']}")
            for s in f["sample"]:
                print(f"     [{s['timestamp']}] h{s['hour']:02d}h — Port {s['dst_port']}/{s['proto']}")
    else:
        print(f"  ✅ No suspicious off-hours activity")
    return findings

def load_suricata_flows(filepath):
    """Load Suricata eve.json FLOW events (not just alerts)."""
    flows = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("event_type") == "flow":  # <--- CHANGED THIS
                    flows.append(e)
            except (json.JSONDecodeError, ValueError):
                continue
    return flows

def detect_port_scan_slow_v2(flows, threshold_ports=15, window_minutes=15):
    print(f"\n[*] Slow Port Scan Detection (>{threshold_ports} unique ports in {window_minutes}min)")

    # src -> window -> dest -> {ports}
    ip_ports = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    # src -> window -> dest -> {timestamps}
    ip_ts = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    for flow in flows:
        src = flow.get("src_ip", "")
        dest = flow.get("dest_ip", "")
        dst_port = flow.get("dest_port", 0)
        ts_str = flow.get("flow", {}).get("start")
        # ts_str = flow.get("flow", {}).get("start") or flow.get("timestamp", "")

        if not src or not dst_port or not ts_str or not dest:
            continue

        try:
            ts = datetime.fromisoformat(ts_str[:19])
            minute_block = (ts.minute // window_minutes) * window_minutes
            window_key = ts.strftime(f"%Y-%m-%d %H:{minute_block:02d}")

            ip_ports[src][window_key][dest].add(dst_port)
            ip_ts[src][window_key][dest].add(ts)
        except (ValueError, TypeError):
            continue

    findings = []
    for src, windows in ip_ports.items():
        for window, dests in windows.items():
            for dest, ports in dests.items():
                if len(ports) >= threshold_ports:
                    # Compute actual span in minutes
                    ts_list = sorted(ip_ts[src][window][dest])
                    span_min = (ts_list[-1] - ts_list[0]).total_seconds() / 60.0
                    rate = len(ports) / span_min if span_min > 0 else float(len(ports))

                    findings.append({
                        "type": "SLOW_PORT_SCAN",
                        "src_ip": src,
                        "dest_ip": dest,
                        "window": window,
                        "unique_ports": len(ports),
                        "span_minutes": round(span_min, 1),
                        "rate_per_min": round(rate, 2),
                        "ports_sample": sorted(ports)[:10],
                    })

    if findings:
        for f in findings:
            print(f"  🔴 ANOMALY DETECTED")
            print(f"     Source IP      : {f['src_ip']}")
            print(f"     Destination IP : {f['dest_ip']}")
            print(f"     Time window    : {f['window']}")
            print(f"     Unique ports   : {f['unique_ports']}")
            print(f"     Active span    : {f['span_minutes']} min")
            print(f"     Rate           : {f['rate_per_min']} ports/min")
            print(f"     Ports (sample) : {f['ports_sample']}")
    else:
        print(f"  ✅ No slow port scan detected")

    return findings   

if __name__ == "__main__":
    EVE_FILE = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"

    print("="*55)
    print("ANOMALY DETECTION REPORT")
    print(f"Source: {EVE_FILE}")
    print("="*55)

    if not Path(EVE_FILE).exists():
        print(f"[!] File not found: {EVE_FILE}")
        print("[*] Run: sudo chmod o+r /var/log/suricata/eve.json")
        sys.exit(1)

    # ... setup ...
    flows = load_suricata_flows(EVE_FILE)
    print(f"[+] Loaded {len(flows)} flows from eve.json")

    all_findings = []
    all_findings += detect_port_scan_slow_v2(flows) # Pass flows, not alerts!
    all_findings += detect_dns_anomaly_v2(EVE_FILE)
    all_findings += detect_off_hours_connections_v2(flows)

    print(f"\n{'='*55}")
    print(f"SUMMARY: {len(all_findings)} anomalies detected")

    # Save to JSON
    import json as _json
    report = {
        "generated": datetime.now().isoformat(),
        "total_flows_analyzed": len(flows),
        "anomalies_found": len(all_findings),
        "findings": all_findings
    }
    report_file = f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        _json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved: {report_file}")