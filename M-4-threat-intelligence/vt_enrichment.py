#!/usr/bin/env python3
# vt_enrichment.py : IOC enrichment via VirusTotal API
# SOC Home Lab : Month 4

import requests
import json
import time

VT_API_KEY = "your_API_KEY"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json"
}

def check_ip(ip):
    """Query VirusTotal for an IP address."""
    url = f"{VT_BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        country = data["data"]["attributes"].get("country", "Unknown")
        return {
            "type": "ip",
            "value": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": country
        }
    return {"error": response.status_code}

def check_domain(domain):
    """Query VirusTotal for a domain."""
    url = f"{VT_BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "type": "domain",
            "value": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    return {"error": response.status_code}

def check_hash(file_hash):
    """Query VirusTotal for a file hash."""
    url = f"{VT_BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        name = data["data"]["attributes"].get("meaningful_name", "Unknown")
        return {
            "type": "hash",
            "value": file_hash,
            "name": name,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    return {"error": response.status_code}

def enrich_iocs(ioc_list):
    """Enrich a list of IOCs and generate a report."""
    results = []
    for ioc in ioc_list:
        print(f"[*] Checking {ioc['type']}: {ioc['value']}")
        if ioc["type"] == "ip":
            result = check_ip(ioc["value"])
        elif ioc["type"] == "domain":
            result = check_domain(ioc["value"])
        elif ioc["type"] == "hash":
            result = check_hash(ioc["value"])
        else:
            continue
        results.append(result)
        # Respect VT rate limit (4 req/min on free tier)
        time.sleep(20)
    return results

def print_report(results):
    """Print enrichment report."""
    print("\n" + "="*60)
    print("IOC ENRICHMENT REPORT - VirusTotal")
    print("="*60)
    for r in results:
        if "error" in r:
            print(f"  [ERROR] {r}")
            continue
        verdict = "🔴 MALICIOUS" if r["malicious"] > 3 else \
                  "🟡 SUSPICIOUS" if r["malicious"] > 0 else \
                  "🟢 CLEAN"
        print(f"\n  {verdict}")
        print(f"  Type    : {r['type']}")
        print(f"  Value   : {r['value']}")
        print(f"  Malicious engines : {r['malicious']}")
        print(f"  Suspicious        : {r['suspicious']}")
        if r.get("country"):
            print(f"  Country : {r['country']}")
        if r.get("name"):
            print(f"  File name : {r['name']}")

# --- IOCs from my lab investigations ----------------------------
iocs = [
    # Lumma Stealer - Project 1.2 (2026-01-31)
    {"type": "ip",     "value": "153.92.1.49"},
    {"type": "domain", "value": "whitepepper.su"},
    {"type": "domain", "value": "whooptm.cyou"},
    # NetSupport RAT - Project 1.2 (2026-02-28)
    {"type": "ip",     "value": "45.131.214.85"},
    {"type": "domain", "value": "vadusa.xyz"},
]

if __name__ == "__main__":
    results = enrich_iocs(iocs)
    print_report(results)
    # Save to JSON
    with open("vt_enrichment_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n[+] Results saved to vt_enrichment_results.json")