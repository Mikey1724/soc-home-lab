#!/usr/bin/env python3
# yara_scanner.py : Automated YARA scanner
# SOC Home Lab : Month 4

import yara
import os
import json
from datetime import datetime

RULES_FILE = "/home/test/yara-lab/local_rules.yar"
SCAN_DIR   = "/tmp/"

def scan_file(rules, filepath):
    """Scan a single file with YARA rules."""
    try:
        matches = rules.match(filepath)
        if matches:
            return {
                "file": filepath,
                "matches": [
                    {
                        "rule": m.rule,
                        "tags": m.tags,
                        "meta": m.meta,
                        "strings": [
                            {"offset": s.instances[0].offset,
                             "identifier": s.identifier,
                             "data": str(s.instances[0].matched_data)}
                            for s in m.strings
                        ]
                    }
                    for m in matches
                ]
            }
    except yara.Error as e:
        return {"file": filepath, "error": str(e)}
    return None

def scan_directory(rules, directory):
    """Scan all files in a directory."""
    results = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            result = scan_file(rules, filepath)
            if result:
                results.append(result)
    return results

if __name__ == "__main__":
    print(f"[*] Loading YARA rules from {RULES_FILE}")
    rules = yara.compile(RULES_FILE)

    print(f"[*] Scanning directory: {SCAN_DIR}")
    results = scan_directory(rules, SCAN_DIR)

    print(f"\n{'='*60}")
    print(f"YARA SCAN REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    if not results:
        print("[✓] No matches found — directory is clean")
    else:
        print(f"[!] {len(results)} file(s) matched YARA rules:\n")
        for r in results:
            print(f"  File : {r['file']}")
            for match in r.get("matches", []):
                print(f"  Rule : {match['rule']}")
                print(f"  Tags : {match['tags']}")
                for s in match["strings"]:
                    print(f"    -> [{s['identifier']}] at offset {s['offset']}: {s['data']}")
            print()

    # Save report
    report_file = f"yara_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Report saved to {report_file}")