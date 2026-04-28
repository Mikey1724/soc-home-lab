#!/bin/bash

LOGFILE="/var/log/auth.log"
THRESHOLD=5
REPORT_FILE="~/soc-home-lab/soc-reports/bruteforce-$(date +%Y%m%d).txt"

mkdir -p "~/soc-home-lab/soc-reports"

echo "=== SOC ALERT REPORT ===" > "$REPORT_FILE"
echo "Generated: $(date) " >> "$REPORT_FILE"
echo "Threshold: $THRESHOLD failed attemps" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "[+] Scanning $LOGFILE for brute-force patterns..."

grep "Failed password" "$LOGFILE" | \
  awk '{print $11}' | sort | uniq -c | sort -nr | \
  awk -v t="$THRESHOLD" '
    $1 >= t {
        printf "ALERT | IP: %-16s | Attempts: %d\n", $2, $1
    }
  ' | tee -a "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "[+] Top targeted users:" >> "$REPORT_FILE"
grep "Failed password" "$LOGFILE" | \
  awk '{print $11}' | sort | uniq -c | sort -nr | head -5 >> "$REPORT_FILE"

echo "[+] Report saved to $REPORT_FILE"