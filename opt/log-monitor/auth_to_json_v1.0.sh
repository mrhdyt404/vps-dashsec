#!/bin/bash

LOG="/var/log/auth.log"
OUT="/opt/log-monitor/auth_summary.json"

FAILED_TOTAL=$(grep -c "Failed password" "$LOG")

TOP_IP=$(grep "Failed password" "$LOG" \
 | awk '{print $(NF-3)}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"ip\":\"%s\",\"count\":%s},", $2, $1}')

TOP_USER=$(grep "Failed password" "$LOG" \
 | awk '{print $(NF-5)}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"user\":\"%s\",\"count\":%s},", $2, $1}')

cat <<EOF > "$OUT"
{
  "date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "failed_total": $FAILED_TOTAL,
  "top_ips": [${TOP_IP%,}],
  "top_users": [${TOP_USER%,}]
}
EOF
