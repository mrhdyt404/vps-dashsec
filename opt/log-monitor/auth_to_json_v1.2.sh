#!/bin/bash
LOG="/var/log/auth.log"
OUT="/opt/log-monitor/auth_summary.json"

# Total percobaan gagal
FAILED_TOTAL=$(grep -c "Failed password" "$LOG")

# Top IPs dan Users
TOP_IP=$(grep "Failed password" "$LOG" \
 | awk '{print $(NF-3)}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"ip\":\"%s\",\"count\":%s},", $2, $1}')

TOP_USER=$(grep "Failed password" "$LOG" \
 | awk '{print $(NF-5)}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"user\":\"%s\",\"count\":%s},", $2, $1}')

# Jumlah IP diblokir ufw + fail2ban
UFW_BLOCKED=$(ufw status | grep -c DENY)
F2B_BLOCKED=$(fail2ban-client status sshd 2>/dev/null | grep -Eo '[0-9]+ banned' | awk '{sum+=$1} END {print sum+0}')

BLOCKED_TOTAL=$((UFW_BLOCKED + F2B_BLOCKED))
SUCCESS_TOTAL=$((FAILED_TOTAL - BLOCKED_TOTAL))

# Generate JSON
cat <<EOF > "$OUT"
{
  "date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "failed_total": $FAILED_TOTAL,
  "blocked_total": $BLOCKED_TOTAL,
  "success_total": $SUCCESS_TOTAL,
  "top_ips": [${TOP_IP%,}],
  "top_users": [${TOP_USER%,}]
}
EOF
