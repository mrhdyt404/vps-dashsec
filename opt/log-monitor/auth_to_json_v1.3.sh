#!/bin/bash

LOG="/var/log/auth.log"
OUT="/opt/log-monitor/auth_summary.json"

# Total gagal, berhasil, dan IP diblokir
FAILED_TOTAL=$(grep -c "Failed password" "$LOG")
SUCCESS_TOTAL=$(grep -c "Accepted password" "$LOG")
BLOCKED_TOTAL=$(sudo ufw status numbered | grep -c "DENY")

# Top 10 IP
TOP_IP=$(grep "Failed password" "$LOG" \
 | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"ip\":\"%s\",\"count\":%s},", $2, $1}')

# Top 10 User
TOP_USER=$(grep "Failed password" "$LOG" \
 | awk '{for(i=1;i<=NF;i++){if($i=="for"){print $(i+1)}}}' \
 | sort | uniq -c | sort -nr | head -n 10 \
 | awk '{printf "{\"user\":\"%s\",\"count\":%s},", $2, $1}')

# Hitung percobaan per jam (00–23)
HOURLY_FAILED="["
for h in {0..23}; do
  count=$(grep "Failed password" "$LOG" | awk -v hr=$h '{split($3,t,":"); if(t[1]==hr) print}' | wc -l)
  HOURLY_FAILED+="$count,"
done
HOURLY_FAILED=${HOURLY_FAILED%,}
HOURLY_FAILED+="]"

# Misal blocked per jam sama dengan 0 (bisa dikembangkan)
HOURLY_BLOCKED="[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"

# Buat JSON output
cat <<EOF > "$OUT"
{
  "date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "failed_total": $FAILED_TOTAL,
  "blocked_total": $BLOCKED_TOTAL,
  "success_total": $SUCCESS_TOTAL,
  "top_ips": [${TOP_IP%,}],
  "top_users": [${TOP_USER%,}],
  "hourly_failed": $HOURLY_FAILED,
  "hourly_blocked": $HOURLY_BLOCKED
}
EOF
