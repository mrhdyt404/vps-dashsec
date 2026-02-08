#!/bin/bash

LOG="/var/log/auth.log"
OUT="/opt/log-monitor/report_$(date +%F).txt"

echo "📊 LAPORAN KEAMANAN SSH - $(date)" > "$OUT"
echo "===================================" >> "$OUT"

# Top 10 IP gagal login
echo -e "\n🔴 Top 10 IP gagal login:" >> "$OUT"
grep "Failed password" "$LOG" | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' \
    | sort | uniq -c | sort -nr | head >> "$OUT"

# Top 10 username yang diserang
echo -e "\n👤 Username paling sering diserang:" >> "$OUT"
grep "Failed password" "$LOG" | awk '{for(i=1;i<=NF;i++){if($i=="for"){print $(i+1)}}}' \
    | sort | uniq -c | sort -nr | head >> "$OUT"

# Negara berdasarkan IP (reverse DNS)
echo -e "\n🌍 Negara (reverse DNS / lookup):" >> "$OUT"
grep "Failed password" "$LOG" | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' \
    | sort | uniq | head -n 10 | while read ip; do
    host "$ip" 2>/dev/null | head -n 1
done >> "$OUT"

# IP diblokir fail2ban
echo -e "\n🚨 IP diblokir fail2ban:" >> "$OUT"
fail2ban-client status sshd 2>/dev/null >> "$OUT"

# Total percobaan gagal
echo -e "\n📈 Total percobaan gagal hari ini:" >> "$OUT"
grep -c "Failed password" "$LOG" >> "$OUT"
