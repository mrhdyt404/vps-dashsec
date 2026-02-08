#!/bin/bash

LOG="/var/log/auth.log"
OUT="/opt/log-monitor/report_$(date +%F).txt"

echo "📊 LAPORAN KEAMANAN SSH - $(date)" > "$OUT"
echo "===================================" >> "$OUT"

echo -e "\n🔴 Top 10 IP gagal login:" >> "$OUT"
grep "Failed password" $LOG | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head >> "$OUT"

echo -e "\n👤 Username paling sering diserang:" >> "$OUT"
grep "Failed password" $LOG | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr | head >> "$OUT"

echo -e "\n🌍 Negara (berdasarkan reverse DNS jika ada):" >> "$OUT"
grep "Failed password" $LOG | awk '{print $(NF-3)}' | sort | uniq | head -n 10 | while read ip; do
    host $ip 2>/dev/null | head -n 1
done >> "$OUT"

echo -e "\n🚨 IP diblokir fail2ban:" >> "$OUT"
fail2ban-client status sshd 2>/dev/null >> "$OUT"

echo -e "\n📈 Total percobaan gagal hari ini:" >> "$OUT"
grep -c "Failed password" $LOG >> "$OUT"
