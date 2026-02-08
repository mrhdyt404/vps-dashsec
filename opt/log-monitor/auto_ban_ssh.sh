#!/bin/bash

LOG="/var/log/auth.log"
THRESHOLD=10
TMP="/tmp/ssh_attackers.txt"

grep "Failed password" "$LOG" \
 | awk '{print $(NF-3)}' \
 | sort | uniq -c | sort -nr \
 | awk -v t=$THRESHOLD '$1 >= t {print $2}' > "$TMP"

while read ip; do
    ufw status | grep -q "$ip" && continue
    echo "🚨 BANNING $ip"
    ufw insert 1 deny from $ip to any
done < "$TMP"
