#!/bin/bash

URL="https://realtimechat.gbsuper.my.id/"

echo "Starting random requests..."

for i in $(seq 1 100); do
    curl -s -o /dev/null -w "[$i] HTTP %{http_code}\n" "$URL"
    sleep 0.05
done

echo "Finished."
