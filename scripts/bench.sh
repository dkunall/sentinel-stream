#!/usr/bin/env bash
# Small local benchmark against the compose stack, synthetic events only.
#   ingest:    B batches of 200 noise events posted back to back (sequential, one curl per batch)
#   detection: time from posting a 25-event spray burst to its alert showing in /v1/alerts, R rounds
# Prints what it measured on this machine; the numbers say nothing about other hardware.
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh
B=${B:-25}
R=${R:-5}
TAG=${TAG:-$(date +%s)}
# a fresh tenant per run, so earlier runs' alerts cannot satisfy this run's wait
ADMIN=$(bearer "$(token "admin@bench$TAG" 'sentinel.analyst sentinel.admin')")
KEY=$(expect 201 "$ADMIN" POST /v1/collectors "{\"name\":\"bench-$TAG\"}" | jq -r .apiKey)
COLLECTOR="X-Api-Key: $KEY"
put() { local s; s=$(status "$ADMIN" POST /v1/rules "$1"); [[ $s == 201 || $s == 200 ]] || { echo "rule -> $s" >&2; exit 1; }; }
put '{"id":"bench-spray","name":"bench-spray","dsl":"threshold login.failure >= 20 by ip within 5m","severity":"HIGH"}'
sleep 3 # the detector picks up rule changes on a 2 s poll

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 gen.py --scenario noise --count $((B * 200)) --batch 200 --seed "bench-$TAG" > "$tmp/batches"
start=$(date +%s%N)
while read -r batch; do
  curl -s -o /dev/null -w '%{time_total}\n' -X POST "$BASE/v1/events:batch" -H "$COLLECTOR" \
    -H 'Content-Type: application/json' -d "$batch" >> "$tmp/ingest"
done < "$tmp/batches"
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))
echo "ingest: $((B * 200)) events in $B batches, ${elapsed_ms} ms wall, $(( B * 200 * 1000 / elapsed_ms )) events/s;" \
  "per-batch latency p50 $(percentile "$tmp/ingest" 50)s p95 $(percentile "$tmp/ingest" 95)s"

for ((r = 0; r < R; r++)); do
  ip="203.0.113.$((20 + r))"
  now=$(date -u +%s)
  burst=$(jq -nc --arg ip "$ip" --arg tag "$TAG-$r" --argjson now "$now" \
    '{events: [range(25) | {id: "bench-\($tag)-\(.)", ts: (($now - 30 + .) | todate), user: "u\(.)@example.test",
      ip: $ip, action: "login", outcome: "failure", user_agent: "SyntheticAgent/1.0"}]}')
  t0=$(date +%s%N)
  expect 202 "$COLLECTOR" POST /v1/events:batch "$burst" > /dev/null
  until call "$ADMIN" GET "/v1/alerts?limit=200" | sed '$d' | jq -e --arg ip "$ip" 'any(.[]; .rule_id == "bench-spray" and .entity_key == $ip)' > /dev/null; do
    sleep 0.1
    (( ($(date +%s%N) - t0) / 1000000000 < 60 )) || { echo "FAIL: no alert for $ip within 60s" >&2; exit 1; }
  done
  echo $(( ($(date +%s%N) - t0) / 1000000 )) >> "$tmp/detect"
done
echo "detection: post-to-visible-alert over $R bursts (polled every 100 ms, so +~100 ms granularity):" \
  "min $(sort -n "$tmp/detect" | head -1) ms, p50 $(percentile "$tmp/detect" 50) ms, max $(sort -n "$tmp/detect" | tail -1) ms"
echo "server-side detection latency timer (event ingest -> signal):"
expect 200 "$ADMIN" GET /v1/dashboard/summary?hours=1 | jq -c .detectionLatency
