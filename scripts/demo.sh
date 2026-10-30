#!/usr/bin/env bash
# End-to-end walk through the running compose stack using only synthetic events from scripts/gen.py.
# Every request goes to 127.0.0.1; nothing is scanned or contacted outside this machine.
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh
RUN=${RUN:-$(date +%s)}
PRIYA="priya.$RUN@example.test"

ADMIN=$(bearer "$(token admin@acme 'sentinel.analyst sentinel.admin')")
ADMIN2=$(bearer "$(token admin2@acme 'sentinel.analyst sentinel.admin')")
ANALYST=$(bearer "$(token analyst@acme sentinel.analyst)")
PII=$(bearer "$(token lead@acme 'sentinel.analyst sentinel.pii')")
GLOBEX=$(bearer "$(token admin@globex 'sentinel.analyst sentinel.admin')")

echo "1. rules and a block list (admin)"
rule() { expect "$1" "$ADMIN" POST /v1/rules "$(jq -nc --arg id "$2" --arg dsl "$3" --arg sev "$4" '{id:$id,name:$id,dsl:$dsl,severity:$sev}')" > /dev/null; }
put_rule() { local s; s=$(status "$ADMIN" POST /v1/rules "$(jq -nc --arg id "$1" --arg dsl "$2" --arg sev "$3" '{id:$id,name:$id,dsl:$dsl,severity:$sev}')"); [[ $s == 201 || $s == 200 ]] || { echo "FAIL rule $1 -> $s" >&2; exit 1; }; }
put_rule spray "threshold login.failure >= 20 by ip within 5m" HIGH
put_rule takeover "sequence login.failure{5,} then login.success where asn is new by user within 10m" CRITICAL
put_rule travel "travel login.success by user faster than 900 kmh" MEDIUM
put_rule blocked-ip "ioc ip in \"blocked-ips\"" HIGH
check "saving an identical rule again changes nothing" \
  "$(status "$ADMIN" POST /v1/rules '{"id":"spray","name":"spray","dsl":"threshold   login.failure >= 20 by ip within 5m","severity":"HIGH"}')" 200
check "an analyst cannot change rules" "$(status "$ANALYST" POST /v1/rules '{"id":"x","name":"x","dsl":"threshold login.failure >= 2 by ip within 5m","severity":"LOW"}')" 403
check "a bad rule says what is wrong" "$(expect 400 "$ADMIN" POST /v1/rules '{"id":"bad","name":"bad","dsl":"threshold login.failure >= by ip","severity":"LOW"}' | jq -r .code)" rule-syntax
expect 200 "$ADMIN" POST /v1/iocs/blocked-ips '{"kind":"ip","values":["192.0.2.66"]}' > /dev/null

sleep 3 # rules and block lists apply on the next poll (every 2 s)

echo "2. a collector sends synthetic events"
KEY=$(expect 201 "$ADMIN" POST /v1/collectors "{\"name\":\"demo-$RUN\"}" | jq -r .apiKey)
COLLECTOR="X-Api-Key: $KEY"
ATTACK=$(python3 gen.py --scenario attack --seed "$RUN" --tag ".$RUN")
NOISE=$(python3 gen.py --scenario noise --count 300 --seed "$RUN")
accepted=0
while read -r batch; do
  accepted=$((accepted + $(expect 202 "$COLLECTOR" POST /v1/events:batch "$batch" | jq .accepted)))
done <<< "$NOISE"$'\n'"$ATTACK"
check "all 335 synthetic events accepted" "$accepted" 335
check "resending the attack batch is all duplicates" "$(expect 202 "$COLLECTOR" POST /v1/events:batch "$ATTACK" | jq .duplicates)" 35
check "a wrong collector key is refused" "$(status 'X-Api-Key: sk_wrong' POST /v1/events:batch "$ATTACK")" 401
# two OpenSSH-style lines over syslog TCP, to the local port only
{
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '<38>1 %s demo-host sshd 4242 - - Failed password for invalid user root from 203.0.113.10 port 50022 ssh2\n' "$now"
  printf '<38>1 %s demo-host sshd 4242 - - Failed password for invalid user admin from 203.0.113.10 port 50023 ssh2\n' "$now"
} > "/dev/tcp/127.0.0.1/$SYSLOG_PORT"

echo "3. detections become alerts and incidents"
has_alert() { call "$ANALYST" GET "/v1/alerts?limit=200" | sed '$d' | jq -e --arg r "$1" --arg e "$2" 'any(.[]; .rule_id == $r and .entity_key == $e)'; }
wait_for 120 has_alert spray 203.0.113.10
wait_for 60 has_alert takeover $PRIYA
wait_for 60 has_alert travel ravi.$RUN@example.test
wait_for 60 has_alert blocked-ip 192.0.2.66
echo "  ok   spray, takeover, travel and block-list alerts all raised"
INCIDENT=$(expect 200 "$ANALYST" GET "/v1/incidents?limit=200" | jq -r --arg u "$PRIYA" '[.[] | select(.entityKey == $u and .state == "NEW")][0].id')
[[ $INCIDENT != null ]] || { echo "FAIL: no incident for priya" >&2; exit 1; }
check "takeover incident is critical" "$(expect 200 "$ANALYST" GET "/v1/incidents/$INCIDENT" | jq -r .incident.severity)" CRITICAL
check "NEW cannot jump to RESOLVED" "$(status "$ANALYST" POST "/v1/incidents/$INCIDENT/transition" '{"to":"RESOLVED"}')" 409
expect 200 "$ANALYST" POST "/v1/incidents/$INCIDENT/transition" '{"to":"TRIAGED","note":"demo"}' > /dev/null
expect 200 "$ANALYST" POST "/v1/incidents/$INCIDENT/transition" '{"to":"INVESTIGATING"}' > /dev/null

echo "4. a playbook locks the (demo) account and notifies, after a second person approves"
PB="lock-notify-$RUN"
expect 200 "$ADMIN" PUT "/v1/playbooks/$PB" '{"name":"Lock and notify","needsApproval":true,"steps":[
  {"kind":"LOCK_ACCOUNT","params":{}},{"kind":"NOTIFY_WEBHOOK","params":{"url":"http://localhost:7990/demo/webhook-sink"}}]}' > /dev/null
check "webhooks to other hosts are refused" "$(status "$ADMIN" PUT "/v1/playbooks/x-$RUN" '{"name":"x","needsApproval":false,"steps":[{"kind":"NOTIFY_WEBHOOK","params":{"url":"https://example.com/hook"}}]}')" 400
RUNID=$(expect 201 "$ADMIN" POST "/v1/incidents/$INCIDENT/playbooks/$PB:run" | jq -r .id)
check "the requester cannot approve their own run" "$(status "$ADMIN" POST "/v1/playbook-runs/$RUNID:approve")" 403
expect 200 "$ADMIN2" POST "/v1/playbook-runs/$RUNID:approve" > /dev/null
run_done() { call "$ANALYST" GET "/v1/playbook-runs/$RUNID" | sed '$d' | jq -e '.run.status == "SUCCEEDED"'; }
wait_for 60 run_done
check "incident contained by the playbook" "$(expect 200 "$ANALYST" GET "/v1/incidents/$INCIDENT" | jq -r .incident.state)" CONTAINED
check "demo account locked" "$(expect 200 "$ANALYST" GET /v1/demo/accounts | jq -r --arg u "$PRIYA" '.[] | select(.user_name == $u) | .locked')" true
delivered() { call "$ADMIN" GET /v1/demo/webhook-deliveries | sed '$d' | jq -e --arg r "$RUNID" '[.[] | select((.body | fromjson).runId == $r)] | length == 1'; }
wait_for 30 delivered
echo "  ok   one signed webhook delivered to the in-app sink"

echo "5. search masks personal data unless the caller holds sentinel.pii"
check "default search is masked" "$(expect 200 "$ANALYST" GET "/v1/events/search?user=$PRIYA&limit=5" | jq -r --arg u "$PRIYA" '.events[0].user == $u')" false
check "asking for cleartext without the scope is refused" "$(status "$ANALYST" GET "/v1/events/search?user=$PRIYA&unmasked=true")" 403
check "the pii scope sees cleartext" "$(expect 200 "$PII" GET "/v1/events/search?user=$PRIYA&unmasked=true&limit=5" | jq -r '.events[0].user')" "$PRIYA"

echo "6. tenants are isolated"
check "globex sees none of acme's alerts" "$(expect 200 "$GLOBEX" GET '/v1/alerts?limit=200' | jq 'length')" 0
check "globex cannot read acme's incident" "$(status "$GLOBEX" GET "/v1/incidents/$INCIDENT")" 404

echo "7. the audit trail is sealed, signed and stored under object lock"
expect 200 "$ADMIN" POST /v1/audit/batches:seal > /dev/null
BATCH=$(expect 200 "$ADMIN" GET /v1/audit/batches | jq -r '.[0].id')
VERIFY=$(expect 200 "$ADMIN" GET "/v1/audit/batches/$BATCH/verify")
check "latest batch verifies" "$(jq -r .valid <<< "$VERIFY")" true
check "stored under compliance lock" "$(jq -r .objectLockMode <<< "$VERIFY")" COMPLIANCE

echo "8. dashboard"
expect 200 "$ANALYST" GET /v1/dashboard/summary?hours=1 | jq -c '{alertsBySeverity, incidentsByState}'
echo "demo passed"
