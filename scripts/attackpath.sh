#!/usr/bin/env bash
# Attack-path / lateral-movement demo for the Amankan graph engine.
#
# Builds a 3-tier topology and asks: how can an attacker reach the crown-jewel
# database from the internet?
#
#   [external] web-dmz  --CAN_REACH:8080-->  app-server  --CAN_REACH:3306-->  db-core (CRITICAL)
#
# Each tier is scanned (critical profile) so it carries exploitable vulns, then
# reachability edges are drawn and attack paths to db-core are queried.
#
# Requires: API on :8080, a worker running, postgres + redis + neo4j up.
set -euo pipefail
BASE="${AMANKAN_BASE:-http://localhost:8080}"

pj() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

mkasset() { # name type target criticality tags-json
  curl -fsS -X POST "$BASE/api/v1/assets" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"type\":\"$2\",\"target\":\"$3\",\"criticality\":\"$4\",\"tags\":$5}" | pj id
}

scan() { # asset_id
  curl -fsS -X POST "$BASE/api/v1/assets/$1/scans" -H 'Content-Type: application/json' \
    -d '{"profile":"critical"}' >/dev/null
}

reach() { # src dst port
  curl -fsS -X POST "$BASE/api/v1/assets/$1/reachability" -H 'Content-Type: application/json' \
    -d "{\"target_id\":\"$2\",\"port\":$3}" >/dev/null
}

echo "== build 3-tier topology =="
WEB=$(mkasset web-dmz domain web.dmz.local high '["public","web"]')
APP=$(mkasset app-server ip 10.0.1.20 high '["internal"]')
DB=$(mkasset db-core ip 10.0.2.10 critical '["internal","database"]')
echo "  web-dmz=$WEB"
echo "  app-server=$APP"
echo "  db-core=$DB (crown jewel)"

echo "== scan every tier (populates vulnerabilities) =="
scan "$WEB"; scan "$APP"; scan "$DB"

echo "== wait for scans to complete =="
for i in $(seq 1 30); do
  PENDING=$(curl -fsS "$BASE/api/v1/scans" | python3 -c "import sys,json;print(sum(1 for s in json.load(sys.stdin) if s['status'] not in ('completed','failed')))")
  [ "$PENDING" = "0" ] && break
  sleep 1
done
echo "  all scans done"

echo "== draw reachability (lateral movement) edges =="
reach "$WEB" "$APP" 8080
reach "$APP" "$DB" 3306
echo "  web-dmz -> app-server -> db-core"

echo "== attack paths to db-core (min_risk>=7) =="
curl -fsS "$BASE/api/v1/assets/$DB/attack-paths?min_risk=7&max_hops=4" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f\"found {d['count']} attack path(s) to target (min_risk={d['min_risk']}):\\n\")
for i,p in enumerate(d['paths'],1):
    chain=' -> '.join(h['asset_name'] for h in p['hops'])
    print(f\"  Path {i}: {chain}  (edges={p['length']}, max_risk={p['max_risk']})\")
    for h in p['hops']:
        tag='[ENTRY/external]' if h['exposure']=='external' else f\"[{h['criticality']}]\"
        print(f\"      - {h['asset_name']:<12} {tag:<18} via {h['via_vuln_title']} (risk {h['via_vuln_risk']}, {h['via_vuln_cwe']})\")
    print()
"
echo "== attack-path demo done =="
