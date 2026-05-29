#!/usr/bin/env bash
# Auto-derived privilege-escalation demo.
#
# The CAN_ESCALATE (local foothold->root) edges are NOT seeded by hand: they are
# derived automatically from scan findings. The PwnKit finding (CVE-2021-4034 ->
# CWE-269) emitted during a scan makes Amankan wire a foothold->root escalation
# edge on that host, with weight taken from the finding's risk score.
#
# The only manual edge is the cross-host CREDENTIAL_REUSE (trust between hosts is
# not observable from scanning a single host).
#
#   [scan] web-dmz  => auto CAN_ESCALATE foothold->root
#   [scan] db-core  => auto CAN_ESCALATE foothold->root
#   [manual] root@web-dmz --CREDENTIAL_REUSE--> foothold@db-core
#
#   query: privesc-path foothold@web-dmz -> root@db-core
#
# Requires: API on :8080 + worker + Neo4j (apoc) enabled.
set -euo pipefail
BASE="${AMANKAN_BASE:-http://localhost:8080}"
pj() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

mkasset() { curl -fsS -X POST "$BASE/api/v1/assets" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$1\",\"type\":\"$2\",\"target\":\"$3\",\"criticality\":\"$4\",\"tags\":$5}" | pj id; }

acct_id() { # asset_id username  -> account id (from the list endpoint)
  curl -fsS "$BASE/api/v1/assets/$1/accounts" | \
    python3 -c "import sys,json;print(next((a['id'] for a in json.load(sys.stdin) if a['username']=='$2'),''))"; }

echo "== assets =="
WEB=$(mkasset web-edge domain web.edge.local high '["public","web"]')
DB=$(mkasset db-vault ip 10.0.9.10 critical '["internal","database"]')
echo "  web-edge=$WEB  db-vault=$DB (crown jewel)"

echo "== scan both (critical profile emits the PwnKit priv-esc finding) =="
curl -fsS -X POST "$BASE/api/v1/assets/$WEB/scans" -H 'Content-Type: application/json' -d '{"profile":"critical"}' >/dev/null
curl -fsS -X POST "$BASE/api/v1/assets/$DB/scans"  -H 'Content-Type: application/json' -d '{"profile":"critical"}' >/dev/null

echo "== wait for scans =="
for i in $(seq 1 30); do
  PENDING=$(curl -fsS "$BASE/api/v1/scans" | python3 -c "import sys,json;print(sum(1 for s in json.load(sys.stdin) if s['status'] not in ('completed','failed')))")
  [ "$PENDING" = "0" ] && break; sleep 1
done
echo "  done"

echo "== accounts auto-created on each host (no manual input) =="
echo "  web-edge:"; curl -fsS "$BASE/api/v1/assets/$WEB/accounts" | python3 -c "import sys,json;[print(f\"    {a['username']:<9} [{a['privilege']}]  {a['id']}\") for a in json.load(sys.stdin)]"
echo "  db-vault:"; curl -fsS "$BASE/api/v1/assets/$DB/accounts"  | python3 -c "import sys,json;[print(f\"    {a['username']:<9} [{a['privilege']}]  {a['id']}\") for a in json.load(sys.stdin)]"

WEB_FOOT=$(acct_id "$WEB" foothold); WEB_ROOT=$(acct_id "$WEB" root)
DB_FOOT=$(acct_id "$DB" foothold);  DB_ROOT=$(acct_id "$DB" root)

echo "== manual cross-host credential reuse: root@web-edge -> foothold@db-vault =="
curl -fsS -X POST "$BASE/api/v1/accounts/$WEB_ROOT/credential-reuse" -H 'Content-Type: application/json' \
  -d "{\"target_account_id\":\"$DB_FOOT\"}" >/dev/null
echo "  edge added"

echo "== self-formed privilege-escalation path: foothold@web-edge -> root@db-vault =="
curl -fsS "$BASE/api/v1/privesc-path?from=$WEB_FOOT&to=$DB_ROOT" | python3 -c "
import sys,json
p=json.load(sys.stdin)
if not p.get('found'): print('  no path found'); sys.exit(0)
accts=p['accounts']; steps=p['steps']
print(f\"  total attacker effort (cost) = {p['total_cost']}  ({len(steps)} steps)\\n\")
for i,a in enumerate(accts):
    print(f\"  {a['username']}@{a['asset']}  [{a['privilege']}]\")
    if i < len(steps):
        s=steps[i]; label=s.get('technique') or 'credential reuse'
        auto='(auto-derived from scan)' if s['type']=='CAN_ESCALATE' else '(manual)'
        cwe=f\" {s['cwe']}\" if s.get('cwe') else ''
        print(f\"        |  {s['type']}: {label}{cwe}  (weight {s['weight']}) {auto}\")
        print('        v')
"
echo "== auto priv-esc demo done =="
