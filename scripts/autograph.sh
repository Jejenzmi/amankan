#!/usr/bin/env bash
# Fully self-formed privilege attack graph — ZERO manual graph edges.
#
# Two hosts are scanned. From the findings alone, Amankan derives BOTH kinds of
# privilege edges:
#   * CAN_ESCALATE    (local)   <- PwnKit priv-esc finding (CWE-269)
#   * CREDENTIAL_REUSE (lateral) <- shared hard-coded credential (CWE-798):
#         both hosts expose the same svc-deploy fingerprint, so compromising
#         root on one lets the attacker land as a user on the other.
#
# Resulting self-formed path foothold@web -> root@db:
#   foothold@web --escalate(PwnKit)--> root@web
#                --cred-reuse(shared svc-deploy)--> foothold@db
#                --escalate(PwnKit)--> root@db
#
# No /reachability, no /accounts, no /credential-reuse calls. Only scans.
#
# Requires: API on :8080 + worker + Neo4j (apoc) enabled.
set -euo pipefail
BASE="${AMANKAN_BASE:-http://localhost:8080}"
pj() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }
mkasset() { curl -fsS -X POST "$BASE/api/v1/assets" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$1\",\"type\":\"$2\",\"target\":\"$3\",\"criticality\":\"$4\",\"tags\":$5}" | pj id; }
acct_id() { curl -fsS "$BASE/api/v1/assets/$1/accounts" | \
  python3 -c "import sys,json;print(next((a['id'] for a in json.load(sys.stdin) if a['username']=='$2'),''))"; }

echo "== assets =="
WEB=$(mkasset web-gw domain web.gw.local high '["public","web"]')
DB=$(mkasset db-crown ip 10.0.7.10 critical '["internal","database"]')
echo "  web-gw=$WEB  db-crown=$DB"

echo "== scan both (critical profile: nmap+nuclei+crypto+secrets) =="
curl -fsS -X POST "$BASE/api/v1/assets/$WEB/scans" -H 'Content-Type: application/json' -d '{"profile":"critical"}' >/dev/null
curl -fsS -X POST "$BASE/api/v1/assets/$DB/scans"  -H 'Content-Type: application/json' -d '{"profile":"critical"}' >/dev/null
for i in $(seq 1 30); do
  PENDING=$(curl -fsS "$BASE/api/v1/scans" | python3 -c "import sys,json;print(sum(1 for s in json.load(sys.stdin) if s['status'] not in ('completed','failed')))")
  [ "$PENDING" = "0" ] && break; sleep 1
done
echo "  scans complete"

WEB_FOOT=$(acct_id "$WEB" foothold); DB_ROOT=$(acct_id "$DB" root)

echo "== self-formed privilege-escalation path: foothold@web-gw -> root@db-crown =="
echo "   (no manual edges were created — everything below is derived from scans)"
echo
curl -fsS "$BASE/api/v1/privesc-path?from=$WEB_FOOT&to=$DB_ROOT" | python3 -c "
import sys,json
p=json.load(sys.stdin)
if not p.get('found'): print('  no path found'); sys.exit(1)
accts=p['accounts']; steps=p['steps']
print(f\"  total attacker effort (cost) = {p['total_cost']}  ({len(steps)} steps)\\n\")
for i,a in enumerate(accts):
    print(f\"  {a['username']}@{a['asset']}  [{a['privilege']}]\")
    if i < len(steps):
        s=steps[i]; label=s.get('technique') or 'shared credential'
        cwe=f\" {s['cwe']}\" if s.get('cwe') else ''
        print(f\"        |  {s['type']}: {label}{cwe}  (weight {s['weight']})  [auto-derived]\")
        print('        v')
"
echo "== fully self-formed attack-graph demo done =="
