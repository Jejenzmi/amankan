#!/usr/bin/env bash
# Privilege-escalation attack-path demo (Account/Privilege graph + apoc Dijkstra).
#
# Models how an attacker turns an initial foothold into domain-level control,
# combining LOCAL privilege escalation (CAN_ESCALATE, intra-host) with LATERAL
# credential reuse (CREDENTIAL_REUSE, inter-host). Edge weights = attacker effort
# (lower = easier); apoc.algo.dijkstra returns the minimum-effort chain.
#
#   www-data@web-dmz  --escalate(kernel CVE,0.5)-->  root@web-dmz
#                     --cred-reuse(ssh key,3)----->  appuser@app-server
#                     --escalate(sudo misconfig,1)-> root@app-server
#                     --cred-reuse(db creds,2)----->  dba@db-core
#                     --escalate(db role,1)--------> dbroot@db-core   (TARGET)
#
#   (a noisy shortcut www-data --cred-reuse(9)--> dba exists; Dijkstra rejects it
#    because the multi-step chain is cheaper: 7.5 < 10.)
#
# Requires: API on :8080 with Neo4j (apoc) enabled.
set -euo pipefail
BASE="${AMANKAN_BASE:-http://localhost:8080}"
pj() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

mkasset() { curl -fsS -X POST "$BASE/api/v1/assets" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$1\",\"type\":\"$2\",\"target\":\"$3\",\"criticality\":\"$4\",\"tags\":$5}" | pj id; }

mkacct() { # asset_id username privilege
  curl -fsS -X POST "$BASE/api/v1/accounts" -H 'Content-Type: application/json' \
    -d "{\"asset_id\":\"$1\",\"username\":\"$2\",\"privilege\":\"$3\"}" | pj id; }

escalate() { # from to technique cwe weight
  curl -fsS -X POST "$BASE/api/v1/accounts/$1/escalation" -H 'Content-Type: application/json' \
    -d "{\"target_account_id\":\"$2\",\"technique\":\"$3\",\"cwe\":\"$4\",\"weight\":$5}" >/dev/null; }

reuse() { # from to weight
  curl -fsS -X POST "$BASE/api/v1/accounts/$1/credential-reuse" -H 'Content-Type: application/json' \
    -d "{\"target_account_id\":\"$2\",\"weight\":$3}" >/dev/null; }

echo "== assets =="
WEB=$(mkasset web-dmz domain web2.dmz.local high '["public","web"]')
APP=$(mkasset app-srv ip 10.0.1.30 high '["internal"]')
DB=$(mkasset db-core2 ip 10.0.2.20 critical '["internal","database"]')
echo "  web-dmz=$WEB  app-srv=$APP  db-core2=$DB"

echo "== accounts =="
WWW=$(mkacct "$WEB" www-data service)   # initial foothold
RWEB=$(mkacct "$WEB" root root)
APPU=$(mkacct "$APP" appuser user)
RAPP=$(mkacct "$APP" root root)
DBA=$(mkacct "$DB" dba admin)
DBROOT=$(mkacct "$DB" dbroot root)       # crown-jewel target
echo "  foothold=www-data@web-dmz ($WWW)"
echo "  target  =dbroot@db-core2  ($DBROOT)"

echo "== escalation + credential-reuse edges =="
escalate "$WWW"  "$RWEB"   "DirtyPipe kernel LPE" "CWE-269" 0.5
reuse    "$RWEB" "$APPU"   3
escalate "$APPU" "$RAPP"   "sudo misconfiguration" "CWE-250" 1
reuse    "$RAPP" "$DBA"    2
escalate "$DBA"  "$DBROOT" "DB superuser role grant" "CWE-269" 1
reuse    "$WWW"  "$DBA"    9     # noisy shortcut Dijkstra should avoid

echo "== minimum-effort privilege-escalation path (www-data -> dbroot) =="
curl -fsS "$BASE/api/v1/privesc-path?from=$WWW&to=$DBROOT" | python3 -c "
import sys,json
p=json.load(sys.stdin)
if not p.get('found'):
    print('  no path found'); sys.exit(0)
accts=p['accounts']; steps=p['steps']
print(f\"  total attacker effort (cost) = {p['total_cost']}  ({len(steps)} steps)\\n\")
for i,a in enumerate(accts):
    print(f\"  {a['username']}@{a['asset']}  [{a['privilege']}]\")
    if i < len(steps):
        s=steps[i]
        label = s.get('technique') or 'credential reuse'
        cwe = f\" {s['cwe']}\" if s.get('cwe') else ''
        print(f\"        |  {s['type']}: {label}{cwe}  (weight {s['weight']})\")
        print(f\"        v\")
"
echo "== privilege-escalation demo done =="
