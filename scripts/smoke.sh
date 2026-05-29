#!/usr/bin/env bash
# End-to-end smoke test for the Amankan PoC.
# Requires: API on :8080, a worker running, postgres + redis up.
set -euo pipefail

BASE="${AMANKAN_BASE:-http://localhost:8080}"
# Use jq if present; otherwise fall back to python for pretty-print and -r field reads.
jqbin() { if command -v jq >/dev/null; then jq "$@"; else py_jq "$@"; fi; }
py_jq() {
  if [ "${1:-}" = "-r" ]; then
    field="${2#.}"; python3 -c "import sys,json;print(json.load(sys.stdin).get('$field',''))"
  else
    python3 -m json.tool
  fi
}

echo "== health =="
curl -fsS "$BASE/healthz" | jqbin .

echo "== create asset =="
ASSET=$(curl -fsS -X POST "$BASE/api/v1/assets" \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-web","type":"domain","target":"demo.local","criticality":"critical","tags":["public","web"]}')
echo "$ASSET" | jqbin .
ASSET_ID=$(echo "$ASSET" | jqbin -r .id)

echo "== start critical scan (nmap + nuclei + crypto) =="
SCAN=$(curl -fsS -X POST "$BASE/api/v1/assets/$ASSET_ID/scans" \
  -H 'Content-Type: application/json' -d '{"profile":"critical"}')
echo "$SCAN" | jqbin .
SCAN_ID=$(echo "$SCAN" | jqbin -r .id)

echo "== wait for worker to finish =="
for i in $(seq 1 30); do
  STATUS=$(curl -fsS "$BASE/api/v1/scans/$SCAN_ID" | jqbin -r .status)
  echo "  status=$STATUS"
  [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] && break
  sleep 1
done

echo "== findings (sorted by risk) =="
curl -fsS "$BASE/api/v1/findings?scan_id=$SCAN_ID" | jqbin '.[] | {title, severity, cvss, risk_score, cwe, known_exploit}'

echo "== compliance mapping for CWE-327 =="
curl -fsS "$BASE/api/v1/compliance/cwe/CWE-327" | jqbin .

echo "== smoke test done =="
