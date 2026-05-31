# Amankan — Enterprise Security Intelligence Platform (Phase 1 PoC)

A runnable proof-of-concept for the **Amankan** SOAR / Vulnerability Management
concept. This phase implements the spine of the platform end-to-end:

> **Ingestion → Orchestration → Scan → Normalization → Risk Prioritization → Compliance Mapping → Remediation guidance**

It deliberately uses a pragmatic, laptop-runnable stack. The heavier components
from the full design (Neo4j attack-path graph, Kubernetes Jobs, Keycloak,
RabbitMQ, ELK) are out of scope for Phase 1 and noted as integration seams.

## What's implemented

| Design component | Phase 1 implementation |
| --- | --- |
| Orchestrator Service | Redis queue + worker process (`cmd/worker`) |
| Scanner integration | `nmap` (real), `nuclei` (real), TLS crypto audit, secrets/SAST (hard-coded credentials) — each with a safe **mock fallback** |
| Normalization Engine | `internal/normalize` → one internal `Finding` schema |
| Prioritization | `internal/risk`: CVSS × asset criticality × threat-intel (KEV-style) |
| Compliance Policy Engine | `internal/compliance`: CWE → OWASP Top10/ASVS → ISO 27001 → BSSN/Indeks KAMI → COBIT |
| Remediation | Actionable steps + compliance references attached per finding |
| Primary DB | PostgreSQL (transactional data) |
| **Graph Analysis Engine** | **Neo4j** (`internal/graph`): assets + vulns as a graph, reachability edges, **attack-path / lateral-movement** detection |

| **Dashboard** | **Next.js** (`web/`): asset/finding management, live scan status, remediation + compliance drill-down, attack-graph visualization |
| **Security hardening** | API-key auth + **RBAC** (viewer/analyst/admin), config-driven CORS, security headers, per-IP rate limit |
| **Tamper-evident audit** | append-only, SHA-256 **hash-chained** audit log of every mutation, with chain-integrity verification |
| **Threat intelligence** | CISA **KEV** + FIRST.org **EPSS** feeds (offline fallback set) feeding risk scoring |
| **Remediation SLA** | severity-driven due dates + breach tracking on every finding |
| **Secure SDLC** | GitHub Actions CI: build/vet/test (race), **govulncheck**, **CycloneDX SBOM**, dashboard build |

### Not in Phase 1 (integration seams)
Kubernetes Jobs, Keycloak OAuth2/OIDC (the API-key RBAC here is the enforcement
stand-in), RabbitMQ, ELK, external secret vault, automated patch testing.

## Architecture

```
              ┌────────────┐   enqueue    ┌─────────┐   pop    ┌────────────┐
   client ───▶│  API (8080)│─────────────▶│  Redis  │─────────▶│   worker   │
              └─────┬──────┘   scan job    └─────────┘          └─────┬──────┘
                    │                                                  │
                    ▼                                                  ▼
              ┌──────────┐                          scanners → normalize → risk → compliance
              │ Postgres │◀───── findings (enriched) ────────────────────────┘
              └──────────┘
```

## Quick start

```bash
cp .env.example .env            # optional; defaults work with docker-compose
make up                         # start postgres + redis
make tidy                       # download Go deps
make build                      # compile bin/api and bin/worker

# terminal 1 — API (also runs migrations on startup)
make api

# terminal 2 — worker
make worker

# terminal 3 — drive the full pipeline
make smoke
```

> **Live scanning is off by default.** Set `AMANKAN_ALLOW_LIVE_SCAN=true` to run
> real `nmap`/`nuclei`/TLS probes — and even then only loopback / RFC1918
> targets are scanned for real; everything else uses deterministic mock output.
> This keeps the PoC safe and runnable when scanners aren't installed.

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz` | liveness |
| `GET` | `/readyz` | readiness (DB + Redis reachable) |
| `GET` | `/metrics` | Prometheus metrics |
| `POST` | `/api/v1/assets` | register an asset (ingestion) |
| `GET` | `/api/v1/assets` / `/assets/{id}` | list / get assets |
| `POST` | `/api/v1/assets/{id}/scans` | orchestrate a scan (`profile`: `quick`\|`web`\|`critical`) |
| `POST` | `/api/v1/assets/{id}/authorize` | grant/revoke active-scan authorization (admin) |
| `GET` | `/api/v1/scans` / `/scans/{id}` | list / get scan jobs |
| `GET` | `/api/v1/findings?asset_id=&scan_id=` | findings, sorted by risk score |
| `GET` | `/api/v1/findings/export?asset_id=&scan_id=` | findings as **CSV** (audit/BSSN report) |
| `PATCH` | `/api/v1/findings/{id}/status` | validate / mark false-positive / remediated |
| `GET` | `/api/v1/compliance/cwe/{cwe}` | governance mapping + remediation for a CWE |
| `GET` | `/api/v1/audit` | tamper-evident audit log (admin) |
| `GET` | `/api/v1/audit/verify` | recompute the audit hash-chain integrity (admin) |
| `POST` | `/api/v1/graph/sync` | (re)project all assets + findings into Neo4j |
| `POST` | `/api/v1/graph/topology` | bulk-import `CAN_REACH` edges from a CMDB/topology feed (`edges[]`, assets by id or target) |
| `GET` | `/api/v1/graph/export` | full attack graph (nodes + edges) for visualization |
| `POST` | `/api/v1/assets/{id}/reachability` | add a reachability edge (`target_id`, `port`) — a lateral-movement hop |
| `GET` | `/api/v1/assets/{id}/attack-paths` | attack paths leading to this asset (`min_risk`, `max_hops`) |
| `POST` | `/api/v1/accounts` | register a principal on an asset (`asset_id`, `username`, `privilege`) |
| `POST` | `/api/v1/accounts/{id}/escalation` | local priv-esc edge (`target_account_id`, `technique`, `cwe`, `weight`) |
| `POST` | `/api/v1/accounts/{id}/credential-reuse` | lateral credential-reuse edge (`target_account_id`, `weight`) |
| `GET` | `/api/v1/assets/{id}/accounts` | accounts on an asset (manual + auto-derived) |
| `GET` | `/api/v1/privesc-path` | min-effort privilege-escalation path (`from`, `to` account ids) |

### Example

```bash
# register a critical web asset
curl -XPOST localhost:8080/api/v1/assets -H 'Content-Type: application/json' \
  -d '{"name":"core-api","type":"domain","target":"api.internal","criticality":"critical"}'

# run the full profile (nmap + nuclei + crypto audit)
curl -XPOST localhost:8080/api/v1/assets/<asset-id>/scans \
  -H 'Content-Type: application/json' -d '{"profile":"critical"}'

# see prioritized, compliance-mapped findings
curl 'localhost:8080/api/v1/findings?asset_id=<asset-id>'
```

## Attack-path / lateral movement (Neo4j)

The graph engine answers: *"how can an attacker reach the crown-jewel asset?"*
A valid attack path starts at an **internet-exposed** asset (tagged `public`/
`external`) and every node on it carries an **exploitable** vulnerability
(`risk >= min_risk`). Edges are network reachability (`CAN_REACH`).

```bash
make graph-up        # start Neo4j (browser at http://localhost:7474, user neo4j / amankanpass)
make attackpath      # builds a 3-tier topology, scans it, queries attack paths
```

Example output (`scripts/attackpath.sh`):

```
Path 1: web-dmz -> app-server -> db-core  (edges=2, max_risk=10)
    - web-dmz      [ENTRY/external]   via Apache Log4j RCE (Log4Shell) (risk 10, CWE-502)
    - app-server   [high]             via Apache Log4j RCE (Log4Shell) (risk 10, CWE-502)
    - db-core      [critical]         via Weak TLS protocol version (TLS 1.0) (risk 10, CWE-327)
```

> The graph is **optional**: leave `AMANKAN_NEO4J_URI` empty (or stop Neo4j) and
> the API/worker still run — graph endpoints just return `503`.

### Privilege escalation (Account/Privilege graph + weighted Dijkstra)

Beyond network hops, the graph models **principals and privilege**: `Account`
nodes (per asset, at a privilege level) connected by weighted edges —
`CAN_ESCALATE` (local priv-esc, intra-host) and `CREDENTIAL_REUSE` (lateral,
inter-host). Edge weight = attacker effort; `apoc.algo.dijkstra` returns the
**minimum-effort** escalation chain from a foothold to a privileged target.

```bash
make privesc         # builds accounts + escalation/reuse edges, queries the path
```

Example output (`scripts/privesc.sh`) — note Dijkstra rejects a cheaper-looking
shortcut because the multi-step chain has lower total effort (7.5 < 10):

```
total attacker effort (cost) = 7.5  (5 steps)

www-data@web-dmz [service]
   | CAN_ESCALATE: DirtyPipe kernel LPE CWE-269 (weight 0.5)
root@web-dmz [root]
   | CREDENTIAL_REUSE (weight 3)
appuser@app-srv [user]
   | CAN_ESCALATE: sudo misconfiguration CWE-250 (weight 1)
root@app-srv [root]
   | CREDENTIAL_REUSE (weight 2)
dba@db-core2 [admin]
   | CAN_ESCALATE: DB superuser role grant CWE-269 (weight 1)
dbroot@db-core2 [root]
```

#### Auto-derived escalation edges (from scan findings)

`CAN_ESCALATE` edges form **automatically from scans** — no manual seeding. When
a scan produces a privilege-escalation finding (a priv-esc CWE such as `CWE-269`
PwnKit / `CWE-250`), Amankan ensures a `foothold (user)` and `root` account on
that host and wires a `foothold -> root` escalation edge, weighted from the
finding's `risk_score` (higher risk → lower effort). Only cross-host
`CREDENTIAL_REUSE` stays explicit (host-to-host trust isn't observable from
scanning one host).

```bash
make autoprivesc     # scans 2 hosts, escalation edges appear by themselves
```

```
total attacker effort (cost) = 3.6  (3 steps)

foothold@web-edge [user]
   | CAN_ESCALATE: PwnKit CWE-269 (weight 0.3) (auto-derived from scan)
root@web-edge [root]
   | CREDENTIAL_REUSE (weight 3) (manual)
foothold@db-vault [user]
   | CAN_ESCALATE: PwnKit CWE-269 (weight 0.3) (auto-derived from scan)
root@db-vault [root]
```

#### Auto-derived credential-reuse edges (fully self-formed graph)

The lateral `CREDENTIAL_REUSE` edges also form from scans. A hard-coded-credential
finding (`CWE-798`) reveals a credential with a **fingerprint**; when the *same
fingerprint* surfaces on multiple hosts (a shared service account), Amankan
infers that compromising `root` on one host lets the attacker authenticate as a
`user` on the others, and wires `root@X -> foothold@Y` automatically. Combined
with auto-escalation, the **entire privilege attack graph forms from scans with
zero manual edges**:

```bash
make autograph       # scans 2 hosts; full priv-esc path appears with NO manual edges
```

```
total attacker effort (cost) = 1.6  (3 steps)

foothold@web-gw [user]
   | CAN_ESCALATE: PwnKit CWE-269 (weight 0.3)        [auto-derived]
root@web-gw [root]
   | CREDENTIAL_REUSE: shared credential (weight 1)   [auto-derived]
foothold@db-crown [user]
   | CAN_ESCALATE: PwnKit CWE-269 (weight 0.3)        [auto-derived]
root@db-crown [root]
```

> **Network layer.** `CAN_REACH` edges are populated two ways, both without
> per-edge hand-wiring: (1) **CMDB/topology import** — `POST /graph/topology`
> bulk-loads edges from an inventory feed (assets referenced by id or target);
> (2) **subnet derivation** — scanning a private IP asset auto-creates host-level
> `CAN_REACH` to other assets in the same `/24` (a stand-in for internal
> network-discovery). Full arbitrary topology still comes from the CMDB feed,
> since cross-subnet reachability isn't observable from one host's scan.

## Dashboard (Next.js)

A web UI in `web/` drives the whole pipeline across four views:

- **Assets & Findings** — register assets, launch scans and watch their **live
  status**, drill into each finding (description, evidence, CVSS/CVE, full
  compliance mapping, remediation playbook), run the **validation workflow**
  (validate / false-positive / remediated), and **export findings to CSV**.
- **Scans** — full scan-job history (status, profile, duration, mock/live,
  errors) plus **graph administration**: re-project into Neo4j and bulk-import
  CAN_REACH edges from a CMDB/topology feed.
- **Privilege Escalation** — manage `Account` principals, draw CAN_ESCALATE /
  CREDENTIAL_REUSE edges, and run the **minimum-effort Dijkstra path** query.
- **Attack Graph** — the full graph (network reachability + privilege escalation
  + credential reuse) as an interactive force graph.

```bash
cd web
nvm use            # Node 20–22 (see .nvmrc); Next.js 15 does not build on Node 25
npm install
npm run dev        # http://localhost:3000  (expects the API on :8080)
```

> Point the dashboard at the API with `NEXT_PUBLIC_API_BASE`. For **Keycloak SSO**
> set `NEXT_PUBLIC_OIDC_ISSUER` + `NEXT_PUBLIC_OIDC_CLIENT_ID` (Authorization
> Code + PKCE login is built in, with a `/callback` route and sign-in/out); the
> obtained token is sent as the API bearer. Without OIDC, set
> `NEXT_PUBLIC_API_KEY` to use API-key auth.
>
> **Node version matters:** the `@next/swc` native compiler deadlocks on Node 25,
> so `next build`/`next dev` hang at "Creating an optimized production build".
> Use Node 20–22 LTS (`nvm use` / `engines` in `web/package.json`).

## Security & compliance hardening

The platform is built to the controls expected of a security product itself,
not just to scan for them:

- **Authentication & RBAC** — two interchangeable identity backends behind one
  RBAC model (`viewer` < `analyst` < `admin`): **OIDC/Keycloak** (RS256 JWT
  verified against the realm JWKS, realm roles → Amankan roles) when
  `AMANKAN_OIDC_ISSUER` is set, otherwise **API keys**
  (`AMANKAN_API_KEYS="label:secret:role,..."`, constant-time compared). Reads need
  `viewer`; scans / status / export need `analyst`; graph, accounts, audit and
  scan-authorization need `admin`. *(ISO 27001 A.5.15/A.8.2 · OWASP ASVS V1/V4 ·
  SOC 2 CC6.1)*
- **Authorized scanning only (Layer 3)** — real scanning of non-RFC1918 targets
  requires explicit authorization, recorded **per asset**
  (`POST /assets/{id}/authorize`) or globally (`AMANKAN_SCAN_AUTHORIZED`), and is
  audited. Scanning hosts you don't control is illegal; this gate prevents it by
  accident.
- **Transport & API hardening** — `AMANKAN_CORS_ORIGINS` allow-list (no more
  wildcard), security headers (HSTS/CSP/X-Frame-Options/nosniff), and a per-IP
  token-bucket rate limit (`AMANKAN_RATE_LIMIT` req/s). *(ASVS V9/V14)*
- **Tamper-evident audit trail** — every state-changing request is appended to a
  SHA-256 hash-chained log (`audit_log`); `GET /api/v1/audit/verify` recomputes
  the chain and reports the first broken sequence. *(ISO 27001 A.8.15 · SOC 2
  CC7 · BSSN forensic retention)*
- **Threat intelligence** — point `AMANKAN_KEV_FEED` at a CISA KEV JSON export
  and `AMANKAN_EPSS_FEED` at a FIRST.org EPSS CSV; otherwise an embedded KEV
  fallback set is used. KEV drives the risk multiplier; EPSS is surfaced per
  finding.
- **Remediation SLA** — each finding carries a severity-driven due date
  (critical 7d · high 30d · medium 90d · low 180d), breach flag and days
  remaining, shown in the dashboard. *(PCI DSS Req. 6/11 · ISO 27001 A.8.8)*
- **Transport & input** — optional TLS (`AMANKAN_TLS_CERT`/`_KEY`),
  constant-time API-key comparison, 1 MiB request-body cap, paginated list
  endpoints (`?limit=&offset=`, `X-Total-Count`), and graceful shutdown.
  *(ASVS V9/V13)*
- **Observability** — `/healthz` (liveness), `/readyz` (DB+Redis readiness),
  `/metrics` (Prometheus), and structured JSON access logs. *(ISO 27001 A.8.16)*
- **Secure SDLC** — `.github/workflows/ci.yml` runs `go build/vet/test -race`,
  `govulncheck` (dependency CVEs), **gosec** (SAST), **gitleaks** (secret scan),
  generates a **CycloneDX SBOM**, and builds the dashboard on Node 20; Dependabot
  keeps deps current; runtime ships as a **distroless/non-root** image
  ([Dockerfile](Dockerfile)). *(ISO 27001 A.8.28 · SLSA)*
- **Governance** — [SECURITY.md](SECURITY.md) disclosure policy +
  `/.well-known/security.txt` (RFC 9116), a [threat model](docs/threat-model.md)
  and a [data-retention policy](docs/data-retention.md); findings carry a CVSS
  v3.1 vector string. *(ISO 27001 A.5.5/A.6.8/A.5.34)*

## Production mode (no mock data)

By default the platform runs in **development** mode: scanners fall back to
deterministic mock output when a tool is missing or a target is off-limits, so
the pipeline runs end-to-end on any laptop. Set `AMANKAN_ENV=production` to make
it **real**:

- **No fabricated data** — if a scanner cannot run for real (binary missing,
  target unauthorized, host unreachable) the scan job is marked **failed** with a
  clear reason; it is never silently recorded as a clean result.
- **Secure-by-default startup** — the API **refuses to boot** if production
  config is insecure: no API keys, wildcard CORS, `sslmode=disable`, default
  Neo4j password, no TLS, or no rate limit.
- **Real scanners** — install `nmap`, `nuclei` and `gitleaks` (repo secret
  scanning); set `AMANKAN_ALLOW_LIVE_SCAN=true`.
- **Authorization gate** — real scanning of non-RFC1918 targets requires
  `AMANKAN_SCAN_AUTHORIZED=true`, your explicit confirmation that you own / are
  permitted to test the registered targets. **Scanning hosts you do not control
  is illegal** — this flag exists so it cannot happen by accident.
- **Live threat intel** — `AMANKAN_THREATINTEL_FETCH=true` pulls the current
  CISA KEV + FIRST.org EPSS feeds at startup (or load files via `AMANKAN_KEV_FEED`
  / `AMANKAN_EPSS_FEED` for air-gapped deployments).

```bash
AMANKAN_ENV=production \
AMANKAN_API_KEYS="soc:$(openssl rand -hex 24):admin" \
AMANKAN_CORS_ORIGINS=https://soc.example \
AMANKAN_DATABASE_URL='postgres://…?sslmode=require' \
AMANKAN_TLS_CERT=/etc/tls/cert.pem AMANKAN_TLS_KEY=/etc/tls/key.pem \
AMANKAN_RATE_LIMIT=20 \
AMANKAN_ALLOW_LIVE_SCAN=true AMANKAN_SCAN_AUTHORIZED=true \
AMANKAN_THREATINTEL_FETCH=true \
./bin/api
```

### Deploying it

Turnkey artifacts ship in [deploy/](deploy/): a production
[docker-compose](deploy/docker-compose.prod.yml) (Postgres+TLS, Redis-auth,
Neo4j, **Keycloak**, API+worker), a [worker image](deploy/Dockerfile.worker) with
`nmap`/`nuclei`/`gitleaks` baked in, a TLS [cert script](scripts/gen-certs.sh),
a [Keycloak realm](deploy/keycloak/realm-amankan.json), and
[Kubernetes manifests](deploy/k8s/amankan.yaml) (probes, non-root, NetworkPolicy,
cert-manager Ingress). The full runbook — TLS, secrets/vault, backup/DR, SIEM log
shipping, go-live checklist — is in [docs/deployment.md](docs/deployment.md).

> Still yours to provide (infra/ops + governance, not code): the running
> cluster, CA-issued certificates, a secret vault, and the **written
> authorization** to scan each target.

## Layout

```
cmd/api        REST server (+ migrations on boot)
cmd/worker     scan job consumer
internal/
  config       env config
  db           pgx pool + embedded SQL migrations
  store        PostgreSQL persistence
  queue        Redis job queue
  scanner      nmap / nuclei / crypto adapters (real + mock)
  normalize    scanner output → internal Finding schema
  risk         CVSS × criticality × threat-intel scoring
  compliance   CWE → OWASP/ISO27001/BSSN/COBIT + remediation
  threatintel  CISA KEV + EPSS feeds (offline fallback)
  sla          severity-driven remediation deadlines + breach state
  auth         API-key authentication, RBAC, CORS, security headers, rate limit
  audit        tamper-evident hash-chained audit record
  graph        Neo4j projection + attack-path / lateral-movement queries
  engine       single-job orchestration
```

## Next steps (toward the full platform)
1. ~~Neo4j attack graph: network paths + privilege nodes (apoc Dijkstra) + auto-derived escalation **and** credential-reuse edges from scan findings~~ ✅ done — privilege layer is fully self-forming. Next: infer network `CAN_REACH` from a topology/CMDB feed so the network layer is automated too.
2. Replace the Redis list with RabbitMQ + Kubernetes Jobs for isolated, scalable scans.
3. ~~Front with auth + add the dashboard~~ ✅ done — API-key RBAC + Next.js dashboard. Next: upgrade to full Keycloak (OAuth2/OIDC) + SSO/MFA.
4. ~~Tamper-evident audit log~~ ✅ done (hash-chained). Next: ship signed logs to immutable storage / ELK and add TLS termination + external secret vault.
