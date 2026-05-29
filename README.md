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
| Scanner integration | `nmap` (real), `nuclei` (real), TLS crypto audit — each with a safe **mock fallback** |
| Normalization Engine | `internal/normalize` → one internal `Finding` schema |
| Prioritization | `internal/risk`: CVSS × asset criticality × threat-intel (KEV-style) |
| Compliance Policy Engine | `internal/compliance`: CWE → OWASP Top10/ASVS → ISO 27001 → BSSN/Indeks KAMI → COBIT |
| Remediation | Actionable steps + compliance references attached per finding |
| Primary DB | PostgreSQL (transactional data) |

### Not in Phase 1 (integration seams)
Neo4j attack-path graph, Kubernetes Jobs, Keycloak OAuth2, RabbitMQ, ELK,
immutable/signed logs, automated patch testing, Next.js dashboard.

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
| `POST` | `/api/v1/assets` | register an asset (ingestion) |
| `GET` | `/api/v1/assets` / `/assets/{id}` | list / get assets |
| `POST` | `/api/v1/assets/{id}/scans` | orchestrate a scan (`profile`: `quick`\|`web`\|`critical`) |
| `GET` | `/api/v1/scans` / `/scans/{id}` | list / get scan jobs |
| `GET` | `/api/v1/findings?asset_id=&scan_id=` | findings, sorted by risk score |
| `PATCH` | `/api/v1/findings/{id}/status` | validate / mark false-positive / remediated |
| `GET` | `/api/v1/compliance/cwe/{cwe}` | governance mapping + remediation for a CWE |

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
  engine       single-job orchestration
```

## Next steps (toward the full platform)
1. Add Neo4j to model assets/vulns/privileges and compute **attack paths** (lateral movement).
2. Replace the Redis list with RabbitMQ + Kubernetes Jobs for isolated, scalable scans.
3. Front with Keycloak (OAuth2/OIDC) and add the Next.js + Ant Design Pro dashboard.
4. Sign + ship logs to immutable storage (BSSN forensic retention) and ELK.
```
