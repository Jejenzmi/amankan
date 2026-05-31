# Deployment & Operations Runbook

Covers the production deployment of Amankan (Layer 2 infrastructure) and the
operational controls expected of an international-standard security platform.

> Layer 3 (legal authorization to scan) is enforced in-app via per-asset
> authorization (`POST /api/v1/assets/{id}/authorize`) and the global
> `AMANKAN_SCAN_AUTHORIZED` flag. You remain responsible for holding written
> authorization for every target you scan.

## 1. Single host (Docker Compose)

```bash
./scripts/gen-certs.sh                          # TLS certs → deploy/certs/
sudo chown 999:999 deploy/certs/server.key deploy/certs/server.crt   # postgres uid
cp deploy/.env.prod.example deploy/.env.prod && $EDITOR deploy/.env.prod
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod up -d --build
```

Brings up: Postgres (TLS), Redis (auth), Neo4j, Keycloak, the API (HTTPS,
production mode), and the worker (with `nmap`/`nuclei`/`gitleaks` baked in).

## 2. Kubernetes

```bash
# build & push images
docker build -t ghcr.io/your-org/amankan-api:1.0.0 -f Dockerfile .
docker build -t ghcr.io/your-org/amankan-worker:1.0.0 -f deploy/Dockerfile.worker .
docker push ghcr.io/your-org/amankan-api:1.0.0
docker push ghcr.io/your-org/amankan-worker:1.0.0

# edit image refs + secrets, then:
kubectl apply -f deploy/k8s/amankan.yaml
```

The manifests include readiness/liveness probes (`/readyz`, `/healthz`),
non-root + read-only-rootfs security contexts, a default-deny NetworkPolicy, and
a cert-manager-annotated Ingress. **Isolate scanner workers** on a dedicated node
pool / egress policy so active scans cannot reach the control plane.

## 3. Identity (Keycloak / OIDC)

1. Keycloak imports `deploy/keycloak/realm-amankan.json` (realm `amankan`, roles
   `amankan-viewer|analyst|admin`, client `amankan-dashboard`).
2. Set `AMANKAN_OIDC_ISSUER=https://<keycloak>/realms/amankan` and
   `AMANKAN_OIDC_AUDIENCE=amankan-api` on the API — JWT bearer auth then replaces
   API keys. Enable MFA / SSO in Keycloak per your policy.
3. The dashboard obtains a token (Authorization Code + PKCE) and sends it as
   `Authorization: Bearer …`; roles map to Amankan RBAC automatically.

## 4. TLS everywhere

- **API**: `AMANKAN_TLS_CERT/KEY` (or terminate at the Ingress/proxy).
- **PostgreSQL**: `sslmode=require` in `AMANKAN_DATABASE_URL` (compose enables
  `ssl=on`). Use a CA-signed server cert in production.
- **Redis/Neo4j**: enable TLS per vendor docs; keep them on a private network.
- Replace the self-signed `gen-certs.sh` output with CA / cert-manager certs.

## 5. Secrets management

Compose/K8s read secrets from env / Kubernetes Secrets. For production, source
them from a vault (HashiCorp Vault, cloud KMS, or the External Secrets Operator)
— never bake secrets into images or commit `.env.prod`.

## 6. Backup & DR

- **PostgreSQL** (system of record incl. the audit log): nightly `pg_dump` plus
  continuous WAL archiving / PITR. Test restores quarterly.
  ```bash
  kubectl exec -n amankan postgres-0 -- pg_dump -U amankan amankan | gzip > amankan-$(date +%F).sql.gz
  ```
- **Neo4j**: `neo4j-admin database dump` on a schedule (graph is re-derivable
  from Postgres via `POST /graph/sync`, so it is recoverable even without a dump).
- **Audit integrity after restore**: run `GET /api/v1/audit/verify` — it must
  report `intact: true`.

## 7. Logging → SIEM

The API emits **structured JSON logs** to stdout (one object per request:
method, path, status, actor, latency). Ship them to your SIEM:

- Kubernetes: a Fluent Bit / Vector DaemonSet tails container stdout → Loki / ELK
  / Splunk.
- Forward the **audit trail** (`GET /api/v1/audit`) to immutable (WORM) storage
  for BSSN forensic retention; alert on `audit/verify` returning `intact: false`.
- Scrape `/metrics` (Prometheus) for request rate, error ratio, in-flight.

## 8. Pre-go-live checklist

- [ ] `AMANKAN_ENV=production` (boot fails on insecure config)
- [ ] OIDC issuer set (or strong, rotated API keys) + MFA enforced
- [ ] TLS on API, DB (`sslmode=require`), and ingress
- [ ] Strong, vaulted secrets (DB / Redis / Neo4j / Keycloak admin)
- [ ] CORS restricted to the real dashboard origin; rate limit set
- [ ] Per-asset authorization reviewed; `SCAN_AUTHORIZED=false` globally
- [ ] Backups scheduled + a restore tested; audit chain verified post-restore
- [ ] Logs + metrics flowing to SIEM/Prometheus; alerts wired
- [ ] CI green: tests, `govulncheck`, `gosec`, `gitleaks`, SBOM published
- [ ] Written authorization on file for every scan target (Layer 3)
