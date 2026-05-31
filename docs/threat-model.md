# Amankan — Threat Model (Phase 1)

A lightweight STRIDE-oriented threat model for the PoC. It records the assets,
trust boundaries, threats and the controls already implemented (✅) or deferred
to an integration seam (▢).

## Assets to protect
- Vulnerability findings & attack-path data (sensitive: reveals how to breach assets)
- The audit trail (must be tamper-evident for forensic value)
- API credentials / scanner targets
- The scanning capability itself (must not become an attack tool against third parties)

## Trust boundaries
1. Browser (dashboard) → API — untrusted client over the network
2. API → PostgreSQL / Redis / Neo4j — backend data stores
3. Worker → scan targets — outbound, potentially dangerous actions

## STRIDE

| Threat | Vector | Control |
| --- | --- | --- |
| **Spoofing** | Unauthenticated API access | ✅ API-key auth + RBAC (`internal/auth`); constant-time key compare |
| **Tampering** | Altering audit history | ✅ SHA-256 hash-chained audit log + `/audit/verify` |
| **Tampering** | Oversized/malicious payloads | ✅ 1 MiB body cap; `DisallowUnknownFields` JSON decoding |
| **Repudiation** | "I didn't run that scan" | ✅ Every mutation audited with actor, action, status |
| **Information disclosure** | Cross-origin data theft | ✅ CORS allow-list (no wildcard); security headers |
| **Information disclosure** | Secrets in transit | ✅ optional TLS (`AMANKAN_TLS_*`); ▢ TLS to DB/Redis (`sslmode`), secret vault |
| **Denial of service** | Request floods / unbounded lists | ✅ per-IP rate limit; paginated list endpoints; request timeout |
| **Elevation of privilege** | Viewer performing admin actions | ✅ Per-route role enforcement (viewer < analyst < admin) |
| **Abuse of capability** | Scanning unauthorised targets | ✅ live scanning off by default; only loopback/RFC1918 scanned for real |

## Residual risk / deferred (integration seams)
- ▢ Identity: API keys are a stand-in for full OAuth2/OIDC (Keycloak) + MFA/SSO.
- ▢ Secrets management: env vars instead of a vault/KMS.
- ▢ At-rest encryption and TLS on PostgreSQL/Neo4j/Redis.
- ▢ Network isolation of scanners (Kubernetes Jobs + network policies).
- ▢ Immutable/off-host log shipping (WORM/SIEM) for the audit trail.

## Supply chain
✅ `govulncheck` (dependency CVEs), `gosec` (SAST), `gitleaks` (secret scan),
Dependabot, and a CycloneDX SBOM run in CI; runtime image is distroless/nonroot.
