# Security Policy

Amankan is a security platform; we hold its own security to the same bar it
measures others against.

## Supported versions

This is a Phase 1 proof-of-concept. Security fixes are applied to `main` only.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for security problems.

- Email: **security@amankan.example** (replace with your team's address)
- Encrypt sensitive reports with our PGP key if one is published.
- Include: affected component/endpoint, reproduction steps, impact, and any PoC.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of report | within 3 business days |
| Initial assessment / severity | within 7 business days |
| Fix or mitigation plan | depends on severity (see remediation SLAs below) |

We follow coordinated disclosure: we ask for up to 90 days to remediate before
public disclosure, and we will credit reporters who wish to be named.

## Remediation SLAs

The platform applies the same severity-driven remediation windows it tracks for
findings (see `internal/sla`):

| Severity | Window |
| --- | --- |
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

## Scope

In scope: the API (`cmd/api`), worker (`cmd/worker`), the `internal/*` packages,
and the dashboard (`web/`). Out of scope: third-party dependencies (report
upstream; we track them via Dependabot + `govulncheck`) and the example
credentials/secrets in `.env.example` (these are placeholders).

## Hardening references

See the "Security & compliance hardening" section of the [README](README.md)
and [docs/threat-model.md](docs/threat-model.md).
