# Data Retention & Privacy (Phase 1)

Supports ISO/IEC 27001 A.5.34 (privacy & protection of PII) and A.8.10
(information deletion), and BSSN forensic-retention expectations.

## Data categories & retention

| Data | Store | Default retention | Notes |
| --- | --- | --- | --- |
| Assets | PostgreSQL `assets` | until deleted by operator | deleting an asset cascades to its scans/findings |
| Scan jobs | PostgreSQL `scan_jobs` | tied to the asset | operational record |
| Findings | PostgreSQL `findings` | tied to the asset | sensitive — describes exploitable weaknesses |
| Audit log | PostgreSQL `audit_log` | **append-only, retain ≥ 1 year** | hash-chained; never edited or deleted in place |
| Credentials/secrets | not stored | n/a | hard-coded-credential findings store a non-reversible fingerprint, never the secret |

## Principles
- **Data minimisation** — only fingerprints (not plaintext secrets) are persisted
  for credential findings (`CredFP`); transient scan-time fields are not stored.
- **Integrity over deletion for audit** — the audit trail is append-only and
  hash-chained; if records must be expired for storage, expire the *oldest
  contiguous prefix* and re-anchor, never delete from the middle (which would
  break the chain and is therefore detectable).
- **Right to erasure** — deleting an asset removes its scans and findings
  (FK `ON DELETE CASCADE`); audit entries about those actions are retained as
  the forensic record.

## Deferred (integration seams)
- Automated retention enforcement / scheduled purges.
- Off-host immutable (WORM) archival of the audit trail.
- Encryption at rest for the database.
