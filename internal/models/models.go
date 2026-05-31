// Package models defines Amankan's internal domain schema. Scanner output from
// heterogeneous tools (Nmap, Nuclei, ...) is normalized into these types so the
// rest of the platform reasons over one consistent shape.
package models

import "time"

// AssetType enumerates what kind of target an asset represents.
type AssetType string

const (
	AssetIP     AssetType = "ip"
	AssetDomain AssetType = "domain"
	AssetRepo   AssetType = "repo"
)

// Criticality reflects business impact and drives risk scoring weights.
type Criticality string

const (
	CritLow      Criticality = "low"
	CritMedium   Criticality = "medium"
	CritHigh     Criticality = "high"
	CritCritical Criticality = "critical"
)

// Asset is a registered target (the "Ingestion" step of the workflow).
type Asset struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        AssetType   `json:"type"`
	Target      string      `json:"target"` // IP, domain, or repo URL
	Criticality Criticality `json:"criticality"`
	Tags        []string    `json:"tags"`
	// ScanAuthorized records explicit permission to actively scan this target.
	// In production, real scanning requires this (or the global override).
	ScanAuthorized bool      `json:"scan_authorized"`
	CreatedAt      time.Time `json:"created_at"`
}

// ScanProfile is a named risk profile selecting which scanners run.
type ScanProfile string

const (
	ProfileQuick    ScanProfile = "quick"    // nmap top ports
	ProfileWeb      ScanProfile = "web"      // nuclei web templates
	ProfileCritical ScanProfile = "critical" // full: nmap + nuclei + crypto audit
)

// ScannerType identifies a single scanner adapter.
type ScannerType string

const (
	ScannerNmap    ScannerType = "nmap"
	ScannerNuclei  ScannerType = "nuclei"
	ScannerCrypto  ScannerType = "crypto"  // TLS/cipher audit (BSSN-ready)
	ScannerSecrets ScannerType = "secrets" // SAST-style hard-coded credential detection
)

// ScanStatus tracks lifecycle of an orchestrated scan job.
type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ScanJob is one orchestrated run against an asset.
type ScanJob struct {
	ID         string        `json:"id"`
	AssetID    string        `json:"asset_id"`
	Profile    ScanProfile   `json:"profile"`
	Scanners   []ScannerType `json:"scanners"`
	Status     ScanStatus    `json:"status"`
	Error      string        `json:"error,omitempty"`
	UsedMock   bool          `json:"used_mock"`
	CreatedAt  time.Time     `json:"created_at"`
	StartedAt  *time.Time    `json:"started_at,omitempty"`
	FinishedAt *time.Time    `json:"finished_at,omitempty"`
}

// Severity is the qualitative severity bucket.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// FindingStatus supports the zero-false-positive validation workflow.
type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"
	FindingValidated     FindingStatus = "validated"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingRemediated    FindingStatus = "remediated"
)

// Finding is a normalized vulnerability/observation produced by a scanner and
// enriched with risk score and compliance references.
type Finding struct {
	ID         string        `json:"id"`
	ScanJobID  string        `json:"scan_job_id"`
	AssetID    string        `json:"asset_id"`
	Scanner    ScannerType   `json:"scanner"`
	Title      string        `json:"title"`
	Desc       string        `json:"description"`
	Severity   Severity      `json:"severity"`
	CVSS       float64       `json:"cvss"`
	CVSSVector string        `json:"cvss_vector,omitempty"` // CVSS v3.1 vector (computed at read time)
	CVE        string        `json:"cve,omitempty"`
	CWE        string        `json:"cwe,omitempty"` // e.g. "CWE-327"
	Port       int           `json:"port,omitempty"`
	Service    string        `json:"service,omitempty"`
	Evidence   string        `json:"evidence,omitempty"`
	Status     FindingStatus `json:"status"`

	// Enrichment (computed at normalization time).
	RiskScore    float64           `json:"risk_score"`
	KnownExploit bool              `json:"known_exploit"`
	Compliance   []ComplianceRef   `json:"compliance,omitempty"`
	Remediation  *RemediationGuide `json:"remediation,omitempty"`

	// Runtime enrichment (computed at read time, not persisted): EPSS
	// exploitation probability and the severity-driven remediation SLA.
	EPSS        float64    `json:"epss,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	SLABreached bool       `json:"sla_breached"`
	SLADaysLeft int        `json:"sla_days_left"`

	// Transient scan-time metadata for credential findings (CWE-798). Populated
	// by the normalizer and consumed by the graph engine to infer credential
	// reuse; NOT persisted to PostgreSQL (only meaningful at scan time).
	Principal string `json:"principal,omitempty"`
	CredFP    string `json:"cred_fp,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// ComplianceRef maps a finding to a governance control.
type ComplianceRef struct {
	Framework string `json:"framework"` // OWASP, ISO27001, BSSN, COBIT
	Control   string `json:"control"`   // control id
	Title     string `json:"title"`
}

// RemediationGuide is the actionable output attached to a ticket.
type RemediationGuide struct {
	Summary string   `json:"summary"`
	Steps   []string `json:"steps"`
	Refs    []string `json:"refs,omitempty"`
}
