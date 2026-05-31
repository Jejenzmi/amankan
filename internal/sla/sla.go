// Package sla derives remediation deadlines and breach state for findings,
// driven by severity. Time-bound remediation SLAs are a baseline expectation of
// mature vulnerability management (PCI DSS Req. 6/11, ISO 27001 A.8.8).
package sla

import (
	"time"

	"github.com/amankan/amankan/internal/models"
)

// Window is the time allowed to remediate a finding of a given severity,
// measured from when it was first observed. Tuned to common enterprise policy.
var Window = map[models.Severity]time.Duration{
	models.SevCritical: 7 * 24 * time.Hour,
	models.SevHigh:     30 * 24 * time.Hour,
	models.SevMedium:   90 * 24 * time.Hour,
	models.SevLow:      180 * 24 * time.Hour,
	models.SevInfo:     365 * 24 * time.Hour,
}

// DueDate returns the remediation deadline for a finding of severity sev first
// observed at createdAt.
func DueDate(sev models.Severity, createdAt time.Time) time.Time {
	w, ok := Window[sev]
	if !ok {
		w = Window[models.SevMedium]
	}
	return createdAt.Add(w)
}

// Breached reports whether an unresolved finding is past its remediation
// deadline as of now. Resolved findings (false-positive / remediated) never
// count as breached.
func Breached(status models.FindingStatus, sev models.Severity, createdAt, now time.Time) bool {
	if status == models.FindingFalsePositive || status == models.FindingRemediated {
		return false
	}
	return now.After(DueDate(sev, createdAt))
}

// DaysRemaining returns the (possibly negative) whole days until the deadline.
func DaysRemaining(sev models.Severity, createdAt, now time.Time) int {
	return int(DueDate(sev, createdAt).Sub(now).Hours() / 24)
}
