// Package risk computes an actionable risk score from a finding's CVSS base
// score, the asset's business criticality, and threat-intelligence signal
// (is the vulnerability being actively exploited in the wild?).
package risk

import (
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/threatintel"
)

// criticalityWeight scales risk by business impact of the asset.
func criticalityWeight(c models.Criticality) float64 {
	switch c {
	case models.CritCritical:
		return 1.5
	case models.CritHigh:
		return 1.25
	case models.CritMedium:
		return 1.0
	case models.CritLow:
		return 0.75
	default:
		return 1.0
	}
}

// Score returns (risk_score in 0..10, knownExploit). The base CVSS is amplified
// by asset criticality and by a threat-intel factor, then clamped to 10.
func Score(cvss float64, cve string, crit models.Criticality) (float64, bool) {
	known := IsKnownExploited(cve)
	threat := 1.0
	if known {
		threat = 1.3
	}
	score := cvss * criticalityWeight(crit) * threat
	if score > 10 {
		score = 10
	}
	if score < 0 {
		score = 0
	}
	return round1(score), known
}

// IsKnownExploited reports whether any of the (possibly comma-joined) CVEs is in
// the threat-intel (CISA KEV) feed.
func IsKnownExploited(cve string) bool {
	return threatintel.IsKEV(cve)
}

// SeverityToCVSS provides a representative base score when a tool reports only a
// qualitative severity (e.g. nuclei "medium") without a numeric CVSS.
func SeverityToCVSS(sev models.Severity) float64 {
	switch sev {
	case models.SevCritical:
		return 9.5
	case models.SevHigh:
		return 7.5
	case models.SevMedium:
		return 5.0
	case models.SevLow:
		return 3.0
	default:
		return 1.0
	}
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

// cweVectors maps a weakness class to a representative CVSS v3.1 base vector.
// This gives every finding the standard vector notation expected by
// international tooling without each scanner having to emit one.
var cweVectors = map[string]string{
	"CWE-327":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", // weak crypto / TLS
	"CWE-502":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // unsafe deserialization (RCE)
	"CWE-798":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // hard-coded credentials
	"CWE-269":  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // privilege escalation
	"CWE-250":  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", // excessive privilege
	"CWE-538":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // sensitive file exposure
	"CWE-693":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // missing security headers
	"CWE-1327": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", // exposed service
}

// RepresentativeVector returns a CVSS v3.1 base vector for a finding's weakness
// class, or "" when none is known.
func RepresentativeVector(cwe string) string {
	return cweVectors[cwe]
}
