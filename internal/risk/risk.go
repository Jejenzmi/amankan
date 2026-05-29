// Package risk computes an actionable risk score from a finding's CVSS base
// score, the asset's business criticality, and threat-intelligence signal
// (is the vulnerability being actively exploited in the wild?).
package risk

import (
	"strings"

	"github.com/amankan/amankan/internal/models"
)

// knownExploited is a tiny stand-in for a CISA KEV / threat-intel feed. CVEs
// here get a threat multiplier because they are exploited in the wild.
var knownExploited = map[string]bool{
	"CVE-2021-44228": true, // Log4Shell
	"CVE-2017-0144":  true, // EternalBlue
	"CVE-2014-0160":  true, // Heartbleed
}

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
// the threat-intel feed.
func IsKnownExploited(cve string) bool {
	if cve == "" {
		return false
	}
	for _, c := range strings.Split(cve, ",") {
		if knownExploited[strings.TrimSpace(c)] {
			return true
		}
	}
	return false
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
