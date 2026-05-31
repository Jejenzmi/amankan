package risk

import (
	"testing"

	"github.com/amankan/amankan/internal/models"
)

func TestScore(t *testing.T) {
	tests := []struct {
		name      string
		cvss      float64
		cve       string
		crit      models.Criticality
		wantScore float64
		wantKnown bool
	}{
		{"medium asset is neutral weight", 5.0, "", models.CritMedium, 5.0, false},
		{"high asset amplifies", 7.5, "", models.CritHigh, 9.4, false},                              // 7.5*1.25=9.375 -> 9.4
		{"low asset dampens", 8.0, "", models.CritLow, 6.0, false},                                  // 8.0*0.75=6.0
		{"known-exploited adds threat factor", 5.0, "CVE-2021-44228", models.CritMedium, 6.5, true}, // 5*1.3
		{"clamped to 10", 10.0, "CVE-2021-44228", models.CritCritical, 10.0, true},                  // 10*1.5*1.3=19.5 -> 10
		{"unknown criticality is neutral", 4.0, "", models.Criticality("weird"), 4.0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := Score(tt.cvss, tt.cve, tt.crit)
			if got != tt.wantScore {
				t.Errorf("Score()=%v, want %v", got, tt.wantScore)
			}
			if known != tt.wantKnown {
				t.Errorf("known=%v, want %v", known, tt.wantKnown)
			}
		})
	}
}

func TestScoreNeverExceedsBounds(t *testing.T) {
	for _, c := range []models.Criticality{models.CritLow, models.CritMedium, models.CritHigh, models.CritCritical} {
		for cvss := 0.0; cvss <= 10.0; cvss += 0.5 {
			got, _ := Score(cvss, "CVE-2021-44228", c)
			if got < 0 || got > 10 {
				t.Errorf("Score(%v,%v) = %v out of [0,10]", cvss, c, got)
			}
		}
	}
}

func TestIsKnownExploited(t *testing.T) {
	tests := []struct {
		cve  string
		want bool
	}{
		{"CVE-2021-44228", true},
		{"CVE-2021-4034", true},
		{"CVE-2099-0000", false},
		{"", false},
		{"CVE-2099-0000, CVE-2014-0160", true}, // comma-joined, whitespace, one is KEV
		{"CVE-2099-0000,CVE-2099-0001", false},
	}
	for _, tt := range tests {
		if got := IsKnownExploited(tt.cve); got != tt.want {
			t.Errorf("IsKnownExploited(%q)=%v, want %v", tt.cve, got, tt.want)
		}
	}
}

func TestSeverityToCVSS(t *testing.T) {
	tests := []struct {
		sev  models.Severity
		want float64
	}{
		{models.SevCritical, 9.5},
		{models.SevHigh, 7.5},
		{models.SevMedium, 5.0},
		{models.SevLow, 3.0},
		{models.SevInfo, 1.0},
		{models.Severity("unknown"), 1.0},
	}
	for _, tt := range tests {
		if got := SeverityToCVSS(tt.sev); got != tt.want {
			t.Errorf("SeverityToCVSS(%q)=%v, want %v", tt.sev, got, tt.want)
		}
	}
}
