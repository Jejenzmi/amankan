// Package normalize converts heterogeneous scanner output into Amankan's
// internal Finding schema, then enriches each finding with a risk score and
// compliance references. This is the "Normalization Engine" of the design.
package normalize

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/amankan/amankan/internal/compliance"
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/risk"
	"github.com/amankan/amankan/internal/scanner"
)

// Normalize parses one raw scanner result into enriched findings.
func Normalize(raw scanner.RawResult, asset models.Asset, scanJobID string) ([]models.Finding, error) {
	var findings []models.Finding
	var err error
	switch raw.Format {
	case "nmap-xml":
		findings, err = parseNmap(raw.Data, asset)
	case "nuclei-jsonl":
		findings, err = parseNuclei(raw.Data, asset)
	case "crypto-json":
		findings, err = parseCrypto(raw.Data, asset)
	case "secrets-json":
		findings, err = parseSecrets(raw.Data, asset)
	default:
		return nil, fmt.Errorf("unknown format %q", raw.Format)
	}
	if err != nil {
		return nil, err
	}
	for i := range findings {
		enrich(&findings[i], asset, scanJobID, raw.Scanner)
	}
	return findings, nil
}

// enrich fills scan/asset linkage, risk score, and compliance/remediation.
func enrich(f *models.Finding, asset models.Asset, scanJobID string, sc models.ScannerType) {
	f.ScanJobID = scanJobID
	f.AssetID = asset.ID
	f.Scanner = sc
	f.Status = models.FindingOpen
	if f.CVSS == 0 {
		f.CVSS = risk.SeverityToCVSS(f.Severity)
	}
	score, known := risk.Score(f.CVSS, f.CVE, asset.Criticality)
	f.RiskScore = score
	f.KnownExploit = known
	if f.CWE != "" {
		f.Compliance = compliance.Refs(f.CWE)
		rem := compliance.Remediation(f.CWE)
		f.Remediation = &rem
	}
}

// ---- nmap ----

type nmapRun struct {
	Hosts []struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Tunnel  string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// sensitiveServices map open ports that warrant a finding to a base CVSS.
var sensitiveServices = map[string]float64{
	"ssh": 4.0, "mysql": 6.5, "mssql": 6.5, "postgresql": 6.0,
	"redis": 7.0, "mongodb": 7.0, "telnet": 8.0, "ftp": 5.5, "rdp": 7.5,
}

func parseNmap(data []byte, asset models.Asset) ([]models.Finding, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	var out []models.Finding
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			svc := strings.ToLower(p.Service.Name)
			cvss, sensitive := sensitiveServices[svc]
			sev := models.SevInfo
			if sensitive {
				sev = severityFromCVSS(cvss)
			}
			f := models.Finding{
				Title:    fmt.Sprintf("Open port %d/%s (%s)", p.PortID, p.Protocol, svc),
				Desc:     fmt.Sprintf("Service %s %s exposed on port %d", p.Service.Product, p.Service.Version, p.PortID),
				Severity: sev,
				CVSS:     cvss,
				CWE:      "CWE-1327", // exposed/unrestricted service binding
				Port:     p.PortID,
				Service:  svc,
				Evidence: fmt.Sprintf("%s %s on %d/%s", p.Service.Product, p.Service.Version, p.PortID, p.Protocol),
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// ---- nuclei ----

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CVE []string `json:"cve-id"`
			CWE []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
}

func parseNuclei(data []byte, asset models.Asset) ([]models.Finding, error) {
	var out []models.Finding
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var n nucleiLine
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			continue // skip malformed lines, real nuclei can interleave noise
		}
		cwe := ""
		if len(n.Info.Classification.CWE) > 0 {
			cwe = n.Info.Classification.CWE[0]
		}
		f := models.Finding{
			Title:    n.Info.Name,
			Desc:     fmt.Sprintf("Template %s matched at %s", n.TemplateID, n.MatchedAt),
			Severity: parseSeverity(n.Info.Severity),
			CVE:      strings.Join(n.Info.Classification.CVE, ","),
			CWE:      cwe,
			Evidence: n.MatchedAt,
		}
		out = append(out, f)
	}
	return out, nil
}

// ---- crypto ----

type cryptoReport struct {
	Target     string `json:"target"`
	TLSVersion string `json:"tls_version"`
	WeakTLS    bool   `json:"weak_tls"`
	WeakRSA    bool   `json:"weak_rsa"`
	Note       string `json:"note"`
}

func parseCrypto(data []byte, asset models.Asset) ([]models.Finding, error) {
	var rep cryptoReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse crypto report: %w", err)
	}
	var out []models.Finding
	if rep.WeakTLS {
		out = append(out, models.Finding{
			Title:    fmt.Sprintf("Weak TLS protocol version (TLS %s)", rep.TLSVersion),
			Desc:     "Endpoint negotiates TLS < 1.2, below BSSN/NIST minimums. " + rep.Note,
			Severity: models.SevHigh,
			CVSS:     7.4,
			CWE:      "CWE-327",
			Service:  "https",
			Port:     443,
			Evidence: rep.Note,
		})
	}
	if rep.WeakRSA {
		out = append(out, models.Finding{
			Title:    "Weak RSA key length (< 2048-bit)",
			Desc:     "Certificate uses an RSA key below the 2048-bit national crypto standard.",
			Severity: models.SevMedium,
			CVSS:     5.9,
			CWE:      "CWE-327",
			Service:  "https",
			Port:     443,
			Evidence: rep.Note,
		})
	}
	return out, nil
}

// ---- secrets (SAST hard-coded credentials) ----

type secretsReport struct {
	Credentials []struct {
		Principal   string `json:"principal"`
		Fingerprint string `json:"fingerprint"`
		Type        string `json:"type"`
		Location    string `json:"location"`
	} `json:"credentials"`
}

func parseSecrets(data []byte, asset models.Asset) ([]models.Finding, error) {
	var rep secretsReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse secrets report: %w", err)
	}
	var out []models.Finding
	for _, c := range rep.Credentials {
		out = append(out, models.Finding{
			Title:    fmt.Sprintf("Hard-coded credential for %q", c.Principal),
			Desc:     fmt.Sprintf("%s credential found at %s (fingerprint %s)", c.Type, c.Location, c.Fingerprint),
			Severity: models.SevHigh,
			CVSS:     8.2,
			CWE:      "CWE-798",
			Evidence: c.Location,
			// Transient: drives credential-reuse inference in the graph engine.
			Principal: c.Principal,
			CredFP:    c.Fingerprint,
		})
	}
	return out, nil
}

// ---- helpers ----

func parseSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SevCritical
	case "high":
		return models.SevHigh
	case "medium":
		return models.SevMedium
	case "low":
		return models.SevLow
	default:
		return models.SevInfo
	}
}

func severityFromCVSS(cvss float64) models.Severity {
	switch {
	case cvss >= 9.0:
		return models.SevCritical
	case cvss >= 7.0:
		return models.SevHigh
	case cvss >= 4.0:
		return models.SevMedium
	case cvss > 0:
		return models.SevLow
	default:
		return models.SevInfo
	}
}
