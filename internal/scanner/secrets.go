package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/amankan/amankan/internal/models"
)

// Secrets detects hard-coded credentials in a repo asset's source tree by
// wrapping gitleaks (https://github.com/gitleaks/gitleaks). In production it
// runs the real tool against the repo path; in development, when gitleaks is
// absent, it falls back to deterministic mock output.
//
// Only repo-type assets are scanned for secrets; for ip/domain assets the
// adapter is a no-op (returns no findings).
type Secrets struct{ opts Options }

func NewSecrets(opts Options) *Secrets { return &Secrets{opts: opts} }

func (s *Secrets) Type() models.ScannerType { return models.ScannerSecrets }

func (s *Secrets) Scan(ctx context.Context, asset models.Asset) (RawResult, error) {
	res := RawResult{Scanner: models.ScannerSecrets, Format: "secrets-json"}

	// Secret scanning only applies to source repositories.
	if asset.Type != models.AssetRepo {
		res.Data = []byte(`{"credentials":[]}`)
		return res, nil
	}

	binName := s.opts.GitleaksBin
	if binName == "" {
		binName = "gitleaks"
	}
	bin, err := exec.LookPath(binName)
	if err != nil {
		return s.opts.fallback(res, mockSecretsJSON(), "gitleaks binary not found")
	}

	// gitleaks detect over the repo path; JSON report to stdout. Exit code 1
	// means leaks were found (expected), other non-zero codes are real errors.
	cmd := exec.CommandContext(ctx, bin, "detect",
		"--source", asset.Target,
		"--no-banner", "--exit-code", "1",
		"--report-format", "json", "--report-path", "/dev/stdout")
	out, runErr := cmd.Output()
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) || ee.ExitCode() != 1 {
			if s.opts.Production {
				return RawResult{}, fmt.Errorf("gitleaks: scan of %q failed: %w", asset.Target, runErr)
			}
			return s.opts.fallback(res, mockSecretsJSON(), "gitleaks run failed")
		}
		// exit code 1 → leaks found; `out` holds the JSON report.
	}

	res.Data = convertGitleaks(out)
	return res, nil
}

// gitleaksFinding is the subset of gitleaks' JSON report we consume. The plaintext
// Secret is intentionally NOT retained — only gitleaks' non-reversible
// Fingerprint, which is what the graph engine needs to correlate reuse.
type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Fingerprint string `json:"Fingerprint"`
}

// convertGitleaks maps gitleaks' report to the internal "secrets-json" schema
// that normalize.parseSecrets consumes.
func convertGitleaks(raw []byte) []byte {
	var findings []gitleaksFinding
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &findings) // tolerate empty / non-array output
	}
	type cred struct {
		Principal   string `json:"principal"`
		Fingerprint string `json:"fingerprint"`
		Type        string `json:"type"`
		Location    string `json:"location"`
	}
	out := struct {
		Credentials []cred `json:"credentials"`
	}{Credentials: []cred{}}
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = fmt.Sprintf("%s:%s:%d", f.RuleID, f.File, f.StartLine)
		}
		out.Credentials = append(out.Credentials, cred{
			Principal:   f.RuleID,
			Fingerprint: fp,
			Type:        f.Description,
			Location:    fmt.Sprintf("%s:%d", f.File, f.StartLine),
		})
	}
	data, _ := json.Marshal(out)
	return data
}

// mockSecretsJSON is development-only fallback output: an organization-wide
// service credential with a fixed fingerprint, so the same secret surfaces on
// every scanned host — the signal the graph engine uses to infer credential reuse.
func mockSecretsJSON() []byte {
	return []byte(`{"credentials":[
	  {"principal":"svc-deploy","fingerprint":"sha256:9f86d0818884","type":"service_account","location":"/etc/app/deploy.yaml"}
	]}`)
}
