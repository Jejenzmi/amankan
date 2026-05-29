package scanner

import (
	"context"

	"github.com/amankan/amankan/internal/models"
)

// Secrets is a SAST-style adapter that detects hard-coded credentials in an
// asset's code/config. It is mock-only in the PoC (no standard CLI to shell out
// to that ships everywhere); a real deployment would wrap gitleaks/trufflehog.
//
// The mock reports an organization-wide service credential (svc-deploy) with a
// FIXED fingerprint, so the same secret surfaces on every scanned host — which
// is exactly the signal the graph engine uses to infer credential reuse.
type Secrets struct{ opts Options }

func NewSecrets(opts Options) *Secrets { return &Secrets{opts: opts} }

func (s *Secrets) Type() models.ScannerType { return models.ScannerSecrets }

func (s *Secrets) Scan(ctx context.Context, asset models.Asset) (RawResult, error) {
	return RawResult{
		Scanner: models.ScannerSecrets,
		Format:  "secrets-json",
		Mock:    true,
		Data: []byte(`{"credentials":[
		  {"principal":"svc-deploy","fingerprint":"sha256:9f86d0818884","type":"service_account","location":"/etc/app/deploy.yaml","secret":"AKIA****REDACTED"}
		]}`),
	}, nil
}
