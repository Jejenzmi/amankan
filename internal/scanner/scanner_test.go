package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/amankan/amankan/internal/models"
)

var ipAsset = models.Asset{Type: models.AssetIP, Target: "203.0.113.10"} // public (TEST-NET-3)
var localAsset = models.Asset{Type: models.AssetIP, Target: "127.0.0.1"}

func TestLiveAllowed(t *testing.T) {
	pub := models.Asset{Target: "203.0.113.10"}
	local := models.Asset{Target: "127.0.0.1"}

	// not allowed at all when AllowLiveScan is off
	o := Options{AllowLiveScan: false, ScanAuthorized: true}
	if o.liveAllowed(local) {
		t.Error("liveAllowed must be false when AllowLiveScan is off")
	}
	// globally authorized → any target allowed
	o = Options{AllowLiveScan: true, ScanAuthorized: true}
	if !o.liveAllowed(pub) {
		t.Error("globally authorized operator should be allowed to scan a public target")
	}
	// not authorized → only loopback/RFC1918
	o = Options{AllowLiveScan: true, ScanAuthorized: false}
	if o.liveAllowed(pub) {
		t.Error("unauthorized public target must not be live-scanned")
	}
	if !o.liveAllowed(local) {
		t.Error("loopback should be allowed even without explicit authorization")
	}
	// per-asset authorization lifts the restriction for that asset only
	if !o.liveAllowed(models.Asset{Target: "203.0.113.10", ScanAuthorized: true}) {
		t.Error("per-asset authorized public target should be allowed")
	}
}

func TestProductionNoMockFailsLoud(t *testing.T) {
	// nmap binary intentionally missing + production → must error, never mock.
	n := NewNmap(Options{NmapBin: "definitely-not-a-real-binary-xyz", Production: true, AllowLiveScan: true, ScanAuthorized: true})
	if _, err := n.Scan(context.Background(), localAsset); err == nil {
		t.Error("production nmap with missing binary should error, not return mock")
	}

	// same in development → returns mock, no error.
	n = NewNmap(Options{NmapBin: "definitely-not-a-real-binary-xyz"})
	res, err := n.Scan(context.Background(), localAsset)
	if err != nil || !res.Mock {
		t.Errorf("development should fall back to mock: mock=%v err=%v", res.Mock, err)
	}
}

func TestSecretsOnlyScansRepos(t *testing.T) {
	s := NewSecrets(Options{Production: true})
	// ip asset → no findings, no error (secret scanning N/A)
	res, err := s.Scan(context.Background(), ipAsset)
	if err != nil {
		t.Fatalf("secrets on ip asset should not error: %v", err)
	}
	if !strings.Contains(string(res.Data), `"credentials":[]`) {
		t.Errorf("secrets on non-repo asset should be empty, got %s", res.Data)
	}

	// repo asset + missing gitleaks + production → error
	s = NewSecrets(Options{Production: true, GitleaksBin: "no-such-gitleaks-xyz"})
	repo := models.Asset{Type: models.AssetRepo, Target: "/tmp/repo"}
	if _, err := s.Scan(context.Background(), repo); err == nil {
		t.Error("production secrets with missing gitleaks should error")
	}
}

func TestConvertGitleaks(t *testing.T) {
	raw := []byte(`[{"RuleID":"aws-key","Description":"AWS Access Key","File":"cfg/app.yaml","StartLine":12,"Fingerprint":"abc:cfg/app.yaml:aws-key:12","Secret":"AKIAREAL"}]`)
	out := convertGitleaks(raw)
	s := string(out)
	if !strings.Contains(s, `"principal":"aws-key"`) || !strings.Contains(s, `"fingerprint":"abc:cfg/app.yaml:aws-key:12"`) {
		t.Errorf("gitleaks mapping wrong: %s", s)
	}
	// the plaintext secret must NEVER be carried through
	if strings.Contains(s, "AKIAREAL") {
		t.Error("plaintext secret leaked into converted output")
	}
}

func TestConvertGitleaksEmpty(t *testing.T) {
	if got := string(convertGitleaks(nil)); !strings.Contains(got, `"credentials":[]`) {
		t.Errorf("empty gitleaks output should yield empty credentials, got %s", got)
	}
}
