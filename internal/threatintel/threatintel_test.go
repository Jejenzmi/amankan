package threatintel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultKEV(t *testing.T) {
	f := &Feed{kev: copyBoolMap(defaultKEV), epss: map[string]float64{}}
	if !f.IsKEV("CVE-2021-44228") {
		t.Error("Log4Shell should be in default KEV")
	}
	if !f.IsKEV("CVE-2099-0000,CVE-2021-4034") {
		t.Error("comma-joined with one KEV should be true")
	}
	if f.IsKEV("CVE-2099-0000") {
		t.Error("unknown CVE should not be KEV")
	}
	if f.IsKEV("") {
		t.Error("empty CVE is not KEV")
	}
}

func TestEPSSDefaultZero(t *testing.T) {
	f := &Feed{kev: map[string]bool{}, epss: map[string]float64{}}
	if f.EPSS("CVE-2021-44228") != 0 {
		t.Error("EPSS with no feed loaded should be 0")
	}
}

func TestLoadFeeds(t *testing.T) {
	dir := t.TempDir()
	kevPath := filepath.Join(dir, "kev.json")
	epssPath := filepath.Join(dir, "epss.csv")

	kevJSON := `{"vulnerabilities":[{"cveID":"CVE-2030-1111"},{"cveID":"CVE-2030-2222"}]}`
	if err := os.WriteFile(kevPath, []byte(kevJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	epssCSV := "#model_version:v2025\ncve,epss,percentile\nCVE-2030-1111,0.97500,0.99\nCVE-2030-3333,0.01000,0.20\n"
	if err := os.WriteFile(epssPath, []byte(epssCSV), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &Feed{kev: map[string]bool{}, epss: map[string]float64{}}
	kevN, epssN, err := f.Load(kevPath, epssPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// default fallback set is merged in, plus the 2 loaded ids
	if !f.IsKEV("CVE-2030-1111") || !f.IsKEV("CVE-2030-2222") {
		t.Error("loaded KEV ids should be present")
	}
	if !f.IsKEV("CVE-2021-44228") {
		t.Error("default fallback KEV should remain after load")
	}
	if kevN < 2 {
		t.Errorf("kevN=%d, want >=2", kevN)
	}
	if epssN != 2 {
		t.Errorf("epssN=%d, want 2", epssN)
	}
	if got := f.EPSS("CVE-2030-1111"); got != 0.975 {
		t.Errorf("EPSS=%v, want 0.975", got)
	}
	if f.EPSS("CVE-2030-9999") != 0 {
		t.Error("unknown EPSS should be 0")
	}
}
