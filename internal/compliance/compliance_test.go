package compliance

import (
	"strings"
	"testing"
)

// wantFrameworks is the fixed set of governance frameworks every finding maps to.
var wantFrameworks = []string{"OWASP-Top10", "OWASP-ASVS", "ISO27001", "BSSN", "COBIT2019"}

func TestRefsAlwaysCoversAllFrameworks(t *testing.T) {
	// Both a catalogued CWE and an unknown one must yield the full framework set.
	for _, cwe := range []string{"CWE-327", "CWE-798", "CWE-DOES-NOT-EXIST"} {
		refs := Refs(cwe)
		if len(refs) != len(wantFrameworks) {
			t.Fatalf("Refs(%q) returned %d refs, want %d", cwe, len(refs), len(wantFrameworks))
		}
		got := map[string]string{}
		for _, r := range refs {
			got[r.Framework] = r.Control
		}
		for _, fw := range wantFrameworks {
			ctrl, ok := got[fw]
			if !ok {
				t.Errorf("Refs(%q) missing framework %q", cwe, fw)
			}
			if strings.TrimSpace(ctrl) == "" {
				t.Errorf("Refs(%q) framework %q has empty control", cwe, fw)
			}
		}
	}
}

func TestRefsKnownMapping(t *testing.T) {
	refs := Refs("CWE-327") // broken crypto
	var owasp string
	for _, r := range refs {
		if r.Framework == "OWASP-Top10" {
			owasp = r.Control
		}
	}
	if !strings.Contains(owasp, "Cryptographic Failures") {
		t.Errorf("CWE-327 OWASP control = %q, want it to mention Cryptographic Failures", owasp)
	}
}

func TestRefsUnknownFallsBackToDefault(t *testing.T) {
	refs := Refs("CWE-NOPE")
	for _, r := range refs {
		if r.Framework == "OWASP-Top10" && !strings.Contains(r.Control, "A06:2021") {
			t.Errorf("unknown CWE should fall back to default OWASP A06, got %q", r.Control)
		}
	}
}

func TestRemediation(t *testing.T) {
	rem := Remediation("CWE-798") // hard-coded credentials
	if rem.Summary == "" || len(rem.Steps) == 0 {
		t.Fatalf("CWE-798 remediation incomplete: %+v", rem)
	}
	if !strings.Contains(strings.ToLower(rem.Summary), "credential") {
		t.Errorf("CWE-798 summary = %q, want it to mention credentials", rem.Summary)
	}

	// Unknown CWE still returns a usable baseline playbook.
	def := Remediation("CWE-NOPE")
	if def.Summary == "" || len(def.Steps) == 0 {
		t.Errorf("default remediation must not be empty: %+v", def)
	}
}

func TestIsPrivEsc(t *testing.T) {
	for _, cwe := range []string{"CWE-269", "CWE-250", "CWE-732"} {
		if !IsPrivEsc(cwe) {
			t.Errorf("IsPrivEsc(%q) = false, want true", cwe)
		}
	}
	for _, cwe := range []string{"CWE-327", "CWE-798", ""} {
		if IsPrivEsc(cwe) {
			t.Errorf("IsPrivEsc(%q) = true, want false", cwe)
		}
	}
}

func TestIsCredentialLeak(t *testing.T) {
	for _, cwe := range []string{"CWE-798", "CWE-259", "CWE-522"} {
		if !IsCredentialLeak(cwe) {
			t.Errorf("IsCredentialLeak(%q) = false, want true", cwe)
		}
	}
	for _, cwe := range []string{"CWE-269", "CWE-327", ""} {
		if IsCredentialLeak(cwe) {
			t.Errorf("IsCredentialLeak(%q) = true, want false", cwe)
		}
	}
}

func TestCatalogCWEsNonEmpty(t *testing.T) {
	cwes := CatalogCWEs()
	if len(cwes) == 0 {
		t.Fatal("CatalogCWEs() returned empty")
	}
	// every catalogued CWE must resolve to a complete remediation playbook
	for _, cwe := range cwes {
		if Remediation(cwe).Summary == "" {
			t.Errorf("catalog CWE %q has empty remediation summary", cwe)
		}
	}
}
