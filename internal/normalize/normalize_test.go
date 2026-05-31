package normalize

import (
	"testing"

	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/scanner"
)

var testAsset = models.Asset{
	ID:          "asset-1",
	Name:        "db-core",
	Type:        models.AssetIP,
	Target:      "10.0.1.5",
	Criticality: models.CritCritical,
}

func raw(format string, data string) scanner.RawResult {
	return scanner.RawResult{Format: format, Data: []byte(data)}
}

func TestNormalizeUnknownFormat(t *testing.T) {
	if _, err := Normalize(raw("bogus", "{}"), testAsset, "job-1"); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

func TestNormalizeEnrichesEveryFinding(t *testing.T) {
	const nmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	findings, err := Normalize(raw("nmap-xml", nmapXML), testAsset, "job-1")
	if err != nil {
		t.Fatalf("Normalize nmap: %v", err)
	}
	// closed port is skipped → 2 findings
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (closed port must be skipped)", len(findings))
	}
	for _, f := range findings {
		if f.ScanJobID != "job-1" || f.AssetID != testAsset.ID {
			t.Errorf("finding not linked to scan/asset: %+v", f)
		}
		if f.Scanner == "" {
			// Scanner comes from raw.Scanner which is empty in this test, acceptable.
		}
		if f.Status != models.FindingOpen {
			t.Errorf("new finding status = %q, want open", f.Status)
		}
		if f.CWE != "CWE-1327" {
			t.Errorf("open-port CWE = %q, want CWE-1327", f.CWE)
		}
		if f.RiskScore <= 0 {
			t.Errorf("finding %q has no risk score", f.Title)
		}
		if len(f.Compliance) == 0 || f.Remediation == nil {
			t.Errorf("finding %q not enriched with compliance/remediation", f.Title)
		}
	}
}

func TestNormalizeCryptoWeakTLS(t *testing.T) {
	const cryptoJSON = `{"target":"10.0.1.5","tls_version":"1.0","weak_tls":true,"weak_rsa":true,"note":"negotiated TLS 1.0"}`
	findings, err := Normalize(raw("crypto-json", cryptoJSON), testAsset, "job-1")
	if err != nil {
		t.Fatalf("Normalize crypto: %v", err)
	}
	if len(findings) != 2 { // weak TLS + weak RSA
		t.Fatalf("got %d crypto findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.CWE != "CWE-327" {
			t.Errorf("crypto finding CWE = %q, want CWE-327", f.CWE)
		}
	}
}

func TestNormalizeSecretsPreservesCredentialMetadata(t *testing.T) {
	const secretsJSON = `{"credentials":[{"principal":"svc-deploy","fingerprint":"abc123","type":"api-key","location":"config/app.yaml"}]}`
	findings, err := Normalize(raw("secrets-json", secretsJSON), testAsset, "job-1")
	if err != nil {
		t.Fatalf("Normalize secrets: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d secret findings, want 1", len(findings))
	}
	f := findings[0]
	if f.CWE != "CWE-798" {
		t.Errorf("secret CWE = %q, want CWE-798", f.CWE)
	}
	// The transient fields drive credential-reuse inference in the graph engine.
	if f.Principal != "svc-deploy" || f.CredFP != "abc123" {
		t.Errorf("credential metadata lost: principal=%q fp=%q", f.Principal, f.CredFP)
	}
}

func TestNormalizeNucleiKnownExploitRaisesRisk(t *testing.T) {
	// Log4Shell: known-exploited CVE on a critical asset → max risk + KEV flag.
	const nucleiJSONL = `{"template-id":"log4shell","matched-at":"10.0.1.5:8080","info":{"name":"Apache Log4j RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]}}}`
	findings, err := Normalize(raw("nuclei-jsonl", nucleiJSONL), testAsset, "job-1")
	if err != nil {
		t.Fatalf("Normalize nuclei: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d nuclei findings, want 1", len(findings))
	}
	f := findings[0]
	if !f.KnownExploit {
		t.Error("Log4Shell finding should be flagged KnownExploit")
	}
	if f.RiskScore != 10 {
		t.Errorf("Log4Shell on critical asset risk = %v, want 10 (clamped)", f.RiskScore)
	}
	if f.CVE != "CVE-2021-44228" || f.CWE != "CWE-502" {
		t.Errorf("nuclei classification lost: cve=%q cwe=%q", f.CVE, f.CWE)
	}
}

func TestNormalizeNucleiSkipsMalformedLines(t *testing.T) {
	const data = "not-json\n{\"template-id\":\"t\",\"info\":{\"name\":\"ok\",\"severity\":\"low\"}}\n\n"
	findings, err := Normalize(raw("nuclei-jsonl", data), testAsset, "job-1")
	if err != nil {
		t.Fatalf("Normalize nuclei: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (malformed + blank lines skipped)", len(findings))
	}
}
