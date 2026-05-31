package config

import (
	"strings"
	"testing"
)

func TestValidateSkippedInDevelopment(t *testing.T) {
	c := Config{Env: "development"} // all insecure defaults, but dev → no checks
	if probs := c.Validate(); probs != nil {
		t.Errorf("development should not validate, got %v", probs)
	}
}

func TestValidateProductionRejectsInsecure(t *testing.T) {
	c := Config{
		Env:         "production",
		APIKeys:     "",                             // insecure
		CORSOrigins: []string{"*"},                  // insecure
		DatabaseURL: "postgres://x?sslmode=disable", // insecure
		RateLimit:   0,                              // insecure
		// no TLS → insecure
	}
	probs := c.Validate()
	if len(probs) < 5 {
		t.Fatalf("expected several problems, got %d: %v", len(probs), probs)
	}
	joined := strings.Join(probs, "\n")
	for _, want := range []string{"API_KEYS", "CORS", "sslmode", "TLS", "RATE_LIMIT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem mentioning %q in:\n%s", want, joined)
		}
	}
}

func TestValidateProductionAcceptsSecure(t *testing.T) {
	c := Config{
		Env:         "production",
		APIKeys:     "ops:secret:admin",
		CORSOrigins: []string{"https://soc.example"},
		DatabaseURL: "postgres://db/amankan?sslmode=require",
		RateLimit:   20,
		TLSCert:     "/etc/tls/cert.pem",
		TLSKey:      "/etc/tls/key.pem",
		// graph disabled (Neo4jURI empty) so default-password check is skipped
	}
	if probs := c.Validate(); len(probs) != 0 {
		t.Errorf("secure production config should pass, got: %v", probs)
	}
}

func TestValidateFlagsDefaultNeo4jPassword(t *testing.T) {
	c := Config{
		Env:         "production",
		APIKeys:     "ops:secret:admin",
		CORSOrigins: []string{"https://soc.example"},
		DatabaseURL: "postgres://db/amankan?sslmode=require",
		RateLimit:   20,
		TLSCert:     "c", TLSKey: "k",
		Neo4jURI:  "bolt://neo4j:7687",
		Neo4jPass: "amankanpass", // default → must be flagged
	}
	probs := c.Validate()
	if len(probs) != 1 || !strings.Contains(probs[0], "NEO4J_PASS") {
		t.Errorf("expected only the default-Neo4j-password problem, got: %v", probs)
	}
}
