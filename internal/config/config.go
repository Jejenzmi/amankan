// Package config loads runtime configuration from environment variables.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amankan/amankan/internal/threatintel"
)

type Config struct {
	Env           string // "development" (default) or "production"
	HTTPAddr      string
	DatabaseURL   string
	RedisAddr     string
	RedisPassword string
	QueueKey      string
	NmapBin       string
	NucleiBin     string
	GitleaksBin   string
	ScanTimeout   time.Duration
	AllowLiveScan bool
	// ScanAuthorized confirms the operator is authorized to scan the registered
	// targets, lifting the loopback/RFC1918 restriction. Off by default.
	ScanAuthorized bool

	Neo4jURI  string
	Neo4jUser string
	Neo4jPass string

	// Security / API hardening.
	APIKeys     string   // "label:secret:role,..." — empty disables auth
	CORSOrigins []string // allowed browser origins ("*" = permissive)
	RateLimit   float64  // requests/sec per client IP (0 = disabled)
	TLSCert     string   // path to TLS certificate (enables HTTPS with TLSKey)
	TLSKey      string   // path to TLS private key

	// OIDC (OAuth2/Keycloak). When OIDCIssuer is set, JWT bearer auth replaces
	// API-key auth.
	OIDCIssuer   string
	OIDCAudience string

	// Threat intelligence (optional external feeds; offline fallback otherwise).
	KEVFeedPath      string // path to a CISA KEV JSON export
	EPSSFeedPath     string // path to an EPSS CSV export
	ThreatIntelFetch bool   // fetch live KEV/EPSS feeds over HTTP at startup
	KEVFeedURL       string // override for the CISA KEV URL
	EPSSFeedURL      string // override for the EPSS URL
}

// GraphEnabled reports whether graph (Neo4j) integration is configured.
func (c Config) GraphEnabled() bool { return c.Neo4jURI != "" }

// IsProduction reports whether the server runs in production mode (no mock data,
// strict startup safety checks).
func (c Config) IsProduction() bool { return strings.EqualFold(c.Env, "production") }

func Load() Config {
	return Config{
		Env:              env("AMANKAN_ENV", "development"),
		HTTPAddr:         env("AMANKAN_HTTP_ADDR", ":8080"),
		DatabaseURL:      env("AMANKAN_DATABASE_URL", "postgres://amankan:amankan@localhost:5544/amankan?sslmode=disable"),
		RedisAddr:        env("AMANKAN_REDIS_ADDR", "localhost:6399"),
		RedisPassword:    env("AMANKAN_REDIS_PASSWORD", ""),
		QueueKey:         env("AMANKAN_QUEUE_KEY", "amankan:scanjobs"),
		NmapBin:          env("AMANKAN_NMAP_BIN", "nmap"),
		NucleiBin:        env("AMANKAN_NUCLEI_BIN", "nuclei"),
		GitleaksBin:      env("AMANKAN_GITLEAKS_BIN", "gitleaks"),
		ScanTimeout:      time.Duration(envInt("AMANKAN_SCAN_TIMEOUT_SECONDS", 120)) * time.Second,
		AllowLiveScan:    envBool("AMANKAN_ALLOW_LIVE_SCAN", false),
		ScanAuthorized:   envBool("AMANKAN_SCAN_AUTHORIZED", false),
		Neo4jURI:         env("AMANKAN_NEO4J_URI", "bolt://localhost:7688"),
		Neo4jUser:        env("AMANKAN_NEO4J_USER", "neo4j"),
		Neo4jPass:        env("AMANKAN_NEO4J_PASS", "amankanpass"),
		APIKeys:          env("AMANKAN_API_KEYS", ""),
		CORSOrigins:      splitCSV(env("AMANKAN_CORS_ORIGINS", "http://localhost:3000")),
		RateLimit:        envFloat("AMANKAN_RATE_LIMIT", 0),
		TLSCert:          env("AMANKAN_TLS_CERT", ""),
		TLSKey:           env("AMANKAN_TLS_KEY", ""),
		OIDCIssuer:       env("AMANKAN_OIDC_ISSUER", ""),
		OIDCAudience:     env("AMANKAN_OIDC_AUDIENCE", ""),
		KEVFeedPath:      env("AMANKAN_KEV_FEED", ""),
		EPSSFeedPath:     env("AMANKAN_EPSS_FEED", ""),
		ThreatIntelFetch: envBool("AMANKAN_THREATINTEL_FETCH", false),
		KEVFeedURL:       env("AMANKAN_KEV_URL", threatintel.DefaultKEVURL),
		EPSSFeedURL:      env("AMANKAN_EPSS_URL", threatintel.DefaultEPSSURL),
	}
}

// Validate enforces production safety invariants. In production it refuses to
// run with insecure defaults so the platform cannot be deployed wide-open by
// accident. Returns a list of problems (empty = OK).
func (c Config) Validate() []string {
	if !c.IsProduction() {
		return nil
	}
	var probs []string
	if c.APIKeys == "" {
		probs = append(probs, "AMANKAN_API_KEYS is empty — authentication would be disabled")
	}
	for _, o := range c.CORSOrigins {
		if o == "*" {
			probs = append(probs, "AMANKAN_CORS_ORIGINS contains '*' — wildcard CORS is unsafe in production")
		}
	}
	if strings.Contains(c.DatabaseURL, "sslmode=disable") {
		probs = append(probs, "AMANKAN_DATABASE_URL uses sslmode=disable — require TLS to the database")
	}
	if c.GraphEnabled() && c.Neo4jPass == "amankanpass" {
		probs = append(probs, "AMANKAN_NEO4J_PASS is the default — set a strong password")
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		probs = append(probs, "no TLS configured (AMANKAN_TLS_CERT/KEY) — terminate TLS at a proxy or set them")
	}
	if c.RateLimit <= 0 {
		probs = append(probs, "AMANKAN_RATE_LIMIT is 0 — set a per-IP request rate limit")
	}
	return probs
}

// splitCSV splits a comma-separated env value into trimmed, non-empty items.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
