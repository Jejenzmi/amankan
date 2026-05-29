// Package config loads runtime configuration from environment variables.
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr       string
	DatabaseURL    string
	RedisAddr      string
	QueueKey       string
	NmapBin        string
	NucleiBin      string
	ScanTimeout    time.Duration
	AllowLiveScan  bool

	Neo4jURI  string
	Neo4jUser string
	Neo4jPass string
}

// GraphEnabled reports whether graph (Neo4j) integration is configured.
func (c Config) GraphEnabled() bool { return c.Neo4jURI != "" }

func Load() Config {
	return Config{
		HTTPAddr:      env("AMANKAN_HTTP_ADDR", ":8080"),
		DatabaseURL:   env("AMANKAN_DATABASE_URL", "postgres://amankan:amankan@localhost:5544/amankan?sslmode=disable"),
		RedisAddr:     env("AMANKAN_REDIS_ADDR", "localhost:6399"),
		QueueKey:      env("AMANKAN_QUEUE_KEY", "amankan:scanjobs"),
		NmapBin:       env("AMANKAN_NMAP_BIN", "nmap"),
		NucleiBin:     env("AMANKAN_NUCLEI_BIN", "nuclei"),
		ScanTimeout:   time.Duration(envInt("AMANKAN_SCAN_TIMEOUT_SECONDS", 120)) * time.Second,
		AllowLiveScan: envBool("AMANKAN_ALLOW_LIVE_SCAN", false),
		Neo4jURI:      env("AMANKAN_NEO4J_URI", "bolt://localhost:7688"),
		Neo4jUser:     env("AMANKAN_NEO4J_USER", "neo4j"),
		Neo4jPass:     env("AMANKAN_NEO4J_PASS", "amankanpass"),
	}
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
