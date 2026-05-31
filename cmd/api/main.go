// Command api runs the Amankan REST API server. It also applies DB migrations
// on startup so the PoC is one-command runnable.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amankan/amankan/internal/api"
	"github.com/amankan/amankan/internal/auth"
	"github.com/amankan/amankan/internal/config"
	"github.com/amankan/amankan/internal/db"
	"github.com/amankan/amankan/internal/graph"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/store"
	"github.com/amankan/amankan/internal/threatintel"
)

func main() {
	migrateOnly := flag.Bool("migrate-only", false, "apply migrations and exit")
	flag.Parse()

	// Structured (JSON) logging for machine-parsable, SIEM-friendly output.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg := config.Load()

	// In production, refuse to start with insecure configuration.
	if probs := cfg.Validate(); len(probs) > 0 {
		for _, p := range probs {
			log.Printf("FATAL config: %s", p)
		}
		log.Fatalf("refusing to start in production with %d insecure setting(s)", len(probs))
	}
	if cfg.IsProduction() {
		log.Println("running in PRODUCTION mode (mock scanning disabled)")
	}

	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations applied")
	if *migrateOnly {
		return
	}

	q := queue.New(cfg.RedisAddr, cfg.RedisPassword, cfg.QueueKey)
	if err := q.Ping(ctx); err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer q.Close()

	// Graph component is optional: if Neo4j is unreachable, the rest of the API
	// still serves and graph endpoints return 503.
	var g *graph.Graph
	if cfg.GraphEnabled() {
		if g, err = graph.Connect(ctx, cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPass); err != nil {
			log.Printf("graph disabled: %v", err)
			g = nil
		} else {
			log.Printf("graph (Neo4j) connected at %s", cfg.Neo4jURI)
			defer g.Close(ctx)
		}
	}

	// Threat-intel feeds are optional. Priority: live HTTP fetch (if enabled) →
	// local file paths → embedded fallback KEV set.
	switch {
	case cfg.ThreatIntelFetch:
		fctx, fcancel := context.WithTimeout(ctx, 30*time.Second)
		if kevN, epssN, err := threatintel.FetchAndLoad(fctx, cfg.KEVFeedURL, cfg.EPSSFeedURL, 30*time.Second); err != nil {
			log.Printf("threat-intel: live fetch failed (using fallback): %v", err)
		} else {
			log.Printf("threat-intel: fetched %d KEV + %d EPSS records", kevN, epssN)
		}
		fcancel()
	case cfg.KEVFeedPath != "" || cfg.EPSSFeedPath != "":
		if kevN, epssN, err := threatintel.Load(cfg.KEVFeedPath, cfg.EPSSFeedPath); err != nil {
			log.Printf("threat-intel: load failed (using fallback): %v", err)
		} else {
			log.Printf("threat-intel: loaded %d KEV + %d EPSS records", kevN, epssN)
		}
	}

	// Identity: OIDC (Keycloak) takes precedence when an issuer is configured;
	// otherwise fall back to API-key authentication.
	var provider auth.Provider
	if cfg.OIDCIssuer != "" {
		provider = auth.NewOIDCVerifier(auth.OIDCConfig{
			Issuer:   cfg.OIDCIssuer,
			Audience: cfg.OIDCAudience,
		})
		log.Printf("auth: OIDC enabled (issuer=%s)", cfg.OIDCIssuer)
	} else {
		authn, warnings := auth.ParseKeys(cfg.APIKeys)
		for _, w := range warnings {
			log.Printf("auth: %s", w)
		}
		if authn.Enabled() {
			log.Printf("auth: API key authentication ENABLED")
		}
		provider = authn
	}

	st := store.New(pool)
	handler := api.New(st, q, g, provider, api.Options{
		CORSOrigins: cfg.CORSOrigins,
		RateLimit:   cfg.RateLimit,
	}).Router()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Listen in the background so the main goroutine can wait for a shutdown
	// signal and drain in-flight requests gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tls := cfg.TLSCert != "" && cfg.TLSKey != ""
	go func() {
		var err error
		if tls {
			log.Printf("Amankan API listening on %s (TLS)", cfg.HTTPAddr)
			err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			log.Printf("Amankan API listening on %s (plaintext — terminate TLS at a proxy or set AMANKAN_TLS_CERT/KEY)", cfg.HTTPAddr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown signal received, draining…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("stopped")
}
