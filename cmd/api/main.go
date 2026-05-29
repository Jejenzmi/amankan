// Command api runs the Amankan REST API server. It also applies DB migrations
// on startup so the PoC is one-command runnable.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/amankan/amankan/internal/api"
	"github.com/amankan/amankan/internal/config"
	"github.com/amankan/amankan/internal/db"
	"github.com/amankan/amankan/internal/graph"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/store"
)

func main() {
	migrateOnly := flag.Bool("migrate-only", false, "apply migrations and exit")
	flag.Parse()

	cfg := config.Load()
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

	q := queue.New(cfg.RedisAddr, cfg.QueueKey)
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

	st := store.New(pool)
	handler := api.New(st, q, g).Router()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("Amankan API listening on %s", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
