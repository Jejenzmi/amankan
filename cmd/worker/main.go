// Command worker consumes scan jobs from the Redis queue and processes them.
// Run one or more instances for concurrency (the design's high-concurrency scan).
package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/amankan/amankan/internal/config"
	"github.com/amankan/amankan/internal/db"
	"github.com/amankan/amankan/internal/engine"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/store"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	q := queue.New(cfg.RedisAddr, cfg.QueueKey)
	if err := q.Ping(ctx); err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer q.Close()

	st := store.New(pool)
	proc := engine.NewProcessor(st, cfg)

	log.Println("Amankan worker started, waiting for scan jobs...")
	for {
		select {
		case <-ctx.Done():
			log.Println("worker shutting down")
			return
		default:
		}

		jobID, err := q.Dequeue(ctx, 5*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("dequeue error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if jobID == "" {
			continue // timeout, loop again
		}

		if err := proc.Process(ctx, jobID); err != nil {
			log.Printf("job %s failed: %v", jobID, err)
			_ = st.MarkFailed(context.Background(), jobID, err.Error())
		}
	}
}
