// Package queue is a thin Redis-backed job queue. The API enqueues scan job IDs
// and the worker pops them. This mirrors the "Redis + RabbitMQ for high-concurrency
// scan" component of the design with a single pragmatic dependency for the PoC.
package queue

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Queue struct {
	rdb *redis.Client
	key string
}

func New(addr, key string) *Queue {
	return &Queue{
		rdb: redis.NewClient(&redis.Options{Addr: addr}),
		key: key,
	}
}

func (q *Queue) Ping(ctx context.Context) error {
	return q.rdb.Ping(ctx).Err()
}

func (q *Queue) Close() error { return q.rdb.Close() }

// Enqueue pushes a scan job ID onto the queue.
func (q *Queue) Enqueue(ctx context.Context, scanJobID string) error {
	return q.rdb.LPush(ctx, q.key, scanJobID).Err()
}

// Dequeue blocks up to timeout for the next job ID. Returns ("", nil) on timeout.
func (q *Queue) Dequeue(ctx context.Context, timeout time.Duration) (string, error) {
	res, err := q.rdb.BRPop(ctx, timeout, q.key).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// res = [key, value]
	if len(res) == 2 {
		return res[1], nil
	}
	return "", nil
}
