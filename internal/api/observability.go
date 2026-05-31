package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/amankan/amankan/internal/auth"
)

// metrics holds dependency-free counters exposed in Prometheus text format.
type metrics struct {
	total    atomic.Int64
	s2xx     atomic.Int64
	s3xx     atomic.Int64
	s4xx     atomic.Int64
	s5xx     atomic.Int64
	inFlight atomic.Int64
}

func statusClass(m *metrics, code int) {
	switch {
	case code >= 500:
		m.s5xx.Add(1)
	case code >= 400:
		m.s4xx.Add(1)
	case code >= 300:
		m.s3xx.Add(1)
	default:
		m.s2xx.Add(1)
	}
}

// observe is middleware that counts requests/statuses, tracks in-flight, and
// emits a structured (JSON) access log line per request including the request
// id, authenticated actor, status and latency.
func (a *API) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		a.metrics.total.Add(1)
		a.metrics.inFlight.Add(1)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		a.metrics.inFlight.Add(-1)
		statusClass(a.metrics, rec.status)

		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"actor", auth.PrincipalFromRequest(r).ID,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// handleMetrics renders the counters in Prometheus exposition format.
func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := a.metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP amankan_http_requests_total Total HTTP requests by status class.\n")
	fmt.Fprintf(w, "# TYPE amankan_http_requests_total counter\n")
	fmt.Fprintf(w, "amankan_http_requests_total{class=\"2xx\"} %d\n", m.s2xx.Load())
	fmt.Fprintf(w, "amankan_http_requests_total{class=\"3xx\"} %d\n", m.s3xx.Load())
	fmt.Fprintf(w, "amankan_http_requests_total{class=\"4xx\"} %d\n", m.s4xx.Load())
	fmt.Fprintf(w, "amankan_http_requests_total{class=\"5xx\"} %d\n", m.s5xx.Load())
	fmt.Fprintf(w, "# HELP amankan_http_in_flight In-flight HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE amankan_http_in_flight gauge\n")
	fmt.Fprintf(w, "amankan_http_in_flight %d\n", m.inFlight.Load())
}

// handleReadyz is the readiness probe: it reports 200 only when the critical
// dependencies (PostgreSQL, Redis) are reachable. /healthz remains a pure
// liveness check that never touches dependencies.
func (a *API) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{"database": "ok", "redis": "ok"}
	ready := true
	if err := a.store.Ping(ctx); err != nil {
		checks["database"] = err.Error()
		ready = false
	}
	if a.queue != nil {
		if err := a.queue.Ping(ctx); err != nil {
			checks["redis"] = err.Error()
			ready = false
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ready": ready, "checks": checks})
}
