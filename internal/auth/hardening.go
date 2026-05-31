package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CORS returns a CORS middleware restricted to an allow-list of origins. A "*"
// entry restores permissive behaviour (local dev). The request Origin is echoed
// back only when allowed, which is required for credentialed requests.
func CORS(allowed []string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	wildcard := false
	for _, o := range allowed {
		o = strings.TrimSpace(o)
		if o == "*" {
			wildcard = true
		} else if o != "" {
			set[o] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && (wildcard || set[origin]) {
				if wildcard {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Add("Vary", "Origin")
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody caps the request body size to n bytes, returning 413 on overflow when
// the body is read. Protects against memory-exhaustion via oversized payloads
// (OWASP ASVS V13.2). n <= 0 disables the cap.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if n <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets baseline response hardening headers (OWASP ASVS V14.4).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// HSTS is only meaningful over TLS; harmless to advertise for when the
		// API is fronted by a TLS-terminating proxy.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a per-client-IP token bucket. Lightweight, dependency-free,
// good enough to blunt abuse / brute force in the PoC.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64
	lastSeen map[string]time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// RateLimit returns middleware limiting each client IP to `perSecond` requests
// with a short burst. perSecond <= 0 disables limiting. `now` is injectable for
// tests; pass time.Now in production.
func RateLimit(perSecond float64, now func() time.Time) func(http.Handler) http.Handler {
	if now == nil {
		now = time.Now
	}
	if perSecond <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	rl := &rateLimiter{
		buckets:  map[string]*bucket{},
		lastSeen: map[string]time.Time{},
		rate:     perSecond,
		burst:    perSecond * 2,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if !rl.allow(clientIP(r), now()) {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *rateLimiter) allow(ip string, t time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[ip]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: t}
		rl.buckets[ip] = b
	}
	// refill
	elapsed := t.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = t
	}
	rl.lastSeen[ip] = t
	rl.evict(t)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evict drops buckets unused for >10 minutes to bound memory.
func (rl *rateLimiter) evict(t time.Time) {
	for ip, seen := range rl.lastSeen {
		if t.Sub(seen) > 10*time.Minute {
			delete(rl.lastSeen, ip)
			delete(rl.buckets, ip)
		}
	}
}

// clientIP extracts the best-effort client IP (honours X-Forwarded-For first hop).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
