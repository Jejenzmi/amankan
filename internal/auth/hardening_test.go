package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
}

func TestCORSAllowList(t *testing.T) {
	h := CORS([]string{"http://localhost:3000"})(okHandler())

	// allowed origin is echoed
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("allowed origin not echoed: %q", got)
	}

	// disallowed origin gets no ACAO header
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://evil.example")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin should get no ACAO, got %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

func TestRateLimitBlocksBurst(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	h := RateLimit(1, clock)(okHandler()) // 1 rps, burst 2

	count200, count429 := 0, 0
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			count200++
		} else if rec.Code == http.StatusTooManyRequests {
			count429++
		}
	}
	// burst is 2 → first 2 pass, rest throttled (clock frozen, no refill)
	if count200 != 2 || count429 != 3 {
		t.Errorf("got %d ok / %d throttled, want 2/3", count200, count429)
	}

	// after 2s the bucket refills → request allowed again
	now = now.Add(2 * time.Second)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("after refill: got %d, want 200", rec.Code)
	}
}

func TestMaxBody(t *testing.T) {
	// handler that tries to read the whole body; MaxBytesReader fails oversize reads.
	readAll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := MaxBody(16)(readAll)

	// oversize → 413
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 100))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: got %d, want 413", rec.Code)
	}

	// within limit → 200
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("small")))
	if rec.Code != http.StatusOK {
		t.Errorf("small body: got %d, want 200", rec.Code)
	}
}

func TestRateLimitDisabled(t *testing.T) {
	h := RateLimit(0, nil)(okHandler())
	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatal("rate limiting should be disabled at rate 0")
		}
	}
}
