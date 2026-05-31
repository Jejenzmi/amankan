package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/amankan/amankan/internal/audit"
	"github.com/amankan/amankan/internal/auth"
)

// statusRecorder captures the response status code for the audit middleware.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// auditMiddleware appends a tamper-evident audit record for every state-changing
// request (POST/PATCH/PUT/DELETE). Reads are not audited (they don't alter
// state and would flood the trail). The record captures the authenticated
// actor, the action, and the resulting status code.
func (a *API) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutating := r.Method == http.MethodPost || r.Method == http.MethodPatch ||
			r.Method == http.MethodPut || r.Method == http.MethodDelete
		if !mutating {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		p := auth.PrincipalFromRequest(r)
		entry := &audit.Entry{
			Actor:    p.ID,
			Role:     p.Role.String(),
			Method:   r.Method,
			Path:     r.URL.Path,
			Status:   rec.status,
			RemoteIP: r.RemoteAddr,
		}
		// Audit must never break the request; log-and-continue on failure.
		if err := a.store.AppendAudit(r.Context(), entry); err != nil {
			log.Printf("audit: append failed for %s %s: %v", r.Method, r.URL.Path, err)
		}
	})
}

// listAudit returns the most recent audit entries (admin only).
func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := a.store.ListAudit(r.Context(), limit)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// verifyAudit recomputes the hash chain over the entire audit log and reports
// whether it is intact (admin only).
func (a *API) verifyAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := a.store.AllAuditForVerify(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	ok, brokenAt := audit.VerifyChain(entries)
	writeJSON(w, http.StatusOK, map[string]any{
		"intact":  ok,
		"entries": len(entries),
		"broken_at_seq": func() any {
			if ok {
				return nil
			}
			return brokenAt
		}(),
	})
}
