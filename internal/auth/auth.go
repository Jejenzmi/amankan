// Package auth provides API-key authentication and role-based access control
// (RBAC) for the Amankan REST surface, plus the supporting HTTP hardening
// middleware (CORS, security headers, rate limiting).
//
// Authentication is deliberately simple for the PoC — bearer API keys mapped to
// roles — but the role model and enforcement points mirror what an OAuth2/OIDC
// (Keycloak) integration would gate. When no keys are configured the API runs
// open (with a startup warning) so local development stays one-command.
package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// Role is a coarse permission tier. Higher value = more privilege.
type Role int

const (
	RoleNone    Role = iota
	RoleViewer       // read-only: list/get assets, findings, scans, graph
	RoleAnalyst      // viewer + run scans, change finding status, export
	RoleAdmin        // analyst + graph admin, accounts/edges, topology, audit
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleAnalyst:
		return "analyst"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseRole maps a role name to a Role (RoleNone if unknown).
func ParseRole(s string) Role {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer
	case "analyst":
		return RoleAnalyst
	case "admin":
		return RoleAdmin
	default:
		return RoleNone
	}
}

// Provider is an authentication strategy: it resolves a caller to a principal
// (Authenticate) and enforces role requirements (Require). Both the API-key
// Authenticator and the OIDC verifier implement it, so the router is agnostic to
// which identity mechanism is configured.
type Provider interface {
	Authenticate(next http.Handler) http.Handler
	Require(min Role) func(http.Handler) http.Handler
	Enabled() bool
}

// Principal is the authenticated caller carried on the request context.
type Principal struct {
	ID   string // a stable, non-secret identifier (the key label)
	Role Role
}

type ctxKey int

const principalKey ctxKey = 0

// principalFrom returns the principal attached to the context, if any.
func principalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// PrincipalFromRequest returns the authenticated principal for audit/logging.
// When auth is disabled it returns an "anonymous" admin-equivalent principal.
func PrincipalFromRequest(r *http.Request) Principal {
	if p, ok := principalFrom(r.Context()); ok {
		return p
	}
	return Principal{ID: "anonymous", Role: RoleAdmin}
}

// Authenticator holds the configured key→principal table.
type Authenticator struct {
	keys    map[string]Principal // secret key -> principal
	enabled bool
}

// ParseKeys builds an Authenticator from a spec string of the form
// "label:secret:role,label2:secret2:role2". When the spec is empty the
// authenticator is disabled (open access) and Enabled() returns false.
func ParseKeys(spec string) (*Authenticator, []string) {
	a := &Authenticator{keys: map[string]Principal{}}
	var warnings []string
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return a, []string{"AMANKAN_API_KEYS not set — API authentication is DISABLED (open access)"}
	}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 {
			warnings = append(warnings, "ignored malformed API key entry (want label:secret:role)")
			continue
		}
		label, secret, roleName := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), parts[2]
		role := ParseRole(roleName)
		if secret == "" || role == RoleNone {
			warnings = append(warnings, "ignored API key with empty secret or invalid role: "+label)
			continue
		}
		a.keys[secret] = Principal{ID: label, Role: role}
	}
	a.enabled = len(a.keys) > 0
	return a, warnings
}

// Enabled reports whether authentication is enforced.
func (a *Authenticator) Enabled() bool { return a.enabled }

// lookup resolves a presented secret to a principal using a constant-time
// comparison against every configured key, so response timing does not leak
// which (or how much) of a key matched (OWASP ASVS V2.10).
func (a *Authenticator) lookup(secret string) (Principal, bool) {
	var found Principal
	ok := false
	sb := []byte(secret)
	for k, p := range a.keys {
		if subtle.ConstantTimeCompare([]byte(k), sb) == 1 {
			found, ok = p, true
		}
	}
	return found, ok
}

// bearer extracts the API key from either the Authorization: Bearer header or
// the X-API-Key header.
func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// Authenticate is middleware that resolves the API key to a principal and stores
// it on the request context. When auth is disabled it passes through untouched.
// Unknown/missing keys get 401.
func (a *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}
		// Always allow CORS preflight through (no credentials on OPTIONS).
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := a.lookup(bearer(r))
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require returns middleware that enforces a minimum role. When auth is disabled
// it is a no-op (open access).
func (a *Authenticator) Require(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.enabled || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			p, ok := principalFrom(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if p.Role < min {
				writeError(w, http.StatusForbidden, "insufficient role: "+min.String()+" required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":` + quote(msg) + `}`))
}

// quote is a tiny JSON string quoter (avoids importing encoding/json here).
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
