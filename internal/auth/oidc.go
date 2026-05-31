package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCVerifier authenticates callers with OAuth2/OIDC bearer tokens (e.g. issued
// by Keycloak), verifying RS256 JWTs against the issuer's JWKS and mapping realm
// roles to Amankan roles. It is the production-grade identity path; API-key auth
// remains the lightweight fallback. Implemented with the standard library only.
type OIDCVerifier struct {
	issuer   string
	audience string
	jwksURL  string
	roleMap  map[string]Role // realm role name -> Amankan role

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey // kid -> public key
	fetched bool
	client  *http.Client
	nowFn   func() time.Time
}

// OIDCConfig configures the verifier.
type OIDCConfig struct {
	Issuer   string
	Audience string
	JWKSURL  string          // optional; discovered from issuer when empty
	RoleMap  map[string]Role // realm role -> Amankan role
}

// DefaultRoleMap maps conventional Keycloak realm roles to Amankan roles.
func DefaultRoleMap() map[string]Role {
	return map[string]Role{
		"amankan-admin":   RoleAdmin,
		"amankan-analyst": RoleAnalyst,
		"amankan-viewer":  RoleViewer,
	}
}

// NewOIDCVerifier builds a verifier. The JWKS is fetched lazily on first use.
func NewOIDCVerifier(cfg OIDCConfig) *OIDCVerifier {
	rm := cfg.RoleMap
	if len(rm) == 0 {
		rm = DefaultRoleMap()
	}
	jwks := cfg.JWKSURL
	if jwks == "" && cfg.Issuer != "" {
		jwks = strings.TrimRight(cfg.Issuer, "/") + "/protocol/openid-connect/certs"
	}
	return &OIDCVerifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		jwksURL:  jwks,
		roleMap:  rm,
		keys:     map[string]*rsa.PublicKey{},
		client:   &http.Client{Timeout: 10 * time.Second},
		nowFn:    time.Now,
	}
}

func (v *OIDCVerifier) Enabled() bool { return true }

// Authenticate verifies the bearer token and attaches the resolved principal.
func (v *OIDCVerifier) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		tok := bearer(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		p, err := v.verify(r.Context(), tok)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require enforces a minimum role (the principal is set by Authenticate).
func (v *OIDCVerifier) Require(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
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

// ---- verification ----

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Iss         string          `json:"iss"`
	Sub         string          `json:"sub"`
	Exp         int64           `json:"exp"`
	Aud         json.RawMessage `json:"aud"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	PreferredUsername string `json:"preferred_username"`
}

func (v *OIDCVerifier) verify(ctx context.Context, token string) (Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, errors.New("malformed JWT")
	}
	var hdr jwtHeader
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return Principal{}, fmt.Errorf("header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return Principal{}, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}

	key, err := v.keyForKid(ctx, hdr.Kid)
	if err != nil {
		return Principal{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Principal{}, fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return Principal{}, errors.New("signature verification failed")
	}

	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Principal{}, fmt.Errorf("claims: %w", err)
	}
	if claims.Exp != 0 && v.nowFn().Unix() >= claims.Exp {
		return Principal{}, errors.New("token expired")
	}
	if v.issuer != "" && claims.Iss != v.issuer {
		return Principal{}, fmt.Errorf("issuer mismatch")
	}
	if v.audience != "" && !audienceContains(claims.Aud, v.audience) {
		return Principal{}, errors.New("audience mismatch")
	}

	role := v.mapRoles(claims.RealmAccess.Roles)
	if role == RoleNone {
		return Principal{}, errors.New("no recognized Amankan role in token")
	}
	id := claims.PreferredUsername
	if id == "" {
		id = claims.Sub
	}
	return Principal{ID: id, Role: role}, nil
}

// mapRoles returns the highest Amankan role granted by the token's realm roles.
func (v *OIDCVerifier) mapRoles(roles []string) Role {
	best := RoleNone
	for _, r := range roles {
		if mapped, ok := v.roleMap[r]; ok && mapped > best {
			best = mapped
		}
	}
	return best
}

func (v *OIDCVerifier) keyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fetched := v.fetched
	v.mu.RUnlock()
	if ok {
		return key, nil
	}
	if !fetched {
		if err := v.refreshKeys(ctx); err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}
		v.mu.RLock()
		key, ok = v.keys[kid]
		v.mu.RUnlock()
		if ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("no key for kid %q", kid)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *OIDCVerifier) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from JWKS endpoint", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pk, err := rsaKeyFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pk
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = true
	v.mu.Unlock()
	return nil
}

func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func decodeSegment(seg string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// audienceContains handles the aud claim being either a string or an array.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
