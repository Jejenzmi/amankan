package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// signJWT builds an RS256 JWT for testing.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload := b64(claims)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newTestVerifier(t *testing.T, key *rsa.PrivateKey, kid string) *OIDCVerifier {
	t.Helper()
	v := NewOIDCVerifier(OIDCConfig{Issuer: "https://kc.example/realms/amankan", Audience: "amankan-api"})
	// inject the public key directly (skip the JWKS HTTP fetch)
	v.keys[kid] = &key.PublicKey
	v.fetched = true
	return v
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss":                "https://kc.example/realms/amankan",
		"aud":                "amankan-api",
		"sub":                "user-123",
		"preferred_username": "alice",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"realm_access":       map[string]any{"roles": []string{"amankan-admin", "offline_access"}},
	}
}

func TestOIDCValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	tok := signJWT(t, key, "k1", baseClaims())

	p, err := v.verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if p.Role != RoleAdmin {
		t.Errorf("role = %v, want admin", p.Role)
	}
	if p.ID != "alice" {
		t.Errorf("id = %q, want alice", p.ID)
	}
}

func TestOIDCRoleMapping(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	c := baseClaims()
	c["realm_access"] = map[string]any{"roles": []string{"amankan-viewer"}}
	p, err := v.verify(context.Background(), signJWT(t, key, "k1", c))
	if err != nil || p.Role != RoleViewer {
		t.Errorf("viewer mapping: role=%v err=%v", p.Role, err)
	}
}

func TestOIDCRejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	c := baseClaims()
	c["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := v.verify(context.Background(), signJWT(t, key, "k1", c)); err == nil {
		t.Error("expired token must be rejected")
	}
}

func TestOIDCRejectsWrongIssuerAndAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")

	c := baseClaims()
	c["iss"] = "https://evil.example"
	if _, err := v.verify(context.Background(), signJWT(t, key, "k1", c)); err == nil {
		t.Error("wrong issuer must be rejected")
	}

	c = baseClaims()
	c["aud"] = "some-other-api"
	if _, err := v.verify(context.Background(), signJWT(t, key, "k1", c)); err == nil {
		t.Error("wrong audience must be rejected")
	}
}

func TestOIDCRejectsTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	tok := signJWT(t, key, "k1", baseClaims())
	// flip the last character of the signature
	tampered := tok[:len(tok)-1]
	if tok[len(tok)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}
	if _, err := v.verify(context.Background(), tampered); err == nil {
		t.Error("tampered signature must be rejected")
	}
}

func TestOIDCRejectsUnknownRole(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	c := baseClaims()
	c["realm_access"] = map[string]any{"roles": []string{"random-role"}}
	if _, err := v.verify(context.Background(), signJWT(t, key, "k1", c)); err == nil {
		t.Error("token without a recognized Amankan role must be rejected")
	}
}

func TestOIDCAudienceArray(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "k1")
	c := baseClaims()
	c["aud"] = []string{"other", "amankan-api"} // array form
	if _, err := v.verify(context.Background(), signJWT(t, key, "k1", c)); err != nil {
		t.Errorf("array audience containing the expected value should pass: %v", err)
	}
}
