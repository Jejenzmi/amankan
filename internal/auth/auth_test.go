package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRoleOrdering(t *testing.T) {
	if !(RoleViewer < RoleAnalyst && RoleAnalyst < RoleAdmin) {
		t.Fatal("role ordering must be viewer < analyst < admin")
	}
	if ParseRole("ADMIN") != RoleAdmin || ParseRole(" analyst ") != RoleAnalyst {
		t.Error("ParseRole should be case-insensitive and trim spaces")
	}
	if ParseRole("nonsense") != RoleNone {
		t.Error("unknown role should be RoleNone")
	}
}

func TestParseKeysDisabledWhenEmpty(t *testing.T) {
	a, warns := ParseKeys("")
	if a.Enabled() {
		t.Error("empty spec must disable auth")
	}
	if len(warns) == 0 {
		t.Error("disabling auth should warn")
	}
}

func TestParseKeysValidAndMalformed(t *testing.T) {
	a, _ := ParseKeys("ops:secret123:admin, ro:viewme:viewer, bad-entry, empty::admin")
	if !a.Enabled() {
		t.Fatal("auth should be enabled with valid keys")
	}
	if p, ok := a.lookup("secret123"); !ok || p.Role != RoleAdmin || p.ID != "ops" {
		t.Errorf("admin key lookup wrong: %+v ok=%v", p, ok)
	}
	if p, ok := a.lookup("viewme"); !ok || p.Role != RoleViewer {
		t.Errorf("viewer key lookup wrong: %+v ok=%v", p, ok)
	}
	if _, ok := a.lookup("nope"); ok {
		t.Error("unknown secret must not resolve")
	}
}

func ok(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func TestAuthenticateRejectsBadKey(t *testing.T) {
	a, _ := ParseKeys("ops:secret:admin")
	h := a.Authenticate(http.HandlerFunc(ok))

	// missing key → 401
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/assets", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing key: got %d, want 401", rec.Code)
	}

	// valid bearer → 200
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid key: got %d, want 200", rec.Code)
	}

	// X-API-Key header also accepted
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/assets", nil)
	req.Header.Set("X-API-Key", "secret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("X-API-Key: got %d, want 200", rec.Code)
	}
}

func TestRequireEnforcesRole(t *testing.T) {
	a, _ := ParseKeys("ro:viewme:viewer")
	// chain Authenticate → Require(admin)
	h := a.Authenticate(a.Require(RoleAdmin)(http.HandlerFunc(ok)))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/graph/sync", nil)
	req.Header.Set("Authorization", "Bearer viewme")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer hitting admin route: got %d, want 403", rec.Code)
	}
}

func TestDisabledAuthIsOpen(t *testing.T) {
	a, _ := ParseKeys("") // disabled
	h := a.Authenticate(a.Require(RoleAdmin)(http.HandlerFunc(ok)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/graph/sync", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("disabled auth must be open: got %d, want 200", rec.Code)
	}
}
