package api

import (
	"net/http/httptest"
	"testing"
)

func TestPageParamsDefaultsAndCap(t *testing.T) {
	// default
	l, o := pageParams(httptest.NewRequest("GET", "/x", nil))
	if l != defaultPageLimit || o != 0 {
		t.Errorf("defaults: got limit=%d offset=%d", l, o)
	}
	// explicit
	l, o = pageParams(httptest.NewRequest("GET", "/x?limit=10&offset=5", nil))
	if l != 10 || o != 5 {
		t.Errorf("explicit: got limit=%d offset=%d, want 10/5", l, o)
	}
	// over-cap is clamped
	l, _ = pageParams(httptest.NewRequest("GET", "/x?limit=99999", nil))
	if l != maxPageLimit {
		t.Errorf("cap: got limit=%d, want %d", l, maxPageLimit)
	}
	// negative/garbage falls back to default
	l, o = pageParams(httptest.NewRequest("GET", "/x?limit=-3&offset=abc", nil))
	if l != defaultPageLimit || o != 0 {
		t.Errorf("garbage: got limit=%d offset=%d", l, o)
	}
}

func TestPaginate(t *testing.T) {
	items := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	rec := httptest.NewRecorder()
	page := paginate(rec, httptest.NewRequest("GET", "/x?limit=3&offset=2", nil), items)
	if len(page) != 3 || page[0] != 2 || page[2] != 4 {
		t.Errorf("page = %v, want [2 3 4]", page)
	}
	if got := rec.Header().Get("X-Total-Count"); got != "10" {
		t.Errorf("X-Total-Count = %q, want 10", got)
	}

	// offset beyond the end → empty page, not a panic
	page = paginate(httptest.NewRecorder(), httptest.NewRequest("GET", "/x?offset=100", nil), items)
	if len(page) != 0 {
		t.Errorf("offset past end: got %v, want empty", page)
	}

	// limit past the end is clamped to slice length
	page = paginate(httptest.NewRecorder(), httptest.NewRequest("GET", "/x?limit=1000&offset=8", nil), items)
	if len(page) != 2 {
		t.Errorf("tail page len = %d, want 2", len(page))
	}
}
