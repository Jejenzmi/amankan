//go:build integration

// Integration tests exercise the store against a REAL PostgreSQL instance.
// They are gated behind the `integration` build tag and the AMANKAN_TEST_DATABASE_URL
// env var, so the default `go test ./...` (unit tests) never requires a database.
//
//	AMANKAN_TEST_DATABASE_URL=postgres://amankan:amankan@localhost:5432/amankan_test?sslmode=disable \
//	  go test -tags=integration ./internal/store/...
package store

import (
	"context"
	"os"
	"testing"

	"github.com/amankan/amankan/internal/audit"
	"github.com/amankan/amankan/internal/db"
	"github.com/amankan/amankan/internal/models"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("AMANKAN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AMANKAN_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return New(pool)
}

func TestIntegrationAssetLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	a := &models.Asset{Name: "it-asset", Type: models.AssetIP, Target: "10.9.9.9", Criticality: models.CritHigh}
	if err := s.CreateAsset(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == "" {
		t.Fatal("asset id not assigned")
	}

	got, err := s.GetAsset(ctx, a.ID)
	if err != nil || got.Name != "it-asset" || got.ScanAuthorized {
		t.Fatalf("get: %+v err=%v", got, err)
	}

	// Layer-3 authorization round-trips.
	if err := s.SetAssetAuthorization(ctx, a.ID, true); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	got, _ = s.GetAsset(ctx, a.ID)
	if !got.ScanAuthorized {
		t.Error("scan_authorized not persisted")
	}

	if _, err := s.GetAsset(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrNotFound {
		t.Errorf("missing asset should be ErrNotFound, got %v", err)
	}
}

func TestIntegrationScanAndFindings(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	a := &models.Asset{Name: "it-scan", Type: models.AssetDomain, Target: "it.example", Criticality: models.CritCritical}
	if err := s.CreateAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	job := &models.ScanJob{AssetID: a.ID, Profile: models.ProfileQuick}
	if err := s.CreateScanJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRunning(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCompleted(ctx, job.ID, false); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		f := &models.Finding{
			ScanJobID: job.ID, AssetID: a.ID, Scanner: models.ScannerNmap,
			Title: "open port", Severity: models.SevHigh, CWE: "CWE-1327",
			RiskScore: float64(9 - i), Status: models.FindingOpen,
		}
		if err := s.CreateFinding(ctx, f); err != nil {
			t.Fatalf("finding: %v", err)
		}
	}

	all, err := s.ListFindings(ctx, a.ID, "", 0, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("list all: got %d err=%v", len(all), err)
	}
	// pagination: limit 2 returns the 2 highest-risk
	page, err := s.ListFindings(ctx, a.ID, "", 2, 0)
	if err != nil || len(page) != 2 {
		t.Fatalf("list page: got %d err=%v", len(page), err)
	}
	if page[0].RiskScore < page[1].RiskScore {
		t.Error("findings not ordered by risk desc")
	}
}

func TestIntegrationAuditChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		e := &audit.Entry{Actor: "it", Role: "admin", Method: "POST", Path: "/x", Status: 200}
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
		if e.Hash == "" || e.Seq == 0 {
			t.Fatal("audit entry not populated")
		}
	}
	entries, err := s.AllAuditForVerify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, at := audit.VerifyChain(entries); !ok {
		t.Fatalf("real audit chain broken at %d", at)
	}
}
