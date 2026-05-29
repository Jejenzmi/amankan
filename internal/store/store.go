// Package store implements persistence for Amankan domain types over PostgreSQL.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amankan/amankan/internal/models"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ---- Assets ----

func (s *Store) CreateAsset(ctx context.Context, a *models.Asset) error {
	a.ID = uuid.NewString()
	a.CreatedAt = time.Now().UTC()
	if a.Tags == nil {
		a.Tags = []string{}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO assets (id,name,type,target,criticality,tags,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID, a.Name, a.Type, a.Target, a.Criticality, a.Tags, a.CreatedAt)
	return err
}

func (s *Store) GetAsset(ctx context.Context, id string) (*models.Asset, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id,name,type,target,criticality,tags,created_at FROM assets WHERE id=$1`, id)
	var a models.Asset
	if err := row.Scan(&a.ID, &a.Name, &a.Type, &a.Target, &a.Criticality, &a.Tags, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// GetAssetByTarget resolves an asset by its target (IP/domain/repo). Used by the
// CMDB/topology import to reference assets by address instead of UUID.
func (s *Store) GetAssetByTarget(ctx context.Context, target string) (*models.Asset, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id,name,type,target,criticality,tags,created_at FROM assets WHERE target=$1 LIMIT 1`, target)
	var a models.Asset
	if err := row.Scan(&a.ID, &a.Name, &a.Type, &a.Target, &a.Criticality, &a.Tags, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListAssets(ctx context.Context) ([]models.Asset, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id,name,type,target,criticality,tags,created_at FROM assets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Asset{}
	for rows.Next() {
		var a models.Asset
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Target, &a.Criticality, &a.Tags, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Scan jobs ----

func (s *Store) CreateScanJob(ctx context.Context, j *models.ScanJob) error {
	j.ID = uuid.NewString()
	j.CreatedAt = time.Now().UTC()
	j.Status = models.StatusQueued
	if j.Scanners == nil {
		j.Scanners = []models.ScannerType{}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scan_jobs (id,asset_id,profile,scanners,status,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		j.ID, j.AssetID, j.Profile, scannerStrings(j.Scanners), j.Status, j.CreatedAt)
	return err
}

func (s *Store) GetScanJob(ctx context.Context, id string) (*models.ScanJob, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id,asset_id,profile,scanners,status,error,used_mock,created_at,started_at,finished_at
		 FROM scan_jobs WHERE id=$1`, id)
	return scanJobFromRow(row)
}

func (s *Store) ListScanJobs(ctx context.Context) ([]models.ScanJob, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id,asset_id,profile,scanners,status,error,used_mock,created_at,started_at,finished_at
		 FROM scan_jobs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ScanJob{}
	for rows.Next() {
		j, err := scanJobFromRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func (s *Store) MarkRunning(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs SET status='running', started_at=$2 WHERE id=$1`, id, now)
	return err
}

func (s *Store) MarkCompleted(ctx context.Context, id string, usedMock bool) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs SET status='completed', finished_at=$2, used_mock=$3 WHERE id=$1`, id, now, usedMock)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs SET status='failed', finished_at=$2, error=$3 WHERE id=$1`, id, now, errMsg)
	return err
}

// ---- Findings ----

func (s *Store) CreateFinding(ctx context.Context, f *models.Finding) error {
	if f.ID == "" {
		f.ID = uuid.NewString()
	}
	f.CreatedAt = time.Now().UTC()
	if f.Status == "" {
		f.Status = models.FindingOpen
	}
	compJSON, err := json.Marshal(f.Compliance)
	if err != nil {
		return err
	}
	var remJSON []byte
	if f.Remediation != nil {
		if remJSON, err = json.Marshal(f.Remediation); err != nil {
			return err
		}
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO findings
		 (id,scan_job_id,asset_id,scanner,title,description,severity,cvss,cve,cwe,port,service,evidence,status,risk_score,known_exploit,compliance,remediation,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		f.ID, f.ScanJobID, f.AssetID, f.Scanner, f.Title, f.Desc, f.Severity, f.CVSS, f.CVE, f.CWE,
		f.Port, f.Service, f.Evidence, f.Status, f.RiskScore, f.KnownExploit, compJSON, nullableJSON(remJSON), f.CreatedAt)
	return err
}

// ListFindings returns findings, optionally filtered by asset and/or scan job.
func (s *Store) ListFindings(ctx context.Context, assetID, scanJobID string) ([]models.Finding, error) {
	q := `SELECT id,scan_job_id,asset_id,scanner,title,description,severity,cvss,cve,cwe,port,service,evidence,status,risk_score,known_exploit,compliance,remediation,created_at
	      FROM findings WHERE ($1='' OR asset_id::text=$1) AND ($2='' OR scan_job_id::text=$2)
	      ORDER BY risk_score DESC, created_at DESC`
	rows, err := s.pool.Query(ctx, q, assetID, scanJobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Finding{}
	for rows.Next() {
		f, err := findingFromRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

func (s *Store) UpdateFindingStatus(ctx context.Context, id string, status models.FindingStatus) error {
	tag, err := s.pool.Exec(ctx, `UPDATE findings SET status=$2 WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- helpers ----

type scannable interface {
	Scan(dest ...any) error
}

func scanJobFromRow(row scannable) (*models.ScanJob, error) {
	var j models.ScanJob
	var scanners []string
	if err := row.Scan(&j.ID, &j.AssetID, &j.Profile, &scanners, &j.Status, &j.Error, &j.UsedMock,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	for _, sc := range scanners {
		j.Scanners = append(j.Scanners, models.ScannerType(sc))
	}
	return &j, nil
}

func findingFromRow(row scannable) (*models.Finding, error) {
	var f models.Finding
	var compJSON []byte
	var remJSON []byte
	if err := row.Scan(&f.ID, &f.ScanJobID, &f.AssetID, &f.Scanner, &f.Title, &f.Desc, &f.Severity,
		&f.CVSS, &f.CVE, &f.CWE, &f.Port, &f.Service, &f.Evidence, &f.Status, &f.RiskScore,
		&f.KnownExploit, &compJSON, &remJSON, &f.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(compJSON) > 0 {
		_ = json.Unmarshal(compJSON, &f.Compliance)
	}
	if len(remJSON) > 0 {
		_ = json.Unmarshal(remJSON, &f.Remediation)
	}
	return &f, nil
}

func scannerStrings(in []models.ScannerType) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}

func nullableJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
