package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amankan/amankan/internal/audit"
)

// auditLockKey is a fixed advisory-lock key that serialises audit appends so the
// hash chain cannot fork under concurrent writers.
const auditLockKey int64 = 0x4155444954 // "AUDIT"

// AppendAudit writes one audit entry, computing its position in the hash chain.
// It serialises appends with a transaction-scoped advisory lock so concurrent
// callers cannot read the same prev_hash and fork the chain.
func (s *Store) AppendAudit(ctx context.Context, e *audit.Entry) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return err
	}

	prev := audit.GenesisHash
	var last string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&last)
	if err == nil {
		prev = last
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err // empty table is fine (genesis); anything else is fatal
	}

	e.TS = time.Now().UTC()
	e.PrevHash = prev
	e.Hash = audit.Hash(prev, *e)

	err = tx.QueryRow(ctx,
		`INSERT INTO audit_log (ts, actor, role, method, path, status, remote_ip, prev_hash, hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING seq`,
		e.TS, e.Actor, e.Role, e.Method, e.Path, e.Status, e.RemoteIP, e.PrevHash, e.Hash,
	).Scan(&e.Seq)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListAudit returns up to limit audit entries in ascending sequence order.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]audit.Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	// Take the newest `limit` rows, then return them in ascending order so the
	// chain reads naturally and verifies in-order.
	rows, err := s.pool.Query(ctx,
		`SELECT seq, ts, actor, role, method, path, status, remote_ip, prev_hash, hash
		   FROM (SELECT * FROM audit_log ORDER BY seq DESC LIMIT $1) t
		  ORDER BY seq ASC`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Role, &e.Method, &e.Path, &e.Status, &e.RemoteIP, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllAuditForVerify streams the full chain in ascending order for integrity
// verification.
func (s *Store) AllAuditForVerify(ctx context.Context) ([]audit.Entry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT seq, ts, actor, role, method, path, status, remote_ip, prev_hash, hash
		   FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Role, &e.Method, &e.Path, &e.Status, &e.RemoteIP, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
