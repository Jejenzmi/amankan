// Package audit defines the tamper-evident audit-log record and its hash-chain.
//
// Each entry's Hash is sha256(prevHash || canonical(entry)). Because every hash
// commits to the previous one, any insertion, deletion or modification of a
// historical record breaks the chain from that point forward — giving the
// append-only, forensically-verifiable trail required for BSSN retention
// (ISO 27001 A.8.15, SOC 2 CC7).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// GenesisHash anchors the chain (the prev_hash of the very first entry).
const GenesisHash = "GENESIS"

// Entry is one audited action (an authenticated, state-changing API call).
type Entry struct {
	Seq      int64     `json:"seq"`
	TS       time.Time `json:"ts"`
	Actor    string    `json:"actor"`     // principal id (API key label) or "anonymous"
	Role     string    `json:"role"`      // role at the time of the action
	Method   string    `json:"method"`    // HTTP method
	Path     string    `json:"path"`      // request path
	Status   int       `json:"status"`    // response status code
	RemoteIP string    `json:"remote_ip"` // best-effort client IP
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Canonical serialises the entry's content fields into a stable string. It
// excludes Seq (assigned by the DB) and Hash (the output) but includes PrevHash
// so the chain linkage is bound into every hash.
func Canonical(prevHash string, e Entry) string {
	var b strings.Builder
	b.WriteString(prevHash)
	b.WriteByte('|')
	b.WriteString(e.TS.UTC().Format(time.RFC3339Nano))
	b.WriteByte('|')
	b.WriteString(e.Actor)
	b.WriteByte('|')
	b.WriteString(e.Role)
	b.WriteByte('|')
	b.WriteString(e.Method)
	b.WriteByte('|')
	b.WriteString(e.Path)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(e.Status))
	b.WriteByte('|')
	b.WriteString(e.RemoteIP)
	return b.String()
}

// Hash returns the hex SHA-256 of the canonical form chained to prevHash.
func Hash(prevHash string, e Entry) string {
	sum := sha256.Sum256([]byte(Canonical(prevHash, e)))
	return hex.EncodeToString(sum[:])
}

// VerifyChain recomputes the hash chain over entries (which must be ordered by
// ascending Seq) and returns the first sequence number whose stored hash does
// not match, or ok=true when the whole chain is intact.
func VerifyChain(entries []Entry) (ok bool, brokenAtSeq int64) {
	prev := GenesisHash
	for _, e := range entries {
		if e.PrevHash != prev {
			return false, e.Seq
		}
		if Hash(prev, e) != e.Hash {
			return false, e.Seq
		}
		prev = e.Hash
	}
	return true, 0
}
