package audit

import (
	"testing"
	"time"
)

func chain(entries ...Entry) []Entry {
	prev := GenesisHash
	out := make([]Entry, 0, len(entries))
	for i, e := range entries {
		e.Seq = int64(i + 1)
		e.PrevHash = prev
		e.Hash = Hash(prev, e)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

var ts = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestHashDeterministic(t *testing.T) {
	e := Entry{TS: ts, Actor: "ops", Role: "admin", Method: "POST", Path: "/x", Status: 200}
	if Hash(GenesisHash, e) != Hash(GenesisHash, e) {
		t.Fatal("hash must be deterministic")
	}
	// changing any field changes the hash
	e2 := e
	e2.Status = 500
	if Hash(GenesisHash, e) == Hash(GenesisHash, e2) {
		t.Fatal("hash must change when content changes")
	}
}

func TestVerifyChainIntact(t *testing.T) {
	entries := chain(
		Entry{TS: ts, Actor: "a", Role: "admin", Method: "POST", Path: "/1", Status: 201},
		Entry{TS: ts, Actor: "b", Role: "analyst", Method: "PATCH", Path: "/2", Status: 200},
		Entry{TS: ts, Actor: "a", Role: "admin", Method: "POST", Path: "/3", Status: 202},
	)
	if ok, at := VerifyChain(entries); !ok {
		t.Fatalf("intact chain reported broken at %d", at)
	}
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	entries := chain(
		Entry{TS: ts, Actor: "a", Role: "admin", Method: "POST", Path: "/1", Status: 201},
		Entry{TS: ts, Actor: "b", Role: "analyst", Method: "PATCH", Path: "/2", Status: 200},
		Entry{TS: ts, Actor: "a", Role: "admin", Method: "POST", Path: "/3", Status: 202},
	)
	// Tamper with the middle record's content but keep its old hash → break.
	entries[1].Path = "/2-tampered"
	ok, at := VerifyChain(entries)
	if ok {
		t.Fatal("tampering must be detected")
	}
	if at != 2 {
		t.Errorf("break reported at seq %d, want 2", at)
	}
}

func TestVerifyChainDetectsDeletion(t *testing.T) {
	entries := chain(
		Entry{TS: ts, Actor: "a", Role: "admin", Method: "POST", Path: "/1", Status: 201},
		Entry{TS: ts, Actor: "b", Role: "analyst", Method: "PATCH", Path: "/2", Status: 200},
		Entry{TS: ts, Actor: "c", Role: "admin", Method: "POST", Path: "/3", Status: 202},
	)
	// Delete the middle entry; entry 3's prev_hash no longer matches entry 1's hash.
	spliced := []Entry{entries[0], entries[2]}
	if ok, _ := VerifyChain(spliced); ok {
		t.Fatal("deletion must be detected")
	}
}

func TestEmptyChainIsIntact(t *testing.T) {
	if ok, _ := VerifyChain(nil); !ok {
		t.Fatal("empty chain should verify as intact")
	}
}
