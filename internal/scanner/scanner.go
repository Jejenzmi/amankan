// Package scanner wraps external security tools behind a uniform interface.
//
// In development each adapter runs the real binary when it is installed AND the
// target is safe to scan; otherwise it returns deterministic mock output so the
// PoC runs end-to-end on any machine. In PRODUCTION mode there is NO mock: an
// adapter that cannot run for real fails loudly so a scan never reports fabricated
// data. Raw output is parsed later by the normalize package.
package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/amankan/amankan/internal/models"
)

// RawResult is the unparsed output of one scanner run.
type RawResult struct {
	Scanner models.ScannerType
	Format  string // "nmap-xml", "nuclei-jsonl", "crypto-json", "secrets-json"
	Data    []byte
	Mock    bool // true when mock data was used instead of the real tool
}

// Scanner is a single tool adapter.
type Scanner interface {
	Type() models.ScannerType
	Scan(ctx context.Context, asset models.Asset) (RawResult, error)
}

// Options configures all adapters.
type Options struct {
	NmapBin       string
	NucleiBin     string
	GitleaksBin   string
	AllowLiveScan bool

	// Production turns off all mock fallbacks: when a real scan cannot run the
	// adapter returns an error instead of fabricated data.
	Production bool
	// ScanAuthorized records that the operator has confirmed authorization to
	// scan the registered targets. Without it, real scanning is restricted to
	// loopback / RFC1918 (so a misconfiguration can't hit third-party hosts).
	ScanAuthorized bool
}

// liveAllowed reports whether a real scan of the asset may proceed. Authorization
// can be granted globally (Options.ScanAuthorized) or per-asset
// (asset.ScanAuthorized); absent either, real scanning is limited to
// loopback / RFC1918 so a misconfiguration cannot reach third-party hosts.
func (o Options) liveAllowed(asset models.Asset) bool {
	if !o.AllowLiveScan {
		return false
	}
	if o.ScanAuthorized || asset.ScanAuthorized {
		return true
	}
	return isSafeTarget(asset.Target)
}

// fallback resolves the no-real-scan case: an error in production (never
// fabricate data), or deterministic mock output in development.
func (o Options) fallback(res RawResult, mockData []byte, reason string) (RawResult, error) {
	if o.Production {
		return RawResult{}, fmt.Errorf("%s: cannot run real scan (%s) and mock is disabled in production", res.Scanner, reason)
	}
	res.Data = mockData
	res.Mock = true
	return res, nil
}

// ForProfile returns the scanner set selected by a scan profile.
func ForProfile(p models.ScanProfile, opts Options) []Scanner {
	switch p {
	case models.ProfileQuick:
		return []Scanner{NewNmap(opts)}
	case models.ProfileWeb:
		return []Scanner{NewNuclei(opts)}
	case models.ProfileCritical:
		return []Scanner{NewNmap(opts), NewNuclei(opts), NewCrypto(opts), NewSecrets(opts)}
	default:
		return []Scanner{NewNmap(opts)}
	}
}

// isSafeTarget gates real scanning to loopback and RFC1918 ranges. Public
// targets fall back to mock unless the operator opts in per asset (out of scope
// for the PoC). This prevents accidental scanning of third-party hosts.
func isSafeTarget(target string) bool {
	host := target
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	if host == "localhost" {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Could not resolve -> treat as unsafe (use mock).
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			return false
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
	}
	return false
}
