package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/amankan/amankan/internal/models"
)

// Crypto adapter performs a cryptographic audit (BSSN-ready): it inspects the
// negotiated TLS version of a target's :443 endpoint. For safe targets it does a
// real handshake; otherwise it emits a representative mock report.
type Crypto struct{ opts Options }

func NewCrypto(opts Options) *Crypto { return &Crypto{opts: opts} }

func (c *Crypto) Type() models.ScannerType { return models.ScannerCrypto }

// cryptoReport is the internal "crypto-json" format consumed by normalize.
type cryptoReport struct {
	Target     string `json:"target"`
	TLSVersion string `json:"tls_version"` // e.g. "1.0", "1.2"
	WeakTLS    bool   `json:"weak_tls"`
	WeakRSA    bool   `json:"weak_rsa"` // RSA < 2048-bit
	Note       string `json:"note"`
}

func (c *Crypto) Scan(ctx context.Context, asset models.Asset) (RawResult, error) {
	res := RawResult{Scanner: models.ScannerCrypto, Format: "crypto-json"}

	if c.opts.AllowLiveScan && isSafeTarget(asset.Target) {
		if rep, ok := probeTLS(ctx, asset.Target); ok {
			res.Data, _ = json.Marshal(rep)
			return res, nil
		}
	}

	// Mock: represent a host still on TLS 1.0 with an undersized RSA key.
	rep := cryptoReport{
		Target:     asset.Target,
		TLSVersion: "1.0",
		WeakTLS:    true,
		WeakRSA:    true,
		Note:       "mock crypto audit: TLS 1.0 and RSA-1024 detected",
	}
	res.Data, _ = json.Marshal(rep)
	res.Mock = true
	return res, nil
}

func probeTLS(ctx context.Context, target string) (cryptoReport, bool) {
	host := stripScheme(target)
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return cryptoReport{}, false
	}
	defer conn.Close()
	state := conn.ConnectionState()
	ver := tlsVersionString(state.Version)
	rep := cryptoReport{
		Target:     target,
		TLSVersion: ver,
		WeakTLS:    state.Version < tls.VersionTLS12,
		Note:       fmt.Sprintf("live handshake negotiated TLS %s, cipher 0x%04x", ver, state.CipherSuite),
	}
	return rep, true
}

func stripScheme(s string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(s) > len(p) && s[:len(p)] == p {
			s = s[len(p):]
		}
	}
	if i := indexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func indexAny(s, chars string) int {
	for i, c := range s {
		for _, c2 := range chars {
			if c == c2 {
				return i
			}
		}
	}
	return -1
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}
