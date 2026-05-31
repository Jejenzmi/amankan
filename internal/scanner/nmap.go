package scanner

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/amankan/amankan/internal/models"
)

// Nmap adapter. Runs `nmap -oX -` against safe targets, else returns mock XML.
type Nmap struct{ opts Options }

func NewNmap(opts Options) *Nmap { return &Nmap{opts: opts} }

func (n *Nmap) Type() models.ScannerType { return models.ScannerNmap }

func (n *Nmap) Scan(ctx context.Context, asset models.Asset) (RawResult, error) {
	res := RawResult{Scanner: models.ScannerNmap, Format: "nmap-xml"}

	bin, err := exec.LookPath(n.opts.NmapBin)
	if err != nil {
		return n.opts.fallback(res, mockNmapXML(asset.Target), "nmap binary not found")
	}
	if !n.opts.liveAllowed(asset) {
		return n.opts.fallback(res, mockNmapXML(asset.Target), "live scanning not permitted for this target")
	}

	// -sV service/version detection, top 100 ports, XML to stdout.
	cmd := exec.CommandContext(ctx, bin, "-sV", "-T4", "--top-ports", "100", "-oX", "-", asset.Target)
	out, runErr := cmd.Output()
	if runErr != nil || len(out) == 0 {
		if n.opts.Production {
			return RawResult{}, fmt.Errorf("nmap: scan of %q failed: %w", asset.Target, runErr)
		}
		res.Data = mockNmapXML(asset.Target)
		res.Mock = true
		return res, nil
	}
	res.Data = out
	return res, nil
}

func mockNmapXML(target string) []byte {
	return []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="mock">
  <host>
    <address addr="` + escapeAttr(target) + `" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.29"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.14.0" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="5.7.31"/>
      </port>
    </ports>
  </host>
</nmaprun>`)
}

func escapeAttr(s string) string {
	r := []rune{}
	for _, c := range s {
		switch c {
		case '"', '<', '>', '&':
			continue
		default:
			r = append(r, c)
		}
	}
	return string(r)
}
