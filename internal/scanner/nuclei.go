package scanner

import (
	"context"
	"os/exec"

	"github.com/amankan/amankan/internal/models"
)

// Nuclei adapter. Runs `nuclei -jsonl -u <target>` against safe targets, else
// returns mock JSONL output (nuclei is frequently not installed in dev).
type Nuclei struct{ opts Options }

func NewNuclei(opts Options) *Nuclei { return &Nuclei{opts: opts} }

func (n *Nuclei) Type() models.ScannerType { return models.ScannerNuclei }

func (n *Nuclei) Scan(ctx context.Context, asset models.Asset) (RawResult, error) {
	res := RawResult{Scanner: models.ScannerNuclei, Format: "nuclei-jsonl"}

	bin, err := exec.LookPath(n.opts.NucleiBin)
	if err != nil || !n.opts.AllowLiveScan || !isSafeTarget(asset.Target) {
		res.Data = mockNucleiJSONL(asset.Target)
		res.Mock = true
		return res, nil
	}

	cmd := exec.CommandContext(ctx, bin, "-jsonl", "-silent", "-u", asset.Target)
	out, runErr := cmd.Output()
	if runErr != nil || len(out) == 0 {
		res.Data = mockNucleiJSONL(asset.Target)
		res.Mock = true
		return res, nil
	}
	res.Data = out
	return res, nil
}

// mockNucleiJSONL returns two newline-delimited JSON findings shaped like real
// nuclei output (template-id, info.severity, classification.cve/cwe, matched-at).
func mockNucleiJSONL(target string) []byte {
	return []byte(`{"template-id":"git-config","info":{"name":"Git Configuration Exposure","severity":"medium","classification":{"cve-id":[],"cwe-id":["CWE-538"]}},"matched-at":"http://` + escapeAttr(target) + `/.git/config"}
{"template-id":"missing-csp","info":{"name":"Missing Content-Security-Policy Header","severity":"low","classification":{"cve-id":[],"cwe-id":["CWE-693"]}},"matched-at":"http://` + escapeAttr(target) + `/"}
{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE (Log4Shell)","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]}},"matched-at":"http://` + escapeAttr(target) + `/api"}`)
}
