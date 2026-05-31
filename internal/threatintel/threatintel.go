// Package threatintel provides threat-intelligence enrichment: whether a CVE is
// known-exploited (CISA KEV) and its EPSS exploitation-probability score. It
// ships with a small embedded fallback set so scoring works offline, and can
// ingest full CISA KEV (JSON) and EPSS (CSV) feeds at startup for production
// fidelity.
package threatintel

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default upstream feeds (CISA KEV catalog + FIRST.org current EPSS scores).
const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// defaultKEV is the offline fallback set of known-exploited CVEs. In production
// this is dwarfed by the loaded CISA KEV feed (~1000+ entries).
var defaultKEV = map[string]bool{
	"CVE-2021-44228": true, // Log4Shell
	"CVE-2021-4034":  true, // PwnKit (polkit pkexec LPE)
	"CVE-2017-0144":  true, // EternalBlue
	"CVE-2014-0160":  true, // Heartbleed
	"CVE-2019-0708":  true, // BlueKeep
	"CVE-2020-1472":  true, // Zerologon
	"CVE-2021-34527": true, // PrintNightmare
	"CVE-2022-1388":  true, // F5 BIG-IP iControl REST
	"CVE-2023-23397": true, // Outlook privilege escalation
	"CVE-2023-34362": true, // MOVEit Transfer SQLi
}

// Feed holds the active threat-intel data behind a read-write lock so it can be
// hot-reloaded without races.
type Feed struct {
	mu   sync.RWMutex
	kev  map[string]bool
	epss map[string]float64
}

var global = &Feed{kev: copyBoolMap(defaultKEV), epss: map[string]float64{}}

// IsKEV reports whether any of the (possibly comma-joined) CVEs is known-exploited.
func IsKEV(cve string) bool { return global.IsKEV(cve) }

// EPSS returns the highest EPSS probability (0..1) across the CVE(s), 0 if unknown.
func EPSS(cve string) float64 { return global.EPSS(cve) }

// Load replaces the global feed from the given files; empty paths are skipped.
// It returns the number of KEV and EPSS records loaded.
func Load(kevPath, epssPath string) (kevN, epssN int, err error) {
	return global.Load(kevPath, epssPath)
}

func (f *Feed) IsKEV(cve string) bool {
	if cve == "" {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, c := range strings.Split(cve, ",") {
		if f.kev[strings.TrimSpace(c)] {
			return true
		}
	}
	return false
}

func (f *Feed) EPSS(cve string) float64 {
	if cve == "" {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	max := 0.0
	for _, c := range strings.Split(cve, ",") {
		if v := f.epss[strings.TrimSpace(c)]; v > max {
			max = v
		}
	}
	return max
}

func (f *Feed) Load(kevPath, epssPath string) (int, int, error) {
	kev := copyBoolMap(defaultKEV)
	epss := map[string]float64{}

	if kevPath != "" {
		ids, err := parseKEV(kevPath)
		if err != nil {
			return 0, 0, err
		}
		for _, id := range ids {
			kev[id] = true
		}
	}
	if epssPath != "" {
		m, err := parseEPSS(epssPath)
		if err != nil {
			return 0, 0, err
		}
		epss = m
	}

	f.mu.Lock()
	f.kev = kev
	f.epss = epss
	f.mu.Unlock()
	return len(kev), len(epss), nil
}

// parseKEV reads a CISA KEV JSON export: {"vulnerabilities":[{"cveID":"..."}]}.
func parseKEV(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if id := strings.TrimSpace(v.CveID); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// parseEPSS reads a FIRST.org EPSS CSV (cve,epss,percentile), skipping the
// leading "#"-prefixed metadata lines and the header row.
func parseEPSS(path string) (map[string]float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 || !strings.HasPrefix(strings.ToUpper(parts[0]), "CVE-") {
			continue // header or noise
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
			out[strings.TrimSpace(parts[0])] = v
		}
	}
	return out, sc.Err()
}

// FetchAndLoad downloads the KEV (JSON) and EPSS (gzipped CSV) feeds over HTTP
// and replaces the global feed. On any error the existing feed is left intact
// (caller should fall back to the embedded set). Empty URLs are skipped.
func FetchAndLoad(ctx context.Context, kevURL, epssURL string, timeout time.Duration) (int, int, error) {
	return global.FetchAndLoad(ctx, kevURL, epssURL, timeout)
}

func (f *Feed) FetchAndLoad(ctx context.Context, kevURL, epssURL string, timeout time.Duration) (int, int, error) {
	client := &http.Client{Timeout: timeout}
	kev := copyBoolMap(defaultKEV)
	epss := map[string]float64{}

	if kevURL != "" {
		body, err := fetch(ctx, client, kevURL)
		if err != nil {
			return 0, 0, fmt.Errorf("fetch KEV: %w", err)
		}
		ids, err := decodeKEV(body)
		if err != nil {
			return 0, 0, fmt.Errorf("parse KEV: %w", err)
		}
		for _, id := range ids {
			kev[id] = true
		}
	}
	if epssURL != "" {
		body, err := fetch(ctx, client, epssURL)
		if err != nil {
			return 0, 0, fmt.Errorf("fetch EPSS: %w", err)
		}
		if strings.HasSuffix(epssURL, ".gz") {
			gz, gerr := gzip.NewReader(strings.NewReader(string(body)))
			if gerr != nil {
				return 0, 0, fmt.Errorf("gunzip EPSS: %w", gerr)
			}
			defer gz.Close()
			if body, err = io.ReadAll(gz); err != nil {
				return 0, 0, fmt.Errorf("read EPSS gz: %w", err)
			}
		}
		epss = decodeEPSS(body)
	}

	f.mu.Lock()
	f.kev = kev
	f.epss = epss
	f.mu.Unlock()
	return len(kev), len(epss), nil
}

func fetch(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // cap at 64 MiB
}

func decodeKEV(data []byte) ([]string, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if id := strings.TrimSpace(v.CveID); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

func decodeEPSS(data []byte) map[string]float64 {
	out := map[string]float64{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 || !strings.HasPrefix(strings.ToUpper(parts[0]), "CVE-") {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
			out[strings.TrimSpace(parts[0])] = v
		}
	}
	return out
}

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
