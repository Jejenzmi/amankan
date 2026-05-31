// Package engine orchestrates a single scan job end-to-end: load asset, run the
// profile's scanners, normalize + enrich their output, and persist findings.
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/amankan/amankan/internal/compliance"
	"github.com/amankan/amankan/internal/config"
	"github.com/amankan/amankan/internal/graph"
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/normalize"
	"github.com/amankan/amankan/internal/scanner"
	"github.com/amankan/amankan/internal/store"
)

type Processor struct {
	store *store.Store
	graph *graph.Graph // optional; nil when graph integration is disabled
	opts  scanner.Options
	cfg   config.Config
}

// NewProcessor builds a processor. graph may be nil (graph component disabled).
func NewProcessor(st *store.Store, g *graph.Graph, cfg config.Config) *Processor {
	return &Processor{
		store: st,
		graph: g,
		cfg:   cfg,
		opts: scanner.Options{
			NmapBin:        cfg.NmapBin,
			NucleiBin:      cfg.NucleiBin,
			GitleaksBin:    cfg.GitleaksBin,
			AllowLiveScan:  cfg.AllowLiveScan,
			Production:     cfg.IsProduction(),
			ScanAuthorized: cfg.ScanAuthorized,
		},
	}
}

// Process runs one scan job to completion, updating its status and findings.
func (p *Processor) Process(ctx context.Context, scanJobID string) error {
	job, err := p.store.GetScanJob(ctx, scanJobID)
	if err != nil {
		return fmt.Errorf("load job: %w", err)
	}
	asset, err := p.store.GetAsset(ctx, job.AssetID)
	if err != nil {
		return fmt.Errorf("load asset: %w", err)
	}

	if err := p.store.MarkRunning(ctx, job.ID); err != nil {
		return err
	}
	log.Printf("scan %s: running profile=%s asset=%s target=%s", job.ID, job.Profile, asset.Name, asset.Target)

	// Project the asset into the graph so attack-path analysis sees it even if
	// no findings result. Graph errors are non-fatal to the scan.
	if p.graph != nil {
		if err := p.graph.SyncAsset(ctx, *asset); err != nil {
			log.Printf("scan %s: graph sync asset error: %v", job.ID, err)
		}
	}

	scanCtx, cancel := context.WithTimeout(ctx, p.cfg.ScanTimeout)
	defer cancel()

	scanners := scanner.ForProfile(job.Profile, p.opts)
	usedMock := false
	total := 0
	var scanErrs []string
	for _, sc := range scanners {
		raw, err := sc.Scan(scanCtx, *asset)
		if err != nil {
			log.Printf("scan %s: scanner %s error: %v", job.ID, sc.Type(), err)
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", sc.Type(), err))
			continue
		}
		if raw.Mock {
			usedMock = true
		}
		findings, err := normalize.Normalize(raw, *asset, job.ID)
		if err != nil {
			log.Printf("scan %s: normalize %s error: %v", job.ID, sc.Type(), err)
			continue
		}
		for i := range findings {
			if err := p.store.CreateFinding(scanCtx, &findings[i]); err != nil {
				log.Printf("scan %s: persist finding error: %v", job.ID, err)
				continue
			}
			if p.graph != nil {
				if err := p.graph.SyncFinding(scanCtx, findings[i]); err != nil {
					log.Printf("scan %s: graph sync finding error: %v", job.ID, err)
				}
				// A privilege-escalation weakness on this host automatically wires
				// a CAN_ESCALATE (foothold -> root) edge into the privilege graph.
				if compliance.IsPrivEsc(findings[i].CWE) {
					if err := p.graph.AutoDeriveEscalation(scanCtx, asset.ID, findings[i].CWE, findings[i].Title, findings[i].RiskScore); err != nil {
						log.Printf("scan %s: graph auto-escalation error: %v", job.ID, err)
					} else {
						log.Printf("scan %s: auto-derived CAN_ESCALATE on %s from %s (%s)", job.ID, asset.Name, findings[i].Title, findings[i].CWE)
					}
				}
				// A leaked/shared credential automatically wires CREDENTIAL_REUSE
				// edges to every other host exposing the same credential.
				if compliance.IsCredentialLeak(findings[i].CWE) && findings[i].CredFP != "" {
					if n, err := p.graph.AutoDeriveCredentialReuse(scanCtx, asset.ID, findings[i].Principal, findings[i].CredFP, findings[i].Title, findings[i].RiskScore); err != nil {
						log.Printf("scan %s: graph auto-credential-reuse error: %v", job.ID, err)
					} else {
						log.Printf("scan %s: auto-derived CREDENTIAL_REUSE for %q on %s (%d lateral edges total)", job.ID, findings[i].Principal, asset.Name, n)
					}
				}
			}
			total++
		}
	}

	// Derive network reachability (CAN_REACH) to same-subnet peers — a stand-in
	// for an internal network-discovery scan. Honest scope: this only infers
	// host-level L3 reachability within a shared private /24, not the full
	// topology (which would come from a CMDB feed via POST /graph/topology).
	if p.graph != nil && asset.Type == models.AssetIP {
		if n := p.deriveSubnetReachability(scanCtx, *asset); n > 0 {
			log.Printf("scan %s: derived CAN_REACH to %d same-subnet peer(s) of %s", job.ID, n, asset.Name)
		}
	}

	// Fail loudly when every scanner errored and nothing was produced — a scan
	// that ran nothing must not be recorded as a clean "completed" result.
	if total == 0 && len(scanErrs) > 0 {
		msg := "all scanners failed: " + strings.Join(scanErrs, "; ")
		if err := p.store.MarkFailed(ctx, job.ID, msg); err != nil {
			return err
		}
		log.Printf("scan %s: failed — %s", job.ID, msg)
		return nil
	}

	if err := p.store.MarkCompleted(ctx, job.ID, usedMock); err != nil {
		return err
	}
	log.Printf("scan %s: completed, %d findings persisted (mock=%v, scanner_errors=%d)", job.ID, total, usedMock, len(scanErrs))
	return nil
}

// deriveSubnetReachability creates bidirectional CAN_REACH edges between an IP
// asset and other IP assets sharing its private /24, returning the peer count.
func (p *Processor) deriveSubnetReachability(ctx context.Context, asset models.Asset) int {
	assets, err := p.store.ListAssets(ctx)
	if err != nil {
		log.Printf("subnet derivation: list assets: %v", err)
		return 0
	}
	net, ok := privateSubnet24(asset.Target)
	if !ok {
		return 0
	}
	count := 0
	for _, peer := range assets {
		if peer.ID == asset.ID || peer.Type != models.AssetIP {
			continue
		}
		pnet, ok := privateSubnet24(peer.Target)
		if !ok || pnet != net {
			continue
		}
		_ = p.graph.UpsertReachability(ctx, asset.ID, peer.ID, 0, "ip")
		_ = p.graph.UpsertReachability(ctx, peer.ID, asset.ID, 0, "ip")
		count++
	}
	return count
}

// privateSubnet24 returns the /24 prefix (e.g. "10.0.1") of a private IPv4
// target, and whether the target is a private IPv4 address.
func privateSubnet24(target string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil || !ip.IsPrivate() {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", v4[0], v4[1], v4[2]), true
}
