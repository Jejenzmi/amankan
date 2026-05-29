// Package engine orchestrates a single scan job end-to-end: load asset, run the
// profile's scanners, normalize + enrich their output, and persist findings.
package engine

import (
	"context"
	"fmt"
	"log"

	"github.com/amankan/amankan/internal/config"
	"github.com/amankan/amankan/internal/normalize"
	"github.com/amankan/amankan/internal/scanner"
	"github.com/amankan/amankan/internal/store"
)

type Processor struct {
	store *store.Store
	opts  scanner.Options
	cfg   config.Config
}

func NewProcessor(st *store.Store, cfg config.Config) *Processor {
	return &Processor{
		store: st,
		cfg:   cfg,
		opts: scanner.Options{
			NmapBin:       cfg.NmapBin,
			NucleiBin:     cfg.NucleiBin,
			AllowLiveScan: cfg.AllowLiveScan,
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

	scanCtx, cancel := context.WithTimeout(ctx, p.cfg.ScanTimeout)
	defer cancel()

	scanners := scanner.ForProfile(job.Profile, p.opts)
	usedMock := false
	total := 0
	for _, sc := range scanners {
		raw, err := sc.Scan(scanCtx, *asset)
		if err != nil {
			log.Printf("scan %s: scanner %s error: %v", job.ID, sc.Type(), err)
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
			total++
		}
	}

	if err := p.store.MarkCompleted(ctx, job.ID, usedMock); err != nil {
		return err
	}
	log.Printf("scan %s: completed, %d findings persisted (mock=%v)", job.ID, total, usedMock)
	return nil
}
