// Package api exposes Amankan's REST surface for the Phase 1 PoC.
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/amankan/amankan/internal/auth"
	"github.com/amankan/amankan/internal/compliance"
	"github.com/amankan/amankan/internal/graph"
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/risk"
	"github.com/amankan/amankan/internal/sla"
	"github.com/amankan/amankan/internal/store"
	"github.com/amankan/amankan/internal/threatintel"
)

type API struct {
	store   *store.Store
	queue   *queue.Queue
	graph   *graph.Graph  // optional; nil when graph integration is disabled
	auth    auth.Provider // API-key Authenticator or OIDC verifier
	opts    Options
	metrics *metrics
}

// Options carries HTTP-hardening configuration into the router.
type Options struct {
	CORSOrigins []string
	RateLimit   float64
}

func New(st *store.Store, q *queue.Queue, g *graph.Graph, a auth.Provider, opts Options) *API {
	if a == nil {
		a, _ = auth.ParseKeys("") // disabled API-key authenticator = open access
	}
	return &API{store: st, queue: q, graph: g, auth: a, opts: opts, metrics: &metrics{}}
}

func (a *API) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(a.observe) // metrics + structured access log
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(auth.SecurityHeaders)
	r.Use(auth.CORS(a.opts.CORSOrigins))
	r.Use(auth.RateLimit(a.opts.RateLimit, nil))
	r.Use(auth.MaxBody(1 << 20)) // cap request bodies at 1 MiB

	r.Get("/healthz", a.health)      // liveness (no dependencies)
	r.Get("/readyz", a.handleReadyz) // readiness (DB + Redis)
	r.Get("/metrics", a.handleMetrics)
	r.Get("/.well-known/security.txt", securityTxt) // RFC 9116 disclosure pointer

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(a.auth.Authenticate) // resolve API key → principal
		r.Use(a.auditMiddleware)   // tamper-evident audit of mutations

		viewer := a.auth.Require(auth.RoleViewer)
		analyst := a.auth.Require(auth.RoleAnalyst)
		admin := a.auth.Require(auth.RoleAdmin)

		// ---- read (viewer+) ----
		r.With(viewer).Get("/assets", a.listAssets)
		r.With(viewer).Get("/assets/{id}", a.getAsset)
		r.With(viewer).Get("/scans", a.listScans)
		r.With(viewer).Get("/scans/{id}", a.getScan)
		r.With(viewer).Get("/findings", a.listFindings) // ?asset_id= &scan_id=
		r.With(viewer).Get("/compliance/cwe/{cwe}", a.complianceForCWE)
		r.With(viewer).Get("/graph/export", a.exportGraph)
		r.With(viewer).Get("/assets/{id}/attack-paths", a.attackPaths) // ?min_risk= &max_hops=
		r.With(viewer).Get("/assets/{id}/accounts", a.listAccounts)
		r.With(viewer).Get("/privesc-path", a.privEscPath) // ?from= &to=

		// ---- operate (analyst+) ----
		r.With(analyst).Post("/assets", a.createAsset)
		r.With(analyst).Post("/assets/{id}/scans", a.startScan)
		r.With(analyst).Patch("/findings/{id}/status", a.updateFindingStatus)
		r.With(analyst).Get("/findings/export", a.exportFindings) // CSV (data egress)

		// ---- administer (admin only) ----
		r.With(admin).Post("/graph/sync", a.graphSync)
		r.With(admin).Post("/graph/topology", a.importTopology)        // bulk CAN_REACH import (CMDB)
		r.With(admin).Post("/assets/{id}/authorize", a.authorizeAsset) // Layer-3 scan permission
		r.With(admin).Post("/assets/{id}/reachability", a.addReachability)
		r.With(admin).Post("/accounts", a.createAccount)
		r.With(admin).Post("/accounts/{id}/escalation", a.addEscalation)
		r.With(admin).Post("/accounts/{id}/credential-reuse", a.addCredentialReuse)
		r.With(admin).Get("/audit", a.listAudit)          // tamper-evident audit log
		r.With(admin).Get("/audit/verify", a.verifyAudit) // hash-chain integrity
	})

	return r
}

// ---- assets ----

func (a *API) createAsset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name           string             `json:"name"`
		Type           models.AssetType   `json:"type"`
		Target         string             `json:"target"`
		Criticality    models.Criticality `json:"criticality"`
		Tags           []string           `json:"tags"`
		ScanAuthorized bool               `json:"scan_authorized"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if in.Name == "" || in.Target == "" {
		badRequest(w, "name and target are required")
		return
	}
	if in.Type == "" {
		in.Type = models.AssetDomain
	}
	if in.Criticality == "" {
		in.Criticality = models.CritMedium
	}
	asset := &models.Asset{Name: in.Name, Type: in.Type, Target: in.Target, Criticality: in.Criticality, Tags: in.Tags, ScanAuthorized: in.ScanAuthorized}
	if err := a.store.CreateAsset(r.Context(), asset); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, asset)
}

func (a *API) listAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := a.store.ListAssets(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paginate(w, r, assets))
}

func (a *API) getAsset(w http.ResponseWriter, r *http.Request) {
	asset, err := a.store.GetAsset(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

// authorizeAsset grants or revokes active-scan authorization for an asset
// (admin only) — the auditable Layer-3 permission record.
func (a *API) authorizeAsset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Authorized bool `json:"authorized"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := a.store.SetAssetAuthorization(r.Context(), chi.URLParam(r, "id"), in.Authorized); err != nil {
		notFoundOrError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": chi.URLParam(r, "id"), "scan_authorized": in.Authorized})
}

// ---- scans ----

func (a *API) startScan(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "id")
	asset, err := a.store.GetAsset(r.Context(), assetID)
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	var in struct {
		Profile models.ScanProfile `json:"profile"`
	}
	_ = decode(r, &in) // body optional
	if in.Profile == "" {
		in.Profile = models.ProfileQuick
	}
	job := &models.ScanJob{AssetID: asset.ID, Profile: in.Profile}
	if err := a.store.CreateScanJob(r.Context(), job); err != nil {
		serverError(w, err)
		return
	}
	if err := a.queue.Enqueue(r.Context(), job.ID); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListScanJobs(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paginate(w, r, jobs))
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetScanJob(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// ---- findings ----

func (a *API) listFindings(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("asset_id")
	scanID := r.URL.Query().Get("scan_id")
	limit, offset := pageParams(r)
	findings, err := a.store.ListFindings(r.Context(), assetID, scanID, limit, offset)
	if err != nil {
		serverError(w, err)
		return
	}
	enrichRuntime(findings)
	writeJSON(w, http.StatusOK, findings)
}

const (
	defaultPageLimit = 200
	maxPageLimit     = 1000
)

// pageParams parses ?limit= & ?offset=, applying a sane default and hard cap so
// list endpoints cannot be coerced into returning unbounded result sets.
func pageParams(r *http.Request) (limit, offset int) {
	limit = defaultPageLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// paginate slices an in-memory list per the request's limit/offset and sets an
// X-Total-Count header so clients can page. Used for the small, internally
// referenced collections (assets, scans) that are not paginated at the DB.
func paginate[T any](w http.ResponseWriter, r *http.Request, items []T) []T {
	limit, offset := pageParams(r)
	w.Header().Set("X-Total-Count", strconv.Itoa(len(items)))
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

// enrichRuntime decorates findings with data that is computed fresh on every
// read rather than persisted: the EPSS exploitation probability (from the
// threat-intel feed) and the severity-driven remediation SLA (due date, breach
// state, days remaining).
func enrichRuntime(findings []models.Finding) {
	now := time.Now().UTC()
	for i := range findings {
		f := &findings[i]
		f.EPSS = threatintel.EPSS(f.CVE)
		if f.CVSSVector == "" {
			f.CVSSVector = risk.RepresentativeVector(f.CWE)
		}
		due := sla.DueDate(f.Severity, f.CreatedAt)
		f.DueDate = &due
		f.SLABreached = sla.Breached(f.Status, f.Severity, f.CreatedAt, now)
		f.SLADaysLeft = sla.DaysRemaining(f.Severity, f.CreatedAt, now)
	}
}

func (a *API) updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status models.FindingStatus `json:"status"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	switch in.Status {
	case models.FindingOpen, models.FindingValidated, models.FindingFalsePositive, models.FindingRemediated:
	default:
		badRequest(w, "invalid status")
		return
	}
	if err := a.store.UpdateFindingStatus(r.Context(), chi.URLParam(r, "id"), in.Status); err != nil {
		notFoundOrError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": string(in.Status)})
}

// exportFindings streams the (optionally filtered) findings as CSV for audit /
// reporting — the enriched view an analyst would attach to a BSSN/ISO ticket.
func (a *API) exportFindings(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("asset_id")
	scanID := r.URL.Query().Get("scan_id")
	findings, err := a.store.ListFindings(r.Context(), assetID, scanID, 0, 0) // full set for the report
	if err != nil {
		serverError(w, err)
		return
	}
	enrichRuntime(findings)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="amankan-findings.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"risk_score", "severity", "known_exploit", "epss", "status", "scanner",
		"title", "cwe", "cve", "cvss", "cvss_vector", "port", "service",
		"due_date", "sla_breached", "iso27001", "bssn", "remediation",
	})
	for _, f := range findings {
		due := ""
		if f.DueDate != nil {
			due = f.DueDate.Format("2006-01-02")
		}
		_ = cw.Write([]string{
			strconv.FormatFloat(f.RiskScore, 'f', -1, 64),
			string(f.Severity),
			strconv.FormatBool(f.KnownExploit),
			strconv.FormatFloat(f.EPSS, 'f', -1, 64),
			string(f.Status),
			string(f.Scanner),
			f.Title,
			f.CWE,
			f.CVE,
			strconv.FormatFloat(f.CVSS, 'f', -1, 64),
			f.CVSSVector,
			strconv.Itoa(f.Port),
			f.Service,
			due,
			strconv.FormatBool(f.SLABreached),
			frameworkControl(f.Compliance, "ISO27001"),
			frameworkControl(f.Compliance, "BSSN"),
			remediationSummary(f.Remediation),
		})
	}
}

// frameworkControl extracts the control id for a given framework from a
// finding's compliance references (empty string if absent).
func frameworkControl(refs []models.ComplianceRef, framework string) string {
	for _, r := range refs {
		if r.Framework == framework {
			return r.Control
		}
	}
	return ""
}

func remediationSummary(rem *models.RemediationGuide) string {
	if rem == nil {
		return ""
	}
	return rem.Summary
}

// ---- compliance ----

func (a *API) complianceForCWE(w http.ResponseWriter, r *http.Request) {
	cwe := chi.URLParam(r, "cwe")
	writeJSON(w, http.StatusOK, map[string]any{
		"cwe":         cwe,
		"compliance":  compliance.Refs(cwe),
		"remediation": compliance.Remediation(cwe),
	})
}

// ---- graph / attack paths ----

// graphSync re-projects all assets and findings from PostgreSQL into Neo4j.
// Useful after enabling the graph on an existing dataset.
func (a *API) graphSync(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	ctx := r.Context()
	assets, err := a.store.ListAssets(ctx)
	if err != nil {
		serverError(w, err)
		return
	}
	syncedAssets, syncedVulns := 0, 0
	for _, as := range assets {
		if err := a.graph.SyncAsset(ctx, as); err != nil {
			serverError(w, err)
			return
		}
		syncedAssets++
		findings, err := a.store.ListFindings(ctx, as.ID, "", 0, 0)
		if err != nil {
			serverError(w, err)
			return
		}
		for _, f := range findings {
			if err := a.graph.SyncFinding(ctx, f); err != nil {
				serverError(w, err)
				return
			}
			syncedVulns++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"assets": syncedAssets, "vulnerabilities": syncedVulns})
}

// importTopology bulk-loads CAN_REACH edges from a CMDB / topology feed. Each
// edge references assets by UUID or by target (IP/domain), so an inventory export
// can be ingested directly without knowing Amankan's internal ids.
func (a *API) importTopology(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	var in struct {
		Edges []struct {
			From  string `json:"from"` // asset id or target
			To    string `json:"to"`   // asset id or target
			Port  int    `json:"port"`
			Proto string `json:"proto"`
		} `json:"edges"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	imported := 0
	var problems []string
	for i, e := range in.Edges {
		src, err := a.resolveAsset(r.Context(), e.From)
		if err != nil {
			problems = append(problems, fmt.Sprintf("edge %d: from %q not found", i, e.From))
			continue
		}
		dst, err := a.resolveAsset(r.Context(), e.To)
		if err != nil {
			problems = append(problems, fmt.Sprintf("edge %d: to %q not found", i, e.To))
			continue
		}
		// Project both endpoints so CAN_REACH attaches even before either is scanned.
		_ = a.graph.SyncAsset(r.Context(), *src)
		_ = a.graph.SyncAsset(r.Context(), *dst)
		proto := e.Proto
		if proto == "" {
			proto = "tcp"
		}
		if err := a.graph.UpsertReachability(r.Context(), src.ID, dst.ID, e.Port, proto); err != nil {
			serverError(w, err)
			return
		}
		imported++
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "problems": problems})
}

// resolveAsset resolves an asset reference that may be a UUID or a target string.
func (a *API) resolveAsset(ctx context.Context, ref string) (*models.Asset, error) {
	if asset, err := a.store.GetAsset(ctx, ref); err == nil {
		return asset, nil
	}
	return a.store.GetAssetByTarget(ctx, ref)
}

// exportGraph returns the full attack graph (nodes + edges) for visualization.
func (a *API) exportGraph(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	g, err := a.graph.ExportGraph(r.Context())
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// addReachability records a network reachability edge (source -> destination),
// a candidate lateral-movement hop used by attack-path analysis.
func (a *API) addReachability(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	srcID := chi.URLParam(r, "id")
	var in struct {
		TargetID string `json:"target_id"`
		Port     int    `json:"port"`
		Proto    string `json:"proto"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if in.TargetID == "" {
		badRequest(w, "target_id is required")
		return
	}
	if in.Proto == "" {
		in.Proto = "tcp"
	}
	// Ensure both assets exist before drawing the edge.
	if _, err := a.store.GetAsset(r.Context(), srcID); err != nil {
		notFoundOrError(w, err)
		return
	}
	if _, err := a.store.GetAsset(r.Context(), in.TargetID); err != nil {
		notFoundOrError(w, err)
		return
	}
	if err := a.graph.UpsertReachability(r.Context(), srcID, in.TargetID, in.Port, in.Proto); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"from": srcID, "to": in.TargetID, "port": in.Port, "proto": in.Proto})
}

// attackPaths returns attack paths that lead to the given asset (the crown jewel).
func (a *API) attackPaths(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	targetID := chi.URLParam(r, "id")
	if _, err := a.store.GetAsset(r.Context(), targetID); err != nil {
		notFoundOrError(w, err)
		return
	}
	minRisk := 7.0
	if v := r.URL.Query().Get("min_risk"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			minRisk = f
		}
	}
	maxHops := 4
	if v := r.URL.Query().Get("max_hops"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxHops = n
		}
	}
	paths, err := a.graph.FindAttackPaths(r.Context(), targetID, minRisk, maxHops)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target_id": targetID,
		"min_risk":  minRisk,
		"max_hops":  maxHops,
		"count":     len(paths),
		"paths":     paths,
	})
}

// ---- accounts / privilege escalation ----

var validPrivileges = map[string]bool{
	"user": true, "service": true, "admin": true, "root": true, "domain_admin": true,
}

// listAccounts returns the accounts (manual + auto-derived) attached to an asset.
func (a *API) listAccounts(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	assetID := chi.URLParam(r, "id")
	if _, err := a.store.GetAsset(r.Context(), assetID); err != nil {
		notFoundOrError(w, err)
		return
	}
	accounts, err := a.graph.ListAccounts(r.Context(), assetID)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

// createAccount registers a principal on an asset in the privilege graph.
func (a *API) createAccount(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	var in struct {
		AssetID   string `json:"asset_id"`
		Username  string `json:"username"`
		Privilege string `json:"privilege"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if in.AssetID == "" || in.Username == "" {
		badRequest(w, "asset_id and username are required")
		return
	}
	if in.Privilege == "" {
		in.Privilege = "user"
	}
	if !validPrivileges[in.Privilege] {
		badRequest(w, "invalid privilege (user|service|admin|root|domain_admin)")
		return
	}
	asset, err := a.store.GetAsset(r.Context(), in.AssetID)
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	// Ensure the asset node exists in the graph before linking an account to it
	// (the asset may not have been scanned/synced yet).
	if err := a.graph.SyncAsset(r.Context(), *asset); err != nil {
		serverError(w, err)
		return
	}
	acc := graph.Account{ID: uuid.NewString(), Username: in.Username, Privilege: in.Privilege, AssetID: in.AssetID}
	if err := a.graph.SyncAccount(r.Context(), acc); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, acc)
}

// addEscalation adds a local privilege-escalation edge between two accounts.
func (a *API) addEscalation(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	var in struct {
		TargetAccountID string  `json:"target_account_id"`
		Technique       string  `json:"technique"`
		CWE             string  `json:"cwe"`
		Weight          float64 `json:"weight"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if in.TargetAccountID == "" {
		badRequest(w, "target_account_id is required")
		return
	}
	if in.Weight <= 0 {
		in.Weight = 1.0 // a known local exploit is cheap by default
	}
	ok, err := a.graph.UpsertEscalation(r.Context(), chi.URLParam(r, "id"), in.TargetAccountID, in.Technique, in.CWE, in.Weight)
	if err != nil {
		serverError(w, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "one or both accounts not found"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"from": chi.URLParam(r, "id"), "to": in.TargetAccountID,
		"type": "CAN_ESCALATE", "technique": in.Technique, "weight": in.Weight,
	})
}

// addCredentialReuse adds a lateral credential-reuse edge between two accounts.
func (a *API) addCredentialReuse(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	var in struct {
		TargetAccountID string  `json:"target_account_id"`
		Weight          float64 `json:"weight"`
	}
	if err := decode(r, &in); err != nil {
		badRequest(w, err.Error())
		return
	}
	if in.TargetAccountID == "" {
		badRequest(w, "target_account_id is required")
		return
	}
	if in.Weight <= 0 {
		in.Weight = 3.0 // credential reuse is plausible but costlier than a local exploit
	}
	ok, err := a.graph.UpsertCredentialReuse(r.Context(), chi.URLParam(r, "id"), in.TargetAccountID, in.Weight)
	if err != nil {
		serverError(w, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "one or both accounts not found"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"from": chi.URLParam(r, "id"), "to": in.TargetAccountID,
		"type": "CREDENTIAL_REUSE", "weight": in.Weight,
	})
}

// privEscPath returns the minimum-effort privilege-escalation path between two accounts.
func (a *API) privEscPath(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		graphDisabled(w)
		return
	}
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" || to == "" {
		badRequest(w, "from and to query params are required")
		return
	}
	path, err := a.graph.FindPrivEscPath(r.Context(), from, to)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, path)
}

func graphDisabled(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "graph component disabled (set AMANKAN_NEO4J_URI)"})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// securityTxt serves an RFC 9116 vulnerability-disclosure pointer.
func securityTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(
		"Contact: mailto:security@amankan.example\n" +
			"Expires: 2027-12-31T23:59:59Z\n" +
			"Preferred-Languages: en, id\n" +
			"Policy: https://github.com/amankan/amankan/blob/main/SECURITY.md\n"))
}

// ---- helpers ----

func decode(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func serverError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func notFoundOrError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	serverError(w, err)
}
