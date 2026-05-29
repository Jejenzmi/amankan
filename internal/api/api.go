// Package api exposes Amankan's REST surface for the Phase 1 PoC.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/amankan/amankan/internal/compliance"
	"github.com/amankan/amankan/internal/graph"
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/store"
)

type API struct {
	store *store.Store
	queue *queue.Queue
	graph *graph.Graph // optional; nil when graph integration is disabled
}

func New(st *store.Store, q *queue.Queue, g *graph.Graph) *API {
	return &API{store: st, queue: q, graph: g}
}

func (a *API) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", a.health)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/assets", a.listAssets)
		r.Post("/assets", a.createAsset)
		r.Get("/assets/{id}", a.getAsset)

		r.Post("/assets/{id}/scans", a.startScan) // orchestrate a scan for an asset
		r.Get("/scans", a.listScans)
		r.Get("/scans/{id}", a.getScan)

		r.Get("/findings", a.listFindings) // ?asset_id= &scan_id=
		r.Patch("/findings/{id}/status", a.updateFindingStatus)

		r.Get("/compliance/cwe/{cwe}", a.complianceForCWE)

		// Graph Analysis Engine (attack paths / lateral movement).
		r.Post("/graph/sync", a.graphSync)
		r.Post("/assets/{id}/reachability", a.addReachability)
		r.Get("/assets/{id}/attack-paths", a.attackPaths) // ?min_risk= &max_hops=

		// Privilege-escalation graph (accounts + weighted escalation/reuse edges).
		r.Post("/accounts", a.createAccount)
		r.Post("/accounts/{id}/escalation", a.addEscalation)
		r.Post("/accounts/{id}/credential-reuse", a.addCredentialReuse)
		r.Get("/privesc-path", a.privEscPath) // ?from= &to=
	})

	return r
}

// ---- assets ----

func (a *API) createAsset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string             `json:"name"`
		Type        models.AssetType   `json:"type"`
		Target      string             `json:"target"`
		Criticality models.Criticality `json:"criticality"`
		Tags        []string           `json:"tags"`
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
	asset := &models.Asset{Name: in.Name, Type: in.Type, Target: in.Target, Criticality: in.Criticality, Tags: in.Tags}
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
	writeJSON(w, http.StatusOK, assets)
}

func (a *API) getAsset(w http.ResponseWriter, r *http.Request) {
	asset, err := a.store.GetAsset(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		notFoundOrError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, asset)
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
	writeJSON(w, http.StatusOK, jobs)
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
	findings, err := a.store.ListFindings(r.Context(), assetID, scanID)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, findings)
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
		findings, err := a.store.ListFindings(ctx, as.ID, "")
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
