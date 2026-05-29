// Package api exposes Amankan's REST surface for the Phase 1 PoC.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amankan/amankan/internal/compliance"
	"github.com/amankan/amankan/internal/models"
	"github.com/amankan/amankan/internal/queue"
	"github.com/amankan/amankan/internal/store"
)

type API struct {
	store *store.Store
	queue *queue.Queue
}

func New(st *store.Store, q *queue.Queue) *API {
	return &API{store: st, queue: q}
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
