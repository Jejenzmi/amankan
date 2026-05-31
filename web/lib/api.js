// Thin client for the Amankan REST API. Base URL is configurable so the
// dashboard can point at any deployment.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8080";

// Optional API key for when the backend has API-key auth enabled
// (AMANKAN_API_KEYS). Used as a fallback when OIDC is not configured.
import { oidcEnabled, getToken } from "@/lib/oidc";

const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

// authHeaders prefers an OIDC bearer token (Keycloak login) when OIDC is
// configured, falling back to a static API key otherwise.
function authHeaders() {
  if (oidcEnabled()) {
    const tok = getToken();
    return tok ? { Authorization: `Bearer ${tok}` } : {};
  }
  return API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {};
}

async function req(path, opts = {}) {
  const res = await fetch(API_BASE + path, {
    headers: { "Content-Type": "application/json", ...authHeaders() },
    cache: "no-store",
    ...opts,
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

export const listAssets = () => req("/api/v1/assets");
export const createAsset = (body) =>
  req("/api/v1/assets", { method: "POST", body: JSON.stringify(body) });
export const startScan = (assetId, profile) =>
  req(`/api/v1/assets/${assetId}/scans`, {
    method: "POST",
    body: JSON.stringify({ profile }),
  });
export const listScans = () => req("/api/v1/scans");
export const getScan = (scanId) => req(`/api/v1/scans/${scanId}`);
export const listFindings = (assetId) =>
  req(`/api/v1/findings?limit=1000${assetId ? `&asset_id=${assetId}` : ""}`);
export const updateFindingStatus = (findingId, status) =>
  req(`/api/v1/findings/${findingId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
export const attackPaths = (assetId, minRisk = 7, maxHops = 5) =>
  req(`/api/v1/assets/${assetId}/attack-paths?min_risk=${minRisk}&max_hops=${maxHops}`);
export const exportGraph = () => req("/api/v1/graph/export");

// Download findings as CSV. Uses fetch (not a plain link) so the API key header
// is sent when auth is enabled, then streams the response to a file download.
export async function downloadFindingsCsv(assetId) {
  const url = `${API_BASE}/api/v1/findings/export${assetId ? `?asset_id=${assetId}` : ""}`;
  const res = await fetch(url, { headers: authHeaders(), cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = "amankan-findings.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(href);
}

// ---- audit (admin) ----
export const listAudit = (limit = 100) => req(`/api/v1/audit?limit=${limit}`);
export const verifyAudit = () => req("/api/v1/audit/verify");

// ---- graph admin ----
export const graphSync = () =>
  req("/api/v1/graph/sync", { method: "POST" });
export const importTopology = (edges) =>
  req("/api/v1/graph/topology", { method: "POST", body: JSON.stringify({ edges }) });

// ---- accounts / privilege escalation ----
export const listAccounts = (assetId) =>
  req(`/api/v1/assets/${assetId}/accounts`);
export const createAccount = (body) =>
  req("/api/v1/accounts", { method: "POST", body: JSON.stringify(body) });
export const addEscalation = (accountId, body) =>
  req(`/api/v1/accounts/${accountId}/escalation`, {
    method: "POST",
    body: JSON.stringify(body),
  });
export const addCredentialReuse = (accountId, body) =>
  req(`/api/v1/accounts/${accountId}/credential-reuse`, {
    method: "POST",
    body: JSON.stringify(body),
  });
export const privEscPath = (fromId, toId) =>
  req(`/api/v1/privesc-path?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`);
