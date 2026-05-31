// Minimal OIDC Authorization-Code + PKCE client for a public SPA (Keycloak).
// No external dependencies — uses the Web Crypto API. SSR-safe (guards window).
//
// Configure via env:
//   NEXT_PUBLIC_OIDC_ISSUER    e.g. https://keycloak.example/realms/amankan
//   NEXT_PUBLIC_OIDC_CLIENT_ID e.g. amankan-dashboard
//   NEXT_PUBLIC_OIDC_REDIRECT  (optional) defaults to <origin>/callback

const ISSUER = process.env.NEXT_PUBLIC_OIDC_ISSUER || "";
const CLIENT_ID = process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || "";

export function oidcEnabled() {
  return Boolean(ISSUER && CLIENT_ID);
}

function redirectUri() {
  if (typeof window === "undefined") return "";
  return process.env.NEXT_PUBLIC_OIDC_REDIRECT || window.location.origin + "/callback";
}

const authzEndpoint = () => `${ISSUER}/protocol/openid-connect/auth`;
const tokenEndpoint = () => `${ISSUER}/protocol/openid-connect/token`;
const logoutEndpoint = () => `${ISSUER}/protocol/openid-connect/logout`;

// ---- token storage ----
const TOKEN_KEY = "amankan_oidc";

export function getToken() {
  if (typeof window === "undefined") return "";
  try {
    const raw = localStorage.getItem(TOKEN_KEY);
    if (!raw) return "";
    const t = JSON.parse(raw);
    if (!t.access_token || (t.expires_at && Date.now() >= t.expires_at)) {
      return "";
    }
    return t.access_token;
  } catch {
    return "";
  }
}

export function isAuthenticated() {
  return Boolean(getToken());
}

function storeToken(tok) {
  const expires_at = tok.expires_in ? Date.now() + (tok.expires_in - 30) * 1000 : 0;
  localStorage.setItem(TOKEN_KEY, JSON.stringify({ access_token: tok.access_token, expires_at }));
}

// ---- PKCE helpers ----
function randomString(len = 64) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

function base64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(str) {
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64url(new Uint8Array(digest));
}

// ---- flow ----
export async function login() {
  if (!oidcEnabled()) return;
  const verifier = randomString(48);
  const state = randomString(16);
  sessionStorage.setItem("amankan_pkce_verifier", verifier);
  sessionStorage.setItem("amankan_pkce_state", state);
  const challenge = await sha256(verifier);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: "openid profile",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  window.location.href = `${authzEndpoint()}?${params.toString()}`;
}

// handleCallback exchanges the authorization code for tokens. Returns true on success.
export async function handleCallback() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const verifier = sessionStorage.getItem("amankan_pkce_verifier");
  const expectedState = sessionStorage.getItem("amankan_pkce_state");
  if (!code || !verifier || state !== expectedState) {
    throw new Error("invalid OIDC callback (state mismatch or missing code)");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(),
    client_id: CLIENT_ID,
    code_verifier: verifier,
  });
  const res = await fetch(tokenEndpoint(), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status} ${await res.text()}`);
  storeToken(await res.json());
  sessionStorage.removeItem("amankan_pkce_verifier");
  sessionStorage.removeItem("amankan_pkce_state");
  return true;
}

export function logout() {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  if (oidcEnabled()) {
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      post_logout_redirect_uri: window.location.origin,
    });
    window.location.href = `${logoutEndpoint()}?${params.toString()}`;
  }
}
