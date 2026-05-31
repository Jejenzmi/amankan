"use client";
import { useEffect, useState } from "react";
import { handleCallback } from "@/lib/oidc";

// OIDC redirect target: exchanges the authorization code for a token, then
// returns to the dashboard.
export default function Callback() {
  const [err, setErr] = useState("");

  useEffect(() => {
    handleCallback()
      .then(() => {
        window.location.replace("/");
      })
      .catch((e) => setErr(String(e.message)));
  }, []);

  return (
    <div className="container">
      <div className="panel">
        {err ? (
          <>
            <h2>Sign-in failed</h2>
            <div className="error">{err}</div>
            <p>
              <a href="/">Return to dashboard</a>
            </p>
          </>
        ) : (
          <h2>Signing you in…</h2>
        )}
      </div>
    </div>
  );
}
