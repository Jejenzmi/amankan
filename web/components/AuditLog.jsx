"use client";
import { useState } from "react";
import { listAudit, verifyAudit } from "@/lib/api";

// AuditLog views the tamper-evident audit trail and runs the hash-chain
// integrity check. Admin-only on the backend; if the caller lacks the role (or
// auth is off and the log is empty) it degrades to a friendly message.
export default function AuditLog() {
  const [entries, setEntries] = useState(null);
  const [verdict, setVerdict] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setErr("");
    try {
      setEntries(await listAudit(100));
    } catch (e) {
      setErr(String(e.message));
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setErr("");
    try {
      setVerdict(await verifyAudit());
    } catch (e) {
      setErr(String(e.message));
    }
  }

  return (
    <div className="panel" style={{ marginTop: 18 }}>
      <div className="toolbar">
        <h2 style={{ margin: 0 }}>Audit trail (tamper-evident)</h2>
        <div className="row" style={{ marginLeft: "auto" }}>
          <button className="ghost" onClick={load} disabled={busy}>
            {busy ? "Loading…" : "Load"}
          </button>
          <button className="primary" onClick={verify}>
            ✓ Verify chain
          </button>
        </div>
      </div>
      <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
        Append-only, SHA-256 hash-chained record of every state-changing action
        (ISO 27001 A.8.15 · SOC 2 CC7 · BSSN forensic retention). Admin role.
      </p>

      {err && <div className="error">{err}</div>}
      {verdict && (
        <div className={verdict.intact ? "ok-msg" : "error"}>
          {verdict.intact
            ? `✓ Chain intact across ${verdict.entries} entries.`
            : `✗ Chain BROKEN at sequence ${verdict.broken_at_seq}.`}
        </div>
      )}

      {entries && entries.length === 0 && (
        <div className="empty">No audited actions yet.</div>
      )}
      {entries && entries.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Actor</th>
              <th>Role</th>
              <th>Action</th>
              <th>Status</th>
              <th>Hash</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq}>
                <td className="muted">{e.seq}</td>
                <td className="muted">{new Date(e.ts).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td className="muted">{e.role}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {e.method} {e.path}
                </td>
                <td className="muted">{e.status}</td>
                <td className="mono muted" style={{ fontSize: 11 }} title={e.hash}>
                  {String(e.hash).slice(0, 10)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
