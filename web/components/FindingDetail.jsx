"use client";
import { useState } from "react";
import { updateFindingStatus } from "@/lib/api";

function sevClass(s) {
  return ["crit", "critical"].includes(s) ? "crit" : s;
}

const STATUS_ACTIONS = [
  { status: "validated", label: "✓ Validate", hint: "confirmed true positive" },
  { status: "false_positive", label: "✕ False positive", hint: "not exploitable" },
  { status: "remediated", label: "✔ Remediated", hint: "fix applied" },
];

// FindingDetail is a slide-out drawer exposing the full enriched finding:
// description, evidence, CVE/CVSS, the complete compliance mapping and the
// remediation playbook — plus the validation workflow (PATCH status).
export default function FindingDetail({ finding, onClose, onStatusChange }) {
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  if (!finding) return null;
  const f = finding;

  async function setStatus(status) {
    setBusy(status);
    setErr("");
    try {
      await updateFindingStatus(f.id, status);
      onStatusChange?.(f.id, status);
    } catch (e) {
      setErr(String(e.message));
    } finally {
      setBusy("");
    }
  }

  const rem = f.remediation;

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Finding detail">
        <div className="drawer-head">
          <div>
            <div className="row" style={{ gap: 8 }}>
              <span className={`badge ${sevClass(f.severity)}`}>{f.severity}</span>
              {f.known_exploit && <span className="badge kev">KEV</span>}
              <span className={`badge status-${f.status}`}>{f.status}</span>
            </div>
            <h2 style={{ margin: "10px 0 2px" }}>{f.title}</h2>
            <div className="muted" style={{ fontSize: 12 }}>
              {f.scanner}
              {f.service ? ` · ${f.service}` : ""}
              {f.port ? ` · port ${f.port}` : ""}
            </div>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {err && <div className="error">{err}</div>}

        <div className="metricstrip">
          <div>
            <span className="muted">Risk</span>
            <b style={{ color: riskColor(f.risk_score) }}>{f.risk_score}</b>
          </div>
          <div>
            <span className="muted">CVSS</span>
            <b>{f.cvss || "—"}</b>
          </div>
          <div>
            <span className="muted">EPSS</span>
            <b>{f.epss ? `${(f.epss * 100).toFixed(1)}%` : "—"}</b>
          </div>
          <div>
            <span className="muted">CWE</span>
            <b>{f.cwe || "—"}</b>
          </div>
          <div>
            <span className="muted">CVE</span>
            <b>{f.cve || "—"}</b>
          </div>
        </div>

        {f.cvss_vector && (
          <div className="mono muted" style={{ fontSize: 11, marginTop: 6 }}>
            {f.cvss_vector}
          </div>
        )}

        <div className="sla-line">
          <span className="muted">Remediation SLA:</span>{" "}
          {["false_positive", "remediated"].includes(f.status) ? (
            <span className="muted">closed</span>
          ) : f.sla_breached ? (
            <span className="badge crit">breached</span>
          ) : (
            <span className={`badge ${f.sla_days_left <= 7 ? "high" : "low"}`}>
              {f.sla_days_left}d left
            </span>
          )}
          {f.due_date && (
            <span className="muted"> · due {new Date(f.due_date).toLocaleDateString()}</span>
          )}
        </div>

        {f.description && (
          <section>
            <h3>Description</h3>
            <p>{f.description}</p>
          </section>
        )}

        {f.evidence && (
          <section>
            <h3>Evidence</h3>
            <pre className="evidence">{f.evidence}</pre>
          </section>
        )}

        {rem && (
          <section>
            <h3>Remediation</h3>
            {rem.summary && <p>{rem.summary}</p>}
            {rem.steps?.length > 0 && (
              <ol className="steps">
                {rem.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            )}
            {rem.refs?.length > 0 && (
              <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
                Refs: {rem.refs.join(" · ")}
              </div>
            )}
          </section>
        )}

        {f.compliance?.length > 0 && (
          <section>
            <h3>Compliance mapping</h3>
            <table className="compliance">
              <tbody>
                {f.compliance.map((c, i) => (
                  <tr key={i}>
                    <td>
                      <span className="badge framework">{c.framework}</span>
                    </td>
                    <td className="mono">{c.control}</td>
                    <td className="muted">{c.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        <section>
          <h3>Validation workflow</h3>
          <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
            {STATUS_ACTIONS.map((a) => (
              <button
                key={a.status}
                className={f.status === a.status ? "primary" : "ghost"}
                disabled={!!busy}
                title={a.hint}
                onClick={() => setStatus(a.status)}
              >
                {busy === a.status ? "…" : a.label}
              </button>
            ))}
          </div>
        </section>
      </aside>
    </>
  );
}

function riskColor(r) {
  if (r >= 9) return "var(--crit)";
  if (r >= 7) return "var(--high)";
  if (r >= 4) return "var(--med)";
  return "var(--low)";
}
