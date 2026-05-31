"use client";

function sevClass(s) {
  return ["crit", "critical"].includes(s) ? "crit" : s;
}

export default function FindingsTable({ findings, onSelect, selectedId }) {
  if (!findings) return <div className="empty">Select an asset to view findings.</div>;
  if (findings.length === 0)
    return <div className="empty">No findings yet — run a scan.</div>;

  return (
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>Severity</th>
          <th>Scanner</th>
          <th>Finding</th>
          <th>CWE</th>
          <th>SLA</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr
            key={f.id}
            className={`finding-row ${selectedId === f.id ? "selected" : ""}`}
            onClick={() => onSelect?.(f)}
          >
            <td className="risk" style={{ color: riskColor(f.risk_score) }}>
              {f.risk_score}
            </td>
            <td>
              <span className={`badge ${sevClass(f.severity)}`}>{f.severity}</span>
              {f.known_exploit && <span className="badge kev">KEV</span>}
            </td>
            <td className="muted">{f.scanner}</td>
            <td>{f.title}</td>
            <td className="muted">{f.cwe || "—"}</td>
            <td>{slaCell(f)}</td>
            <td>
              <span className={`badge status-${f.status}`}>{f.status}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function riskColor(r) {
  if (r >= 9) return "var(--crit)";
  if (r >= 7) return "var(--high)";
  if (r >= 4) return "var(--med)";
  return "var(--low)";
}

// slaCell renders the remediation SLA state: a breach badge, or days remaining.
// Resolved findings (false-positive / remediated) show a neutral dash.
function slaCell(f) {
  if (["false_positive", "remediated"].includes(f.status)) {
    return <span className="muted">—</span>;
  }
  if (f.sla_breached) {
    return <span className="badge crit">breached</span>;
  }
  const d = f.sla_days_left;
  if (d == null) return <span className="muted">—</span>;
  const cls = d <= 7 ? "high" : "low";
  return <span className={`badge ${cls}`}>{d}d left</span>;
}
