"use client";

// RiskSummary distills a finding set into a one-glance posture strip:
// counts per severity, KEV (known-exploited) count and the peak risk score.
export default function RiskSummary({ findings }) {
  if (!findings || findings.length === 0) return null;

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let kev = 0;
  let peak = 0;
  let open = 0;
  let overdue = 0;
  for (const f of findings) {
    const s = f.severity === "crit" ? "critical" : f.severity;
    if (counts[s] !== undefined) counts[s]++;
    if (f.known_exploit) kev++;
    if (f.risk_score > peak) peak = f.risk_score;
    if (f.status === "open") open++;
    if (f.sla_breached) overdue++;
  }

  const sevs = [
    ["critical", "crit"],
    ["high", "high"],
    ["medium", "medium"],
    ["low", "low"],
    ["info", "info"],
  ];

  return (
    <div className="summary">
      <div className="stat">
        <span className="num">{findings.length}</span>
        <span className="lbl">findings</span>
      </div>
      <div className="stat">
        <span className="num" style={{ color: riskColor(peak) }}>{peak}</span>
        <span className="lbl">peak risk</span>
      </div>
      <div className="stat">
        <span className="num" style={{ color: kev ? "var(--crit)" : "var(--text)" }}>
          {kev}
        </span>
        <span className="lbl">KEV</span>
      </div>
      <div className="stat">
        <span className="num">{open}</span>
        <span className="lbl">open</span>
      </div>
      <div className="stat">
        <span className="num" style={{ color: overdue ? "var(--crit)" : "var(--text)" }}>
          {overdue}
        </span>
        <span className="lbl">SLA overdue</span>
      </div>
      <div className="sevbar">
        {sevs.map(([s, cls]) =>
          counts[s] > 0 ? (
            <span key={s} className={`badge ${cls}`}>
              {counts[s]} {s}
            </span>
          ) : null
        )}
      </div>
    </div>
  );
}

function riskColor(r) {
  if (r >= 9) return "var(--crit)";
  if (r >= 7) return "var(--high)";
  if (r >= 4) return "var(--med)";
  return "var(--low)";
}
