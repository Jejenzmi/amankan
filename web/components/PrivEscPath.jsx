"use client";

// PrivEscPath renders the Dijkstra result: the interleaved chain of accounts and
// the escalation/reuse steps between them, plus the total attacker effort.
export default function PrivEscPath({ path }) {
  if (!path) return null;
  if (!path.found) {
    return (
      <div className="empty" style={{ padding: 18 }}>
        No escalation path exists between those accounts.
      </div>
    );
  }
  const accts = path.accounts || [];
  const steps = path.steps || [];

  return (
    <div className="privesc-result">
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="badge crit">cost {path.total_cost}</span>
        <span className="muted">total attacker effort · {steps.length} step(s)</span>
      </div>
      <div className="chain">
        {accts.map((a, i) => (
          <div key={a.account_id || i}>
            <div className="chain-node">
              <span className="dot" style={{ background: privColor(a.privilege) }} />
              <b>{a.username}</b>
              <span className="muted">@{a.asset || "?"}</span>
              <span className="badge framework">{a.privilege}</span>
            </div>
            {i < steps.length && (
              <div className="chain-step">
                <span className={`edge-tag ${steps[i].type}`}>{steps[i].type}</span>
                {steps[i].technique ? ` ${steps[i].technique}` : ""}
                {steps[i].cwe ? ` (${steps[i].cwe})` : ""}
                <span className="muted"> · weight {steps[i].weight}</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function privColor(p) {
  if (["root", "domain_admin"].includes(p)) return "var(--crit)";
  if (["admin", "service"].includes(p)) return "var(--high)";
  return "var(--low)";
}
