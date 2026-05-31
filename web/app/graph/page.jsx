import TopBar from "@/components/TopBar";
import AttackGraph from "@/components/AttackGraph";

export default function GraphPage() {
  return (
    <>
      <TopBar />
      <div className="container">
        <div className="panel">
          <h2>Attack Graph — assets, accounts, escalation &amp; lateral movement</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
            Network reachability (CAN_REACH), local privilege escalation
            (CAN_ESCALATE) and credential reuse (CREDENTIAL_REUSE) — most of it
            derived automatically from scan findings.
          </p>
          <AttackGraph />
        </div>
      </div>
    </>
  );
}
