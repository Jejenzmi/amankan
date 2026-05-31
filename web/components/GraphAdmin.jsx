"use client";
import { useState } from "react";
import { graphSync, importTopology } from "@/lib/api";

const SAMPLE = `[
  { "from": "10.0.1.10", "to": "10.0.2.20", "port": 443 },
  { "from": "10.0.2.20", "to": "10.0.3.30", "port": 5432 }
]`;

// GraphAdmin surfaces the two graph-maintenance endpoints that previously
// required curl: re-projecting Postgres into Neo4j, and bulk-importing
// CAN_REACH edges from a CMDB / topology feed.
export default function GraphAdmin({ onDone }) {
  const [edges, setEdges] = useState("");
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  function flash(m) {
    setMsg(m);
    setErr("");
    setTimeout(() => setMsg(""), 4000);
  }

  async function onSync() {
    setBusy("sync");
    setErr("");
    try {
      const r = await graphSync();
      flash(`Synced ${r.assets} assets · ${r.vulnerabilities} vulnerabilities into the graph.`);
      onDone?.();
    } catch (e) {
      setErr(String(e.message));
    } finally {
      setBusy("");
    }
  }

  async function onImport() {
    setBusy("import");
    setErr("");
    let parsed;
    try {
      parsed = JSON.parse(edges);
      if (!Array.isArray(parsed)) throw new Error("expected a JSON array of edges");
    } catch (e) {
      setErr("Invalid JSON: " + e.message);
      setBusy("");
      return;
    }
    try {
      const r = await importTopology(parsed);
      const probs = r.problems?.length ? ` (${r.problems.length} skipped)` : "";
      flash(`Imported ${r.imported} CAN_REACH edge(s)${probs}.`);
      if (r.problems?.length) setErr(r.problems.join("\n"));
      onDone?.();
    } catch (e) {
      setErr(String(e.message));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="panel" style={{ marginTop: 18 }}>
      <h2>Graph administration</h2>
      <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
        Maintain the Neo4j attack graph. Requires the graph component enabled
        (<span className="mono">AMANKAN_NEO4J_URI</span>); otherwise these return 503.
      </p>

      {msg && <div className="ok-msg">{msg}</div>}
      {err && <div className="error" style={{ whiteSpace: "pre-wrap" }}>{err}</div>}

      <div className="row" style={{ margin: "10px 0" }}>
        <button className="primary" onClick={onSync} disabled={!!busy}>
          {busy === "sync" ? "Syncing…" : "↻ Re-project assets + findings into graph"}
        </button>
      </div>

      <h3>Import topology (CMDB feed)</h3>
      <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
        Bulk-load network reachability. Each edge references assets by id or by
        target (IP/domain).
      </p>
      <textarea
        className="code-input"
        rows={7}
        placeholder={SAMPLE}
        value={edges}
        onChange={(e) => setEdges(e.target.value)}
      />
      <div className="row" style={{ marginTop: 8 }}>
        <button className="primary" onClick={onImport} disabled={!!busy || !edges.trim()}>
          {busy === "import" ? "Importing…" : "↑ Import edges"}
        </button>
        <button className="ghost" onClick={() => setEdges(SAMPLE)} disabled={!!busy}>
          Fill sample
        </button>
      </div>
    </div>
  );
}
