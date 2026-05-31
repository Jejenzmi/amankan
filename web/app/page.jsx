"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import TopBar from "@/components/TopBar";
import FindingsTable from "@/components/FindingsTable";
import FindingDetail from "@/components/FindingDetail";
import RiskSummary from "@/components/RiskSummary";
import {
  listAssets,
  createAsset,
  startScan,
  getScan,
  listFindings,
  attackPaths,
  downloadFindingsCsv,
} from "@/lib/api";

export default function Dashboard() {
  const [assets, setAssets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [findings, setFindings] = useState(null);
  const [paths, setPaths] = useState(null);
  const [profile, setProfile] = useState("critical");
  const [err, setErr] = useState("");
  const [toast, setToast] = useState("");
  const [scanState, setScanState] = useState(null); // {status, used_mock} of the live scan
  const [detail, setDetail] = useState(null); // finding shown in the drawer
  const [form, setForm] = useState({
    name: "",
    type: "ip",
    target: "",
    criticality: "high",
    tags: "internal",
    scan_authorized: false,
  });
  const pollRef = useRef(false);

  const refreshAssets = useCallback(async () => {
    try {
      setAssets(await listAssets());
    } catch (e) {
      setErr(String(e.message));
    }
  }, []);

  useEffect(() => {
    refreshAssets();
  }, [refreshAssets]);

  const selectAsset = useCallback(async (a) => {
    setSelected(a);
    setFindings(null);
    setPaths(null);
    setDetail(null);
    try {
      setFindings(await listFindings(a.id));
      const p = await attackPaths(a.id).catch(() => null);
      setPaths(p);
    } catch (e) {
      setErr(String(e.message));
    }
  }, []);

  async function onAdd(e) {
    e.preventDefault();
    setErr("");
    try {
      const body = {
        ...form,
        tags: form.tags ? form.tags.split(",").map((t) => t.trim()) : [],
      };
      const a = await createAsset(body);
      setForm({ ...form, name: "", target: "", scan_authorized: false });
      await refreshAssets();
      selectAsset(a);
    } catch (e) {
      setErr(String(e.message));
    }
  }

  // onScan orchestrates a scan and tracks the *actual* job lifecycle: it polls
  // the scan job until it reaches a terminal state, refreshing findings as it
  // goes, instead of guessing with a fixed delay.
  async function onScan(a) {
    setErr("");
    if (pollRef.current) return; // avoid overlapping polls
    try {
      const job = await startScan(a.id, profile);
      setSelected(a);
      setScanState({ status: job.status || "queued" });
      flash(`Scan (${profile}) queued for ${a.name}`);

      pollRef.current = true;
      let terminal = false;
      for (let i = 0; i < 40 && !terminal; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const j = await getScan(job.id).catch(() => null);
        if (j) {
          setScanState({ status: j.status, used_mock: j.used_mock, error: j.error });
          if (["completed", "failed"].includes(j.status)) terminal = true;
        }
        setFindings(await listFindings(a.id).catch(() => findings));
      }
      const p = await attackPaths(a.id).catch(() => null);
      setPaths(p);
      if (!terminal) setScanState((s) => s && { ...s, status: "running" });
    } catch (e) {
      setErr(String(e.message));
      setScanState(null);
    } finally {
      pollRef.current = false;
    }
  }

  function flash(msg) {
    setToast(msg);
    setTimeout(() => setToast(""), 2500);
  }

  // Reflect a status change from the drawer back into the table without a refetch.
  function onStatusChange(id, status) {
    setFindings((fs) => (fs ? fs.map((f) => (f.id === id ? { ...f, status } : f)) : fs));
    setDetail((d) => (d && d.id === id ? { ...d, status } : d));
    flash(`Marked ${status.replace("_", " ")}`);
  }

  return (
    <>
      <TopBar />
      <div className="container">
        {err && <div className="error">{err}</div>}
        <div className="grid">
          {/* left: assets + add form */}
          <div className="panel">
            <h2>Assets ({assets.length})</h2>
            {assets.map((a) => (
              <div
                key={a.id}
                className={`asset-item ${selected?.id === a.id ? "selected" : ""}`}
                onClick={() => selectAsset(a)}
              >
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <span className="name">{a.name}</span>
                  <span className="row" style={{ gap: 4 }}>
                    {a.scan_authorized && (
                      <span className="badge low" title="authorized for active scanning">
                        auth
                      </span>
                    )}
                    <span className={`badge ${a.criticality}`}>{a.criticality}</span>
                  </span>
                </div>
                <div className="meta">
                  {a.type} · {a.target} · {(a.tags || []).join(", ")}
                </div>
                <div style={{ marginTop: 8 }}>
                  <button
                    className="ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      onScan(a);
                    }}
                  >
                    ▶ Scan
                  </button>
                </div>
              </div>
            ))}

            <h3>Register asset</h3>
            <form onSubmit={onAdd}>
              <div className="row" style={{ marginBottom: 8 }}>
                <input
                  placeholder="name"
                  value={form.name}
                  required
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
                <select
                  value={form.type}
                  onChange={(e) => setForm({ ...form, type: e.target.value })}
                >
                  <option value="ip">ip</option>
                  <option value="domain">domain</option>
                  <option value="repo">repo</option>
                </select>
              </div>
              <div className="row" style={{ marginBottom: 8 }}>
                <input
                  placeholder="target (10.0.1.5 / host)"
                  value={form.target}
                  required
                  onChange={(e) => setForm({ ...form, target: e.target.value })}
                />
                <select
                  value={form.criticality}
                  onChange={(e) =>
                    setForm({ ...form, criticality: e.target.value })
                  }
                >
                  <option>low</option>
                  <option>medium</option>
                  <option>high</option>
                  <option>critical</option>
                </select>
              </div>
              <div className="row" style={{ marginBottom: 8 }}>
                <input
                  placeholder="tags (comma): public, internal"
                  value={form.tags}
                  onChange={(e) => setForm({ ...form, tags: e.target.value })}
                  style={{ flex: 1 }}
                />
              </div>
              <label className="row" style={{ marginBottom: 8, fontSize: 12, cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={form.scan_authorized}
                  onChange={(e) => setForm({ ...form, scan_authorized: e.target.checked })}
                  style={{ width: "auto" }}
                />
                I am authorized to actively scan this target
              </label>
              <button className="primary" type="submit">
                + Add asset
              </button>
            </form>
          </div>

          {/* right: findings + attack paths */}
          <div className="panel">
            <div className="toolbar">
              <h2 style={{ margin: 0 }}>
                {selected ? `Findings — ${selected.name}` : "Findings"}
              </h2>
              {scanState && (
                <span className={`scanpill ${scanState.status}`}>
                  <span className="spinner-dot" />
                  {scanState.status}
                  {scanState.used_mock ? " · mock" : ""}
                </span>
              )}
              <div className="row" style={{ marginLeft: "auto" }}>
                <span className="muted">profile</span>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                >
                  <option value="quick">quick (nmap)</option>
                  <option value="web">web (nuclei)</option>
                  <option value="critical">critical (all)</option>
                </select>
                {selected && (
                  <button className="primary" onClick={() => onScan(selected)}>
                    ▶ Scan {selected.name}
                  </button>
                )}
                {findings && findings.length > 0 && (
                  <button
                    className="ghost"
                    onClick={() =>
                      downloadFindingsCsv(selected?.id).catch((e) => setErr(String(e.message)))
                    }
                    title="Download findings as CSV (audit / BSSN report)"
                  >
                    ⤓ CSV
                  </button>
                )}
              </div>
            </div>

            <RiskSummary findings={findings} />

            <FindingsTable
              findings={findings}
              onSelect={setDetail}
              selectedId={detail?.id}
            />

            {paths && paths.count > 0 && (
              <>
                <h3>Attack paths to this asset ({paths.count})</h3>
                {paths.paths.slice(0, 5).map((p, i) => (
                  <div key={i} style={{ marginBottom: 6, fontSize: 13 }}>
                    <span className="badge crit">risk {p.max_risk}</span>{" "}
                    {p.hops.map((h) => h.asset_name).join("  →  ")}
                  </div>
                ))}
                <div style={{ marginTop: 8 }}>
                  <a href="/graph">Open full attack graph →</a>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <FindingDetail
        finding={detail}
        onClose={() => setDetail(null)}
        onStatusChange={onStatusChange}
      />

      {toast && <div className="toast">{toast}</div>}
    </>
  );
}
