"use client";
import { useEffect, useState, useCallback } from "react";
import TopBar from "@/components/TopBar";
import GraphAdmin from "@/components/GraphAdmin";
import AuditLog from "@/components/AuditLog";
import { listScans, listAssets } from "@/lib/api";

function fmtTime(t) {
  if (!t) return "—";
  const d = new Date(t);
  return isNaN(d) ? "—" : d.toLocaleString();
}

function duration(job) {
  if (!job.started_at) return "—";
  const end = job.finished_at ? new Date(job.finished_at) : new Date();
  const ms = end - new Date(job.started_at);
  if (isNaN(ms) || ms < 0) return "—";
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState({});
  const [err, setErr] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([listScans(), listAssets()]);
      setScans(s || []);
      setAssets(Object.fromEntries((a || []).map((x) => [x.id, x])));
    } catch (e) {
      setErr(String(e.message));
    }
  }, []);

  useEffect(() => {
    refresh();
    // keep the view live while jobs are queued/running
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  const active = scans.filter((s) => ["queued", "running"].includes(s.status)).length;

  return (
    <>
      <TopBar />
      <div className="container">
        {err && <div className="error">{err}</div>}
        <div className="panel">
          <div className="toolbar">
            <h2 style={{ margin: 0 }}>Scan history ({scans.length})</h2>
            {active > 0 && (
              <span className="scanpill running">
                <span className="spinner-dot" />
                {active} active
              </span>
            )}
            <button className="ghost" style={{ marginLeft: "auto" }} onClick={refresh}>
              ↻ Refresh
            </button>
          </div>

          {scans.length === 0 ? (
            <div className="empty">No scans yet — launch one from Assets &amp; Findings.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Asset</th>
                  <th>Profile</th>
                  <th>Scanners</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td className="muted">{fmtTime(s.created_at)}</td>
                    <td>{assets[s.asset_id]?.name || s.asset_id.slice(0, 8)}</td>
                    <td>{s.profile}</td>
                    <td className="muted">{(s.scanners || []).join(", ") || "—"}</td>
                    <td>
                      <span className={`scanpill ${s.status}`}>
                        {["queued", "running"].includes(s.status) && (
                          <span className="spinner-dot" />
                        )}
                        {s.status}
                      </span>
                      {s.error && (
                        <div className="error" style={{ marginTop: 4 }}>
                          {s.error}
                        </div>
                      )}
                    </td>
                    <td className="muted">{duration(s)}</td>
                    <td className="muted">{s.used_mock ? "mock" : "live"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <GraphAdmin onDone={refresh} />
        <AuditLog />
      </div>
    </>
  );
}
