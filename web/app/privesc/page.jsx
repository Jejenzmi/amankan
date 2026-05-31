"use client";
import { useEffect, useState, useCallback } from "react";
import TopBar from "@/components/TopBar";
import PrivEscPath from "@/components/PrivEscPath";
import {
  listAssets,
  listAccounts,
  createAccount,
  addEscalation,
  addCredentialReuse,
  privEscPath,
} from "@/lib/api";

const PRIVILEGES = ["user", "service", "admin", "root", "domain_admin"];

export default function PrivEscPage() {
  const [assets, setAssets] = useState([]);
  const [accounts, setAccounts] = useState([]); // flat, across all assets
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [path, setPath] = useState(null);
  const [loading, setLoading] = useState(true);

  // account-creation form
  const [acc, setAcc] = useState({ asset_id: "", username: "", privilege: "user" });
  // edge-builder form
  const [edge, setEdge] = useState({
    from: "",
    to: "",
    type: "escalate",
    technique: "",
    cwe: "",
    weight: "",
  });
  // path query
  const [query, setQuery] = useState({ from: "", to: "" });

  const assetName = useCallback(
    (id) => assets.find((a) => a.id === id)?.name || id?.slice(0, 8),
    [assets]
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const as = await listAssets();
      setAssets(as || []);
      // fan out: collect accounts from every asset (graph-derived + manual)
      const lists = await Promise.all(
        (as || []).map((a) =>
          listAccounts(a.id)
            .then((accs) => (accs || []).map((x) => ({ ...x, _asset: a })))
            .catch(() => [])
        )
      );
      setAccounts(lists.flat());
      setErr("");
    } catch (e) {
      setErr(String(e.message));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function flash(m) {
    setMsg(m);
    setTimeout(() => setMsg(""), 3500);
  }

  const label = (a) =>
    `${a.username}@${a._asset ? a._asset.name : assetName(a.asset_id)} [${a.privilege}]`;

  async function onCreateAccount(e) {
    e.preventDefault();
    setErr("");
    try {
      await createAccount(acc);
      setAcc({ ...acc, username: "" });
      flash(`Account ${acc.username} created`);
      refresh();
    } catch (e) {
      setErr(String(e.message));
    }
  }

  async function onAddEdge(e) {
    e.preventDefault();
    setErr("");
    if (!edge.from || !edge.to) {
      setErr("pick both a source and target account");
      return;
    }
    if (edge.from === edge.to) {
      setErr("source and target must differ");
      return;
    }
    const weight = edge.weight === "" ? 0 : parseFloat(edge.weight);
    try {
      if (edge.type === "escalate") {
        await addEscalation(edge.from, {
          target_account_id: edge.to,
          technique: edge.technique,
          cwe: edge.cwe,
          weight,
        });
      } else {
        await addCredentialReuse(edge.from, { target_account_id: edge.to, weight });
      }
      flash("Edge added");
      setEdge({ ...edge, technique: "", cwe: "", weight: "" });
    } catch (e) {
      setErr(String(e.message));
    }
  }

  async function onQuery(e) {
    e.preventDefault();
    setErr("");
    setPath(null);
    if (!query.from || !query.to) {
      setErr("pick a foothold and a target account");
      return;
    }
    try {
      setPath(await privEscPath(query.from, query.to));
    } catch (e) {
      setErr(String(e.message));
    }
  }

  return (
    <>
      <TopBar />
      <div className="container">
        {err && <div className="error" style={{ whiteSpace: "pre-wrap" }}>{err}</div>}
        {msg && <div className="ok-msg">{msg}</div>}

        <div className="grid">
          {/* left: accounts list + create */}
          <div className="panel">
            <div className="toolbar">
              <h2 style={{ margin: 0 }}>Accounts ({accounts.length})</h2>
              <button className="ghost" style={{ marginLeft: "auto" }} onClick={refresh}>
                ↻
              </button>
            </div>
            {loading ? (
              <div className="empty">Loading…</div>
            ) : accounts.length === 0 ? (
              <div className="empty">
                No accounts yet. Register one below, or run scans with priv-esc /
                credential findings to auto-derive them.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Principal</th>
                    <th>Asset</th>
                    <th>Privilege</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((a) => (
                    <tr key={a.id}>
                      <td>{a.username}</td>
                      <td className="muted">
                        {a._asset ? a._asset.name : assetName(a.asset_id)}
                      </td>
                      <td>
                        <span className="badge framework">{a.privilege}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <h3>Register account</h3>
            <form onSubmit={onCreateAccount}>
              <div className="row" style={{ marginBottom: 8 }}>
                <select
                  value={acc.asset_id}
                  required
                  onChange={(e) => setAcc({ ...acc, asset_id: e.target.value })}
                  style={{ flex: 1 }}
                >
                  <option value="">select asset…</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="row" style={{ marginBottom: 8 }}>
                <input
                  placeholder="username"
                  value={acc.username}
                  required
                  onChange={(e) => setAcc({ ...acc, username: e.target.value })}
                />
                <select
                  value={acc.privilege}
                  onChange={(e) => setAcc({ ...acc, privilege: e.target.value })}
                >
                  {PRIVILEGES.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </div>
              <button className="primary" type="submit">
                + Add account
              </button>
            </form>
          </div>

          {/* right: edge builder + path query */}
          <div className="panel">
            <h2>Build escalation edge</h2>
            <form onSubmit={onAddEdge}>
              <div className="row" style={{ marginBottom: 8 }}>
                <AccountSelect
                  value={edge.from}
                  accounts={accounts}
                  label={label}
                  onChange={(v) => setEdge({ ...edge, from: v })}
                  placeholder="from account…"
                />
                <span className="muted">→</span>
                <AccountSelect
                  value={edge.to}
                  accounts={accounts}
                  label={label}
                  onChange={(v) => setEdge({ ...edge, to: v })}
                  placeholder="to account…"
                />
              </div>
              <div className="row" style={{ marginBottom: 8 }}>
                <select
                  value={edge.type}
                  onChange={(e) => setEdge({ ...edge, type: e.target.value })}
                >
                  <option value="escalate">CAN_ESCALATE (local priv-esc)</option>
                  <option value="reuse">CREDENTIAL_REUSE (lateral)</option>
                </select>
                <input
                  placeholder="weight (effort)"
                  type="number"
                  step="0.1"
                  value={edge.weight}
                  onChange={(e) => setEdge({ ...edge, weight: e.target.value })}
                  style={{ width: 120 }}
                />
              </div>
              {edge.type === "escalate" && (
                <div className="row" style={{ marginBottom: 8 }}>
                  <input
                    placeholder="technique (e.g. sudo misconfig)"
                    value={edge.technique}
                    onChange={(e) => setEdge({ ...edge, technique: e.target.value })}
                    style={{ flex: 1 }}
                  />
                  <input
                    placeholder="CWE (e.g. CWE-269)"
                    value={edge.cwe}
                    onChange={(e) => setEdge({ ...edge, cwe: e.target.value })}
                    style={{ width: 140 }}
                  />
                </div>
              )}
              <button className="primary" type="submit">
                + Add edge
              </button>
            </form>

            <h2 style={{ marginTop: 22 }}>Minimum-effort escalation path</h2>
            <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
              Weighted Dijkstra over CAN_ESCALATE + CREDENTIAL_REUSE — the cheapest
              chain from a foothold to a privileged target.
            </p>
            <form onSubmit={onQuery}>
              <div className="row" style={{ marginBottom: 8 }}>
                <AccountSelect
                  value={query.from}
                  accounts={accounts}
                  label={label}
                  onChange={(v) => setQuery({ ...query, from: v })}
                  placeholder="foothold (from)…"
                />
                <span className="muted">→</span>
                <AccountSelect
                  value={query.to}
                  accounts={accounts}
                  label={label}
                  onChange={(v) => setQuery({ ...query, to: v })}
                  placeholder="target (to)…"
                />
                <button className="primary" type="submit">
                  Find path
                </button>
              </div>
            </form>

            <PrivEscPath path={path} />
          </div>
        </div>
      </div>
    </>
  );
}

function AccountSelect({ value, accounts, label, onChange, placeholder }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} style={{ flex: 1 }}>
      <option value="">{placeholder}</option>
      {accounts.map((a) => (
        <option key={a.id} value={a.id}>
          {label(a)}
        </option>
      ))}
    </select>
  );
}
