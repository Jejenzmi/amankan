"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { exportGraph } from "@/lib/api";

// react-force-graph uses the canvas/DOM, so it must be client-only.
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

const NODE_COLOR = {
  Asset: "#4da3ff",
  Account: "#ffce4d",
  Credential: "#c08bff",
  Vulnerability: "#6b7689",
};
const EDGE_COLOR = {
  CAN_REACH: "#4da3ff",
  CAN_ESCALATE: "#ff924d",
  CREDENTIAL_REUSE: "#ff4d4f",
  HAS_ACCOUNT: "#344054",
  HAS_VULN: "#27324a",
  CAN_READ: "#3a2f55",
  VALID_ON: "#3a2f55",
};

export default function AttackGraph() {
  const [raw, setRaw] = useState({ nodes: [], edges: [] });
  const [showVulns, setShowVulns] = useState(false);
  const [err, setErr] = useState("");
  const [hover, setHover] = useState(null);
  const fgRef = useRef();

  useEffect(() => {
    exportGraph()
      .then(setRaw)
      .catch((e) => setErr(String(e.message)));
  }, []);

  const data = useMemo(() => {
    const nodes = raw.nodes.filter(
      (n) => showVulns || n.type !== "Vulnerability"
    );
    const ids = new Set(nodes.map((n) => n.id));
    const links = raw.edges
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e) => ({ ...e }));
    return {
      nodes: nodes.map((n) => ({ ...n })),
      links,
    };
  }, [raw, showVulns]);

  function nodeLabel(n) {
    const extra =
      n.type === "Asset"
        ? ` [${n.criticality}${n.exposure === "external" ? ", external" : ""}]`
        : n.type === "Account"
        ? ` [${n.privilege}]`
        : "";
    return `${n.type}: ${n.label}${extra}`;
  }

  return (
    <div>
      {err && <div className="error">{err}</div>}
      <div className="legend">
        {Object.entries(NODE_COLOR).map(([k, c]) => (
          <span className="item" key={k}>
            <span className="dot" style={{ background: c }} /> {k}
          </span>
        ))}
        <span style={{ width: 16 }} />
        {["CAN_REACH", "CAN_ESCALATE", "CREDENTIAL_REUSE"].map((k) => (
          <span className="item" key={k}>
            <span className="line" style={{ borderTopColor: EDGE_COLOR[k] }} /> {k}
          </span>
        ))}
        <label className="item" style={{ marginLeft: "auto", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={showVulns}
            onChange={(e) => setShowVulns(e.target.checked)}
            style={{ width: "auto" }}
          />
          show vulnerabilities
        </label>
      </div>

      <div
        style={{
          border: "1px solid var(--border)",
          borderRadius: 10,
          overflow: "hidden",
          background: "#0a0e15",
          height: "70vh",
          position: "relative",
        }}
      >
        <ForceGraph2D
          ref={fgRef}
          graphData={data}
          backgroundColor="#0a0e15"
          nodeLabel={nodeLabel}
          nodeRelSize={5}
          linkColor={(l) => EDGE_COLOR[l.type] || "#2a3550"}
          linkWidth={(l) =>
            ["CAN_REACH", "CAN_ESCALATE", "CREDENTIAL_REUSE"].includes(l.type)
              ? 2
              : 1
          }
          linkDirectionalArrowLength={(l) =>
            ["CAN_REACH", "CAN_ESCALATE", "CREDENTIAL_REUSE"].includes(l.type)
              ? 4
              : 0
          }
          linkDirectionalArrowRelPos={1}
          linkLineDash={(l) => (l.type === "CREDENTIAL_REUSE" ? [4, 3] : null)}
          onNodeHover={setHover}
          nodeCanvasObject={(node, ctx, scale) => {
            const r =
              node.type === "Asset" ? 7 : node.type === "Vulnerability" ? 3 : 5;
            ctx.beginPath();
            ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
            ctx.fillStyle = NODE_COLOR[node.type] || "#888";
            ctx.fill();
            if (node.type === "Asset" && node.exposure === "external") {
              ctx.lineWidth = 2 / scale;
              ctx.strokeStyle = "#ff4d4f";
              ctx.stroke();
            }
            if (scale > 1.3 || node.type === "Asset") {
              const label = node.label || "";
              ctx.font = `${11 / scale}px sans-serif`;
              ctx.fillStyle = "#cdd6e0";
              ctx.fillText(label, node.x + r + 2, node.y + 3);
            }
          }}
        />
      </div>
      <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
        {data.nodes.length} nodes · {data.links.length} edges
        {hover ? ` · hovering: ${nodeLabel(hover)}` : ""}
      </div>
    </div>
  );
}
