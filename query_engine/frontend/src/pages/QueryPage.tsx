import React, { useRef, useEffect, useCallback, useState } from "react";
import { Link } from "react-router-dom";
import ForceGraph2D from "react-force-graph-2d";
import { rdfNlQuery, sparqlQuery, subgraphForQuestion } from "../api";

interface GNode {
  id: string; label: string; class: string; color: string;
  x?: number; y?: number;
  properties?: Record<string, any>;
}
interface GLink { source: string; target: string; label: string; }
export interface GraphData { nodes: GNode[]; links: GLink[]; }

/** RDF property keys are camelCase — display them as words ("datePublished" → "date published"). */
function prettyKey(k: string): string {
  return k.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
}

function nodeIsKev(n: GNode | null): boolean {
  return !!(n?.properties?.exploitedInWild || n?.properties?.exploited_in_wild);
}

/** Raw KEV fields render as a dedicated callout, not generic rows. */
const KEV_KEYS = new Set(["exploitedInWild", "exploitationVerifiedDate", "ransomwareUse"]);

const CLASS_COLORS: Record<string, string> = {
  Vendor: "#6366f1", Software: "#22c55e", SoftwareType: "#84cc16",
  Version: "#f59e0b", Vulnerability: "#ef4444", VulnerabilityType: "#ec4899",
  Attack: "#a855f7", Impact: "#0ea5e9",
};

export interface QueryState {
  question: string;
  sparql: string;
  showSparql: boolean;
  sparqlResult: { headers: string[]; rows: (string | null)[][] } | null;
  sparqlError: string;
  graphData: GraphData;
  graphError: string;
  loading: boolean;
}

export const INITIAL_QUERY_STATE: QueryState = {
  question: "",
  sparql: "",
  showSparql: false,
  sparqlResult: null,
  sparqlError: "",
  graphData: { nodes: [], links: [] },
  graphError: "",
  loading: false,
};

interface Props {
  state: QueryState;
  setState: (s: QueryState | ((prev: QueryState) => QueryState)) => void;
}

export default function QueryPage({ state, setState }: Props) {
  const graphRef = useRef<any>(null);
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);
  const graphWrapRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ width: 800, height: 420 });
  const {
    question,
    sparql,
    showSparql,
    sparqlResult = null,
    sparqlError = "",
    graphData = { nodes: [], links: [] },
    graphError = "",
    loading,
  } = state;

  const set = (patch: Partial<QueryState>) => setState((prev) => ({ ...prev, ...patch }));

  const runSparqlPipeline = useCallback(
    async (sparqlText: string, q: string) => {
      if (!sparqlText.trim()) {
        setState((prev) => ({
          ...prev,
          sparqlResult: null,
          sparqlError: "No SPARQL was generated for this question.",
          graphData: { nodes: [], links: [] },
          graphError: "",
        }));
        return;
      }

      let nextTable: { headers: string[]; rows: (string | null)[][] } | null = null;
      let tableErr = "";
      try {
        const res = await sparqlQuery(sparqlText);
        if (res.error) tableErr = typeof res.error === "string" ? res.error : JSON.stringify(res.error);
        else nextTable = { headers: res.headers || [], rows: (res.rows || []) as (string | null)[][] };
      } catch (e: any) {
        tableErr = e.response?.data?.error || e.message || "SPARQL request failed";
      }

      let nextGraph: GraphData = { nodes: [], links: [] };
      let gErr = "";
      try {
        const data = await subgraphForQuestion(q, sparqlText, 120);
        if (data?.nodes) nextGraph = { nodes: data.nodes, links: data.links || [] };
      } catch (e: any) {
        gErr = e.response?.data?.error || e.message || "Graph request failed";
      }

      setState((prev) => ({
        ...prev,
        sparqlError: tableErr,
        sparqlResult: tableErr ? null : nextTable,
        graphData: nextGraph,
        graphError: gErr,
      }));
    },
    [setState]
  );

  const query = async (q?: string) => {
    const questionText = q ?? question;
    if (!questionText.trim()) return;
    if (q) set({ question: q });
    set({
      loading: true,
      graphError: "",
      sparqlError: "",
      sparqlResult: null,
      graphData: { nodes: [], links: [] },
    });

    try {
      const gen = await rdfNlQuery(questionText);
      if (gen?.error) {
        setState((prev) => ({
          ...prev,
          sparqlError: gen.error,
          sparqlResult: null,
          graphData: { nodes: [], links: [] },
          graphError: "",
          loading: false,
        }));
        return;
      }
      const generated = gen?.sparql || "";
      if (generated) set({ sparql: generated });
      await runSparqlPipeline(generated, questionText);
    } catch (e: any) {
      setState((prev) => ({
        ...prev,
        sparqlError: e?.response?.data?.error || e?.message || "SPARQL generation failed",
        sparqlResult: null,
        graphData: { nodes: [], links: [] },
        graphError: "",
      }));
    }

    set({ loading: false });
  };

  const executeSparql = async () => {
    if (!sparql.trim()) return;
    set({ loading: true, sparqlError: "", graphError: "" });
    await runSparqlPipeline(sparql, question);
    set({ loading: false });
  };

  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => graphRef.current?.zoomToFit(400, 60), 300);
    }
    setSelectedNode(null);
  }, [graphData]);

  const hasResults = sparqlResult || sparqlError || graphData.nodes.length > 0 || graphError || sparql;
  const showTable = !!(sparqlResult && sparqlResult.headers.length > 0);
  const showGraphCard = !!(sparql || graphData.nodes.length > 0 || graphError);

  // Keep the force-graph canvas sized to its flex cell (the page itself never
  // scrolls; each results panel scrolls internally).
  useEffect(() => {
    const el = graphWrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      if (el.clientWidth > 0 && el.clientHeight > 0) {
        setGraphSize({ width: el.clientWidth, height: el.clientHeight });
      }
    });
    ro.observe(el);
    if (el.clientWidth > 0 && el.clientHeight > 0) {
      setGraphSize({ width: el.clientWidth, height: el.clientHeight });
    }
    return () => ro.disconnect();
  }, [showGraphCard, graphData.nodes.length]);

  return (
    <div className="query-page">
      {/* NL input */}
      <div className="nl-input-row">
        <input
          placeholder="Ask a question about vulnerabilities, software, or the knowledge graph…"
          value={question}
          onChange={(e) => set({ question: e.target.value })}
          onKeyDown={(e) => e.key === "Enter" && query()}
        />
        <button className="btn" onClick={() => query()} disabled={loading}>
          {loading ? "Querying…" : "Query"}
        </button>
      </div>

      {/* Results */}
      {hasResults && (
        <div className="query-block query-block--fill">
          {/* SPARQL toggle */}
          <div className="query-block-header">
            <span className="query-block-label">SPARQL</span>
            {sparql && (
              <button type="button" className="toggle-btn" onClick={() => set({ showSparql: !showSparql })}>
                {showSparql ? "▾ Hide" : "▸ Show"} query
              </button>
            )}
          </div>

          {showSparql && sparql && (
            <div style={{ marginBottom: 8 }}>
              <textarea className="sql-editor" rows={6} value={sparql}
                onChange={(e) => set({ sparql: e.target.value })}
                onKeyDown={(e) => {
                  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); executeSparql(); }
                }} />
              <div className="sql-actions">
                <button type="button" className="btn" onClick={executeSparql}
                  disabled={loading || !sparql.trim()}>Run SPARQL</button>
                <span className="hint">⌘+Enter</span>
              </div>
            </div>
          )}

          {sparqlError && <div className="error" style={{ marginBottom: 12 }}>{sparqlError}</div>}

          <div className={`query-results${showTable && showGraphCard ? "" : " query-results--single"}`}>
          {/* Table result */}
          {showTable && sparqlResult && (
            <div className="card result-card query-table-card">
              <h3>Results ({sparqlResult.rows.length} rows)</h3>
              <div className="table-wrap query-table-scroll">
                <table>
                  <thead>
                    <tr>
                      {sparqlResult.headers.map((h, i) => <th key={`${h}-${i}`}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {sparqlResult.rows.map((row, i) => (
                      <tr key={i}>
                        {row.map((cell, j) => (
                          <td key={j}>{cell !== null && cell !== undefined ? String(cell) : "—"}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Graph */}
          {showGraphCard && (
            <div className="card result-card query-graph-card">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: graphError ? 0 : 8 }}>
                <h3 style={{ marginBottom: 0 }}>Knowledge Graph</h3>
                {sparql.trim() && (
                  <button type="button" className="btn" style={{ padding: "8px 16px", fontSize: 13 }}
                    onClick={executeSparql} disabled={loading}>
                    {loading ? "…" : "Re-run SPARQL"}
                  </button>
                )}
              </div>
              {graphError && <div className="error" style={{ marginBottom: 10 }}>{graphError}</div>}
              {graphData.nodes.length === 0 ? (
                <div style={{
                  flex: 1, minHeight: 200, border: "1px dashed var(--border)", borderRadius: 8,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  padding: 24, textAlign: "center", color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5,
                }}>
                  {loading ? "Building graph…" : "No graph nodes found for this query."}
                </div>
              ) : (
                <>
                  <p style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
                    {graphData.nodes.length} nodes · {graphData.links.length} edges
                  </p>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", fontSize: 11, marginBottom: 6 }}>
                    {Object.entries(CLASS_COLORS).map(([c, color]) => {
                      const count = graphData.nodes.filter((n) => n.class === c).length;
                      if (!count) return null;
                      return <span key={c} style={{ display: "inline-flex", alignItems: "center", gap: 3 }}>
                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
                        {c} ({count})
                      </span>;
                    })}
                  </div>
                  <div className="query-graph-split" ref={graphWrapRef}>
                    <div className="query-graph-canvas">
                    <ForceGraph2D
                      ref={graphRef}
                      graphData={graphData}
                      width={graphSize.width}
                      height={graphSize.height}
                      nodeColor={(n: any) => n.color}
                      onNodeClick={(n: any) => setSelectedNode(n)}
                      onBackgroundClick={() => setSelectedNode(null)}
                      nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
                        const r = (node.class === "Vulnerability" || node.class === "Software") ? 5 : 3.5;
                        const isSel = selectedNode?.id === node.id;
                        if (nodeIsKev(node)) {
                          ctx.beginPath();
                          ctx.arc(node.x!, node.y!, r + 2.2, 0, 2 * Math.PI);
                          ctx.strokeStyle = "rgba(185,28,28,0.9)";
                          ctx.lineWidth = 1.4;
                          ctx.setLineDash([3, 2]);
                          ctx.stroke();
                          ctx.setLineDash([]);
                        }
                        if (isSel) {
                          ctx.beginPath();
                          ctx.arc(node.x!, node.y!, r + 3.5, 0, 2 * Math.PI);
                          ctx.fillStyle = "rgba(37,99,235,0.18)";
                          ctx.fill();
                        }
                        ctx.beginPath();
                        ctx.arc(node.x!, node.y!, r, 0, 2 * Math.PI);
                        ctx.fillStyle = node.color;
                        ctx.fill();
                        if (isSel) {
                          ctx.strokeStyle = "#1e293b";
                          ctx.lineWidth = 1.2;
                          ctx.stroke();
                        }
                        if (globalScale > 1.2) {
                          ctx.font = `${Math.max(3, 10 / globalScale)}px sans-serif`;
                          ctx.textAlign = "center";
                          ctx.textBaseline = "top";
                          ctx.fillStyle = "#374151";
                          const label = node.label.length > 28 ? node.label.slice(0, 26) + "…" : node.label;
                          ctx.fillText(label, node.x!, node.y! + r + 1);
                        }
                      }}
                      linkColor={() => "#cbd5e1"}
                      linkWidth={1.5}
                      linkDirectionalArrowLength={5}
                      linkDirectionalArrowRelPos={1}
                      linkCanvasObjectMode={() => "after"}
                      linkCanvasObject={(link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
                        if (globalScale < 0.8 || !link.label) return;
                        const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
                        const mx = (sx + tx) / 2, my = (sy + ty) / 2;
                        ctx.font = `${Math.max(2.5, 8 / globalScale)}px sans-serif`;
                        ctx.textAlign = "center";
                        ctx.textBaseline = "middle";
                        ctx.fillStyle = "#9ca3af";
                        ctx.fillText(link.label, mx, my);
                      }}
                      nodeLabel={(n: any) => {
                        const props = n.properties || {};
                        const keys = Object.keys(props).filter(k => k !== "name" && k !== "vulnId" && props[k] != null && props[k] !== "");
                        let html = `<b>${n.label}</b>&nbsp;<span style="opacity:0.6">(${n.class})</span>`;
                        for (const k of keys.slice(0, 5)) {
                          let v = String(Array.isArray(props[k]) ? props[k].join(", ") : props[k]);
                          if (v.length > 80) v = v.slice(0, 77) + "…";
                          html += `<br/><span style="opacity:0.6">${k}:</span> ${v}`;
                        }
                        if (keys.length > 5) html += `<br/><em style="opacity:0.5">+${keys.length - 5} more…</em>`;
                        html += `<br/><em style="opacity:0.5">Click to inspect</em>`;
                        return html;
                      }}
                      cooldownTicks={80}
                    />
                    </div>
                    {selectedNode && (() => {
                      const props = selectedNode.properties || {};
                      const vulnId = props.vulnId || (selectedNode.class === "Vulnerability" ? selectedNode.label : null);
                      const refs: string[] = Array.isArray(props.references)
                        ? props.references
                        : (typeof props.references === "string" ? [props.references] : []);
                      const rows = Object.entries(props).filter(
                        ([k, v]) => k !== "references" && !KEV_KEYS.has(k) && v != null && v !== ""
                      );
                      return (
                        <div className="query-node-panel">
                          <button type="button" className="query-node-close" title="Close"
                            onClick={() => setSelectedNode(null)}>×</button>
                          <div className="kg-detail-title">{selectedNode.label}</div>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                            <span className="kg-detail-type" style={{ marginBottom: 0, background: `${selectedNode.color}22`, color: selectedNode.color }}>
                              {selectedNode.class}
                            </span>
                            {nodeIsKev(selectedNode) && <span className="badge badge-kev">CISA KEV</span>}
                          </div>
                          {nodeIsKev(selectedNode) && (
                            <div className="kev-callout" role="alert">
                              <div className="kev-callout-title">⚠ Exploited in the wild</div>
                              <div className="kev-callout-row">
                                CISA-verified exploitation
                                {props.exploitationVerifiedDate ? <> — confirmed <strong>{String(props.exploitationVerifiedDate).slice(0, 10)}</strong></> : null}.
                                {" "}Ransomware use: <strong>{String(props.ransomwareUse || "Unknown")}</strong>.
                              </div>
                            </div>
                          )}
                          <dl>
                            {rows.slice(0, 14).map(([k, v]) => (
                              <React.Fragment key={k}>
                                <dt>{prettyKey(k)}</dt>
                                <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
                              </React.Fragment>
                            ))}
                          </dl>
                          {refs.length > 0 && (
                            <div className="kg-sources" style={{ marginTop: 12 }}>
                              <div className="kg-sources-head">Sources</div>
                              <ul className="kg-sources-list">
                                {refs.slice(0, 8).map((u) => (
                                  <li key={u}>
                                    <a href={u} target="_blank" rel="noopener noreferrer" title={u}>
                                      {(() => { try { const p = new URL(u); return p.hostname.replace(/^www\./, "") + (p.pathname.length > 26 ? "…" + p.pathname.slice(-24) : p.pathname); } catch { return u.slice(0, 42); } })()}
                                    </a>
                                  </li>
                                ))}
                                {refs.length > 8 && <li style={{ color: "var(--text-secondary)" }}>+{refs.length - 8} more in full record</li>}
                              </ul>
                            </div>
                          )}
                          {vulnId && (
                            <Link className="query-node-open-link" to={`/vuln/${vulnId}`}>
                              Open full record →
                            </Link>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                </>
              )}
            </div>
          )}
          </div>
        </div>
      )}

      {!loading && !sparqlResult && graphData.nodes.length === 0 && !sparqlError && !graphError && sparql && (
        <div className="card result-card"><h3>No results returned</h3></div>
      )}
    </div>
  );
}
