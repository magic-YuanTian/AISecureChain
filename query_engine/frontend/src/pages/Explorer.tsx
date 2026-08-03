import React, { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import ForceGraph2D from "react-force-graph-2d";
import {
  fetchKgNeighbors,
  fetchKgOverview,
  fetchKgStatus,
  fetchOntologyGraph,
  searchKgGraph,
} from "../api";
import axios from "axios";

const API = axios.create({ baseURL: "/api" });

/* ────── Lifted state (persisted in App) ────── */

export interface GNode {
  id: string; label: string; class: string; color: string;
  x?: number; y?: number;
  fx?: number; fy?: number;
  properties?: Record<string, any>;
  dataProperties?: string[];
}
export interface GLink { source: string; target: string; label: string; }
export interface ExplorerGraphData { nodes: GNode[]; links: GLink[]; }

interface KgNode {
  id: string;
  label: string;
  type: string;
  labels?: string[];
  properties?: Record<string, any>;
}
interface KgLink {
  source: string;
  target: string;
  type: string;
  label?: string;
  properties?: Record<string, any>;
}
interface KgGraphData { nodes: KgNode[]; links: KgLink[]; }

export interface ExplorerState {
  lastExplorerPath: string;
  graphData: ExplorerGraphData;
  graphError: string;
  /** Selected class or edge label shown in the table below the graph */
  selectedItem: string;
  selectedKind: "class" | "edge" | "";
  tablePage: number;
}

export const INITIAL_EXPLORER_STATE: ExplorerState = {
  lastExplorerPath: "/",
  graphData: { nodes: [], links: [] },
  graphError: "",
  selectedItem: "",
  selectedKind: "",
  tablePage: 0,
};

const NODE_POSITIONS_STORAGE_KEY = "aisecurechain_explorer_node_positions_v1";

function loadSavedNodePositions(): Record<string, { x: number; y: number }> {
  try {
    const raw = localStorage.getItem(NODE_POSITIONS_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    return parsed;
  } catch {
    return {};
  }
}

function persistNodePositions(nodes: GNode[]) {
  const positions: Record<string, { x: number; y: number }> = {};
  for (const n of nodes) {
    if (Number.isFinite(n.x) && Number.isFinite(n.y)) {
      positions[n.id] = { x: n.x as number, y: n.y as number };
    }
  }
  localStorage.setItem(NODE_POSITIONS_STORAGE_KEY, JSON.stringify(positions));
}

const CAMERA_STORAGE_KEY = "aisecurechain_explorer_camera_v1";
type ExplorerViewMode = "ontology" | "kg";

interface SavedCamera { k: number; x: number; y: number; }

function loadSavedCamera(): SavedCamera | null {
  try {
    const raw = localStorage.getItem(CAMERA_STORAGE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw);
    if (p && Number.isFinite(p.k) && Number.isFinite(p.x) && Number.isFinite(p.y)) return p;
    return null;
  } catch { return null; }
}

function persistCamera(fg: any) {
  try {
    const k = fg.zoom();
    const center = fg.centerAt();
    if (Number.isFinite(k) && center && Number.isFinite(center.x) && Number.isFinite(center.y)) {
      localStorage.setItem(CAMERA_STORAGE_KEY, JSON.stringify({ k, x: center.x, y: center.y }));
    }
  } catch { /* noop */ }
}

interface ExplorerProps {
  explorerState: ExplorerState;
  setExplorerState: (u: ExplorerState | ((prev: ExplorerState) => ExplorerState)) => void;
}

export default function Explorer({ explorerState, setExplorerState }: ExplorerProps) {
  const patch = (p: Partial<ExplorerState>) =>
    setExplorerState((prev) => ({ ...prev, ...p }));

  return <GraphExplorer explorerState={explorerState} patchExplorer={patch} />;
}

/* ────── Data table below graph ────── */

// ── Column-aware filtering ────────────────────────────────────────────
type ColType = "text" | "numeric" | "boolean" | "enum" | "date";
type ColFilter = { text?: string; min?: string; max?: string; bool?: string; values?: string[] };

const ENUM_COLS = new Set(["cvss_severity", "software_type", "risk_domain", "record_type"]);
const BOOL_COLS = new Set(["is_ai"]);
const NUMERIC_COLS = new Set(["cvss_base_score"]);
const DATE_COLS = new Set(["date_published", "date_updated"]);

function colType(col: string): ColType {
  if (BOOL_COLS.has(col)) return "boolean";
  if (ENUM_COLS.has(col)) return "enum";
  if (DATE_COLS.has(col)) return "date";
  if (NUMERIC_COLS.has(col)) return "numeric";
  return "text";
}

// Convert the UI's per-column filter state into the backend's filter list.
function buildBackendFilters(colFilters: Record<string, ColFilter>): { column: string; op: string; value: any }[] {
  const out: { column: string; op: string; value: any }[] = [];
  for (const [col, fv] of Object.entries(colFilters)) {
    const t = colType(col);
    if (t === "text" && fv.text?.trim()) {
      out.push({ column: col, op: "contains", value: fv.text.trim() });
    } else if (t === "boolean" && fv.bool) {
      out.push({ column: col, op: "eq", value: fv.bool === "true" ? 1 : 0 });
    } else if (t === "enum" && fv.values && fv.values.length) {
      out.push({ column: col, op: "in", value: fv.values });
    } else if (t === "numeric" || t === "date") {
      if (fv.min?.trim()) out.push({ column: col, op: "gte", value: t === "numeric" ? Number(fv.min) : fv.min.trim() });
      if (fv.max?.trim()) out.push({ column: col, op: "lte", value: t === "numeric" ? Number(fv.max) : fv.max.trim() });
    }
  }
  return out;
}

const FACET_PARAM = Array.from(ENUM_COLS).join(",");

function DataTable({ selectedItem, selectedKind, page, setPage, onClose, fullWidth, onToggleFullWidth }: {
  selectedItem: string; selectedKind: "class" | "edge" | "";
  page: number; setPage: (n: number) => void;
  onClose: () => void;
  fullWidth: boolean;
  onToggleFullWidth: () => void;
}) {
  const [tableData, setTableData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [jumpPageInput, setJumpPageInput] = useState(String(page + 1));
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [colFilters, setColFilters] = useState<Record<string, ColFilter>>({});
  const [debouncedFilters, setDebouncedFilters] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [facets, setFacets] = useState<Record<string, (string | number)[]>>({});
  const limit = 30;

  const backendFilters = useMemo(() => buildBackendFilters(colFilters), [colFilters]);
  const filtersJson = useMemo(
    () => (backendFilters.length ? JSON.stringify(backendFilters) : ""),
    [backendFilters]
  );
  const total: number = tableData?.total || 0;
  const totalPages = Math.ceil(total / limit) || 1;

  useEffect(() => {
    if (!selectedItem || !selectedKind) return;
    setLoading(true);
    const endpoint = selectedKind === "class"
      ? `/class-data/${selectedItem}`
      : `/edge-data/${selectedItem}`;
    API.get(endpoint, {
      params: {
        limit,
        offset: page * limit,
        q: debouncedSearch || undefined,
        filters: debouncedFilters || undefined,
        facets: FACET_PARAM,
      },
    })
      .then((r) => {
        setTableData(r.data);
        if (r.data.facets) setFacets(r.data.facets);
      })
      .catch(() => setTableData(null))
      .finally(() => setLoading(false));
  }, [selectedItem, selectedKind, page, debouncedSearch, debouncedFilters]);

  useEffect(() => {
    setJumpPageInput(String(page + 1));
  }, [page]);

  // Debounce the in-table search box.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  // Debounce per-column filters (typed inputs shouldn't refetch on every keystroke).
  useEffect(() => {
    const t = setTimeout(() => setDebouncedFilters(filtersJson), 300);
    return () => clearTimeout(t);
  }, [filtersJson]);

  // Clear search + filters when switching to a different class/relationship.
  useEffect(() => {
    setSearch("");
    setDebouncedSearch("");
    setColFilters({});
    setDebouncedFilters("");
  }, [selectedItem, selectedKind]);

  const setColFilter = (col: string, patch: Partial<ColFilter>) => {
    setColFilters((prev) => ({ ...prev, [col]: { ...prev[col], ...patch } }));
    setPage(0);
  };
  const clearFilters = () => { setColFilters({}); setPage(0); };
  const activeFilterCount = backendFilters.length;

  if (loading && !tableData) return <div className="loading">Loading…</div>;
  if (!tableData) return <div className="error">Failed to load data</div>;

  const cols: string[] = tableData.columns || [];
  const rows: any[] = tableData.data || [];

  const jumpToPage = () => {
    const raw = Number.parseInt(jumpPageInput.trim(), 10);
    if (!Number.isFinite(raw)) return;
    const target = Math.max(1, Math.min(totalPages, raw));
    setPage(target - 1);
  };

  const renderFilterCell = (col: string) => {
    const t = colType(col);
    const fv = colFilters[col] || {};
    if (t === "boolean") {
      return (
        <select className="ont-filter-input" value={fv.bool || ""} onChange={(e) => setColFilter(col, { bool: e.target.value })}>
          <option value="">Any</option>
          <option value="true">True</option>
          <option value="false">False</option>
        </select>
      );
    }
    if (t === "enum") {
      const opts = facets[col] || [];
      return (
        <select
          className="ont-filter-input"
          value={fv.values?.[0] ?? ""}
          onChange={(e) => setColFilter(col, { values: e.target.value ? [e.target.value] : [] })}
        >
          <option value="">Any</option>
          {opts.map((o) => <option key={String(o)} value={String(o)}>{String(o)}</option>)}
        </select>
      );
    }
    if (t === "numeric") {
      return (
        <div className="ont-filter-range">
          <input className="ont-filter-input" inputMode="decimal" placeholder="min" value={fv.min || ""} onChange={(e) => setColFilter(col, { min: e.target.value })} />
          <input className="ont-filter-input" inputMode="decimal" placeholder="max" value={fv.max || ""} onChange={(e) => setColFilter(col, { max: e.target.value })} />
        </div>
      );
    }
    if (t === "date") {
      return (
        <div className="ont-filter-range">
          <input className="ont-filter-input" type="date" value={fv.min || ""} onChange={(e) => setColFilter(col, { min: e.target.value })} />
          <input className="ont-filter-input" type="date" value={fv.max || ""} onChange={(e) => setColFilter(col, { max: e.target.value })} />
        </div>
      );
    }
    return (
      <input
        className="ont-filter-input"
        value={fv.text || ""}
        onChange={(e) => setColFilter(col, { text: e.target.value })}
        placeholder="contains…"
      />
    );
  };

  return (
    <div className="ont-table-container">
      <div className="ont-table-header">
        <span className="ont-table-class-name">{selectedItem}</span>
        <span className="ont-table-kind-badge" data-kind={selectedKind}>
          {selectedKind === "class" ? "Class" : "Relationship"}
        </span>
        <span className="ont-table-count">{total}</span>
        <div className="ont-table-search-wrap">
          <span className="ont-table-search-icon" aria-hidden>⌕</span>
          <input
            className="ont-table-search"
            type="search"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            placeholder={`Search all columns…`}
            aria-label={`Search ${selectedItem} records`}
          />
        </div>
        <button
          type="button"
          className="ont-table-filters-toggle"
          data-active={showFilters || activeFilterCount > 0 ? "true" : "false"}
          onClick={() => setShowFilters((v) => !v)}
          title="Filter by column"
        >
          ⛃ Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
        </button>
        {activeFilterCount > 0 && (
          <button type="button" className="ont-table-clear-filters" onClick={clearFilters} title="Clear all column filters">
            Clear
          </button>
        )}
        <button
          type="button"
          className="ont-table-expand"
          onClick={onToggleFullWidth}
          title={fullWidth ? "Show graph beside table" : "Expand table to full width"}
          aria-expanded={fullWidth}
          aria-label={fullWidth ? "Split view" : "Full width"}
          data-active={fullWidth ? "true" : "false"}
        >
          {fullWidth ? "🗗" : "⛶"}
        </button>
        <button className="ont-table-close" onClick={onClose} title="Close table">×</button>
      </div>
      <div className="ont-table-scroll">
        <table>
          <thead>
            <tr>{cols.map(c => <th key={c}>{c}</th>)}</tr>
            {showFilters && (
              <tr className="ont-filter-row">
                {cols.map((c) => <th key={c}>{renderFilterCell(c)}</th>)}
              </tr>
            )}
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={cols.length || 1} className="ont-table-empty">
                  {debouncedSearch ? `No records match “${debouncedSearch}”` : "No records"}
                </td>
              </tr>
            )}
            {rows.map((r: any, i: number) => (
              <tr key={i}>
                {cols.map(c => {
                  let val = r[c];
                  if (val == null) return <td key={c} style={{ color: "#9ca3af" }}>—</td>;
                  if (c === "is_ai") return <td key={c}><span className={`badge ${val ? "badge-ai" : "badge-non-ai"}`}>{val ? "True" : "False"}</span></td>;
                  if (c === "exploited_in_wild") return <td key={c}>{val ? <span className="badge badge-kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog">KEV</span> : <span style={{ color: "#9ca3af" }}>—</span>}</td>;
                  if (c === "ransomware_use") return <td key={c}>{val === "Known" ? <span className="badge badge-ransomware">Known</span> : <span style={{ color: "#9ca3af" }}>{String(val)}</span>}</td>;
                  if (c === "vuln_id") return <td key={c}><Link to={`/vuln/${val}`}>{val}</Link></td>;
                  if (c === "references_json") {
                    try { val = JSON.parse(val).length + " links"; } catch { val = "—"; }
                    return <td key={c} style={{ fontSize: 11 }}>{val}</td>;
                  }
                  if (c === "cvss_severity") {
                    const sc: Record<string, string> = { CRITICAL: "#7f1d1d", HIGH: "#dc2626", MEDIUM: "#f59e0b", LOW: "#22c55e" };
                    return <td key={c}><span className="badge" style={{ background: sc[val] || "#6b7280", color: "#fff" }}>{val}</span></td>;
                  }
                  const s = String(val);
                  if ((c === "date_published" || c === "date_updated") && s.length > 10)
                    return <td key={c} style={{ fontSize: 12, whiteSpace: "nowrap" }}>{s.slice(0, 10)}</td>;
                  if (s.length > 100) return <td key={c} className="cell-truncate" style={{ maxWidth: 220 }} title={s}>{s.slice(0, 100)}…</td>;
                  return <td key={c}>{s}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {total > limit && (
        <div className="pagination">
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>← Prev</button>
          <span>Page {page + 1} of {totalPages}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => setPage(page + 1)}>Next →</button>
          <div className="pagination-jump">
            <label htmlFor="pagination-jump-input" className="pagination-jump-label">Go to</label>
            <input
              id="pagination-jump-input"
              className="pagination-jump-input"
              value={jumpPageInput}
              onChange={(e) => setJumpPageInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") jumpToPage();
              }}
              inputMode="numeric"
              pattern="[0-9]*"
              aria-label="Jump to page number"
            />
            <button type="button" className="pagination-jump-btn" onClick={jumpToPage}>
              Go
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── UML box geometry (shared: draw + pointer hit area) ── */

const UML_BOX_W = 160;
const UML_HEADER_H = 28;
const UML_LINE_H = 18;
const UML_PAD_Y = 10;
const UML_CORNER_R = 6;
const UML_HIT_PADDING = 6;

function getUmlBoxBounds(node: any) {
  const dps: string[] = node.dataProperties || [];
  const boxH = UML_HEADER_H + Math.max(dps.length, 1) * UML_LINE_H + UML_PAD_Y * 2;
  return {
    x: node.x! - UML_BOX_W / 2,
    y: node.y! - boxH / 2,
    boxW: UML_BOX_W,
    boxH,
    headerH: UML_HEADER_H,
  };
}

function pathRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number, rad: number
) {
  ctx.beginPath();
  ctx.moveTo(x + rad, y); ctx.lineTo(x + w - rad, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rad);
  ctx.lineTo(x + w, y + h - rad);
  ctx.quadraticCurveTo(x + w, y + h, x + w - rad, y + h);
  ctx.lineTo(x + rad, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - rad);
  ctx.lineTo(x, y + rad);
  ctx.quadraticCurveTo(x, y, x + rad, y);
  ctx.closePath();
}

function paintUmlPointerArea(node: any, color: string, ctx: CanvasRenderingContext2D) {
  const b = getUmlBoxBounds(node);
  const p = UML_HIT_PADDING;
  pathRoundedRect(ctx, b.x - p, b.y - p, b.boxW + 2 * p, b.boxH + 2 * p, UML_CORNER_R + 2);
  ctx.fillStyle = color;
  ctx.fill();
}

function drawUmlBox(
  ctx: CanvasRenderingContext2D, node: any, selected: boolean
) {
  const b = getUmlBoxBounds(node);
  const { x, y, boxW, boxH, headerH } = b;
  const dps: string[] = node.dataProperties || [];
  const rad = UML_CORNER_R;

  ctx.shadowColor = selected ? "rgba(37,99,235,0.35)" : "rgba(0,0,0,0.10)";
  ctx.shadowBlur = selected ? 16 : 8;
  ctx.shadowOffsetY = 2;

  pathRoundedRect(ctx, x, y, boxW, boxH, rad);
  ctx.fillStyle = "#fff";
  ctx.fill();
  ctx.shadowColor = "transparent";
  ctx.strokeStyle = selected ? "#2563eb" : "#93c5fd";
  ctx.lineWidth = selected ? 2.5 : 1.5;
  ctx.stroke();

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(x + rad, y); ctx.lineTo(x + boxW - rad, y);
  ctx.quadraticCurveTo(x + boxW, y, x + boxW, y + rad);
  ctx.lineTo(x + boxW, y + headerH); ctx.lineTo(x, y + headerH);
  ctx.lineTo(x, y + rad);
  ctx.quadraticCurveTo(x, y, x + rad, y);
  ctx.closePath();
  ctx.fillStyle = selected ? "#1d4ed8" : "#2563eb";
  ctx.fill();
  ctx.restore();

  ctx.beginPath();
  ctx.moveTo(x, y + headerH); ctx.lineTo(x + boxW, y + headerH);
  ctx.strokeStyle = "#93c5fd";
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.font = "bold 12px -apple-system, BlinkMacSystemFont, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillStyle = "#fff";
  ctx.fillText(node.label, node.x!, y + headerH / 2);

  ctx.font = "10px -apple-system, BlinkMacSystemFont, sans-serif";
  ctx.textAlign = "left";
  for (let i = 0; i < dps.length; i++) {
    const label = dps[i].toUpperCase();
    ctx.fillStyle = "#6b7280";
    ctx.fillText("•", x + 10, y + headerH + UML_PAD_Y + i * UML_LINE_H + UML_LINE_H / 2);
    ctx.fillStyle = "#374151";
    ctx.fillText(label, x + 22, y + headerH + UML_PAD_Y + i * UML_LINE_H + UML_LINE_H / 2);
  }
  if (dps.length === 0) {
    ctx.fillStyle = "#9ca3af";
    ctx.font = "italic 10px sans-serif";
    ctx.fillText("(no attributes)", x + 10, y + headerH + UML_PAD_Y + UML_LINE_H / 2);
  }
}

const KG_COLORS: Record<string, string> = {
  Vulnerability: "#ef4444",
  VulnerabilityType: "#ec4899",
  Software: "#3b82f6",
  Version: "#06b6d4",
  Vendor: "#8b5cf6",
  SoftwareType: "#84cc16",
  License: "#64748b",
  Attack: "#a855f7",
  Impact: "#0ea5e9",
};

const KG_TYPE_FILTERS: { key: string; label: string }[] = [
  { key: "Vulnerability", label: "vulnerability" },
  { key: "VulnerabilityType", label: "weakness type (CWE)" },
  { key: "Software", label: "software" },
  { key: "Version", label: "version" },
  { key: "Vendor", label: "vendor" },
  { key: "Attack", label: "attack" },
  { key: "Impact", label: "impact" },
];

const ALL_KG_TYPES = new Set(KG_TYPE_FILTERS.map((t) => t.key));

function kgLinkEndpoint(ref: string | { id?: string }): string {
  return typeof ref === "string" ? ref : (ref.id || "");
}

function kgDisplayLabel(node: KgNode): string {
  const props = node.properties || {};
  if (node.type === "Vulnerability") {
    const id = props.vuln_id || node.id.split(":")[1] || node.label;
    const title = props.title ? String(props.title) : "";
    if (title && title.length <= 36) return `${id}: ${title}`;
    if (title) return `${id}: ${title.slice(0, 32)}…`;
    return String(id);
  }
  if (node.type === "VulnerabilityType") return node.label;
  if (node.type === "Version") return String(props.version_string || node.label || "").slice(0, 24);
  return String(node.label || node.id).slice(0, 28);
}

/** CISA KEV flag — accepts both relational (exploited_in_wild) and RDF (exploitedInWild) keys. */
function isKevNode(props?: Record<string, any>): boolean {
  if (!props) return false;
  return !!(props.exploited_in_wild || props.exploitedInWild);
}

/** Raw KEV columns are rendered as a dedicated callout, not generic property rows. */
const KEV_PROP_KEYS = new Set([
  "exploited_in_wild", "exploitation_verified_date", "ransomware_use",
  "exploitedInWild", "exploitationVerifiedDate", "ransomwareUse",
]);

function KevCallout({ props: p }: { props: Record<string, any> }) {
  const date = p.exploitation_verified_date || p.exploitationVerifiedDate;
  const ransomware = p.ransomware_use || p.ransomwareUse;
  return (
    <div className="kev-callout" role="alert">
      <div className="kev-callout-title">⚠ CISA KEV · Exploited in the wild</div>
      <div className="kev-callout-row">
        Verified in-the-wild exploitation
        {date ? <> — confirmed <strong>{String(date)}</strong></> : null}.
        {" "}Ransomware use: <strong>{String(ransomware || "Unknown")}</strong>.
      </div>
      <div className="kev-callout-row">
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
           target="_blank" rel="noopener noreferrer">CISA KEV Catalog ↗</a>
      </div>
    </div>
  );
}

interface KgSourceLink { url: string; via?: string }

/** Short human label for a source URL (host + trimmed path). */
function sourceUrlLabel(url: string): string {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    const path = u.pathname.replace(/\/$/, "");
    const tail = path.length > 30 ? "…" + path.slice(-28) : path;
    return host + tail;
  } catch {
    return url.length > 44 ? url.slice(0, 42) + "…" : url;
  }
}

/**
 * URLs a node was drawn from. Vulnerability nodes carry `source_urls` directly;
 * for other node types we walk up to 3 hops to the nearest Vulnerability nodes
 * and attribute their sources (tagged with the via-vuln id). Capped so hub
 * nodes don't flood the panel.
 */
function nodeSourceLinks(node: KgNode, graph: KgGraphData, cap = 15): KgSourceLink[] {
  const out: KgSourceLink[] = [];
  const seen = new Set<string>();
  const push = (url: string, via?: string) => {
    if (url && !seen.has(url) && out.length < cap) {
      seen.add(url);
      out.push({ url, via });
    }
  };

  const direct: string[] = node.properties?.source_urls || [];
  for (const u of direct) push(u);
  if (node.type === "Vulnerability") return out;

  // BFS outward to the nearest Vulnerability nodes.
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const adj = new Map<string, Set<string>>();
  for (const l of graph.links) {
    const s = kgLinkEndpoint(l.source as any);
    const t = kgLinkEndpoint(l.target as any);
    if (!adj.has(s)) adj.set(s, new Set());
    if (!adj.has(t)) adj.set(t, new Set());
    adj.get(s)!.add(t);
    adj.get(t)!.add(s);
  }
  const visited = new Set<string>([node.id]);
  let frontier = [node.id];
  for (let depth = 0; depth < 3 && out.length < cap; depth++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const nb of Array.from(adj.get(id) || [])) {
        if (visited.has(nb)) continue;
        visited.add(nb);
        const other = byId.get(nb);
        if (other?.type === "Vulnerability") {
          const via = other.properties?.vuln_id || other.id.split(":")[1] || other.label;
          for (const u of (other.properties?.source_urls || []) as string[]) push(u, via);
        } else {
          next.push(nb);
        }
      }
    }
    frontier = next;
  }
  return out;
}

function filterKgGraph(graph: KgGraphData, activeTypes: Set<string>): KgGraphData {
  const nodes = (graph.nodes || []).filter((n) => activeTypes.has(n.type));
  const nodeIds = new Set(nodes.map((n) => n.id));
  const links = (graph.links || []).filter((l) => {
    const s = kgLinkEndpoint(l.source as string | { id?: string });
    const t = kgLinkEndpoint(l.target as string | { id?: string });
    return nodeIds.has(s) && nodeIds.has(t);
  });
  return { nodes, links };
}

function mergeKgGraph(current: KgGraphData, incoming: KgGraphData): KgGraphData {
  const nodes = new Map<string, KgNode>();
  const links = new Map<string, KgLink>();
  for (const n of current.nodes || []) nodes.set(n.id, n);
  for (const n of incoming.nodes || []) nodes.set(n.id, { ...nodes.get(n.id), ...n });
  for (const l of current.links || []) {
    const source = typeof l.source === "string" ? l.source : (l.source as any).id;
    const target = typeof l.target === "string" ? l.target : (l.target as any).id;
    links.set(`${source}|${target}|${l.type || l.label}`, { ...l, source, target });
  }
  for (const l of incoming.links || []) {
    const source = typeof l.source === "string" ? l.source : (l.source as any).id;
    const target = typeof l.target === "string" ? l.target : (l.target as any).id;
    links.set(`${source}|${target}|${l.type || l.label}`, { ...l, source, target });
  }
  return { nodes: Array.from(nodes.values()), links: Array.from(links.values()) };
}

function KnowledgeGraphExplorer({ focusQuery }: { focusQuery?: string }) {
  const [status, setStatus] = useState<any>(null);
  const [graph, setGraph] = useState<KgGraphData>({ nodes: [], links: [] });
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<KgNode | null>(null);
  const [hovered, setHovered] = useState<KgNode | null>(null);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(() => new Set(ALL_KG_TYPES));
  const [showLabels, setShowLabels] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const graphRef = useRef<any>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ width: 800, height: 640 });

  const loadStatus = useCallback(async () => {
    const out = await fetchKgStatus();
    setStatus(out);
    return out;
  }, []);

  const filteredGraph = useMemo(
    () => filterKgGraph(graph, activeTypes),
    [graph, activeTypes],
  );

  /** Node degree within the visible graph — drives hub sizing. */
  const degree = useMemo(() => {
    const d: Record<string, number> = {};
    for (const l of filteredGraph.links) {
      const s = kgLinkEndpoint(l.source as any);
      const t = kgLinkEndpoint(l.target as any);
      d[s] = (d[s] || 0) + 1;
      d[t] = (d[t] || 0) + 1;
    }
    return d;
  }, [filteredGraph]);

  const nodeRadius = useCallback(
    (n: KgNode) => {
      const deg = degree[n.id] || 0;
      // 4px floor, grows with sqrt(degree) so hubs read as hubs but don't explode.
      return Math.min(16, 4 + Math.sqrt(deg) * 1.6);
    },
    [degree],
  );

  useEffect(() => {
    setLoading(true);
    loadStatus()
      .then(() => fetchKgOverview().then((g) => setGraph(g)))
      .catch((e) => setError(e.response?.data?.error || e.message))
      .finally(() => setLoading(false));
  }, [loadStatus]);

  // Deep-link: when arriving with a ?focus=<id> term (e.g. from the Extract
  // consolidation panel's "Open in graph"), search for it and center the view.
  useEffect(() => {
    const term = (focusQuery || "").trim();
    if (!term) return;
    setQuery(term);
    setLoading(true);
    setError("");
    searchKgGraph(term)
      .then((out) => {
        setGraph(out);
        setSelected(null);
        setTimeout(() => graphRef.current?.zoomToFit(400, 56), 200);
      })
      .catch((e: any) => setError(e.response?.data?.error || e.message))
      .finally(() => setLoading(false));
  }, [focusQuery]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      setGraphSize({ width: el.clientWidth, height: el.clientHeight });
    });
    ro.observe(el);
    setGraphSize({ width: el.clientWidth, height: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (graphRef.current && filteredGraph.nodes.length > 0) {
      const t = setTimeout(() => graphRef.current?.zoomToFit(400, 56), 120);
      return () => clearTimeout(t);
    }
  }, [filteredGraph.nodes.length, activeTypes]);

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    const n = filteredGraph.nodes.length;
    const linkForce = fg.d3Force("link");
    // Shorter links + stronger pull on big graphs => one tight connected web
    // rather than long scattered threads.
    if (linkForce) linkForce.distance(n > 250 ? 34 : 60).strength(0.6);
    const charge = fg.d3Force("charge");
    if (charge) charge.strength(n > 250 ? -90 : -160).distanceMax(420);
    const center = fg.d3Force("center");
    if (center) center.strength(0.05);
  }, [filteredGraph.nodes.length]);

  const toggleType = (key: string) => {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        if (next.size === 1) return prev;
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const runSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError("");
    try {
      const out = await searchKgGraph(query.trim());
      setGraph(out);
      setSelected(null);
    } catch (e: any) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadOverview = () => {
    setLoading(true);
    setError("");
    fetchKgOverview()
      .then((g) => {
        setGraph(g);
        setSelected(null);
      })
      .catch((e) => setError(e.response?.data?.error || e.message))
      .finally(() => setLoading(false));
  };

  const expandNode = async (node: KgNode) => {
    setSelected(node);
    setLoading(true);
    setError("");
    try {
      const out = await fetchKgNeighbors(node.id);
      setGraph((prev) => mergeKgGraph(prev, out));
    } catch (e: any) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setLoading(false);
    }
  };

  const labelForNode = (node: KgNode) => kgDisplayLabel(node);

  return (
    <div className="kg-panel">
      {error && <div className="error">{error}</div>}
      <div className="kg-layout">
        <div className="card kg-graph-shell">
          <div className="kg-canvas-wrap" ref={wrapRef}>
            <div className="kg-overlay kg-overlay-top">
              <div className="kg-search-wrap">
                <span className="kg-search-icon" aria-hidden>⌕</span>
                <input
                  className="kg-search-inline"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
                  placeholder="Search CVE, CWE, software, vendor…"
                />
              </div>
              <div className="kg-type-filters" role="group" aria-label="Node types">
                {KG_TYPE_FILTERS.map(({ key, label }) => (
                  <button
                    key={key}
                    type="button"
                    className="kg-type-pill"
                    data-active={activeTypes.has(key) ? "true" : "false"}
                    onClick={() => toggleType(key)}
                  >
                    <span className="kg-type-dot" style={{ background: KG_COLORS[key] || "#94a3b8" }} />
                    {label}
                  </button>
                ))}
              </div>
              <div className="kg-zoom-stack">
                <button type="button" className="kg-zoom-btn" title="Zoom in" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() * 1.35, 200)}>+</button>
                <button type="button" className="kg-zoom-btn" title="Zoom out" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() / 1.35, 200)}>−</button>
                <button type="button" className="kg-zoom-btn" title="Fit graph" onClick={() => graphRef.current?.zoomToFit(400, 56)}>⤢</button>
                <button type="button" className="kg-zoom-btn" title="Toggle labels" data-active={showLabels ? "true" : "false"} onClick={() => setShowLabels((v) => !v)}>Aa</button>
              </div>
            </div>

            {filteredGraph.nodes.length ? (
              <ForceGraph2D
                ref={graphRef}
                width={graphSize.width}
                height={graphSize.height}
                graphData={filteredGraph as any}
                backgroundColor="#f8fafc"
                nodeLabel={(n: any) => `${n.type}: ${n.label}`}
                nodeColor={(n: any) => KG_COLORS[n.type] || "#94a3b8"}
                nodeVal={(n: any) => {
                  const r = nodeRadius(n);
                  return (r * r) / 8;
                }}
                linkColor={() => "rgba(100,116,139,0.30)"}
                linkWidth={1.2}
                linkCurvature={0.06}
                linkDirectionalArrowLength={4}
                linkDirectionalArrowRelPos={1}
                linkDirectionalArrowColor={() => "rgba(71,85,105,0.55)"}
                onNodeClick={(n: any) => expandNode(n)}
                onNodeHover={(n: any) => setHovered(n || null)}
                cooldownTicks={160}
                warmupTicks={40}
                nodeCanvasObjectMode={() => "replace"}
                nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
                  const radius = nodeRadius(node);
                  const isFocus = selected?.id === node.id || hovered?.id === node.id;
                  const showText = showLabels && (isFocus || globalScale > 1.15);
                  const color = KG_COLORS[node.type] || "#94a3b8";
                  const kev = isKevNode(node.properties);

                  // Soft focus halo behind the node.
                  if (isFocus) {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, radius + 4 / globalScale, 0, 2 * Math.PI, false);
                    ctx.fillStyle = "rgba(37,99,235,0.18)";
                    ctx.fill();
                  }

                  // CISA KEV: red hazard ring so exploited-in-the-wild vulns
                  // stand out at any zoom level.
                  if (kev) {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, radius + 3 / globalScale, 0, 2 * Math.PI, false);
                    ctx.strokeStyle = "rgba(185,28,28,0.9)";
                    ctx.lineWidth = 1.8 / globalScale;
                    ctx.setLineDash([4 / globalScale, 2.5 / globalScale]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                  }

                  // Node body with a crisp outline so it reads on the light canvas.
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                  ctx.fillStyle = color;
                  ctx.fill();
                  ctx.lineWidth = (isFocus ? 2 : 1.25) / globalScale;
                  ctx.strokeStyle = kev ? "#7f1d1d" : (isFocus ? "#1e293b" : "#ffffff");
                  ctx.stroke();

                  if (!showText) return;
                  const label = labelForNode(node);
                  const fontSize = Math.max(9, 11 / globalScale);
                  ctx.font = `${isFocus ? "600 " : ""}${fontSize}px -apple-system, BlinkMacSystemFont, sans-serif`;
                  ctx.textAlign = "left";
                  ctx.textBaseline = "middle";
                  const tx = node.x + radius + 5 / globalScale;
                  const textW = ctx.measureText(label).width;
                  const padX = 4 / globalScale;
                  const padY = 3 / globalScale;
                  // Translucent pill behind the label keeps it legible over edges.
                  pathRoundedRect(
                    ctx, tx - padX, node.y - fontSize / 2 - padY,
                    textW + padX * 2, fontSize + padY * 2, 3 / globalScale
                  );
                  ctx.fillStyle = isFocus ? "rgba(255,255,255,0.95)" : "rgba(248,250,252,0.78)";
                  ctx.fill();
                  ctx.fillStyle = isFocus ? "#0f172a" : "#334155";
                  ctx.fillText(label, tx, node.y);
                }}
              />
            ) : (
              <div className="kg-empty kg-empty-dark">
                {loading
                  ? "Loading graph…"
                  : graph.nodes.length
                    ? "No nodes match the selected types. Turn on a filter above."
                    : "No graph data yet. Run extraction, then search or open Overview."}
              </div>
            )}

            <div className="kg-legend">
              {KG_TYPE_FILTERS.filter((t) => activeTypes.has(t.key)).map(({ key, label }) => (
                <div key={key} className="kg-legend-item">
                  <span className="kg-legend-dot" style={{ background: KG_COLORS[key] }} />
                  {label}
                </div>
              ))}
              <div className="kg-legend-item" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
                <span className="kg-legend-dot kg-legend-dot--kev" />
                CISA KEV (exploited)
              </div>
            </div>

            <div className="kg-overlay-bottom">
              <button type="button" className="btn btn-ghost kg-action-btn" onClick={runSearch} disabled={loading || !query.trim()}>Search</button>
              <button type="button" className="btn btn-ghost kg-action-btn" onClick={loadOverview} disabled={loading}>Overview</button>
              {status?.counts && (
                <span className="kg-summary-dark">
                  {filteredGraph.nodes.length} nodes · {filteredGraph.links.length} edges shown
                  {" · "}{status.counts.vulnerabilities} vulns total
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="card kg-detail">
          <h3>Details</h3>
          {selected ? (
            <>
              <div className="kg-detail-title">{labelForNode(selected)}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                <div className="kg-detail-type">{selected.type}</div>
                {isKevNode(selected.properties) && (
                  <span className="badge badge-kev" style={{ marginBottom: 12 }}>CISA KEV</span>
                )}
              </div>
              {isKevNode(selected.properties) && <KevCallout props={selected.properties || {}} />}
              <dl>
                {Object.entries(selected.properties || {})
                  .filter(([k, v]) => k !== "source_urls" && !KEV_PROP_KEYS.has(k) && v != null && v !== "")
                  .slice(0, 18)
                  .map(([k, v]) => (
                    <React.Fragment key={k}>
                      <dt>{k}</dt>
                      <dd>{String(v ?? "")}</dd>
                    </React.Fragment>
                  ))}
              </dl>
              {(() => {
                const sources = nodeSourceLinks(selected, graph);
                if (sources.length === 0) return null;
                const isVuln = selected.type === "Vulnerability";
                return (
                  <div className="kg-sources">
                    <div className="kg-sources-head">
                      Sources
                      <span className="kg-sources-hint">
                        {isVuln ? "where this node was extracted from"
                                : "advisories this node appears in"}
                      </span>
                    </div>
                    <ul className="kg-sources-list">
                      {sources.map(({ url, via }) => (
                        <li key={url}>
                          <a href={url} target="_blank" rel="noopener noreferrer" title={url}>
                            {sourceUrlLabel(url)}
                          </a>
                          {via && <span className="kg-source-via">via {via}</span>}
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })()}
            </>
          ) : (
            <p>Click a node to expand neighbors and see the source URLs it came from. Hover to see its label on the graph.</p>
          )}
        </div>
      </div>
    </div>
  );
}

/* ────── Graph Explorer (unified) ────── */

function GraphExplorer({
  explorerState,
  patchExplorer,
}: {
  explorerState: ExplorerState;
  patchExplorer: (p: Partial<ExplorerState>) => void;
}) {
  const { graphData, graphError, selectedItem, selectedKind, tablePage } = explorerState;
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<ExplorerViewMode>("kg");
  // Once the KG view has been opened we keep it mounted (as an overlay) so that
  // toggling back to the ontology view doesn't remount/reset either graph.
  const [kgEverShown, setKgEverShown] = useState(false);
  useEffect(() => { if (viewMode === "kg") setKgEverShown(true); }, [viewMode]);
  const [searchParams, setSearchParams] = useSearchParams();
  const focusParam = searchParams.get("focus") || "";

  // A ?focus=<id> deep-link opens the Knowledge Graph view on that node. We
  // capture the term once, switch views, then strip the param from the URL so
  // re-renders / back-navigation don't keep re-triggering it.
  const [focusQuery, setFocusQuery] = useState("");
  useEffect(() => {
    if (!focusParam) return;
    setFocusQuery(focusParam);
    setViewMode("kg");
    const next = new URLSearchParams(searchParams);
    next.delete("focus");
    setSearchParams(next, { replace: true });
  }, [focusParam]); // eslint-disable-line react-hooks/exhaustive-deps
  const graphRef = useRef<any>(null);
  const graphWrapRef = useRef<HTMLDivElement>(null);
  const [graphWidth, setGraphWidth] = useState<number | undefined>(undefined);
  const [graphHeight, setGraphHeight] = useState<number>(640);
  const tableOpen = !!(selectedItem && selectedKind);
  const [tableFullWidth, setTableFullWidth] = useState(false);
  const hasSavedView = useRef(!!loadSavedCamera());
  const cameraTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const restoreRaf1Ref = useRef<number | null>(null);
  const restoreRaf2Ref = useRef<number | null>(null);
  const [isViewReady, setIsViewReady] = useState(!hasSavedView.current);

  const closeTable = useCallback(() => {
    setTableFullWidth(false);
    patchExplorer({ selectedItem: "", selectedKind: "", tablePage: 0 });
  }, [patchExplorer]);

  useEffect(() => {
    if (!tableOpen) setTableFullWidth(false);
  }, [tableOpen]);

  useEffect(() => {
    setLoading(true);
    patchExplorer({ graphError: "" });
    fetchOntologyGraph()
      .then((res: any) => {
        const savedPositions = loadSavedNodePositions();
        const nodes: GNode[] = (res.nodes || []).map((n: GNode) => {
          const saved = savedPositions[n.id];
          if (!saved) return n;
          return { ...n, x: saved.x, y: saved.y, fx: saved.x, fy: saved.y };
        });
        patchExplorer({ graphData: { nodes, links: res.links || [] } });
        if (!nodes.length) patchExplorer({ graphError: "No ontology classes found in RDF." });
      })
      .catch((e: any) => {
        patchExplorer({ graphError: e.response?.data?.error || e.message, graphData: { nodes: [], links: [] } });
      })
      .finally(() => setLoading(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const el = graphWrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      setGraphWidth(w > 0 ? w : undefined);
      setGraphHeight(h > 0 ? h : 640);
    });
    ro.observe(el);
    setGraphWidth(el.clientWidth > 0 ? el.clientWidth : undefined);
    setGraphHeight(el.clientHeight > 0 ? el.clientHeight : 640);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    fg.d3Force("charge")?.strength(-2000).distanceMax(600);
    fg.d3Force("link")?.distance(260);
    fg.d3Force("center")?.strength(0.03);
  }, [graphData]);

  useEffect(() => {
    if (!graphRef.current || graphData.nodes.length === 0) return;
    // Wait for the canvas to have real dimensions. react-force-graph resets its
    // zoom transform whenever width/height change, so a camera restore applied
    // before the size settles gets clobbered — this was the cause of the graph
    // appearing zoomed-in when returning to the Explorer tab. Depending on
    // graphWidth/graphHeight also re-applies the saved view after any resize.
    if (!graphWidth || !graphHeight) return;
    if (hasSavedView.current) {
      const cam = loadSavedCamera();
      if (cam) {
        setIsViewReady(false);
        restoreRaf1Ref.current = requestAnimationFrame(() => {
          const fg = graphRef.current;
          if (!fg) return;
          fg.centerAt(cam.x, cam.y, 0);
          fg.zoom(cam.k, 0);
          restoreRaf2Ref.current = requestAnimationFrame(() => setIsViewReady(true));
        });
        return () => {
          if (restoreRaf1Ref.current != null) cancelAnimationFrame(restoreRaf1Ref.current);
          if (restoreRaf2Ref.current != null) cancelAnimationFrame(restoreRaf2Ref.current);
        };
      }
    }
    setIsViewReady(true);
    const t = setTimeout(() => graphRef.current?.zoomToFit(400, 40), 0);
    return () => clearTimeout(t);
  }, [graphData, graphWidth, graphHeight]); // eslint-disable-line react-hooks/exhaustive-deps

  /** Re-fit when panel opens/closes or graph width changes — only if user hasn't set their own view. */
  useEffect(() => {
    if (!graphRef.current || graphData.nodes.length === 0) return;
    if (hasSavedView.current) return;
    const t = window.setTimeout(() => graphRef.current?.zoomToFit(400, 48), 320);
    return () => window.clearTimeout(t);
  }, [tableOpen, tableFullWidth, graphWidth, graphData.nodes.length]);

  const handleNodeClick = useCallback(
    (node: any) => {
      patchExplorer({ selectedItem: node.label, selectedKind: "class", tablePage: 0 });
    },
    [patchExplorer]
  );

  const handleNodeDragEnd = useCallback(
    (draggedNode: any) => {
      draggedNode.fx = draggedNode.x;
      draggedNode.fy = draggedNode.y;
      persistNodePositions(graphData.nodes);
    },
    [graphData.nodes]
  );

  const handleZoom = useCallback(() => {
    if (cameraTimerRef.current) clearTimeout(cameraTimerRef.current);
    cameraTimerRef.current = setTimeout(() => {
      const fg = graphRef.current;
      if (!fg) return;
      persistCamera(fg);
      hasSavedView.current = true;
    }, 400);
  }, []);

  const handleLinkClick = useCallback(
    (link: any) => {
      if (!link.label) return;
      patchExplorer({ selectedItem: link.label, selectedKind: "edge", tablePage: 0 });
    },
    [patchExplorer]
  );

  const buildTooltip = useCallback((n: any) => {
    return `<b style="font-size:13px">${n.label}</b><br/><span style="opacity:0.6">Click to view instances</span>`;
  }, []);

  const renderGraph = () => (
    graphData.nodes.length > 0 ? (
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={graphWidth}
        height={graphHeight}
        nodeVal={() => 80}
        nodeColor={(n: any) => n.color}
        nodeCanvasObjectMode={() => "replace"}
        nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) =>
          paintUmlPointerArea(node, color, ctx)}
        linkPointerAreaPaint={(link: any, color: string, ctx: CanvasRenderingContext2D) => {
          const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
          if (![sx, sy, tx, ty].every(Number.isFinite)) return;

          // 1) Wide invisible stroke as the primary click target.
          ctx.strokeStyle = color;
          ctx.lineWidth = 24;
          ctx.lineCap = "round";
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();

          // 2) Include label box in hit area.
          if (link.label) {
            const mx = (sx + tx) / 2, my = (sy + ty) / 2;
            ctx.font = "bold 13px -apple-system, BlinkMacSystemFont, sans-serif";
            const tw = ctx.measureText(link.label).width;
            const padX = 10, padY = 11;
            ctx.fillStyle = color;
            ctx.fillRect(mx - tw / 2 - padX, my - padY, tw + padX * 2, padY * 2);
          }
        }}
        nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D) => {
          drawUmlBox(ctx, node, selectedItem === node.label && selectedKind === "class");
        }}
        linkColor={(link: any) =>
          selectedItem === link.label && selectedKind === "edge" ? "#1d4ed8" : "#60a5fa"}
        linkWidth={(link: any) =>
          selectedItem === link.label && selectedKind === "edge" ? 4 : 2.5}
        linkCurvature={0}
        d3VelocityDecay={0.38}
        d3AlphaDecay={0.05}
        d3AlphaMin={0.001}
        autoPauseRedraw={false}
        linkDirectionalArrowLength={0}
        linkCanvasObjectMode={() => "after"}
        linkCanvasObject={(link: any, ctx: CanvasRenderingContext2D) => {
          const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
          if (![sx, sy, tx, ty].every(Number.isFinite)) return;
          const isSelected = link.label && selectedItem === link.label && selectedKind === "edge";

          const dx = tx - sx, dy = ty - sy;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 1) return;
          const ux = dx / dist, uy = dy / dist;

          const targetBounds = getUmlBoxBounds(link.target);
          const halfW = targetBounds.boxW / 2 + 4;
          const halfH = targetBounds.boxH / 2 + 4;
          const tEntry = Math.min(
            Math.abs(ux) > 0.001 ? halfW / Math.abs(ux) : Infinity,
            Math.abs(uy) > 0.001 ? halfH / Math.abs(uy) : Infinity,
          );
          const arrowTipX = tx - ux * tEntry;
          const arrowTipY = ty - uy * tEntry;

          const arrowLen = 14;
          const arrowHalfW = 6;
          const baseX = arrowTipX - ux * arrowLen;
          const baseY = arrowTipY - uy * arrowLen;
          const perpX = -uy, perpY = ux;

          ctx.beginPath();
          ctx.moveTo(arrowTipX, arrowTipY);
          ctx.lineTo(baseX + perpX * arrowHalfW, baseY + perpY * arrowHalfW);
          ctx.lineTo(baseX - perpX * arrowHalfW, baseY - perpY * arrowHalfW);
          ctx.closePath();
          ctx.fillStyle = isSelected ? "#1e40af" : "#2563eb";
          ctx.fill();

          if (link.label) {
            const mx = (sx + tx) / 2, my = (sy + ty) / 2;
            ctx.font = `bold ${isSelected ? 14 : 13}px -apple-system, BlinkMacSystemFont, sans-serif`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            const tw = ctx.measureText(link.label).width;
            const padX = 7, padY = 10, boxH = padY * 2;
            ctx.fillStyle = isSelected ? "#dbeafe" : "#fff";
            ctx.fillRect(mx - tw / 2 - padX, my - padY, tw + padX * 2, boxH);
            if (isSelected) {
              ctx.strokeStyle = "#2563eb";
              ctx.lineWidth = 1.5;
              ctx.strokeRect(mx - tw / 2 - padX, my - padY, tw + padX * 2, boxH);
            }
            ctx.fillStyle = isSelected ? "#1e3a8a" : "#1d4ed8";
            ctx.fillText(link.label, mx, my);
          }
        }}
        nodeLabel={buildTooltip}
        onNodeClick={handleNodeClick}
        onNodeDragEnd={handleNodeDragEnd}
        onLinkClick={handleLinkClick}
        onBackgroundClick={closeTable}
        onZoom={handleZoom}
        linkHoverPrecision={18}
        cooldownTicks={200}
        warmupTicks={120}
      />
    ) : (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: graphHeight, color: "#9ca3af", fontSize: 14 }}>
        {loading ? "Loading ontology…" : "Could not load ontology graph"}
      </div>
    )
  );

  return (
    <div className="explorer-root">
      {graphError && <div className="error">{graphError}</div>}
      <div className="explorer-toolbar">
        <div className="explorer-view-switch">
          <button
            type="button"
            className={`view-btn${viewMode === "ontology" ? " active" : ""}`}
            onClick={() => setViewMode("ontology")}
          >
            Ontology View
          </button>
          <button
            type="button"
            className={`view-btn${viewMode === "kg" ? " active" : ""}`}
            onClick={() => setViewMode("kg")}
          >
            Knowledge Graph View
          </button>
        </div>
      </div>
      <div className="explorer-views">
        {/* Ontology view is always mounted in normal flow, so its force-graph
            keeps the same canvas dimensions (and therefore its camera/zoom)
            when you switch to the KG view and back. */}
        <div className={`ont-split${tableOpen && tableFullWidth ? " ont-split--table-full" : ""}`}>
          <div
            ref={graphWrapRef}
            className="ont-split-graph card"
            style={{ padding: 0, overflow: "hidden" }}
          >
            {renderGraph()}
          </div>
          <div className={`ont-split-table${tableOpen ? " open" : ""}`}>
            {tableOpen && (
              <DataTable
                selectedItem={selectedItem}
                selectedKind={selectedKind}
                page={tablePage}
                setPage={(p) => patchExplorer({ tablePage: p })}
                onClose={closeTable}
                fullWidth={tableFullWidth}
                onToggleFullWidth={() => setTableFullWidth((v) => !v)}
              />
            )}
          </div>
        </div>

        {/* KG view: lazily mounted on first open, then kept alive as an overlay
            (hidden, not unmounted) so neither graph resets on view toggle. */}
        {kgEverShown && (
          <div className={`explorer-kg-layer${viewMode === "kg" ? "" : " hidden"}`} aria-hidden={viewMode !== "kg"}>
            <KnowledgeGraphExplorer focusQuery={focusQuery} />
          </div>
        )}
      </div>
    </div>
  );
}
