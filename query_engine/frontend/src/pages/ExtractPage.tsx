import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  fetchRecentRuns,
  stopAllRuns,
  stopRun,
  fetchUrls,
  addUrl,
  deleteUrl,
  clearAllUrls,
  previewUrlById,
  mergeUrlById,
} from "../api";

// ── Types ─────────────────────────────────────────────────────────────

interface CanonicalEntity {
  canonical_key: string;
  attributes: Record<string, any>;
  is_partial: boolean;
}
interface Relation {
  predicate: string;
  subject: string;
  object: string;
}
interface ExtractionResponse {
  url: string;
  markdown_length: number;
  status?: UrlRow["status"];
  cached?: boolean;
  extraction: {
    entities_by_class: Record<string, CanonicalEntity[]>;
    relations: Relation[];
    vulnerabilities: any[];
    entity_counts: Record<string, number>;
    partial_rate: number;
    warnings: string[];
    errors: string[];
    chunks_total: number;
    chunks_extracted: number;
  };
  db_stats: Record<string, number> | null;
  vuln_count: number;
}

interface UrlRow {
  id: number;
  url: string;
  status: "never" | "extracted" | "merged" | "stale" | "error";
  raw_status?: "never" | "fresh" | "stale" | "error";
  entities_count: number | null;
  last_ingested: string | null;
  last_activity?: string | null;
  error: string | null;
  source_id: string | null;
  preview_cached?: boolean;
}

interface RunRow {
  id: number;
  source_id: string | null;
  url: string | null;
  started_at: string | null;
  finished_at: string | null;
  status: "running" | "success" | "error" | "cancelled";
  entities_inserted: number;
  same_as_edges: number;
  chunks_extracted: number;
  error_message: string | null;
}

// Per-row preview/consolidate state. Kept in a map keyed by URL id so multiple
// rows can stay expanded and each remembers its own data + expand/collapse
// state across list refreshes.
interface PreviewState {
  open: boolean;
  loading: boolean;
  data: ExtractionResponse | null;
  error: string;
  merging: boolean;
  startedAt: number;
}
const DEFAULT_PREVIEW: PreviewState = {
  open: false, loading: false, data: null, error: "", merging: false, startedAt: 0,
};

interface ConfirmState {
  title: string;
  message: React.ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
}

const STATUS_COLORS: Record<string, string> = {
  fresh: "#22c55e",
  merged: "#22c55e",
  extracted: "#4f8cff",
  stale: "#f59e0b",
  never: "#94a3b8",
  error: "#ef4444",
  running: "#4f8cff",
  success: "#22c55e",
  cancelled: "#6b7280",
};

const COLUMN_ORDER: Record<string, string[]> = {
  Vulnerability: ["vuln_id", "title", "description", "cvss_severity", "cvss_base_score", "date_published", "credit"],
  Vendor: ["name"],
  Software: ["name", "is_ai", "software_type"],
  Version: ["version_string"],
  License: ["name"],
  VulnerabilityType: ["id", "description"],
  SoftwareType: ["name"],
  Attack: ["name", "description"],
  Impact: ["name", "description"],
};

// Classes to hide as separate tables (merged into their parent table)
const MERGED_CLASSES = new Set(["VulnerabilityType", "SoftwareType"]);

const CLASS_ORDER = ["Vulnerability", "VulnerabilityType", "Attack", "Impact", "Vendor", "Software", "Version", "License", "SoftwareType"];

// ── Page ──────────────────────────────────────────────────────────────

export default function ExtractPage() {
  return (
    <div className="extract-page">
      <UrlList />
    </div>
  );
}

function ExtractResult({ data }: { data: ExtractionResponse }) {
  const ext = data.extraction;
  const classes = Object.keys(ext.entities_by_class).sort(
    (a, b) => CLASS_ORDER.indexOf(a) - CLASS_ORDER.indexOf(b)
  );

  // Build a map: vulnerability canonical_key -> VulnerabilityType description
  const vulnTypeMap: Record<string, string> = {};
  const vtEntities = ext.entities_by_class["VulnerabilityType"] || [];
  const vtByKey: Record<string, CanonicalEntity> = {};
  for (const vt of vtEntities) {
    vtByKey[vt.canonical_key] = vt;
  }
  for (const rel of ext.relations) {
    if (rel.predicate === "isA_vulnType" && vtByKey[rel.object]) {
      const vt = vtByKey[rel.object];
      const id = vt.attributes.id || "";
      const desc = vt.attributes.description || "";
      vulnTypeMap[rel.subject] = id ? `${id}: ${desc}` : desc;
    }
  }

  return (
    <div className="extract-results">
      {classes.length === 0 && (
        <div className="card">
          <div style={{ color: "#94a3b8" }}>No entities extracted from this page.</div>
        </div>
      )}

      {classes.map((cls) => {
        // Skip merged classes — they're shown inline in their parent table
        if (MERGED_CLASSES.has(cls)) return null;
        return (
          <EntityTable
            key={cls}
            className={cls}
            entities={ext.entities_by_class[cls]}
            vulnTypeMap={cls === "Vulnerability" ? vulnTypeMap : undefined}
          />
        );
      })}
    </div>
  );
}

// After consolidation, lead with a plain-language summary and the actual
// vulnerabilities that landed (id, title, what they connected to), then tuck
// the raw row/link counts into a collapsible breakdown.
function ConsolidationSummary({ data }: { data: ExtractionResponse }) {
  const [showBreakdown, setShowBreakdown] = useState(false);
  const s = data.db_stats || {};
  const num = (k: string) => Number(s[k] || 0);
  const hasStats = !!data.db_stats;

  const added: [string, number][] = [
    ["vulnerability", num("vulnerabilities_inserted")],
    ["vendor", num("vendors_inserted")],
    ["software", num("software_inserted")],
    ["version", num("versions_inserted")],
    ["license", num("licenses_inserted")],
    ["CWE type", num("vuln_types_inserted")],
    ["attack", num("attacks_inserted")],
    ["impact", num("impacts_inserted")],
  ];
  const reused: [string, number][] = [
    ["vulnerability", num("vulnerabilities_reused")],
    ["vendor", num("vendors_reused")],
    ["software", num("software_reused")],
    ["version", num("versions_reused")],
    ["CWE type", num("vuln_types_reused")],
    ["attack", num("attacks_reused")],
    ["impact", num("impacts_reused")],
  ];
  const linked: [string, number][] = [
    ["affected-software link", num("vulnerable_to_links")],
    ["CWE classification", num("is_a_links")],
    ["vendor → product link", num("produce_links")],
    ["dependency link", num("depends_on_links")],
    ["attack → vuln link", num("exploits_links")],
    ["vuln → impact link", num("results_in_links")],
    ["duplicate merged", num("same_as_edges_written")],
  ];
  const totalAdded = added.reduce((a, [, n]) => a + n, 0);
  const totalReused = reused.reduce((a, [, n]) => a + n, 0);
  const totalLinks = linked.reduce((a, [, n]) => a + n, 0);
  const skipped = num("skipped_partial") + num("skipped_no_id");

  const vulnsInserted = num("vulnerabilities_inserted");
  const vulnsReused = num("vulnerabilities_reused");

  // Enrich each extracted vulnerability with its CWE + affected software,
  // derived from the relations, so the cards tell the connection story.
  const ext = data.extraction;
  const vtById: Record<string, string> = {};
  for (const vt of ext.entities_by_class["VulnerabilityType"] || []) {
    vtById[vt.canonical_key] = String(vt.attributes.id || vt.attributes.description || "").trim();
  }
  const swByKey: Record<string, string> = {};
  for (const sw of ext.entities_by_class["Software"] || []) {
    swByKey[sw.canonical_key] = String(sw.attributes.name || "").trim();
  }
  const cweOf: Record<string, Set<string>> = {};
  const swOf: Record<string, Set<string>> = {};
  for (const r of ext.relations) {
    if (r.predicate === "isA_vulnType" && vtById[r.object]) {
      (cweOf[r.subject] ||= new Set()).add(vtById[r.object]);
    }
    if (r.predicate === "vulnerableTo" && swByKey[r.subject]) {
      (swOf[r.object] ||= new Set()).add(swByKey[r.subject]);
    }
  }
  const vulns = (ext.entities_by_class["Vulnerability"] || []).filter((v) => v.attributes.vuln_id);

  // Per-card new/reused verdict — only when unambiguous (avoid mislabeling
  // mixed batches). Minted ids are always brand-new findings.
  const verdict = (v: CanonicalEntity): "new" | "reused" | null => {
    if (v.attributes._minted_id) return "new";
    if (vulnsInserted > 0 && vulnsReused === 0) return "new";
    if (vulnsReused > 0 && vulnsInserted === 0) return "reused";
    return null;
  };

  // Plain-language headline.
  const addedPhrase = phraseList(added);
  let headline: React.ReactNode;
  if (!hasStats) {
    headline = "Already consolidated — open the records below.";
  } else if (totalAdded === 0 && totalReused > 0) {
    headline = <>Everything was already in the knowledge base — <strong>{totalReused}</strong> record{totalReused === 1 ? "" : "s"} matched and reused, <strong>no duplicates</strong> created.</>;
  } else if (totalAdded === 0) {
    headline = "No new records were added from this page.";
  } else {
    headline = (
      <>
        Added <strong>{addedPhrase}</strong> to the knowledge base
        {totalReused > 0 && <> · reused {totalReused} existing</>}
        {totalLinks > 0 && <> · {totalLinks} link{totalLinks === 1 ? "" : "s"} created</>}.
      </>
    );
  }

  return (
    <div className="consolidate-summary">
      <div className="consolidate-head"><IconCheck /> Consolidated into the knowledge base</div>
      <div className="consolidate-headline">{headline}</div>

      {vulns.length > 0 && (
        <div className="consolidate-vulns">
          {vulns.map((v) => (
            <VulnResultCard
              key={v.canonical_key}
              vuln={v}
              cwes={Array.from(cweOf[v.canonical_key] || [])}
              software={Array.from(swOf[v.canonical_key] || [])}
              verdict={verdict(v)}
            />
          ))}
        </div>
      )}

      {hasStats && skipped > 0 && (
        <div className="consolidate-note">{skipped} incomplete record{skipped === 1 ? "" : "s"} skipped (missing required fields).</div>
      )}

      {hasStats && (
        <>
          <button
            type="button"
            className="consolidate-breakdown-toggle"
            onClick={() => setShowBreakdown((x) => !x)}
            aria-expanded={showBreakdown}
          >
            {showBreakdown ? "▾" : "▸"} Full breakdown
          </button>
          {showBreakdown && (
            <div className="consolidate-cols">
              <SummaryCol title="Added (new rows)" tone="add" items={added} />
              <SummaryCol title="Reused (already in DB)" tone="reuse" items={reused} />
              <SummaryCol title="Links created" tone="link" items={linked} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

// One vulnerability that landed, with its connections and a status badge.
function VulnResultCard({
  vuln, cwes, software, verdict,
}: {
  vuln: CanonicalEntity;
  cwes: string[];
  software: string[];
  verdict: "new" | "reused" | null;
}) {
  const id = String(vuln.attributes.vuln_id || "");
  const title = String(vuln.attributes.title || "").trim();
  const minted = !!vuln.attributes._minted_id;
  const severity = vuln.attributes.cvss_severity ? String(vuln.attributes.cvss_severity) : "";
  const sevColor = ({ CRITICAL: "#7f1d1d", HIGH: "#dc2626", MEDIUM: "#f59e0b", LOW: "#22c55e" } as Record<string, string>)[severity] || "#6b7280";

  return (
    <div className="vuln-result-card">
      <div className="vuln-result-top">
        <Link to={`/vuln/${id}`} className="vuln-result-id">{id}</Link>
        {verdict === "new" && <span className="vuln-tag vuln-tag--new">New</span>}
        {verdict === "reused" && <span className="vuln-tag vuln-tag--reused">Already in DB</span>}
        {minted && <span className="vuln-tag vuln-tag--minted" title="No official CVE/GHSA — the system minted this identifier for the finding">Minted ID</span>}
        {severity && <span className="vuln-tag" style={{ background: sevColor, color: "#fff" }}>{severity}</span>}
      </div>
      {title && <div className="vuln-result-title">{title}</div>}
      <div className="vuln-result-meta">
        {software.length > 0 && (
          <span className="vuln-result-rel">
            <span className="vuln-result-rel-label">affects</span> {software.join(", ")}
          </span>
        )}
        {cwes.length > 0 && (
          <span className="vuln-result-rel">
            <span className="vuln-result-rel-label">classified as</span> {cwes.join(", ")}
          </span>
        )}
      </div>
      <div className="vuln-result-actions">
        <Link to={`/vuln/${encodeURIComponent(id)}`} className="consolidate-link">View record ↗</Link>
        <Link to={`/?focus=${encodeURIComponent(id)}`} className="consolidate-link consolidate-link--graph">Open in graph ↗</Link>
      </div>
    </div>
  );
}

// "1 vulnerability, 1 software and 2 vendors"
function phraseList(items: [string, number][]): string {
  const clean = items
    .filter(([, n]) => n > 0)
    .map(([label, n]) => `${n} ${n > 1 ? pluralize(label) : label}`);
  if (clean.length === 0) return "nothing";
  if (clean.length === 1) return clean[0];
  return clean.slice(0, -1).join(", ") + " and " + clean[clean.length - 1];
}

function pluralize(label: string): string {
  if (label.endsWith("y")) return label.slice(0, -1) + "ies";
  return label + "s";
}

function SummaryCol({ title, tone, items }: { title: string; tone: string; items: [string, number][] }) {
  const shown = items.filter(([, n]) => n > 0);
  return (
    <div className={`consolidate-col consolidate-col--${tone}`}>
      <div className="consolidate-col-title">{title}</div>
      {shown.length === 0 ? (
        <div className="consolidate-col-empty">—</div>
      ) : (
        <ul>
          {shown.map(([label, n]) => (
            <li key={label}><span className="consolidate-count">{n}</span> {n > 1 ? pluralize(label) : label}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function EntityTable({
  className,
  entities,
  vulnTypeMap,
}: {
  className: string;
  entities: CanonicalEntity[];
  vulnTypeMap?: Record<string, string>;
}) {
  if (!entities || entities.length === 0) return null;

  const preferred = COLUMN_ORDER[className] || [];
  const seen = new Set<string>(preferred);
  for (const e of entities) {
    for (const k of Object.keys(e.attributes || {})) seen.add(k);
  }
  const extra = Array.from(seen).filter((k) => !preferred.includes(k)).sort();
  const showVulnType = className === "Vulnerability" && vulnTypeMap && Object.keys(vulnTypeMap).length > 0;

  // Insert vulnerability_type after "description" (before cvss_severity etc.)
  const baseColumns = [...preferred.filter((k) => seen.has(k)), ...extra];
  const columns: string[] = [];
  const vtInsertAfter = "description";
  let vtInserted = false;
  for (const c of baseColumns) {
    columns.push(c);
    if (showVulnType && c === vtInsertAfter && !vtInserted) {
      columns.push("vulnerability_type");
      vtInserted = true;
    }
  }
  if (showVulnType && !vtInserted) columns.push("vulnerability_type");

  return (
    <div className="card entity-table-card">
      <div className="entity-table-header">
        <h4>{className}</h4>
        <span className="badge" style={{ background: "#e2e8f0", color: "#475569" }}>
          {entities.length}
        </span>
      </div>
      <div className="entity-table-wrap">
        <table className="entity-table">
          <thead>
            <tr>
              {columns.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {entities.map((e, i) => (
              <tr key={i} className={e.is_partial ? "row-partial" : ""}>
                {columns.map((c) => {
                  if (c === "vulnerability_type") {
                    return (
                      <td key={c}>
                        {vulnTypeMap![e.canonical_key] ? (
                          <span className="badge" style={{ background: "#dbeafe", color: "#1e40af", fontWeight: 500 }}>
                            {vulnTypeMap![e.canonical_key]}
                          </span>
                        ) : (
                          <span style={{ color: "#cbd5e1" }}>—</span>
                        )}
                      </td>
                    );
                  }
                  return <td key={c}>{renderAttr(className, c, e.attributes[c])}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function renderAttr(className: string, attr: string, v: any): React.ReactNode {
  if (v === null || v === undefined || v === "") return <span style={{ color: "#cbd5e1" }}>—</span>;
  if (Array.isArray(v)) {
    if (v.length === 0) return <span style={{ color: "#cbd5e1" }}>—</span>;
    return <span title={v.join(", ")}>{v.length} items</span>;
  }
  if (typeof v === "boolean") {
    if (className === "Software" && attr === "is_ai") {
      return v
        ? <span className="badge" style={{ background: "#dbeafe", color: "#1e40af" }}>AI</span>
        : <span className="badge" style={{ background: "#f1f5f9", color: "#64748b" }}>Non-AI</span>;
    }
    return v ? "yes" : "no";
  }
  if (typeof v === "object") return <code style={{ fontSize: 11 }}>{JSON.stringify(v)}</code>;
  if (className === "Software" && attr === "software_type") {
    const typeColors: Record<string, string> = {
      "Application": "#7c3aed", "AI Component": "#2563eb", "ML Infrastructure": "#0891b2",
      "Library": "#059669", "Agent": "#d97706", "Model": "#dc2626",
      "Skill": "#7c3aed", "Database": "#475569", "Dataset": "#475569",
    };
    const bg = typeColors[String(v)] || "#64748b";
    return <span className="badge" style={{ background: bg, color: "#fff" }}>{String(v)}</span>;
  }
  const s = String(v);
  if (className === "Vulnerability" && attr === "vuln_id") {
    return <Link to={`/vuln/${s}`}>{s}</Link>;
  }
  if (className === "Vulnerability" && attr === "cvss_severity") {
    const c = { CRITICAL: "#7f1d1d", HIGH: "#dc2626", MEDIUM: "#f59e0b", LOW: "#22c55e" }[s] || "#6b7280";
    return <span className="badge" style={{ background: c, color: "#fff" }}>{s}</span>;
  }
  if (s.length > 120) return <span title={s}>{s.slice(0, 117)}…</span>;
  return s;
}

// ── Status-aware extract button ───────────────────────────────────────

type ExtractIconButtonProps = {
  status: UrlRow["status"];
  isRunning: boolean;
  isOpen: boolean;
  isBusy: boolean;
  elapsed: number;
  onClick: () => void;
};

function ExtractIconButton({ status, isRunning, isOpen, isBusy, elapsed, onClick }: ExtractIconButtonProps) {
  // Choose variant based on state.
  let variant: "extract" | "done" | "retry" | "close" | "running" | "merged" = "extract";
  let label = "Extract";
  let title = "Run extraction (preview, no DB write)";
  let icon: React.ReactNode = <IconPlay />;

  if (isRunning) {
    variant = "running";
    label = "Running…";
    title = "Extraction running in background";
    icon = <span className="extract-spinner" />;
  } else if (isOpen) {
    variant = "close";
    label = isBusy ? `Previewing ${elapsed}s` : "Close";
    title = isBusy ? "Preview in progress" : "Close preview";
    icon = isBusy ? <span className="extract-spinner" /> : <IconX />;
  } else if (status === "merged") {
    variant = "merged";
    label = "Merged";
    title = "Open cached extraction result";
    icon = <IconCheck />;
  } else if (status === "extracted") {
    variant = "done";
    label = "Extracted";
    title = "Open cached extraction result";
    icon = <IconCheck />;
  } else if (status === "stale") {
    variant = "retry";
    label = "Re-extract";
    title = "Source has changed · re-run extraction";
    icon = <IconRefresh />;
  } else if (status === "error") {
    variant = "retry";
    label = "Retry";
    title = "Last run errored · try again";
    icon = <IconRefresh />;
  }

  return (
    <button
      className={`btn btn-icon btn-extract btn-extract--${variant}`}
      onClick={onClick}
      disabled={isRunning || isBusy}
      title={title}
      aria-label={label}
    >
      <span className="btn-extract-icon">{icon}</span>
      <span className="btn-extract-label">{label}</span>
    </button>
  );
}

function IconPlay() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path d="M2 1 L9 5 L2 9 Z" fill="currentColor" />
    </svg>
  );
}
function IconCheck() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
      <path d="M2 6.5 L4.8 9.2 L10 3.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  );
}
function IconRefresh() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
      <path
        d="M10 6 a4 4 0 1 1 -1.2 -2.83"
        stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round"
      />
      <path d="M10 1.5 L10 4 L7.5 4" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function IconX() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path d="M1.5 1.5 L8.5 8.5 M8.5 1.5 L1.5 8.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" fill="none" />
    </svg>
  );
}

// ── In-app confirmation modal (replaces window.confirm) ───────────────

function ConfirmDialog({ state, onClose }: { state: ConfirmState; onClose: () => void }) {
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !busy) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const run = async () => {
    setBusy(true);
    try { await state.onConfirm(); onClose(); }
    finally { setBusy(false); }
  };

  return (
    <div className="modal-overlay" onClick={() => { if (!busy) onClose(); }}>
      <div className="modal-card" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="modal-title">{state.title}</div>
        <div className="modal-body">{state.message}</div>
        <div className="modal-actions">
          <button className="btn btn-inline btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button
            className={`btn btn-inline${state.danger ? " btn-danger" : ""}`}
            onClick={run}
            disabled={busy}
            autoFocus
          >
            {busy ? "Working…" : state.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Flat URL list ─────────────────────────────────────────────────────

function UrlList() {
  const [urls, setUrls] = useState<UrlRow[]>([]);
  const [newUrl, setNewUrl] = useState("");
  const [adding, setAdding] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [message, setMessage] = useState("");
  const [running, setRunning] = useState<RunRow[]>([]);
  const [stopping, setStopping] = useState(false);
  const [loaded, setLoaded] = useState(false);

  // Preview-and-consolidate state, kept per row (see PreviewState).
  const [previews, setPreviews] = useState<Record<number, PreviewState>>({});
  const [, setNowTick] = useState(0);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);

  const patchPreview = useCallback((id: number, patch: Partial<PreviewState>) => {
    setPreviews((prev) => ({
      ...prev,
      [id]: { ...DEFAULT_PREVIEW, ...prev[id], ...patch },
    }));
  }, []);

  // One ticking clock drives every row's elapsed counter while it's loading.
  const anyLoading = Object.values(previews).some((p) => p.loading);
  useEffect(() => {
    if (!anyLoading) return;
    const t = setInterval(() => setNowTick(Date.now()), 200);
    return () => clearInterval(t);
  }, [anyLoading]);

  const loadUrls = useCallback(async () => {
    const data = await fetchUrls();
    setUrls(data.urls || []);
    setLoaded(true);
  }, []);

  const loadRuns = useCallback(async () => {
    const data = await fetchRecentRuns(undefined, 30);
    const all: RunRow[] = data.runs || [];
    setRunning(all.filter((r) => r.status === "running"));
  }, []);

  useEffect(() => {
    loadUrls();
    loadRuns();
    const t = setInterval(loadRuns, 2500);
    return () => clearInterval(t);
  }, [loadUrls, loadRuns]);

  // When anything finishes running, reload the URL list.
  const prevRunning = useRef(0);
  useEffect(() => {
    if (prevRunning.current > 0 && running.length === 0) loadUrls();
    prevRunning.current = running.length;
  }, [running, loadUrls]);

  // Poll URL list while something is running so status updates propagate.
  useEffect(() => {
    if (running.length === 0) return;
    const t = setInterval(loadUrls, 4000);
    return () => clearInterval(t);
  }, [running, loadUrls]);

  const handleAdd = async () => {
    const u = newUrl.trim();
    if (!u) return;
    setAdding(true);
    setMessage("");
    try {
      const out = await addUrl(u);
      setMessage(out.created ? "URL added" : "URL already in the list");
      setNewUrl("");
      await loadUrls();
    } catch (e: any) {
      setMessage(e.response?.data?.error || e.message);
    } finally {
      setAdding(false);
    }
  };

  // Collapse a row but keep its fetched data so re-expanding is instant.
  const collapse = (id: number) => patchPreview(id, { open: false });

  const handlePreview = async (row: UrlRow) => {
    const cur = previews[row.id];
    if (cur?.open) { patchPreview(row.id, { open: false }); return; }   // collapse, keep data
    if (cur?.data) { patchPreview(row.id, { open: true }); return; }    // re-open instantly
    patchPreview(row.id, { open: true, loading: true, error: "", data: null, startedAt: Date.now() });
    setMessage("");
    try {
      const data: ExtractionResponse = await previewUrlById(row.id);
      patchPreview(row.id, { loading: false, data });
      await loadUrls();
    } catch (e: any) {
      patchPreview(row.id, { loading: false, error: e.response?.data?.error || e.message || "Preview failed" });
    }
  };

  const handleMerge = async (row: UrlRow) => {
    patchPreview(row.id, { merging: true });
    setMessage("");
    try {
      const data: ExtractionResponse = await mergeUrlById(row.id);
      patchPreview(row.id, { merging: false, data, open: true });
      setMessage("Consolidated into the database.");
      await loadUrls();
    } catch (e: any) {
      patchPreview(row.id, { merging: false, error: e.response?.data?.error || e.message || "Consolidate failed" });
    }
  };

  const handleDelete = (row: UrlRow) => {
    setConfirmState({
      title: "Remove URL",
      message: <>Remove this URL from the list?<code className="confirm-mono">{row.url}</code></>,
      confirmLabel: "Remove",
      danger: true,
      onConfirm: async () => {
        try {
          setPreviews((prev) => { const n = { ...prev }; delete n[row.id]; return n; });
          await deleteUrl(row.id);
          await loadUrls();
        } catch (e: any) {
          setMessage(e.response?.data?.error || e.message);
        }
      },
    });
  };

  const handleClearAll = () => {
    if (urls.length === 0 || clearing) return;
    setConfirmState({
      title: "Delete all URLs",
      message: <>Delete all URLs from the list? This will remove <strong>{urls.length}</strong> row{urls.length === 1 ? "" : "s"}.</>,
      confirmLabel: "Delete all",
      danger: true,
      onConfirm: async () => {
        setClearing(true);
        setMessage("");
        try {
          setPreviews({});
          const out = await clearAllUrls();
          setMessage(`deleted ${out.deleted || 0} URL row${(out.deleted || 0) === 1 ? "" : "s"}`);
          await loadUrls();
        } catch (e: any) {
          setMessage(e.response?.data?.error || e.message || "Clear all failed");
        } finally {
          setClearing(false);
        }
      },
    });
  };

  const handleStopAll = async () => {
    if (running.length === 0 || stopping) return;
    setStopping(true);
    try {
      const out = await stopAllRuns();
      setMessage(`cancelled ${out.cancelled || 0} running task${(out.cancelled || 0) === 1 ? "" : "s"}`);
      await Promise.all([loadRuns(), loadUrls()]);
    } catch (e: any) {
      setMessage(`stop-all failed: ${e.response?.data?.error || e.message}`);
    } finally {
      setStopping(false);
    }
  };

  const handleStopRun = async (runId: number) => {
    try {
      await stopRun(runId);
      await Promise.all([loadRuns(), loadUrls()]);
    } catch (e: any) {
      setMessage(`stop failed: ${e.response?.data?.error || e.message}`);
    }
  };

  // Map url -> running run for showing "extracting" badge per row.
  const runningByUrl = useMemo(() => {
    const map: Record<string, RunRow> = {};
    for (const r of running) if (r.url) map[r.url] = r;
    return map;
  }, [running]);

  const filtered = urls;

  return (
    <div className="card urls-section">
      <div className="urls-actions">
        <input
          className="extract-url-input"
          type="url"
          placeholder="Add URL to the list…"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !adding) handleAdd(); }}
          disabled={adding}
        />
        <button className="btn" onClick={handleAdd} disabled={adding || !newUrl.trim()}>
          {adding ? "Adding…" : "Add"}
        </button>
        <button
          className="btn btn-ghost"
          onClick={handleClearAll}
          disabled={clearing || urls.length === 0}
          title="Delete all URLs from the list"
        >
          {clearing ? "Clearing…" : "Clear all"}
        </button>
      </div>

      {running.length > 0 && (
        <div className="runs-panel runs-panel--active">
          <div className="runs-panel-header">
            <span className="extract-spinner" />
            <strong>Extracting · {running.length} running</strong>
            <button className="btn btn-danger btn-inline" onClick={handleStopAll} disabled={stopping}>
              {stopping ? "Stopping…" : "Stop all"}
            </button>
          </div>
          <ul className="runs-panel-list">
            {running.map((r) => (
              <li key={r.id} className="run-item run-item--running">
                <span className="badge" style={{ background: STATUS_COLORS.running, color: "#fff" }}>running</span>
                <span className="run-url">{trunc(r.url || "", 100)}</span>
                <span className="run-elapsed">{elapsedSince(r.started_at)}</span>
                <button className="btn btn-danger btn-inline" onClick={() => handleStopRun(r.id)}>Stop</button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {message && <div className="sources-toast">{message}</div>}

      {!loaded ? (
        <div style={{ padding: 20, color: "#94a3b8" }}>Loading URLs…</div>
      ) : filtered.length === 0 ? (
        <div style={{ padding: 20, color: "#94a3b8" }}>
          No URLs yet. Add one above.
        </div>
      ) : (
        <ul className="url-flat-list">
          {filtered.map((u) => {
            const pv = previews[u.id] || DEFAULT_PREVIEW;
            const isRunning = !!runningByUrl[u.url];
            const isOpen = pv.open;
            const elapsed = pv.startedAt ? Math.floor((Date.now() - pv.startedAt) / 1000) : 0;
            return (
              <li
                key={u.id}
                className={`url-flat-item${isOpen ? " url-flat-item--open" : ""}`}
              >
                <div className="url-flat-row">
                  <span
                    className="status-dot"
                    style={{ background: isRunning ? STATUS_COLORS.running : STATUS_COLORS[u.status] }}
                    title={isRunning ? "running" : u.status}
                  />
                  <a
                    href={u.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="url-flat-link"
                  >
                    {u.url}
                  </a>
                  {u.entities_count != null && u.entities_count > 0 && (
                    <span className="url-flat-entities">{u.entities_count} entities</span>
                  )}
                  {u.status === "error" && u.error && (
                    <span className="url-flat-error" title={u.error}>{trunc(u.error, 40)}</span>
                  )}
                  <span className="url-flat-time">{fmtDate(u.last_activity || u.last_ingested)}</span>
                  <ExtractIconButton
                    status={u.status}
                    isRunning={isRunning}
                    isOpen={isOpen}
                    isBusy={isOpen && pv.loading}
                    elapsed={elapsed}
                    onClick={() => handlePreview(u)}
                  />
                  <button
                    className="btn btn-icon btn-ghost"
                    onClick={() => handleDelete(u)}
                    title="Remove from list"
                    aria-label="Remove"
                  >
                    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                      <path d="M2 2 L10 10 M10 2 L2 10" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" fill="none" />
                    </svg>
                  </button>
                </div>

                {isOpen && (
                  <div className="url-preview">
                    {pv.loading && (
                      <div className="url-preview-status">
                        <span className="extract-spinner" /> Previewing… {elapsed}s
                      </div>
                    )}
                    {pv.error && (
                      <div className="error" style={{ marginTop: 0 }}>{pv.error}</div>
                    )}
                    {pv.data && !pv.loading && (
                      <>
                        <div className="url-preview-toolbar">
                          <div className="url-preview-actions">
                            {pv.data.status !== "merged" && !pv.data.db_stats && (
                              <button
                                className="btn btn-inline"
                                onClick={() => handleMerge(u)}
                                disabled={pv.merging}
                                title="Consolidate these entities into the knowledge base"
                              >
                                {pv.merging ? "Consolidating…" : "Consolidate"}
                              </button>
                            )}
                            <button
                              className="btn btn-inline btn-ghost"
                              onClick={() => collapse(u.id)}
                              disabled={pv.merging}
                            >
                              Collapse
                            </button>
                          </div>
                        </div>
                        {(pv.data.db_stats || pv.data.status === "merged") && (
                          <ConsolidationSummary data={pv.data} />
                        )}
                        <ExtractResult data={pv.data} />
                      </>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {confirmState && (
        <ConfirmDialog state={confirmState} onClose={() => setConfirmState(null)} />
      )}
    </div>
  );
}

// ── Utils ─────────────────────────────────────────────────────────────

function trunc(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function fmtDate(s: string | null): string {
  if (!s) return "";
  return s.replace("T", " ").slice(0, 16);
}

function elapsedSince(startIso: string | null): string {
  if (!startIso) return "—";
  const started = Date.parse(startIso.replace(" ", "T"));
  if (Number.isNaN(started)) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - started) / 1000));
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}
