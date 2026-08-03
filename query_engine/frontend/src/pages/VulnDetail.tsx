import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { fetchVulnDetail } from "../api";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#7f1d1d", HIGH: "#dc2626", MEDIUM: "#f59e0b", LOW: "#22c55e",
};
const THREAT_LABEL: Record<number, string> = { 1: "High", 2: "Medium", 3: "Low", 4: "Undefined" };

export default function VulnDetail() {
  const { id } = useParams();
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (id) fetchVulnDetail(id).then(setData).catch(() => setErr("Not found"));
  }, [id]);

  if (err) return <div className="error">{err}</div>;
  if (!data) return <div className="loading">Loading…</div>;

  const refs: string[] = (() => {
    try { return JSON.parse(data.references_json || "[]"); } catch { return []; }
  })();

  return (
    <div>
      <Link to="/" style={{ fontSize: 13, color: "var(--accent)", textDecoration: "none", marginBottom: 16, display: "inline-block" }}>← Back</Link>

      <div className="page-header">
        <h1 style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {data.vuln_id}
          {!!data.exploited_in_wild && <span className="badge badge-kev">CISA KEV</span>}
          {data.ransomware_use === "Known" && <span className="badge badge-ransomware">Ransomware</span>}
        </h1>
        {data.title && <p style={{ fontSize: 14, color: "#6b7280", marginTop: 4 }}>{data.title}</p>}
      </div>

      {!!data.exploited_in_wild && (
        <div className="kev-banner" role="alert">
          <div className="kev-banner-icon" aria-hidden>⚠</div>
          <div className="kev-banner-body">
            <div className="kev-banner-title">Known Exploited Vulnerability</div>
            <div className="kev-banner-text">
              CISA has verified active, in-the-wild exploitation of this vulnerability.
              It is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog
              and should be treated as remediate-first.
            </div>
            <div className="kev-banner-meta">
              {data.exploitation_verified_date && (
                <div className="kev-banner-meta-item">
                  <span className="kev-banner-meta-label">Exploitation verified</span>
                  <span className="kev-banner-meta-value">{data.exploitation_verified_date}</span>
                </div>
              )}
              <div className="kev-banner-meta-item">
                <span className="kev-banner-meta-label">Ransomware campaign use</span>
                <span className="kev-banner-meta-value">{data.ransomware_use || "Unknown"}</span>
              </div>
            </div>
          </div>
          <a
            className="kev-banner-link"
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
            rel="noopener noreferrer"
          >
            CISA KEV Catalog ↗
          </a>
        </div>
      )}

      {data.external_ids?.length > 0 && (
        <div style={{ marginBottom: 16, display: "flex", gap: 8, flexWrap: "wrap" }}>
          {data.external_ids.map((eid: any, i: number) => (
            <span key={i} className="badge" style={{ background: "#dbeafe", color: "#1d4ed8", fontSize: 12 }}>
              {eid.source}: {eid.external_id}
            </span>
          ))}
        </div>
      )}

      {/* CVSS + Dates + MISP summary bar */}
      <div className="vuln-meta-bar">
        {data.cvss_base_score != null && (
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">CVSS</span>
            <span className="vuln-meta-value" style={{ fontWeight: 700, fontFamily: "monospace", fontSize: 16 }}>
              {data.cvss_base_score.toFixed(1)}
            </span>
            {data.cvss_severity && (
              <span className="badge" style={{ background: SEVERITY_COLOR[data.cvss_severity] || "#6b7280", color: "#fff", marginLeft: 6 }}>
                {data.cvss_severity}
              </span>
            )}
          </div>
        )}
        {data.date_published && (
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Published</span>
            <span className="vuln-meta-value">{data.date_published.slice(0, 10)}</span>
          </div>
        )}
        {data.date_updated && (
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Updated</span>
            <span className="vuln-meta-value">{data.date_updated.slice(0, 10)}</span>
          </div>
        )}
        {data.record_type && (
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Record Type</span>
            <span className="vuln-meta-value">{data.record_type}</span>
          </div>
        )}
        {data.credit && (
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Credit</span>
            <span className="vuln-meta-value">{data.credit}</span>
          </div>
        )}
      </div>

      {data.cvss_vector && (
        <div style={{ marginBottom: 16 }}>
          <span className="vuln-meta-label" style={{ marginRight: 8 }}>CVSS Vector</span>
          <code style={{ fontSize: 12, background: "#f1f5f9", padding: "4px 8px", borderRadius: 4 }}>{data.cvss_vector}</code>
        </div>
      )}

      {data.tags && (
        <div style={{ marginBottom: 16 }}>
          <span className="vuln-meta-label" style={{ marginRight: 8 }}>Tags</span>
          {data.tags.split(",").map((t: string, i: number) => (
            <span key={i} className="badge" style={{ background: "#e0e7ff", color: "#3730a3", marginRight: 4 }}>{t.trim()}</span>
          ))}
        </div>
      )}
      {(data.risk_domain || data.lifecycle_stage) && (
        <div style={{ marginBottom: 16, display: "flex", gap: 16, flexWrap: "wrap" }}>
          {data.risk_domain && (
            <span><span className="vuln-meta-label" style={{ marginRight: 6 }}>Risk Domain</span>{data.risk_domain}</span>
          )}
          {data.lifecycle_stage && (
            <span><span className="vuln-meta-label" style={{ marginRight: 6 }}>Lifecycle Stage</span>{data.lifecycle_stage}</span>
          )}
        </div>
      )}

      {data.description && (
        <div className="desc-box">{data.description}</div>
      )}

      {refs.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>References ({refs.length})</h3>
          <ul className="ref-list">
            {refs.map((url: string, i: number) => (
              <li key={i}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></li>
            ))}
          </ul>
        </div>
      )}

      {data.types?.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Vulnerability Type (CWE)</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Type ID</th><th>Description</th></tr></thead>
              <tbody>
                {data.types.map((c: any) => (
                  <tr key={c.id}><td style={{ fontWeight: 600, color: "#9f1239" }}>{c.id}</td><td>{c.description}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data.affected_software?.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Affected Software</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Vendor</th><th>Software</th><th>Version</th></tr></thead>
              <tbody>
                {data.affected_software.map((a: any, i: number) => (
                  <tr key={i}>
                    <td>{a.vendor || "—"}</td>
                    <td style={{ fontWeight: 500 }}>{a.software}</td>
                    <td style={{ fontFamily: "monospace" }}>{a.version_string}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data.affected_hardware?.length > 0 && (
        <div className="card">
          <h3>Affected Hardware</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Vendor</th><th>Hardware</th><th>Version</th></tr></thead>
              <tbody>
                {data.affected_hardware.map((a: any, i: number) => (
                  <tr key={i}>
                    <td>{a.vendor || "—"}</td>
                    <td style={{ fontWeight: 500 }}>{a.hardware}</td>
                    <td style={{ fontFamily: "monospace" }}>{a.version_string}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
