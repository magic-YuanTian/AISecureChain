"""
AISecureChain — Comprehensive Data-Driven Analysis
====================================================
All charts are derived purely from structured data fields.
No predefined keyword lists — frequencies are computed from the data itself.

Data sources:
  - MISP AI events (output/all_ai_events_full.json) — event metadata, CVSS, dates
  - cvelistV5 records (output/cve_details.json)     — CWE, vendor, product, version
"""

import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

plt.rcParams.update({
    "figure.dpi": 200,
    "savefig.dpi": 200,
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 12,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.25,
    "font.family": "sans-serif",
})

OUT = "output/charts_datadriven"
os.makedirs(OUT, exist_ok=True)

SEV_COLORS = {"CRITICAL": "#7F1D1D", "HIGH": "#DC2626", "MEDIUM": "#F59E0B", "LOW": "#10B981", "UNKNOWN": "#9CA3AF"}


# =====================================================================
# Data Loading
# =====================================================================
def load_all():
    """Load and merge MISP + cvelistV5 data into a flat record list."""

    with open("output/all_ai_events_full.json") as f:
        misp_raw = json.load(f)

    with open("output/cve_details.json") as f:
        cve_raw = json.load(f)

    # Build MISP lookup: cve_id -> {date, info, cvss_score, cvss_string, severity, threat_level_id}
    misp_lookup = {}
    for ev_wrapper in misp_raw:
        e = ev_wrapper.get("Event", ev_wrapper)
        cve_id = None
        cvss_score = None
        cvss_string = None
        severity = None
        for obj in e.get("Object", []):
            for a in obj.get("Attribute", []):
                rel = a.get("object_relation", "")
                val = a.get("value", "")
                if rel == "id" and val.startswith("CVE"):
                    cve_id = val
                elif rel == "cvss-score":
                    try:
                        cvss_score = float(val)
                    except ValueError:
                        pass
                elif rel == "cvss-string":
                    cvss_string = val
        for a in e.get("Attribute", []):
            tags = [t.get("name", "") for t in a.get("Tag", [])]
            if "severity" in tags:
                severity = a.get("value", "").upper()
        if cve_id:
            misp_lookup[cve_id] = {
                "date": e.get("date", ""),
                "info": e.get("info", ""),
                "threat_level_id": e.get("threat_level_id", ""),
                "cvss_score": cvss_score,
                "cvss_string": cvss_string,
                "severity": severity,
            }

    # Merge into records
    records = []
    for cve_id, cve_record in cve_raw.items():
        if "error" in cve_record:
            continue
        misp = misp_lookup.get(cve_id, {})
        cna = cve_record.get("containers", {}).get("cna", {})

        # CWE
        cwes = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                cwe_desc = desc.get("description", "")
                if cwe_id:
                    cwes.append({"id": cwe_id, "description": cwe_desc})

        # Affected vendor/product/version
        affected = []
        for af in cna.get("affected", []):
            v = af.get("vendor", "").strip()
            p = af.get("product", "").strip()
            versions = af.get("versions", [])
            if v.lower() in ("n/a", "") and p.lower() in ("n/a", ""):
                continue
            # Clean product: remove vendor prefix duplication
            clean_p = p
            if "/" in p:
                parts = p.split("/", 1)
                if parts[0].lower() == v.lower():
                    clean_p = parts[1]
            affected.append({"vendor": v, "product": clean_p, "raw_product": p, "versions": versions})

        # CVSS from cvelistV5 (fallback to MISP)
        cvss_score = misp.get("cvss_score")
        cvss_string = misp.get("cvss_string", "")
        for metric_block in cna.get("metrics", []):
            for key, val in metric_block.items():
                if isinstance(val, dict) and "baseScore" in val:
                    cvss_score = val["baseScore"]
                    cvss_string = val.get("vectorString", cvss_string)

        records.append({
            "cve_id": cve_id,
            "date": misp.get("date", ""),
            "info": misp.get("info", ""),
            "cvss_score": cvss_score,
            "cvss_string": cvss_string,
            "cwes": cwes,
            "affected": affected,
        })

    return records


def severity_from_cvss(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# =====================================================================
# Chart helpers
# =====================================================================
def wrap_text(text, max_chars=55):
    """Wrap long text at word boundaries for multi-line labels."""
    if len(text) <= max_chars:
        return text
    words = text.split()
    lines = []
    current = ""
    for w in words:
        if len(current) + len(w) + 1 <= max_chars:
            current = f"{current} {w}".strip() if current else w
        else:
            if current:
                lines.append(current)
            current = w
    if current:
        lines.append(current)
    return "\n".join(lines)


def hbar(ax, labels, values, colormap="Blues", title="", xlabel="Number of CVEs"):
    cmap = plt.get_cmap(colormap)
    colors = cmap(np.linspace(0.35, 0.92, len(labels)))[::-1]
    ax.barh(range(len(labels)), values, color=colors, edgecolor="white", linewidth=0.5)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    for i, val in enumerate(values):
        ax.text(val + max(values) * 0.01, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_xlim(0, max(values) * 1.14)


# =====================================================================
# Charts
# =====================================================================

def chart_01_yearly(records):
    """Yearly growth of AI CVEs."""
    year_counter = Counter()
    for r in records:
        y = r["date"][:4]
        if y and y >= "2020":
            year_counter[y] += 1

    years = sorted(year_counter.keys())
    counts = [year_counter[y] for y in years]

    fig, ax = plt.subplots(figsize=(9, 5))
    cmap = plt.get_cmap("Blues")
    colors = cmap(np.linspace(0.4, 0.92, len(years)))
    bars = ax.bar(years, counts, color=colors, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 8,
                str(val), ha="center", va="bottom", fontweight="bold", fontsize=11)
    ax.set_title("Yearly Growth of AI Security Vulnerabilities")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    ax.set_ylim(0, max(counts) * 1.25)
    ax.annotate("* 2026 data is partial (through Feb 15)",
                xy=(0.98, 0.02), xycoords="axes fraction", ha="right", fontsize=8, color="#6B7280", style="italic")
    plt.tight_layout()
    fig.savefig(f"{OUT}/01_yearly_growth.png", bbox_inches="tight")
    plt.close()


def chart_02_monthly(records):
    """Monthly trend of AI CVEs."""
    month_counter = Counter()
    for r in records:
        ym = r["date"][:7]
        if ym and ym >= "2020-01":
            month_counter[ym] += 1

    months = sorted(month_counter.keys())
    counts = [month_counter[m] for m in months]
    x_dates = [datetime.strptime(m + "-01", "%Y-%m-%d") for m in months]

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.bar(x_dates, counts, width=25, color="#2563EB", alpha=0.85, edgecolor="white", linewidth=0.3)

    z = np.polyfit(range(len(counts)), counts, 2)
    p = np.poly1d(z)
    ax.plot(x_dates, p(range(len(counts))), color="#EF4444", linewidth=2.5, linestyle="--", label="Trend (quadratic fit)")

    ax.set_title("Monthly AI Security Vulnerabilities Reported in MISP")
    ax.set_xlabel("Date")
    ax.set_ylabel("Number of CVEs")
    ax.legend()
    ax.xaxis.set_major_locator(mticker.MaxNLocator(12))
    fig.autofmt_xdate(rotation=45)
    plt.tight_layout()
    fig.savefig(f"{OUT}/02_monthly_trend.png", bbox_inches="tight")
    plt.close()


def chart_03_cvss_histogram(records):
    """CVSS score distribution histogram colored by severity."""
    scores = [r["cvss_score"] for r in records if r["cvss_score"] is not None]

    fig, ax = plt.subplots(figsize=(10, 5))
    bins = np.arange(0, 10.5, 0.5)
    n, bins_out, patches = ax.hist(scores, bins=bins, edgecolor="white", linewidth=0.5)

    for patch, left in zip(patches, bins_out[:-1]):
        if left >= 9.0:
            patch.set_facecolor(SEV_COLORS["CRITICAL"])
        elif left >= 7.0:
            patch.set_facecolor(SEV_COLORS["HIGH"])
        elif left >= 4.0:
            patch.set_facecolor(SEV_COLORS["MEDIUM"])
        else:
            patch.set_facecolor(SEV_COLORS["LOW"])

    median_v = np.median(scores)
    mean_v = np.mean(scores)
    ax.axvline(median_v, color="black", linestyle="--", linewidth=1.5)
    ax.axvline(mean_v, color="#7C3AED", linestyle=":", linewidth=1.5)

    from matplotlib.patches import Patch
    s = np.array(scores)
    legend_elements = [
        Patch(facecolor=SEV_COLORS["CRITICAL"], label=f"Critical 9.0–10.0: {(s >= 9).sum()}"),
        Patch(facecolor=SEV_COLORS["HIGH"], label=f"High 7.0–8.9: {((s >= 7) & (s < 9)).sum()}"),
        Patch(facecolor=SEV_COLORS["MEDIUM"], label=f"Medium 4.0–6.9: {((s >= 4) & (s < 7)).sum()}"),
        Patch(facecolor=SEV_COLORS["LOW"], label=f"Low 0.1–3.9: {((s > 0) & (s < 4)).sum()}"),
        plt.Line2D([0], [0], color="black", linestyle="--", label=f"Median: {median_v:.1f}"),
        plt.Line2D([0], [0], color="#7C3AED", linestyle=":", label=f"Mean: {mean_v:.1f}"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=9)
    ax.set_title(f"CVSS Score Distribution of AI Vulnerabilities (n={len(scores)})")
    ax.set_xlabel("CVSS Score")
    ax.set_ylabel("Number of CVEs")
    ax.set_xlim(0, 10.5)
    plt.tight_layout()
    fig.savefig(f"{OUT}/03_cvss_distribution.png", bbox_inches="tight")
    plt.close()


def chart_04_severity_donut(records):
    """Severity distribution donut chart."""
    sev_counter = Counter()
    for r in records:
        sev_counter[severity_from_cvss(r["cvss_score"])] += 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    labels = [s for s in order if s in sev_counter]
    values = [sev_counter[s] for s in labels]
    colors = [SEV_COLORS[s] for s in labels]

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        values, labels=labels, autopct="%1.1f%%", colors=colors, startangle=90, pctdistance=0.75,
        wedgeprops=dict(width=0.5, edgecolor="white", linewidth=2))
    for t in autotexts:
        t.set_fontsize(10)
        t.set_fontweight("bold")
    ax.add_artist(plt.Circle((0, 0), 0.50, fc="white"))
    ax.text(0, 0, f"{len(records)}\nTotal", ha="center", va="center", fontsize=16, fontweight="bold")
    ax.set_title("Severity Distribution of AI Vulnerabilities\n(Based on CVSS Scores)")
    plt.tight_layout()
    fig.savefig(f"{OUT}/04_severity_donut.png", bbox_inches="tight")
    plt.close()


def chart_05_cwe_top(records):
    """Top 20 CWE types — data-driven from cvelistV5 problemTypes field. Full descriptions, no truncation."""
    cwe_counter = Counter()
    cwe_names = {}
    has_cwe = 0

    for r in records:
        if r["cwes"]:
            has_cwe += 1
        for cwe in r["cwes"]:
            cid = cwe["id"]
            cwe_counter[cid] += 1
            if cid not in cwe_names and cwe["description"]:
                raw = cwe["description"]
                # Clean JSON-wrapped descriptions
                if isinstance(raw, str) and raw.startswith("{"):
                    try:
                        d = json.loads(raw)
                        raw = list(d.values())[0] if d else raw
                    except json.JSONDecodeError:
                        pass
                raw = str(raw)
                raw = re.sub(r"^CWE-\d+[:\s]*", "", raw)
                cwe_names[cid] = raw

    # Remove N/A entries
    if "N/A" in cwe_counter:
        del cwe_counter["N/A"]

    top20 = cwe_counter.most_common(20)
    labels = []
    for cid, _ in top20:
        name = cwe_names.get(cid, "")
        # Wrap long descriptions for full display; no truncation
        wrapped = wrap_text(name, max_chars=50)
        labels.append(f"{cid}\n{wrapped}" if name else cid)

    # Larger figure with more height for multi-line labels; no truncation
    fig, ax = plt.subplots(figsize=(14, 14))
    hbar(ax, labels, [c for _, c in top20], colormap="Reds",
         title=f"Top 20 CWE Types in AI Vulnerabilities\n({has_cwe} of {len(records)} CVEs have CWE data · {len(cwe_counter)} unique types)")
    ax.set_xlabel("Number of CVEs")
    plt.tight_layout()
    fig.savefig(f"{OUT}/05_cwe_distribution.png", bbox_inches="tight")
    plt.close()

    # Compact version for slides: Top 12 with full labels
    top12 = cwe_counter.most_common(12)
    labels12 = [f"{cid}\n{wrap_text(cwe_names.get(cid, ''), 50)}" for cid, _ in top12]
    fig2, ax2 = plt.subplots(figsize=(12, 8))
    hbar(ax2, labels12, [c for _, c in top12], colormap="Reds",
         title=f"Top 12 CWE Types in AI Vulnerabilities")
    ax2.set_xlabel("Number of CVEs")
    plt.tight_layout()
    fig2.savefig(f"{OUT}/05b_cwe_distribution_compact.png", bbox_inches="tight")
    plt.close()

    return cwe_counter, cwe_names


def _cwe_leading_phrase(desc, num_words=5):
    """Normalize and take first num_words as grouping key (no predefined list)."""
    s = re.sub(r"^CWE-\d+[:\s]*", "", (desc or "").strip()).lower()
    s = re.sub(r"[^\w\s]", " ", s)
    words = [w for w in s.split() if len(w) > 1][:num_words]
    return " ".join(words) if words else ""


def chart_06_cwe_categories(cwe_counter, cwe_names):
    """Group CWEs by shared leading phrase of description (no predefined keywords)."""
    total_cwe_count = sum(c for cid, c in cwe_counter.items() if cid != "N/A")
    phrase_to_count = Counter()
    phrase_to_label = {}  # best (longest) description prefix per phrase

    for cid, count in cwe_counter.items():
        if cid == "N/A":
            continue
        desc = (cwe_names.get(cid) or "").strip()
        if not desc:
            phrase_to_count["(no description)"] += count
            if "(no description)" not in phrase_to_label:
                phrase_to_label["(no description)"] = "Uncategorized"
            continue
        raw = re.sub(r"^CWE-\d+[:\s]*", "", desc).strip()
        phrase = _cwe_leading_phrase(desc, num_words=5)
        if not phrase:
            phrase_to_count["(no description)"] += count
            continue
        phrase_to_count[phrase] += count
        # Keep longest prefix as label (up to 55 chars)
        label = raw[:55] + "…" if len(raw) > 55 else raw
        if phrase not in phrase_to_label or len(phrase_to_label[phrase]) < len(label):
            phrase_to_label[phrase] = label

    # Use readable label for display; sort by count
    top_phrases = phrase_to_count.most_common(15)
    labels = [phrase_to_label.get(p, p) for p, _ in top_phrases]
    values = [v for _, v in top_phrases]

    fig, ax = plt.subplots(figsize=(11, 6))
    hbar(ax, labels, values, colormap="RdYlBu_r",
         title="CWE Weakness Categories in AI Vulnerabilities\n(Groups = shared leading phrase of CWE description — no predefined categories)")
    for i, val in enumerate(values):
        pct = val / total_cwe_count * 100 if total_cwe_count else 0
        ax.texts[-len(values) + i].set_text(f"{val} ({pct:.1f}%)")
    plt.tight_layout()
    fig.savefig(f"{OUT}/06_cwe_categories.png", bbox_inches="tight")
    plt.close()


def chart_07_products(records):
    """Top 30 affected products — data-driven from cvelistV5 affected field."""
    product_counter = Counter()
    for r in records:
        seen = set()
        for a in r["affected"]:
            p = a["product"]
            if p.lower() not in ("n/a", "") and p not in seen:
                product_counter[p] += 1
                seen.add(p)

    top30 = product_counter.most_common(30)
    labels = [p for p, _ in top30]
    values = [c for _, c in top30]

    fig, ax = plt.subplots(figsize=(11, 8))
    hbar(ax, labels, values, colormap="Greens",
         title=f"Top 30 Affected AI Products\n(from CVE affected field — {len(product_counter)} unique products)")
    plt.tight_layout()
    fig.savefig(f"{OUT}/07_product_distribution.png", bbox_inches="tight")
    plt.close()


def chart_08_vendors(records):
    """Top 25 vendors — data-driven from cvelistV5 affected field."""
    vendor_counter = Counter()
    for r in records:
        seen = set()
        for a in r["affected"]:
            v = a["vendor"]
            if v.lower() not in ("n/a", "", "unknown") and v not in seen:
                vendor_counter[v] += 1
                seen.add(v)

    top25 = vendor_counter.most_common(25)
    labels = [v for v, _ in top25]
    values = [c for _, c in top25]

    fig, ax = plt.subplots(figsize=(10, 7))
    hbar(ax, labels, values, colormap="Purples",
         title=f"Top 25 Vendors of Affected AI Software\n({len(vendor_counter)} unique vendors)")
    plt.tight_layout()
    fig.savefig(f"{OUT}/08_vendor_distribution.png", bbox_inches="tight")
    plt.close()


def chart_09_attack_vector(records):
    """Attack vector distribution — parsed from CVSS vector string."""
    av_counter = Counter()
    ac_counter = Counter()
    pr_counter = Counter()
    ui_counter = Counter()

    av_map = {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"}
    ac_map = {"L": "Low", "H": "High"}
    pr_map = {"N": "None", "L": "Low", "H": "High"}
    ui_map = {"N": "None", "R": "Required"}

    for r in records:
        s = r.get("cvss_string", "")
        if not isinstance(s, str) or not s:
            continue
        m = re.search(r"AV:([NALP])", s)
        if m:
            av_counter[av_map.get(m.group(1), m.group(1))] += 1
        m = re.search(r"AC:([LH])", s)
        if m:
            ac_counter[ac_map.get(m.group(1), m.group(1))] += 1
        m = re.search(r"PR:([NLH])", s)
        if m:
            pr_counter[pr_map.get(m.group(1), m.group(1))] += 1
        m = re.search(r"UI:([NR])", s)
        if m:
            ui_counter[ui_map.get(m.group(1), m.group(1))] += 1

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    pie_colors = ["#EF4444", "#F59E0B", "#2563EB", "#10B981"]

    for ax, (title, counter) in zip(axes.flat, [
        ("Attack Vector", av_counter),
        ("Attack Complexity", ac_counter),
        ("Privileges Required", pr_counter),
        ("User Interaction", ui_counter),
    ]):
        items = counter.most_common()
        labels = [k for k, _ in items]
        vals = [v for _, v in items]
        wedges, texts, autotexts = ax.pie(
            vals, labels=labels, autopct="%1.1f%%",
            colors=pie_colors[:len(items)], startangle=90,
            wedgeprops=dict(edgecolor="white", linewidth=1.5), pctdistance=0.7)
        for t in autotexts:
            t.set_fontsize(10)
            t.set_fontweight("bold")
        ax.set_title(f"{title}\n(n={sum(vals)})", fontsize=12, fontweight="bold")

    fig.suptitle("CVSS Vector Component Analysis", fontsize=15, fontweight="bold", y=1.01)
    plt.tight_layout()
    fig.savefig(f"{OUT}/09_cvss_vectors.png", bbox_inches="tight")
    plt.close()


def chart_10_attack_vector_single(records):
    """Attack vector distribution as horizontal bar chart (no pie, avoids label overlap)."""
    av_map = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
    av_counter = Counter()
    for r in records:
        s = r.get("cvss_string", "")
        if not isinstance(s, str):
            continue
        m = re.search(r"AV:([NALP])", s)
        if m:
            av_counter[av_map.get(m.group(1), m.group(1))] += 1

    items = av_counter.most_common()
    labels = [k for k, _ in items]
    vals = [v for _, v in items]
    n_total = sum(vals)

    fig, ax = plt.subplots(figsize=(8, 4))
    colors = ["#EF4444", "#F59E0B", "#2563EB", "#10B981"]
    bars = ax.barh(range(len(labels)), vals, color=colors[:len(labels)], edgecolor="white", height=0.6)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=12)
    ax.invert_yaxis()
    for i, (val, lab) in enumerate(zip(vals, labels)):
        pct = val / n_total * 100 if n_total else 0
        ax.text(val + (n_total * 0.01), i, f"{val} ({pct:.1f}%)", va="center", fontsize=11, fontweight="bold")
    ax.set_xlabel("Number of CVEs")
    ax.set_title(f"Attack Vector Distribution (n={n_total})")
    ax.set_xlim(0, (n_total * 1.18) if n_total else 1)
    plt.tight_layout()
    fig.savefig(f"{OUT}/10_attack_vector.png", bbox_inches="tight")
    plt.close()


def _product_leading_phrase(vendor, product, num_words=4):
    """Normalize vendor + product and take first num_words as grouping key (no predefined list)."""
    s = f"{vendor} {product}".lower().strip()
    s = re.sub(r"[^\w\s]", " ", s)
    words = [w for w in s.split() if len(w) > 1][:num_words]
    return " ".join(words) if words else ""


def chart_11_ai_categories(records):
    """Group CVEs by leading phrase of affected vendor/product (no predefined categories)."""
    phrase_count = Counter()
    phrase_label = {}  # representative "vendor product" for display

    for r in records:
        assigned = False
        for a in r["affected"]:
            v, p = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
            if (v or p).lower() in ("n/a", ""):
                continue
            phrase = _product_leading_phrase(v, p, num_words=4)
            if not phrase:
                continue
            phrase_count[phrase] += 1
            assigned = True
            display = f"{v} {p}".strip()[:50]
            if display and (phrase not in phrase_label or len(phrase_label[phrase]) < len(display)):
                phrase_label[phrase] = display
            break
        if not assigned:
            phrase_count["(no vendor/product)"] += 1
            if "(no vendor/product)" not in phrase_label:
                phrase_label["(no vendor/product)"] = "Uncategorized"

    items = phrase_count.most_common(15)
    labels = [phrase_label.get(p, p) for p, _ in items]
    values = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(10, 7))
    cat_colors = ["#2563EB", "#7C3AED", "#EF4444", "#F59E0B", "#10B981", "#EC4899", "#6366F1", "#14B8A6", "#84CC16", "#F97316", "#06B6D4", "#8B5CF6", "#EC4899", "#14B8A6", "#EAB308"]
    wedges, texts, autotexts = ax.pie(
        values, labels=None, autopct="%1.1f%%",
        colors=cat_colors[:len(items)], startangle=90, pctdistance=0.8,
        wedgeprops=dict(width=0.45, edgecolor="white", linewidth=2))
    for t in autotexts:
        t.set_fontsize(9)
        t.set_fontweight("bold")
    ax.add_artist(plt.Circle((0, 0), 0.55, fc="white"))
    ax.text(0, 0, f"{len(records)}\nAI CVEs", ha="center", va="center", fontsize=15, fontweight="bold")
    legend_labels = [f"{l} ({v})" for l, v in zip(labels, values)]
    ax.legend(wedges, legend_labels, title="Product group (leading phrase)", loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1), fontsize=8)
    ax.set_title("AI CVE Groups by Affected Product Name\n(groups = shared leading phrase — no predefined categories)")
    plt.tight_layout()
    fig.savefig(f"{OUT}/11_ai_categories_donut.png", bbox_inches="tight")
    plt.close()

    items_clean = [(c, v) for c, v in items if c != "Uncategorized" and "(no vendor/product)" not in str(c)]
    if items_clean:
        labels_c = [c for c, _ in items_clean]
        values_c = [v for _, v in items_clean]
        fig, ax = plt.subplots(figsize=(10, 5))
        hbar(ax, labels_c, values_c, colormap="Set2",
             title=f"AI CVEs by Product Name Group\n(leading phrase of vendor/product — data-driven)")
        for i, val in enumerate(values_c):
            pct = val / len(records) * 100
            ax.texts[-len(values_c) + i].set_text(f"{val} ({pct:.1f}%)")
        plt.tight_layout()
        fig.savefig(f"{OUT}/12_ai_categories_bar.png", bbox_inches="tight")
        plt.close()

    return phrase_count


# Predefined keyword sets for "AI three categories" (Foundation Models / Agentic / Infrastructure)
AI_FOUNDATION_MODEL_TERMS = [
    "ollama", "vllm", "llama.cpp", "llama-cpp", "transformers", "huggingface", "hugging face",
    "openai", "anthropic", "claude", "gemini", "mistral", "gpt-", "chatgpt", "llm", "llama",
    "tensorflow", "pytorch", "keras", "jax", "onnx", "caffe", "mxnet", "paddle",
]
AI_AGENTIC_TERMS = [
    "langchain", "langgraph", "autogpt", "auto-gpt", "crewai", "flowise", "n8n", "dify", "devika",
    "browserpilot", "cursor", "copilot", "claude-code", "cody", "continue", "agno", "agent",
    "anything-llm", "anythingllm", "open-webui", "openwebui", "librechat", "lollms", "lunary",
    "chuanhuchatgpt", "gpt_academic", "fastgpt", "docsgpt", "privategpt", "localai", "litellm",
]
AI_INFRASTRUCTURE_TERMS = [
    "mlflow", "kubeflow", "bentoml", "seldon", "label-studio", "labelstudio", "ray", "aim", "clearml",
    "wandb", "cvat", "h2o", "datahub", "milvus", "pinecone", "weaviate", "qdrant", "chroma",
    "mindsdb", "lakefs", "jupyter", "notebook", "vector", "embedding", "gradio", "streamlit",
]


def _classify_ai_three(vendor, product):
    """Classify vendor+product into Foundation Model / Agentic / AI Infrastructure (predefined keywords)."""
    combined = f"{vendor} {product}".lower()
    for t in AI_FOUNDATION_MODEL_TERMS:
        if t in combined:
            return "Foundation Models / LLM"
    for t in AI_AGENTIC_TERMS:
        if t in combined:
            return "Agentic Systems"
    for t in AI_INFRASTRUCTURE_TERMS:
        if t in combined:
            return "AI Infrastructure"
    return None


def chart_ai_three_categories(records):
    """Count CVEs by predefined three categories (Foundation Models, Agentic, AI Infrastructure)."""
    cat_counter = Counter()
    for r in records:
        assigned = None
        for a in r["affected"]:
            v, p = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
            if (v or p).lower() in ("n/a", ""):
                continue
            assigned = _classify_ai_three(v, p)
            if assigned:
                break
        cat_counter[assigned if assigned else "Other"] += 1

    # Fixed order for chart: Foundation Models, Agentic, Infrastructure, Other
    order = ["Foundation Models / LLM", "Agentic Systems", "AI Infrastructure", "Other"]
    items = [(c, cat_counter[c]) for c in order if cat_counter[c] > 0]
    labels = [c for c, _ in items]
    values = [v for _, v in items]
    n = len(records)

    fig, ax = plt.subplots(figsize=(9, 4))
    colors = ["#2563EB", "#7C3AED", "#10B981", "#9CA3AF"]
    bars = ax.barh(range(len(labels)), values, color=colors[:len(labels)], edgecolor="white", height=0.6)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=11)
    ax.invert_yaxis()
    for i, val in enumerate(values):
        pct = val / n * 100 if n else 0
        ax.text(val + n * 0.01, i, f"{val} ({pct:.1f}%)", va="center", fontsize=11, fontweight="bold")
    ax.set_xlabel("Number of CVEs")
    ax.set_title(f"AI CVEs by Predefined Category\n(Foundation Models / Agentic / Infrastructure — keyword match on vendor+product)")
    ax.set_xlim(0, max(values) * 1.25 if values else 1)
    plt.tight_layout()
    fig.savefig(f"{OUT}/19_ai_three_categories.png", bbox_inches="tight")
    plt.close()

    return cat_counter


def chart_12_ontology_coverage(records):
    """How well does the data cover each ontology node?"""
    has_cwe = sum(1 for r in records if r["cwes"])
    has_vendor = sum(1 for r in records if any(a["vendor"].lower() not in ("n/a", "") for a in r["affected"]))
    has_product = sum(1 for r in records if any(a["product"].lower() not in ("n/a", "") for a in r["affected"]))
    has_version = sum(1 for r in records if any(a["versions"] for a in r["affected"]))
    has_cvss = sum(1 for r in records if r["cvss_score"] is not None)

    items = [
        ("Vulnerability (CVE ID)", len(records)),
        ("Type (CWE)", has_cwe),
        ("CVSS Score", has_cvss),
        ("Version", has_version),
        ("Product (Software)", has_product),
        ("Vendor", has_vendor),
    ]
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    pcts = [v / len(records) * 100 for v in values]
    bar_colors = ["#2563EB", "#EF4444", "#F59E0B", "#10B981", "#7C3AED", "#EC4899"]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(range(len(items)), pcts, color=bar_colors, edgecolor="white", height=0.6)
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels(labels, fontsize=11)
    ax.invert_yaxis()
    for i, (pct, val) in enumerate(zip(pcts, values)):
        ax.text(pct + 1, i, f"{val} ({pct:.1f}%)", va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, 115)
    ax.set_xlabel("Coverage (%)")
    ax.set_title(f"Ontology Field Coverage Across {len(records)} AI CVEs\n(How much structured data is available for each ontology node)")
    ax.axvline(100, color="gray", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig.savefig(f"{OUT}/13_ontology_coverage.png", bbox_inches="tight")
    plt.close()

    return {k: v for k, v in items}


# =====================================================================
# Additional charts — AI label only (same dataset, same logic)
# =====================================================================

def chart_14_severity_by_year(records):
    """AI CVEs only: stacked bar of severity by year."""
    year_sev = defaultdict(lambda: Counter())
    for r in records:
        y = r["date"][:4]
        if not y or y < "2020":
            continue
        sev = severity_from_cvss(r["cvss_score"])
        year_sev[y][sev] += 1

    years = sorted(year_sev.keys())
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    bottom = np.zeros(len(years))
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = [SEV_COLORS[s] for s in order]
    for i, sev in enumerate(order):
        vals = [year_sev[y].get(sev, 0) for y in years]
        ax.bar(years, vals, bottom=bottom, label=sev, color=colors[i], edgecolor="white", linewidth=0.5)
        bottom += np.array(vals)

    ax.set_title(f"AI CVEs by Severity and Year\n(n={len(records)} AI-tagged CVEs)")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    ax.legend(loc="upper right")
    plt.tight_layout()
    fig.savefig(f"{OUT}/14_severity_by_year.png", bbox_inches="tight")
    plt.close()


def chart_15_products_high_critical(records):
    """AI CVEs only: top 15 products by count of High + Critical severity CVEs."""
    product_counts = Counter()
    for r in records:
        sev = severity_from_cvss(r["cvss_score"])
        if sev not in ("HIGH", "CRITICAL"):
            continue
        seen = set()
        for a in r["affected"]:
            p = a["product"]
            if p.lower() in ("n/a", "") or p in seen:
                continue
            product_counts[p] += 1
            seen.add(p)

    top15 = product_counts.most_common(15)
    if not top15:
        return
    labels = [wrap_text(p, 40) for p, _ in top15]
    values = [c for _, c in top15]

    fig, ax = plt.subplots(figsize=(11, 6))
    hbar(ax, labels, values, colormap="Reds",
         title=f"Top 15 AI Products by High/Critical CVE Count\n(AI-tagged CVEs only)")
    ax.set_xlabel("Number of High or Critical CVEs")
    plt.tight_layout()
    fig.savefig(f"{OUT}/15_products_high_critical.png", bbox_inches="tight")
    plt.close()


def chart_16_cwe_count_per_cve(records):
    """AI CVEs only: distribution of how many CWEs each CVE has (0, 1, 2, 3+)."""
    count_dist = Counter()
    for r in records:
        n = len(r["cwes"])
        if n >= 3:
            count_dist["3+"] += 1
        else:
            count_dist[str(n)] += 1

    order = ["0", "1", "2", "3+"]
    labels = [f"{x} CWE(s)" for x in order]
    values = [count_dist.get(x, 0) for x in order]
    colors = ["#9CA3AF", "#2563EB", "#7C3AED", "#DC2626"]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, edgecolor="white", linewidth=1)
    for bar, val in zip(bars, values):
        pct = val / len(records) * 100
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 10,
                f"{val}\n({pct:.1f}%)", ha="center", va="bottom", fontweight="bold", fontsize=10)
    ax.set_title(f"CWE Count per CVE (AI-Tagged Only, n={len(records)})")
    ax.set_ylabel("Number of CVEs")
    ax.set_ylim(0, max(values) * 1.25)
    plt.tight_layout()
    fig.savefig(f"{OUT}/16_cwe_count_per_cve.png", bbox_inches="tight")
    plt.close()


def chart_17_yearly_cwe_top5_trend(records, cwe_counter):
    """AI CVEs only: trend of top 5 CWE types over years. Legend from data only."""
    top5_cids = [cid for cid, _ in cwe_counter.most_common(5)]
    cwe_desc = {}
    for r in records:
        for cwe in r["cwes"]:
            cid = cwe["id"]
            if cid in top5_cids and cid not in cwe_desc and cwe.get("description"):
                cwe_desc[cid] = cwe["description"].strip()
    year_cwe = defaultdict(lambda: Counter())
    for r in records:
        y = r["date"][:4]
        if not y or y < "2020":
            continue
        for cwe in r["cwes"]:
            cid = cwe["id"]
            if cid in top5_cids:
                year_cwe[y][cid] += 1

    years = sorted(year_cwe.keys())
    x = np.arange(len(years))
    width = 0.15
    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ["#DC2626", "#EA580C", "#CA8A04", "#16A34A", "#2563EB"]
    for i, cid in enumerate(top5_cids):
        vals = [year_cwe[y].get(cid, 0) for y in years]
        offset = (i - 2) * width
        raw = (cwe_desc.get(cid) or "").strip()
        if raw and raw.upper().startswith(cid.upper()):
            raw = raw[len(cid):].lstrip(": ").strip()
        short = (raw[:42] + "…") if len(raw) > 42 else raw
        label = f"{cid}: {short}" if short else cid
        ax.bar(x + offset, vals, width, label=label, color=colors[i])

    ax.set_xticks(x)
    ax.set_xticklabels(years)
    ax.set_title("Top 5 CWE Types by Year (AI-Tagged CVEs Only)")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    ax.legend(loc="upper right", fontsize=9)
    plt.tight_layout()
    fig.savefig(f"{OUT}/17_cwe_top5_by_year.png", bbox_inches="tight")
    plt.close()


def chart_18_attack_vector_by_severity(records):
    """AI CVEs only: attack vector distribution within High/Critical vs rest."""
    av_map = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
    high_crit = {"Network": 0, "Adjacent": 0, "Local": 0, "Physical": 0}
    other = {"Network": 0, "Adjacent": 0, "Local": 0, "Physical": 0}

    for r in records:
        sev = severity_from_cvss(r["cvss_score"])
        s = r.get("cvss_string", "")
        m = re.search(r"AV:([NALP])", s) if isinstance(s, str) else None
        av = av_map.get(m.group(1), "Network") if m else "Network"
        if sev in ("HIGH", "CRITICAL"):
            high_crit[av] = high_crit.get(av, 0) + 1
        else:
            other[av] = other.get(av, 0) + 1

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(4)
    width = 0.35
    labels = list(av_map.values())
    ax.bar(x - width / 2, [high_crit[l] for l in labels], width, label="High/Critical", color="#DC2626", edgecolor="white")
    ax.bar(x + width / 2, [other[l] for l in labels], width, label="Medium/Low", color="#2563EB", alpha=0.85, edgecolor="white")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_title("Attack Vector by Severity (AI-Tagged CVEs Only)")
    ax.set_ylabel("Number of CVEs")
    ax.legend()
    plt.tight_layout()
    fig.savefig(f"{OUT}/18_attack_vector_by_severity.png", bbox_inches="tight")
    plt.close()


# =====================================================================
# Main
# =====================================================================
def main():
    print("=" * 60)
    print("  AISecureChain — Comprehensive Analysis")
    print("=" * 60)

    print("\nLoading data...")
    records = load_all()
    print(f"  Total records: {len(records)}")
    print(f"  Date range: {min(r['date'] for r in records if r['date'])} — {max(r['date'] for r in records if r['date'])}")
    scores = [r["cvss_score"] for r in records if r["cvss_score"] is not None]
    print(f"  With CVSS: {len(scores)} (mean={np.mean(scores):.1f}, median={np.median(scores):.1f})")

    print("\nGenerating charts...")

    print("  [01] Yearly growth")
    chart_01_yearly(records)

    print("  [02] Monthly trend")
    chart_02_monthly(records)

    print("  [03] CVSS score distribution")
    chart_03_cvss_histogram(records)

    print("  [04] Severity donut")
    chart_04_severity_donut(records)

    print("  [05] CWE distribution (top 20 + compact top 12)")
    cwe_counter, cwe_names = chart_05_cwe_top(records)

    print("  [06] CWE weakness categories")
    chart_06_cwe_categories(cwe_counter, cwe_names)

    print("  [07] Product distribution (top 30)")
    chart_07_products(records)

    print("  [08] Vendor distribution (top 25)")
    chart_08_vendors(records)

    print("  [09] CVSS vector components (4-in-1)")
    chart_09_attack_vector(records)

    print("  [10] Attack vector pie (single)")
    chart_10_attack_vector_single(records)

    print("  [11–12] AI system categories")
    cat_counter = chart_11_ai_categories(records)

    print("  [13] Ontology coverage")
    coverage = chart_12_ontology_coverage(records)

    print("  [14] Severity by year (AI only)")
    chart_14_severity_by_year(records)

    print("  [15] Products by High/Critical count (AI only)")
    chart_15_products_high_critical(records)

    print("  [16] CWE count per CVE (AI only)")
    chart_16_cwe_count_per_cve(records)

    print("  [17] Top 5 CWE by year (AI only)")
    chart_17_yearly_cwe_top5_trend(records, cwe_counter)

    print("  [18] Attack vector by severity (AI only)")
    chart_18_attack_vector_by_severity(records)

    print("  [19] AI three categories (Foundation / Agentic / Infrastructure)")
    three_cats = chart_ai_three_categories(records)

    # Print summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total AI CVEs analyzed: {len(records)}")
    print(f"  CVSS scores: mean={np.mean(scores):.1f}, median={np.median(scores):.1f}")
    print(f"  Severity: {sum(1 for r in records if severity_from_cvss(r['cvss_score']) in ('CRITICAL','HIGH'))}/{len(records)} are High or Critical")
    print(f"\n  Ontology Coverage:")
    for field, count in coverage.items():
        print(f"    {field}: {count}/{len(records)} ({count/len(records)*100:.1f}%)")
    print(f"\n  AI Categories (leading phrase):")
    for cat, count in cat_counter.most_common():
        print(f"    {cat}: {count} ({count/len(records)*100:.1f}%)")
    print(f"\n  AI Three Categories (predefined keywords):")
    for cat in ["Foundation Models / LLM", "Agentic Systems", "AI Infrastructure", "Other"]:
        c = three_cats.get(cat, 0)
        if c > 0:
            print(f"    {cat}: {c} ({c/len(records)*100:.1f}%)")

    print(f"\n  All charts saved to {OUT}/")
    for f in sorted(os.listdir(OUT)):
        if f.endswith(".png"):
            print(f"    {f}")
    print()


if __name__ == "__main__":
    main()
