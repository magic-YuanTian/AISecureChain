#!/usr/bin/env python3
"""
Generate static figures for slides (no UI changes).

Outputs (under query_engine/output/ppt_assets/):
  - ontology_graph.png                      — T-box classes + object properties (from ai_vuln_kb.ttl)
  - software_type_stacked_bar.png           — alias of the plain distribution chart (kept for compatibility)
  - software_type_distribution.png          — horizontal bars: software instance count per software_type
  - software_type_is_ai_stacked_bar.png     — stacked bars per type: software.is_ai = 1 vs 0

Usage:
  cd query_engine && python3 scripts/generate_ppt_assets.py
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
QE_ROOT = os.path.dirname(HERE)
DB_PATH = os.path.join(QE_ROOT, "ai_vuln_kb.db")
TTL_PATH = os.path.join(QE_ROOT, "ai_vuln_kb.ttl")
OUT_DIR = os.path.join(QE_ROOT, "output", "ppt_assets")
ONT = "http://aisecurechain.org/ontology#"


def load_ontology_graph():
    """Same graph as /api/rdf/ontology-graph (classes + object property edges)."""
    from rdflib import Graph, RDF, RDFS, OWL

    g = Graph()
    g.parse(TTL_PATH, format="turtle")
    nodes = {}
    links = []
    seen = set()

    def add_class(uri):
        s = str(uri)
        if s not in nodes and s.startswith(ONT):
            nodes[s] = s.split("#")[-1]

    for s, _, o in g.triples((None, RDF.type, OWL.Class)):
        if str(s).startswith(ONT):
            add_class(s)

    for p, _, _ in g.triples((None, RDF.type, OWL.ObjectProperty)):
        pstr = str(p)
        if not pstr.startswith(ONT):
            continue
        dom = rng = None
        for _, _, d in g.triples((p, RDFS.domain, None)):
            dom = d
            break
        for _, _, r in g.triples((p, RDFS.range, None)):
            rng = r
            break
        if dom is None or rng is None:
            continue
        if not str(dom).startswith(ONT) or not str(rng).startswith(ONT):
            continue
        add_class(dom)
        add_class(rng)
        plabel = pstr.split("#")[-1]
        for _, _, lit in g.triples((p, RDFS.label, None)):
            plabel = str(lit)
            break
        ek = (str(dom), str(rng), plabel)
        if ek not in seen:
            seen.add(ek)
            links.append((str(dom), str(rng), plabel))

    return nodes, links


def render_ontology_png(out_path: str) -> None:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    try:
        import networkx as nx
    except ImportError:
        print("networkx is required for ontology layout: pip install networkx", file=sys.stderr)
        sys.exit(1)

    nodes, links = load_ontology_graph()
    if not nodes:
        print("No ontology nodes found.", file=sys.stderr)
        sys.exit(1)

    G = nx.DiGraph()
    for uri, label in nodes.items():
        G.add_node(uri, label=label)
    for s, t, lab in links:
        G.add_edge(s, t, label=lab)

    pos = nx.spring_layout(G, k=2.8, iterations=120, seed=42)

    fig, ax = plt.subplots(figsize=(14, 10), facecolor="white")
    ax.set_facecolor("#fafafa")
    ax.axis("off")

    # Edges
    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        ax.annotate(
            "",
            xy=(x1, y1),
            xytext=(x0, y0),
            arrowprops=dict(
                arrowstyle="-|>",
                color="#60a5fa",
                lw=2.2,
                shrinkA=28,
                shrinkB=28,
                mutation_scale=14,
                connectionstyle="arc3,rad=0.12",
            ),
        )
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        lab = data.get("label", "")
        if lab:
            ax.text(
                mx, my,
                lab,
                fontsize=8,
                ha="center",
                va="center",
                color="#1d4ed8",
                bbox=dict(boxstyle="round,pad=0.25", facecolor="white", edgecolor="#bfdbfe", linewidth=0.8),
            )

    # Nodes (UML-style boxes)
    for uri, label in nodes.items():
        x, y = pos[uri]
        w, h = 0.14, 0.065
        rect = mpatches.FancyBboxPatch(
            (x - w / 2, y - h / 2),
            w,
            h,
            boxstyle="round,pad=0.01,rounding_size=0.012",
            linewidth=1.8,
            edgecolor="#2563eb",
            facecolor="#2563eb",
        )
        ax.add_patch(rect)
        ax.text(x, y, label, ha="center", va="center", fontsize=8.5, fontweight="bold", color="white")

    ax.set_xlim(-1.15, 1.15)
    ax.set_ylim(-1.15, 1.15)
    fig.suptitle("AISecureChain — Ontology (T-box)", fontsize=16, fontweight="bold", y=0.98)
    fig.text(0.5, 0.02, "Classes and object properties · generated from ai_vuln_kb.ttl", ha="center", fontsize=9, color="#6b7280")
    fig.savefig(out_path, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {out_path}")


def software_type_counts(conn: sqlite3.Connection):
    """Per software_type.name: count software rows."""
    cur = conn.execute(
        """
        SELECT st.name,
               COUNT(*) AS cnt
        FROM software s
        JOIN software_type st ON s.software_type_id = st.id
        GROUP BY st.id, st.name
        ORDER BY cnt DESC, st.name
        """
    )
    rows = cur.fetchall()
    return [(r[0], int(r[1])) for r in rows]


def render_distribution_bar_png(out_path: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    conn = sqlite3.connect(DB_PATH)
    try:
        data = software_type_counts(conn)
    finally:
        conn.close()

    if not data:
        print("No software/type data in DB.", file=sys.stderr)
        sys.exit(1)

    labels = [d[0] for d in data]
    counts = np.array([d[1] for d in data], dtype=float)

    fig, ax = plt.subplots(figsize=(11, 6.2), facecolor="white")
    y = np.arange(len(labels))
    h = 0.65

    colors = plt.cm.Purples(np.linspace(0.45, 0.9, len(labels)))[::-1]
    ax.barh(y, counts, h, color=colors, edgecolor="white", linewidth=0.6)

    for i, t in enumerate(counts):
        if t > 0:
            ax.text(t + max(counts) * 0.01, i, f"{int(t)}", va="center", fontsize=9, color="#334155")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Number of software instances", fontsize=11)
    ax.set_title("Software instances by software type", fontsize=14, fontweight="bold", pad=12)
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)
    xmax = max(counts.max() * 1.18, 1)
    ax.set_xlim(0, xmax)
    fig.text(
        0.5, 0.01,
        "Source: SQLite software × software_type",
        ha="center",
        fontsize=8,
        color="#64748b",
    )
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    fig.savefig(out_path, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {out_path}")


def software_type_counts_by_is_ai(conn: sqlite3.Connection):
    """Per software_type: count software where is_ai is 1 vs 0 (NULL treated as 0)."""
    cur = conn.execute(
        """
        SELECT st.name,
               SUM(CASE WHEN COALESCE(s.is_ai, 0) = 1 THEN 1 ELSE 0 END) AS cnt_ai,
               SUM(CASE WHEN COALESCE(s.is_ai, 0) = 0 THEN 1 ELSE 0 END) AS cnt_non
        FROM software s
        JOIN software_type st ON s.software_type_id = st.id
        GROUP BY st.id, st.name
        ORDER BY (cnt_ai + cnt_non) DESC, st.name
        """
    )
    rows = cur.fetchall()
    return [(r[0], int(r[1]), int(r[2])) for r in rows]


def render_is_ai_stacked_bar_png(out_path: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    conn = sqlite3.connect(DB_PATH)
    try:
        data = software_type_counts_by_is_ai(conn)
    finally:
        conn.close()

    if not data:
        print("No software/type data in DB.", file=sys.stderr)
        sys.exit(1)

    labels = [d[0] for d in data]
    ai = np.array([d[1] for d in data], dtype=float)
    non = np.array([d[2] for d in data], dtype=float)

    fig, ax = plt.subplots(figsize=(11, 6.2), facecolor="white")
    y = np.arange(len(labels))
    h = 0.65

    ax.barh(y, ai, h, label="is_ai = True", color="#4f46e5", edgecolor="white", linewidth=0.5)
    ax.barh(y, non, h, left=ai, label="is_ai = False", color="#94a3b8", edgecolor="white", linewidth=0.5)

    totals = ai + non
    for i, t in enumerate(totals):
        if t > 0:
            ax.text(t + max(totals) * 0.01, i, f"{int(t)}", va="center", fontsize=9, color="#334155")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Number of software instances", fontsize=11)
    ax.set_title(
        "Software instances by type (stacked by software.is_ai)",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.legend(loc="lower right", framealpha=0.95)
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)
    xmax = max(totals.max() * 1.18, 1)
    ax.set_xlim(0, xmax)
    fig.text(
        0.5,
        0.01,
        "Source: SQLite software.is_ai (per product) × software_type",
        ha="center",
        fontsize=8,
        color="#64748b",
    )
    plt.tight_layout(rect=[0, 0.03, 1, 1])
    fig.savefig(out_path, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {out_path}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    if not os.path.isfile(TTL_PATH):
        print(f"Missing TTL: {TTL_PATH}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(DB_PATH):
        print(f"Missing DB: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    render_ontology_png(os.path.join(OUT_DIR, "ontology_graph.png"))
    bar_path = os.path.join(OUT_DIR, "software_type_stacked_bar.png")
    render_distribution_bar_png(bar_path)
    # Alias for slide decks / papers
    shutil.copyfile(bar_path, os.path.join(OUT_DIR, "software_type_distribution.png"))
    print(f"Wrote {os.path.join(OUT_DIR, 'software_type_distribution.png')} (copy)")
    render_is_ai_stacked_bar_png(os.path.join(OUT_DIR, "software_type_is_ai_stacked_bar.png"))
    print(f"\nDone. Files in: {OUT_DIR}")


if __name__ == "__main__":
    main()
