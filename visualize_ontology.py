"""
AISecureChain - AI Vulnerability Ontology Graph
================================================
Extends the core CVE/CWE ontology with AI-specific
and MIT AI Risk Repository concepts.

Data Sources are listed separately (not part of the ontology).
"""

import graphviz


def build_ontology_graph():
    g = graphviz.Digraph(
        "AI_Vulnerability_Ontology",
        format="png",
        engine="neato",
        graph_attr={
            "bgcolor": "white",
            "fontname": "Helvetica Neue",
            "pad": "0.8",
            "dpi": "200",
            "overlap": "false",
            "splines": "curved",
            "sep": "+10",
            "label": (
                "<<FONT POINT-SIZE='24'><B>AISecureChain — AI Vulnerability Ontology</B></FONT>"
                "<BR/><FONT POINT-SIZE='13' COLOR='#888888'>"
                "Extending CVE/CWE with AI System Categories, MIT Risk Domains "
                "&amp; Causal Taxonomy</FONT>>"
            ),
            "labelloc": "t",
        },
    )

    # ── Node Styles ──
    PINK = {"shape": "ellipse", "style": "filled", "fillcolor": "#F9D5D3",
            "color": "#C0392B", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}
    BLUE = {"shape": "ellipse", "style": "filled", "fillcolor": "#D4E6F1",
            "color": "#2980B9", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}
    YELLOW = {"shape": "ellipse", "style": "filled", "fillcolor": "#FEF9E7",
              "color": "#B7950B", "fontname": "Helvetica Neue", "fontsize": "12", "penwidth": "1.5"}
    GRAY = {"shape": "ellipse", "style": "filled", "fillcolor": "#E5E7E9",
            "color": "#7F8C8D", "fontname": "Helvetica Neue", "fontsize": "12", "penwidth": "1.5"}
    RED = {"shape": "ellipse", "style": "filled", "fillcolor": "#FADBD8",
           "color": "#E74C3C", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}
    GREEN = {"shape": "ellipse", "style": "filled", "fillcolor": "#D5F5E3",
             "color": "#27AE60", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}
    ORANGE = {"shape": "ellipse", "style": "filled", "fillcolor": "#FDEBD0",
              "color": "#E67E22", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}
    PURPLE = {"shape": "ellipse", "style": "filled", "fillcolor": "#E8DAEF",
              "color": "#8E44AD", "fontname": "Helvetica Neue", "fontsize": "13", "penwidth": "2"}

    EL = {"fontname": "Helvetica Neue", "fontsize": "10", "fontcolor": "#333333",
          "color": "#555555", "penwidth": "1.5", "arrowsize": "0.8"}
    EL_R = {**EL, "style": "dashed", "color": "#C0392B", "fontcolor": "#C0392B"}

    # ═══════════════════════════════════════
    #  CORE (existing ontology - center)
    # ═══════════════════════════════════════
    g.node("Vulnerability", "Vulnerability\n(CVE)",
           pos="8,8!", **{**PINK, "fontsize": "16", "penwidth": "3"})

    g.node("Type", "Type\n(CWE)", pos="12,10!", **PINK)
    g.edge("Vulnerability", "Type", label="is-a", **EL)

    g.node("Severity", "Severity\n(CVSS)", pos="8,5.5!", **GRAY)
    g.edge("Vulnerability", "Severity", label="has-score", **EL)

    # Software side
    g.node("Software", "Software", pos="4,8!", **BLUE)
    g.node("SWVersion", "Version", pos="5.5,10!", **YELLOW)
    g.node("License", "License", pos="3.5,11!", **GRAY)
    g.node("Vendor", "Vendor /\nManufacturer", pos="4,4.5!", **GRAY)

    g.edge("Software", "SWVersion", label="has-a", **EL)
    g.edge("SWVersion", "License", label="has-a", **EL)
    g.edge("SWVersion", "Vulnerability", label="vulnerable-to", **EL)
    g.edge("SWVersion", "SWVersion", label="depends-on", **EL)
    g.edge("Vendor", "Software", label="produce", **EL)

    # Hardware side
    g.node("Hardware", "Hardware", pos="12,4.5!", **BLUE)
    g.node("HWVersion", "Version", pos="11,6.5!", **YELLOW)

    g.edge("Hardware", "HWVersion", label="has-a", **EL)
    g.edge("HWVersion", "Vulnerability", label="vulnerable-to", **EL)
    g.edge("SWVersion", "HWVersion", label="operate-on", **EL)
    g.edge("Vendor", "Hardware", label="produce", **EL)

    # ═══════════════════════════════════════
    #  EXTENSION 1: AI System Category (orange)
    # ═══════════════════════════════════════
    g.node("AICategory", "AI System\nCategory", pos="0.5,7!", **{**ORANGE, "fontsize": "14", "penwidth": "2.5"})
    g.edge("Software", "AICategory", label="classified-as", **EL)

    ai_cats = [
        ("ac0", "Foundation\nModel / LLM", "-2.5,10!"),
        ("ac1", "AI Agent /\nAgentic System", "-2.5,8.5!"),
        ("ac2", "ML Framework\n/ Library", "-2.5,7!"),
        ("ac3", "ML Platform\n/ MLOps", "-2.5,5.5!"),
        ("ac4", "AI Data\nInfrastructure", "-2.5,4!"),
        ("ac5", "AI Application\n/ Product", "0.5,10.5!"),
        ("ac6", "AI Plugin\n/ Extension", "0.5,4!"),
    ]
    for nid, label, pos in ai_cats:
        g.node(nid, label, pos=pos, **{**ORANGE, "fontsize": "9.5", "penwidth": "1.2"})
        g.edge("AICategory", nid, **{**EL, "penwidth": "1", "color": "#E67E22", "arrowsize": "0.5", "label": ""})

    # ═══════════════════════════════════════
    #  EXTENSION 2: Risk Domain - MIT (red)
    # ═══════════════════════════════════════
    g.node("RiskDomain", "Risk\nDomain", pos="8,12!", **{**RED, "fontsize": "15", "penwidth": "2.5"})
    g.edge("Vulnerability", "RiskDomain", label="maps-to", **EL_R)
    g.edge("Type", "RiskDomain", label="implies", **EL_R)

    g.node("RiskSub", "Risk\nSubdomain", pos="5,13!", **{**RED, "fontsize": "12"})
    g.edge("RiskDomain", "RiskSub", label="has-a", **EL)

    domains = [
        ("RD1", "Discrimination\n&amp; Toxicity", "3.5,14.5!"),
        ("RD2", "Privacy\n&amp; Security", "5.5,14.5!"),
        ("RD3", "Misinformation", "7.5,14.5!"),
        ("RD4", "Malicious Actors\n&amp; Misuse", "9.5,14.5!"),
        ("RD5", "Human-Computer\nInteraction", "11.5,14.5!"),
        ("RD6", "Socioeconomic\n&amp; Environmental", "13,12.5!"),
        ("RD7", "AI System Safety\n&amp; Limitations", "11.5,11!"),
    ]
    for nid, label, pos in domains:
        g.node(nid, label, pos=pos, **{**RED, "fontsize": "9.5", "penwidth": "1.2"})
        g.edge("RiskDomain", nid, **{**EL, "penwidth": "1", "color": "#E74C3C", "arrowsize": "0.5", "label": ""})

    # ═══════════════════════════════════════
    #  EXTENSION 3: Causal Taxonomy (green)
    # ═══════════════════════════════════════
    g.node("CausalFactor", "Causal\nFactor", pos="5,5.5!", **{**GREEN, "fontsize": "14", "penwidth": "2.5"})
    g.edge("Vulnerability", "CausalFactor", label="has-cause", **{**EL, "style": "dashed", "color": "#27AE60", "fontcolor": "#27AE60"})

    g.node("Entity", "Entity", pos="2.5,3!", **{**GREEN, "fontsize": "11"})
    g.node("Intent", "Intent", pos="5,2.5!", **{**GREEN, "fontsize": "11"})
    g.node("Timing", "Timing", pos="7.5,3!", **{**GREEN, "fontsize": "11"})

    g.edge("CausalFactor", "Entity", label="dimension", **{**EL, "color": "#27AE60", "fontsize": "9"})
    g.edge("CausalFactor", "Intent", label="dimension", **{**EL, "color": "#27AE60", "fontsize": "9"})
    g.edge("CausalFactor", "Timing", label="dimension", **{**EL, "color": "#27AE60", "fontsize": "9"})

    causal_vals = [
        ("E_Human", "Human", "Entity", "1,1.5!"),
        ("E_AI", "AI", "Entity", "2.5,1!"),
        ("I_Intent", "Intentional", "Intent", "4,0.8!"),
        ("I_Unintent", "Unintentional", "Intent", "6,0.8!"),
        ("T_Pre", "Pre-deploy", "Timing", "7.5,1!"),
        ("T_Post", "Post-deploy", "Timing", "9.5,1.5!"),
    ]
    for nid, label, parent, pos in causal_vals:
        g.node(nid, label, pos=pos, **{**GREEN, "fontsize": "9.5", "penwidth": "1"})
        g.edge(parent, nid, **{**EL, "penwidth": "0.8", "color": "#27AE60", "arrowsize": "0.5"})

    # ═══════════════════════════════════════
    #  EXTENSION 4: Attack Pattern (purple)
    # ═══════════════════════════════════════
    g.node("AttackPattern", "Attack\nPattern\n(CAPEC)", pos="12.5,8!", **PURPLE)
    g.edge("AttackPattern", "Vulnerability", label="exploits", **EL)
    g.edge("AttackPattern", "Type", label="targets", **{**EL, "style": "dashed", "color": "#8E44AD"})

    # ═══════════════════════════════════════
    #  LEGEND (bottom-right, no overlap)
    # ═══════════════════════════════════════
    with g.subgraph(name="cluster_legend") as lg:
        lg.attr(
            label="<<B>Legend</B>>", fontsize="12", fontname="Helvetica Neue",
            style="rounded,filled", fillcolor="#FAFAFA", color="#CCCCCC",
            margin="16",
        )
        ls = {"fontsize": "9", "width": "1.1", "height": "0.45"}
        lg.node("L1", "Core (existing)", pos="15,3!", **{**PINK, **ls})
        lg.node("L2", "Software / HW", pos="15,2.3!", **{**BLUE, **ls})
        lg.node("L3", "AI Category ★", pos="15,1.6!", **{**ORANGE, **ls})
        lg.node("L4", "Risk Domain ★", pos="15,0.9!", **{**RED, **ls})
        lg.node("L5", "Causal Factor ★", pos="15,0.2!", **{**GREEN, **ls})
        lg.node("L6", "Attack Pattern ★", pos="15,-0.5!", **{**PURPLE, **ls})
        lg.node("L7", "Attribute", pos="15,-1.2!", **{**GRAY, **ls})
        for a, b in [("L1", "L2"), ("L2", "L3"), ("L3", "L4"),
                      ("L4", "L5"), ("L5", "L6"), ("L6", "L7")]:
            lg.edge(a, b, style="invis")

    return g


if __name__ == "__main__":
    g = build_ontology_graph()
    out = "output/ai_vulnerability_ontology"
    g.render(out, cleanup=True)
    print(f"Ontology graph saved to {out}.png")
