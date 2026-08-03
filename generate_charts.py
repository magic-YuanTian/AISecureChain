"""
AISecureChain - Visualization Charts for Presentation
======================================================
Generates publication-quality charts analyzing 2,629 AI security events from MISP.
"""

import json
import re
from collections import Counter, defaultdict

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

plt.rcParams.update({
    "figure.dpi": 200,
    "savefig.dpi": 200,
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.labelsize": 12,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

COLORS = {
    "primary": "#2563EB",
    "secondary": "#7C3AED",
    "accent": "#F59E0B",
    "danger": "#EF4444",
    "success": "#10B981",
    "gray": "#6B7280",
    "gradient": ["#1E3A5F", "#2563EB", "#3B82F6", "#60A5FA", "#93C5FD"],
    "severity": {"CRITICAL": "#7F1D1D", "HIGH": "#DC2626", "MEDIUM": "#F59E0B", "LOW": "#10B981"},
    "pie": ["#2563EB", "#7C3AED", "#EF4444", "#F59E0B", "#10B981", "#6366F1", "#EC4899", "#14B8A6"],
}

OUTPUT_DIR = "output/charts"


def load_data():
    with open("output/all_ai_events_full.json") as f:
        raw = json.load(f)

    records = []
    for ev_wrapper in raw:
        e = ev_wrapper.get("Event", ev_wrapper)
        rec = {
            "id": e.get("id"),
            "date": e.get("date", ""),
            "info": e.get("info", ""),
            "threat_level_id": e.get("threat_level_id", ""),
            "attribute_count": int(e.get("attribute_count", 0)),
        }

        for obj in e.get("Object", []):
            for a in obj.get("Attribute", []):
                rel = a.get("object_relation", "")
                val = a.get("value", "")
                if rel == "id" and val.startswith("CVE"):
                    rec["cve_id"] = val
                elif rel == "cvss-score":
                    try:
                        rec["cvss_score"] = float(val)
                    except ValueError:
                        pass
                elif rel == "cvss-string":
                    rec["cvss_string"] = val
                elif rel == "description":
                    rec["description"] = val

        for a in e.get("Attribute", []):
            tags = [t.get("name", "") for t in a.get("Tag", [])]
            if "severity" in tags:
                rec["severity"] = a.get("value", "").upper()

        records.append(rec)

    return pd.DataFrame(records)


def parse_severity(row):
    """Derive severity from CVSS score."""
    score = row.get("cvss_score")
    if pd.isna(score):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def extract_software(info):
    """Extract software/platform name from event info."""
    software_patterns = [
        (r"(?i)\b(AutoGPT|Auto-GPT)\b", "AutoGPT"),
        (r"(?i)\b(ChatGPT)\b", "ChatGPT"),
        (r"(?i)\b(LangChain|langchain)\b", "LangChain"),
        (r"(?i)\b(PyTorch|pytorch)\b", "PyTorch"),
        (r"(?i)\b(TensorFlow|tensorflow)\b", "TensorFlow"),
        (r"(?i)\b(Hugging\s?Face|huggingface)\b", "Hugging Face"),
        (r"(?i)\b(ollama)\b", "Ollama"),
        (r"(?i)\b(Dify|dify)\b", "Dify"),
        (r"(?i)\b(Gradio|gradio)\b", "Gradio"),
        (r"(?i)\b(vLLM|vllm)\b", "vLLM"),
        (r"(?i)\b(FastGPT|fastgpt)\b", "FastGPT"),
        (r"(?i)\b(Crawl4AI|crawl4ai)\b", "Crawl4AI"),
        (r"(?i)\b(DB-GPT|dbgpt)\b", "DB-GPT"),
        (r"(?i)\b(DocsGPT|docsgpt)\b", "DocsGPT"),
        (r"(?i)\b(MindsDB|mindsdb)\b", "MindsDB"),
        (r"(?i)\b(Milvus|milvus)\b", "Milvus"),
        (r"(?i)\b(WordPress)\b", "WordPress (AI Plugins)"),
        (r"(?i)\b(Cursor)\b", "Cursor"),
        (r"(?i)\b(GitHub\s*Copilot)\b", "GitHub Copilot"),
        (r"(?i)\b(OpenAI)\b", "OpenAI"),
        (r"(?i)\b(lunary)\b", "Lunary"),
        (r"(?i)\b(MLflow|mlflow)\b", "MLflow"),
        (r"(?i)\b(ChuanhuChatGPT|chuanhuchatgpt)\b", "ChuanhuChatGPT"),
        (r"(?i)\b(BrowserPilot|browserpilot)\b", "BrowserPilot"),
        (r"(?i)\b(PrivateGPT|privategpt)\b", "PrivateGPT"),
        (r"(?i)\b(aim|aimhubio)\b", "Aim (aimhubio)"),
        (r"(?i)\b(Keras|keras)\b", "Keras"),
        (r"(?i)\b(lakeFS|lakefs)\b", "lakeFS"),
        (r"(?i)\b(AnythingLLM|anythingllm)\b", "AnythingLLM"),
        (r"(?i)\b(Open WebUI|open-webui)\b", "Open WebUI"),
        (r"(?i)\b(ComfyUI|comfyui)\b", "ComfyUI"),
        (r"(?i)\b(LocalAI|localai)\b", "LocalAI"),
        (r"(?i)\b(LiteLLM|litellm)\b", "LiteLLM"),
        (r"(?i)\b(Label Studio|label-studio)\b", "Label Studio"),
        (r"(?i)\b(Ray)\b", "Ray"),
        (r"(?i)\b(BentoML|bentoml)\b", "BentoML"),
        (r"(?i)\b(Jupyter)\b", "Jupyter"),
    ]
    for pattern, name in software_patterns:
        if re.search(pattern, info):
            return name
    return None


def extract_vuln_type(info):
    """Extract vulnerability type from event info."""
    vuln_patterns = [
        (r"(?i)remote code execution|(?<!\w)RCE(?!\w)", "Remote Code Execution (RCE)"),
        (r"(?i)code injection", "Code Injection"),
        (r"(?i)command injection", "Command Injection"),
        (r"(?i)SQL injection|sql.?inject", "SQL Injection"),
        (r"(?i)cross.?site.?scripting|(?<!\w)XSS(?!\w)", "Cross-Site Scripting (XSS)"),
        (r"(?i)cross.?site.?request.?forgery|(?<!\w)CSRF(?!\w)", "Cross-Site Request Forgery (CSRF)"),
        (r"(?i)server.?side.?request.?forgery|(?<!\w)SSRF(?!\w)", "Server-Side Request Forgery (SSRF)"),
        (r"(?i)denial.?of.?service|(?<!\w)DoS(?!\w)|(?<!\w)DDoS(?!\w)", "Denial of Service (DoS)"),
        (r"(?i)privilege.?escalation", "Privilege Escalation"),
        (r"(?i)path.?traversal|directory.?traversal", "Path Traversal"),
        (r"(?i)broken.?access.?control|access.?control", "Broken Access Control"),
        (r"(?i)information.?disclosure|information.?exposure|sensitive.?information", "Information Disclosure"),
        (r"(?i)authentication.?bypass|improper.?authentication", "Authentication Bypass"),
        (r"(?i)deserialization", "Insecure Deserialization"),
        (r"(?i)(?<!\w)IDOR(?!\w)|insecure.?direct", "IDOR"),
        (r"(?i)open.?redirect", "Open Redirect"),
        (r"(?i)file.?upload|arbitrary.?file", "Arbitrary File Operation"),
        (r"(?i)buffer.?overflow|out.?of.?bounds|heap.?overflow|stack.?overflow", "Memory Corruption"),
        (r"(?i)use.?after.?free", "Use After Free"),
        (r"(?i)sandbox.?escape", "Sandbox Escape"),
        (r"(?i)prompt.?injection", "Prompt Injection"),
        (r"(?i)improper.?access|missing.?authorization|unauthorized", "Missing Authorization"),
    ]
    for pattern, name in vuln_patterns:
        if re.search(pattern, info):
            return name
    return "Other"


def parse_attack_vector(cvss_string):
    """Extract attack vector from CVSS string."""
    if not isinstance(cvss_string, str):
        return None
    m = re.search(r"AV:([NALP])", cvss_string)
    if m:
        mapping = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
        return mapping.get(m.group(1))
    return None


# =========================================================================
# Chart 1: Monthly Trend
# =========================================================================
def chart_monthly_trend(df):
    print("  Creating Chart 1: Monthly Trend...")
    df["year_month"] = df["date"].str[:7]
    monthly = df.groupby("year_month").size().reset_index(name="count")
    monthly = monthly[monthly["year_month"] >= "2020-01"]
    monthly["dt"] = pd.to_datetime(monthly["year_month"] + "-01")

    fig, ax = plt.subplots(figsize=(14, 5))
    bars = ax.bar(monthly["dt"], monthly["count"], width=25, color=COLORS["primary"], alpha=0.85, edgecolor="white", linewidth=0.5)

    z = np.polyfit(range(len(monthly)), monthly["count"], 2)
    p = np.poly1d(z)
    ax.plot(monthly["dt"], p(range(len(monthly))), color=COLORS["danger"], linewidth=2.5, linestyle="--", label="Trend (quadratic fit)")

    ax.set_title("Monthly AI Security Vulnerabilities (CVEs) Reported in MISP")
    ax.set_xlabel("Date")
    ax.set_ylabel("Number of CVEs")
    ax.legend()
    ax.xaxis.set_major_locator(mticker.MaxNLocator(12))
    fig.autofmt_xdate(rotation=45)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/1_monthly_trend.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 2: Yearly Growth
# =========================================================================
def chart_yearly_growth(df):
    print("  Creating Chart 2: Yearly Growth...")
    df["year"] = df["date"].str[:4]
    yearly = df.groupby("year").size().reset_index(name="count")
    yearly = yearly[yearly["year"] >= "2020"]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(yearly["year"], yearly["count"], color=COLORS["gradient"][:1] * len(yearly), edgecolor="white", linewidth=0.5)

    colors = plt.cm.Blues(np.linspace(0.4, 0.9, len(yearly)))
    for bar, c in zip(bars, colors):
        bar.set_color(c)

    for bar, val in zip(bars, yearly["count"]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                str(val), ha="center", va="bottom", fontweight="bold", fontsize=11)

    ax.set_title("Yearly Growth of AI Security Vulnerabilities")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    ax.set_ylim(0, max(yearly["count"]) * 1.3)
    note = "* 2026 data is partial (through Feb 15)"
    ax.annotate(note, xy=(0.98, 0.02), xycoords="axes fraction", ha="right", fontsize=8, color=COLORS["gray"], style="italic")
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/2_yearly_growth.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 3: CVSS Score Distribution
# =========================================================================
def chart_cvss_distribution(df):
    print("  Creating Chart 3: CVSS Score Distribution...")
    scores = df["cvss_score"].dropna()

    fig, ax = plt.subplots(figsize=(10, 5))

    bins = np.arange(0, 10.5, 0.5)
    n, bins_out, patches = ax.hist(scores, bins=bins, edgecolor="white", linewidth=0.5)

    for patch, left_edge in zip(patches, bins_out[:-1]):
        if left_edge >= 9.0:
            patch.set_facecolor(COLORS["severity"]["CRITICAL"])
        elif left_edge >= 7.0:
            patch.set_facecolor(COLORS["severity"]["HIGH"])
        elif left_edge >= 4.0:
            patch.set_facecolor(COLORS["severity"]["MEDIUM"])
        else:
            patch.set_facecolor(COLORS["severity"]["LOW"])

    ax.axvline(scores.median(), color="black", linestyle="--", linewidth=1.5, label=f"Median: {scores.median():.1f}")
    ax.axvline(scores.mean(), color=COLORS["secondary"], linestyle=":", linewidth=1.5, label=f"Mean: {scores.mean():.1f}")

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS["severity"]["CRITICAL"], label=f"Critical (9.0-10.0): {(scores >= 9).sum()}"),
        Patch(facecolor=COLORS["severity"]["HIGH"], label=f"High (7.0-8.9): {((scores >= 7) & (scores < 9)).sum()}"),
        Patch(facecolor=COLORS["severity"]["MEDIUM"], label=f"Medium (4.0-6.9): {((scores >= 4) & (scores < 7)).sum()}"),
        Patch(facecolor=COLORS["severity"]["LOW"], label=f"Low (0.1-3.9): {((scores > 0) & (scores < 4)).sum()}"),
        plt.Line2D([0], [0], color="black", linestyle="--", label=f"Median: {scores.median():.1f}"),
        plt.Line2D([0], [0], color=COLORS["secondary"], linestyle=":", label=f"Mean: {scores.mean():.1f}"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=9)
    ax.set_title(f"CVSS Score Distribution of AI Vulnerabilities (n={len(scores)})")
    ax.set_xlabel("CVSS Score")
    ax.set_ylabel("Number of CVEs")
    ax.set_xlim(0, 10.5)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/3_cvss_distribution.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 4: Severity Pie Chart
# =========================================================================
def chart_severity_pie(df):
    print("  Creating Chart 4: Severity Distribution...")
    df["severity_derived"] = df.apply(parse_severity, axis=1)
    sev_counts = df["severity_derived"].value_counts()

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    sev_counts = sev_counts.reindex([s for s in order if s in sev_counts.index])
    colors_list = [COLORS["severity"].get(s, COLORS["gray"]) for s in sev_counts.index]

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sev_counts.values, labels=sev_counts.index, autopct="%1.1f%%",
        colors=colors_list, startangle=90, pctdistance=0.75,
        wedgeprops=dict(width=0.5, edgecolor="white", linewidth=2),
    )
    for t in autotexts:
        t.set_fontsize(10)
        t.set_fontweight("bold")

    centre_circle = plt.Circle((0, 0), 0.50, fc="white")
    ax.add_artist(centre_circle)
    ax.text(0, 0, f"{len(df)}\nTotal", ha="center", va="center", fontsize=16, fontweight="bold")

    ax.set_title("Severity Distribution of AI Vulnerabilities\n(Based on CVSS Scores)")
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/4_severity_distribution.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 5: Top Affected AI Software
# =========================================================================
def chart_top_software(df):
    print("  Creating Chart 5: Top Affected AI Software...")
    df["software"] = df["info"].apply(extract_software)
    sw_counts = df["software"].dropna().value_counts().head(20)

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(range(len(sw_counts)), sw_counts.values, color=COLORS["primary"], alpha=0.85, edgecolor="white")

    colors = plt.cm.Blues(np.linspace(0.4, 0.9, len(sw_counts)))[::-1]
    for bar, c in zip(bars, colors):
        bar.set_color(c)

    ax.set_yticks(range(len(sw_counts)))
    ax.set_yticklabels(sw_counts.index)
    ax.invert_yaxis()

    for i, (val, name) in enumerate(zip(sw_counts.values, sw_counts.index)):
        ax.text(val + 1, i, str(val), va="center", fontweight="bold", fontsize=10)

    identified = df["software"].notna().sum()
    ax.set_title(f"Top 20 Most Affected AI Software / Platforms\n({identified} of {len(df)} events identified)")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(sw_counts.values) * 1.15)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/5_top_software.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 6: Vulnerability Types
# =========================================================================
def chart_vuln_types(df):
    print("  Creating Chart 6: Vulnerability Types...")
    df["vuln_type"] = df["info"].apply(extract_vuln_type)
    type_counts = df["vuln_type"].value_counts().head(15)

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = plt.cm.RdYlBu_r(np.linspace(0.15, 0.85, len(type_counts)))
    bars = ax.barh(range(len(type_counts)), type_counts.values, color=colors, edgecolor="white")

    ax.set_yticks(range(len(type_counts)))
    ax.set_yticklabels(type_counts.index, fontsize=10)
    ax.invert_yaxis()

    for i, val in enumerate(type_counts.values):
        pct = val / len(df) * 100
        ax.text(val + 1, i, f"{val} ({pct:.1f}%)", va="center", fontsize=9)

    ax.set_title(f"Vulnerability Types in AI Security Events (n={len(df)})")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(type_counts.values) * 1.2)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/6_vulnerability_types.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Chart 7: Attack Vector
# =========================================================================
def chart_attack_vector(df):
    print("  Creating Chart 7: Attack Vector Distribution...")
    df["attack_vector"] = df["cvss_string"].apply(parse_attack_vector)
    av_counts = df["attack_vector"].dropna().value_counts()

    fig, ax = plt.subplots(figsize=(8, 6))
    av_colors = [COLORS["danger"], COLORS["accent"], COLORS["primary"], COLORS["success"]]
    wedges, texts, autotexts = ax.pie(
        av_counts.values, labels=av_counts.index, autopct="%1.1f%%",
        colors=av_colors[: len(av_counts)], startangle=90,
        wedgeprops=dict(edgecolor="white", linewidth=2),
        pctdistance=0.75,
    )
    for t in autotexts:
        t.set_fontsize(11)
        t.set_fontweight("bold")

    ax.set_title(f"Attack Vector Distribution (from CVSS)\n(n={av_counts.sum()})")
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/7_attack_vector.png", bbox_inches="tight")
    plt.close()


# =========================================================================
# Main
# =========================================================================
def main():
    import os
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Loading data...")
    df = load_data()
    print(f"Loaded {len(df)} events")
    print(f"  - With CVSS scores: {df['cvss_score'].notna().sum()}")
    print(f"  - With descriptions: {df['description'].notna().sum() if 'description' in df.columns else 0}")
    print()

    print("Generating charts...")
    chart_monthly_trend(df)
    chart_yearly_growth(df)
    chart_cvss_distribution(df)
    chart_severity_pie(df)
    chart_top_software(df)
    chart_vuln_types(df)
    chart_attack_vector(df)

    print(f"\nAll charts saved to {OUTPUT_DIR}/")
    print("Files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.endswith(".png"):
            print(f"  - {f}")


if __name__ == "__main__":
    main()
