"""
AISecureChain - Ontology-Based Analysis
========================================
Analyzes CVE data against the vulnerability ontology:
  Vulnerability -> Type (CWE)
  Vulnerability -> Software -> Version -> Vendor
  Categorization: AI Infrastructure / Agentic Systems / Foundation Models
"""

import json
import os
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
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 12,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

OUTPUT_DIR = "output/charts"


AI_CATEGORY_RULES = {
    "Foundation Model / LLM": [
        r"(?i)\b(openai|gpt|chatgpt|llama|claude|gemini|anthropic|mistral)\b",
        r"(?i)\b(transformers|huggingface|hugging.face)\b",
        r"(?i)\b(ollama|vllm|llm|large.language.model)\b",
        r"(?i)\b(text.generation|language.model|diffusion|stable.diffusion)\b",
        r"(?i)\b(onnx|safetensors)\b",
    ],
    "AI Agent / Agentic System": [
        r"(?i)\b(autogpt|auto-gpt|agentgpt|babyagi|crewai)\b",
        r"(?i)\b(langchain|langgraph|langflow|flowise)\b",
        r"(?i)\b(browserpilot|browser.use|crawl4ai)\b",
        r"(?i)\b(dify|n8n.ai|zapier.ai|agent|agentic)\b",
        r"(?i)\b(mcp.server|mcp-server|tool.use|function.calling)\b",
        r"(?i)\b(copilot|cursor|cody|continue|tabby)\b",
        r"(?i)\b(docsgpt|privategpt|localai|anythingllm|open.webui)\b",
    ],
    "ML Framework / Library": [
        r"(?i)\b(tensorflow|pytorch|keras|jax|mxnet|caffe)\b",
        r"(?i)\b(scikit.learn|sklearn|xgboost|lightgbm|catboost)\b",
        r"(?i)\b(numpy|scipy|pandas)\b.*(ml|model|train|tensor)",
        r"(?i)\b(onnxruntime|tensorrt|triton)\b",
    ],
    "ML Platform / MLOps": [
        r"(?i)\b(mlflow|kubeflow|mlrun|metaflow|airflow)\b",
        r"(?i)\b(bentoml|seldon|torchserve|tensorflow.serving)\b",
        r"(?i)\b(wandb|weights.biases|neptune|comet)\b",
        r"(?i)\b(label.studio|labelbox|prodigy|snorkel)\b",
        r"(?i)\b(ray|ray.serve|anyscale)\b",
        r"(?i)\b(aim|aimhubio|clearml)\b",
    ],
    "AI Data Infrastructure": [
        r"(?i)\b(milvus|pinecone|weaviate|qdrant|chroma|chromadb)\b",
        r"(?i)\b(vector.database|vector.store|embedding)\b",
        r"(?i)\b(mindsdb|featurestore|feature.store)\b",
        r"(?i)\b(lakefs|delta.lake|iceberg)\b",
        r"(?i)\b(jupyter|notebook|jupyterlab|jupyterhub)\b",
    ],
    "AI Application / Product": [
        r"(?i)\b(chatbot|chat.bot|conversational)\b",
        r"(?i)\b(deepfake|face.swap|voice.clone)\b",
        r"(?i)\b(recommendation|recommender)\b",
        r"(?i)\b(image.generation|text.to.image|image.to.text)\b",
        r"(?i)\b(speech.to.text|text.to.speech|tts|stt|whisper)\b",
        r"(?i)\b(comfyui|automatic1111|stable.diffusion.webui)\b",
        r"(?i)\b(fastgpt|db-gpt|chuanhuchatgpt|lunary|litellm)\b",
        r"(?i)\b(gradio|streamlit)\b",
    ],
    "AI-Integrated Plugin / Extension": [
        r"(?i)\bwordpress\b.*(ai|gpt|chatbot|ml|intelligence)",
        r"(?i)\b(ai.plugin|ai.addon|ai.extension|ai.widget)\b",
        r"(?i)\b(wpaicg|bertha.ai|ai.power|ai.engine|elementor.ai)\b",
        r"(?i)\b(ai.for.seo|ai.writer|ai.content)\b",
    ],
}


def load_data():
    with open("output/cve_details.json") as f:
        cve_data = json.load(f)

    with open("output/all_ai_events_full.json") as f:
        misp_events = json.load(f)

    misp_info = {}
    for ev in misp_events:
        e = ev.get("Event", ev)
        for obj in e.get("Object", []):
            for a in obj.get("Attribute", []):
                if a.get("object_relation") == "id" and str(a.get("value", "")).startswith("CVE"):
                    misp_info[a["value"]] = e.get("info", "")

    return cve_data, misp_info


def extract_cwe(cve_record):
    """Extract CWE IDs and descriptions from a CVE record."""
    cwes = []
    cna = cve_record.get("containers", {}).get("cna", {})
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId", "")
            cwe_desc = desc.get("description", "")
            if cwe_id:
                cwes.append({"id": cwe_id, "description": cwe_desc})
            elif cwe_desc and not cwe_id:
                cwes.append({"id": "N/A", "description": cwe_desc})
    return cwes


def extract_affected(cve_record):
    """Extract affected vendor/product/version from a CVE record."""
    affected_list = []
    cna = cve_record.get("containers", {}).get("cna", {})
    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "n/a")
        product = affected.get("product", "n/a")
        versions = []
        for v in affected.get("versions", []):
            versions.append({
                "version": v.get("version", ""),
                "status": v.get("status", ""),
                "lessThan": v.get("lessThan", ""),
                "lessThanOrEqual": v.get("lessThanOrEqual", ""),
            })
        affected_list.append({
            "vendor": vendor,
            "product": product,
            "versions": versions,
        })
    return affected_list


def categorize_ai(cve_id, cve_record, misp_info_text):
    """Categorize a CVE into AI category based on product info and event description."""
    cna = cve_record.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])

    search_text_parts = [misp_info_text]
    for a in affected:
        search_text_parts.append(a.get("vendor", ""))
        search_text_parts.append(a.get("product", ""))
    for desc_list in cna.get("descriptions", []):
        search_text_parts.append(desc_list.get("value", ""))
    search_text = " ".join(search_text_parts)

    for category, patterns in AI_CATEGORY_RULES.items():
        for pattern in patterns:
            if re.search(pattern, search_text):
                return category
    return "Other / Uncategorized"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Loading data...")
    cve_data, misp_info = load_data()
    print(f"CVE records: {len(cve_data)}")
    print(f"MISP event info mapping: {len(misp_info)}")

    # === Parse all records ===
    records = []
    for cve_id, record in cve_data.items():
        if "error" in record:
            continue
        cwes = extract_cwe(record)
        affected = extract_affected(record)
        info_text = misp_info.get(cve_id, "")
        category = categorize_ai(cve_id, record, info_text)

        records.append({
            "cve_id": cve_id,
            "cwes": cwes,
            "affected": affected,
            "category": category,
            "info": info_text,
        })

    print(f"Parsed records: {len(records)}")

    # =====================================================================
    # 1. CWE Distribution
    # =====================================================================
    print("\n=== CWE DISTRIBUTION ===")
    cwe_counter = Counter()
    cwe_names = {}
    no_cwe_count = 0

    for rec in records:
        if not rec["cwes"]:
            no_cwe_count += 1
        for cwe in rec["cwes"]:
            cid = cwe["id"]
            cwe_counter[cid] += 1
            if cid not in cwe_names and cwe["description"]:
                cwe_names[cid] = cwe["description"]

    print(f"CVEs with CWE: {len(records) - no_cwe_count}")
    print(f"CVEs without CWE: {no_cwe_count}")
    print(f"Unique CWE types: {len(cwe_counter)}")

    top_cwes = cwe_counter.most_common(25)
    print("\nTop 25 CWEs:")
    for cid, count in top_cwes:
        name = cwe_names.get(cid, "")
        short = re.sub(r"^CWE-\d+:\s*", "", name)[:60]
        print(f"  {cid}: {count} ({short})")

    # Chart: CWE Distribution (Top 20)
    top20_cwes = cwe_counter.most_common(20)
    labels = []
    for cid, _ in top20_cwes:
        name = cwe_names.get(cid, "")
        short = re.sub(r"^CWE-\d+:\s*", "", name)
        if len(short) > 40:
            short = short[:37] + "..."
        labels.append(f"{cid}\n{short}")

    fig, ax = plt.subplots(figsize=(12, 8))
    colors = plt.cm.Reds(np.linspace(0.3, 0.9, len(top20_cwes)))[::-1]
    bars = ax.barh(range(len(top20_cwes)), [c for _, c in top20_cwes], color=colors, edgecolor="white")
    ax.set_yticks(range(len(top20_cwes)))
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.invert_yaxis()
    for i, (_, val) in enumerate(top20_cwes):
        ax.text(val + 2, i, str(val), va="center", fontweight="bold", fontsize=9)
    total_with_cwe = len(records) - no_cwe_count
    ax.set_title(f"Top 20 CWE Types in AI Vulnerabilities\n({total_with_cwe} of {len(records)} CVEs have CWE data)")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(c for _, c in top20_cwes) * 1.15)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/8_cwe_distribution.png", bbox_inches="tight")
    plt.close()
    print(f"  -> Saved 8_cwe_distribution.png")

    # =====================================================================
    # 2. Software (Vendor/Product) Distribution
    # =====================================================================
    print("\n=== SOFTWARE (VENDOR/PRODUCT) DISTRIBUTION ===")
    vendor_counter = Counter()
    product_counter = Counter()
    vendor_product_counter = Counter()

    for rec in records:
        for a in rec["affected"]:
            v = a["vendor"].strip().lower()
            p = a["product"].strip().lower()
            if v and v not in ("n/a", ""):
                vendor_counter[a["vendor"].strip()] += 1
            if p and p not in ("n/a", ""):
                product_counter[a["product"].strip()] += 1
            if v not in ("n/a", "") and p not in ("n/a", ""):
                vendor_product_counter[f"{a['vendor'].strip()} / {a['product'].strip()}"] += 1

    print(f"Unique vendors: {len(vendor_counter)}")
    print(f"Unique products: {len(product_counter)}")

    # Chart: Top 25 Vendor/Product
    top25_vp = vendor_product_counter.most_common(25)
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = plt.cm.Blues(np.linspace(0.35, 0.9, len(top25_vp)))[::-1]
    bars = ax.barh(range(len(top25_vp)), [c for _, c in top25_vp], color=colors, edgecolor="white")
    ax.set_yticks(range(len(top25_vp)))
    ax.set_yticklabels([name[:50] for name, _ in top25_vp], fontsize=9)
    ax.invert_yaxis()
    for i, (_, val) in enumerate(top25_vp):
        ax.text(val + 0.5, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(f"Top 25 Affected Software (Vendor / Product)\nfrom CVE Affected Products ({len(vendor_product_counter)} unique)")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(c for _, c in top25_vp) * 1.15)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/9_software_distribution.png", bbox_inches="tight")
    plt.close()
    print(f"  -> Saved 9_software_distribution.png")

    # Chart: Top 20 Vendors
    top20_vendors = vendor_counter.most_common(20)
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = plt.cm.Purples(np.linspace(0.35, 0.9, len(top20_vendors)))[::-1]
    bars = ax.barh(range(len(top20_vendors)), [c for _, c in top20_vendors], color=colors, edgecolor="white")
    ax.set_yticks(range(len(top20_vendors)))
    ax.set_yticklabels([name[:40] for name, _ in top20_vendors], fontsize=9)
    ax.invert_yaxis()
    for i, (_, val) in enumerate(top20_vendors):
        ax.text(val + 0.5, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(f"Top 20 Vendors of Affected AI Software\n({len(vendor_counter)} unique vendors)")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(c for _, c in top20_vendors) * 1.15)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/10_vendor_distribution.png", bbox_inches="tight")
    plt.close()
    print(f"  -> Saved 10_vendor_distribution.png")

    # =====================================================================
    # 3. AI Category Distribution
    # =====================================================================
    print("\n=== AI CATEGORY DISTRIBUTION ===")
    cat_counter = Counter()
    for rec in records:
        cat_counter[rec["category"]] += 1

    print("Categories:")
    for cat, count in cat_counter.most_common():
        pct = count / len(records) * 100
        print(f"  {cat}: {count} ({pct:.1f}%)")

    # Chart: AI Category Donut
    cat_data = cat_counter.most_common()
    cat_labels = [c for c, _ in cat_data]
    cat_values = [v for _, v in cat_data]

    cat_colors = [
        "#2563EB", "#7C3AED", "#EF4444", "#F59E0B",
        "#10B981", "#EC4899", "#6366F1", "#14B8A6",
    ]

    fig, ax = plt.subplots(figsize=(10, 7))
    wedges, texts, autotexts = ax.pie(
        cat_values, labels=None, autopct="%1.1f%%",
        colors=cat_colors[:len(cat_data)], startangle=90,
        pctdistance=0.8,
        wedgeprops=dict(width=0.45, edgecolor="white", linewidth=2),
    )
    for t in autotexts:
        t.set_fontsize(9)
        t.set_fontweight("bold")

    centre_circle = plt.Circle((0, 0), 0.55, fc="white")
    ax.add_artist(centre_circle)
    ax.text(0, 0, f"{len(records)}\nAI CVEs", ha="center", va="center", fontsize=15, fontweight="bold")

    legend_labels = [f"{label} ({val})" for label, val in zip(cat_labels, cat_values)]
    ax.legend(wedges, legend_labels, title="AI Category", loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1), fontsize=9)

    ax.set_title("AI Vulnerability Categorization\n(Infrastructure / Agentic / Foundation Model / ...)")
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/11_ai_category_distribution.png", bbox_inches="tight")
    plt.close()
    print(f"  -> Saved 11_ai_category_distribution.png")

    # Chart: AI Category bar (excluding Other)
    cat_data_no_other = [(c, v) for c, v in cat_data if c != "Other / Uncategorized"]
    if cat_data_no_other:
        fig, ax = plt.subplots(figsize=(10, 5))
        colors = cat_colors[:len(cat_data_no_other)]
        bars = ax.barh(range(len(cat_data_no_other)),
                       [v for _, v in cat_data_no_other],
                       color=colors, edgecolor="white")
        ax.set_yticks(range(len(cat_data_no_other)))
        ax.set_yticklabels([c for c, _ in cat_data_no_other], fontsize=10)
        ax.invert_yaxis()
        for i, (_, val) in enumerate(cat_data_no_other):
            pct = val / len(records) * 100
            ax.text(val + 2, i, f"{val} ({pct:.1f}%)", va="center", fontweight="bold", fontsize=9)
        identified = sum(v for _, v in cat_data_no_other)
        ax.set_title(f"AI CVEs by System Category (Identified: {identified} of {len(records)})")
        ax.set_xlabel("Number of CVEs")
        ax.set_xlim(0, max(v for _, v in cat_data_no_other) * 1.25)
        plt.tight_layout()
        fig.savefig(f"{OUTPUT_DIR}/12_ai_category_bar.png", bbox_inches="tight")
        plt.close()
        print(f"  -> Saved 12_ai_category_bar.png")

    # =====================================================================
    # 4. Ontology Coverage Summary
    # =====================================================================
    print("\n=== ONTOLOGY COVERAGE SUMMARY ===")
    has_cwe = sum(1 for r in records if r["cwes"])
    has_vendor = sum(1 for r in records if any(a["vendor"].lower() not in ("n/a", "") for a in r["affected"]))
    has_product = sum(1 for r in records if any(a["product"].lower() not in ("n/a", "") for a in r["affected"]))
    has_version = sum(1 for r in records if any(v for a in r["affected"] for v in a["versions"]))
    has_category = sum(1 for r in records if r["category"] != "Other / Uncategorized")

    coverage = {
        "Vulnerability (CVE ID)": len(records),
        "Type (CWE)": has_cwe,
        "Vendor": has_vendor,
        "Product (Software)": has_product,
        "Version": has_version,
        "AI Category": has_category,
    }

    fig, ax = plt.subplots(figsize=(9, 5))
    items = list(coverage.items())
    labels_cov = [k for k, _ in items]
    values_cov = [v for _, v in items]
    pcts = [v / len(records) * 100 for v in values_cov]
    bar_colors = ["#2563EB", "#EF4444", "#7C3AED", "#F59E0B", "#10B981", "#EC4899"]

    bars = ax.barh(range(len(items)), pcts, color=bar_colors, edgecolor="white", height=0.6)
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels(labels_cov, fontsize=11)
    ax.invert_yaxis()
    for i, (pct, val) in enumerate(zip(pcts, values_cov)):
        ax.text(pct + 1, i, f"{val} ({pct:.1f}%)", va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, 115)
    ax.set_xlabel("Coverage (%)")
    ax.set_title(f"Ontology Field Coverage Across {len(records)} AI CVEs")
    ax.axvline(100, color="gray", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/13_ontology_coverage.png", bbox_inches="tight")
    plt.close()
    print(f"  -> Saved 13_ontology_coverage.png")

    for k, v in coverage.items():
        pct = v / len(records) * 100
        print(f"  {k}: {v}/{len(records)} ({pct:.1f}%)")

    # Save analysis data
    analysis_output = {
        "total_records": len(records),
        "cwe_distribution": dict(cwe_counter.most_common(50)),
        "cwe_names": cwe_names,
        "vendor_distribution": dict(vendor_counter.most_common(50)),
        "product_distribution": dict(product_counter.most_common(50)),
        "vendor_product_distribution": dict(vendor_product_counter.most_common(50)),
        "ai_category_distribution": dict(cat_counter.most_common()),
        "ontology_coverage": coverage,
    }
    with open("output/ontology_analysis.json", "w") as f:
        json.dump(analysis_output, f, indent=2, ensure_ascii=False)
    print("\n  -> Full analysis saved to output/ontology_analysis.json")


if __name__ == "__main__":
    main()
