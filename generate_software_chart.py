"""
Generate software distribution chart from cvelistV5 structured data.
No predefined keyword lists — purely data-driven from CVE affected products.
"""

import json
import os
import re
from collections import Counter

import matplotlib.pyplot as plt
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
    "grid.alpha": 0.3,
})

OUTPUT_DIR = "output/charts"


def normalize_name(vendor, product):
    """Normalize vendor/product pairs to merge duplicates."""
    v = vendor.strip().lower()
    p = product.strip().lower()

    # Skip unknowns
    if v in ("n/a", "", "unknown") and p in ("n/a", "", "unknown"):
        return None, None

    # Remove redundant vendor prefix from product names like "gradio-app/gradio" -> "gradio"
    clean_product = p
    if "/" in p:
        parts = p.split("/")
        if len(parts) == 2 and (parts[0] == v or parts[0] in v or v in parts[0]):
            clean_product = parts[1]
        elif len(parts) == 2:
            clean_product = parts[1]

    # Capitalize for display
    display_vendor = vendor.strip()
    display_product = clean_product.strip()

    # Merge known duplicates (discovered from data, not predefined topics)
    merge_map = {
        ("tensorflow", "tensorflow"): ("TensorFlow", "TensorFlow"),
        ("gradio-app", "gradio"): ("Gradio", "Gradio"),
        ("gradio-app", "gradio-app/gradio"): ("Gradio", "Gradio"),
        ("huggingface", "transformers"): ("Hugging Face", "Transformers"),
        ("hugging face", "transformers"): ("Hugging Face", "Transformers"),
        ("cursor", "cursor"): ("Cursor", "Cursor"),
        ("vllm-project", "vllm"): ("vLLM", "vLLM"),
        ("mlflow", "mlflow/mlflow"): ("MLflow", "MLflow"),
        ("langchain-ai", "langchain"): ("LangChain", "LangChain"),
        ("langchain-ai", "langchain-ai/langchain"): ("LangChain", "LangChain"),
        ("langgenius", "dify"): ("Dify", "Dify"),
        ("langgenius", "langgenius/dify"): ("Dify", "Dify"),
    }
    key = (v, clean_product)
    if key in merge_map:
        display_vendor, display_product = merge_map[key]

    return display_vendor, display_product


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open("output/cve_details.json") as f:
        cve_data = json.load(f)

    # Collect all vendor/product from structured data
    vp_counter = Counter()
    vendor_counter = Counter()
    product_counter = Counter()
    skipped = 0

    for cve_id, record in cve_data.items():
        if "error" in record:
            continue
        cna = record.get("containers", {}).get("cna", {})
        for a in cna.get("affected", []):
            raw_v = a.get("vendor", "")
            raw_p = a.get("product", "")
            dv, dp = normalize_name(raw_v, raw_p)
            if dv is None:
                skipped += 1
                continue
            vp_counter[f"{dv} / {dp}"] += 1
            vendor_counter[dv] += 1
            product_counter[dp] += 1

    print(f"Total vendor/product entries: {sum(vp_counter.values())}")
    print(f"Skipped (n/a): {skipped}")
    print(f"Unique vendor/product pairs: {len(vp_counter)}")
    print(f"Unique vendors: {len(vendor_counter)}")
    print(f"Unique products: {len(product_counter)}")

    # ---- Chart: Top 30 Vendor/Product ----
    top30 = vp_counter.most_common(30)
    print("\nTop 30 Vendor / Product:")
    for name, count in top30:
        print(f"  {count:4d}  {name}")

    fig, ax = plt.subplots(figsize=(12, 9))
    colors = plt.cm.Blues(np.linspace(0.35, 0.9, len(top30)))[::-1]
    vals = [c for _, c in top30]
    bars = ax.barh(range(len(top30)), vals, color=colors, edgecolor="white")
    ax.set_yticks(range(len(top30)))
    ax.set_yticklabels([n for n, _ in top30], fontsize=9)
    ax.invert_yaxis()
    for i, val in enumerate(vals):
        ax.text(val + 1, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(
        f"Top 30 Affected Software (Vendor / Product)\n"
        f"Data-driven from CVE Affected Products field ({len(vp_counter)} unique pairs)"
    )
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(vals) * 1.12)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/9_software_distribution.png", bbox_inches="tight")
    plt.close()
    print("  -> Saved 9_software_distribution.png")

    # ---- Chart: Top 25 Vendors ----
    top25v = vendor_counter.most_common(25)
    fig, ax = plt.subplots(figsize=(10, 7))
    colors = plt.cm.Purples(np.linspace(0.35, 0.9, len(top25v)))[::-1]
    vals = [c for _, c in top25v]
    bars = ax.barh(range(len(top25v)), vals, color=colors, edgecolor="white")
    ax.set_yticks(range(len(top25v)))
    ax.set_yticklabels([n for n, _ in top25v], fontsize=9)
    ax.invert_yaxis()
    for i, val in enumerate(vals):
        ax.text(val + 1, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(
        f"Top 25 Vendors of Affected AI Software\n"
        f"({len(vendor_counter)} unique vendors)"
    )
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(vals) * 1.12)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/10_vendor_distribution.png", bbox_inches="tight")
    plt.close()
    print("  -> Saved 10_vendor_distribution.png")

    # ---- Chart: Top 30 Products ----
    top30p = product_counter.most_common(30)
    fig, ax = plt.subplots(figsize=(11, 8))
    colors = plt.cm.Greens(np.linspace(0.35, 0.9, len(top30p)))[::-1]
    vals = [c for _, c in top30p]
    bars = ax.barh(range(len(top30p)), vals, color=colors, edgecolor="white")
    ax.set_yticks(range(len(top30p)))
    ax.set_yticklabels([n for n, _ in top30p], fontsize=9)
    ax.invert_yaxis()
    for i, val in enumerate(vals):
        ax.text(val + 1, i, str(val), va="center", fontweight="bold", fontsize=9)
    ax.set_title(
        f"Top 30 Affected AI Products\n"
        f"({len(product_counter)} unique products)"
    )
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(vals) * 1.12)
    plt.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/14_product_distribution.png", bbox_inches="tight")
    plt.close()
    print("  -> Saved 14_product_distribution.png")

    # Save raw data
    output = {
        "top_vendor_product": dict(vp_counter.most_common(100)),
        "top_vendors": dict(vendor_counter.most_common(100)),
        "top_products": dict(product_counter.most_common(100)),
        "stats": {
            "unique_vendors": len(vendor_counter),
            "unique_products": len(product_counter),
            "unique_pairs": len(vp_counter),
            "skipped_na": skipped,
        },
    }
    with open("output/software_distribution.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("  -> Saved output/software_distribution.json")


if __name__ == "__main__":
    main()
