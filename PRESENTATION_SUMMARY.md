# AISecureChain — Presentation Summary

**Data**: 2,631 AI-related CVEs from MISP (tag: AI) + cvelistV5 structured fields  
**Date**: 2018–2026 (partial)

---

## Slide 1: Yearly Growth (01_yearly_growth.png)

**Key Points:**
- AI security vulnerabilities have **grown dramatically**: 42 (2020) → 1,102 (2025)
- **2024–2025** saw the largest jump (+93%)
- 2026 data is partial (through Feb 15) but already 254 CVEs

---

## Slide 2: Monthly Trend (02_monthly_trend.png)

**Key Points:**
- Clear upward trend with quadratic fit
- Peak months in 2025 exceeded 100+ CVEs
- Acceleration in 2024–2025 indicates growing focus on AI security research

---

## Slide 3: CVSS Severity (03_cvss_distribution.png, 04_severity_donut.png)

**Key Points:**
- **Median CVSS: 7.1** (High severity)
- **51.3%** of AI CVEs are High or Critical (9.0+)
- Distribution is multi-modal: notable peaks in Medium (4–7) and High (7–9)

---

## Slide 4: CWE Distribution (05_cwe_distribution.png, 05b_cwe_distribution_compact.png)

**Chart options:** Full chart (top 20, wrapped labels) or compact (top 12) for space-limited slides.

**Key Points:**
- **88.2%** of AI CVEs have CWE classification (2,320 of 2,631)
- Top weaknesses:
  - **CWE-79**: Cross-Site Scripting (XSS)
  - **CWE-22**: Path Traversal
  - **CWE-502**: Insecure Deserialization
  - **CWE-94**: Code Injection
  - **CWE-918**: SSRF
- **238 unique CWE types** in the dataset

---

## Slide 5: CWE Categories (06_cwe_categories.png)

**Key Points:**
- CWE types grouped into broader weakness categories
- **Injection**, **Authorization/Access Control**, **Memory Safety**, **Path Traversal** are most common
- Useful for prioritizing remediation strategies

---

## Slide 6: Affected Products & Vendors (07, 08)

**Key Points:**
- **TensorFlow** leads with 399 CVEs (data from cvelistV5 affected field)
- Top products: lunary, anything-llm, gradio, mlflow, vllm, cursor, langchain…
- Top vendors: tensorflow, Red Hat, Siemens, lunary-ai, mintplex-labs
- **771 unique products**, **545 unique vendors**

---

## Slide 7: Attack Characteristics (09_cvss_vectors.png, 10_attack_vector.png)

**Key Points:**
- **79.6%** exploitable over **Network**
- **82.8%** have **Low** attack complexity
- **55.8%** require **No** privileges
- **78.1%** require **No** user interaction
- → Most AI vulnerabilities are **easier to exploit remotely**

---

## Slide 8: AI System Categories (11, 12)

**Key Points:**
- **ML Framework/Library**: 433 (16.5%) — TensorFlow, PyTorch…
- **AI Application/Product**: 307 (11.7%)
- **Foundation Model/LLM**: 290 (11.0%)
- **AI Agent/Agentic System**: 185 (7.0%)
- **45.4%** Other/Uncategorized

---

## Slide 9: Ontology Coverage (13_ontology_coverage.png)

**Key Points:**
- CVE ID & CVSS: **100%**
- CWE: **88.2%**
- Product, Vendor, Version: **~90%**
- Data quality supports ontology-based analysis

---

## Slide 10: AI-Only Deep Dives (14–18)

All charts below use the same AI-tagged CVE set (n=2,631).

| Chart | File | Content |
|-------|------|---------|
| **Severity by year** | 14_severity_by_year.png | Stacked bar: Critical/High/Medium/Low per year |
| **Products by High/Critical** | 15_products_high_critical.png | Top 15 products with most High or Critical CVEs |
| **CWE count per CVE** | 16_cwe_count_per_cve.png | How many CVEs have 0, 1, 2, or 3+ CWEs |
| **Top 5 CWE by year** | 17_cwe_top5_by_year.png | Trend of top 5 CWE types over 2020–2026 |
| **Attack vector by severity** | 18_attack_vector_by_severity.png | Network/Local/etc. for High+Critical vs Medium/Low |

---

## Data Sources

- **MISP** (Purdue COMPLiQ): CVE IDs tagged as "AI", event metadata
- **cvelistV5 / CVE API**: CWE (problemTypes), affected products (vendor/product/version), CVSS
- No predefined keyword rules — all distributions from structured fields
