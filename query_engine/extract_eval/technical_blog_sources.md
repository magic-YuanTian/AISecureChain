# Technical Blog and Security Source URL Formats

This file lists reusable URL formats for AISecureChain extraction. The goal is not to store one-off URLs, but to define source patterns that can generate many candidate pages for crawling, extraction, freshness checking, and database merge.

## Placeholder Format

Use these placeholders consistently:

| Placeholder | Meaning | Example Shape |
|---|---|---|
| `{YYYY}` | Four-digit year | `2024` |
| `{MM}` | Two-digit month | `06` |
| `{DD}` | Two-digit day | `11` |
| `{slug}` | Article slug, usually lowercase words joined by hyphens | `exploiting-ml-models-with-pickle-file-attacks-part-1` |
| `{cve_id}` | Full CVE identifier | `CVE-2024-5184` |
| `{ghsa_id}` | Full GitHub Security Advisory identifier | `GHSA-xxxx-yyyy-zzzz` |
| `{avid_id}` | Full AVID identifier | `avid-2023-v013` |
| `{technique_id}` | MITRE ATLAS technique ID | `AML.T0051.000` |
| `{repo_owner}` | GitHub organization or user | `langchain-ai` |
| `{repo_name}` | GitHub repository | `langchain` |
| `{content_type}` | Site-specific content bucket | `blog`, `articles` |
| `{section}` | News site section/category | `vulnerabilities-threats` |

## Verified Source Formats

These are the most useful targets for the current ontology because they usually contain vendors, software names, vulnerability types, attack descriptions, affected AI systems, or public identifiers.

Verification means the example URL was tested with `crawl4ai`, produced non-empty markdown, did not look like a 404 page, and contained security/AI keywords. `MD chars` is the crawled markdown length.

| Priority | Source | URL Format | Verified Example | MD chars | Best For |
|---|---|---|---|---:|---|
| 1 | NVD CVE Detail | `https://nvd.nist.gov/vuln/detail/{cve_id}` | `https://nvd.nist.gov/vuln/detail/CVE-2024-5184` | 12,440 | Public CVEs, CVSS, affected products, CWE |
| 1 | GitHub Security Advisory | `https://github.com/advisories/{ghsa_id}` | `https://github.com/advisories/GHSA-7gfq-f96f-g85j` | 15,901 | Package vulnerabilities, ecosystems, patched versions, CVEs |
| 1 | GitHub Repo Advisories | `https://github.com/{repo_owner}/{repo_name}/security/advisories/{ghsa_id}` | `https://github.com/langchain-ai/langchain/security/advisories/GHSA-7gfq-f96f-g85j` | 11,211 | Project-specific advisories with more context |
| 1 | AVID Database | `https://avidml.org/database/{avid_id}/` | `https://avidml.org/database/avid-2023-v013/` | 3,197 | AI-specific incidents, ML failures, AI vulnerability records |
| 1 | MITRE ATLAS Technique | `https://atlas.mitre.org/techniques/{technique_id}` | `https://atlas.mitre.org/techniques/AML.T0051` | 24,793 | AI attack taxonomy, tactics, techniques |
| 2 | Embrace The Red Blog | `https://embracethered.com/blog/posts/{YYYY}/{slug}/` | `https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/` | 13,180 | Prompt injection, Copilot, ChatGPT, Gemini, data exfiltration |
| 2 | Trail of Bits Blog | `https://blog.trailofbits.com/{YYYY}/{MM}/{DD}/{slug}/` | `https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/` | 15,252 | ML model file attacks, pickle risks, supply chain vulnerabilities |
| 2 | Lakera Blog | `https://www.lakera.ai/blog/{slug}` | `https://www.lakera.ai/blog/visual-prompt-injections` | 23,080 | Prompt injection, jailbreaks, visual attacks, LLM threat taxonomy |
| 2 | HiddenLayer Innovation Hub | `https://hiddenlayer.com/innovation-hub/{slug}/` | `https://hiddenlayer.com/innovation-hub/shadowlogic/` | 42,694 | Model backdoors, AI supply chain, model threat research |
| 2 | Protect AI Blog | `https://protectai.com/blog/{slug}` | `https://protectai.com/blog/announcing-modelscan` | 47,436 | MLSecOps, ModelScan, AI security tooling, vulnerability reports |
| 3 | Snyk Articles/Blog | `https://snyk.io/{content_type}/{slug}/` | `https://snyk.io/articles/understanding-prompt-injection-techniques-challenges-and-risks/` | 26,891 | Developer security, LLM app security, supply chain |
| 3 | Palo Alto Unit 42 Blog | `https://unit42.paloaltonetworks.com/{slug}/` | `https://unit42.paloaltonetworks.com/autonomous-ai-cloud-attacks/` | 82,861 | Threat research, cloud/AI security campaigns |
| 3 | Wiz Blog | `https://www.wiz.io/blog/{slug}` | `https://www.wiz.io/blog/wiz-and-hugging-face-address-risks-to-ai-infrastructure` | 30,534 | Cloud AI security, AI infrastructure, model supply chain |
| 3 | Microsoft Security Blog | `https://www.microsoft.com/en-us/security/blog/{YYYY}/{MM}/{DD}/{slug}/` | `https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/` | 43,713 | Microsoft Copilot, Azure AI, enterprise security context |
| 3 | Google Security Blog | `https://security.googleblog.com/{YYYY}/{MM}/{slug}.html` | `https://security.googleblog.com/2026/04/ai-threats-in-wild-current-state-of.html` | 32,660 | Google AI security, prompt injection, Gemini/Chrome agentic systems |
| 3 | OpenAI Blog | `https://openai.com/index/{slug}/` | `https://openai.com/index/ai-agent-link-safety/` | 12,939 | Model safety, AI-agent data exfiltration, system cards |
| 3 | Anthropic News | `https://www.anthropic.com/news/{slug}` | `https://www.anthropic.com/news/detecting-countering-misuse-aug-2025` | 18,502 | Model misuse, Claude threat intelligence, safety reports |
| 3 | Hugging Face Blog | `https://huggingface.co/blog/{slug}` | `https://huggingface.co/blog/safetensors-security-audit` | 12,363 | Hub security, model supply chain, safetensors, malware scanning |
| 4 | Dark Reading | `https://www.darkreading.com/{section}/{slug}` | `https://www.darkreading.com/vulnerabilities-threats/every-old-vulnerability-ai-vulnerability` | 28,537 | Secondary reporting on AI vulnerabilities |
| 4 | The Hacker News | `https://thehackernews.com/{YYYY}/{MM}/{slug}.html` | `https://thehackernews.com/2026/03/openclaw-ai-agent-flaws-could-enable.html` | 22,824 | Secondary reporting, fast triage source |
| 4 | BleepingComputer | `https://www.bleepingcomputer.com/news/security/{slug}/` | `https://www.bleepingcomputer.com/news/security/hackers-hijack-exposed-llm-endpoints-in-bizarre-bazaar-operation/` | 26,623 | Secondary reporting, breaches and exploitation |

## Recommended System Schema

Use this normalized format if these sources are added to the UI/database as source templates:

```yaml
sources:
  - id: nvd-cve-detail
    name: NVD CVE Detail
    source_type: advisory_database
    url_pattern: "https://nvd.nist.gov/vuln/detail/{cve_id}"
    placeholder_fields: ["cve_id"]
    discovery:
      method: cve_id_feed
      inputs: ["CVE IDs from NVD feed", "CVE IDs found in blogs/advisories"]
    extraction_profile: cve_detail
    expected_entities: ["Vulnerability", "Vendor", "Software", "Version", "VulnerabilityType"]
    merge_confidence: high

  - id: github-advisory
    name: GitHub Security Advisory
    source_type: advisory_database
    url_pattern: "https://github.com/advisories/{ghsa_id}"
    placeholder_fields: ["ghsa_id"]
    discovery:
      method: advisory_search
      inputs: ["GHSA IDs", "package names", "ecosystem filters"]
    extraction_profile: advisory_detail
    expected_entities: ["Vulnerability", "Software", "Version", "VulnerabilityType"]
    merge_confidence: high

  - id: embracethered-blog
    name: Embrace The Red Blog
    source_type: technical_blog
    url_pattern: "https://embracethered.com/blog/posts/{YYYY}/{slug}/"
    placeholder_fields: ["YYYY", "slug"]
    discovery:
      method: rss_or_index
      filters: ["prompt injection", "Copilot", "ChatGPT", "Gemini", "data exfiltration"]
    extraction_profile: research_writeup
    expected_entities: ["Vulnerability", "Vendor", "Software", "VulnerabilityType"]
    merge_confidence: medium

  - id: trailofbits-blog
    name: Trail of Bits Blog
    source_type: technical_blog
    url_pattern: "https://blog.trailofbits.com/{YYYY}/{MM}/{DD}/{slug}/"
    placeholder_fields: ["YYYY", "MM", "DD", "slug"]
    discovery:
      method: rss_or_index
      filters: ["ML", "AI", "model", "pickle", "safetensors", "supply chain"]
    extraction_profile: research_writeup
    expected_entities: ["Vulnerability", "Vendor", "Software", "VulnerabilityType"]
    merge_confidence: medium

  - id: lakera-blog
    name: Lakera Blog
    source_type: technical_blog
    url_pattern: "https://www.lakera.ai/blog/{slug}"
    placeholder_fields: ["slug"]
    discovery:
      method: blog_index
      filters: ["prompt injection", "jailbreak", "visual prompt injection", "LLM security"]
    extraction_profile: taxonomy_or_research_writeup
    expected_entities: ["Vendor", "Software", "VulnerabilityType", "Vulnerability"]
    merge_confidence: medium

  - id: hiddenlayer-hub
    name: HiddenLayer Innovation Hub
    source_type: technical_blog
    url_pattern: "https://hiddenlayer.com/innovation-hub/{slug}/"
    placeholder_fields: ["slug"]
    discovery:
      method: blog_index
      filters: ["model backdoor", "AI supply chain", "model attack", "LLM"]
    extraction_profile: research_writeup
    expected_entities: ["Vendor", "Software", "VulnerabilityType", "Vulnerability"]
    merge_confidence: medium
```

## Extraction Profiles

Use different expectations for different source types.

| Profile | Source Type | Should Usually Extract | Notes |
|---|---|---|---|
| `cve_detail` | NVD/CVE pages | `Vulnerability.vuln_id`, `CVSS`, `CWE`, affected software/vendor/version | Highest merge confidence |
| `advisory_detail` | GitHub/GHSA/vendor advisories | advisory ID, package/software, patched versions, CVE if present | Good for exact dedup |
| `ai_incident_record` | AVID records | AVID ID, affected AI system, vulnerability/incident type, impact | AI-specific but may not map to CVE |
| `taxonomy` | MITRE ATLAS, OWASP LLM Top 10, Lakera taxonomy pages | `VulnerabilityType`, attack technique, mitigation terms | Do not force `Vulnerability.vuln_id` |
| `research_writeup` | Technical blogs | named finding, vendor, software/system, attack type, CWE if present | Often partial, but valuable context |
| `secondary_reporting` | news/security media | CVE/advisory references, affected vendor/software, narrative summary | Use as same_as/context, prefer primary source for merge |

## Recommended Crawling Logic

1. Discover candidate URLs from RSS, sitemap, blog index, GitHub advisory search, or CVE/advisory IDs.
2. Before LLM extraction, run a crawl quality check:
   - markdown length should usually be `> 1500`
   - title/body should not contain `404`, `Page Not Found`, or mostly navigation text
   - count security keywords such as `CVE`, `CWE`, `prompt injection`, `jailbreak`, `model`, `LLM`, `exfiltration`, `vulnerability`
3. Pick extraction profile from the source template.
4. Run extraction with `skip_db=True` first and cache the preview.
5. Merge only after user review or confidence threshold passes.
6. During merge, run deduplication by:
   - exact public ID (`CVE`, `GHSA`, `AVID`)
   - normalized vendor + software + vulnerability title
   - same incident described from multiple perspectives, linked by `same_as`

## Practical Recommendation

For the next iteration of AISecureChain, start with these source templates:

1. `nvd-cve-detail`
2. `github-advisory`
3. `avid-database`
4. `embracethered-blog`
5. `trailofbits-blog`
6. `lakera-blog`
7. `hiddenlayer-hub`
8. `mitre-atlas-technique`

This gives the system a strong balance:

- NVD/GitHub/AVID provide precise identifiers and merge anchors.
- Embrace The Red, Trail of Bits, Lakera, and HiddenLayer provide rich AI-security technical context.
- MITRE ATLAS provides taxonomy-level concepts that improve ontology coverage.
