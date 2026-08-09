# Extract review — ontology + link-by-link

Source of truth: `extract_pipeline/ontology.py` (`CLASS_HINTS` / `RELATION_HINTS`) + T-Box in `ai_vuln_kb.ttl`.

We go **one URL at a time**: for each class, what the page should yield vs what the preview actually returned.

---

## 1. Classes

| Class | Identity attr | Description (short) | Extract attrs (snake_case) |
|--------|---------------|---------------------|----------------------------|
| Vendor | `name` | Org that produces software/hardware (not threat actors) | `name` |
| Software | `name` (+ vendor in merge) | Concrete named product in the security story | `name`, `is_ai`, `software_type`, `role` |
| SoftwareType | `name` | Category of software (via `isA_softwareType`) | `name` |
| License | `name` | Software license id | `name` |
| Version | `version_string` | Specific version of a product | `version_string` |
| Vulnerability | `vuln_id` | CVE / GHSA / AVID / narrative (may mint `AISC-…`) | `vuln_id`, `title`, `description`, `date_published`, `date_updated`, `cvss_base_score`, `cvss_severity`, `cvss_vector`, `references`, `credit` |
| VulnerabilityType | `id` | Weakness class (usually CWE) | `id`, `description` |
| Attack | `name` | Method / HOW the adversary exploits | `name`, `description` |
| Impact | `name` | Harm / outcome for the victim | `name`, `description` |

---

## 2. Object properties (relations)

| Predicate | Domain → Range | Meaning |
|-----------|----------------|---------|
| `produce` | Vendor → Software | Vendor produces this product |
| `isA_softwareType` | Software → SoftwareType | Product categorisation |
| `hasVersion` | Software → Version | Product has this version |
| `hasLicense` | Version → License | Version ships under license |
| `dependsOn` | Version → Version | Version depends on another version |
| `vulnerableTo` | Version → Vulnerability | Version is vulnerable to this finding |
| `isA_vulnType` | Vulnerability → VulnerabilityType | Finding maps to CWE / weakness |
| `exploits` | Attack → Vulnerability | Attack method abuses this finding |
| `resultsIn` | Vulnerability → Impact | Finding leads to this harm |

---

## 3. Data properties

Extract JSON uses **snake_case**; TTL uses **camelCase** where noted.

| Extract attr | TTL property | Typical class | Type | Required? | Notes |
|--------------|--------------|---------------|------|-----------|-------|
| `name` | `asc:name` | Vendor, Software, SoftwareType, License, Attack, Impact | string | yes (per class) | |
| `is_ai` | `asc:isAI` | Software | boolean | yes | Must always be set |
| `software_type` | *(extract enum → often `isA_softwareType`)* | Software | string enum | no* | *Prompt says always set; not a TTL datatype |
| `role` | *(extract-only)* | Software | string enum | no* | Filter: only `affected` / `tool` kept in KB |
| `version_string` | `asc:versionString` | Version | string | yes | |
| `vuln_id` | `asc:vulnId` | Vulnerability | string | yes* | *null → partial / may mint |
| `title` | `asc:title` | Vulnerability | string | no | |
| `description` | `asc:description` | Vulnerability, Attack, Impact, VulnerabilityType | string | no | |
| `date_published` | `asc:datePublished` | Vulnerability | string (ISO date) | no | |
| `date_updated` | `asc:dateUpdated` | Vulnerability | string (ISO date) | no | |
| `cvss_base_score` | `asc:cvssBaseScore` | Vulnerability | number 0–10 | no | |
| `cvss_severity` | `asc:cvssBaseSeverity` | Vulnerability | string enum | no | |
| `cvss_vector` | `asc:cvssVector` | Vulnerability | string | no | |
| `references` | `asc:references` | Vulnerability | list[string] | no | |
| `credit` | `asc:credit` | Vulnerability | string | no | |
| `id` | *(via VulnerabilityType label / id)* | VulnerabilityType | string | yes | e.g. `CWE-79` |

**In TTL but not in extract `CLASS_HINTS` today:** `asc:effectCategory`, `asc:lifecycleStage`, `asc:recordType`, `asc:riskDomain`, `asc:tags` — ignore for Track A scoring unless we start emitting them.

---

## 4. Enum / controlled values

### `Software.software_type` (exactly one)

| Value | Meaning |
|-------|---------|
| `Application` | End-user product |
| `AI Component` | AI module/plugin inside a larger system |
| `ML Infrastructure` | Training / serving / pipeline platform |
| `Library` | Reusable code package |
| `Agent` | Autonomous AI agent / agentic system |
| `Model` | Foundation or fine-tuned model |
| `Skill` | Specific capability/tool of an AI agent |
| `Database` | Data storage system |
| `Dataset` | Training / evaluation dataset |

### `Software.role` (exactly one)

| Value | Meaning | Kept in KB? |
|-------|---------|-------------|
| `affected` | Vulnerable / attacked / abused system | yes |
| `tool` | Software the attacker uses | yes |
| `defense` | Detection / mitigation product | no |
| `mentioned` | Background, comparison, analogy only | no |

### `Software.is_ai`

| Value |
|-------|
| `true` |
| `false` |

### `Vulnerability.cvss_severity`

| Value |
|-------|
| `LOW` |
| `MEDIUM` |
| `HIGH` |
| `CRITICAL` |

### Preferred `Attack.name` (normalize when one fits)

`Prompt Injection` · `Indirect Prompt Injection` · `Visual Prompt Injection` · `Jailbreak` · `Data Poisoning` · `Model Backdoor` · `Supply Chain Attack` · `Deserialization Attack` · `Code Injection` · `SQL Injection` · `Template Injection` · `ASCII Smuggling` · `Social Engineering` · `Phishing` · `Adversarial Example` · `Model Extraction`

Only invent a new name when none of these fit. Never emit CVSS labels (`Attack Vector`, etc.).

### Preferred `Impact.name` (most specific that fits)

`Remote Code Execution` · `Arbitrary Code Execution` · `Data Exfiltration` · `Information Disclosure` · `System Prompt Disclosure` · `Memory Poisoning` · `Credential Theft` · `Privilege Escalation` · `Denial of Service` · `Financial Loss` · `Model Theft` · `Model Manipulation` · `Malware Delivery` · `Instruction Override` · `Misinformation` · `Persistence` · `Harmful Content Generation`

Avoid vague `Unauthorized Access` / `Unauthorized Actions` unless nothing more specific is stated.

---

## 5. Link-by-link review

Template (copy per URL):

```md
### N. <short name>

**URL:** …

| Class | Should have got | Actually got | Score |
|-------|-----------------|--------------|-------|
| Vulnerability | | | |
| Vendor | | | |
| Software | | | |
| Attack | | | |
| Impact | | | |
| Version | | | |
| … | | | |

**Notes:**
```

### Queue

| # | Name | URL | Reviewed? |
|---|------|-----|-----------|
| 1 | ClaudeBleed | https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/ | |
| 2 | EchoLeak | https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html | |
| 3 | MCPoison (Dark Reading) | https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk | |
| 4 | Anthropic Git MCP | https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059 | |
| 5 | Semantic Kernel | https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/ | |
| 6 | Bleeding Llama | https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ | |
| 7 | Gemini CLI | https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768 | |
| 8 | Comment and Control | https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ | |
| 9 | MCPoison (CPR) | https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/ | |
| 10 | MCP by design (OX) | https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html | |

<!-- Start filling below when ready -->
