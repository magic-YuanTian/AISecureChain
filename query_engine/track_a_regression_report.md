# Track A regression report

Generated from `query_engine/track_a_report.json` (2026-08-08T12:15:21).
Source: `fixture` · model: `(default)` · docs: 9.

### How to read the tables

| column | meaning |
|---|---|
| **expected** | Gold label (what we scored against) |
| **role** | `required` = must be found (counts for recall); `acceptable` = optional, not an FP if predicted |
| **hit** | Was this gold item matched by ≥1 prediction? `yes` / `no` |
| **predicted** | What the pipeline emitted (one row per prediction) |
| **verdict** | `TP` = matched required gold; `acceptable` = matched acceptable gold; `FP` = matched neither |

Gold rows and prediction rows are listed separately (not zipped). Empty side shown as a note under the table when needed.

Single run — diagnostic baseline, not a stable score.

---

## Overall results

**Micro overall:** P 0.786 · R 0.873 · F1 0.827 · tp=55 fp=15 fn=8

| class | P | R | F1 | tp | fp | fn |
|---|---:|---:|---:|---:|---:|---:|
| Vulnerability | 0.929 | 1.000 | 0.963 | 13 | 1 | 0 |
| Vendor | 1.000 | 0.750 | 0.857 | 9 | 0 | 3 |
| Software | 0.722 | 0.929 | 0.813 | 13 | 5 | 1 |
| Attack | 0.583 | 0.778 | 0.667 | 7 | 5 | 2 |
| Impact | 0.765 | 0.867 | 0.812 | 13 | 4 | 2 |

| # | short name | doc | URL | P | R | F1 |
|---:|---|---|---|---:|---:|---:|
| 1 | ClaudeBleed | `securityweek-vulnerability-in-claude` | https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/ | 1.000 | 1.000 | 1.000 |
| 2 | EchoLeak | `thehackernews-zero-click-ai` | https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html | 0.750 | 0.818 | 0.783 |
| 3 | MCPoison (Dark Reading) | `darkreading-rce-flaw-in` | https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk | 0.667 | 0.800 | 0.727 |
| 4 | Anthropic Git MCP | `theregister-anthropic-quietly-fixed` | https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059 | 0.700 | 1.000 | 0.824 |
| 6 | Bleeding Llama | `securityweek-critical-bug-could` | https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ | 0.750 | 0.600 | 0.667 |
| 7 | Gemini CLI RCE | `theregister-google-fixes-cvss` | https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768 | 1.000 | 1.000 | 1.000 |
| 8 | Comment and Control | `securityweek-claude-code-gemini` | https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ | 0.750 | 1.000 | 0.857 |
| 9 | MCPoison (CPR) | `research-cursor-vulnerability-mcpoison` | https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/ | 0.833 | 0.714 | 0.769 |
| 10 | OX MCP by-design | `thehackernews-anthropic-mcp-design` | https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html | 0.800 | 0.889 | 0.842 |

---

## Per URL

### #1 — ClaudeBleed

- **doc id:** `securityweek-vulnerability-in-claude`
- **URL:** https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:claudebleed` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-39B822` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `LayerX` (LayerX Security) | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Claude Extension for Chrome` (Claude in Chrome, Claude Chrome Extension, Claude extension for Chrome) | required | yes |

| predicted | verdict |
|---|---|
| `Claude extension for Chrome` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Indirect Prompt Injection` | required | yes |
| `Prompt Injection` (Remote Prompt Injection) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Indirect Prompt Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` | required | yes |
| `Information Disclosure` (Information Theft) | required | yes |
| `Instruction Override` (Unauthorized Actions, AI Agent Takeover) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `Data Exfiltration` | TP |
| `Instruction Override` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |

---

### #2 — EchoLeak

- **doc id:** `thehackernews-zero-click-ai`
- **URL:** https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
- **doc micro:** P 0.750 · R 0.818 · F1 0.783

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-32711` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-32711` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Microsoft` | required | yes |
| `GitHub` | required | yes |
| `Aim Security` (Aim) | acceptable | no |
| `CyberArk` | acceptable | no |
| `Invariant Labs` (Invariant) | acceptable | no |
| `Straiker` (Straiker AI Research, STAR) | acceptable | no |
| `Anthropic` | acceptable | no |

| predicted | verdict |
|---|---|
| `Microsoft` | TP |
| `GitHub` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Microsoft 365 Copilot` (M365 Copilot, Copilot) | required | yes |
| `Model Context Protocol` (MCP, Model Context Protocol (MCP)) | required | yes |
| `GitHub MCP integration` (GitHub MCP, github-mcp-server, MCP server) | required | yes |

| predicted | verdict |
|---|---|
| `Microsoft 365 Copilot` | TP |
| `Copilot` | TP |
| `Model Context Protocol` | TP |
| `GitHub MCP integration` | TP |
| `MCP server` | TP |
| `Burp` | FP |
| `sqlmap` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Indirect Prompt Injection` | required | yes |
| `Tool Poisoning` (TPA, Tool Poisoning Attack, Full-Schema Poisoning, FSP, ATPA, Advanced Tool Poisoning) | required | no |
| `DNS Rebinding` (MCP Rebinding, MCP Rebinding Attack) | required | no |
| `Prompt Injection` | acceptable | yes |
| `Phishing` | acceptable | yes |
| `Social Engineering` | acceptable | yes |
| `Command Injection` | acceptable | yes |
| `Toxic Agent Flow` | acceptable | no |

| predicted | verdict |
|---|---|
| `Indirect Prompt Injection` | TP |
| `Command Injection` | acceptable |
| `Phishing` | acceptable |
| `Social Engineering` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` | required | yes |
| `Information Disclosure` | required | yes |
| `Remote Code Execution` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `Data Exfiltration` | TP |
| `Remote Code Execution` | acceptable |
| `Privilege Escalation` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |
| Software | 0.600 | 1.000 | 0.750 | 3 | 2 | 0 | — | `Burp`, `sqlmap` |
| Attack | 1.000 | 0.333 | 0.500 | 1 | 0 | 2 | `Tool Poisoning`, `DNS Rebinding` | — |
| Impact | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 | — | `Privilege Escalation` |

---

### #3 — MCPoison (Dark Reading)

- **doc id:** `darkreading-rce-flaw-in`
- **URL:** https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk
- **doc micro:** P 0.667 · R 0.800 · F1 0.727

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-54136` | required | yes |
| `CVE-2025-54135` | acceptable | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-54136` | TP |
| `CVE-2025-54135` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Cursor` (Anysphere) | required | no |
| `Check Point` (Check Point Research) | acceptable | no |
| `Aim Labs` (Aim, Aim Security) | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `Cursor` (Cursor IDE) | required | yes |
| `Model Context Protocol` (MCP) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Cursor` | TP |
| `MCP` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Supply Chain Attack` | required | yes |
| `Code Injection` | acceptable | yes |
| `Command Injection` | acceptable | no |
| `Prompt Injection` (Indirect Prompt Injection) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Code Injection` | acceptable |
| `Prompt Injection` | acceptable |
| `Data Poisoning` | FP |
| `Supply Chain Attack` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution) | required | yes |
| `Persistence` | acceptable | yes |
| `Credential Theft` | acceptable | yes |
| `Privilege Escalation` | acceptable | yes |
| `Data Exfiltration` | acceptable | yes |
| `Information Disclosure` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `Privilege Escalation` | acceptable |
| `Persistence` | acceptable |
| `Data Exfiltration` | acceptable |
| `Model Manipulation` | FP |
| `Credential Theft` | acceptable |
| `Information Disclosure` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | 0.000 | — | 0 | 0 | 1 | `Cursor` | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Data Poisoning` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Model Manipulation` |

---

### #4 — Anthropic Git MCP

- **doc id:** `theregister-anthropic-quietly-fixed`
- **URL:** https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059
- **doc micro:** P 0.700 · R 1.000 · F1 0.824

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-68145` | required | yes |
| `CVE-2025-68143` | required | yes |
| `CVE-2025-68144` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-68145` | TP |
| `CVE-2025-68143` | TP |
| `CVE-2025-68144` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `Cyata` | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `mcp-server-git` (Git MCP server, Git MCP) | required | yes |
| `Model Context Protocol` (MCP) | acceptable | yes |
| `Filesystem MCP` (Filesystem MCP server) | acceptable | yes |
| `Git` | acceptable | yes |
| `Copilot` (GitHub Copilot) | acceptable | no |
| `Claude` (Claude Code) | acceptable | yes |
| `Cursor` | acceptable | no |

| predicted | verdict |
|---|---|
| `Git MCP server` | TP |
| `mcp-server-git` | TP |
| `Model Context Protocol (MCP)` | acceptable |
| `Claude Code` | acceptable |
| `MCP server` | TP |
| `Filesystem MCP server` | acceptable |
| `Git` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Indirect Prompt Injection` | required | yes |
| `Prompt Injection` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |
| `Indirect Prompt Injection` | TP |
| `Argument Injection` | FP |
| `Code Injection` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` | required | yes |
| `File Overwrite` (Arbitrary File Overwrite) | acceptable | yes |
| `File Deletion` | acceptable | yes |
| `Information Disclosure` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `File Overwrite` | acceptable |
| `Instruction Override` | FP |
| `Information Disclosure` | acceptable |
| `File Deletion` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Argument Injection`, `Code Injection` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Instruction Override` |

---

### #6 — Bleeding Llama

- **doc id:** `securityweek-critical-bug-could`
- **URL:** https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/
- **doc micro:** P 0.750 · R 0.600 · F1 0.667

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2026-7482` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2026-7482` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Ollama` | required | no |
| `Cyera` | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `Ollama` | required | yes |

| predicted | verdict |
|---|---|
| `Ollama` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| *(none in gold)* | — | — |

| predicted | verdict |
|---|---|
| `Model Extraction` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Information Disclosure` | required | yes |
| `Data Exfiltration` | required | no |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | 0.000 | — | 0 | 0 | 1 | `Ollama` | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.000 | — | — | 0 | 1 | 0 | — | `Model Extraction` |
| Impact | 1.000 | 0.500 | 0.667 | 1 | 0 | 1 | `Data Exfiltration` | — |

---

### #7 — Gemini CLI RCE

- **doc id:** `theregister-google-fixes-cvss`
- **URL:** https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:.gemini|headless|workspace trust|environment variable|gemini cli` | required | yes |
| `title_any:yolo|allowlist` | acceptable | yes |
| `GHSA-wpqr-6v78-jr5g` | acceptable | no |

| predicted | verdict |
|---|---|
| `AISC-2026-C6591D` | TP |
| `AISC-2026-A5D658` | TP |
| `AISC-2026-872BB8` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Google` | required | yes |
| `Novee` (Novee Security) | acceptable | no |
| `Pillar Security` (Pillar) | acceptable | no |

| predicted | verdict |
|---|---|
| `Google` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Gemini CLI` (Google Gemini CLI) | required | yes |
| `run-gemini-cli GitHub Action` (run-gemini-cli, Gemini CLI Action) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Gemini CLI` | TP |
| `run-gemini-cli GitHub Action` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Code Injection` | acceptable | yes |
| `Supply Chain Attack` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Supply Chain Attack` | acceptable |
| `Code Injection` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution) | required | yes |
| `Credential Theft` | acceptable | yes |
| `Information Disclosure` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `Arbitrary Code Execution` | TP |
| `Credential Theft` | acceptable |
| `Information Disclosure` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | — | — | — | 0 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #8 — Comment and Control

- **doc id:** `securityweek-claude-code-gemini`
- **URL:** https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
- **doc micro:** P 0.750 · R 1.000 · F1 0.857

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:comment and control` | required | yes |
| `title_any:prompt injection|github comment|pr title|issue comment` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-2C4DA4` | TP |
| `AISC-2026-3BD568` | FP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `Google` | required | yes |
| `GitHub` | required | yes |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |
| `Google` | TP |
| `GitHub` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Claude Code Security Review` (Claude Code) | required | yes |
| `Gemini CLI Action` (Gemini CLI) | required | yes |
| `GitHub Copilot Agent` (Copilot Agent, GitHub Copilot) | required | yes |

| predicted | verdict |
|---|---|
| `Claude Code Security Review` | TP |
| `Gemini CLI Action` | TP |
| `GitHub Copilot Agent` | TP |
| `security review agent` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Indirect Prompt Injection` (Prompt Injection, Comment and Control) | required | yes |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Credential Theft` | required | yes |
| `Information Disclosure` | acceptable | yes |
| `Data Exfiltration` | acceptable | no |
| `Arbitrary Code Execution` (Remote Code Execution) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Arbitrary Code Execution` | acceptable |
| `Credential Theft` | TP |
| `Information Disclosure` | acceptable |
| `Privilege Escalation` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `AISC-2026-3BD568` |
| Vendor | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |
| Software | 0.750 | 1.000 | 0.857 | 3 | 1 | 0 | — | `security review agent` |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Privilege Escalation` |

---

### #9 — MCPoison (CPR)

- **doc id:** `research-cursor-vulnerability-mcpoison`
- **URL:** https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/
- **doc micro:** P 0.833 · R 0.714 · F1 0.769

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-54136` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-54136` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Cursor` (Anysphere) | required | no |
| `Check Point` (Check Point Research) | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `Cursor` (Cursor IDE) | required | yes |
| `Model Context Protocol` (MCP) | required | no |

| predicted | verdict |
|---|---|
| `Cursor IDE` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Code Injection` (Command Injection) | required | yes |
| `Supply Chain Attack` | acceptable | no |
| `Social Engineering` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Trust Bypass` | FP |
| `Command Injection` | TP |
| `Code Injection` | TP |
| `Social Engineering` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution) | required | yes |
| `Persistence` | required | yes |
| `Privilege Escalation` | acceptable | yes |
| `Credential Theft` | acceptable | no |
| `Information Disclosure` | acceptable | no |
| `Data Exfiltration` | acceptable | no |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `Arbitrary Code Execution` | TP |
| `Persistence` | TP |
| `Privilege Escalation` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | 0.000 | — | 0 | 0 | 1 | `Cursor` | — |
| Software | 1.000 | 0.500 | 0.667 | 1 | 0 | 1 | `Model Context Protocol` | — |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Trust Bypass` |
| Impact | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |

---

### #10 — OX MCP by-design

- **doc id:** `thehackernews-anthropic-mcp-design`
- **URL:** https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
- **doc micro:** P 0.800 · R 0.889 · F1 0.842

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-65720` | required | yes |
| `CVE-2026-30623` | required | yes |
| `CVE-2026-40933` | required | yes |
| `CVE-2026-30624` | acceptable | yes |
| `CVE-2026-30618` | acceptable | yes |
| `CVE-2026-33224` | acceptable | yes |
| `CVE-2026-30617` | acceptable | yes |
| `CVE-2026-30625` | acceptable | yes |
| `CVE-2026-30615` | acceptable | yes |
| `CVE-2026-26015` | acceptable | yes |
| `CVE-2025-49596` | acceptable | yes |
| `CVE-2026-22252` | acceptable | yes |
| `CVE-2026-22688` | acceptable | yes |
| `CVE-2025-54994` | acceptable | yes |
| `CVE-2025-54136` | acceptable | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-65720` | TP |
| `CVE-2026-30623` | TP |
| `CVE-2026-30624` | acceptable |
| `CVE-2026-30618` | acceptable |
| `CVE-2026-33224` | acceptable |
| `CVE-2026-30617` | acceptable |
| `CVE-2026-30625` | acceptable |
| `CVE-2026-30615` | acceptable |
| `CVE-2026-26015` | acceptable |
| `CVE-2026-40933` | TP |
| `CVE-2025-49596` | acceptable |
| `CVE-2026-22252` | acceptable |
| `CVE-2026-22688` | acceptable |
| `CVE-2025-54994` | acceptable |
| `CVE-2025-54136` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `OX Security` (OX) | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Model Context Protocol` (MCP, Model Context Protocol (MCP), MCP SDK) | required | yes |
| `LiteLLM` | acceptable | yes |
| `LangChain` | acceptable | yes |
| `LangFlow` | acceptable | yes |
| `Flowise` | acceptable | yes |
| `LettaAI` (Letta) | acceptable | yes |
| `LangBot` | acceptable | yes |
| `GPT Researcher` | acceptable | yes |
| `Agent Zero` | acceptable | yes |
| `Fay Framework` (Fay) | acceptable | yes |
| `Bisheng` | acceptable | yes |
| `Jaaz` | acceptable | yes |
| `Upsonic` | acceptable | yes |
| `Windsurf` | acceptable | yes |
| `DocsGPT` | acceptable | yes |
| `MCP Inspector` | acceptable | yes |
| `LibreChat` | acceptable | yes |
| `WeKnora` | acceptable | yes |
| `@akoskm/create-mcp-server-stdio` (create-mcp-server-stdio) | acceptable | yes |
| `Cursor` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Model Context Protocol` | TP |
| `MCP SDK` | TP |
| `LiteLLM` | acceptable |
| `LangChain` | acceptable |
| `LangFlow` | acceptable |
| `Flowise` | acceptable |
| `LettaAI` | acceptable |
| `LangBot` | acceptable |
| `GPT Researcher` | acceptable |
| `Agent Zero` | acceptable |
| `Fay Framework` | acceptable |
| `Bisheng` | acceptable |
| `Langchain-Chatchat` | acceptable |
| `Jaaz` | acceptable |
| `Upsonic` | acceptable |
| `Windsurf` | acceptable |
| `DocsGPT` | acceptable |
| `Model Context Protocol` | TP |
| `MCP Inspector` | TP |
| `LibreChat` | acceptable |
| `WeKnora` | acceptable |
| `@akoskm/create-mcp-server-stdio` | TP |
| `Cursor` | acceptable |
| `Burp` | FP |
| `sqlmap` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Command Injection` | required | yes |
| `Prompt Injection` (Indirect Prompt Injection) | acceptable | yes |
| `Supply Chain Attack` | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | acceptable |
| `Command Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution) | required | yes |
| `Information Disclosure` | required | yes |
| `Credential Theft` | required | no |
| `Data Exfiltration` | acceptable | no |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `Information Disclosure` | TP |
| `Arbitrary Code Execution` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Burp`, `sqlmap` |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 0.667 | 0.800 | 2 | 0 | 1 | `Credential Theft` | — |

---

## Quick failure themes

1. **Vendor recall:** Cursor (#3, #9), Ollama (#6) not emitted as Vendor.
2. **Attack noise:** Data Poisoning, Model Extraction, Model Manipulation, Trust Bypass, Argument/Code Injection extras.
3. **THN page chrome:** Burp / sqlmap as Software (#2, #10).
4. **Remediation bleed (#8):** second minted vuln + `security review agent`.
5. **Bundle attack recall (#2):** missed Tool Poisoning + DNS Rebinding.
6. **MCP as Software (#9):** required MCP missed.
