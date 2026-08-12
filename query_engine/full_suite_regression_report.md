# Full suite regression report

Generated from `query_engine/track_a_report.json` (2026-08-11T14:10:42).
Source: `fixture` · model: `(default)` · docs: 31.

Merged suite (prior fixtures + Track A). Single run — diagnostic baseline.

### How to read the tables

| column | meaning |
|---|---|
| **expected** | Gold label (what we scored against) |
| **role** | `required` = must be found (counts for recall); `acceptable` = optional, not an FP if predicted |
| **hit** | Was this gold item matched by ≥1 prediction? `yes` / `no` |
| **predicted** | What the pipeline emitted (one row per prediction) |
| **verdict** | `TP` = matched required gold; `acceptable` = matched acceptable gold; `FP` = matched neither |

Gold rows and prediction rows are listed separately (not zipped).

---

## Overall results

**Micro overall:** P 0.647 · R 0.887 · F1 0.749 · tp=134 fp=73 fn=17

| class | P | R | F1 | tp | fp | fn |
|---|---:|---:|---:|---:|---:|---:|
| Vulnerability | 0.744 | 0.935 | 0.829 | 29 | 10 | 2 |
| Vendor | 0.739 | 0.850 | 0.791 | 17 | 6 | 3 |
| Software | 0.659 | 0.964 | 0.783 | 27 | 14 | 1 |
| Attack | 0.562 | 0.818 | 0.667 | 27 | 21 | 6 |
| Impact | 0.607 | 0.872 | 0.716 | 34 | 22 | 5 |
| VulnerabilityType * | 0.000 | — | — | 0 | 3 | 0 |

\* informational — excluded from micro overall

| # | short name | doc | URL | P | R | F1 |
|---:|---|---|---|---:|---:|---:|
| 1 | thehackernews new chrome vulnerability | `thehackernews-new-chrome-vulnerability` | https://thehackernews.com/2026/03/new-chrome-vulnerability-let-malicious.html | 0.538 | 0.875 | 0.667 |
| 2 | research caught in the | `research-caught-in-the` | https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ | 0.538 | 1.000 | 0.700 |
| 3 | latimes hacker used anthropic | `latimes-hacker-used-anthropic` | https://www.latimes.com/business/story/2026-02-26/hacker-used-anthropics-claude-ai-to-steal-mexican-government-data | 0.667 | 0.800 | 0.727 |
| 4 | cyberscoop uk cyber agency | `cyberscoop-uk-cyber-agency` | https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/ | 0.000 | 0.000 | — |
| 5 | unit42 investigating llm jailbreaking | `unit42-investigating-llm-jailbreaking` | https://unit42.paloaltonetworks.com/jailbreaking-generative-ai-web-products/ | 1.000 | 1.000 | 1.000 |
| 6 | blog nation state threat | `blog-nation-state-threat` | https://blog.knowbe4.com/nation-state-threat-actors-incorporate-ai-to-streamline-attacks | 0.833 | 1.000 | 0.909 |
| 7 | neuraltrust ai driven supply | `neuraltrust-ai-driven-supply` | https://neuraltrust.ai/blog/ai-driven-supply-chain-attacks | 0.333 | 1.000 | 0.500 |
| 8 | welivesecurity this month in | `welivesecurity-this-month-in` | https://www.welivesecurity.com/en/videos/month-security-tony-anscombe-february-2026/ | 0.500 | 0.333 | 0.400 |
| 9 | adversa top ai security | `adversa-top-ai-security` | https://adversa.ai/blog/adversa-ai-unveils-explosive-2025-ai-security-incidents-report-revealing-how-generative-and-agentic-ai-are-already-under-attack/ | 0.857 | 1.000 | 0.923 |
| 10 | blog agentic ai the | `blog-agentic-ai-the` | https://blog.barracuda.com/2026/02/27/agentic-ai--the-2026-threat-multiplier-reshaping-cyberattacks | 0.333 | 1.000 | 0.500 |
| 11 | blog owasp top 10 | `blog-owasp-top-10` | https://blog.barracuda.com/2024/11/20/owasp-top-10-risks-large-language-models-2025-updates | 0.429 | 1.000 | 0.600 |
| 12 | obsidiansecurity prompt injection attacks | `obsidiansecurity-prompt-injection-attacks` | https://www.obsidiansecurity.com/blog/prompt-injection | 0.833 | 1.000 | 0.909 |
| 13 | linkedin kicking off the | `linkedin-kicking-off-the` | https://www.linkedin.com/pulse/kicking-off-2026-update-owasp-top-10-llm-applications-steve-wilson-ww6nc | 0.000 | — | — |
| 14 | nvd emailgpt prompt injection | `nvd-emailgpt-prompt-injection` | https://nvd.nist.gov/vuln/detail/CVE-2024-5184 | 1.000 | 1.000 | 1.000 |
| 15 | nvd langchain palchain code | `nvd-langchain-palchain-code` | https://nvd.nist.gov/vuln/detail/CVE-2023-36258 | 1.000 | 1.000 | 1.000 |
| 16 | github langchain ssrf advisory | `github-langchain-ssrf-advisory` | https://github.com/advisories/GHSA-7gfq-f96f-g85j | 1.000 | 0.500 | 0.667 |
| 17 | github langchain sql injection | `github-langchain-sql-injection` | https://github.com/advisories/GHSA-56xg-wfcc-g829 | 1.000 | 1.000 | 1.000 |
| 18 | embracethered chatgpt hacking memories | `embracethered-chatgpt-hacking-memories` | https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/ | 0.556 | 1.000 | 0.714 |
| 19 | embracethered copilot ascii smuggling | `embracethered-copilot-ascii-smuggling` | https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/ | 0.500 | 1.000 | 0.667 |
| 20 | blog pickle file attacks | `blog-pickle-file-attacks` | https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/ | 0.300 | 1.000 | 0.462 |
| 21 | hiddenlayer shadowlogic backdoor technique | `hiddenlayer-shadowlogic-backdoor-technique` | https://hiddenlayer.com/innovation-hub/shadowlogic/ | 0.429 | 1.000 | 0.600 |
| 22 | lakera visual prompt injections | `lakera-visual-prompt-injections` | https://www.lakera.ai/blog/visual-prompt-injections | 0.429 | 1.000 | 0.600 |
| 23 | ClaudeBleed | `securityweek-vulnerability-in-claude` | https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/ | 1.000 | 1.000 | 1.000 |
| 24 | EchoLeak | `thehackernews-zero-click-ai` | https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html | 0.750 | 0.818 | 0.783 |
| 25 | MCPoison (Dark Reading) | `darkreading-rce-flaw-in` | https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk | 0.571 | 0.800 | 0.667 |
| 26 | Anthropic Git MCP | `theregister-anthropic-quietly-fixed` | https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059 | 0.778 | 1.000 | 0.875 |
| 27 | Bleeding Llama | `securityweek-critical-bug-could` | https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ | 0.750 | 0.600 | 0.667 |
| 28 | Gemini CLI RCE | `theregister-google-fixes-cvss` | https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768 | 1.000 | 1.000 | 1.000 |
| 29 | Comment and Control | `securityweek-claude-code-gemini` | https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ | 0.727 | 0.889 | 0.800 |
| 30 | MCPoison (CPR) | `research-cursor-vulnerability-mcpoison` | https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/ | 0.833 | 0.714 | 0.769 |
| 31 | OX MCP by-design | `thehackernews-anthropic-mcp-design` | https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html | 0.800 | 0.889 | 0.842 |

---

## Per URL

### #1 — thehackernews new chrome vulnerability

- **doc id:** `thehackernews-new-chrome-vulnerability`
- **URL:** https://thehackernews.com/2026/03/new-chrome-vulnerability-let-malicious.html
- **doc micro:** P 0.538 · R 0.875 · F1 0.667

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2026-0628` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2026-0628` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Google` | required | yes |
| `Palo Alto Networks` (Unit 42) | acceptable | no |

| predicted | verdict |
|---|---|
| `Google` | TP |
| `Microsoft` | FP |
| `Salesforce` | FP |

**Software**

| expected | role | hit |
|---|---|---|
| `Google Chrome` (Chrome) | required | yes |
| `Gemini` (Gemini Live, Gemini Live panel, Gemini panel) | required | yes |

| predicted | verdict |
|---|---|
| `Google Chrome` | TP |
| `Gemini Live panel` | TP |
| `Chrome` | TP |
| `Gemini` | TP |
| `Gemini panel` | TP |
| `Microsoft Teams` | FP |
| `Salesforce` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Malicious Browser Extension` (Malicious Extension, Crafted Extension, Script Injection, JavaScript Injection) | required | no |
| `Indirect Prompt Injection` (Prompt Injection, Hidden Prompt) | acceptable | no |
| `Glic Jack` | acceptable | no |

| predicted | verdict |
|---|---|
| `Social Engineering` | FP |
| `Code Injection` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Privilege Escalation` (Escalate Privileges) | required | yes |
| `Remote Code Execution` (Arbitrary Code Execution, Code Execution) | required | yes |
| `Data Exfiltration` (Data Access, Information Disclosure, Sensitive Data Access, Local File Access) | required | yes |
| `Unauthorized Access` (Device Access, Camera Access, Microphone Access) | acceptable | no |

| predicted | verdict |
|---|---|
| `Privilege Escalation` | TP |
| `Data Exfiltration` | TP |
| `Arbitrary Code Execution` | TP |
| `Information Disclosure` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Microsoft`, `Salesforce` |
| Software | 0.500 | 1.000 | 0.667 | 2 | 2 | 0 | — | `Microsoft Teams`, `Salesforce` |
| Attack | 0.000 | 0.000 | — | 0 | 2 | 1 | `Malicious Browser Extension` | `Social Engineering`, `Code Injection` |
| Impact | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |

---

### #2 — research caught in the

- **doc id:** `research-caught-in-the`
- **URL:** https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
- **doc micro:** P 0.538 · R 1.000 · F1 0.700

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2025-59536` | required | yes |
| `CVE-2026-21852` | required | yes |
| `GHSA-ph6w-f82w-28w6` | acceptable | yes |

| predicted | verdict |
|---|---|
| `CVE-2025-59536` | TP |
| `CVE-2026-21852` | TP |
| `GHSA-ph6w-f82w-28w6` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `Check Point` (Check Point Research) | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Claude Code` | required | yes |
| `Model Context Protocol` (MCP) | acceptable | yes |
| `Claude Workspaces` (Workspaces, Claude's Workspaces) | acceptable | yes |
| `Code Execution Tool` | acceptable | yes |
| `mitmproxy` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Claude Code` | TP |
| `mitmproxy` | acceptable |
| `Claude` | TP |
| `Claude’s code execution tool` | TP |
| `MCP` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Supply Chain Attack` (Malicious Repository, Malicious Project Configuration, Malicious Configuration, Malicious Pull Request, Configuration-Based Attack, Configuration Based Attack) | required | yes |
| `MCP Consent Bypass` (User Consent Bypass, Consent Bypass) | acceptable | no |
| `Malicious Hooks` (Untrusted Hooks, Hook Injection, Untrusted Project Hooks) | acceptable | no |
| `Honeypot Repository` | acceptable | no |
| `Internal Enterprise Repository` | acceptable | no |
| `Code Injection` (Command Injection) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Code Injection` | acceptable |
| `Indirect Prompt Injection` | FP |
| `Command Injection` | acceptable |
| `Social Engineering` | FP |
| `Prompt Injection` | FP |
| `Supply Chain Attack` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (RCE, Arbitrary Command Execution, Reverse Shell, Code Execution) | required | yes |
| `API Key Exfiltration` (API Token Exfiltration, Credential Theft, API Key Theft, Credential Exfiltration, API Key Interception) | required | yes |
| `Billing Fraud` (API Credit Exhaustion, Financial Loss, Exhaust API Credits) | acceptable | yes |
| `Data Exfiltration` (Information Disclosure, Workspace File Access) | acceptable | yes |
| `Access Sensitive Files` (Sensitive File Access, Unauthorized Access) | acceptable | no |
| `Delete Critical Files` (File Deletion, Data Destruction) | acceptable | no |
| `Upload Arbitrary Files` (Arbitrary File Upload, Workspace Poisoning, Poison Workspace) | acceptable | no |

| predicted | verdict |
|---|---|
| `Remote Code Execution` | TP |
| `Credential Theft` | TP |
| `Instruction Override` | FP |
| `Information Disclosure` | acceptable |
| `Privilege Escalation` | FP |
| `Financial Loss` | acceptable |
| `Data Exfiltration` | acceptable |
| `Denial of Service` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.250 | 1.000 | 0.400 | 1 | 3 | 0 | — | `Indirect Prompt Injection`, `Social Engineering`, `Prompt Injection` |
| Impact | 0.400 | 1.000 | 0.571 | 2 | 3 | 0 | — | `Instruction Override`, `Privilege Escalation`, `Denial of Service` |

---

### #3 — latimes hacker used anthropic

- **doc id:** `latimes-hacker-used-anthropic`
- **URL:** https://www.latimes.com/business/story/2026-02-26/hacker-used-anthropics-claude-ai-to-steal-mexican-government-data
- **doc micro:** P 0.667 · R 0.800 · F1 0.727

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:jailbreak|guardrail|misuse|weaponiz|bypass|data breach|data theft|steal|claude|cyberattack|exploit` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-FC5D6C` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Anthropic` | required | yes |
| `OpenAI` | acceptable | yes |
| `Gambit Security` (Gambit) | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic` | TP |
| `OpenAI` | acceptable |
| `Google` | FP |

**Software**

| expected | role | hit |
|---|---|---|
| `Claude` (Claude AI, Claude Opus 4.6) | required | yes |
| `ChatGPT` | acceptable | no |

| predicted | verdict |
|---|---|
| `Claude` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Jailbreak` (Jailbreaking, Guardrail Bypass) | required | yes |
| `Prompt Injection` | acceptable | no |
| `Social Engineering` | acceptable | no |
| `Cyber Espionage` (AI-orchestrated cyber-espionage, Cyberespionage) | acceptable | no |
| `Penetration Testing` | acceptable | no |

| predicted | verdict |
|---|---|
| `Jailbreak` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` (Data Theft, Data Breach, Information Theft, Sensitive Data Theft) | required | no |
| `Credential Theft` (Credential Compromise) | acceptable | no |
| `Misuse for Cyberattacks` (AI Weaponization, Malware Generation, Exploit Generation) | acceptable | no |
| `Unauthorized Access` (System Compromise, Identity Compromise) | acceptable | no |

| predicted | verdict |
|---|---|
| `Information Disclosure` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Google` |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.000 | 0.000 | — | 0 | 1 | 1 | `Data Exfiltration` | `Information Disclosure` |

---

### #4 — cyberscoop uk cyber agency

- **doc id:** `cyberscoop-uk-cyber-agency`
- **URL:** https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/
- **doc micro:** P 0.000 · R 0.000 · F1 —

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection` | required | no |

| predicted | verdict |
|---|---|
| `AISC-2026-B53AED` | FP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `OpenAI` (Open AI) | acceptable | yes |
| `Anthropic` | acceptable | yes |
| `NCSC` (National Cyber Security Centre) | acceptable | no |

| predicted | verdict |
|---|---|
| `OpenAI` | acceptable |
| `Anthropic` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `ChatGPT` | acceptable | yes |
| `Claude` | acceptable | no |

| predicted | verdict |
|---|---|
| `Anthropic models` | FP |
| `ChatGPT` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` | required | no |
| `Jailbreak` (Jailbreaking) | acceptable | yes |
| `Indirect Prompt Injection` | acceptable | no |

| predicted | verdict |
|---|---|
| `Jailbreak` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (RCE, Code Execution) | acceptable | no |
| `Data Leakage` (Data Exfiltration, Information Disclosure) | acceptable | no |
| `Guardrail Bypass` | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.000 | 0.000 | — | 0 | 1 | 1 | `title_any:prompt injection` | `AISC-2026-B53AED` |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 0.000 | — | — | 0 | 1 | 0 | — | `Anthropic models` |
| Attack | — | 0.000 | — | 0 | 0 | 1 | `Prompt Injection` | — |
| Impact | — | — | — | 0 | 0 | 0 | — | — |

---

### #5 — unit42 investigating llm jailbreaking

- **doc id:** `unit42-investigating-llm-jailbreaking`
- **URL:** https://unit42.paloaltonetworks.com/jailbreaking-generative-ai-web-products/
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:jailbreak` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-7AE8B4` | TP |
| `AISC-2026-AA1B01` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Palo Alto Networks` (Unit 42) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Palo Alto Networks` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| *(none in gold)* | — | — |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Attack**

| expected | role | hit |
|---|---|---|
| `Jailbreak` (Jailbreaking, LLM Jailbreak) | required | yes |
| `Prompt Injection` | acceptable | yes |
| `Repeated Token Attack` | acceptable | yes |
| `Storytelling Attack` (Storytelling) | acceptable | yes |
| `Do Anything Now` (DAN) | acceptable | yes |
| `Multi-turn Jailbreak` | acceptable | yes |
| `Single-turn Jailbreak` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Jailbreak` | TP |
| `Repeated Token Attack` | acceptable |
| `Storytelling` | acceptable |
| `Do Anything Now (DAN)` | acceptable |
| `Prompt Injection` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Leakage` (Training Data Extraction, Training Data Leakage, Data Leak, Sensitive Information Disclosure, Sensitive Information Extraction, Training Data Disclosure) | required | yes |
| `System Prompt Disclosure` (System Prompt Leakage, System Prompt Extraction) | acceptable | yes |
| `Harmful Content Generation` (Harmful Content, Malware Generation, Unsafe Content, Malware Delivery) | acceptable | yes |
| `PII Disclosure` (PII Leakage) | acceptable | no |
| `Safety Violation` (AI Safety Violation) | acceptable | no |
| `Self-harm` | acceptable | no |
| `Hateful Content` | acceptable | yes |
| `Indiscriminate Weapons` | acceptable | no |
| `Criminal Activity` | acceptable | no |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `System Prompt Disclosure` | acceptable |
| `Harmful Content Generation` | acceptable |
| `Malware Generation` | acceptable |
| `Hateful Content Generation` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #6 — blog nation state threat

- **doc id:** `blog-nation-state-threat`
- **URL:** https://blog.knowbe4.com/nation-state-threat-actors-incorporate-ai-to-streamline-attacks
- **doc micro:** P 0.833 · R 1.000 · F1 0.909

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:guardrail|abuse|misuse|ai|bypass|phishing` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-342610` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Google` | required | yes |
| `OpenAI` | acceptable | no |
| `Microsoft` | acceptable | no |
| `DeepSeek` | acceptable | no |
| `xAI` | acceptable | no |
| `KnowBe4` | acceptable | no |

| predicted | verdict |
|---|---|
| `Google` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Gemini` | required | yes |
| `ChatGPT` | acceptable | yes |
| `Copilot` (CoPilot, Microsoft Copilot) | acceptable | yes |
| `DeepSeek` | acceptable | yes |
| `Grok` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Gemini` | TP |
| `ChatGPT` | acceptable |
| `CoPilot` | acceptable |
| `DeepSeek` | acceptable |
| `Grok` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Social Engineering` (Phishing, ClickFix, Rapport-building Phishing) | required | yes |
| `Guardrail Bypass` (Safety Guardrail Bypass) | acceptable | no |
| `Prompt Injection` | acceptable | yes |
| `Jailbreak` (Jailbreaking) | acceptable | no |

| predicted | verdict |
|---|---|
| `ClickFix` | TP |
| `Prompt Injection` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Malware Delivery` (Malware Distribution, Malware Deployment, Malware Installation, Malware) | required | yes |
| `Credential Theft` (Account Compromise) | acceptable | no |
| `Reconnaissance` | acceptable | no |

| predicted | verdict |
|---|---|
| `Malware Delivery` | TP |
| `Social Engineering` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Social Engineering` |

---

### #7 — neuraltrust ai driven supply

- **doc id:** `neuraltrust-ai-driven-supply`
- **URL:** https://neuraltrust.ai/blog/ai-driven-supply-chain-attacks
- **doc micro:** P 0.333 · R 1.000 · F1 0.500

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:supply chain|poison|deepfake|malware` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-AA03B7` | TP |
| `AISC-2026-0C2F27` | FP |
| `AISC-2026-4706F7` | FP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `NeuralTrust` | acceptable | no |
| `Cybersecurity Ventures` | acceptable | no |
| `World Economic Forum` | acceptable | no |
| `SolarWinds` | acceptable | no |
| `Kaseya` | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| *(none in gold)* | — | — |

| predicted | verdict |
|---|---|
| `Logistics SaaS platform` | FP |
| `Machine-learning system for firmware verification` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Data Poisoning` (Model Poisoning, Model Corruption, Training Data Poisoning, AI Model Poisoning) | required | yes |
| `Supply Chain Attack` (AI-Driven Supply Chain Attack) | acceptable | yes |
| `Deepfake Vendor Impersonation` (Deepfake Impersonation, Deepfake) | acceptable | no |
| `AI-Generated Malware` (AI Malware, Self-Learning Malware) | acceptable | no |
| `Automated Reconnaissance` (Supply Chain Reconnaissance) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Supply Chain Attack` | acceptable |
| `Automated Reconnaissance` | acceptable |
| `Data Poisoning` | TP |
| `Prompt Injection` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` (Data Loss, Data Theft, Credential Exfiltration) | required | yes |
| `Operational Disruption` (Service Disruption, Business Disruption) | acceptable | no |
| `Firmware Backdoor` (Backdoor, Remote Tampering) | acceptable | no |
| `Physical Harm` (Safety Risk) | acceptable | no |
| `Supply Chain Compromise` | acceptable | no |
| `Malicious Code Injection` | acceptable | no |
| `Fraudulent Vendor Approval` | acceptable | no |
| `Payment Authorization Fraud` (Payment Fraud) | acceptable | no |
| `Shipment Diversion` | acceptable | no |
| `Device Recall` | acceptable | no |
| `Financial Loss` (Breach Costs, Increased Breach Costs) | acceptable | yes |
| `Persistence` (Dormancy, Detection Evasion) | acceptable | yes |
| `Model Manipulation` (Compromised AI Models, Model Poisoning) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Financial Loss` | acceptable |
| `Denial of Service` | FP |
| `Data Exfiltration` | TP |
| `Model Manipulation` | acceptable |
| `Persistence` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `AISC-2026-0C2F27`, `AISC-2026-4706F7` |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 0.000 | — | — | 0 | 2 | 0 | — | `Logistics SaaS platform`, `Machine-learning system for firmware verification` |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Prompt Injection` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Denial of Service` |

---

### #8 — welivesecurity this month in

- **doc id:** `welivesecurity-this-month-in`
- **URL:** https://www.welivesecurity.com/en/videos/month-security-tony-anscombe-february-2026/
- **doc micro:** P 0.500 · R 0.333 · F1 0.400

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:fortigate|weak credential|authentication|exposed management|genai|generative ai|misuse|abuse|promptspy|android|jackpot|atm|wiper` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-EDCDE1` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `ESET` | acceptable | no |
| `Amazon` (AWS, Amazon Threat Intelligence) | acceptable | no |
| `Fortinet` | acceptable | no |
| `FBI` | acceptable | no |
| `CERT Polska` (Poland's CERT, CERT.PL, Polish CERT) | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `FortiGate` (FortiGate devices, Fortinet FortiGate) | required | yes |
| `PromptSpy` | acceptable | yes |
| `Android` | acceptable | yes |
| `DynoWiper` | acceptable | no |

| predicted | verdict |
|---|---|
| `FortiGate` | TP |
| `PromptSpy` | acceptable |
| `Android` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `AI-Assisted Attack` (GenAI Misuse, Generative AI Misuse, AI Misuse, AI-Augmented Attack, Misuse of Generative AI, Commercial GenAI Tool Misuse, AI Tool Abuse) | required | no |
| `ATM Jackpotting` (Jackpotting, Jackpotting Attack) | acceptable | no |
| `Credential Attack` (Weak Credential Exploitation, Credential Stuffing, Brute Force, Weak Authentication Exploitation) | acceptable | no |
| `Wiper Attack` (Data Wiping) | acceptable | no |
| `UI Manipulation` (User Interface Manipulation, Context-Aware UI Manipulation) | acceptable | no |
| `Malware` (Android Malware) | acceptable | no |

| predicted | verdict |
|---|---|
| `Social Engineering` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Device Compromise` (Unauthorized Access, Compromised Devices, System Compromise) | required | no |
| `Cash Theft` (Cash Dispensing, Financial Theft, Financial Loss, ATM Cash Theft) | acceptable | yes |
| `Data Destruction` (Data Wiping, Data Loss) | acceptable | no |
| `Spying` (Surveillance, User Data Theft) | acceptable | no |
| `Operational Disruption` (Energy Sector Disruption, Service Disruption) | acceptable | no |

| predicted | verdict |
|---|---|
| `Financial Loss` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | — | — | — | 0 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.000 | 0.000 | — | 0 | 1 | 1 | `AI-Assisted Attack` | `Social Engineering` |
| Impact | — | 0.000 | — | 0 | 0 | 1 | `Device Compromise` | — |

---

### #9 — adversa top ai security

- **doc id:** `adversa-top-ai-security`
- **URL:** https://adversa.ai/blog/adversa-ai-unveils-explosive-2025-ai-security-incidents-report-revealing-how-generative-and-agentic-ai-are-already-under-attack/
- **doc micro:** P 0.857 · R 1.000 · F1 0.923

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection|data leak|crypto|incident|cross-tenant|mcp` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-6821BE` | FP |
| `AISC-2026-0ED316` | acceptable |
| `AISC-2026-E91E38` | acceptable |
| `AISC-2026-D19672` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Adversa AI` (Adversa) | required | yes |
| `Microsoft` | acceptable | yes |
| `Amazon` | acceptable | yes |
| `Asana` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Adversa AI` | TP |
| `Amazon` | acceptable |
| `Microsoft` | acceptable |
| `Asana` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `Amazon Q` | required | yes |
| `ElizaOS` | required | yes |
| `Microsoft Azure` (Azure) | acceptable | yes |
| `OmniGPT` | acceptable | yes |
| `Microsoft Bing` (Bing) | acceptable | no |
| `Asana AI` (Asana) | acceptable | no |
| `Model Context Protocol` (MCP, MCP Stacks) | acceptable | no |
| `Agentic AI Security Platform` | acceptable | no |

| predicted | verdict |
|---|---|
| `Amazon Q` | TP |
| `Microsoft Azure` | acceptable |
| `OmniGPT` | acceptable |
| `ElizaOS` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` (Prompt Injection Attack, Malicious Prompts, Simple Prompts) | required | yes |
| `Supply Chain Attack` | acceptable | yes |
| `Jailbreak` (Jailbreaking) | acceptable | no |
| `API Abuse` | acceptable | no |
| `Cross-Tenant Attack` (Cross-Tenant Data Leak) | acceptable | no |
| `AI Red Teaming` (Red Teaming) | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |
| `Supply Chain Attack` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Financial Loss` (Monetary Loss, Crypto Theft, Unauthorized Crypto Transfers, Cryptocurrency Theft, Real Losses) | required | yes |
| `Data Leak` (Data Leakage, Personal Data Leak, Cross-Tenant Data Leak, Data Exposure, Information Disclosure, Data Exfiltration) | required | yes |
| `Legal Liability` (Legal Disasters, Legal Consequences) | acceptable | no |
| `API Abuse` | acceptable | no |
| `Reputational Damage` | acceptable | no |
| `Unauthorized Actions` (Unauthorized Transactions) | acceptable | no |
| `Credential Theft` (API Key Theft) | acceptable | yes |
| `Supply Chain Attack` (Supply Chain Attacks, Supply Chain Compromise) | acceptable | no |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `Financial Loss` | TP |
| `Credential Theft` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.000 | — | — | 0 | 1 | 0 | — | `AISC-2026-6821BE` |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |

---

### #10 — blog agentic ai the

- **doc id:** `blog-agentic-ai-the`
- **URL:** https://blog.barracuda.com/2026/02/27/agentic-ai--the-2026-threat-multiplier-reshaping-cyberattacks
- **doc micro:** P 0.333 · R 1.000 · F1 0.500

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:agentic|autonomous|ransomware|ai` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-46331F` | acceptable |
| `AISC-2026-698249` | acceptable |
| `AISC-2026-591D24` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Barracuda` (Barracuda Networks) | acceptable | no |
| `Fortinet` | acceptable | yes |
| `Trend Micro` | acceptable | no |
| `Aisera` | acceptable | no |

| predicted | verdict |
|---|---|
| `Fortinet` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `FortiGate` (FortiGate firewalls, Fortinet FortiGate) | acceptable | yes |

| predicted | verdict |
|---|---|
| `FortiGate` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Agentic AI Attack` (Autonomous Attack, Agentic Attack, AI Agent Attack, Autonomous AI Attack, Agentic AI-Driven Attack) | required | yes |
| `Ransomware` (Ransomware Attack) | acceptable | no |
| `Phishing` (AI-Generated Phishing, Phishing Content Generation) | acceptable | no |
| `Malware Generation` (Malware Development, AI-Generated Malware) | acceptable | no |
| `Reconnaissance` (Automated Reconnaissance, Attack Reconnaissance) | acceptable | yes |
| `Credential Theft` | acceptable | no |

| predicted | verdict |
|---|---|
| `Reconnaissance` | acceptable |
| `Agentic AI attacks` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Credential Theft` (Credential Compromise) | acceptable | yes |
| `Initial Access` (Unauthorized Access, Network Access, Network Compromise, System Compromise) | acceptable | no |
| `Data Breach` | acceptable | no |
| `Persistence` (Persistent Access) | acceptable | yes |
| `Reconnaissance` | acceptable | no |

| predicted | verdict |
|---|---|
| `Credential Theft` | acceptable |
| `Malware Delivery` | FP |
| `Information Disclosure` | FP |
| `Persistence` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | — | — | — | 0 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.000 | — | — | 0 | 2 | 0 | — | `Malware Delivery`, `Information Disclosure` |

---

### #11 — blog owasp top 10

- **doc id:** `blog-owasp-top-10`
- **URL:** https://blog.barracuda.com/2024/11/20/owasp-top-10-risks-large-language-models-2025-updates
- **doc micro:** P 0.429 · R 1.000 · F1 0.600

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection|sensitive information|supply chain|poisoning|output handling|excessive agency|system prompt|embedding|misinformation|unbounded consumption|llm|owasp` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-2D2012` | acceptable |
| `AISC-2026-03BDC9` | acceptable |
| `AISC-2026-F31348` | acceptable |
| `AISC-2026-AA03B7` | acceptable |
| `AISC-2026-FC1477` | acceptable |
| `AISC-2026-8C6328` | acceptable |
| `AISC-2026-B28E49` | acceptable |
| `AISC-2026-610AE0` | acceptable |
| `AISC-2026-6BB9E3` | acceptable |
| `AISC-2026-4B0149` | acceptable |
| `AISC-2026-030CCD` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `OWASP` | acceptable | no |
| `Barracuda` (Barracuda Networks) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Anthropic` | FP |
| `Barracuda` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `Large Language Models` (LLM, LLMs, LLM Applications, GenAI) | acceptable | no |

| predicted | verdict |
|---|---|
| `Claude Mythos` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` | required | yes |
| `Data Poisoning` (Data and Model Poisoning, Model Poisoning, Training Data Poisoning, Poisoning Attack) | required | yes |
| `Supply Chain Attack` (Supply Chain Vulnerabilities) | acceptable | yes |
| `Jailbreak` (Jailbreaking) | acceptable | no |
| `System Prompt Leakage` (Prompt Leakage) | acceptable | no |
| `Embedding Attack` (Vector and Embedding Weaknesses, Embedding Exploitation, Vector Attack) | acceptable | no |
| `Backdoor` (Hidden Backdoor, Backdoor Attack) | acceptable | no |
| `Denial of Service` (Unbounded Consumption, Resource Exhaustion) | acceptable | no |
| `Excessive Agency` (Excessive Autonomy) | acceptable | no |
| `Sensitive Information Disclosure` | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |
| `Supply Chain Attack` | acceptable |
| `Data Poisoning` | TP |
| `Phishing` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Sensitive Information Disclosure` (Information Disclosure, Data Leak, Data Leakage, Sensitive Data Disclosure, Confidential Data Exposure) | required | yes |
| `Misinformation` (False Information, Biased Output, Misleading Outputs, Skewed Outputs) | acceptable | yes |
| `Unauthorized Actions` | acceptable | no |
| `Supply Chain Compromise` | acceptable | no |
| `Denial of Service` (Resource Exhaustion, Degraded Performance, System Overload) | acceptable | yes |
| `Financial Loss` (Billing Surge, Increased Costs) | acceptable | yes |
| `Harmful Content` (Harmful Content Generation, Harmful Language) | acceptable | yes |
| `Unauthorized Access` | acceptable | no |
| `System Prompt Leakage` (System Prompt Disclosure) | acceptable | no |
| `Unintended Code Execution` (Unsafe Code Execution, Code Execution) | acceptable | no |
| `Reputational Damage` (Reputation Damage) | acceptable | no |
| `Legal Liability` (Legal Liabilities) | acceptable | no |
| `Bias` (Biased Content) | acceptable | no |
| `Credential Theft` (API Key Leakage, Credential Leakage) | acceptable | no |
| `Model Manipulation` (Model Tampering, Altered Outputs) | acceptable | yes |
| `Model Backdoor` (Backdoor) | acceptable | no |
| `Data Integrity Manipulation` (Integrity Compromise) | acceptable | no |

| predicted | verdict |
|---|---|
| `Misinformation` | acceptable |
| `Information Disclosure` | TP |
| `Harmful Content Generation` | acceptable |
| `Privilege Escalation` | FP |
| `Model Manipulation` | acceptable |
| `Denial of Service` | acceptable |
| `Financial Loss` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | — | — | — | 0 | 0 | 0 | — | — |
| Vendor | 0.000 | — | — | 0 | 1 | 0 | — | `Anthropic` |
| Software | 0.000 | — | — | 0 | 1 | 0 | — | `Claude Mythos` |
| Attack | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 | — | `Phishing` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Privilege Escalation` |

---

### #12 — obsidiansecurity prompt injection attacks

- **doc id:** `obsidiansecurity-prompt-injection-attacks`
- **URL:** https://www.obsidiansecurity.com/blog/prompt-injection
- **doc micro:** P 0.833 · R 1.000 · F1 0.909

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection` | required | yes |
| `title_any:jailbreak|token compromise|oauth|salesloft` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-03BDC9` | TP |
| `AISC-2026-C58093` | TP |
| `AISC-2026-2B4FEE` | TP |
| `AISC-2026-7C9ADB` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Obsidian Security` (Obsidian) | acceptable | no |
| `OWASP` | acceptable | no |
| `Salesforce` | acceptable | no |
| `Salesloft` | acceptable | no |
| `Drift` | acceptable | no |
| `Amazon` (AWS) | acceptable | no |
| `Microsoft` (Azure) | acceptable | no |
| `Splunk` | acceptable | no |
| `NIST` | acceptable | no |
| `FBI` | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `Splunk` | acceptable | no |
| `Azure Sentinel` | acceptable | no |
| `Azure AD` (Azure Active Directory, Azure AD Managed Identities) | acceptable | no |
| `Salesforce` | acceptable | yes |
| `Salesloft` | acceptable | yes |
| `Drift` (Salesloft-Drift) | acceptable | yes |
| `DynamoDB` (Amazon DynamoDB) | acceptable | no |
| `AWS Lambda` (Lambda) | acceptable | no |
| `AWS IAM` (IAM) | acceptable | no |
| `Large Language Models` (LLM, LLMs) | acceptable | no |

| predicted | verdict |
|---|---|
| `Salesforce` | acceptable |
| `Salesloft` | acceptable |
| `Drift` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` (Prompt Injection Attack) | required | yes |
| `Jailbreak` (Jailbreaking, Jailbreak Attack) | required | yes |
| `Direct Prompt Injection` | acceptable | yes |
| `Indirect Prompt Injection` | acceptable | yes |
| `Cross-Plugin Poisoning` (Cross Plugin Poisoning, Plugin Poisoning) | acceptable | no |
| `Supply Chain Attack` (OAuth Token Compromise, Third-Party App Compromise) | acceptable | yes |
| `Credential Theft` (Token Compromise, Stolen Credentials) | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |
| `Indirect Prompt Injection` | TP |
| `Jailbreak` | TP |
| `Supply Chain Attack` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` (Data Leak, Data Leakage, Data Breach, Data Breaches, Information Disclosure, Exfiltration of Confidential Data, Exfiltrate Confidential Data, Leak of Business Intelligence) | required | yes |
| `Unauthorized Actions` (Unauthorized Access, Unauthorized Data Access, Execute Unauthorized Actions, Authorization Bypass, Bypass Authentication, Bypass Authorization) | required | yes |
| `Privilege Escalation` (Elevated Privileges, Excessive Privileges) | acceptable | yes |
| `Misinformation` (Manipulated Outputs, Manipulate Outputs, Fraud, Output Manipulation) | acceptable | yes |
| `Safety Filter Bypass` (Disable Safety Filters, Guardrail Bypass) | acceptable | no |
| `Security Control Bypass` (Bypass Security Controls, Override System Directives, Instruction Override) | acceptable | yes |
| `Lateral Movement` | acceptable | yes |
| `Regulatory Fines` (Compliance Violation) | acceptable | no |
| `Reputational Damage` (Reputation Damage) | acceptable | no |
| `Financial Loss` (Monetary Loss, Transaction Fraud) | acceptable | no |
| `Operational Disruption` (Business Disruption) | acceptable | no |

| predicted | verdict |
|---|---|
| `Data Exfiltration` | TP |
| `Unauthorized Access` | TP |
| `Privilege Escalation` | acceptable |
| `Instruction Override` | acceptable |
| `Misinformation` | acceptable |
| `Information Disclosure` | TP |
| `Credential Theft` | FP |
| `Lateral Movement` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | — | — |
| Impact | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 | — | `Credential Theft` |

---

### #13 — linkedin kicking off the

- **doc id:** `linkedin-kicking-off-the`
- **URL:** https://www.linkedin.com/pulse/kicking-off-2026-update-owasp-top-10-llm-applications-steve-wilson-ww6nc
- **doc micro:** P 0.000 · R — · F1 —

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt|agentic|leak|llm|owasp` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-7A57B7` | acceptable |

**Vendor**

| expected | role | hit |
|---|---|---|
| `OWASP` (OWASP Generative AI Security Project) | acceptable | no |
| `LinkedIn` | acceptable | no |
| `Anthropic` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Anthropic` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `OpenClaw` | acceptable | yes |
| `Claude Mythos` (Anthropic Mythos, Mythos) | acceptable | no |
| `Project Glasswing` (Glasswing) | acceptable | no |
| `Lobot` | acceptable | yes |
| `Large Language Models` (LLM, LLMs) | acceptable | no |

| predicted | verdict |
|---|---|
| `OpenClaw` | acceptable |
| `Lobot` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` (Prompt Chain Exploitation, Complex Prompt Chains) | acceptable | yes |
| `Agent Manipulation` (Manipulation via Autonomous Agents, Multi-Modal Agent Manipulation) | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Leak` (Contextual Data Leak, API Data Leak, Data Leakage, Data Exfiltration) | acceptable | no |
| `Model Manipulation` (Agent Manipulation, Model Tampering) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Information Disclosure` | FP |
| `Model Manipulation` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | — | — | — | 0 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | — | — | — | 0 | 0 | 0 | — | — |
| Impact | 0.000 | — | — | 0 | 1 | 0 | — | `Information Disclosure` |

---

### #14 — nvd emailgpt prompt injection

- **doc id:** `nvd-emailgpt-prompt-injection`
- **URL:** https://nvd.nist.gov/vuln/detail/CVE-2024-5184
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2024-5184` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2024-5184` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `EmailGPT` | required | yes |
| `Synopsys` | acceptable | no |
| `NIST` (NVD) | acceptable | no |
| `CISA` (CISA-ADP) | acceptable | no |

| predicted | verdict |
|---|---|
| `EmailGPT` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `EmailGPT` | required | yes |

| predicted | verdict |
|---|---|
| `EmailGPT` | TP |
| `EmailGPT` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` (Direct Prompt Injection) | required | yes |
| `System Prompt Extraction` (System Prompt Leak) | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `System Prompt Disclosure` (System Prompt Leakage, Leak System Prompts, Information Disclosure) | required | yes |
| `Service Takeover` (Take Over Service Logic, Logic Manipulation) | acceptable | no |
| `Harmful Content` (Harmful Information) | acceptable | no |
| `Instruction Override` (Execution of Unwanted Prompts, Unwanted Prompt Execution) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `Instruction Override` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #15 — nvd langchain palchain code

- **doc id:** `nvd-langchain-palchain-code`
- **URL:** https://nvd.nist.gov/vuln/detail/CVE-2023-36258
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `CVE-2023-36258` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2023-36258` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `LangChain` | acceptable | no |
| `MITRE` | acceptable | no |
| `NIST` (NVD) | acceptable | no |
| `CISA` (CISA-ADP) | acceptable | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Software**

| expected | role | hit |
|---|---|---|
| `LangChain` (langchain) | required | yes |
| `PALChain` | acceptable | no |

| predicted | verdict |
|---|---|
| `LangChain` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Code Injection` (Arbitrary Code Execution, Python Code Injection, Code Execution via PALChain) | required | yes |

| predicted | verdict |
|---|---|
| `Code Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution, Code Execution, RCE) | required | yes |

| predicted | verdict |
|---|---|
| `Arbitrary Code Execution` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #16 — github langchain ssrf advisory

- **doc id:** `github-langchain-ssrf-advisory`
- **URL:** https://github.com/advisories/GHSA-7gfq-f96f-g85j
- **doc micro:** P 1.000 · R 0.500 · F1 0.667

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `id_any:GHSA-7gfq-f96f-g85j|CVE-2023-36281` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2023-36281` | TP |
| `GHSA-7gfq-f96f-g85j` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `LangChain` (langchain-ai) | acceptable | yes |

| predicted | verdict |
|---|---|
| `langchain-ai` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `LangChain` (langchain, langchain-ai/langchain) | required | yes |

| predicted | verdict |
|---|---|
| `langchain` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Code Injection` (Template Injection, Server-Side Template Injection, SSTI, Arbitrary Code Execution, Prompt Template Injection) | required | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution, Code Execution, RCE) | required | no |

| predicted | verdict |
|---|---|
| *(none predicted)* | — |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | — | 0.000 | — | 0 | 0 | 1 | `Code Injection` | — |
| Impact | — | 0.000 | — | 0 | 0 | 1 | `Remote Code Execution` | — |

---

### #17 — github langchain sql injection

- **doc id:** `github-langchain-sql-injection`
- **URL:** https://github.com/advisories/GHSA-56xg-wfcc-g829
- **doc micro:** P 1.000 · R 1.000 · F1 1.000

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `id_any:GHSA-56xg-wfcc-g829|CVE-2024-34359` | required | yes |

| predicted | verdict |
|---|---|
| `CVE-2024-34359` | TP |
| `GHSA-56xg-wfcc-g829` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `abetlen` | acceptable | yes |

| predicted | verdict |
|---|---|
| `abetlen` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `llama-cpp-python` (llama_cpp, llama-cpp) | required | yes |
| `Jinja2` | acceptable | no |

| predicted | verdict |
|---|---|
| `llama-cpp-python` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Template Injection` (Server-Side Template Injection, SSTI, Jinja2 Template Injection, Code Injection, Chat Template Injection) | required | yes |

| predicted | verdict |
|---|---|
| `Code Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Remote Code Execution` (Arbitrary Code Execution, Code Execution, RCE) | required | yes |

| predicted | verdict |
|---|---|
| `Arbitrary Code Execution` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #18 — embracethered chatgpt hacking memories

- **doc id:** `embracethered-chatgpt-hacking-memories`
- **URL:** https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/
- **doc micro:** P 0.556 · R 1.000 · F1 0.714

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection|memory|indirect` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-46E4D2` | TP |
| `AISC-2026-FEE31C` | FP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `OpenAI` | required | yes |
| `Microsoft` | acceptable | no |
| `Google` | acceptable | no |

| predicted | verdict |
|---|---|
| `OpenAI` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `ChatGPT` | required | yes |
| `Bing` (Bing Chat) | acceptable | no |
| `Google Docs` (Google Drive) | acceptable | no |
| `OneDrive` | acceptable | no |

| predicted | verdict |
|---|---|
| `ChatGPT` | TP |
| `Gemini` | FP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Indirect Prompt Injection` (Prompt Injection, Memory Injection) | required | yes |
| `Automatic Tool Invocation` (Tool Chaining) | acceptable | yes |
| `Delayed Tool Invocation` (Delayed Execution) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Indirect Prompt Injection` | TP |
| `Prompt Injection` | TP |
| `Tool Chaining` | acceptable |
| `Delayed Execution` | acceptable |
| `Context Pollution` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Memory Poisoning` (False Memory Injection, Persistent Memory Manipulation, Data Integrity Loss, Store False Memories, Model Manipulation) | required | yes |
| `Misinformation` (Bias, False Information) | acceptable | yes |
| `Persistence` | acceptable | yes |
| `Data Deletion` (Delete Memories) | acceptable | no |
| `Instruction Override` (Behavior Override) | acceptable | yes |

| predicted | verdict |
|---|---|
| `Instruction Override` | acceptable |
| `Data Exfiltration` | FP |
| `Misinformation` | acceptable |
| `Persistence` | acceptable |
| `Model Manipulation` | TP |
| `Memory Poisoning` | TP |
| `Memory Manipulation` | TP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `AISC-2026-FEE31C` |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Gemini` |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Context Pollution` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Data Exfiltration` |

---

### #19 — embracethered copilot ascii smuggling

- **doc id:** `embracethered-copilot-ascii-smuggling`
- **URL:** https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/
- **doc micro:** P 0.500 · R 1.000 · F1 0.667

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:prompt injection|exfiltration|ascii smuggling|copilot` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-72C839` | TP |
| `AISC-2026-1F811F` | TP |
| `AISC-2026-EA7797` | FP |
| `AISC-2026-2C8972` | TP |
| `AISC-2026-08C3A0` | FP |
| `AISC-2026-20893C` | TP |
| `AISC-2026-B142B7` | TP |
| `AISC-2026-DED13E` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Microsoft` (MSRC) | required | yes |

| predicted | verdict |
|---|---|
| `Microsoft` | TP |

**Software**

| expected | role | hit |
|---|---|---|
| `Microsoft 365 Copilot` (M365 Copilot, Copilot, Microsoft Copilot) | required | yes |

| predicted | verdict |
|---|---|
| `Microsoft 365 Copilot` | TP |
| `Copilot` | TP |
| `ASCII Smuggler` | FP |
| `Microsoft` | TP |

**Attack**

| expected | role | hit |
|---|---|---|
| `Prompt Injection` (Indirect Prompt Injection) | required | yes |
| `ASCII Smuggling` (Unicode Tag Smuggling, Hidden Unicode) | required | yes |
| `Automatic Tool Invocation` (Request Forgery, Tool Invocation) | acceptable | no |
| `Conditional Prompt Injection` | acceptable | yes |
| `Hyperlink Rendering` | acceptable | no |

| predicted | verdict |
|---|---|
| `Prompt Injection` | TP |
| `ASCII Smuggling` | TP |
| `Conditional Prompt Injection` | TP |
| `Social Engineering` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Data Exfiltration` (Data Theft, Email Theft, PII Exfiltration, Information Theft, Steal Emails, Information Disclosure) | required | yes |
| `Credential Theft` (MFA Code Theft) | acceptable | yes |
| `Phishing` (Scam) | acceptable | no |

| predicted | verdict |
|---|---|
| `Information Disclosure` | TP |
| `Data Exfiltration` | TP |
| `Model Manipulation` | FP |
| `Denial of Service` | FP |
| `Credential Theft` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `AISC-2026-EA7797`, `AISC-2026-08C3A0` |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `ASCII Smuggler` |
| Attack | 0.667 | 1.000 | 0.800 | 2 | 1 | 0 | — | `Social Engineering` |
| Impact | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Model Manipulation`, `Denial of Service` |

---

### #20 — blog pickle file attacks

- **doc id:** `blog-pickle-file-attacks`
- **URL:** https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
- **doc micro:** P 0.300 · R 1.000 · F1 0.462

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:pickle|sleepy pickle|deserialization|supply chain|aisc-` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-F8A3D6` | TP |
| `AISC-2026-968E29` | TP |
| `AISC-2026-143F54` | TP |
| `AISC-2026-707DF5` | TP |
| `AISC-2026-342907` | TP |
| `AISC-2026-57D0C5` | TP |
| `AISC-2026-D70808` | TP |
| `AISC-2026-7AE54D` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Trail of Bits` | acceptable | no |
| `Hugging Face` (HuggingFace) | acceptable | no |
| `Google` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Google` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `Pickle` (pickle, Pickle file format) | acceptable | yes |
| `Fickling` | acceptable | yes |
| `GPT-2-XL` (GPT-2) | acceptable | yes |
| `SafeTensors` | acceptable | no |
| `PyTorch` | acceptable | no |
| `ROME` | acceptable | no |
| `Otter AI` | acceptable | yes |
| `Avoma` | acceptable | yes |
| `Fireflies` | acceptable | yes |
| `ReaderGPT` | acceptable | yes |
| `Smmry` | acceptable | yes |
| `Smodin` | acceptable | yes |
| `TldrThis` | acceptable | yes |

| predicted | verdict |
|---|---|
| `pickle` | acceptable |
| `Fickling` | acceptable |
| `GPT-2-XL` | acceptable |
| `Rank One Model Editing` | FP |
| `Otter AI` | acceptable |
| `Avoma` | acceptable |
| `Fireflies` | acceptable |
| `ReaderGPT` | acceptable |
| `Smmry` | acceptable |
| `Smodin` | acceptable |
| `TldrThis` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Deserialization Attack` (Pickle Deserialization, Malicious Pickle, Pickle Injection, Sleepy Pickle, Insecure Deserialization) | required | yes |
| `Supply Chain Attack` (Supply Chain Compromise, Model Supply Chain Attack) | acceptable | yes |
| `Model Poisoning` (Model Tampering, Weight Poisoning) | acceptable | no |
| `Man-in-the-Middle` (MITM) | acceptable | yes |
| `Backdoor` (Model Backdoor) | acceptable | yes |
| `Sticky Pickle` | acceptable | no |
| `Phishing` (Insider Attack, Phishing or Insider Attacks) | acceptable | yes |
| `Post-Exploitation` (Post-Exploitation of System Weaknesses) | acceptable | no |
| `Malicious Link Insertion` | acceptable | no |
| `Cross-Site Scripting` (XSS, JavaScript Injection) | acceptable | no |

| predicted | verdict |
|---|---|
| `Sleepy Pickle` | TP |
| `Pickle file attacks` | FP |
| `Deserialization Attack` | TP |
| `Supply Chain Attack` | acceptable |
| `Phishing` | acceptable |
| `Man-In-The-Middle` | acceptable |
| `Man-in-the-Middle Attack` | acceptable |
| `Social Engineering` | FP |
| `Data Poisoning` | FP |
| `Model Backdoor` | acceptable |
| `Indirect Prompt Injection` | FP |
| `Persistence` | FP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Arbitrary Code Execution` (Remote Code Execution, Code Execution, RCE) | required | yes |
| `Data Theft` (Steal User Data, Data Exfiltration, Privacy Loss) | acceptable | yes |
| `Misinformation` (Harmful Output, Disinformation, Harmful Content) | acceptable | yes |
| `Phishing` (Malicious Links, Scam) | acceptable | yes |
| `Model Backdoor` (Backdoor) | acceptable | no |
| `Model Tampering` (Tampering with Model Code, Model Manipulation) | acceptable | yes |
| `Denial of Service` (System Crash, Crash) | acceptable | yes |
| `Detection Evasion` (Evading Detection) | acceptable | no |
| `System Tampering` (Tamper with User System, Data Tampering) | acceptable | no |
| `Persistence` (Foothold, Persistent Access) | acceptable | yes |
| `Malware Infection` (Malware) | acceptable | yes |
| `Compromise User Security` (Compromise End-User Security, Compromise End-User Safety, Compromise End-User Privacy) | acceptable | no |

| predicted | verdict |
|---|---|
| `Arbitrary Code Execution` | TP |
| `Denial of Service` | acceptable |
| `Data Exfiltration` | acceptable |
| `Model Manipulation` | acceptable |
| `Persistence` | acceptable |
| `Misinformation` | acceptable |
| `Harmful Content Generation` | acceptable |
| `Information Disclosure` | FP |
| `Phishing` | acceptable |
| `Malware Delivery` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | 0.000 | — | — | 0 | 1 | 0 | — | `Rank One Model Editing` |
| Attack | 0.167 | 1.000 | 0.286 | 1 | 5 | 0 | — | `Pickle file attacks`, `Social Engineering`, `Data Poisoning`, `Indirect Prompt Injection`, `Persistence` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Information Disclosure` |

---

### #21 — hiddenlayer shadowlogic backdoor technique

- **doc id:** `hiddenlayer-shadowlogic-backdoor-technique`
- **URL:** https://hiddenlayer.com/innovation-hub/shadowlogic/
- **doc micro:** P 0.429 · R 1.000 · F1 0.600

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:shadowlogic|backdoor|computational graph` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-1E9999` | FP |
| `AISC-2026-45B302` | FP |
| `AISC-2026-74A9E6` | TP |
| `AISC-2026-4C5951` | TP |
| `AISC-2026-57D29F` | TP |
| `AISC-2026-E30D55` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `HiddenLayer` | acceptable | no |
| `New York University` (NYU) | acceptable | no |
| `UC Berkeley` (Berkeley) | acceptable | no |
| `MIT` | acceptable | no |
| `IAS` | acceptable | no |
| `Microsoft` | acceptable | yes |
| `Apple` | acceptable | no |

| predicted | verdict |
|---|---|
| `Microsoft` | acceptable |

**Software**

| expected | role | hit |
|---|---|---|
| `ONNX` | acceptable | no |
| `PyTorch` | acceptable | no |
| `TensorFlow` | acceptable | no |
| `ResNet` | acceptable | yes |
| `YOLO` | acceptable | yes |
| `Phi-3` | acceptable | yes |
| `CoreML` | acceptable | no |
| `OpenVINO` | acceptable | no |
| `Netron` | acceptable | no |
| `Model Explorer` | acceptable | no |

| predicted | verdict |
|---|---|
| `ResNet` | acceptable |
| `YOLO (You Only Look Once)` | acceptable |
| `Phi-3` | acceptable |
| `Phi-3 Mini` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Model Backdoor` (Computational Graph Backdoor, Logic Backdoor, ShadowLogic, No-Code Backdoor, Graph Backdoor, Backdoor Injection, Backdoor Creation, Backdoor Attack, Backdoor) | required | yes |
| `Data Poisoning` (Dataset Backdoor, Training Data Poisoning) | acceptable | yes |
| `Supply Chain Attack` (Supply Chain Compromise) | acceptable | yes |
| `Deserialization Attack` | acceptable | no |

| predicted | verdict |
|---|---|
| `Backdoor` | TP |
| `Supply Chain Attack` | acceptable |
| `ShadowLogic` | TP |
| `Model Backdoor` | TP |
| `Data Poisoning` | acceptable |

**Impact**

| expected | role | hit |
|---|---|---|
| `Model Manipulation` (Output Manipulation, Attacker-Defined Output, Attacker-Defined Outcome, Model Hijack, Bypass Model Logic, Model Integrity Loss, Classification Manipulation) | required | yes |
| `Misclassification` (Targeted Misclassification, Manipulated Object Detection, Misinformation) | acceptable | no |
| `Persistence` (Persistent Foothold, Persistent Threat) | acceptable | yes |
| `Data Theft` (Information Theft) | acceptable | no |
| `Hidden Behavior Activation` | acceptable | no |
| `Controlled Token Generation` (Token Manipulation) | acceptable | no |
| `Undetectable Backdoors` (Undetectable Backdoor) | acceptable | no |
| `Erosion of Trust` (Trust Erosion) | acceptable | no |
| `Unauthorized Access` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Unauthorized Access` | acceptable |
| `Information Disclosure` | FP |
| `Model Manipulation` | TP |
| `Instruction Override` | FP |
| `Persistence` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `AISC-2026-1E9999`, `AISC-2026-45B302` |
| Vendor | — | — | — | 0 | 0 | 0 | — | — |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Information Disclosure`, `Instruction Override` |

---

### #22 — lakera visual prompt injections

- **doc id:** `lakera-visual-prompt-injections`
- **URL:** https://www.lakera.ai/blog/visual-prompt-injections
- **doc micro:** P 0.429 · R 1.000 · F1 0.600

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:visual prompt injection|prompt injection` | required | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-B34194` | TP |
| `AISC-2026-03BDC9` | TP |
| `AISC-2026-BBAEC2` | TP |
| `AISC-2026-00A9F7` | TP |
| `AISC-2026-71715F` | TP |

**Vendor**

| expected | role | hit |
|---|---|---|
| `Lakera` | acceptable | yes |
| `OpenAI` | acceptable | yes |
| `Dropbox` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Lakera` | acceptable |
| `OpenAI` | acceptable |
| `Microsoft` | FP |
| `Dropbox` | acceptable |
| `Roboflow` | FP |

**Software**

| expected | role | hit |
|---|---|---|
| `GPT-4V` (GPT-V4, GPT-4, ChatGPT) | acceptable | yes |
| `Lakera Guard` | acceptable | no |
| `Gandalf` | acceptable | yes |

| predicted | verdict |
|---|---|
| `Gandalf` | acceptable |
| `GPT-4V` | acceptable |
| `GPT-V4` | acceptable |

**Attack**

| expected | role | hit |
|---|---|---|
| `Visual Prompt Injection` (Multimodal Prompt Injection, Image Prompt Injection, Prompt Injection) | required | yes |
| `Jailbreak` (Guardrail Bypass) | acceptable | no |
| `CAPTCHA Bypass` | acceptable | no |
| `Invisibility Cloak` | acceptable | no |
| `Identity Manipulation` | acceptable | no |
| `Environment Manipulation` | acceptable | no |
| `Human-to-Robot Deception` (Deception) | acceptable | no |
| `Ad Suppression` | acceptable | no |

| predicted | verdict |
|---|---|
| `Visual Prompt Injection` | TP |
| `Data Poisoning` | FP |
| `Prompt Injection` | TP |

**Impact**

| expected | role | hit |
|---|---|---|
| `Instruction Override` (Ignore Original Instructions, Unintended Actions, Bypass Defenses, Model Manipulation, Perform Unintended Actions) | required | yes |
| `Safety Filter Bypass` (Guardrail Bypass) | acceptable | no |
| `Misinformation` | acceptable | no |
| `Identity Manipulation` (Misdescribe People) | acceptable | no |
| `Ad Suppression` (Advertising Suppression, Advertising Manipulation, Suppression of Competing Content) | acceptable | no |

| predicted | verdict |
|---|---|
| `Instruction Override` | TP |
| `Information Disclosure` | FP |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | 0.000 | — | — | 0 | 2 | 0 | — | `Microsoft`, `Roboflow` |
| Software | — | — | — | 0 | 0 | 0 | — | — |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Data Poisoning` |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Information Disclosure` |

---

### #23 — ClaudeBleed

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

### #24 — EchoLeak

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
| `AI command injection` | acceptable |
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
| `Data Exfiltration` | TP |
| `Information Disclosure` | TP |
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

### #25 — MCPoison (Dark Reading)

- **doc id:** `darkreading-rce-flaw-in`
- **URL:** https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk
- **doc micro:** P 0.571 · R 0.800 · F1 0.667

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
| `Harmful Content Generation` | FP |
| `Credential Theft` | acceptable |
| `Information Disclosure` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Vendor | — | 0.000 | — | 0 | 0 | 1 | `Cursor` | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Data Poisoning` |
| Impact | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Model Manipulation`, `Harmful Content Generation` |

---

### #26 — Anthropic Git MCP

- **doc id:** `theregister-anthropic-quietly-fixed`
- **URL:** https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059
- **doc micro:** P 0.778 · R 1.000 · F1 0.875

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
| `Information Disclosure` | acceptable |
| `File Deletion` | acceptable |

#### Per-class scores

| class | P | R | F1 | tp | fp | fn | missed | false positives |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Vulnerability | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |
| Vendor | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Software | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Attack | 0.333 | 1.000 | 0.500 | 1 | 2 | 0 | — | `Argument Injection`, `Code Injection` |
| Impact | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |

---

### #27 — Bleeding Llama

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

### #28 — Gemini CLI RCE

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

### #29 — Comment and Control

- **doc id:** `securityweek-claude-code-gemini`
- **URL:** https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
- **doc micro:** P 0.727 · R 0.889 · F1 0.800

#### Expected vs actual (by class)

**Vulnerability**

| expected | role | hit |
|---|---|---|
| `title_any:comment and control` | required | no |
| `title_any:prompt injection|github comment|pr title|issue comment` | acceptable | yes |

| predicted | verdict |
|---|---|
| `AISC-2026-1CA6CA` | acceptable |
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
| `Comment and Control` | TP |

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
| Vulnerability | 0.000 | 0.000 | — | 0 | 1 | 1 | `title_any:comment and control` | `AISC-2026-3BD568` |
| Vendor | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 | — | — |
| Software | 0.750 | 1.000 | 0.857 | 3 | 1 | 0 | — | `security review agent` |
| Attack | 1.000 | 1.000 | 1.000 | 1 | 0 | 0 | — | — |
| Impact | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | — | `Privilege Escalation` |

---

### #30 — MCPoison (CPR)

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

### #31 — OX MCP by-design

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

## Quick failure themes (aggregated)

### Most common required misses

| times | miss |
|---:|---|
| 2 | `Impact: Data Exfiltration` |
| 2 | `Vendor: Cursor` |
| 1 | `Attack: AI-Assisted Attack` |
| 1 | `Attack: Code Injection` |
| 1 | `Attack: DNS Rebinding` |
| 1 | `Attack: Malicious Browser Extension` |
| 1 | `Attack: Prompt Injection` |
| 1 | `Attack: Tool Poisoning` |
| 1 | `Impact: Credential Theft` |
| 1 | `Impact: Device Compromise` |
| 1 | `Impact: Remote Code Execution` |
| 1 | `Software: Model Context Protocol` |
| 1 | `Vendor: Ollama` |
| 1 | `Vulnerability: title_any:comment and control` |
| 1 | `Vulnerability: title_any:prompt injection` |

### Most common false positives

| times | FP |
|---:|---|
| 6 | `Impact: Information Disclosure` |
| 5 | `Attack: Social Engineering` |
| 4 | `Impact: Privilege Escalation` |
| 3 | `Attack: Data Poisoning` |
| 3 | `Impact: Denial of Service` |
| 2 | `Attack: Code Injection` |
| 2 | `Attack: Indirect Prompt Injection` |
| 2 | `Attack: Prompt Injection` |
| 2 | `Impact: Instruction Override` |
| 2 | `Impact: Model Manipulation` |
| 2 | `Software: Burp` |
| 2 | `Software: sqlmap` |
| 2 | `Vendor: Microsoft` |
| 1 | `Attack: Argument Injection` |
| 1 | `Attack: Context Pollution` |
| 1 | `Attack: Model Extraction` |
| 1 | `Attack: Persistence` |
| 1 | `Attack: Phishing` |
| 1 | `Attack: Pickle file attacks` |
| 1 | `Attack: Trust Bypass` |
| 1 | `Impact: Credential Theft` |
| 1 | `Impact: Data Exfiltration` |
| 1 | `Impact: Harmful Content Generation` |
| 1 | `Impact: Malware Delivery` |
| 1 | `Impact: Social Engineering` |

### Class takeaways

- **Vulnerability** — P 0.744 · R 0.935 · F1 0.829 (tp=29 fp=10 fn=2)
- **Vendor** — P 0.739 · R 0.850 · F1 0.791 (tp=17 fp=6 fn=3)
- **Software** — P 0.659 · R 0.964 · F1 0.783 (tp=27 fp=14 fn=1)
- **Attack** — P 0.562 · R 0.818 · F1 0.667 (tp=27 fp=21 fn=6)
- **Impact** — P 0.607 · R 0.872 · F1 0.716 (tp=34 fp=22 fn=5)
