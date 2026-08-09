# Article test queue — extraction dumps

Brief article note + what the extraction pipeline returned (`source_url.preview_json`, then merged).
One table per class; every extracted object and the attributes that were set (empty attrs omitted from columns).

---

## 1. ClaudeBleed — Claude Chrome extension agent takeover

**URL:** https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/

LayerX reports a flaw in Anthropic’s Claude extension for Chrome (ClaudeBleed): the extension trusts command origin (`claude.ai`) instead of execution context, so a zero-permission malicious extension can inject prompts and drive the AI agent (Gmail/GitHub/Drive exfil, etc.). Often no CVE → pipeline may mint `AISC-…`.

**Pipeline:** 7 entities · previewed 2026-08-07T21:23:35 · merged 2026-08-07T21:29:16

### Vulnerability (1)

| vuln_id | title | _minted_id |
|---|---|---|
| AISC-2026-39B822 | ClaudeBleed | true |

### Attack (1)

| name | description |
|---|---|
| Indirect Prompt Injection | An attacker can perform remote prompt injection and control the AI agent’s actions. |

### Impact (3)

| name | description |
|---|---|
| Information Disclosure | Exfiltrate data from Gmail, GitHub, or Google Drive. |
| Data Exfiltration | Exfiltrate data from Gmail, GitHub, or Google Drive. |
| Instruction Override | Control the AI agent’s actions. |

### Vendor (1)

| name |
|---|
| Anthropic |

### Software (1)

| name | is_ai | software_type | role |
|---|---|---|---|
| Claude extension for Chrome | true | Agent | affected |

**Notes / investigate**

- No `description` on Vulnerability — page has it (deck: “Lax extension permissions and improper trust implementation…”; also body).
- No `date_published` — page has **May 8, 2026**. May be markdown stripping/cleaning, or LLM drop — check.
- Attack + Impact look good.
- Rest (Vendor Anthropic, Software Claude extension for Chrome / Agent / affected, minted `AISC-…` ClaudeBleed) makes sense.

**Thoughts**

- Core story is clean — not a “wrong extract”; the miss is attribute fill (`description`, `date_published`), and both strings are already in the crawled markdown, so lean LLM drop over strip/clean.
- Info Disclosure + Data Exfiltration are the same Gmail/GitHub/Drive harm twice — fine to keep one.
- Best single-product extract in the queue so far.

---

## 2. EchoLeak — Microsoft 365 Copilot zero-click data exfil

**URL:** https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html

**CVE-2025-32711** (CVSS 9.3), Aim Security: malicious prompt in email → M365 Copilot RAG mixes untrusted content with privileged context (indirect prompt injection / LLM scope violation) → data exfil without user click. Same THN page also digresses into MCP tool poisoning / GitHub MCP / DNS rebinding.

**Pipeline:** 14 entities · previewed 2026-08-07T21:23:30 · merged 2026-08-07T21:29:14

### Vulnerability (1)

| vuln_id | title | description | cvss_severity | cvss_base_score |
|---|---|---|---|---|
| CVE-2025-32711 | EchoLeak | AI command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network. | CRITICAL | 9.3 |

### Attack (4)

| name | description |
|---|---|
| Indirect Prompt Injection | The attacker embeds a malicious prompt payload inside markdown-formatted content, like an email, which is then parsed by the AI system’s retrieval-augmented generation (RAG) engine. |
| Command Injection | — |
| Phishing | — |
| Social Engineering | — |

### Impact (2)

| name | description |
|---|---|
| Information Disclosure | The attacker can automatically exfiltrate sensitive and proprietary information from M365 Copilot context. |
| Data Exfiltration | The attacker relies on Copilot's default behavior to combine and process content from Outlook and SharePoint without isolating trust boundaries – turning helpful automation into a silent leak vector. |

### Vendor (2)

| name |
|---|
| Microsoft |
| GitHub |

### Software (5)

| name | is_ai | software_type | role |
|---|---|---|---|
| Microsoft 365 Copilot | true | Application | affected |
| Copilot | true | Application | affected |
| Model Context Protocol | true | Library | affected |
| GitHub MCP integration | true | AI Component | affected |
| MCP server | true | Application | affected |

**Notes / investigate**

- Unsure about Attack rows **Command Injection**, **Phishing**, **Social Engineering** — feel like noise next to Indirect Prompt Injection.
- Impact looks good.
- Vendor **GitHub** is because the article drifts into GitHub MCP / related MCP stories — not because GitHub owns EchoLeak.
- Softwares for MCP / GitHub MCP marked `affected` same problem (digression bleed); also **Copilot** duplicate of M365 Copilot.
- This page is **not a great test** — THN bundle, all over the place — but overall extract not bad (core CVE + severity + description landed).

**Thoughts**

- For “did we get EchoLeak?” → yes (CVE, severity, description, Indirect PI, Microsoft / M365 Copilot).
- For “did we stay on the headline vuln?” → no; MCP/GitHub as `affected` is digression bleed — role should be `mentioned` at best.
- Weak gold fixture for Track A; use a cleaner Copilot/CVE-only page when you want a fair score.

---

## 3. MCPoison — Cursor MCP trust bypass → silent RCE (Dark Reading)

**URL:** https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk

**CVE-2025-54136** (MCPoison), Check Point: Cursor one-time MCP approval binds trust to entry **name**, not command — shared-repo config swap → silent persistent RCE. Fixed in Cursor **1.3**. Article also notes **CVE-2025-54135** (CurXecute, Aim Labs).

**Pipeline:** 16 entities · previewed 2026-08-07T21:22:17 · merged 2026-08-07T21:29:10

### Vulnerability (2)

| vuln_id | title | description |
|---|---|---|
| CVE-2025-54136 | MCPoison | A flaw in the trust model of Cursor related to how it has configured its Model Context Protocol (MCP), allowing for silent and persistent remote code execution. |
| CVE-2025-54135 | CurXecute | — |

### Attack (4)

| name | description |
|---|---|
| Code Injection | An attacker can repeatedly inject malicious commands without user awareness. |
| Prompt Injection | — |
| Data Poisoning | — |
| Supply Chain Attack | — |

### Impact (7)

| name | description |
|---|---|
| Remote Code Execution | Allows for silent and persistent remote code execution. |
| Privilege Escalation | Attackers can use the flaw to escalate privileges within the user context. |
| Persistence | The malicious MCP is re-executed on every project launch or repository sync. |
| Data Exfiltration | — |
| Model Manipulation | — |
| Credential Theft | — |
| Information Disclosure | — |

### Software (2)

| name | is_ai | software_type | role |
|---|---|---|---|
| Cursor | true | Application | affected |
| MCP | true | AI Component | affected |

### Version (1)

| version_string |
|---|
| 1.3 |

**Notes / investigate**

- CurXecute (`CVE-2025-54135`) is a **side note**, but the page has enough text for a description (“This version also fixes a prompt-injection flaw in Cursor’s MCP discovered by Aim Labs… dubbed CurXecute”) — extract left description empty.
- Attack **Code Injection** is OK-ish for MCPoison (malicious command swapped into MCP config); **Prompt Injection** would fit **CurXecute** better (and the side note literally says prompt-injection).
- No idea why **Data Poisoning** is there — doesn’t match either CVE.
- **Supply Chain Attack** makes sense — article frames shared-repo / AI supply-chain risk.
- Impacts are **fair** (RCE, Persistence, etc.) but several lack descriptions (Data Exfiltration, Model Manipulation, Credential Theft, Information Disclosure empty).

**Thoughts**

- Win is keeping MCPoison ≠ CurXecute as two Vulnerability rows; empty CurXecute description is the clear attr miss.
- Attack set is half-right (Code Injection / Supply Chain) and half-noise (Data Poisoning; Prompt Injection untied to which CVE).
- Prefer fewer Impacts with one-line descriptions; also MCP as `affected` product and Version=`1.3` (fix, not affected-before) are the usual hygiene nits.

---

## 4. Anthropic `mcp-server-git` — three CVEs chained with Filesystem MCP → RCE

**URL:** https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059

Cyata found **CVE-2025-68145** / **68143** / **68144** in Anthropic’s Git MCP server; chained with Filesystem MCP + git smudge/clean filters → RCE via indirect prompt injection. Fixed prior to **2025.12.18**.

**Pipeline:** 17 entities · previewed 2026-08-07T21:23:23 · merged 2026-08-07T21:29:12

### Vulnerability (3)

| vuln_id | title |
|---|---|
| CVE-2025-68145 | MCP server repository path bypass |
| CVE-2025-68143 | Arbitrary filesystem path creation via git_init |
| CVE-2025-68144 | Argument injection in git_diff and git_checkout |

### Attack (2)

| name | description |
|---|---|
| Prompt Injection | Direct prompt injection happens when someone directly submits malicious input |
| Indirect Prompt Injection | indirect injection happens when content contains hidden commands that AI then follows as if the user had entered them |

### Impact (4)

| name | description |
|---|---|
| Remote Code Execution | — |
| File Overwrite | — |
| Information Disclosure | Access any repository on the system |
| File Deletion | — |

### Vendor (1)

| name |
|---|
| Anthropic |

### Software (6)

| name | is_ai | software_type | role |
|---|---|---|---|
| mcp-server-git | true | AI Component | affected |
| Model Context Protocol (MCP) | true | Library | affected |
| Claude Code | true | Agent | affected |
| MCP server | true | AI Component | affected |
| Git | false | Application | affected |
| Git MCP server | true | AI Component | affected |

### Version (1)

| version_string |
|---|
| prior to 2025.12.18 |

**Notes / investigate**

- Attack should be **Indirect Prompt Injection** only for this story (IDE reads malicious README / webpage / GitHub issue). Generic **Prompt Injection** looks like it copied the article’s direct-vs-indirect glossary, not a second attack path.
- Enough info on the page for Vulnerability **descriptions** on all three CVEs — extract left them empty:
  - **68145** — `--repository` path bypass; later `repo_path` args not validated → any repo on the system
  - **68143** — unrestricted `git_init` on arbitrary paths; Anthropic removed the tool
  - **68144** — unsanitized args to `git_diff` / `git_checkout` → `--output=…` overwrite / delete files
- Impacts look good (RCE, File Overwrite, File Deletion, Information Disclosure) but most are **missing descriptions** (only Info Disclosure has one).

**Thoughts**

- Best CVE hygiene so far — three clean ids + Version `prior to 2025.12.18`; titles good, descriptions the miss (Register paragraphs are almost paste-ready).
- Bare Prompt Injection is glossary bleed; keep Indirect only for the Cyata chain.
- Software sprawl (mcp-server-git / Git MCP server / MCP server + Claude Code / Git as `affected`) is the other weak spot if we widen the score later.

---

## 5. Semantic Kernel — prompts → shells (Microsoft Defender Research)

**URL:** https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

Microsoft Security Blog: prompt injection → host RCE via AI agent frameworks. Case study **Semantic Kernel** with **CVE-2026-26030** (Python In-Memory Vector Store / `eval`) and **CVE-2026-25592** (.NET SessionsPythonPlugin).

**Pipeline:** 1 entities · previewed 2026-08-07T16:14:44 · merged 2026-08-07T21:28:57

### Vendor (1)

| name |
|---|
| Microsoft |

---

## 6. Bleeding Llama — Ollama heap OOB → secret theft

**URL:** https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/

**CVE-2026-7482** (CVSS 9.3), Cyera: heap out-of-bounds read in Ollama’s GGUF model loader; exfil via model push. ~300k internet-exposed instances. Fixed in Ollama **0.17.1**.

**Pipeline:** 5 entities · previewed 2026-08-07T16:19:33 · merged 2026-08-07T21:29:00

### Vulnerability (1)

| vuln_id | title | description |
|---|---|---|
| CVE-2026-7482 | Bleeding Llama | A heap out-of-bounds read issue in the GGUF model loader that allows an attacker to access sensitive information stored on the heap. |

### Attack (1)

| name | description |
|---|---|
| Model Extraction | The attacker leverages Ollama’s built-in model push feature to exfiltrate the resulting file – complete with stolen heap data – to an attacker-controlled server. |

### Impact (1)

| name | description |
|---|---|
| Information Disclosure | Exposure of employee interactions, development code, routed tool outputs, and prompts containing PII, PHI, and other sensitive information. |

### Software (1)

| name | is_ai | software_type | role |
|---|---|---|---|
| Ollama | true | ML Infrastructure | affected |

### Version (1)

| version_string |
|---|
| 0.17.1 |

**Notes / investigate**

- Misses `cvss_base_score` / severity — page clearly has **CVSS 9.3** (in markdown).
- Is **Model Extraction** the right Attack? Feels sorta OK because exfil uses model push, but unsure.
- Impact = Information Disclosure — should it also be **Data Exfiltration**? Unclear difference.
- Rest seems fine (CVE, Bleeding Llama description, Ollama, Version).

**Thoughts**

- CVSS miss is same attr-drop pattern as ClaudeBleed date — `CVSS score of 9.3` is in the crawled text.
- **Model Extraction** is the wrong standard name: that usually means stealing model weights via queries. Here the bug is heap OOB read; model push is just the **exfil channel**. Prefer something like unauth API / crafted GGUF (or keep a custom name) — the Attack *description* is actually good, the *label* is off.
- Info Disclosure = secrets become readable; Data Exfiltration = they leave the host (here via push). Both fit; Disclosure alone underplays the push step. Having both would match EchoLeak-style pairing.

---

## 7. Gemini CLI — CVSS 10 RCE / allowlist bypass (The Register)

**URL:** https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768

Google patches Gemini CLI / `run-gemini-cli` GitHub Action: headless mode trusts workspace `.gemini/` env (RCE) and `--yolo` previously bypassed tool allowlists. Often no CVE yet → may mint `AISC-…`. Fixes in **0.39.1** / **0.40.0-preview.3**.

**Pipeline:** 14 entities · previewed 2026-08-07T16:19:59 · merged 2026-08-07T21:29:02

### Vulnerability (3)

| vuln_id | title | description | cvss_severity | cvss_base_score | _minted_id |
|---|---|---|---|---|---|
| AISC-2026-C6591D | Gemini CLI RCE vulnerability | — | CRITICAL | 10.0 | true |
| AISC-2026-A43FFF | Remote code execution via malicious environment variables in the local .gemini/ directory | If used with untrusted directory contents in headless mode, malicious environment variables in the local .gemini/ directory could lead to remote code execution. | — | — | true |
| AISC-2026-872BB8 | Gemini CLI --yolo mode bypasses tool allowlists | — | CRITICAL | 10.0 | true |

### Attack (2)

| name | description |
|---|---|
| Supply Chain Attack | — |
| Code Injection | Using malicious environment variables to execute arbitrary code. |

### Impact (4)

| name | description |
|---|---|
| Remote Code Execution | — |
| Arbitrary Code Execution | Code execution on the host running the agent |
| Credential Theft | Access to secrets, credentials, and source code |
| Information Disclosure | — |

### Vendor (1)

| name |
|---|
| Google |

### Software (2)

| name | is_ai | software_type | role |
|---|---|---|---|
| Gemini CLI | true | Application | affected |
| run-gemini-cli GitHub Action | true | Application | affected |

### Version (2)

| version_string |
|---|
| 0.39.1 |
| 0.40.0-preview.3 |

**Notes / investigate**

- Got **3** minted Vulnerability rows — unclear if all three were supposed to exist (no CVE on page yet).
- Unsure about Attack **Code Injection** / code-execution framing.
- Unsure **Information Disclosure** belongs as an Impact.
- Rest seems fine (Google, Gemini CLI + Action, versions, Credential Theft / RCE themes).

**Thoughts**

- Prefer **1–2** vulns, not 3: (A) headless workspace trust / malicious `.gemini/` env → RCE is the real finding (row `A43FFF` is the good one; generic “Gemini CLI RCE” is a dupe of that). (B) `--yolo` allowlist bypass is a **related fix in the same release**, not clearly a second CVSS-10 CVE — article never scores it separately; treating it as equal CRITICAL is oversplit.
- **Code Injection** is OK-ish for “attacker-controlled config/env executed before sandbox” (Meged: *not* prompt injection). **Supply Chain** is the CI delivery framing, empty description. Neither is wrong; Code Injection is closer to the root mechanism.
- Impacts: keep **RCE** (or Arbitrary Code Execution — not both) + **Credential Theft**. Drop bare **Information Disclosure** — secrets access is already Credential Theft; Disclosure without a distinct leak channel is noise.

---

## 8. Comment and Control — PI via GitHub comments (multi-vendor agents)

**URL:** https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/

Aonan Guan (+ JHU): prompt injection via untrusted GitHub data (PR titles, comments, HTML comments) against Claude Code Security Review, Gemini CLI Action, and GitHub Copilot Agent. Narrative / multi-product — may mint `AISC-…`.

**Pipeline:** 13 entities · previewed 2026-08-07T16:37:54 · merged 2026-08-07T21:29:04

### Vulnerability (2)

| vuln_id | title | description | _minted_id |
|---|---|---|---|
| AISC-2026-2C4DA4 | Comment and Control Prompt Injection | AI agents on GitHub Actions can be hijacked using specially crafted GitHub comments, including PR titles, comments, and issue bodies. | true |
| AISC-2026-3BD568 | overly broad tool access for a security review agent | — | true |

### Attack (1)

| name | description |
|---|---|
| Prompt Injection | A method where specially crafted comments, PR titles, or issue bodies are used to trick an AI agent into executing commands or revealing secrets. |

### Impact (3)

| name | description |
|---|---|
| Arbitrary Code Execution | The AI agent is tricked into executing arbitrary commands. |
| Credential Theft | Extracting credentials and revealing them as a security finding or an entry in the GitHub Actions log. |
| Information Disclosure | Obtaining a full API key. |

### Vendor (3)

| name |
|---|
| Anthropic |
| Google |
| GitHub |

### Software (4)

| name | is_ai | software_type | role |
|---|---|---|---|
| Claude Code Security Review | true | Agent | affected |
| Gemini CLI Action | true | Agent | affected |
| GitHub Copilot Agent | true | Agent | affected |
| security review agent | true | Agent | affected |

**Notes / investigate**

- Second AISC (`overly broad tool access for a security review agent`) is **unnecessary**.
- Unsure about Impact **Arbitrary Code Execution**; also should **Credential Theft** and **Information Disclosure** both be there?
- What the hell is Software **security review agent**?
- Rest looks fine (lead Comment and Control vuln, Prompt Injection, three vendors, three real agents).

**Thoughts**

- Second AISC is Anthropic **remediation commentary** from the page UPDATE (tool access still too broad after the fix) — not a separate vulnerability. Drop it; keep one minted “Comment and Control” row (or ideally one per product, but not a remediation note).
- **security review agent** is the same bleed: a generic alias for Claude Code Security Review, invented from that remediation sentence. Not a fourth product — delete it.
- Impacts: ACE (or RCE) for “agent runs attacker commands” is fair. Credential Theft + Info Disclosure overlap here (API key in Actions log is both); keep **Credential Theft**, drop bare Disclosure, or merge into one secrets-exfil impact.

---

## 9. MCPoison primary — Check Point Research (Cursor MCP trust)

**URL:** https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/

CPR write-up for **CVE-2025-54136** only: Cursor MCP trust on entry name, not content; benign→malicious swap → persistent RCE / reverse shell. Fixed in Cursor **1.3**. (No CurXecute on this page.)

**Pipeline:** 10 entities · previewed 2026-08-07T16:47:15 · merged 2026-08-07T21:29:08

### Vulnerability (1)

| vuln_id | title |
|---|---|
| CVE-2025-54136 | MCPoison Cursor IDE: Persistent Code Execution via MCP Trust Bypass |

### Attack (3)

| name | description |
|---|---|
| Command Injection | — |
| Code Injection | Modifying the MCP configuration to execute a malicious command or payload. |
| Social Engineering | An attacker performs a harmless commit to gain initial approval from the user. |

### Impact (4)

| name | description |
|---|---|
| Remote Code Execution | Execution of a reverse shell payload. |
| Arbitrary Code Execution | — |
| Persistence | The payload is re-evaluated and triggered every time the victim opens Cursor. |
| Privilege Escalation | — |

### Software (1)

| name | is_ai | software_type | role |
|---|---|---|---|
| Cursor IDE | false | Application | affected |

### Version (1)

| version_string |
|---|
| 1.3 |

**Notes / investigate**

- Vulnerability hygiene **good**: one row `CVE-2025-54136` only — correctly no CurXecute bleed from Dark Reading #3. Title OK; description empty despite CPR having a clear write-up.
- Attacks: **Code Injection** OK for command swap in MCP config; **Command Injection** overlaps / empty. **Social Engineering** for the harmless first commit is a stretch — mechanism is trust-on-name, not classic SE.
- Impacts: **RCE** + **Persistence** on-target; **Arbitrary Code Execution** ≈ RCE dupe; **Privilege Escalation** thin / empty.
- Software **Cursor IDE** `affected` right product, but `is_ai=false` is wrong (AI IDE). No Vendor (Cursor / Check Point). Version `1.3` is the **fix**, not affected-before.

**Thoughts**

- Cleaner than Dark Reading #3 on CVE identity (single finding) — crawl recovered and stayed on-story.
- Biggest concrete bug: `is_ai=false` on Cursor IDE; next is empty vuln description + fix-only Version.
- Prefer 1–2 Attacks (Code Injection ± Supply Chain) and 2 Impacts (RCE, Persistence) with descriptions filled.

---

## 10. MCP “by design” STDIO RCE — OX Security / THN

**URL:** https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html

OX Security: Anthropic MCP STDIO config→OS command defaults are unsafe “by design”; cascades into many downstream CVEs (LiteLLM, LangChain, Flowise, …) plus related-family ids (MCP Inspector, LibreChat, Cursor MCPoison, …).

**Pipeline:** 36 entities · previewed 2026-08-07T16:39:08 · merged 2026-08-07T21:29:06

### Vulnerability (15)

| vuln_id |
|---|
| CVE-2025-65720 |
| CVE-2026-30623 |
| CVE-2026-30624 |
| CVE-2026-30618 |
| CVE-2026-33224 |
| CVE-2026-30617 |
| CVE-2026-30625 |
| CVE-2026-30615 |
| CVE-2026-26015 |
| CVE-2026-40933 |
| CVE-2025-49596 |
| CVE-2026-22252 |
| CVE-2026-22688 |
| CVE-2025-54994 |
| CVE-2025-54136 |

### Attack (2)

| name | description |
|---|---|
| Command Injection | Unauthenticated and authenticated command injection via MCP STDIO, configuration edit through zero-click prompt injection, or via marketplaces. |
| Prompt Injection | Unauthenticated command injection via MCP configuration edit through zero-click prompt injection. |

### Impact (2)

| name | description |
|---|---|
| Remote Code Execution | Enables Arbitrary Command Execution (RCE) on any system running a vulnerable MCP implementation. |
| Information Disclosure | Granting attackers direct access to sensitive user data, internal databases, API keys, and chat histories. |

### Vendor (1)

| name |
|---|
| Anthropic |

### Software (16)

| name | is_ai | software_type | role |
|---|---|---|---|
| Model Context Protocol (MCP) | true | Library | affected |
| MCP SDK | true | Library | affected |
| LiteLLM | true | Library | affected |
| LangChain | true | Library | affected |
| LangFlow | true | Application | affected |
| Flowise | true | Application | affected |
| LettaAI | true | Application | affected |
| LangBot | true | Application | affected |
| Model Context Protocol | true | Library | affected |
| MCP Inspector | true | Application | affected |
| LibreChat | true | Application | affected |
| WeKnora | false | Application | affected |
| @akoskm/create-mcp-server-stdio | true | Library | affected |
| Cursor | true | Application | affected |
| Burp | false | Application | tool |
| sqlmap | false | Application | tool |

**Notes / investigate**

- Overall pretty solid for a THN supply-chain bundle.
- 15 CVE ids harvested; titles/descriptions empty on every Vulnerability row.
- Missing many CVE↔product links from the page (GPT Researcher, Agent Zero, Fay, DocsGPT, Windsurf, …); MCP name duplicated; Burp/sqlmap are page chrome as `tool`.
- No separate narrative “MCP STDIO by design” finding — only the CVE list.

**Thoughts**

- Agree it’s solid **relative to how hard this page is**: Attack (Command Injection + PI) and Impact (RCE + Info Disclosure) match OX’s framing; Anthropic + MCP SDK / several named apps landed; CVE recall is the best in the queue.
- Weaknesses are thin vuln shells (id-only) and incomplete Software map — ids without product/title make the graph hard to use, even if the count looks great.
- For Track A scoring: treat as a **pass on coverage**, not a gold fixture for attribute quality. EchoLeak-class page, much better digression hygiene than EchoLeak (no SharePoint sidebar CVE).

---

## Track A trends (from this queue)

9 scored extracts + 1 hard fail (#5 Semantic Kernel). Enough to steer prompt/pipeline work; not enough for statistical claims until we re-run a fixed prompt on the same URLs.

### What it can do

- Land the **headline story** on clean single-product pages (ClaudeBleed, Bleeding Llama, CPR MCPoison).
- Pull **CVE ids** well when listed (#4 three CVEs, #10 fifteen ids).
- Get **Vendor / primary Software / role=affected** right when the page is focused.
- Reasonable **Attack + Impact names** for the main mechanism (Indirect PI, RCE, Credential Theft, Persistence).

### What it can’t / doesn’t do reliably

- **Attribute fill**: `description`, `date_published`, `cvss_*` often empty even when present in markdown (#1, #3 CurXecute, #4, #6, #9, #10).
- **Stay on-story** on news bundles (#2 EchoLeak digression → GitHub/MCP as `affected`).
- **Attack/Impact discipline**: glossary bleed, enum misfires (Model Extraction, Data Poisoning), empty-description noise, RCE≈ACE / Disclosure≈Exfil / Credential Theft≈Disclosure dupes.
- **Software identity**: product name splits (Copilot×2, Git MCP×3), protocol-as-product (MCP `affected`), remediation aliases (“security review agent”).
- **Version framing**: fix version alone (`1.3`, `0.17.1`) vs `prior to …`.
- **Vulnerability cardinality**: oversplit minted rows (#7 three AISC, #8 remediation-as-vuln).
- **Hard pages**: #5 Semantic Kernel almost empty — crawl/extract failure, not a soft miss.

### Where it’s bad (ranked)

1. Optional vuln attrs dropped despite being in text
2. Extra Attack/Impact/Software from digressions, glossaries, remediation notes
3. Name/role hygiene (dupes, `is_ai` flips, MCP-as-affected)
4. Occasional full-page failure (#5)

### Improve next (highest leverage)

1. Prompt: “only fill attrs present in text; prefer fewer entities with descriptions; don’t emit glossary/remediation as Attack/Vuln.”
2. Post-filters: collapse RCE/ACE, Disclosure/Exfil when same evidence; drop empty-description Attack noise; demote digression Software to `mentioned`.
3. Version: prefer `affected before X` / don’t emit fix-only without framing.
4. Re-test crawl on microsoft.com (#5) before trusting MS blogs.
5. Prefer clean advisory pages as gold fixtures; keep THN bundles as stress tests only.

---

## Track A regression eval (fixture gold)

Single run: `python -m extract_eval.regression.evaluate_regression` from `query_engine/` (source=fixture, model=default).  
#5 Semantic Kernel not in suite. Scores are vs `extract_eval/regression/gold.yaml` — not the same as the earlier manual DB preview notes.

### Suite (micro)

| class | P | R | F1 | tp | fp | fn |
|---|---:|---:|---:|---:|---:|---:|
| Vulnerability | 0.929 | 1.000 | 0.963 | 13 | 1 | 0 |
| Vendor | 1.000 | 0.750 | 0.857 | 9 | 0 | 3 |
| Software | 0.722 | 0.929 | 0.813 | 13 | 5 | 1 |
| Attack | 0.636 | 0.778 | 0.700 | 7 | 4 | 2 |
| Impact | 0.765 | 0.867 | 0.812 | 13 | 4 | 2 |
| **OVERALL** | **0.797** | **0.873** | **0.833** | **55** | **14** | **8** |

### Per URL (overall P/R/F1 only)

This console dump has **one micro score per doc** across headline classes — **not** per-class (Vuln/Vendor/…) breakdowns per URL. Those live in `--out report.json` → `per_doc.<id>.by_class` (tp/fp/fn, missed, false_positives).

| # | doc id | URL | P | R | F1 |
|---|---|---|---:|---:|---:|
| 1 | securityweek-vulnerability-in-claude | https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/ | 1.000 | 1.000 | 1.000 |
| 2 | thehackernews-zero-click-ai | https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html | 0.818 | 0.818 | 0.818 |
| 3 | darkreading-rce-flaw-in | https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk | 0.667 | 0.800 | 0.727 |
| 4 | theregister-anthropic-quietly-fixed | https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059 | 0.778 | 1.000 | 0.875 |
| 6 | securityweek-critical-bug-could | https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ | 0.750 | 0.600 | 0.667 |
| 7 | theregister-google-fixes-cvss | https://www.theregister.com/patches/2026/04/30/google-fixes-cvss-100-vulnerability-in-gemini-cli/5225768 | 0.800 | 1.000 | 0.889 |
| 8 | securityweek-claude-code-gemini | https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ | 0.750 | 1.000 | 0.857 |
| 9 | research-cursor-vulnerability-mcpoison | https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/ | 0.833 | 0.714 | 0.769 |
| 10 | thehackernews-anthropic-mcp-design | https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html | 0.800 | 0.889 | 0.842 |

**Read of this run (suite-level classes, not per-URL):** Vuln strongest; Attack weakest (precision); Vendor misses are recall-only (3 FN, 0 FP); Software/Impact middle with extra entities as FP.

**To get class-by-class per URL next time:**

```bash
python -m extract_eval.regression.evaluate_regression --out track_a_report.json
```
