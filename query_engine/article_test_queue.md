# Article test queue — vulnerability briefs

Short explanations of each article/URL we extract for Track A testing (pipeline quality, not CWE validate).

---

## 1. ClaudeBleed — Claude Chrome extension agent takeover

**URL:** https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/

**What it is:** A design/implementation flaw in **Anthropic’s Claude extension for Chrome** (reported by **LayerX**, May 2026). The extension trusts the *origin* of a command (e.g. `claude.ai`) instead of the *execution context*, and is lax about which scripts can talk to it. A **zero-permission** malicious Chrome extension can inject prompts and drive Claude’s agent actions (read Gmail/GitHub/Drive, send mail, share docs). User-confirmation guards can be bypassed (forged confirmations, DOM tricks). Anthropic’s partial fix still left a “privileged mode” bypass.

**How the attack works (plain English):**

Chrome extensions and pages talk to each other with messages. Claude’s extension is supposed to only obey **trusted** callers. LayerX’s point:

1. **Wrong trust check** — Claude-in-Chrome asks “did this come from the `claude.ai` *origin*?” not “is this really Claude’s own code / a safe *context*?” Anything running *as if* it were on `claude.ai` looks trusted.
2. **Malicious extension rides that** — Attacker ships a normal-looking Chrome extension with a **content script** set to run in the page’s **main world** (same JS environment as the site). On a `claude.ai` tab, that script is treated as part of the page origin.
3. **Prompt injection into the agent** — The script messages Claude’s extension. Claude accepts and **forwards arbitrary prompts**, so the attacker steers the AI agent (open mail, pull files, act on the user’s behalf) without the user typing those prompts.

So it’s not “hack Claude’s model weights” — it’s **abuse the browser extension’s trust boundary** so a low-privilege extension inherits Claude’s high-privilege agent powers. “Remote prompt injection” here means injecting instructions *into Claude via that message channel*, not via an email RAG path like EchoLeak.

**Official id:** None required on the page (often **narrative-only** → pipeline may mint `AISC-…`). Sometimes discussed without a CVE.

**Why it matters for us:** Classic **AI-agent / browser-extension** story: Attack → Vulnerability → Impact (takeover, data theft), with clear Software (Claude for Chrome) and Vendor (Anthropic). Richest gold fixture in the eval suite (`securityweek-vulnerability-in-claude`) with CWEs like origin validation / access control / LLM prompt neutralization — but Track A ignores CWE mapping.

**Extract should center on:** Claude Chrome extension, Anthropic, prompt injection / extension abuse / origin-vs-context trust failure, agent takeover / data exfil. Side “related” links on the page are noise.

### Run notes (2026-08-06) — preview only

| Class | Score | What we got |
|--------|--------|-------------|
| Vulnerability | **good** | `AISC-2026-39B822`, title ClaudeBleed, `_minted_id=yes`; description empty (small miss) |
| Vendor | **good** | Anthropic only |
| Software | **good** | Claude extension for Chrome, AI / Agent / affected — single product |
| Attack | **good** | Indirect Prompt Injection (wording a bit EchoLeak-ish, mechanism OK) |
| Impact | **good–messy** | Information Disclosure, Data Exfiltration; Instruction Override vague |

**Worst stage:** none major — stayed on main story (no Related-link bleed). Cleaner than EchoLeak.

---

## 2. EchoLeak — Microsoft 365 Copilot zero-click data exfil

**URL:** https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html

**What it is:** **CVE-2025-32711** (CVSS ~9.3), dubbed **EchoLeak**, found by **Aim Security**. An attacker sends a normal-looking email that embeds a malicious prompt. When the employee later asks **Microsoft 365 Copilot** something business-related, Copilot’s **RAG** path mixes that **untrusted** email with **privileged** internal context (**LLM scope violation** / indirect prompt injection). Sensitive data from the Copilot context can leak out (e.g. via Teams/SharePoint-style URLs) **without the user clicking** the malicious mail. Microsoft patched server-side; no evidence of in-the-wild abuse.

**Official id:** `CVE-2025-32711` (ID-backed, not narrative-only).

**Why it matters for us:** Clean **ID + AI product** story: Microsoft / M365 Copilot / indirect prompt injection / data exfiltration. Good contrast to ClaudeBleed (which may lack a CVE).

**Hard edge case:** The same THN article also wanders into **MCP tool poisoning**, GitHub MCP “toxic agent flow,” and **MCP DNS rebinding**. Those are **separate** research threads. A good extract keeps **EchoLeak / CVE-2025-32711** as the main Vulnerability; a messy one promotes every digression to equal vulns.

**Extract should center on:** CVE-2025-32711, Microsoft, M365 Copilot (`is_ai=true`), indirect prompt injection / scope violation, data exfiltration. Outlook/Teams/SharePoint as context is optional.

### Run notes (2026-08-06) — 14 entities

| Class | Score | What we got |
|--------|--------|-------------|
| Vulnerability | **good** | `CVE-2025-32711` EchoLeak, CRITICAL 9.3, solid description |
| Vendor | **messy** | Microsoft ✓; GitHub only from MCP digression |
| Software | **messy** | M365 Copilot + duplicate “Copilot”; MCP / GitHub MCP marked `affected` |
| Attack | **messy** | Indirect Prompt Injection ✓; Command Injection / Phishing / Social Engineering noisy |
| Impact | **messy** | Info Disclosure + Data Exfiltration (same idea twice) |

**Worst stage:** LLM extract (over-includes digressions; weak Attack names; product name split). Crawl/id look fine.

#### Is MCP really a “side track” if the article mentioned it?

Yes — **mentioned ≠ part of this vulnerability’s story.**

- The page is a **news bundle**: headline = EchoLeak; later sections = other MCP research for context/trend.
- Ontology `role` is the lever: `affected` / `tool` for *this* finding vs `mentioned` for background.
- Extracting MCP as Software with `role=mentioned` (or a separate narrative vuln if it has its own id) can be OK.
- Marking MCP / GitHub MCP as **`affected` by CVE-2025-32711** is wrong — that CVE is Copilot’s flaw, not MCP’s.
- So “side track” means **secondary to the primary CVE**, not “the article never said it.”

#### Where should the Copilot duplicate be fixed?

We got two Software rows: **Microsoft 365 Copilot** and **Copilot** (same product, different strings).

| Stage | What happens today | Ideal |
|--------|-------------------|--------|
| **Extract (LLM)** | Often emits both names from the prose | Prefer one canonical name (`Microsoft 365 Copilot`) and aliases in text, not two entities |
| **Merge** | Identity is `Software::<vendor_norm>::<name_norm>` — **exact normalized name**. `copilot` ≠ `microsoft 365 copilot`, so they **do not merge** | Would need alias lists / same-as / smarter product matching (not implemented as name-alias merge today) |
| **Persist / consolidate** | Inserts both rows if both survived | No magic rename; DB keeps what merge handed it |

**Bottom line:** the dupe is mainly an **extract naming** problem; merge only collapses **identical** (vendor+name) keys, not “Copilot” ≈ “Microsoft 365 Copilot.” Fixing it properly = better extract prompt / post-filters / alias table — not “Consolidate will fix it.”

### Queue status update

EchoLeak: **extracted (messy)** — core CVE good; digression + Copilot split.

---

## 3. MCPoison — Cursor MCP trust bypass → silent RCE

**URL:** https://www.darkreading.com/vulnerabilities-threats/rce-flaw-ai-coding-tool-supply-chain-risk

**What it is:** **CVE-2025-54136** (“MCPoison”), found by **Check Point Research**, in **Cursor** (AI coding IDE). Cursor’s MCP setup used a **one-time approval**: the first time you see an MCP entry, you approve it; later changes to that **same named** entry were trusted with **no new prompt**. An attacker with write access to a **shared repo** can:

1. Commit a **harmless** MCP config (e.g. `echo hello`) under a friendly name.  
2. You approve it once.  
3. Later they **swap the command** for something malicious (still the same name).  
4. Next time you open the project / sync, Cursor **runs that command on your machine** — silently, persistently.

Fixed in Cursor **1.3** by requiring re-approval when the config **content** changes, not only when a name is new. Dark Reading frames this as **AI-assisted supply-chain risk** (poison the shared project config → hit every teammate’s laptop).

**Your MCP intuition — close, but MCPoison is even more basic:**

- You’re right that Cursor **trusts** something after you allow it.  
- The bug was: trust stuck to the **entry name**, not the **exact command/args**.  
- This is **not** mainly “MCP tool output gets injected into the model prompt” (that’s **tool poisoning** / prompt injection).  
- MCPoison is **process launch**: Cursor starts the MCP server command you (thought you) approved. After the swap, that command is attacker-controlled **code on your OS** — the LLM doesn’t have to be tricked.

**How someone else changes “your” laptop config:**

The MCP entry usually lives in the **shared git repo** (e.g. `.cursor/mcp.json`), not only in a private local setting.

1. Attacker commits a harmless MCP command → you pull, open Cursor, **approve once**.  
2. They push a later commit that **changes that same named command**.  
3. You `git pull` / sync → the file **on your desktop** updates.  
4. Cursor still trusts the **name** → runs the new command locally.

They don’t remote-hack your machine first — they poison a file you **voluntarily sync**, and Cursor keeps auto-running it. That’s the supply-chain angle.

**Local MCP + what the command can do:**

- Typical PoC = **local** MCP: Cursor on your desktop runs a **start command** for a process on your desktop.  
- That command can be anything your user can run: reverse shell, delete files, steal `~/.aws` / git tokens, etc.  
- You did **not** need to “install” separate malware from an app store — you approved a **config line** that says how to start the server; after the git edit, that line became the payload.  
- Reverse shell = one demo (dial out, give attacker a remote terminal). Not the only impact.

**Official id (Dark Reading lead):** `CVE-2025-54136` (MCPoison). The same Cursor/MCP story family often also cites **CurXecute** `CVE-2025-54135` — different bug; see below.

### MCPoison vs CurXecute (don’t mix them)

| | **MCPoison** `CVE-2025-54136` | **CurXecute** `CVE-2025-54135` |
|---|---|---|
| Core idea | Trust stuck on MCP **entry name**; git swap of **command** after one approval | **Prompt injection** → agent writes/changes `mcp.json`; Cursor **runs it before you accept/reject** |
| Needs the LLM tricked? | **No** — pure config/process trust | **Yes** — untrusted text (e.g. Slack/MCP data) steers the agent |
| Your earlier intuition | “Approve once, Cursor forever trusts that slot” ≈ **MCPoison** (name, not content) | “Stuff from MCP/untrusted context gets into Cursor and leads to bad MCP/commands” ≈ **CurXecute** |
| Classic impact | Silent local RCE / reverse shell on project open | RCE via agent-written MCP config |

So: you weren’t wrong about the **prompt / untrusted-context → dangerous MCP** path — that’s **CurXecute**. **MCPoison** is the colder supply-chain variant (no model required). Dark Reading’s main headline is MCPoison; extracts often surface both — **prefer two Vulnerability rows** if both CVEs appear.

**Extract should center on / expect:**

| Class | Good extract |
|--------|----------------|
| Vulnerability | Lead: `CVE-2025-54136` MCPoison. If CurXecute present: **second** vuln `CVE-2025-54135` — don’t mash into one id-less blob |
| Vendor | Cursor / Anysphere; Check Point (and/or Aim if CurXecute named) as researcher OK |
| Software | **Cursor** affected; MCP = protocol/feature |
| Attack | MCPoison: config trust bypass / repo command swap. CurXecute: indirect prompt injection → MCP file write |
| Impact | RCE, persistence, credential/data theft, supply-chain hit on developer machines |
| Version | Fixed in Cursor 1.3 if stated |

**Watch for (messy):**
- Treating “MCP” as the vulnerable product instead of Cursor  
- Collapsing MCPoison + CurXecute into one Vulnerability  
- Calling MCPoison “prompt injection” (that label fits **CurXecute** better)  
- Phishing as the main Attack for MCPoison  

### Run notes (2026-08-06) — 16 entities, preview only

| Class | Score | What we got |
|--------|--------|-------------|
| Vulnerability | **good** | Both CVEs as separate rows: `CVE-2025-54136` MCPoison (decent description) + `CVE-2025-54135` CurXecute (title only — thin) |
| Software | **messy** | Cursor ✓ `affected`; **MCP** also `affected` / AI Component — protocol treated like a product |
| Version | **messy** | `1.3` alone — that’s the **fix**, not “affected &lt; 1.3”; easy to misread |
| Attack | **messy** | Supply Chain Attack ✓ for MCPoison; Prompt Injection fits CurXecute; Code Injection / Data Poisoning vague or wrong label |
| Impact | **messy** | RCE + Persistence + Credential Theft on-target; Privilege Escalation / Model Manipulation / Info Disclosure noisy or overlapping (7 impacts is a lot) |
| Vendor | **miss** | No Cursor/Anysphere or Check Point row |

**Worst stage:** extract labeling — right CVE split, but MCP-as-affected, fix version as Version entity, impact sprawl.

**Overall:** better than EchoLeak on vuln ids (kept MCPoison ≠ CurXecute); messier than ClaudeBleed on Software/Impact discipline.

---

## 4. Anthropic `mcp-server-git` — three CVEs chained with Filesystem MCP → RCE

**URL:** https://www.theregister.com/security/2026/01/20/anthropic-quietly-fixed-flaws-in-its-git-mcp-server/4676059  
(alt slug: https://www.theregister.com/2026/01/20/anthropic_prompt_injection_flaws/)

**What it is (plain English):**  
Anthropic’s official **Git MCP server** (`mcp-server-git`) lets AI tools (Copilot, Claude, Cursor, …) talk to Git/GitHub in natural language. **Cyata** found **three bugs** that look limited alone but **chain** with the **Filesystem MCP server** into **RCE**, kicked off by **indirect prompt injection** (malicious README / webpage / GitHub issue the IDE reads).

| CVE | Flaw | Plain meaning |
|-----|------|----------------|
| **CVE-2025-68145** | Path validation bypass (`--repository`) | Meant to stay inside one repo path; later calls could reach **any** repo on the machine |
| **CVE-2025-68143** | Unrestricted `git_init` | Could turn **any directory** into a git repo. Fix: Anthropic **removed** `git_init` |
| **CVE-2025-68144** | Arg injection in `git_diff` / checkout | Unsanitized args → e.g. `--output=…` to **overwrite/delete files** |

**Attack chain (“toxic combination”):**  
1. Indirect prompt injection steers the agent.  
2. Abuse `git_init` / path bypass to get a writable git repo.  
3. **Filesystem MCP** writes a bash payload and poisons `.git/config` + `.gitattributes` with Git **clean/smudge filters** (`clean/smudge = sh exploit.sh`).  
4. Those filters run on git ops → **shell executes → RCE**.

Fixed in `mcp-server-git` **≥ 2025.12.18** (reported Jun, fixed Dec; Register Jan 2026). No known in-the-wild use. Cyata’s point: don’t review each MCP in isolation — **Git + Filesystem** expands the blast radius.

**vs Cursor MCPoison / CurXecute:** those are mostly **Cursor’s MCP config trust**. This is bugs **inside Anthropic’s Git MCP server**, plus chaining another MCP — agentic **composition** risk.

**Extract should center on / expect:**

| Class | Good extract |
|--------|----------------|
| Vulnerability | **Three** rows: `CVE-2025-68145`, `CVE-2025-68143`, `CVE-2025-68144` |
| Vendor | **Anthropic**; **Cyata** as researcher OK |
| Software | **mcp-server-git** / Git MCP server, `role=affected`. Clients (Claude/Cursor/Copilot) = `mentioned` unless story says they’re the buggy component. **Filesystem MCP** = chained tool (`tool` / mentioned), not the primary patched product |
| Attack | Indirect prompt injection; MCP tool chaining; git smudge/clean filter abuse |
| Impact | RCE; arbitrary file overwrite/delete; repo path escape |
| Version | Affected **before 2025.12.18** — don’t only emit the fix version with no “affected” framing |

**Watch for (messy):** one vague “MCP RCE”; generic “MCP” as affected product; Register sidebar stories as equal vulns; collapsing into Cursor MCPoison/CurXecute.

### Run notes (2026-08-06) — 23 entities, preview only

| Class | Score | What we got |
|--------|--------|-------------|
| Vulnerability | **good** | All three CVEs as separate rows with sensible titles; descriptions empty (small miss) |
| Vendor | **good–messy** | Anthropic ✓; Cyata researcher missing |
| Software | **messy** | Right family (Git MCP / mcp-server-git) but **duplicated 3–4 ways** + generic MCP + Claude Code + Git all `affected` |
| Version | **good** | `prior to 2025.12.18` — correct affected framing (better than Cursor “1.3” fix-only) |
| Attack | **messy** | Indirect Prompt Injection ✓ (and the article’s direct vs indirect gloss); generic Prompt Injection + Code Injection overlap; Argument Injection fits 68144 |
| Impact | **messy** | RCE / file overwrite / deletion / repo access on-target; Instruction Override is attack-shaped; Arbitrary File Overwrite ≈ File Overwrite dupe |

**Worst stage:** Software identity — one product split into Git MCP server / mcp-server-git / MCP server / MCP library / Claude Code / Git.

**Overall:** **best CVE hygiene so far** (3 clean ids). Software sprawl like EchoLeak/MCP-as-product pattern.

---

## 5. Semantic Kernel — prompts → shells (Microsoft Defender Research)

**URL:** https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

**What it is (plain English):**  
Microsoft Defender researchers show how **AI agent frameworks** turn **prompt injection** into **host RCE**. The model isn’t broken — it maps language → tool calls as designed. The bug is **framework/tools trusting those parameters**. Case study: **Microsoft Semantic Kernel**. Two fixed CVEs:

| CVE | Where | What goes wrong |
|-----|--------|------------------|
| **CVE-2026-26030** | Python SK — **In-Memory Vector Store** search filter | Default filter builds a `lambda` via string formatting → **`eval()`**. Model-controlled args → injection. AST blocklist bypassable. Demo: one prompt → `calc.exe`. Needs prompt-injection vector + Search Plugin on default In-Memory store. **Fix: `semantic-kernel` ≥ 1.39.4** |
| **CVE-2026-25592** | **.NET** SK — **SessionsPythonPlugin** | Sandbox (Azure Container Apps) escape: `DownloadFileAsync` wrongly exposed as `[KernelFunction]` so the model picks **any host path** for write. Chain: build payload in container → download to Windows **Startup** → RCE on login. Related unsafe upload → host file **read**. **Fix: .NET SDK ≥ 1.71.0** |

**Big lesson:** not LLM bugs — **agent/tool design**. Same family as MCP stories, but vulnerable product = **Semantic Kernel** (framework), not Cursor config or `mcp-server-git`.

**Page noise:** LangChain/CrewAI (series teaser), CTF, hunting KQL, related blogs (ClickFix, ChainDrop) — don’t promote to equal main vulns.

**Extract should center on / expect:**

| Class | Good extract |
|--------|----------------|
| Vulnerability | **Two** rows: `CVE-2026-26030` + `CVE-2026-25592` with distinct mechanisms |
| Vendor | **Microsoft** |
| Software | **Semantic Kernel** / `semantic-kernel`, `is_ai=true`, `role=affected`. Optional components: In-Memory Vector Store, SessionsPythonPlugin. LangChain/CrewAI = `mentioned` only |
| Attack | Prompt injection / tool-argument injection; optional AST bypass, sandbox escape |
| Impact | RCE; arbitrary file write; file read / credential exfil; persistence (Startup) |
| Version | Affected Python **&lt; 1.39.4**, .NET **&lt; 1.71.0** — not only the fixed version alone |

**Watch for (messy):** one mushy SK RCE; “AI agents”/Defender/calc.exe as Software; LangChain as affected; related-post supply-chain stories; Version = only `1.39.4` like Cursor `1.3` footgun.

---

## Quick compare

| | ClaudeBleed | EchoLeak | MCPoison / CurXecute | Git MCP (Cyata) | Semantic Kernel |
|---|-------------|----------|----------------------|-----------------|-----------------|
| Product | Claude Chrome extension | M365 Copilot | Cursor IDE | Anthropic `mcp-server-git` | Microsoft Semantic Kernel |
| Vendor | Anthropic | Microsoft | Cursor / Anysphere | Anthropic | Microsoft |
| Style | Extension origin trust | Email + RAG scope violation | MCP name trust / agent writes mcp.json | Git MCP × Filesystem + PI | Framework tool sinks: `eval` filter + host file write |
| Id | Often `AISC-…` | `CVE-2025-32711` | `CVE-2025-54136` / `54135` | `CVE-2025-68145` / `68143` / `68144` | `CVE-2026-26030` / `CVE-2026-25592` |
| Researcher | LayerX | Aim Security | Check Point (+ Aim) | Cyata | MS Defender Research |

---

## How we use this list

1. Track A: `python scripts/reset_kb.py -y` → restart Flask (optional if not consolidating).
2. **Extract only — do not Consolidate/merge.** Preview tables are enough for scoring; skip persist / `build_rdf` / graph so findings aren’t filtered by DB/CWE and URLs stay independent.
3. Skim **entity tables** per URL → score good / messy / bad; note worst stage.
4. Append new URLs below as mentors send more articles.

### Queue status

| # | Name | Status |
|---|------|--------|
| 1 | ClaudeBleed | extracted (**clean**) — preview only |
| 2 | EchoLeak | extracted (messy) — preview only |
| 3 | MCPoison (Dark Reading / Cursor MCP) | extracted (**mixed**) — preview only; both CVEs kept separate |
| 4 | Anthropic Git MCP (`mcp-server-git` / Cyata) | extracted (**mixed–good** on CVEs) — preview only; Software sprawl |
| 5 | Semantic Kernel (MS prompts→shells) | queued |
