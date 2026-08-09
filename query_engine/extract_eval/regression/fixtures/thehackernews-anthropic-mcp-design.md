# [Anthropic MCP Design Vulnerability Enables RCE, Threatening AI Supply Chain](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
__ Ravie Lakshmanan __ Apr 20, 2026Artificial Intelligence / Vulnerability
[![](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjbUnokdbuoiv9j36ekgZbT7VQVSUJBbB4xzoXJKD8iTTO76tSRyhXGdOk2aZKX-RU_WeGyRzHfAf0zwva_cSY7JL5a7Fhmrtzjd-p-kg6JK75nE-nQiSESaDAHlyTN8be1iUFxp9xCq94-1JwZ16pwYZJkKxIFwqa8vNmfxZl8OCXRWnT0GKWOpYVPgbMb/s1700-e365/mcp.jpg)
Cybersecurity researchers have discovered a critical "by design" weakness in the Model Context Protocol's ([MCP](https://thehackernews.com/2025/04/experts-uncover-critical-mcp-and-a2a.html)) architecture that could pave the way for remote code execution and have a cascading effect on the artificial intelligence (AI) supply chain.
"This flaw enables Arbitrary Command Execution (RCE) on any system running a vulnerable MCP implementation, granting attackers direct access to sensitive user data, internal databases, API keys, and chat histories," OX Security researchers Moshe Siman Tov Bustan, Mustafa Naamnih, Nir Zadok, and Roni Bar [said](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) in an analysis published last week.
The cybersecurity company said the systemic vulnerability is baked into Anthropic's official MCP software development kit (SDK) across any supported language, including Python, TypeScript, Java, and Rust. In all, it affects more than 7,000 publicly accessible servers and software packages totaling more than 150 million downloads.
[![Cybersecurity](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)](https://thehackernews.uk/threatlocker-d)
At issue are unsafe defaults in how MCP configuration works over the [STDIO](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) (standard input/output) transport interface, resulting in the discovery of 10 vulnerabilities spanning popular projects like LiteLLM, LangChain, LangFlow, Flowise, LettaAI, and LangBot -
  * CVE-2025-65720 (GPT Researcher)
  * CVE-2026-30623 (LiteLLM) - Patched
  * CVE-2026-30624 (Agent Zero)
  * CVE-2026-30618 (Fay Framework)
  * CVE-2026-33224 (Bisheng) - Patched
  * CVE-2026-30617 (Langchain-Chatchat)
  * CVE-2026-33224 (Jaaz)
  * CVE-2026-30625 (Upsonic)
  * CVE-2026-30615 (Windsurf)
  * CVE-2026-26015 (DocsGPT) - Patched
  * CVE-2026-40933 (Flowise)

[![](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiAhY4TgSp1qp15G047A5Kd6HlFbTwClDL0e2PtV0irWfvB8U6x7naJ0H8wBDcf7oXRvYh4fAUHi_rjn-UQKWeqtAkHEGZ-JpXKX1Cidpj6f8zvLsWHE45vxP_KUfE0tMfUvDSD7OEa5vRIVWf8tDzCZh_jmbkc6mG3QphEkVBtTTVoMxFjG30jidHyxBfm/s1700-e365/operating.png)
These vulnerabilities fall under four broad categories, effectively triggering remote command execution on the server -
  * Unauthenticated and authenticated command injection via MCP STDIO
  * Unauthenticated command injection via direct STDIO configuration with hardening bypass
  * Unauthenticated command injection via MCP configuration edit through zero-click prompt injection
  * Unauthenticated command injection through MCP marketplaces via network requests, triggering hidden STDIO configurations

"Anthropic's Model Context Protocol gives a direct configuration-to-command execution via their STDIO interface on all of their implementations, regardless of programming language," the researchers explained.
"As this code was meant to be used in order to start a local STDIO server, and give a handle of the STDIO back to the LLM. But in practice it actually lets anyone run any arbitrary OS command, if the command successfully creates an STDIO server it will return the handle, but when given a different command, it returns an error after the command is executed."
[![Cybersecurity](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)](https://thehackernews.uk/corelight-d)
Interestingly, vulnerabilities based on the same core issue have been reported independently over the past year. They include [CVE-2025-49596](https://thehackernews.com/2025/07/critical-vulnerability-in-anthropics.html) (MCP Inspector), CVE-2026-22252 (LibreChat), CVE-2026-22688 (WeKnora), CVE-2025-54994 (@akoskm/create-mcp-server-stdio), and CVE-2025-54136 (Cursor).
Anthropic, however, has declined to modify the protocol's architecture, citing the behavior as "expected." While some of the vendors have issued patches, the shortcoming remains unaddressed in Anthropic's MCP reference implementation, causing developers to inherit the code execution risks.
The findings highlight how AI-powered integrations can inadvertently expand the attack surface. To counter the threat, it's advised to block public IP access to sensitive services, monitor MCP tool invocations, run MCP-enabled services in a sandbox, treat external MCP configuration input as untrusted, and only install MCP servers from verified sources.
"What made this a supply chain event rather than a single CVE is that one architectural decision, made once, propagated silently into every language, every downstream library, and every project that trusted the protocol to be what it appeared to be," OX Security said. "Shifting responsibility to implementers does not transfer the risk. It just obscures who created it."
Found this article interesting? Follow us on [Google News](https://news.google.com/publications/CAAqLQgKIidDQklTRndnTWFoTUtFWFJvWldoaFkydGxjbTVsZDNNdVkyOXRLQUFQAQ), [Twitter](https://twitter.com/thehackersnews) and [LinkedIn](https://www.linkedin.com/company/thehackernews/) to read more exclusive content we post.
SHARE [__](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__](javascript:void\(0\))
[__ Tweet](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share)
[__ Share](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share)
[__ Share](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share)
__ Share
[__](javascript:void\(0\)) [__ Share on Facebook](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Twitter](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Linkedin](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Reddit](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Email](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on WhatsApp](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [![Facebook Messenger](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)Share on Facebook Messenger](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share) [__ Share on Telegram](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html#link_share)
[SHARE __](javascript:void\(0\))
[Anthropic](https://thehackernews.com/search/label/Anthropic), [Application Security](https://thehackernews.com/search/label/Application%20Security), [artificial intelligence](https://thehackernews.com/search/label/artificial%20intelligence), [Command Injection](https://thehackernews.com/search/label/Command%20Injection), [cybersecurity](https://thehackernews.com/search/label/cybersecurity), [remote code execution](https://thehackernews.com/search/label/remote%20code%20execution), [software development](https://thehackernews.com/search/label/software%20development), [Supply Chain Security](https://thehackernews.com/search/label/Supply%20Chain%20Security), [Vulnerability](https://thehackernews.com/search/label/Vulnerability)
[ ![ad](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhWSe3IK0f3Ulhoiz4ss2sau1v3cN23Y2uCi7SNJ4NY7A-VDHDO8WkdyP1suMZhsxx8i1_KxkKwsdQyH1k905CXwMq_iCy3vm04zA4mlHjEfqOkw9BnsWTVQwWo-_9cLlXRLNrvJNB4MFaJp5o9i-j0po2UKVwZ9zE-HMeVt7FwekOpp4E6CdTZ-_Rq-8uV/s300-e100/wiz-side.png) ](https://thehackernews.uk/wiz-ai-starter)
[ ![ad](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgfCVMloTKWv4wmuBC5NG9cHKUNysLH7IkWaJ4w9RfdNB1iWfNMuQN1txuZbOTm2bxcloM7ZhPnbJRgLFjf75dBTatWiTqGoLoTiAtL2I0V_oVJDPkekRmtWRBJsXGd5XDJIty1UHOyMXxajtVmMH1KN4DefsUX7XV5ALsHeZiT2h3TF16WzBGgtv3blu4H/s300-e100/tl-side.jpg) ](https://thehackernews.uk/zero-trust-control)
⚡ Top Stories This Week
⭐ Featured Resources
## Cybersecurity Webinars
[ Risk in AI-Generated Code How to Secure AI Code Before It Reaches Production Learn how 300 enterprise leaders are managing AI-driven open-source risk, remediation debt, and governance at scale. Register ](https://thehacker.news/ai-coding-risk?source=below) [ Build AI Securely How to Secure AI-Built Software at Machine Speed Learn how to govern risk, secure AI-built software, and keep control as development moves at machine speed. Register ](https://thehacker.news/secure-ai-development?source=below)
⚡ Latest News
Cybersecurity Resources
[![Cybersecurity](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) 11 Real Stories: How Identity Exposure Unlocks Active Attack Paths Map cross-domain privilege escalation to sever breach routes at key choke points.](https://thehackernews.uk/xmcyber-c)[![Cybersecurity](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) SANS AI Cybersecurity Summit Returns This November Learn how practitioners are applying AI to today's cybersecurity challenges.](https://thehackernews.uk/sans-summit-ai)[![Cybersecurity](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) Burp, sqlmap, SSRF, XXE, SSTI: Web Exploitation, Hands-On 35 labs plus a live CTF take you from recon to remote code execution. GWAPT prep, SANS CDI in D.C.](https://thehackernews.uk/cyber-defense-26)​
Expert Insights [Articles](https://thehackernews.com/expert-insights/) [Videos](https://thehackernews.com/videos/)
[ ![Expert Insights](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) How AI-Assisted Attacks Are Breaking Legacy SIEM Tools __ August 3, 2026 Read ➝ ](https://thehackernews.com/expert-insights/2026/08/how-ai-assisted-attacks-are-breaking.html)[ ![Expert Insights](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) A Look Inside Lasso's AI Security Platform __ July 27, 2026 Read ➝ ](https://thehackernews.com/expert-insights/2026/07/a-look-inside-lassos-ai-security.html)[ ![Expert Insights](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) Claude Runs Across Six Surfaces in Your Company. Your Security Team Sees One. __ July 27, 2026 Read ➝ ](https://thehackernews.com/expert-insights/2026/07/claude-runs-across-six-surfaces-in-your.html)[ ![Expert Insights](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) How to Make Social Engineering Unprofitable __ July 22, 2026 Read ➝ ](https://thehackernews.com/expert-insights/2026/07/how-to-make-social-engineering.html)
Get the Latest News in Your Inbox
Get the latest news, expert insights, exclusive resources, and strategies from industry leaders, all for free.
Email
Connect with us!
Company
  * [About THN](https://thehackernews.com/p/about-us.html)
  * [Advertise with us](https://thehackernews.com/p/advertising-with-hacker-news.html)
  * [Contact](https://thehackernews.com/p/submit-news.html)

Pages
© 2026 The Hacker News. All Rights Reserved.