# Anthropic quietly fixed flaws in its Git MCP server that allowed for remote code execution
Prompt injection for the win
Jessica Lyons [ Jessica Lyons ](https://www.theregister.com/author/jessica-lyons)
Published Tue 20 Jan 2026 // 13:00 UTC
[](https://www.facebook.com/sharer.php?u=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://twitter.com/intent/tweet?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://www.linkedin.com/sharing/share-offsite/?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://bsky.app/intent/compose?text=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server%0Ahttps%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://www.reddit.com/submit?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059&title=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server) [](https://api.whatsapp.com/send?text=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server%0Ahttps%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059)
Anthropic has fixed three bugs in its official Git MCP server that researchers say can be chained with other MCP tools to remotely execute malicious code or overwrite files via prompt injection.
The Git MCP server, mcp-server-git, connects AI tools such as Copilot, Claude, and Cursor to Git repositories and the GitHub platform, allowing them to read repositories and code files, and automate workflows, all using natural language interactions. 
Agentic AI security startup Cyata found a way to exploit the vulnerabilities - a path validation bypass flaw ([CVE-2025-68145](https://github.com/advisories/GHSA-j22h-9j4x-23w5)), an unrestricted git_init issue ([CVE-2025-68143](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v)), and an argument injection in git_diff ([CVE-2025-68144](https://github.com/advisories/GHSA-9xwc-hfwc-8w59)) - and chain the Git MCP server with the Filesystem MCP server to achieve code execution.
REG AD
"Agentic systems break in unexpected ways when multiple components interact. Each MCP server might look safe in isolation, but combine two of them, Git and Filesystem in this case, and you get a toxic combination," Cyata security researcher Yarden Porat told _The Register_ , adding that there's no indication that attackers exploited the bugs in the wild. 
REG AD
"As organizations adopt more complex agentic systems with multiple tools and integrations, these combinations will multiply," Porat said.
Cyata reported the three vulnerabilities to Anthropic in June, and the AI company fixed them in December. The flaws affect default deployments of mcp-server-git prior to 2025.12.18 - so make sure you're using the updated version.
_The Register_ reached out to Anthropic for this story, but the company did not respond to our inquiries.
## There's no S(ecurity) in MCP
In a Tuesday report shared with _The Register_ ahead of publication, Cyata says the issues stem from the way AI systems connect to external data sources. 
In 2024, [Anthropic introduced](https://www.theregister.com/2025/04/21/mcp_guide/) the Model Context Protocol (MCP), an open standard that enables LLMs to interact with these other systems - filesystems, databases, APIs, messaging platforms, and development tools like Git. MCP servers act as the bridge between the model and external sources, providing the AI with access to the data or tools they need.
As we've [seen](https://www.theregister.com/2025/08/20/amazon_quietly_fixed_q_developer_flaws/) [repeatedly](https://www.theregister.com/2025/09/26/salesforce_agentforce_forceleak_attack/) over the [past year](https://www.theregister.com/2025/08/08/infosec_hounds_spot_prompt_injection/), LLMs can be [manipulated](https://www.theregister.com/2026/01/12/block_ai_agent_goose/) into [doing things](https://www.theregister.com/2026/01/08/openai_chatgpt_prompt_injection/) they're [not supposed to do](https://www.theregister.com/2026/01/15/anthropics_claude_bug_cowork/) via [prompt injection](https://www.theregister.com/2025/10/28/ai_browsers_prompt_injection/), which happens when attacker-controlled input causes an AI system to follow unintended instructions. It's a problem that's not going away anytime soon - and [may never](https://www.theregister.com/2025/10/22/openai_defends_atlas_as_prompt/).
There are two types: indirect and direct. Direct prompt injection happens when someone directly submits malicious input, while indirect injection happens when content contains hidden commands that AI then follows as if the user had entered them.
REG AD
## MORE CONTEXT
  * ### [Contagious Claude Code bug Anthropic ignored promptly spreads to Cowork ](https://www.theregister.com/2026/01/15/anthropics_claude_bug_cowork/)
  * ### [Anthropic Claude wants to be your helpful colleague, always looking over your shoulder ](https://www.theregister.com/2026/01/13/anthropic_previews_claude_cowork_for/)
  * ### [Block CISO: We red-teamed our own AI agent to run an infostealer on an employee laptop ](https://www.theregister.com/2026/01/12/block_ai_agent_goose/)
  * ### [Palo Alto Networks security-intel boss calls AI agents 2026's biggest insider threat ](https://www.theregister.com/2026/01/04/ai_agents_insider_threats_panw/)

This attack abuses the three now-fixed vulnerabilities.
CVE-2025-68145: The --repository flag is supposed to restrict the MCP server to a specific repository path. However, the server didn't validate that repo_path arguments in subsequent tool calls within that configured path, thus allowing an attacker to bypass security boundaries and access any repository on the system.
CVE-2025-68143: The git_init tool accepted arbitrary filesystem paths and created Git repositories without any validation, allowing any directory to be turned into a Git repository and eligible for subsequent git operations through the MCP server. To fix this, Anthropic removed the git_init tool from the server.
CVE-2025-68144: The git_diff and git_checkout functions passed user-controlled arguments directly to the GitPython library without sanitization. "By injecting '--output=/path/to/file' into the 'target' field, an attacker could overwrite any file with an empty diff," and delete files, Cyata explained in the report.
## Attack chain
As Porat explained to us, the attack uses indirect prompt injection: "Your IDE reads something malicious, a README file, a webpage, a GitHub issue, somewhere the attacker has planted instructions," he said. 
The vulnerabilities, when combined with the Filesystem MCP server, abuse Git's smudge and clean filters, which execute shell commands defined in repository configuration files, and enable remote code execution.
According to Porat, it's a four-step process:
REG AD
This attack illustrates how, as more AI agents move into production, security has to keep pace. 
At a high level:
  1. Create a Git repository in a writable directory using git_init.
  2. Use the Filesystem MCP server to write a bash script - this is the payload that will execute.
  3. Use the Filesystem MCP server to write to Git's internal config files (.git/config and .gitattributes), setting up "clean" and "smudge" filters. These are a Git feature that basically means: when certain Git operations happen, trigger this script.

The filters look like:
[filter "myfilter"]
clean = sh exploit.sh
smudge = sh exploit.sh
  1. When the clean or smudge filter is triggered, the bash script runs - and the attacker has code execution.

"Security teams can't evaluate each MCP server in a vacuum," Porat said. "They need to assess the effective permissions of the entire agentic system, understand what tools can be chained together, and put controls in place. MCPs expand what agents can do, but they also expand the attack surface. Trust shouldn't be assumed, it needs to be verified and controlled." ®
[patch](https://www.theregister.com/tag/patch) [anthropic](https://www.theregister.com/tag/anthropic) [ai](https://www.theregister.com/tag/ai) [security](https://www.theregister.com/tag/security) [patches](https://www.theregister.com/tag/patches)
[](https://www.facebook.com/sharer.php?u=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://twitter.com/intent/tweet?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://www.linkedin.com/sharing/share-offsite/?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://bsky.app/intent/compose?text=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server%0Ahttps%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059) [](https://www.reddit.com/submit?url=https%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059&title=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server) [](https://api.whatsapp.com/send?text=Anthropic%20quietly%20fixed%20flaws%20in%20its%20Git%20MCP%20server%0Ahttps%3A%2F%2Fwww.theregister.com%2Fsecurity%2F2026%2F01%2F20%2Fanthropic-quietly-fixed-flaws-in-its-git-mcp-server%2F4676059)
REG AD