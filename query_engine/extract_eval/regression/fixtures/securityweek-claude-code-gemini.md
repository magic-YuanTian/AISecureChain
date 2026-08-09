# Claude Code, Gemini CLI, GitHub Copilot Agents Vulnerable to Prompt Injection via Comments
A researcher has disclosed the details of the AI attack method he has named ‘Comment and Control’.
![](https://www.securityweek.com/wp-content/uploads/2023/11/Ed-Kovacs.jpg)
By
[Eduard Kovacs](https://www.securityweek.com/contributors/eduard-kovacs/)
| April 16, 2026 (4:33 AM ET) 
  
Updated: April 21, 2026 (2:00 AM ET)
[ ](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ "Share on Facebook") [ ](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ "Tweet This Post")
  * [
    * Flipboard ](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ "Share on Flipboard") [
    * Reddit ](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/ "Share on Reddit") [
    * Whatsapp ](https://web.whatsapp.com/send?text=Claude%20Code,%20Gemini%20CLI,%20GitHub%20Copilot%20Agents%20Vulnerable%20to%20Prompt%20Injection%20via%20Comments%20https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/) [
    * Whatsapp ](whatsapp://send?text=Claude%20Code,%20Gemini%20CLI,%20GitHub%20Copilot%20Agents%20Vulnerable%20to%20Prompt%20Injection%20via%20Comments%20https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/)
    * Email

![AI attack](https://www.securityweek.com/wp-content/uploads/2025/08/AI-assistant-chatbot-artificial-intelligence.jpg)
**A researcher has disclosed the details of a prompt injection attack method named ‘Comment and Control’, which has been found to work against several popular AI code security and automation tools.**
The attack method was discovered by security engineer and vulnerability researcher Aonan Guan, with assistance from Johns Hopkins University researchers Zhengyu Liu and Gavin Zhong. 
In a [blog post](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/) published on Wednesday, Guan said the attack has been confirmed to work against several widely used AI agents: Anthropic’s Claude Code Security Review, Google’s Gemini CLI Action, and GitHub Copilot Agent. 
The researchers found that AI agents associated with these tools on GitHub Actions can be hijacked using specially crafted GitHub comments, including PR titles, comments, and issue bodies. 
In the case of Claude Code Security Review, designed for automated security reviews, the researchers showed how an attacker could use a specially crafted PR title to trick the AI agent into executing arbitrary commands, extracting credentials, and revealing them as a security finding or an entry in the GitHub Actions log. 
For Gemini CLI Action, which acts as an autonomous agent for routine coding tasks, the researchers used an issue comment with a prompt-injection title, along with specially crafted issue comments, to bypass guardrails and obtain a full API key.
Advertisement. Scroll to continue reading.
In the Comment and Control attack aimed at GitHub Copilot Agent, the experts leveraged an HTML comment, which hides the payload, to bypass environment filtering, scan for secrets, and bypass the network firewall. 
The Comment and Control attack can pose a serious threat, as the attacker’s malicious prompt is automatically triggered by GitHub Actions workflows, without any action from the victim — except in the case of Copilot, where the attacker’s issue must be manually assigned to Copilot by the victim. 
“The pattern likely applies to any AI agent that ingests untrusted GitHub data and has access to execution tools in the same runtime as production secrets — and beyond GitHub Actions, to any agent that processes untrusted input with access to tools and secrets: Slack bots, Jira agents, email agents, deployment automation. The injection surface changes, but the pattern is the same,” Guan explained. 
The findings have been reported to Anthropic, Google, and GitHub, and all have confirmed them. Anthropic classified the issue as ‘critical’ and implemented some mitigations, awarding a $100 bug bounty to the researchers. Google paid out a $1,337 bug bounty. 
GitHub awarded the researchers $500, saying that their work “sparked some great internal discussions”, but classified the security issue as a known architectural limitation. 
“This is the first public cross-vendor demonstration of a single prompt injection pattern across three major AI agents. All three vulnerabilities follow the same pattern: untrusted GitHub data → AI agent processes it → agent executes commands → credentials exfiltrated through GitHub itself,” Guan said. 
“The deeper issue is architectural: these AI agents are given powerful tools (bash execution, git push, API calls) and secrets (API keys, tokens) in the same runtime that processes untrusted user input. Even when multiple layers of defense exist — model-level, prompt-level, and GitHub’s additional three runtime layers — they can all be bypassed because the prompt injection here is not a bug; it is context that the agent is designed to process,” he added. 
**UPDATE** : Guan clarified for _SecurityWeek_ that Google addressed the issue by adding new ‘guardrail prompts’ to the system prompt. However, this does not change the underlying threat model or attack scenario, because the capabilities (tools) available to the Gemini agent remain the same. 
For Anthropic, the attack method still works in principle, though the specific payload would need to be updated. The company’s remediation was to disallow one tool (‘ps’) rather than adopting a least privilege approach by granting only the tools needed for the security review. The researcher did not attempt a full bypass after the company’s fix, but the underlying issue — overly broad tool access for a “security review agent” — remains unaddressed. 
**Related** : [‘By Design’ Flaw in MCP Could Enable Widespread AI Supply Chain Attacks](https://www.securityweek.com/by-design-flaw-in-mcp-could-enable-widespread-ai-supply-chain-attacks/)
**Related** : [‘Mythos-Ready’ Security: CSA Urges CISOs to Prepare for Accelerated AI Threats](https://www.securityweek.com/mythos-ready-security-csa-urges-cisos-to-prepare-for-accelerated-ai-threats/)
**Related** : [Apple Intelligence AI Guardrails Bypassed in New Attack](https://www.securityweek.com/apple-intelligence-ai-guardrails-bypassed-in-new-attack/)
![](https://www.securityweek.com/wp-content/uploads/2023/11/Ed-Kovacs.jpg)
Written By [Eduard Kovacs](https://www.securityweek.com/contributors/eduard-kovacs/)
Eduard Kovacs (@EduardKovacs) is senior managing editor at SecurityWeek. He worked as a high school IT teacher before starting a career in journalism in 2011. Eduard holds a bachelor’s degree in industrial informatics and a master’s degree in computer techniques applied in electrical engineering.
[](https://x.com/EduardKovacs)[](https://www.linkedin.com/in/eduard-kovacs-7b796134/)
## Daily Briefing Newsletter
Subscribe to the SecurityWeek Email Briefing for the latest cybersecurity threats, trends, and expert insights.