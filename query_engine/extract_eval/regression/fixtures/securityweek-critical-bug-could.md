# Critical Bug Could Expose 300,000 Ollama Deployments to Information Theft
Dubbed Bleeding Llama, the heap out-of-bounds read issue can be exploited remotely, without authentication.
![](https://www.securityweek.com/wp-content/uploads/2023/10/Iounut-SecurityWeek.jpg)
By
[Ionut Arghire](https://www.securityweek.com/contributors/ionut-arghire/)
| May 5, 2026 (8:39 AM ET) 
[ ](https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ "Share on Facebook") [ ](https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ "Tweet This Post")
  * [
    * Flipboard ](https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ "Share on Flipboard") [
    * Reddit ](https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/ "Share on Reddit") [
    * Whatsapp ](https://web.whatsapp.com/send?text=Critical%20Bug%20Could%20Expose%20300,000%20Ollama%20Deployments%20to%20Information%20Theft%20https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/) [
    * Whatsapp ](whatsapp://send?text=Critical%20Bug%20Could%20Expose%20300,000%20Ollama%20Deployments%20to%20Information%20Theft%20https://www.securityweek.com/critical-bug-could-expose-300000-ollama-deployments-to-information-theft/)
    * Email

![Llama Ollama vulnerability](https://www.securityweek.com/wp-content/uploads/2024/05/llama-drama-.jpg)
**Roughly 300,000 Ollama deployments are prone to sensitive information theft through a remotely exploitable, unauthenticated critical vulnerability, Cyera warns.**
Ollama is an open source solution for running LLMs on local machines and is highly popular among organizations as a self-hosted AI inference engine. 
A heap out-of-bounds read issue in Ollama could be exploited to access sensitive information stored on the heap, including prompts, messages, and environment variables, including API keys, tokens, and secrets, Cyera says. 
Tracked as [CVE-2026-7482](https://nvd.nist.gov/vuln/detail/CVE-2026-7482) (CVSS score of 9.3) and dubbed [Bleeding Llama](https://www.cyera.com/research/bleeding-llama-critical-unauthenticated-memory-leak-in-ollama), the bug affects the GGUF model loader, which accepts an attacker-supplied GGUF file containing a declared tensor offset and size larger than the file’s length. 
When processing the file, the sensor reads past the allocated heap buffer, accessing memory that may contain sensitive information. 
“The attacker then leverages Ollama’s built-in model push feature to exfiltrate the resulting file – complete with stolen heap data – to an attacker-controlled server. The entire attack requires only three unauthenticated API calls,” Cyera says.
Advertisement. Scroll to continue reading.
The cybersecurity firm explains that Ollama launches by default without authentication, and that it listens to all network interfaces, meaning that all internet-accessible instances are prone to exploitation. 
“With approximately 300,000 Ollama servers currently exposed on the public internet, this vulnerability is immediately and broadly exploitable – no credentials required,” Cyera warns. 
Depending on how Ollama is used, successful exploitation of Bleeding Llama could expose employee interactions, development code, routed tool outputs, and prompts containing PII, PHI, and other sensitive information. 
According to Cyera, “any deployment where Ollama is network-accessible without a firewall or authentication proxy in front of it” is at risk of exploitation. 
The vulnerability was addressed in Ollama version 0.17.1. Organizations are advised to apply the fix as soon as possible and restrict network access to their deployments. Deploying an authentication proxy and network segmentation should improve security. 
Organizations should also audit running instances for internet exposure and consider any instance accessible from the internet, as well as the environment variables and data passing through it, to be compromised. 
**Related:** [MetInfo, Weaver E-cology Vulnerabilities in Attackers’ Crosshairs](https://www.securityweek.com/metinfo-weaver-e-cology-vulnerabilities-in-attackers-crosshairs/)
**Related:** [WhatsApp Discloses File Spoofing, Arbitrary URL Scheme Vulnerabilities](https://www.securityweek.com/whatsapp-discloses-file-spoofing-arbitrary-url-scheme-vulnerabilities/)
**Related:** [Firefox Vulnerability Allows Tor User Fingerprinting](https://www.securityweek.com/firefox-vulnerability-allows-tor-user-fingerprinting/)
**Related:** [Apple Patches iOS Flaw Allowing Recovery of Deleted Chats](https://www.securityweek.com/apple-patches-ios-flaw-allowing-recovery-of-deleted-chats/)
![](https://www.securityweek.com/wp-content/uploads/2023/10/Iounut-SecurityWeek.jpg)
Written By [Ionut Arghire](https://www.securityweek.com/contributors/ionut-arghire/)
Ionut Arghire is an international correspondent for SecurityWeek.
[](https://twitter.com/IonutArghire)
## Daily Briefing Newsletter
Subscribe to the SecurityWeek Email Briefing for the latest cybersecurity threats, trends, and expert insights.