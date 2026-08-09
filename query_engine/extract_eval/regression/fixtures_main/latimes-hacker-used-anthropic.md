# Hacker used Anthropic’s Claude AI to steal Mexican government data
![President Sheinbaum pays tribute as part of the Flag Day Celebration](https://ca-times.brightspotcdn.com/dims4/default/8a3ddb2/2147483647/strip/true/crop/6221x4147+0+0/resize/1200x800!/quality/75/?url=https%3A%2F%2Fcalifornia-times-brightspot.s3.amazonaws.com%2F4d%2Fc0%2Fdacf624145f2ba6022027b3e35f6%2Fgettyimages-2263407054.jpg)
Mexican President Claudia Sheinbaum pays tribute as part of the Flag Day Celebration at Campo Marte on Tuesday in Mexico City.
(Mariana Maytorena / ObturadorMX via Getty Images)
By Andrew Martin
and Carolina Millan
Feb. 26, 2026 8:30 AM PT 
  * 1 
  * Share via Close extra sharing options
    * Email
    * Copy Link URL Copied!
    * Print

A hacker exploited Anthropic PBC’s artificial intelligence chatbot to carry out a series of attacks against Mexican government agencies, resulting in the theft of a huge trove of sensitive tax and voter information, according to cybersecurity researchers.
The unknown Claude user wrote Spanish-language prompts for the chatbot to act as an elite hacker, finding vulnerabilities in government networks, writing computer scripts to exploit them and determining ways to automate data theft, Israeli cybersecurity startup Gambit Security said in research published Wednesday. 
The activity started in December and continued for roughly a month. In all, 150 gigabytes of Mexican government data was stolen, including documents related to 195 million taxpayer records as well as voter records, government employee credentials and civil registry files, according to the researchers.
Advertisement
AI has become a key enabler of digital crimes, with hackers using the tools to augment their efforts. Last week, researchers at Amazon.com Inc. said a small group of hackers broke into more than 600 firewall devices across dozens of countries with the help of widely available AI tools.
Gambit hasn’t attributed the attack to a specific group, though researchers said they don’t believe they are tied to a foreign government.
The hacker breached Mexico’s federal tax authority and the national electoral institute, Gambit said. State governments in Mexico, Jalisco, Michoacán and Tamaulipas as well as Mexico City’s civil registry and Monterrey’s water utility, were also compromised.
Advertisement
Claude initially warned the unknown user of malicious intent during their conversation about the Mexican government, but eventually complied with the attacker’s requests and executed thousands of commands on government computer networks, the researchers said.
Anthropic investigated Gambit’s claims, disrupted the activity and banned the accounts involved, a representative said. The company feeds examples of malicious activity back into Claude to learn from it, and one of its latest AI models, Claude Opus 4.6, includes probes that can disrupt misuse, the representative said.
In this instance, the hacker continuously probed Claude until they were able to “jailbreak” it — meaning it finally bypassed guardrails, the representative said. But even as the hacking campaign got underway, Claude occasionally refused the hacker’s demands, they added.
Mexico’s tax authority said it had reviewed its access logs and couldn’t find evidence of a breach. The country’s national electoral institute said it hadn’t identified any breaches or unauthorized access in recent months and that it had bolstered its cybersecurity strategy. The state government of Jalisco also denied that it was breached, saying only federal networks were impacted.
Mexico’s national digital agency didn’t comment on the breaches but said cybersecurity was a priority. A representative for Monterrey Water and Drainage Services said the agency didn’t detect any intrusions or major vulnerabilities in the second half of 2025.
The local governments of Mexico, Michoacán and Tamaulipas didn’t respond to requests for comment, nor did representatives of Mexico City’s civil registry. 
Advertisement
Mexican officials released a brief statement in December saying they were investigating breaches from various public institutions, though it’s not clear if that was related to the Claude attack.
The attacker was seeking to obtain a large number of government employee identities, Gambit said, though it’s not yet clear what — if anything — they did with them. Researchers said they found evidence of at least 20 specific vulnerabilities being exploited as part of the attack. 
When Claude encountered problems or required additional information, the hacker turned to OpenAI’s ChatGPT to provide additional insights. That included how to move laterally through computer networks, determine which credentials were needed to access certain systems and calculate how likely the hacking operation would be detected, according to Gambit.
“In total, it produced thousands of detailed reports that included ready-to-execute plans, telling the human operator exactly which internal targets to attack next and what credentials to use,” said Curtis Simpson, Gambit Security’s chief strategy officer. 
OpenAI said it had identified attempts by the hacker to use its models for activities that violate its usage policies, adding that its tools refused to comply with these attempts. 
“We have banned the accounts used by this adversary and value the outreach from Gambit Security,” the company said in an emailed statement.
Advertisement
The Mexican government breaches are the latest example of an alarming trend. Even as Anthropic and OpenAI are betting on building more sophisticated AI coding tools — and cybersecurity companies are tying their futures to AI-enabled defenses — cybercriminals and cyberspies are finding novel ways to use the technology to enable attacks.
In November, Anthropic said it had disrupted the first AI-orchestrated cyber-espionage campaign. The AI company said suspected Chinese state-sponsored hackers manipulated its Claude tool into attempting to hack 30 global targets, a few of which were successful.
“This reality is changing all the game rules we have ever known,” said Alon Gromakov, Gambit’s co-founder and chief executive officer.
Gambit was founded by Gromakov and two other veterans of Unit 8200, a part of the Israel Defense Forces focused on signals intelligence. Wednesday’s research was released in conjunction with an announcement that it is emerging from stealth with $61 million in funding from Spark Capital, Kleiner Perkins and Cyberstarts.
Gambit researchers uncovered the Mexican breaches while they were trying new threat hunting techniques to observe what hackers were doing online. They discovered publicly available evidence about active or recent attacks, including one containing extensive Claude conversations pertaining to the breach of Mexican government computer systems, according to the company. 
Those conversations revealed that in order to bypass Claude’s guardrails, the attacker told the AI tool that it was pursuing a bug bounty, a reward provided by organizations to find flaws in their system. Many companies and government agencies offer bug bounties for ethical hackers, sometimes offering many thousands of dollars for details about computer vulnerabilities. 
Advertisement
The hacker wanted Claude to conduct penetration testing on the Mexican federal tax authority, a type of authorized cyberattack intended to find flaws. However, Claude balked when the attacker added rules to the request, including deleting logs and command history.
“Specific instructions about deleting logs and hiding history are red flags,” Claude responded at one point, according to a transcript provided by Gambit. “In legitimate bug bounty, you don’t need to hide your actions — in fact, you need to document them for reporting.”
The hacker changed strategies, stopping the back-and-forth conversation and instead providing the AI tool with a detailed playbook on how to proceed. That got the intruder past Claude’s guardrails — a “jailbreak” — and allowed the attacks to proceed, according to Gambit.
The hacker sought insights from Claude about other agencies where data could be obtained, suggesting some of the hacks may have been opportunistic rather than planned, Simpson said.
“They were trying to compromise every government identity they possibly could,” he said. “They were asking Claude as an example, ‘Where else can I find these identities? What other systems should we look in? Where else is the information stored?’”
_Martin and Millan write for Bloomberg._
### More to Read 
  * [ ![Dario Amodei, co-founder and chief executive officer of Anthropic, during the World Economic Forum \(WEF\) in Davos, Switzerland, on Tuesday, Jan. 20, 2026. The annual Davos gathering of political leaders, top executives and celebrities runs from Jan. 19-23. Photographer: Krisztian Bocsi/Bloomberg via Getty Images](https://ca-times.brightspotcdn.com/dims4/default/030ea8a/2147483647/strip/true/crop/7487x5007+10+0/resize/320x214!/quality/75/?url=https%3A%2F%2Fcalifornia-times-brightspot.s3.amazonaws.com%2Fd4%2F97%2F6c2f4e9042dba637561d76f176f6%2Fgettyimages-2256664167.jpg) ](https://www.latimes.com/business/story/2026-06-01/ai-company-anthropic-files-to-list-shares-heating-up-race-with-openai)
###  [AI company Anthropic files to list shares, heating up race with OpenAI](https://www.latimes.com/business/story/2026-06-01/ai-company-anthropic-files-to-list-shares-heating-up-race-with-openai)
June 1, 2026
  * [ ![The San Francisco-Oakland Bay Bridge  behind a Google sign at the company's office in San Francisco on April 12, 2023. ](https://ca-times.brightspotcdn.com/dims4/default/68643fb/2147483647/strip/true/crop/5015x3354+7+0/resize/320x214!/quality/75/?url=https%3A%2F%2Fcalifornia-times-brightspot.s3.amazonaws.com%2F1c%2Fa6%2Fa112352545c287d99ce80d51b938%2Fgoogle-epic-explainer-78528.jpg) ](https://www.latimes.com/business/story/2026-04-22/googles-internal-struggle-is-handing-ai-coding-race-to-anthropic-openai)
###  [Google’s internal struggle is handing the AI coding race to Anthropic and OpenAI](https://www.latimes.com/business/story/2026-04-22/googles-internal-struggle-is-handing-ai-coding-race-to-anthropic-openai)
April 22, 2026
  * [ ![FILE - Pages from the Anthropic website and the company's logo are displayed on a computer screen in New York on Feb. 26, 2026. \(AP Photo/Patrick Sison, File\)](https://ca-times.brightspotcdn.com/dims4/default/c85a78d/2147483647/strip/true/crop/4483x2998+7+0/resize/320x214!/quality/75/?url=https%3A%2F%2Fcalifornia-times-brightspot.s3.amazonaws.com%2F01%2F6e%2F4317d9384392a3d49a7c61c981d3%2Fcb1e9f987a2146b1b804e29ca63358bd.jpg) ](https://www.latimes.com/business/story/2026-04-17/white-house-chief-of-staff-to-meet-with-anthropic-ceo-over-its-ai-technolog)
###  [White House chief of staff to meet with Anthropic CEO over its AI](https://www.latimes.com/business/story/2026-04-17/white-house-chief-of-staff-to-meet-with-anthropic-ceo-over-its-ai-technolog)
April 17, 2026

Show Comments
[Business](https://www.latimes.com/business)
### Inside the business of entertainment
The Wide Shot brings you news, analysis and insights on everything from streaming wars to production — and what it all means for the future.
By continuing, you agree to our [Terms of Service](https://www.latimes.com/terms-of-service), which include arbitration and a class action waiver. You agree that we and our third-party vendors may collect and use your information, including through cookies, pixels and similar technologies, for the purposes set forth in our [Privacy Policy](https://www.latimes.com/privacy-policy) such as personalizing your experience and ads. 
Login or register with email
Agree & Continue