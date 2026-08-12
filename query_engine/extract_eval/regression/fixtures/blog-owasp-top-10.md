# OWASP Top 10 Risks for Large Language Models: 2025 updates
**Topics:**
Nov. 20, 2024 
As generative AI and large language models (LLMs) are embedded into a greater number of internal processes and customer-facing applications, the risks associated with LLMs are growing. The [OWASP Top 10 list for LLM applications for 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) details these risks based on real-world usage as a cautionary note for leaders in tech, cybersecurity, privacy, and compliance.
“Organizations are entering uncharted territory in securing and overseeing GenAI solutions. The rapid advancement of GenAI also opens doors for adversaries to enhance their attack strategies, a dual challenge of defense and threat escalation.” — OWASP
Attacks or manipulation of AI models are particularly nefarious because they are often hidden from end users, but they can significantly impact outputs. When these risks are introduced by users, outputs are skewed and can be used for deliberate misinformation or other malicious activities.
## The 2025 OWASP Top 10 for Large Language Models
The [recently announced update for 2025](https://www.prnewswire.com/news-releases/owasp-reveals-updated-2025-top-10-risks-for-llms-announces-new-llm-project-sponsorship-program-and-inaugural-sponsors-302309429.html) expands on the evolving challenges of GenAI, provides a better understanding of existing risks, shares additional guidance on securing [retrieval-augmented generation (RAG)](https://blog.barracuda.com/2024/11/05/RAG-systems-bridge-the-knowledge-gaps-in-LLMs), adds system prompt leakage as a top risk, and gives a fuller account of excessive agency.
Let’s break down each of the top 10 risks with examples and strategies for prevention and mitigation.
##### **1. Prompt injection**
Prompt injection occurs when user inputs alter an LLM’s behavior or output in unintended ways. This might involve bypassing safety measures, unauthorized access, or manipulating decisions.
**Examples:**
  * Injecting prompts into a chatbot to access private data
  * Using hidden instructions in web content to influence outputs
  * Modifying documents in repositories to manipulate [retrieval-augmented generation](https://www.mckinsey.com/featured-insights/mckinsey-explainers/what-is-retrieval-augmented-generation-rag) (RAG)
  * Using different languages in instructions to evade detection

**Prevention and mitigation strategies:**
  * Integrate data sanitization to prevent user data from entering models.
  * Implement filtering for sensitive content on both inputs and outputs.
  * Apply [least privilege access controls](https://www.techtarget.com/searchsecurity/definition/access-control) for model operations.
  * Limit access to external data sources.
  * Incorporate differential privacy to add noise to data or outputs.

Advanced techniques include the use of homomorphic encryption and tokenization to preprocess and sanitize any sensitive information.
##### **2. Sensitive information disclosure**
Sensitive information disclosure happens when a model unintentionally reveals private or confidential data through responses. This often includes information that is contained in training data and disclosed by specific user queries.
**Examples:**
  * Leaking API keys or user credentials
  * Disclosing proprietary business strategies inappropriately
  * Sharing personal user data when answering queries
  * Revealing sensitive system details or prompts

**Prevention and mitigation strategies:**
  * Scrub training data to remove sensitive details.
  * Enforce content filtering for sensitive output categories.
  * Eliminate outdated or vulnerable components.
  * Employ robust access controls to protect sensitive data from exposure.
  * Audit responses to identify and prevent leaks.
  * Implement [response anonymization](https://www.techtarget.com/searchdatabackup/definition/data-anonymizationhttps:/www.techtarget.com/searchdatabackup/definition/data-anonymization) techniques.

##### **3. Supply chain vulnerabilities**
Supply chain vulnerabilities introduce risks when third-party components or dependencies are used. This can include malicious or unverified data, libraries, or models. It may simply be bad data or data crafted for malicious intent.
**Examples:**
  * Integrating an LLM library with hidden backdoors
  * Using compromised third-party APIs for additional functionalities
  * Employing pre-trained models [poisoned with manipulated data](https://blog.barracuda.com/2024/04/03/generative-ai-data-poisoning-manipulation)
  * Deploying updates from untrusted sources

**Prevention and mitigation strategies:**
  * Deploy strict [data governance frameworks](https://www.techtarget.com/searchdatamanagement/tip/5-data-governance-framework-examples).
  * Validate all third-party libraries and datasets.
  * Limit data sources to vetted suppliers.
  * Implement [runtime monitoring](https://nzjohng.github.io/publications/papers/models2024.pdf) to detect suspicious behaviors.
  * Conduct regular security reviews of supply chain dependencies.

##### **4. Data and model poisoning**
In data and model poisoning threats, attackers deliberately manipulate the training data to influence LLM behavior or introduce new vulnerabilities.
**Examples:**
  * Embedding harmful instructions in data to alter outputs
  * Modifying fine-tuning datasets to introduce bias
  * Creating backdoors to enable specific responses to prompts
  * [Poisoning datasets](https://venturebeat.com/ai/how-to-detect-poisoned-data-in-machine-learning-datasets/) to reduce model accuracy

**Prevention and mitigation strategies:**
  * Vet and secure data sources during training and fine-tuning.
  * Use anomaly detection to identify unusual patterns in data.
  * Employ [differential privacy](https://towardsdatascience.com/understanding-differential-privacy-85ce191e198a) to minimize the impact of single data points.
  * Regularly test models against poisoning attempts.
  * Isolate and validate all updates before deployment.

##### **5. Improper output handling**
When outputs are not validated, filtered, or restricted, you can get improper output handling. This can generate harmful content and introduce additional security risks.
**Examples:**
  * Generating biased or harmful language in responses
  * Producing content that leaks private information
  * Returning code that executes unintended operations
  * Providing inaccurate or misleading outputs

**Prevention and mitigation strategies:**
  * Adopt a [zero-trust approach](https://www.barracuda.com/support/glossary/zero-trust?utm_source=11202024&utm_medium=blog&utm_campaign=blog) and apply proper input validation.
  * Apply filters to block harmful or restricted content.
  * Require source citations for factual responses to ensure reliability.
  * Test outputs under diverse scenarios to identify vulnerabilities.

##### **6. Excessive agency**
Excessive agency refers to situations where LLMs are granted too much autonomy, enabling them to perform high-risk actions such as executing commands or accessing sensitive systems without adequate safeguards.
**Examples:**
  * Allowing LLMs to execute API calls without monitoring
  * Automating high-stakes decisions like financial transactions or health information
  * Enabling unrestricted file system access
  * Permitting unsupervised plugin interactions in complex applications

**Prevention and mitigation strategies:**
  * Limit LLM access to essential operations.
  * Implement [human-in-the-loop](https://cloud.google.com/discover/human-in-the-loop) oversight for critical tasks.
  * Use granular privilege controls to restrict capabilities.
  * Log and monitor LLM actions for accountability.
  * Design fail-safe mechanisms to intervene if unauthorized actions are detected.

##### **7. System prompt leakage**
System prompt leakage occurs when confidential or internal prompts embedded in LLM systems are revealed to users or attackers, exposing sensitive instructions or system configurations.
**Examples:**
  * Revealing hidden system prompts
  * Exposing API keys or database connections within system prompts
  * Uncovering filtering criteria, permission and user roles, and other internal rules

**Prevention and mitigation strategies:**
  * Design system prompts to prevent disclosure of sensitive or confidential data.
  * Isolate system instructions from input layers.
  * Employ input/output guardrails to detect and block leaks.
  * Ensure security controls are enforced independently from the LLM.

##### **8. Vector and embedding weaknesses**
With vector and embedding weaknesses, attackers exploit [vector representations](https://thenewstack.io/the-building-blocks-of-llms-vectors-tokens-and-embeddings/) or [embedding systems](https://datasciencedojo.com/blog/embeddings-and-llm/) used in applications to manipulate model behavior or data integrity.
**Examples:**
  * Unauthorized access to embeddings containing sensitive information
  * Spoiling embeddings to degrade search accuracy or results
  * Exploiting proximity-based flaws in [vector similarity calculations](https://engineering.grab.com/llm-assisted-vector-similarity-search)
  * Introducing malicious content into shared embedding spaces

**Prevention and mitigation strategies:**
  * Validate and sanitize inputs before generating embeddings.
  * Regularly monitor vector spaces for anomalies.
  * Apply [noise-tolerant algorithms](https://arxiv.org/html/2402.04004v2) to enhance defenses against adversarial attacks.
  * Implement strict permission and access controls for embedding systems.

##### **9. Misinformation**
Misinformation arises when LLMs generate incorrect, misleading, or biased outputs. This can spread misleading information that appears credible, leading to security breaches, damage to reputation, and legal liabilities.
**Examples:**
  * Generating false medical advice in a healthcare chatbot
  * Producing biased content in response to sensitive queries
  * Misrepresenting facts or spreading conspiracy theories
  * Generating [unsafe code](https://www.darkreading.com/application-security/researchers-turn-code-completion-llms-into-attack-tools) or introducing insecure code libraries

**Prevention and mitigation strategies:**
  * Train models with diverse, verified, and up-to-date datasets.
  * Require source citations and validation for factual outputs.
  * Regularly audit outputs for accuracy and bias.
  * Employ [post-processing filters](https://medium.com/@kbdhunga/guardrails-in-llm-applications-ensuring-safe-and-effective-ai-use-5b7d09d80dff) to flag or correct incorrect content.
  * Use human oversight for use cases requiring high accuracy.

##### **10. Unbounded consumption**
Unbounded consumption refers to scenarios where LLMs are exploited to consume excessive resources, leading to denial of service, increased costs, or degraded system performance.
**Examples:**
  * Generating excessively long outputs in response to user prompts
  * Processing extremely large inputs that overload systems
  * Handling [infinite loops in query chains](https://blog.gdeltproject.org/llm-infinite-loops-in-llm-entity-extraction-when-temperature-basic-prompt-engineering-cant-fix-things/) that drain resources
  * Allowing unrestricted API calls — leading to billing surges

**Prevention and mitigation strategies:**
  * Impose strict limits on input size, output length, and processing time.
  * Use [rate-limiting](https://stack.convex.dev/rate-limiting) for API calls and resource allocation.
  * Implement timeouts and monitoring to terminate excessive operations.
  * Validate inputs to detect and reject resource-intensive requests.

## Download OWASP’s Cybersecurity and Governance Checklist
For further guidance, you can download OWASP’s [LLM AI Cybersecurity and Governance Checklist](https://genai.owasp.org/resource/llm-applications-cybersecurity-and-governance-checklist-english/) for developers and AI leaders in pursuit of responsible and trustworthy AI solutions.
[ e-book: A guide to the role of AI in cybersecurity ![](https://blog.barracuda.com/content/dam/barracuda-corp/icons/arrow-000000.svg) ](https://www.barracuda.com/reports/ai-cybersecurity-guide?utm_source=11202024&utm_medium=blog&utm_campaign=blog)
[ ![](https://blog.barracuda.com/content/dam/barracuda-blog/images/2023/03/paul-dughi.jpg) ](https://blog.barracuda.com/author/paul-dughi)
[ Paul Dughi ](https://blog.barracuda.com/author/paul-dughi)
Paul Dughi is a digital journalist and media industry veteran. He served as VP/Technology for a group of TV stations and also as President of six owned and operated TV stations in California. He currently works as CEO at StrongerContent.com.
Related Posts: 
[ ![The defender's playbook for LLM-powered vulnerability discovery](https://blog.barracuda.com/content/dam/barracuda-blog/images/2026/06/Generic_Featured_DefendersPlaybook_1200x628.jpg) The defender's playbook for LLM-powered vulnerability discovery ](https://blog.barracuda.com/2026/06/11/defenders-playbook-llm-vulnerability-discovery) [ ![Workstation resilience: Why endpoint protection alone isn’t enough](https://blog.barracuda.com/content/dam/barracuda-blog/images/2026/06/workstation-resilience.jpg) Workstation resilience: Why endpoint protection alone isn’t enough ](https://blog.barracuda.com/2026/06/09/workstation-resilience-endpoint-protection) [ ![What is shadow AI? AI security tips for SMBs and MSP](https://blog.barracuda.com/content/dam/barracuda-blog/images/2026/06/shadow-ai.jpg) What is shadow AI? AI security tips for SMBs and MSP ](https://blog.barracuda.com/2026/06/04/shadow-ai-security-tips) [ ![AI security for MSPs: Why AI fluency is a competitive advantage](https://blog.barracuda.com/content/dam/barracuda-blog/images/2026/05/ai-security-msps.jpg) AI security for MSPs: Why AI fluency is a competitive advantage ](https://blog.barracuda.com/2026/05/22/ai-security-msps-ai-fluency)
Search the blog
[ ](https://blog.barracuda.com/2024/11/20/owasp-top-10-risks-large-language-models-2025-updates)
Popular Posts
[Threat Spotlight: Device code phishing is on the rise with 7 million attacks in four weeks](https://blog.barracuda.com/2026/04/23/threat-spotlight-device-code-phishing) [Threat Spotlight: Boutique phishing kit Saiga 2FA hides behind ‘lorem ipsum’ metadata](https://blog.barracuda.com/2026/04/28/threat-spotlight--boutique-phishing-kit-saiga-2fa) [Threat Spotlight: Tycoon 2FA didn’t die — it’s scattered everywhere](https://blog.barracuda.com/2026/04/16/threat-spotlight-tycoon-2fa-scattered-everywhere) [From the desk of the CISO: How will Anthropic’s Mythos change vulnerability discovery?](https://blog.barracuda.com/2026/05/06/How-will-Mythos-change-vulnerability-discovery) [Anthropic’s Claude Mythos: What organizations should do now to boost cyber resilience](https://blog.barracuda.com/2026/04/20/anthropic-s-claude-mythos--what-organizations-should-do-now-to-b)
![](https://blog.barracuda.com/adobe/dynamicmedia/deliver/dm-aid--fba649ab-c561-4141-80d1-5a440e6fc8f6/social-2026-email-threats-report.png?quality=95&preferwebp=true)
2026 Email Threats Report
Learn how AI and phishing-as-a-service are reshaping the email threat landscape and how to stay protected
[ Get the report ![](https://blog.barracuda.com/content/dam/barracuda-corp/icons/arrow-000000.svg) ](https://www.barracuda.com/reports/2026-email-threats-report?utm_source=internal_blog&utm_medium=hyperlink&utm_campaign=threat_research&utm_content=2026-email-threats-report-right-rail-ad)
Topics
[13 Email Threat Types](https://blog.barracuda.com/Series/13-email-threat-types) [Ransomware Protection](https://blog.barracuda.com/category/solutions/technologies/ransomware-protection) [Microsoft 365](https://blog.barracuda.com/category/solutions/technologies/microsoft-365) [Email Protection](https://blog.barracuda.com/category/email-protection) [Network Protection](https://blog.barracuda.com/category/network-protection) [Application and Cloud Protection](https://blog.barracuda.com/category/application-and-cloud-protection) [Data Protection and Recovery](https://blog.barracuda.com/category/data-protection) [Healthcare](https://blog.barracuda.com/category/solutions/industries/healthcare) [Education](https://blog.barracuda.com/category/solutions/industries/education) [Industrial and IoT Security](https://blog.barracuda.com/category/network-protection/industrial-and-iot-security) [Managed Services](https://blog.barracuda.com/topic/managed-services) [Digital Transformation](https://blog.barracuda.com/topic/digital-transformation) [Barracuda Engineering](https://blog.barracuda.com/category/barracuda-engineering)
Resources
[Barracuda Research](https://www.barracuda.com/solutions/barracuda-research?utm_source=internal_blog&utm_medium=hyperlink&utm_campaign=threat_research&utm_content=barracuda-research-right-rail) [Free Email Threat Scan](https://www.barracuda.com/products/email-scan?utm_source=rtrail&utm_medium=blog&utm_campaign=blog) [Cyber Liability Insurance Guide](https://www.barracuda.com/solutions/cyber-liability-insurance?utm_source=rtrail&utm_medium=blog&utm_campaign=blog) [Careers at Barracuda](https://www.barracuda.com/company/careers?utm_source=rtrail&utm_medium=blog&utm_campaign=blog) [Barracuda Engineering](https://www.barracuda.com/company/engineering?utm_source=rtrail&utm_medium=blog&utm_campaign=blog) [Barracuda News Room](https://www.barracuda.com/company/news?utm_source=rtrail&utm_medium=blog&utm_campaign=blog)
Subscribe to the Barracuda Blog.
Sign up to receive threat spotlights, industry commentary, and more.
![](https://blog.barracuda.com/adobe/dynamicmedia/deliver/dm-aid--92afa8fc-e47c-47fc-bd6e-73a0877a1077/social-mockup-xdr-report.jpg?quality=95&preferwebp=true)
The Managed XDR Global Threat Report 
Key findings about the tactics attackers use to target organizations and the security weak spots they try to exploit
[ Get the report ![](https://blog.barracuda.com/content/dam/barracuda-corp/icons/arrow-000000.svg) ](https://www.barracuda.com/reports/managed-xdr-global-threat-report?utm_source=internal_blog&utm_medium=hyperlink&utm_campaign=threat_research&utm_content=managed-xdr-global-threat-report-right-rail-ad)
Sign up to receive threat spotlights, industry commentary, and more.
Get all the latest news, research, and analysis delivered right to your inbox.
Cookie Settings
  * [ Privacy Notice ](https://trust.barracuda.com/privacy/documentation/privacy-notice)
  * [ Images licensed from iStock unless stated otherwise. ](https://www.istockphoto.com/)

© 2003 – 2026 Barracuda Networks, Inc. All rights reserved.
Our website uses certain technologies including cookies to enhance your experience and analyze performance and traffic. We share information about the use of the site with our partners. You may adjust these technologies via our Cookie Settings.[Privacy Policy](https://trust.barracuda.com/privacy/documentation/privacy-notice)
Cookie Settings
## How Barracuda Uses Cookies
Opt-Out Request Honored
## How Barracuda Uses Cookies
  * ### Your Privacy
  * ### Strictly Necessary Cookies
  * ### Functional Cookies
  * ### Analytics Cookies
  * ### Targeting Cookies

#### Your Privacy
Barracuda Sites may request cookies to be set on your device. We use cookies to let us know when you visit our Barracuda Sites, to understand how you interact with us, to enrich and personalize your user experience, to enable social media functionality and to customize your relationship with Barracuda, including providing you with more relevant advertising. Note that blocking some types of cookies may impact your experience on our Barracuda Sites and the services we are able to offer.   
[Privacy Policy](https://trust.barracuda.com/privacy/documentation/privacy-notice)
#### Strictly Necessary Cookies
Always Active
These cookies are necessary for the website to function and cannot be switched off in our systems. They are usually only set in response to actions made by you, such as a request for services, setting your privacy preferences, logging in or filling in forms. You can set your browser to block or alert you about these cookies, but some features of the site will not work properly.
#### Functional Cookies
Functional Cookies
These cookies enable the website to provide enhanced functionality and customization. They may be set by us or by third party providers that we have added to enhance your experience. If you do not allow these cookies then some or all of these services may not function properly.
#### Analytics Cookies
Analytics Cookies
These cookies help Barracuda understand how visitors engage within their session. Analytics Cookies assist in generating site usage statistics which do not personally identify individual users.
#### Targeting Cookies
Targeting Cookies
These cookies may be set through our site by our advertising partners. They may be used by those companies to build a profile of your interests and show you relevant information on other sites. They do not directly identify you, but are based on uniquely identifying your browser and internet device. If you do not allow these cookies, you will experience less targeted advertising.
Back Button
### Cookie List
Filter Button
Consent Leg.Interest
checkbox label label
checkbox label label
checkbox label label
  * checkbox label label

Apply Cancel
Confirm My Choices
[](https://www.onetrust.com/products/cookie-consent/)
![](https://id.rlcdn.com/464526.gif)