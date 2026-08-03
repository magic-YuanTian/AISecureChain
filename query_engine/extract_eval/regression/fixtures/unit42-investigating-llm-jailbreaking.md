# Investigating LLM Jailbreaking of Popular Generative AI Web Products
![Clock Icon](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-clock.svg) 14 min read 
Related Products
[![Unit 42 AI Security Assessment icon](https://unit42.paloaltonetworks.com/wp-content/uploads/2024/06/unit42_RGB_logo_Icon_Color.png)Unit 42 AI Security Assessment](https://unit42.paloaltonetworks.com/product-category/ai-security-assessment/ "Unit 42 AI Security Assessment")[![Unit 42 Incident Response icon](https://unit42.paloaltonetworks.com/wp-content/uploads/2024/06/unit42_RGB_logo_Icon_Color.png)Unit 42 Incident Response](https://unit42.paloaltonetworks.com/product-category/unit-42-incident-response/ "Unit 42 Incident Response")
  * ![Profile Icon](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-profile-grey.svg)
By:
    * [Yongzhe Huang](https://unit42.paloaltonetworks.com/author/yongzhe-huang/)
    * [Yang Ji](https://unit42.paloaltonetworks.com/author/yang-ji/)
    * [Wenjun Hu](https://unit42.paloaltonetworks.com/author/wenjun-hu/)
  * ![Published Icon](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-calendar-grey.svg)
Published:February 21, 2025
  * ![Tags Icon](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-category.svg)
Categories:
    * [Threat Research](https://unit42.paloaltonetworks.com/category/threat-research/)
    * [Vulnerabilities](https://unit42.paloaltonetworks.com/category/vulnerabilities/)
  * ![Tags Icon](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-tags-grey.svg)
Tags:
  * ![Link Email](https://unit42.paloaltonetworks.com/wp-content/themes/unit42-v6/dist/images/icons/icon-sms.svg)
##  Executive Summary
This article summarizes our investigation into jailbreaking 17 of the most popular generative AI (GenAI) web products that offer text generation or chatbot services.
Large language models (LLMs) typically include guardrails to prevent users from generating content considered unsafe (such as language that is biased or violent). Guardrails also prevent users from persuading the LLM to communicate sensitive data, such as the training data used to create the model or its system prompt. Jailbreaking techniques are used to bypass those guardrails.
The goals of our jailbreak attempts were to assess both types of issues.
Our findings provide a more practical understanding of how jailbreaking techniques could be used to adversely affect end users of LLMs. We did this by directly evaluating the GenAI applications and products that are in use by consumers, rather than focusing on a specific underlying model.
We hypothesized that GenAI web products would implement robust safety measures beyond their base models' internal safety alignments. However, our findings revealed that all tested platforms remained susceptible to LLM jailbreaks.
Key findings of our investigation include:
  * All the investigated GenAI web products are vulnerable to jailbreaking in some capacity, with most apps susceptible to multiple jailbreak strategies.
  * Many straightforward single-turn jailbreak strategies can jailbreak the investigated products. This includes a known strategy that can produce data leakage. 
    * Among the single-turn strategies tested, some proved particularly effective, such as “storytelling,” while some previously effective approaches such as “do anything now (DAN),” had lower success jailbreak rates.
    * One app we tested is still vulnerable to the “repeated token attack,” which is a jailbreak technique used to leak a model’s training data. However, this attack did not affect most of the tested apps.
  * Multi-turn jailbreak strategies are generally more effective than single-turn approaches at jailbreaking with the aim of safety violation. However, they are generally not effective for jailbreaking with the aim of model data leakage.

Given the scope of this research, it was not feasible to exhaustively evaluate every GenAI powered web product. To ensure we do not create any false impressions about specific providers, we have chosen to anonymize the tested products mentioned throughout the article.
It is important to note that this study targets edge cases and does not necessarily reflect typical LLM use cases. We believe most AI models are safe and secure when operated responsibly and with caution.
While it can be challenging to guarantee complete protection against all jailbreaking techniques for a specific LLM, organizations can implement security measures that can help monitor when and how employees are using LLMs. This becomes crucial when employees are using unauthorized third-party LLMs.
The Palo Alto Networks portfolio of solutions, powered by [Precision AI](https://www.paloaltonetworks.com/precision-ai-security), can help shut down risks from the use of public GenAI apps, while continuing to fuel an organization’s AI adoption. The [Unit 42 AI Security Assessment](https://www.paloaltonetworks.com/unit42/assess/ai-security-assessment) can speed up innovation, boost productivity and enhance your cybersecurity.
If you think you might have been compromised or have an urgent matter, contact the [Unit 42 Incident Response team](https://start.paloaltonetworks.com/contact-unit42.html).  
| **Related Unit 42 Topics**  |  [**Prompt Injection**](https://unit42.paloaltonetworks.com/tag/prompt-injection/), **[GenAI](https://unit42.paloaltonetworks.com/tag/genai/)**  |  
| --- | --- |  
##  Background: LLM Jailbreaking
Many web products have incorporated LLMs in their core services. However, they can generate harmful content if not properly controlled. To mitigate this risk, LLMs are trained with safety alignments to prevent the production of harmful content.
However, these safety alignments can be bypassed through a process called LLM jailbreaking. This process involves crafting specific prompts (known as prompt engineering or prompt injection) to manipulate the model's output, and it leads the LLM to generate harmful content.
###  Common LLM Jailbreak Strategies
Generally, LLM jailbreak techniques can be classified into two categories:
  * Single-turn
  * Multi-turn

Our LIVEcommunity post [Prompt Injection 101](https://live.paloaltonetworks.com/t5/community-blogs/genai-security-technical-blog-series-2-6-secure-ai-by-design/ba-p/590862#toc-hId-1666391746) provides a list of these strategies.
###  Jailbreak Goals
People’s goals when attempting a jailbreak will vary, but most relate to AI safety violations. Some aim to extract sensitive information from the targeted LLM, such as model training data or system prompts.
Our [Prompt Injection 101](https://live.paloaltonetworks.com/t5/community-blogs/genai-security-technical-blog-series-2-6-secure-ai-by-design/ba-p/590862#toc-hId-1666391746) post also includes a list of common jailbreak goals.
In this study, we focused on the following jailbreak goals:
  * AI safety violation 
    * **Self-harm** : Response that encourages or provides instructions for self-harm
    * **Malware generation** : Response that contains code or instructions for creating malicious software
    * **Hateful content** : Response that contains discriminatory or offensive content
    * **Indiscriminate weapons** : Response that contains information on building weapons that threaten public safety
    * **Criminal activity** : Response that contains instructions or advice for illegal activities
  * Extracting sensitive information that should remain private, such as: 
    * The model's [system prompt](https://promptengineering.org/system-prompts-in-large-language-models/)
    * [Training data ](https://dropbox.tech/machine-learning/bye-bye-bye-evolution-of-repeated-token-attacks-on-chatgpt-models)
    * Personally identifiable information (PII) memorized by the model during its training phase