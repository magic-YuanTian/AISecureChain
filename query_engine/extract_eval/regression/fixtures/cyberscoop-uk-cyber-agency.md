#  UK cyber agency warns LLMs will always be vulnerable to prompt injection 
The comments echo many in the research community who have said the flaw is an inherent trait of generative AI technology. 
**By** [Derek B. Johnson](https://cyberscoop.com/author/derek-johnson/ "Derek B. Johnson")
December 8, 2025
[ ](https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/)
Listen to this article
5:54
Learn more. This feature uses an automated voice, which may result in occasional errors in pronunciation, tone, or sentiment. 
![](https://cyberscoop.com/wp-content/uploads/sites/3/2025/12/GettyImages-2217849521-min.jpg?w=1180) (Getty Images) 
The UK’s top cyber agency issued a warning to the public Monday: large language model AI tools may always contain a persistent flaw that allows malicious actors to hijack models and potentially weaponize them against users.
When ChatGPT launched in 2022, security researchers began testing the tool and other LLMs for functionality, security and privacy. They very quickly identified a fundamental deficiency: because these models treat all prompts as instructions, they can be easily manipulated through simple techniques that would typically only succeed against young children. 
Known as prompt injection, this technique works by sending malicious requests to the AI in the form of instructions, allowing bad actors to blow past any internal guardrails that developers had put in place to prevent models from taking harmful or dangerous actions. 
In a [blog post](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) Monday—three years after ChatGPT’s debut—the UK’s top cybersecurity agency warned that prompt injection is inextricably intertwined in LLMs’ architecture, making the problem impossible to eliminate entirely.
Advertisement
The National Cyber Security Centre’s technical director for platforms research said this is because, at their core, these large language models do not make any distinction between trusted and untrusted content they encounter.   
  
“Current large language models (LLMs) simply do not enforce a security boundary between instructions and data inside a prompt,” wrote David C (the NCSC does not publish its director’s full name in public releases).  
  
Instead these models “concatenate their own instructions with untrusted content in a single prompt, and then treat the model’s response as if there were a robust boundary between ‘what the app asked for’ and anything in the untrusted content,” he wrote.  
  
While there may be a temptation to compare prompt injection to other kinds of manageable attacks, like [SQL injection](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), which also deal with web pages incorrectly handling data and instructions, the English expert said he believes prompt injections are substantively worse in important ways.
Because these algorithms operate solely through pattern matching and prediction, they cannot distinguish between different inputs. The models lack the ability to assess whether the information is trustworthy, or if the input is merely something the program should process and store or treat as active instructions for its next task.
“Under the hood of an LLM, there’s no distinction made between ‘data’ or ‘instructions’; there is only ever ‘next token,’” the author wrote. “When you provide an LLM prompt, it doesn’t understand the text in the way a person does. It is simply predicting the most likely next token from the text so far.  
  
Because of this, “it’s very possible that prompt injection attacks may never be totally mitigated in the way that SQL injection attacks can be,” he wrote.
The NCSC’s findings align with what some independent researchers and even AI companies have been saying: that problems like prompt injections, jailbreaking and hallucinations may never fully be solved. And when these models pull content from the internet, or from external parties to complete tasks, there will always be a danger that such content will be treated as a direct instruction from its owners or administrators.
On software repositories like GitHub, major AI coding tools from Open AI and Anthropic have been integrated into automated software development workflows. These integrations created a vulnerability: maintainers—and in some cases, external contributors—[could embed malicious prompts](https://cyberscoop.com/ai-coding-tools-can-be-turned-against-you-aikido-github-prompt-injection/) within standard development elements like commit messages and pull requests. The LLM would then treat these prompts as legitimate instructions.
Advertisement
While some of the models could only execute major tasks with human approval, the researchers said this too could be circumvented with a one-line prompt.
Meanwhile, AI browser agents that are meant to help users and businesses shop, communicate and do research online have been found to be similarly vulnerable to many of the same problems.
Researchers found they could sometimes piggyback off ChatGPT’s browser authentication protocols to inject hidden instructions into the LLM’s memory and achieve remote code execution privileges.
Other researchers have [created web pages](https://cyberscoop.com/openai-atlas-splx-research-cloaking-attacks-browser-agents/) that served different content to AI crawlers visiting their website, influencing the model’s internal evaluations with untrusted content.
AI companies have increasingly acknowledged the enduring nature of these weaknesses in LLM technology, though they claim to be working on solutions.
Advertisement
In September, OpenAI published a[ paper](https://arxiv.org/abs/2509.04664) claiming that hallucinations are a solvable problem. According to the research, hallucinations occur because of how developers train and evaluate these models: large language models are penalized when they express uncertainty over giving confident answers, even if the confident answers are wrong. For example, if you ask an LLM what your birthday is, an LLM that responds “I don’t know” gets a lower evaluation score than one that guesses any of the possible 365 answers, despite having no way to know the correct answer.
The paper claims that OpenAI’s evaluation for newer models rebalances those incentives, leading to fewer (but nonzero) hallucinations.Companies like Anthropic have said [they rely on](https://cyberscoop.com/anthropic-claude-breaks-bad-jailbreak-reward-hacking-study/) monitoring of user accounts and other outside detection tools, as opposed to internal guardrails within the models themselves, to identify and combat jailbreaking, which affect nearly all commercial and open source models.
![Derek B. Johnson](http://2.gravatar.com/avatar/ea8b076b398ee48b71cfaecf898c582b?s=192&d=mm&r=g)
#### Written by Derek B. Johnson
Derek B. Johnson is a reporter at CyberScoop, where his beat includes cybersecurity, elections and the federal government. Prior to that, he has provided award-winning coverage of cybersecurity news across the public and private sectors for various publications since 2017. Derek has a bachelor’s degree in print journalism from Hofstra University in New York and a master’s degree in public policy from George Mason University in Virginia. 
#### In This Story
Share
  * [ Facebook ](https://www.facebook.com/sharer/sharer.php?u=https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/)
  * [ LinkedIn ](https://www.linkedin.com/cws/share?url=https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/)
  * [ Twitter ](https://twitter.com/intent/tweet?url=https://cyberscoop.com/uk-warns-ai-prompt-injection-unfixable-security-flaw/)
  * Copy Link

Advertisement
Advertisement
## More Like This
  1. ###  [ Anthropic disables new models after government calls them a national security concern ](https://cyberscoop.com/us-government-anthropic-fable-5-mythos-5-export-controls/)
By  [ Greg Otto ](https://cyberscoop.com/author/greg-otto/)
  2. ###  [ US, France, and Italian authorities shut down massive deepfake porn site ](https://cyberscoop.com/us-international-authorities-shutdown-deepfake-porn-site/)
By  [ Derek B. Johnson ](https://cyberscoop.com/author/derek-johnson/)
  3. ###  [ OpenAI: ‘Likely’ Chinese influence operation tried to use ChatGPT to stir debate on data centers ](https://cyberscoop.com/openai-china-influence-campaign-chatgpt/)
By  [ Derek B. Johnson ](https://cyberscoop.com/author/derek-johnson/)

Advertisement