# Loading locally:
model = Llama(model_path="qwen1_5-0_5b-chat-q2_k.gguf")
# Or loading from huggingface:
model = Llama.from_pretrained(
    repo_id="Retr0REG/Whats-up-gguf",
    filename="qwen1_5-0_5b-chat-q2_k.gguf",
    verbose=False
)

print(model.create_chat_completion(messages=[{"role": "user","content": "what is the meaning of life?"}]))
```

Now when the model is loaded whether as  `Llama.from_pretrained` or `Llama` and chatted, our malicious code in the `chat_template` of the `metahead` will be triggered and execute arbitrary code.

PoC video here: <https://drive.google.com/file/d/1uLiU-uidESCs_4EqXDiyKR1eNOF1IUtb/view?usp=sharing>

### References

* [GHSA-56xg-wfcc-g829](https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829 "GHSA-56xg-wfcc-g829")
* <https://nvd.nist.gov/vuln/detail/CVE-2024-34359>
* [abetlen/llama-cpp-python@b454f40](https://github.com/abetlen/llama-cpp-python/commit/b454f40a9a1787b2b5659cd2cb00819d983185df)

[![@abetlen](https://avatars.githubusercontent.com/u/6826477?s=40&v=4)](/abetlen)
[abetlen](/abetlen)
published to
[abetlen/llama-cpp-python](/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829)
May 10, 2024

Published to the GitHub Advisory Database
May 13, 2024

Reviewed
May 13, 2024

Published by the [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-34359)
May 14, 2024

Last updated
May 28, 2024

### Severity

Critical

9.6

# CVSS overall score

This score calculates overall vulnerability severity from 0 to 10 and is based on the Common Vulnerability Scoring System (CVSS).

/ 10

#### CVSS v3 base metrics

Attack vector

Network

Attack complexity

Low

Privileges required

None

User interaction

Required

Scope

Changed

Confidentiality

High

Integrity

High

Availability

High

Learn more about base metrics

# CVSS v3 base metrics

Attack vector:
More severe the more the remote (logically and physically) an attacker can be in order to exploit the vulnerability.

Attack complexity:
More severe for the least complex attacks.

Privileges required:
More severe if no privileges are required.

User interaction:
More severe when no user interaction is required.

Scope:
More severe when a scope change occurs, e.g. one vulnerable component impacts resources in components beyond its security scope.

Confidentiality:
More severe when loss of data confidentiality is highest, measuring the level of data access available to an unauthorized user.

Integrity:
More severe when loss of data integrity is the highest, measuring the consequence of data modification possible by an unauthorized user.

Availability:
More severe when the loss of impacted component availability is highest.

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

### EPSS score

28.42%

# Exploit Prediction Scoring System (EPSS)

This score estimates the probability of this vulnerability being exploited within the next 30 days.
Data provided by [FIRST](https://www.first.org/epss/user-guide).

(98th percentile)

### Weaknesses

 Weakness
CWE-76

#### [Improper Neutralization of Equivalent Special Elements](/advisories?query=cwe%3A76)

The product correctly neutralizes certain special elements, but it improperly neutralizes equivalent special elements.
 [Learn more on MITRE.](https://cwe.mitre.org/data/definitions/76.html)

### CVE ID

CVE-2024-34359

### GHSA ID

GHSA-56xg-wfcc-g829

### Source code

[abetlen/llama-cpp-python](https://github.com/abetlen/llama-cpp-python)

### Credits

* [![@retr0reg](https://avatars.githubusercontent.com/u/72267897?s=40&v=4)](/retr0reg)
  [retr0reg](/retr0reg) 

  Finder

Loading
Checking history

### Uh oh!

There was an error while loading. Please reload this page.

See something to contribute?
[Suggest improvements for this vulnerability](/advisories/GHSA-56xg-wfcc-g829/improve).