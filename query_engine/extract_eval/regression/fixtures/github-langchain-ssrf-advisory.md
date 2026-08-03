# CVSS overall score

This score calculates overall vulnerability severity from 0 to 10 and is based on the Common Vulnerability Scoring System (CVSS).

/ 10

#### CVSS v4 base metrics

##### Exploitability Metrics

Attack Vector
Network

Attack Complexity
Low

Attack Requirements
None

Privileges Required
None

User interaction
None

##### Vulnerable System Impact Metrics

Confidentiality
High

Integrity
High

Availability
High

##### Subsequent System Impact Metrics

Confidentiality
None

Integrity
None

Availability
None

Learn more about base metrics

# CVSS v4 base metrics

##### Exploitability Metrics

Attack Vector:
This metric reflects the context by which vulnerability exploitation is possible. This metric value (and consequently the resulting severity) will be larger the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable system. The assumption is that the number of potential attackers for a vulnerability that could be exploited from across a network is larger than the number of potential attackers that could exploit a vulnerability requiring physical access to a device, and therefore warrants a greater severity.

Attack Complexity:
This metric captures measurable actions that must be taken by the attacker to actively evade or circumvent existing built-in security-enhancing conditions in order to obtain a working exploit. These are conditions whose primary purpose is to increase security and/or increase exploit engineering complexity. A vulnerability exploitable without a target-specific variable has a lower complexity than a vulnerability that would require non-trivial customization. This metric is meant to capture security mechanisms utilized by the vulnerable system.

Attack Requirements:
This metric captures the prerequisite deployment and execution conditions or variables of the vulnerable system that enable the attack. These differ from security-enhancing techniques/technologies (ref Attack Complexity) as the primary purpose of these conditions is not to explicitly mitigate attacks, but rather, emerge naturally as a consequence of the deployment and execution of the vulnerable system.

Privileges Required:
This metric describes the level of privileges an attacker must possess prior to successfully exploiting the vulnerability. The method by which the attacker obtains privileged credentials prior to the attack (e.g., free trial accounts), is outside the scope of this metric. Generally, self-service provisioned accounts do not constitute a privilege requirement if the attacker can grant themselves privileges as part of the attack.

User interaction:
This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable system. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.

##### Vulnerable System Impact Metrics

Confidentiality:
This metric measures the impact to the confidentiality of the information managed by the VULNERABLE SYSTEM due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.

Integrity:
This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of the VULNERABLE SYSTEM is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).

Availability:
This metric measures the impact to the availability of the VULNERABLE SYSTEM resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the system, this metric refers to the loss of availability of the impacted system itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system.

##### Subsequent System Impact Metrics

Confidentiality:
This metric measures the impact to the confidentiality of the information managed by the SUBSEQUENT SYSTEM due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.

Integrity:
This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of the SUBSEQUENT SYSTEM is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).

Availability:
This metric measures the impact to the availability of the SUBSEQUENT SYSTEM resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the system, this metric refers to the loss of availability of the impacted system itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system.

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

### EPSS score

2.831%

# Exploit Prediction Scoring System (EPSS)

This score estimates the probability of this vulnerability being exploited within the next 30 days.
Data provided by [FIRST](https://www.first.org/epss/user-guide).

(85th percentile)

### Weaknesses

 Weakness
CWE-94

#### [Improper Control of Generation of Code ('Code Injection')](/advisories?query=cwe%3A94)

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.
 [Learn more on MITRE.](https://cwe.mitre.org/data/definitions/94.html)

### CVE ID

CVE-2023-36281

### GHSA ID

GHSA-7gfq-f96f-g85j

### Source code

[langchain-ai/langchain](https://github.com/langchain-ai/langchain)

### Credits

* [![@eyurtsev](https://avatars.githubusercontent.com/u/3205522?s=40&v=4)](/eyurtsev)
  [eyurtsev](/eyurtsev) 

  Analyst

Loading
Checking history

### Uh oh!

There was an error while loading. Please reload this page.

See something to contribute?
[Suggest improvements for this vulnerability](/advisories/GHSA-7gfq-f96f-g85j/improve).