---
title: Enumerate Iam Users (aws)
description: An adversary may attempt to enumerate the configured IAM users within an account, to identify entities that they might wish to gain access to or backdoor. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate the configured IAM users within an account, to identify entities that they might wish to gain access to or backdoor.

## MITRE IDs

* [T1033](https://attack.mitre.org/techniques/T1033/)

## Required Permissions

* iam:ListUsers

## Required Parameters

None
## Attacker Action

```bash
aws iam list-users
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ListUsers AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate IAM users
id: 329a2783-4410-47b2-a113-36200ab1037a
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to enumerate the configured IAM users within an account, to identify entities that they might wish to gain access to or backdoor.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "ListUsers"
  condition: selection_source and events
level: low
tags:
  - attack.T1033
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```