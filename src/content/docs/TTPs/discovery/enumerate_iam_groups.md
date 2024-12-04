---
title: Enumerate Iam Groups (aws)
description: An adversary may attempt to enumerate the configured IAM groups within an account, to identify entities that they might wish to gain access to or backdoor. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate the configured IAM groups within an account, to identify entities that they might wish to gain access to or backdoor.

## MITRE IDs

* [T1069.003](https://attack.mitre.org/techniques/T1069.003/)

## Required Permissions

* iam:ListGroups

## Required Parameters

None
## Attacker Action

```bash
aws iam list-groups
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ListGroups AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate IAM groups
id: 88d0e794-1e66-4d93-bf3b-4628bd09aaa3
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to enumerate the configured IAM groups within an account, to identify entities that they might wish to gain access to or backdoor.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "ListGroups"
  condition: selection_source and events
level: low
tags:
  - attack.T1069.003
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```