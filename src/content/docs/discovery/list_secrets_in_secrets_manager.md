---
title: List Secrets In Secrets Manager (aws)
description: An adversary may attempt to enumerate the secrets in secrets manager, in order to find secrets to access. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate the secrets in secrets manager, in order to find secrets to access.

## MITRE IDs

* [T1528](https://attack.mitre.org/techniques/T1528/)

## Required Permissions

* secretsmanager:ListSecrets

## Required Parameters

None
## Attacker Action

```bash
aws secretsmanager list-secrets
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ListSecrets AND eventSource:*.secretsmanager.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: List Secrets in Secrets Manager
id: 40b578f3-5056-42b8-ae6b-13e5b015d817
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to enumerate the secrets in secrets manager, in order to find secrets to access.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.secretsmanager.amazonaws.com"
  events:
    - eventName: "ListSecrets"
  condition: selection_source and events
level: low
tags:
  - attack.T1528
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```