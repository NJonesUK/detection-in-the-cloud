---
title: Sts Get Caller Identity (aws)
description: An adversary may attempt to verify their current identity with the credentials they hold. This could both be to verify that the credentials they hold are valid, and to get more information on their current identity for reconnaissance purposes. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to verify their current identity with the credentials they hold. This could both be to verify that the credentials they hold are valid, and to get more information on their current identity for reconnaissance purposes.

## MITRE IDs

* [T1087.004](https://attack.mitre.org/techniques/T1087.004/)

## Required Permissions

* sts:GetCallerIdentity

## Required Parameters

None
## Attacker Action

```bash
aws sts get-caller-identity
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:GetCallerIdentity AND eventSource:*.sts.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: STS Get Caller Identity
id: b96b69c7-b1d2-44a3-9c53-f419233cac95
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to verify their current identity with the credentials they hold. This could both be to verify that the credentials they hold are valid, and to get more information on their current identity for reconnaissance purposes.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.sts.amazonaws.com"
  events:
    - eventName: "GetCallerIdentity"
  condition: selection_source and events
level: low
tags:
  - attack.T1087.004
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```