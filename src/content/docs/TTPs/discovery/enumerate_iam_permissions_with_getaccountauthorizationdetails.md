---
title: Enumerate Iam Permissions With Getaccountauthorizationdetails (aws)
description: An adversary may attempt to enumerate the configured IAM users within an account, to identify entities that they might wish to gain access to or backdoor. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate the configured IAM users within an account, to identify entities that they might wish to gain access to or backdoor.

## MITRE IDs

* [T1069.003](https://attack.mitre.org/techniques/T1069.003/)

## Required Permissions

* iam:GetAccountAuthorizationDetails

## Required Parameters

None
## Attacker Action

```bash
aws iam get-account-authorization-details
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:GetAccountAuthorizationDetails AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate IAM Permissions with GetAccountAuthorizationDetails
id: 53597a1f-06bd-4a81-9378-7e889fed52c4
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
    - eventName: "GetAccountAuthorizationDetails"
  condition: selection_source and events
level: low
tags:
  - attack.T1069.003
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```