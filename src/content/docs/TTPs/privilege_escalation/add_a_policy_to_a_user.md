---
title: Add A Policy To A User (aws)
description: An adversary may attempt to add a policy to a user, in order to escalate the privileges of that user. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to add a policy to a user, in order to escalate the privileges of that user.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:AttachUserPolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | User to add policy to | root |
| policyarn | str | Policy to add to user | arn:aws:iam::aws:policy/ReadOnlyAccess |

## Attacker Action

```bash
aws iam attach-user-policy --user-name  --policy-arn 
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:AttachUserPolicy AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add a policy to a user
id: ca08ef1e-c37a-4a7e-b1a0-670519faacc2
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to add a policy to a user, in order to escalate the privileges of that user.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "AttachUserPolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```