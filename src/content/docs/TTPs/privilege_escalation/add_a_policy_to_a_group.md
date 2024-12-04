---
title: Add A Policy To A Group (aws)
description: An adversary may attempt to add a policy to a group, in order to alter the permissions assigned to a user they have compromised. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to add a policy to a group, in order to alter the permissions assigned to a user they have compromised.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:AttachGroupPolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| group | str | Group to add policy to | NONE |
| policyarn | str | Policy to add to group | arn:aws:iam::aws:policy/ReadOnlyAccess |

## Attacker Action

```bash
aws iam attach-group-policy --group-name  --policy-arn 
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:AttachGroupPolicy AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add a policy to a group
id: 299b8380-8447-4f24-8520-c7a3c0008ef8
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to add a policy to a group, in order to alter the permissions assigned to a user they have compromised.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "AttachGroupPolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```