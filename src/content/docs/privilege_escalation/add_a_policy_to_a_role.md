---
title: Add A Policy To A Role (aws)
description: An adversary may attempt to add a policy to a role, in order to grant additional privileges to a compromised resource. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to add a policy to a role, in order to grant additional privileges to a compromised resource.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:AttachUserPolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| role | str | Role to add policy to | ReadOnlyRole |
| policyarn | str | Policy to add to Role | arn:aws:iam::aws:policy/ReadOnlyAccess |

## Attacker Action

```bash
aws iam attach-role-policy --role-name  --policy-arn 
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:AttachRolePolicy  
```

### Sigma Definition

```yaml
---
title: Add a policy to a role
id: cdf3b0fc-0c45-4bb4-89f2-1c6b2661ec52
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to add a policy to a role, in order to grant additional privileges to a compromised resource.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: ""
  events:
    - eventName: "AttachRolePolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```