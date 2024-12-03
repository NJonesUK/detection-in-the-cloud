---
title: Add An Entity To An Iam Role Assumption Policy (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:GetRole
* iam:UpdateAssumeRolePolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| role | str | Name of role to alter | OrganizationAccountAccessRole |
| entityarn | str | ARN of entity to add to the policy | arn:aws:iam::000000000000:root |

## Attacker Action

```bash
aws -h
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:None AND eventSource:None  
```

### Sigma Definition

```yaml
---
title: Add an entity to an IAM role assumption policy
id: 8dc9a4f7-ce41-4962-a2d2-5625d9e2502d
status: experimental
author: Nick Jones
date: 2024-12-02
description: None
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "None"
  events:
    - eventName: "None"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```