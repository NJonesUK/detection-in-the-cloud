---
title: Delete Iam Role (aws)
description: An adversary may attempt to delete an IAM role within an account, to alter legitimate access or block administrative activity. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to delete an IAM role within an account, to alter legitimate access or block administrative activity.

## MITRE IDs

* [T1531](https://attack.mitre.org/techniques/T1531/)

## Required Permissions

* iam:DeleteRole

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| role | str | IAM role to delete | example_role |

## Attacker Action

```bash
aws iam delete-role --role-name example_role
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteRole AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete IAM Role
id: 999d40d4-9f65-4b5c-ad2d-349a07a4b6c3
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to delete an IAM role within an account, to alter legitimate access or block administrative activity.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "DeleteRole"
  condition: selection_source and events
level: low
tags:
  - attack.T1531
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```