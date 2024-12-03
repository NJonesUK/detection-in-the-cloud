---
title: Delete Iam Policy (aws)
description: An adversary may attempt to delete an IAM policy within an account, to alter legitimate access or block administrative activity. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to delete an IAM policy within an account, to alter legitimate access or block administrative activity.

## MITRE IDs

* [T1531](https://attack.mitre.org/techniques/T1531/)

## Required Permissions

* iam:DeletePolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| policy | str | ARN of the IAM policy to delete | EXAMPLEARNHERE |

## Attacker Action

```bash
aws iam delete-policy --policy-arn EXAMPLEARNHERE
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeletePolicy AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete IAM Policy
id: d24b1d06-5da8-47a6-b3e2-be701113cf6e
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to delete an IAM policy within an account, to alter legitimate access or block administrative activity.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "DeletePolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1531
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```