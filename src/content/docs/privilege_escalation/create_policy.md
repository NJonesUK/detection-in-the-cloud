---
title: Create Policy (aws)
description: An attacker may attempt to create a new version of a given IAM policy in order to attach extra permissions to an entity they control. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to create a new version of a given IAM policy in order to attach extra permissions to an entity they control.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:CreatePolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| policy_name | str | ARN of the policy to create a new version for | arn:aws:iam::123456789012:policy/test |
| policy_document | str | New policy to upload - for the CLI, this should be a path to the json document. For Leonidas, this should be the JSON document itself. | file://path/to/administrator/policy.json |

## Attacker Action

```bash
aws iam create-policy --policy-name arn:aws:iam::123456789012:policy/test --policy-document file://path/to/administrator/policy.json
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreatePolicy AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Create Policy
id: 1352e02d-4207-4709-8980-b3a08f346c6d
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to create a new version of a given IAM policy in order to attach extra permissions to an entity they control.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "CreatePolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```