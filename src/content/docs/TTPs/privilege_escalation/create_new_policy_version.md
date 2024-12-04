---
title: Create New Policy Version (aws)
description: An attacker may attempt to create a new version of a given IAM policy in order to attach extra permissions to an entity they control. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to create a new version of a given IAM policy in order to attach extra permissions to an entity they control.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:CreatePolicyVersion

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| policy_arn | str | ARN of the policy to create a new version for | arn:aws:iam::123456789012:policy/test |
| policy_document | str | New policy to upload - for the CLI, this should be a path to the json document. For Leonidas, this should be the JSON document itself. | file://path/to/administrator/policy.json |

## Attacker Action

```bash
aws iam create-policy-version –policy-arn policy_arn –policy-document policy_document –set-as-default 
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreatePolicyVersion AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Create New Policy Version
id: b5104c3a-40f4-464a-934a-a917a89faf1a
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
    - eventName: "CreatePolicyVersion"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```