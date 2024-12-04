---
title: Change Default Policy Version (aws)
description: An attacker may attempt to change the default policy version of a policy to one that includes a different set of permissions 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to change the default policy version of a policy to one that includes a different set of permissions

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:SetDefaultPolicyVersion

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| policy_arn | str | ARN of the policy to create a new version for | arn:aws:iam::123456789012:policy/test |
| policy_version | str | Version of the policy to set as default | v2 |

## Attacker Action

```bash
aws iam set-default-policy-version –policy-arn policy_arn –version-id policy_version
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:SetDefaultPolicyVersion AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Change default policy version
id: 089c1b6a-1d77-4071-aac7-c91488ad88d5
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to change the default policy version of a policy to one that includes a different set of permissions
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "SetDefaultPolicyVersion"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```