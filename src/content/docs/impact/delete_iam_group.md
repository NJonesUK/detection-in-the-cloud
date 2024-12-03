---
title: Delete Iam Group (aws)
description: An adversary may attempt to delete an IAM group within an account, to alter legitimate access or block administrative activity. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to delete an IAM group within an account, to alter legitimate access or block administrative activity.

## MITRE IDs

* [T1531](https://attack.mitre.org/techniques/T1531/)

## Required Permissions

* iam:DeleteGroup

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| group | str | IAM group to delete | example_group |

## Attacker Action

```bash
aws iam delete-group --group-name example_group
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteGroup AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete IAM group
id: 84d2c61d-2882-4223-880d-5b69dce1c1d4
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to delete an IAM group within an account, to alter legitimate access or block administrative activity.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "DeleteGroup"
  condition: selection_source and events
level: low
tags:
  - attack.T1531
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```