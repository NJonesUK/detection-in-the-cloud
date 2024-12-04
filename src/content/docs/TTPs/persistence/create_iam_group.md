---
title: Create Iam Group (aws)
description: An adversary may attempt to create an IAM group within an account, to alter legitimate access or block administrative activity. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to create an IAM group within an account, to alter legitimate access or block administrative activity.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:CreateGroup

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| group | str | IAM group to create | example_group |

## Attacker Action

```bash
aws iam create-group --group-name example_group
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateGroup AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Create IAM group
id: 4b33f970-ef9d-49e0-ae7d-040e60d96415
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to create an IAM group within an account, to alter legitimate access or block administrative activity.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "CreateGroup"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```