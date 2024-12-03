---
title: Delete Iam User (aws)
description: An adversary may attempt to delete an IAM user within an account, to alter legitimate access or block administrative activity. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to delete an IAM user within an account, to alter legitimate access or block administrative activity.

## MITRE IDs

* [T1531](https://attack.mitre.org/techniques/T1531/)

## Required Permissions

* iam:DeleteUser

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to delete | example_user |

## Attacker Action

```bash
aws iam delete-user --user-name example_user
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteUser AND eventSource:*.iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete IAM user
id: aeffd059-cd63-4ff5-ac5f-63c79237c6fa
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to delete an IAM user within an account, to alter legitimate access or block administrative activity.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.iam.amazonaws.com"
  events:
    - eventName: "DeleteUser"
  condition: selection_source and events
level: low
tags:
  - attack.T1531
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```