---
title: Add An Iam User To A Group (aws)
description: An attacker may attempt to add an IAM user to a group, in order to escalate their privileges 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to add an IAM user to a group, in order to escalate their privileges

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:AddUserToGroup

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| group | str | Group to add user to | example-group |
| user | str | IAM user to add to group | example-user |

## Attacker Action

```bash
aws iam add-user-to-group --group-name example-group --user-name example-user
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:AddUserToGroup AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add an IAM User to a Group
id: 6e467337-484c-4b11-8a83-fb92af74afed
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to add an IAM user to a group, in order to escalate their privileges
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "AddUserToGroup"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```