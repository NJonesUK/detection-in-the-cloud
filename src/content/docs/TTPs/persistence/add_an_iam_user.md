---
title: Add An Iam User (aws)
description: An attacker may attempt to create an IAM user, in order to provide another means of authenticating to the AWS account 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to create an IAM user, in order to provide another means of authenticating to the AWS account

## MITRE IDs

* [T1136.003](https://attack.mitre.org/techniques/T1136.003/)

## Required Permissions

* iam:CreateUser

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to create | example-user |

## Attacker Action

```bash
aws iam create-user --user-name example-user
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateUser AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add an IAM User
id: 6f660a21-0fcd-4b51-9894-4d2d8213f45b
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to create an IAM user, in order to provide another means of authenticating to the AWS account
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "CreateUser"
  condition: selection_source and events
level: low
tags:
  - attack.T1136.003
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```