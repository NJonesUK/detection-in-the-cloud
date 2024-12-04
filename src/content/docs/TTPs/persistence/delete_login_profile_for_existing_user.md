---
title: Delete Login Profile For Existing User (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1531](https://attack.mitre.org/techniques/T1531/)

## Required Permissions

* iam:DeleteLoginProfile

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to delete the login profile for | root |

## Attacker Action

```bash
aws iam delete-login-profile -user-name user
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteLoginProfile AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete login profile for existing user
id: 7c3333ce-9d4b-4704-8311-a4b68fe0f5f9
status: experimental
author: Nick Jones
date: 2024-12-02
description: None
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "DeleteLoginProfile"
  condition: selection_source and events
level: low
tags:
  - attack.T1531
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```