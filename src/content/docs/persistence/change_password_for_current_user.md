---
title: Change Password For Current User (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:ChangePassword

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| oldpassword | str | Previous password | oldpassword |
| newpassword | str | New password to set | newpassword |

## Attacker Action

```bash
aws iam change-password --old-password oldpassword --new-password newpassword
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ChangePassword AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Change Password for Current User
id: d3f79034-a239-40bb-815f-e1cdd91e648e
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
    - eventName: "ChangePassword"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```