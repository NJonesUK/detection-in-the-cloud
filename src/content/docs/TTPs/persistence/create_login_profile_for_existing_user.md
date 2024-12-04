---
title: Create Login Profile For Existing User (aws)
description: An adversary may attempt to maintain access by adding a login profile to a user that does not have one configured, allowing them to authenticate to the AWS console with a password of their choice 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to maintain access by adding a login profile to a user that does not have one configured, allowing them to authenticate to the AWS console with a password of their choice

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:CreateLoginProfile

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to create the login profile for | root |
| password | str | Password to configure for login profile | TestPass1234567890 |

## Attacker Action

```bash
aws iam create-login-profile --user-name root --password TestPass1234567890 --no-password-reset-required
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateLoginProfile AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Create login profile for existing user
id: e367ad8f-0173-4cb3-8f1a-9b76b69b9de1
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to maintain access by adding a login profile to a user that does not have one configured, allowing them to authenticate to the AWS console with a password of their choice
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "CreateLoginProfile"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```