---
title: Update Login Profile For Existing User (aws)
description: An adversary may attempt to maintain access by updating an existing user's login profile, allowing them to authenticate to the AWS console with a password of their choice. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to maintain access by updating an existing user's login profile, allowing them to authenticate to the AWS console with a password of their choice.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:UpdateLoginProfile

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to update the login profile for | root |
| password | str | Password to configure for login profile | @#$%^&*()TestPass1234567890 |

## Attacker Action

```bash
aws iam update-login-profile -user-name user -password password -no-password-reset-required
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:UpdateLoginProfile AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Update login profile for existing user
id: 1fd04a6c-cf1f-4169-a9aa-1fd495f99930
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to maintain access by updating an existing user's login profile, allowing them to authenticate to the AWS console with a password of their choice.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "UpdateLoginProfile"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```