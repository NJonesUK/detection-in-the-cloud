---
title: Add Api Key To Existing Iam User (aws)
description: An adversary may attempt to maintain access by creating an API key attached to an existing privileged user 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to maintain access by creating an API key attached to an existing privileged user

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:CreateAccessKey

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | IAM user to generate the API key for | root |

## Attacker Action

```bash
aws iam create-access-key --user-name root
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateAccessKey AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add API key to existing IAM user
id: 1570ea27-492c-4615-a518-59155ba03416
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to maintain access by creating an API key attached to an existing privileged user
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "CreateAccessKey"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```