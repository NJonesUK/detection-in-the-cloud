---
title: Delete Secret In Secrets Manager (aws)
description: An adversary may attempt to delete secrets stored in secrets manager, in order to negatively impact the function of an environment 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to delete secrets stored in secrets manager, in order to negatively impact the function of an environment

## MITRE IDs

* [T1485](https://attack.mitre.org/techniques/T1485/)

## Required Permissions

* secretsmanager:DeleteSecret

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| secretid | str | ID of secret to access, either ARN or friendly name | leonidas_created_secret |

## Attacker Action

```bash
aws secretsmanager list-secrets
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteSecret AND eventSource:*.secretsmanager.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete Secret in Secrets Manager
id: c8f201c3-705f-4897-8cab-c765eeb4b1a3
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to delete secrets stored in secrets manager, in order to negatively impact the function of an environment
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.secretsmanager.amazonaws.com"
  events:
    - eventName: "DeleteSecret"
  condition: selection_source and events
level: low
tags:
  - attack.T1485
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```