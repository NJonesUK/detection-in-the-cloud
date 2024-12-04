---
title: Create Secret In Secrets Manager (aws)
description: An adversary may attempt to create secrets in secrets manager 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to create secrets in secrets manager

## MITRE IDs

* [T1527](https://attack.mitre.org/techniques/T1527/)

## Required Permissions

* secretsmanager:CreateSecret

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| name | str | Name of secret to create | leonidas_created_secret |
| secretstring | str | Value of secret to create | totallysecretvalue |

## Attacker Action

```bash
aws secretsmanager create-secret --name leonidas_created_secret --secret-string "totallysecretvalue"
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateSecret AND eventSource:*.secretsmanager.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Create Secret in Secrets Manager
id: 289f5a24-9113-4bd3-a9f3-71af8f583b88
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to create secrets in secrets manager
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.secretsmanager.amazonaws.com"
  events:
    - eventName: "CreateSecret"
  condition: selection_source and events
level: low
tags:
  - attack.T1527
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```