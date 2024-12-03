---
title: Access Secret In Secrets Manager (aws)
description: An adversary may attempt to access the secrets in secrets manager, to steal certificates, credentials or other sensitive material 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to access the secrets in secrets manager, to steal certificates, credentials or other sensitive material

## MITRE IDs

* [T1528](https://attack.mitre.org/techniques/T1528/)

## Required Permissions

* secretsmanager:GetSecretValue
* kms:Decrypt

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| secretid | str | ID of secret to access, either ARN or friendly name | leonidas_created_secret |

## Attacker Action

```bash
aws secretsmanager get-secret-value --secret-id leonidas_created_secret
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:GetSecretValue AND eventSource:*.secretsmanager.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Access Secret in Secrets Manager
id: cbeba6f0-019e-4782-8c7e-e21b10521eed
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to access the secrets in secrets manager, to steal certificates, credentials or other sensitive material
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.secretsmanager.amazonaws.com"
  events:
    - eventName: "GetSecretValue"
  condition: selection_source and events
level: low
tags:
  - attack.T1528
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```