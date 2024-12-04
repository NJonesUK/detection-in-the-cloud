---
title: Cloudtrail Alter Encryption Configuration (aws)
description: Alter cloudtrail encryption configuration such that log ingestion can no longer read logs 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

Alter cloudtrail encryption configuration such that log ingestion can no longer read logs

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* cloudtrail:UpdateTrail

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| trailname | str | Name of the cloudtrail to be targeted | example-cloudtrail |
| kmskeyid | str | KMS key ID to use, supply an empty string to disable encryption |  |

## Attacker Action

```bash
aws cloudtrail update-trail --name example-cloudtrail --kms-key-id 
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:UpdateTrail AND eventSource:*.cloudtrail.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Cloudtrail alter encryption configuration
id: 76e19d12-2ed2-4dfc-b9e9-f3b235ee471a
status: experimental
author: Nick Jones
date: 2024-12-02
description: Alter cloudtrail encryption configuration such that log ingestion can no longer read logs
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.cloudtrail.amazonaws.com"
  events:
    - eventName: "UpdateTrail"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```