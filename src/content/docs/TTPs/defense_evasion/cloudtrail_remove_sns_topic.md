---
title: Cloudtrail Remove Sns Topic (aws)
description: An adversary may attempt to remove the SNS topic from a trail configuration to degrade log delivery and ingestion 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to remove the SNS topic from a trail configuration to degrade log delivery and ingestion

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* cloudtrail:UpdateTrail

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| trailname | str | Name of the cloudtrail to be targeted | example-cloudtrail |

## Attacker Action

```bash
aws cloudtrail update-trail --name example-cloudtrail --sns-topic-name ''
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
title: Cloudtrail remove SNS topic
id: ff61896f-d9a6-40f8-8bb9-0b8c4d214af0
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to remove the SNS topic from a trail configuration to degrade log delivery and ingestion
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