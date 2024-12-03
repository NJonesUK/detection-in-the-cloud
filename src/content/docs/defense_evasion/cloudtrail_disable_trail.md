---
title: Cloudtrail Disable Trail (aws)
description: An attacker may attempt to disable a cloudtrail instance in order to avoid detection 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to disable a cloudtrail instance in order to avoid detection

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* cloudtrail:StopLogging

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| trailname | str | Name of the cloudtrail to be targeted | example-cloudtrail |

## Attacker Action

```bash
aws cloudtrail stop-logging --name example-cloudtrail
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:StopLogging AND eventSource:*.cloudtrail.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Cloudtrail disable trail
id: bf856088-70f3-498b-af19-f061c0bd7740
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to disable a cloudtrail instance in order to avoid detection
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.cloudtrail.amazonaws.com"
  events:
    - eventName: "StopLogging"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```