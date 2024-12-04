---
title: Cloudtrail Disable Global Event Logging (aws)
description: An adversary may attempt to disable global event logging in order to modify configuration of global services such as IAM 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to disable global event logging in order to modify configuration of global services such as IAM

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
aws cloudtrail update-trail --name example-cloudtrail --no-include-global-service-events
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
title: Cloudtrail disable global event logging
id: e7b423d5-abd1-4685-988a-cf718c4d2f98
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to disable global event logging in order to modify configuration of global services such as IAM
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