---
title: Cloudtrail Disable Multi-Region Logging (aws)
description: An adversary may attempt to disable multi-region logging in order to perform actions in other regions without detection 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to disable multi-region logging in order to perform actions in other regions without detection

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
aws cloudtrail update-trail --name example-cloudtrail --no-is-multi-region-trail
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
title: Cloudtrail disable multi-region logging
id: 2bc6d6d1-fde2-4767-b1e3-809aa8f5c200
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to disable multi-region logging in order to perform actions in other regions without detection
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