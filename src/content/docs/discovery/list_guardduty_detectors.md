---
title: List Guardduty Detectors (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1518.001](https://attack.mitre.org/techniques/T1518.001/)

## Required Permissions

* guardduty:ListDetectors

## Required Parameters

None
## Attacker Action

```bash
aws guardduty list-detectors
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ListDetectors AND eventSource:*.ec2.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: List GuardDuty Detectors
id: 79212574-fe46-4d50-8376-74dbcffb0f22
status: experimental
author: Nick Jones
date: 2024-12-02
description: None
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.ec2.amazonaws.com"
  events:
    - eventName: "ListDetectors"
  condition: selection_source and events
level: low
tags:
  - attack.T1518.001
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```