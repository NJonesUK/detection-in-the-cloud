---
title: Get Guardduty Detector (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1518.001](https://attack.mitre.org/techniques/T1518.001/)

## Required Permissions

* guardduty:GetDetector

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| detectorid | str | ID of guardduty detector | NONE |

## Attacker Action

```bash
aws guardduty get-detector --detector-id NONE
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:GetDetector AND eventSource:*.ec2.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Get GuardDuty Detector
id: 6fc4c001-6f00-46e1-9168-5717b5f7068a
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
    - eventName: "GetDetector"
  condition: selection_source and events
level: low
tags:
  - attack.T1518.001
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```