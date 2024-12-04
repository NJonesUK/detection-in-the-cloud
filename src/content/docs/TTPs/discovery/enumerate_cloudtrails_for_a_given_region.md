---
title: Enumerate Cloudtrails For A Given Region (aws)
description: An adversary may attempt to enumerate the configured trails, to identify what actions will be logged and where they will be logged to. In AWS, this may start with a single call to enumerate the trails applicable to the default region. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate the configured trails, to identify what actions will be logged and where they will be logged to. In AWS, this may start with a single call to enumerate the trails applicable to the default region.

## MITRE IDs

* [T1526](https://attack.mitre.org/techniques/T1526/)

## Required Permissions

* cloudtrail:DescribeTrails

## Required Parameters

None
## Attacker Action

```bash
aws cloudtrail describe-trails
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DescribeTrails AND eventSource:*.cloudtrail.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate Cloudtrails for a Given Region
id: 48653a63-085a-4a3b-88be-9680e9adb449
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to enumerate the configured trails, to identify what actions will be logged and where they will be logged to. In AWS, this may start with a single call to enumerate the trails applicable to the default region.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.cloudtrail.amazonaws.com"
  events:
    - eventName: "DescribeTrails"
  condition: selection_source and events
level: low
tags:
  - attack.T1526
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```