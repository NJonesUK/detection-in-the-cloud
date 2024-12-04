---
title: Enumerate Vpc Flow Logs (aws)
description: An adversary may attempt to enumerate which VPCs have flow logs configured, to identify what actions will be logged and where they will be logged to. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to enumerate which VPCs have flow logs configured, to identify what actions will be logged and where they will be logged to.

## MITRE IDs

* [T1526](https://attack.mitre.org/techniques/T1526/)

## Required Permissions

* ec2:DescribeFlowLogs

## Required Parameters

None
## Attacker Action

```bash
aws ec2 describe-flow-logs
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DescribeFlowLogs AND eventSource:*.ec2.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate VPC Flow Logs
id: 1e1cb77a-3ee5-476b-bf20-c233f0742a8f
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to enumerate which VPCs have flow logs configured, to identify what actions will be logged and where they will be logged to.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.ec2.amazonaws.com"
  events:
    - eventName: "DescribeFlowLogs"
  condition: selection_source and events
level: low
tags:
  - attack.T1526
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```