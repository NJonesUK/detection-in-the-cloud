---
title: Cloudtrail Disable Log File Validation (aws)
description: An adversary may attempt to disable log file validation to enable them to tamper with the logs 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to disable log file validation to enable them to tamper with the logs

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
aws cloudtrail update-trail --name example-cloudtrail --no-enable-log-file-validation
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
title: Cloudtrail disable log file validation
id: e0608025-7e8e-4b26-8ac8-e7711d3df52f
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to disable log file validation to enable them to tamper with the logs
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