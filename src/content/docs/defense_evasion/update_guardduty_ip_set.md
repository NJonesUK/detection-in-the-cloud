---
title: Update Guardduty Ip Set (aws)
description: An adversary may attempt to alter a configured GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to alter a configured GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected.

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* guardduty:UpdateIPSet

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| detectorid | str | ID of the guardduty detector associated with the IP set list | 12345 |
| ipsetid | str | ID of the IP set to be updated | 12345 |
| location | str | Location of the IP whitelist | http://www.example.com |

## Attacker Action

```bash
aws guardduty update-ip-set --activate --detector-id 12345 --ip-set-id 12345 --location http://www.example.com
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:UpdateIPSet AND eventSource:*.guardduty.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Update guardduty ip set
id: 2faecc34-b0cb-4d41-872d-85186b6c2c6c
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to alter a configured GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.guardduty.amazonaws.com"
  events:
    - eventName: "UpdateIPSet"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```