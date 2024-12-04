---
title: Add New Guardduty Ip Set (aws)
description: An adversary may attempt to add a new GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected.
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to add a new GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected.

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* guardduty:CreateIPSet

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| detectorid | str | ID of the guardduty detector associated with the IP set list | 12345 |
| format | str | Format of the new IP set list - choice of TXT, STIX, OTX_CSV, ALIEN_VAULT, PROOF_POINT, FIRE_EYE | TXT |
| location | str | Location of the IP whitelist | http://www.example.com |

## Attacker Action

```bash
aws guardduty create-ip-set --activate --detector-id 12345 --format TXT --location http://www.example.com
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:CreateIPSet AND eventSource:*.guardduty.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add new guardduty ip set
id: faf89476-061a-4c29-8f9c-2ed65e65de2e
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to add a new GuardDuty IP whitelist in order to whitelist systems they control and reduce the chance of malicious activity being detected.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.guardduty.amazonaws.com"
  events:
    - eventName: "CreateIPSet"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```