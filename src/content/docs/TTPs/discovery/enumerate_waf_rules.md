---
title: Enumerate Waf Rules (aws)
description: An attacker may attempt to enumerate the rulesets applied to any configured WAFs, to aid further exploitation of applications 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to enumerate the rulesets applied to any configured WAFs, to aid further exploitation of applications

## MITRE IDs

* [T1518.001](https://attack.mitre.org/techniques/T1518.001/)

## Required Permissions

* wafv2:ListWebACLs

## Required Parameters

None
## Attacker Action

```bash
aws waf list-web-acls
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:ListWebACLs AND eventSource:waf.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Enumerate WAF Rules
id: c5dc6f58-05f1-48ae-8b39-1c441729517b
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to enumerate the rulesets applied to any configured WAFs, to aid further exploitation of applications
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "waf.amazonaws.com"
  events:
    - eventName: "ListWebACLs"
  condition: selection_source and events
level: low
tags:
  - attack.T1518.001
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```