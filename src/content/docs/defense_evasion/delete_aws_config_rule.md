---
title: Delete Aws Config Rule (aws)
description: None 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

None

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* config:DeleteConfigRule

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| rulename | str | Name of the rule to delete | example-rule |

## Attacker Action

```bash
aws configservice delete-config-rule --config-rule-name example-rule
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:DeleteConfigRule AND eventSource:*.config.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Delete AWS Config Rule
id: 5934f0e7-e252-4f8c-bf2c-372da6ada60a
status: experimental
author: Nick Jones
date: 2024-12-02
description: None
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.config.amazonaws.com"
  events:
    - eventName: "DeleteConfigRule"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```