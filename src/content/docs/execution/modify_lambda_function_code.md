---
title: Modify Lambda Function Code (aws)
description: An attacker may attempt to modify the code that a lambda function executes in order to gain a foothold in the environment 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attempt to modify the code that a lambda function executes in order to gain a foothold in the environment

## MITRE IDs

* [T1059](https://attack.mitre.org/techniques/T1059/)

## Required Permissions

* lambda:UpdateFunctionCode

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| functionname | str | Name of the function to be targeted | example-function |
| zipfile | str | Filename of the zip file of code to be uploaded | file.zip |

## Attacker Action

```bash
aws lambda update-function-code --function-name example-function --zip-file file.zip --publish
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:None AND eventSource:None  
```

### Sigma Definition

```yaml
---
title: Modify Lambda Function Code
id: 7890b11c-19b3-4fb9-bbec-cae87db769ca
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attempt to modify the code that a lambda function executes in order to gain a foothold in the environment
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "None"
  events:
    - eventName: "None"
  condition: selection_source and events
level: low
tags:
  - attack.T1059
  


```