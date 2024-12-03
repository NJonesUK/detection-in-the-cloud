---
title: Update Inline Policy For User (aws)
description: An adversary may attempt to update the inline policy set on an IAM user, in order to alter the permissions assigned to a user they have compromised. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attempt to update the inline policy set on an IAM user, in order to alter the permissions assigned to a user they have compromised.

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:PutUserPolicy

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| user | str | user to add policy to | NONE |
| policyname | str | name of new inline policy | ExamplePolicy |
| policydocument | str | file of new inline policy to set | file://examplepolicy.json |

## Attacker Action

```bash
aws iam put-user-policy --user-name NONE --policy-name ExamplePolicy --policy-document file://examplepolicy.json
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:AttachGroupPolicy AND eventSource:iam.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Update Inline Policy for User
id: 3f460fd0-f120-4c06-9365-140d1c4c8fda
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attempt to update the inline policy set on an IAM user, in order to alter the permissions assigned to a user they have compromised.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "iam.amazonaws.com"
  events:
    - eventName: "AttachGroupPolicy"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```