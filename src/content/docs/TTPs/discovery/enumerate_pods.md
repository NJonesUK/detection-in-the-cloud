---
title: Enumerate Pods (kubernetes)
description: Enumerate pods within the Leonidas namepsace 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Enumerate pods within the Leonidas namepsace

## MITRE IDs

* [T1580](https://attack.mitre.org/techniques/T1580/)
* [T1613](https://attack.mitre.org/techniques/T1613/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - pods
    verbs:
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl get pods
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:list AND resource:pods
```

### Sigma Definition

```yaml
---
title: Enumerate pods
id: 18490e7b-f1f3-484a-806b-4cb16aa225ce
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Enumerate pods within the Leonidas namepsace
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: list
    
    resource: pods
    
  condition: selection
level: low
tags:
- attack.T1580
- attack.T1613

falsepositives:
- Legitimate administrative activity. Investigate for similar activity from the same identity that could indicate enumeration attempts
```