---
title: Enumerate Nodes (kubernetes)
description: Enumerate nodes within a cluster   This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.  
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Enumerate nodes within a cluster 

This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.

## MITRE IDs

* [T1580](https://attack.mitre.org/techniques/T1580/)
* [T1613](https://attack.mitre.org/techniques/T1613/)

## Scope 

This test case needs Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: false
    resources:
    - nodes
    verbs:
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl get nodes
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:list AND resource:nodes
```

### Sigma Definition

```yaml
---
title: Enumerate nodes
id: 7609f875-66d0-445e-ab16-8b3e53b1edc9
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Enumerate nodes within a cluster 

  This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: list
    
    resource: nodes
    
  condition: selection
level: low
tags:
- attack.T1580
- attack.T1613

falsepositives:
- Legitimate administrative activity. Investigate for similar activity from the same identity that could indicate enumeration attempts
```