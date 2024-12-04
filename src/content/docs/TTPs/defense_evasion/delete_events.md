---
title: Delete Events (kubernetes)
description: Delete all Kubernetes events within a namespace 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Delete all Kubernetes events within a namespace

## MITRE IDs

* [T1070](https://attack.mitre.org/techniques/T1070/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - events
    verbs:
    - delete
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl delete events --all
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:delete AND resource:events
```

### Sigma Definition

```yaml
---
title: Delete Events
id: 3132570d-cab2-4561-9ea6-1743644b2290
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Delete all Kubernetes events within a namespace
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: delete
    
    resource: events
    
  condition: selection
level: medium
tags:
- attack.T1070
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/

```