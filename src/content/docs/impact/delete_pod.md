---
title: Delete Pod (kubernetes)
description: Remove a pod from a cluster to impact business operations 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Remove a pod from a cluster to impact business operations

## MITRE IDs

* [T1498](https://attack.mitre.org/techniques/T1498/)

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
    - delete

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| podname | str | Name of the pod to remove | leonidas-netutils-pod |

## Attacker Action

```bash
kubectl delete pod leonidas-netutils-pod
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:delete AND resource:pods
```

### Sigma Definition

```yaml
---
title: Delete pod
id: 40967487-139b-4811-81d9-c9767a92aa5a
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Remove a pod from a cluster to impact business operations
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: delete
    
    resource: pods
    
  condition: selection
level: low
tags:
- attack.T1498
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/

```