---
title: Delete Service Account (kubernetes)
description: Delete a Kubernetes service account 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Delete a Kubernetes service account

## MITRE IDs

* [1531](https://attack.mitre.org/techniques/1531/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - serviceaccounts
    verbs:
    - delete

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| serviceaccount | str | Name of the service account to delete | leonidas-created-service |

## Attacker Action

```bash
kubectl delete serviceaccount leonidas-created-service
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:delete AND resource:serviceaccounts
```

### Sigma Definition

```yaml
---
title: Delete service account
id: 00d40e2c-a605-4ea5-8efd-af0e8386cbea
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Delete a Kubernetes service account
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: delete
    
    resource: serviceaccounts
    
  condition: selection
level: low
tags:
- attack.1531
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/

```