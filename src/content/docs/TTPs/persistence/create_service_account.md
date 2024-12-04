---
title: Create Service Account (kubernetes)
description: Create a Kubernetes service account 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Create a Kubernetes service account

## MITRE IDs

* [T1136](https://attack.mitre.org/techniques/T1136/)

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
    - create

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| serviceaccount | str | Name of the service account to create | leonidas-created-service |

## Attacker Action

```bash
kubectl create serviceaccount leonidas-created-service
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:create AND resource:serviceaccounts
```

### Sigma Definition

```yaml
---
title: Create service account
id: e31bae15-83ed-473e-bf31-faf4f8a17d36
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Create a Kubernetes service account
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    
    resource: serviceaccounts
    
  condition: selection
level: low
tags:
- attack.T1136
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/container%20service%20account/

```