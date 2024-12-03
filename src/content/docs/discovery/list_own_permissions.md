---
title: List Own Permissions (kubernetes)
description: List the RBAC permissions assigned to the current entity  In the early stages of a breach attackers will aim to list the permissions they have within the compromised environment. In a Kubernetes cluster, this can be achieved by interacting with the SelfSubjectAccessReview API, e.g. via "kubectl auth" command. This will enumerate the Role-Based Access Controls (RBAC) rules defining the compromised user's authorization.   
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

List the RBAC permissions assigned to the current entity

In the early stages of a breach attackers will aim to list the permissions they have within the compromised environment. In a Kubernetes cluster, this can be achieved by interacting with the SelfSubjectAccessReview API, e.g. via "kubectl auth" command. This will enumerate the Role-Based Access Controls (RBAC) rules defining the compromised user's authorization.

## MITRE IDs

* [T1069.003](https://attack.mitre.org/techniques/T1069.003/)
* [T1087.004](https://attack.mitre.org/techniques/T1087.004/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - authorization.k8s.io
    namespaced: true
    resources:
    - selfsubjectrulesreviews
    verbs:
    - create

```

## Required Parameters

None
## Attacker Action

```bash
kubectl auth can-i --list
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:create AND apiGroup:authorization.k8s.io AND resource:selfsubjectrulesreviews
```

### Sigma Definition

```yaml
---
title: List Own Permissions
id: 84b777bd-c946-4d17-aa2e-c39f5a454325
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  List the RBAC permissions assigned to the current entity

  In the early stages of a breach attackers will aim to list the permissions they have within the compromised environment. In a Kubernetes cluster, this can be achieved by interacting with the SelfSubjectAccessReview API, e.g. via "kubectl auth" command. This will enumerate the Role-Based Access Controls (RBAC) rules defining the compromised user's authorization.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    apiGroup: authorization.k8s.io
    resource: selfsubjectrulesreviews
    
  condition: selection
level: low
tags:
- attack.T1069.003
- attack.T1087.004


```