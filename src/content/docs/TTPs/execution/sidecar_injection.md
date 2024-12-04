---
title: Sidecar Injection (kubernetes)
description: Inject a sidecar container into a running deployment   A sidecar container is an additional container that resides alongside the main container within the pod. Containers can be added to running resources like Deployments/DeamonSets/StatefulSets by means of "kubectl patch". By injecting a new container within a legitimate pod attackers can run their code and hide their activity, instead of running their own separated pod in the cluster. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Inject a sidecar container into a running deployment 

A sidecar container is an additional container that resides alongside the main container within the pod. Containers can be added to running resources like Deployments/DeamonSets/StatefulSets by means of "kubectl patch". By injecting a new container within a legitimate pod attackers can run their code and hide their activity, instead of running their own separated pod in the cluster.

## MITRE IDs

* [T609](https://attack.mitre.org/techniques/T609/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - apps
    namespaced: true
    resources:
    - deployments
    verbs:
    - get
    - patch

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| deployment | str | Name of the deployment to patch | patchable-deployment |

## Attacker Action

```bash
kubectl patch deployment patchable-deployment --patch-file /tmp/custom.yml
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:patch AND apiGroup:apps AND resource:deployments
```

### Sigma Definition

```yaml
---
title: Sidecar Injection
id: ad9012a6-e518-4432-9890-f3b82b8fc71f
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Inject a sidecar container into a running deployment 

  A sidecar container is an additional container that resides alongside the main container within the pod. Containers can be added to running resources like Deployments/DeamonSets/StatefulSets by means of "kubectl patch". By injecting a new container within a legitimate pod attackers can run their code and hide their activity, instead of running their own separated pod in the cluster.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: patch
    apiGroup: apps
    resource: deployments
    
  condition: selection
level: low
tags:
- attack.T609
references:
- https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20Injection/

```