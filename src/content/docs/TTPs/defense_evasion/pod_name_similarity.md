---
title: Pod Name Similarity (kubernetes)
description: Deploy a backdoor container named to imitate system pods.   System pods, created by controllers such as Deployments or DaemonSets have random suffixes in their names. Attackers can use this fact and name their backdoor pods as if they were created by the existing controllers to avoid detection. This can be attempted in the kube-system namespace alongside the other administrative containers.  This test case creates pod imitating kube-proxy within the kube-system namespace, which is however based on a public image. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Deploy a backdoor container named to imitate system pods. 

System pods, created by controllers such as Deployments or DaemonSets have random suffixes in their names. Attackers can use this fact and name their backdoor pods as if they were created by the existing controllers to avoid detection. This can be attempted in the kube-system namespace alongside the other administrative containers.

This test case creates pod imitating kube-proxy within the kube-system namespace, which is however based on a public image.

## MITRE IDs

* [T1036.005](https://attack.mitre.org/techniques/T1036.005/)

## Scope 

This test case needs Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: false
    resources:
    - pods
    verbs:
    - create

```

## Required Parameters

None
## Attacker Action

```bash
kubectl -n kube-system run kube-proxy-bv61v --image ubuntu --command -- sleep infinity
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:create AND resource:pods AND namespace:kube\-system
```

### Sigma Definition

```yaml
---
title: Pod Name Similarity
id: a80d927d-ac6e-443f-a867-e8d6e3897318
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Deploy a backdoor container named to imitate system pods. 

  System pods, created by controllers such as Deployments or DaemonSets have random suffixes in their names. Attackers can use this fact and name their backdoor pods as if they were created by the existing controllers to avoid detection. This can be attempted in the kube-system namespace alongside the other administrative containers.

  This test case creates pod imitating kube-proxy within the kube-system namespace, which is however based on a public image.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    
    resource: pods
    namespace: kube-system
  condition: selection
level: medium
tags:
- attack.T1036.005
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Pod%20or%20container%20name%20similarily/

```