---
title: Delete Deployment (kubernetes)
description: Remove a deployment to impact business operations.   The availability features of Kubernetes guarantee that workloads managed by collections such as Deployments or DaemonSets, will be automatically re-scheduled if terminated or deleted. Therefore, removing managed Pods will only incur temporary disruption. Determined actors aiming to cause Denial of Service will instead aim for controller objects like Deployments. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Remove a deployment to impact business operations. 

The availability features of Kubernetes guarantee that workloads managed by collections such as Deployments or DaemonSets, will be automatically re-scheduled if terminated or deleted. Therefore, removing managed Pods will only incur temporary disruption. Determined actors aiming to cause Denial of Service will instead aim for controller objects like Deployments.

## MITRE IDs

* [T1485](https://attack.mitre.org/techniques/T1485/)
* [MS-TA9038](https://attack.mitre.org/techniques/MS-TA9038/)

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
    - delete

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| deploymentname | str | Name of the deployment to remove | leonidas-netutils-deployment |

## Attacker Action

```bash
kubectl delete deployment leonidas-netutils-deployment
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:delete AND resource:deployments
```

### Sigma Definition

```yaml
---
title: Delete deployment
id: 96047487-319b-4811-81d9-b9767a92aa5d
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Remove a deployment to impact business operations. 

  The availability features of Kubernetes guarantee that workloads managed by collections such as Deployments or DaemonSets, will be automatically re-scheduled if terminated or deleted. Therefore, removing managed Pods will only incur temporary disruption. Determined actors aiming to cause Denial of Service will instead aim for controller objects like Deployments.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: delete
    
    resource: deployments
    
  condition: selection
level: medium
tags:
- attack.T1485
- attack.MS-TA9038
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/
- https://www.crowdstrike.com/blog/crowdstrike-discovers-first-ever-dero-cryptojacking-campaign-targeting-kubernetes/

```