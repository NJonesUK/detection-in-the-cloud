---
title: Create Pod (kubernetes)
description: Deploy a malicious container.   For this test case, the example image for the rogue container is fetched from a public repository, however rogue containers may use existing images for alternative purposes.  
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Deploy a malicious container. 

For this test case, the example image for the rogue container is fetched from a public repository, however rogue containers may use existing images for alternative purposes.

## MITRE IDs

* [T1204.003](https://attack.mitre.org/techniques/T1204.003/)
* [T1578.002](https://attack.mitre.org/techniques/T1578.002/)

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
    - create

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| podname | str | Name of the pod to be created | leonidas-netutils-pod |
| imagename | str | Name of the image to be used | skybound/net-utils |
| command | str | Command to execute within the new pod | sleep 3600 |

## Attacker Action

```bash
kubectl run leonidas-netutils-pod --image skybound/net-utils --command -- sleep 3600
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:create AND resource:pods
```

### Sigma Definition

```yaml
---
title: Create pod
id: 3c23ed24-51d0-4e29-bfa7-4ad26eaa27cd
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Deploy a malicious container. 

  For this test case, the example image for the rogue container is fetched from a public repository, however rogue containers may use existing images for alternative purposes.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    
    resource: pods
    
  condition: selection
level: low
tags:
- attack.T1204.003
- attack.T1578.002
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/New%20Container/

```