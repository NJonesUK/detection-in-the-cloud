---
title: Privileged Container (kubernetes)
description: Create a privileged container  A privileged container is a container that can access the host with all of the root capabilities of the host machine. This allows it to view, interact and modify processes, network operations, IPC calls, the file system, mount points, SELinux configurations etc. as the root user on the host. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Create a privileged container

A privileged container is a container that can access the host with all of the root capabilities of the host machine. This allows it to view, interact and modify processes, network operations, IPC calls, the file system, mount points, SELinux configurations etc. as the root user on the host.

## MITRE IDs

* [T611](https://attack.mitre.org/techniques/T611/)

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
    - get

```

## Required Parameters

None
## Attacker Action

```bash
kubectl -f /tmp/custom.yml apply
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
title: Privileged Container
id: c5cd1b20-36bb-488d-8c05-486be3d0cb97
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Create a privileged container

  A privileged container is a container that can access the host with all of the root capabilities of the host machine. This allows it to view, interact and modify processes, network operations, IPC calls, the file system, mount points, SELinux configurations etc. as the root user on the host.
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
- attack.T611
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/
- https://kubenomicon.com/Privilege_escalation/Privileged_container.html

```