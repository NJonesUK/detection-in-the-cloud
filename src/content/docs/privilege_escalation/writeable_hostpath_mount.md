---
title: Writeable Hostpath Mount (kubernetes)
description: Create a container with a writeable hostPath mount  A hostPath volume mounts a directory or a file from the node to the container. Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node.  This test case simulates the first step of this attack, by creating a pod with a hostPath mount. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Create a container with a writeable hostPath mount

A hostPath volume mounts a directory or a file from the node to the container. Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node.

This test case simulates the first step of this attack, by creating a pod with a hostPath mount.

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
verb:create AND resource:pods AND hostPath:*
```

### Sigma Definition

```yaml
---
title: Writeable hostPath Mount
id: 402b955c-8fe0-4a8c-b635-622b4ac5f902
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Create a container with a writeable hostPath mount

  A hostPath volume mounts a directory or a file from the node to the container. Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node.

  This test case simulates the first step of this attack, by creating a pod with a hostPath mount.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    
    resource: pods
    hostPath: "*"
  condition: selection
level: low
tags:
- attack.T611
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/
- https://kubenomicon.com/Persistence/Writable_hostPath_mount.html
falsepositives:
- Various legitimate reasons exist for using hostPath mounts, such as running containers that need node-level access to e.g. transfer logs to a central location, or exposing host configuration files to static pods
```