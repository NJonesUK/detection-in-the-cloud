---
title: Exec Into Container (kubernetes)
description: Execute into a Pod's container  Attackers who have permissions, can run malicious commands in a Pod's container within the cluster using "kubectl exec" command 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Execute into a Pod's container

Attackers who have permissions, can run malicious commands in a Pod's container within the cluster using "kubectl exec" command

## MITRE IDs

* [T1609](https://attack.mitre.org/techniques/T1609/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - pods/exec
    verbs:
    - create
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - pods
    verbs:
    - get

```

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| podname | str | Name of the pod to exec into | vulnerable-pod |
| command | str | The command to execute within the pod. | whoami |

## Attacker Action

```bash
kubectl exec vulnerable-pod -- sh -c whoami
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:create AND resource:pods AND subresource:exec
```

### Sigma Definition

```yaml
---
title: Exec into Container
id: a1b0ca4e-7835-413e-8471-3ff2b8a66be6
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Execute into a Pod's container

  Attackers who have permissions, can run malicious commands in a Pod's container within the cluster using "kubectl exec" command
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    
    resource: pods
    subresource: exec
  condition: selection
level: low
tags:
- attack.T1609
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exec%20into%20container/
falsepositives:
- Legitimate debugging activity, investigate the identity performing the requests and their authorization
```