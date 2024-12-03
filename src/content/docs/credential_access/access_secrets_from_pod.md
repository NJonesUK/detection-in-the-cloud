---
title: Access Secrets From Pod (kubernetes)
description: Access secrets within our own pod's filesystem  This test case simulates an adversary within a pod e.g. in the case of a compromised workload. As this operation would not go through the API server, no Audit event will be recorded and therefore no detection signature can be authored with the log sources currently available to Sigmahq. Instead, the detection's log source is set to the non-existent "Falco" source, should equivalent functionality be onboarded in the future.   
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Access secrets within our own pod's filesystem

This test case simulates an adversary within a pod e.g. in the case of a compromised workload. As this operation would not go through the API server, no Audit event will be recorded and therefore no detection signature can be authored with the log sources currently available to Sigmahq. Instead, the detection's log source is set to the non-existent "Falco" source, should equivalent functionality be onboarded in the future.

## MITRE IDs

* [T1552.001](https://attack.mitre.org/techniques/T1552.001/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - ''
    verbs:
    - ''

```

## Required Parameters

None
## Attacker Action

```bash
find /var/run/secrets/ -type f -exec cat {} \;
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
(NOT _exists_:verb) AND (NOT _exists_:resource)
```

### Sigma Definition

```yaml
---
title: Access Secrets from Pod
id: 98a31be4-f1b6-47ed-9a7c-c564e4c7687b
status: unsupported
author: Leo Tsaousis
date: 2024-12-02
description: |
  Access secrets within our own pod's filesystem

  This test case simulates an adversary within a pod e.g. in the case of a compromised workload. As this operation would not go through the API server, no Audit event will be recorded and therefore no detection signature can be authored with the log sources currently available to Sigmahq. Instead, the detection's log source is set to the non-existent "Falco" source, should equivalent functionality be onboarded in the future.
logsource:
  product: kubernetes
  service: falco
detection:
  selection:
    verb: 
    
    resource: 
    
  condition: selection
level: low
tags:
- attack.T1552.001


```