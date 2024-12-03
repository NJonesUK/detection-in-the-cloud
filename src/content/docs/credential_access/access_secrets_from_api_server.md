---
title: Access Secrets From Api Server (kubernetes)
description: Enumerate cluster secrets by querying the API server  This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.   
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Enumerate cluster secrets by querying the API server

This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.

## MITRE IDs

* [T1552.007](https://attack.mitre.org/techniques/T1552.007/)

## Scope 

This test case does not need Cluster-wide permissions

## Required Permissions

```yaml
-   apiGroups:
    - ''
    namespaced: true
    resources:
    - secrets
    verbs:
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl get secrets -o json
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:list AND resource:secrets
```

### Sigma Definition

```yaml
---
title: Access Secrets from API Server
id: eeb3e9e1-b685-44e4-9232-6bb701f925b5
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Enumerate cluster secrets by querying the API server

  This test case only simulates a standard "list" verb, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: ['list']
    
    resource: secrets
    
  condition: selection
level: low
tags:
- attack.T1552.007
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/List%20K8S%20secrets/

```