---
title: Access Application Credentials From Configmaps (kubernetes)
description: Attempt to Access Application Credentials by listing ConfigMaps   Despite this being a bad practice, Developers sometimes store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Access to those configurations can be obtained by querying the API server.  This test case only simulates a standard "list" operation, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Attempt to Access Application Credentials by listing ConfigMaps 

Despite this being a bad practice, Developers sometimes store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Access to those configurations can be obtained by querying the API server.

This test case only simulates a standard "list" operation, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.

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
    - configmaps
    verbs:
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl get configmaps
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:list AND resource:configmaps
```

### Sigma Definition

```yaml
---
title: Access Application Credentials from ConfigMaps
id: 8235adde-cbe2-4cc0-a34d-1e8f0f068e48
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Attempt to Access Application Credentials by listing ConfigMaps 

  Despite this being a bad practice, Developers sometimes store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Access to those configurations can be obtained by querying the API server.

  This test case only simulates a standard "list" operation, although the same result can also be achieved with a "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: list
    
    resource: configmaps
    
  condition: selection
level: low
tags:
- attack.T1552.007
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20credentials%20in%20configuration%20files/

```