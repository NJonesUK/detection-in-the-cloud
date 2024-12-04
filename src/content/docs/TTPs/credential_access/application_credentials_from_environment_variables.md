---
title: Application Credentials From Environment Variables (kubernetes)
description: Attempt to Access Application Credentials in Environmemt Variables   Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. These variables can be listed within the description of pods.  This test case only simulates a standard "list" operation, although the same result can also be achieved with a  "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| kubernetes | Leo Tsaousis | 2024-12-02 |

Attempt to Access Application Credentials in Environmemt Variables 

Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. These variables can be listed within the description of pods.

This test case only simulates a standard "list" operation, although the same result can also be achieved with a  "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.

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
    - pods
    verbs:
    - list

```

## Required Parameters

None
## Attacker Action

```bash
kubectl get pods -o=jsonpath="{.items[*].spec.containers[*].env}"
```


## Detection Case

### ELK query

When logs are ingested into ELK, the following query can be used to identify relevant events.

```
verb:list AND resource:pods
```

### Sigma Definition

```yaml
---
title: Application Credentials from Environment Variables
id: ec8ec8b1-c696-4e9a-ae20-8e1c1f056b09
status: experimental
author: Leo Tsaousis
date: 2024-12-02
description: |
  Attempt to Access Application Credentials in Environmemt Variables 

  Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. These variables can be listed within the description of pods.

  This test case only simulates a standard "list" operation, although the same result can also be achieved with a  "watch" operation. The associated detection shall therefore not be considered complete, but only a 1-to-1 match of this particular test case.
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: list
    
    resource: pods
    
  condition: selection
level: low
tags:
- attack.T1552.007
references:
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Application%20credentials%20in%20configuration%20files/
falsepositives:
- get pods might be performed for various legitimate reasons. Stronger detections could be based on a correlation search for subsequent activity making use of environment variables
```