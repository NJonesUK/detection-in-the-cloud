---
title: Attach A Malicious Lambda Layer (aws)
description: An attacker may attach a Lambda layer to an existing function to override a library that is used by the function, and use that malicious code to execute AWS API calls with that functions function's IAM role. 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An attacker may attach a Lambda layer to an existing function to override a library that is used by the function, and use that malicious code to execute AWS API calls with that functions function's IAM role.

## MITRE IDs

* [T1525](https://attack.mitre.org/techniques/T1525/)

## Required Permissions

* lambda:UpdateFunctionConfiguration

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| functionname | str | Name of the function to be targeted | example-function |
| layers | str | List of layers to add as space-separated ARNs | arn:aws:lambda:us-east-1:123456789012:layer:my-layer |

## Attacker Action

```bash
aws lambda update-function-configuration --function-name example-function --layers arn:aws:lambda:us-east-1:123456789012:layer:my-layer
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:UpdateFunctionConfiguration AND eventSource:lambda.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Attach a Malicious Lambda Layer
id: 8fb105ea-19f8-4537-965a-cdc68200b8d9
status: experimental
author: Nick Jones
date: 2024-12-02
description: An attacker may attach a Lambda layer to an existing function to override a library that is used by the function, and use that malicious code to execute AWS API calls with that functions function's IAM role.
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "lambda.amazonaws.com"
  events:
    - eventName: "UpdateFunctionConfiguration"
  condition: selection_source and events
level: medium
tags:
  - attack.T1525
  
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html
  - https://docs.aws.amazon.com/cli/latest/reference/lambda/update-function-configuration.html
falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```