---
title: Cloudtrail Change Destination Bucket (aws)
description: Alter cloudtrail log destination to a bucket that target does not have access to 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

Alter cloudtrail log destination to a bucket that target does not have access to

## MITRE IDs

* [T1562](https://attack.mitre.org/techniques/T1562/)

## Required Permissions

* cloudtrail:UpdateTrail

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| trailname | str | Name of the cloudtrail to be targeted | example-cloudtrail |
| bucketname | str | Name of S3 bucket to redirect logs to | example-bucket |

## Attacker Action

```bash
aws cloudtrail update-trail --name example-cloudtrail --s3-bucket-name example-bucket
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:UpdateTrail AND eventSource:*.cloudtrail.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Cloudtrail change destination bucket
id: 9be7e8b4-dd76-4396-b3ca-10c6d8df1048
status: experimental
author: Nick Jones
date: 2024-12-02
description: Alter cloudtrail log destination to a bucket that target does not have access to
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "*.cloudtrail.amazonaws.com"
  events:
    - eventName: "UpdateTrail"
  condition: selection_source and events
level: low
tags:
  - attack.T1562
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```