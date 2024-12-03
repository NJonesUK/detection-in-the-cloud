---
title: Add An Existing Role To A New Ec2 Instance (aws)
description: An adversary may attach an existing role to a new EC2 instance to which they have access 
---

| Platform               | Author               | Last Update                 |
| ---------------------- | -------------------- | --------------------------- |
| aws | Nick Jones | 2024-12-02 |

An adversary may attach an existing role to a new EC2 instance to which they have access

## MITRE IDs

* [T1098](https://attack.mitre.org/techniques/T1098/)

## Required Permissions

* iam:PassRole
* ec2:RunInstances

## Required Parameters

| Name       | Type                  | Description                  | Example Value          |
| ---------- | --------------------- | ---------------------------- | ---------------------- |
| image_id | str | AMI to create instance from | ami-a4dc46db |
| instance_type | str | Type of instance to create | t2.micro |
| iam_instance_profile_name | str | EC2 instance profile to assign | ec2-instance-profile |
| key_name | str | Name of SSH key to assign to instance | my-ssh-key |
| security_group_id | str | ID of a security group to apply to the instance | sg-123456 |

## Attacker Action

```bash
aws ec2 run-instances –image-id image_id –instance-type instance_type –iam-instance-profile Name=iam_instance_profile_name –key-name key_name –security-group-ids security_group_ids
```

## Detection Case

### ELK query

When logs are ingested into ELK, the following Lucene query can be used to identify relevant events.

```
eventName:RunInstances AND eventSource:ec2.amazonaws.com  
```

### Sigma Definition

```yaml
---
title: Add an existing role to a new EC2 instance
id: 899eb2b1-6e96-4203-bd38-9cddf970a50a
status: experimental
author: Nick Jones
date: 2024-12-02
description: An adversary may attach an existing role to a new EC2 instance to which they have access
logsource:
  service: cloudtrail
detection:
  selection_source:
    - eventSource: "ec2.amazonaws.com"
  events:
    - eventName: "RunInstances"
  condition: selection_source and events
level: low
tags:
  - attack.T1098
  

falsepositives:
  - Developers making legitimate changes to the environment. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
```