# Dynamic ACL Update via GCU Test Plan

## Overview

This test plan will certify that Generic Config Updater (GCU) is able to properly add, remove, and update ACL Table Types, ACL Tables, and ACL Rules, and that these ACL rules and their priorities are respected and appropriate action is taken on packets.

## Testbed

The test will run on T0 testbeds.

## Setup Configuration

No setup pre-configuration is required, the test will configure and return the testbed to its original state.

Tests themselves will utilize a fixture that automatically creates a ACL_TABLE_TYPE and ACL_TABLE, and then removes them when the test is complete.

## Testing Plan

To test the capability of GCU to dynamically update ACLs, we will utilize various Json Patch files to create, update, and remove various ACL Tables and Rules.  The contents of the Json Patch files, as well as additional details about verification processes, will be defined in the last section of this document, [JSON Patch Files and Expected Results](#json-patch-files-and-expected-results).

### Test Case # 1 - Create and apply custom ACL table without rules

#### Test Objective

Verify that we can utilize GCU to create a custom ACL Table Type, and then create an ACL Table from this type.  This is accomplished with a fixture, which will automatically be run on each subsequent test

#### Testing Steps

- Use GCU to create a new ACL Table Type via GCU

- Use GCU to create an ACL Table utilizing this ACL Table Type

- Verify that both operations were successful

- Verify that output of "show acl table {tablename}" matches expected output

### Test Case # 2 - Create a drop rule within custom table

#### Test Objective

Verify that we can create a single drop rule utilizing GCU

#### Testing Steps

- Use GCU to create a new drop rule on a specific port in our ACL Table

- Verify that operation was successful

- Verify that output of "show acl rule | grep {rule_name}" matches expected output

- Verify that a packet sent on this port is dropped for both IPv4 and IPv6

### Test Case # 3 - Remove a drop rule from the ACL table

#### Test Objective

Verify that we can remove a previously created drop rule from our ACL Table with GCU

#### Testing Steps

- Use GCU to create a drop rule on ACL Table

- Remove the drop rule from ACL Table

- Verify that all operations were successful

- Verify that the result of "show acl rule {rule_name}" has no relevant output

- Verify that packets that were previously dropped are now forwarded

### Test Case # 4 - Create forward rules within custom ACL table

#### Test Objective

Verify that we can create a forward rule utilizing GCU, and that we can create forward rules for both ipv4 and ipv6

#### Testing Steps

- Use GCU to create 2 new forwarding rules with top priority on our ACL Table, one for IPv4 and one for IPv6

- Use GCU to create drop rule with lower priority in ACL Table

- Verify that all operations were successful

- Verify that for both rules created, "show acl rule | grep {rulename}" matches expected output for both rules

- Verify that packets matching forwarding rules are correctly forwarded

- Verify that packets not matching forwarding rules are correctly dropped

### Test Case # 5 - Replace the IP Address on an ACL Rule

#### Test Objective

Verify that after creation, ACL Rules can have their match conditions updated

#### Testing Steps

- Use GCU to create 2 new forwarding rules on ACL Table

- Use GCU to create drop rule with lower priority on ACL Table

- Use GCU to replace the IP addresses in both forwarding rules

- Verify that all operations were successful

- Verify that the results of "show acl rule | grep {rule_name}" matches expected output for both rules

- Verify that packets with IPs matching original forwarding rules are dropped

- Verify that packets with IPs matching replacement rules are forwarded

### Test Case # 6 - Replace the IP Address of a non-existent ACL Rule

#### Test Objective

Verify that attempting to replace the address of a rule that does not exist properly results in an error and does not affect configDB

#### Testing Steps

- Create 2 new forwarding rules on ACL Table

- Replace the IP addresses in non-existent forwarding rules

- Verify that the replace action failed

### Test Case # 7 - Remove non-existent ACL Table

#### Test Objective

Verify that attempting to remove an ACL Table that does not exist properly results in an error and does not affect configDB

#### Testing Steps

- Attempt to remove a table that does not exist

- Verify that this removal fails

## JSON Patch Files and Expected Results

This section contains explicit details on the contents of each JSON Patch file used within the test, as well as the exact way that these operations are  checked for success

### Create a new ACL table type
**JSON Patch:**

	[
        {
            "op": "add",
            "path": "/ACL_TABLE_TYPE",
            "value": {
                "DYNAMIC_ACL_TABLE_TYPE" : {
                "MATCHES": ["DST_IP","DST_IPV6","IN_PORTS"],
                "ACTIONS": ["PACKET_ACTION","COUNTER"],
                "BIND_POINTS": ["PORT"]
                }
            }
        }
    ]
**Expected Result**
- Operation Success

**Additional checks**
- None

### Create an ACL Table

**Json Patch**:

    [
        {
            "op": "add",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
            "value": {
                "policy_desc": "DYNAMIC_ACL_TABLE",
                "type": "DYNAMIC_ACL_TABLE_TYPE",
                "stage": "INGRESS",
                "ports": {vlan port members from minigraph}
            }
        }
    ]

**Expected result**
- Operation Success


**Additional checks**
- Check that results of the command “show acl table” match this expected output:

Name  | Type | Binding | Description | Stage | Status
------------- | ------------- | ---------- | ----------| --------- | ---------
DYNAMIC_ACL_TABLE | DYNAMIC_ACL_TABLE_TYPE | {vlan port 1} | DYNAMIC_ACL_TABLE_TYPE | ingress | Active
  | | {vlan port 2} | |
  | | {vlan port 3}...

### Create Forwarding Rules

**Json Patch:**

    [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "DYNAMIC_ACL_TABLE|RULE_1": {
                    "DST_IP": "103.23.2.1/32",
                    "PRIORITY": "9999",
                    "PACKET_ACTION": "FORWARD"
                },
                "DYNAMIC_ACL_TABLE|RULE_2": {
                    "DST_IPV6": "103:23:2:1::1/128",
                    "PRIORITY": "9998",
                    "PACKET_ACTION": "FORWARD"
                }
            }
        }
    ]

**Expected Result**
- Operation Success

**Additional Checks**
+ Check that results of “show acl rule | grep RULE_1” and “show acl rule | grep RULE_2” match the following output:
  + DYNAMIC_ACL |_TABLE	RULE_1 | 9999 | FORWARD |  DST_IP: 103.23.2.1/32
  + DYNAMIC_ACL_TABLE | RULE_2 | 9998 | FORWARD | DST_IPV6: 103.23.2.1::1/128

### Create Drop Rule

**Json Patch**

    [
        {
            "op": "add",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3",
            "value": {
                "PRIORITY": "9997",
                "PACKET_ACTION": "DROP",
                "IN_PORTS": {port selected from DUT minigraph}
            }
        }
    ]

**Expected result**
- Operation Success

**Additional checks:**
+ Check that result of “show acl rule | grep RULE_3” matches the following output:
  + DYNAMIC_ACL_TABLE | RULE_3 | 9997  | DROP  | IN_PORTS: {port selected from DUT minigraph}

### Remove Drop Rule

**Json Patch**

    [
        {
            "op": "remove",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3",
            "value":{}
        }
    ]

**Expected result**
 - Operation Success

**Additional checks**
- Check that “show acl rule RULE_3” results in no output

### Replace Non-Existent Rule
**Json Patch**

    [
        {
            "op": "replace",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_10",
            "value": {
                "DST_IP": "103.23.2.2/32",
                "PRIORITY": "9999",
                "PACKET_ACTION": "FORWARD"
            }
        }
    ]

**Expected result**
- Operation Failure

**Additional checks**
- None

### Replace Content of a Rule

**Json Patch**

    [
        {
            "op": "replace",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1",
            "value": {
                "DST_IP": "103.23.2.2/32",
                "PRIORITY": "9999",
                "PACKET_ACTION": "FORWARD"
            }
        },
        {
        "op": "replace",
        "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_2",
            "value": {
                "DST_IPV6": "103:23:2:1::2/128",
                "PRIORITY": "9998",
                "PACKET_ACTION": "FORWARD"
            }
        }
    ]

**Expected result**
- Operation Success

**Additional checks**
+ Check that results of “show acl rule | grep RULE_1” and “show acl rule | grep RULE_2” match the following output:
  + DYNAMIC_ACL_TABLE | RULE_1 | 9999  | FORWARD   | DST_IP: 103.23.2.2/32
  + DYNAMIC_ACL_TABLE | RULE_2 | 9998  | FORWARD   | DST_IPV6: 103.23.2.1::2/128

### Remove Forward Rules
**Json Patch**:

    [
        {
            "op": "remove",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1",
            "value": {}
        },
        {
            "op": "remove",
            "path": "/ACL_RULE",
            "value": {}
        }
    ]

**Expected result**
- Operation Success

**Additional checks**
- Check that “show acl rule RULE_1” and “show acl rule RULE_2” both result in no output

### Remove Non-Existent Table
**Json Patch**:

    [
        {
            "op": "remove",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE_BAD",
            "value": { }
        }
    ]

**Expected result**
- Operation Failure

**Additional checks**
- None

### Remove ACL Table

**Json Patch**

    [
        {
            "op": "remove",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
            "value": { }
        }
    ]

**Expected result**
- Operation Success

**Additional checks**
- None

### Remove ACL Table Type
**Json Patch:**

    [
        {
            "op": "remove",
            "path": "/ACL_TABLE_TYPE",
            "value": { }
        }
    ]

**Expected result**
- Operation Success

**Additional checks**
- None
