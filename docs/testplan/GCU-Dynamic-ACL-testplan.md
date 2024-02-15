# Dynamic ACL Update via GCU Test Plan

## Overview

This test plan will certify that Generic Config Updater (GCU) is able to properly add, remove, and update ACL Table Types, ACL Tables, and ACL Rules.

## Testbed

The test will run on T0 testbeds.

## Setup Configuration

No setup pre-configuration is required, the test will configure and return the testbed to its original state.

## Testing Plan

To test the capability of GCU to dynamically update ACLs, we will utilize various Json Patch files to create, update, and remove various ACL Tables and Rules.  The contents of the Json Patch files, as well as additional details about verification processes, will be defined in [JSON Patch Files and Expected Results](json-patch-files-and-expected-results).

### Test Case # 1 - Create and apply custom ACL table without rules

#### Test Objective

Verify that we can utilize GCU to create a custom ACL Table Type, and then create an ACL Table from this type

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Verify that both operations were successful

- Verify that output of "show acl table {tablename}" matches expected output

### Test Case # 2 - Create a drop rule within custom table

#### Test Objective

Verify that we can create a single drop rule utilizing GCU

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Create a new drop rule on our new ACL Table

- Verify that all operations were successful

- Verify that output of "show acl rule | grep {rule_name}" matches expected output

### Test Case # 3 - Create 2 forward rules witihin custom ACL table

#### Test Objective

Verify that we can create a forward rule utilizing GCU, and that we can create forward rules for both ipv4 and ipv6

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Create 2 new forwarding rules on our new ACL Table

- Verify that all operations were successful

- Verify that for both rules created, "show acl rule | grep {rulename}" matches expected output for both rules

### Test Case # 4 - Remove a drop rule from the ACL table

#### Test Objective

Verify that we can remove a previously created drop rule from our ACL Table

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Create a drop rule on this ACL Table

- Remove the drop rule from this ACL Table

- Verify that all operations were successful

- Verify that the result of "show acl rule {rule_name}" has no relevant output

### Test Case # 5 - Replace the IP Address on an ACL Rule

#### Test Objective

Verify that after creation, ACL Rules can have their match conditions updated

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Create 2 new forwarding rules on ACL Table

- Replace the IP addresses in both forwarding rules

- Verify that all operations were successful

- Verify that the results of "show acl rule | grep {rule_name}" matches expected output for both rules

### Test Case # 6 - Replace the IP Address of a non-existent ACL Rule

#### Test Objective

Verify that attempting to replace the address of a rule that does not exist properly results in an error and does not affect configDB

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Create 2 new forwarding rules on ACL Table

- Replace the IP addresses in non-existent forwarding rules

- Verify that the replace action failed

### Test Case # 7 - Remove non-existent ACL Table

#### Test Objective

Verify that attempting to remove an ACL Table that does not exist properly results in an error and does not affect configDB

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Attempt to remove a table that does not exist

- Verify that this removal fails

### Test Case # 8 - Remove ACL Table

#### Test Objective

Verify that it is possible to remove a custom ACL Table after creating it via GCU

#### Testing Steps

- Create a new ACL Table Type

- Create an ACL Table utilizing this ACL Table Type

- Remove this ACL Table Type

- Verify all operations were successful

### Test Case # 9 - Remove ACL Table Type

#### Test Objective

Verify that it is possible to remove a custom ACL Table Type after creating it

#### Testing Steps

- Create a new ACL Table Type

- Remove this ACL Table Type

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
                "ports": ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"]
            }
        }
    ]

**Expected result**
- Operation Success


**Additional checks**
- Check that results of the command “show acl table” match this expected output:

Name  | Type | Binding | Description | Stage
------------- | ------------- | ---------- | ----------| ---------
DYNAMIC_ACL_TABLE | DYNAMIC_ACL_TABLE_TYPE | Ethernet4 | DYNAMIC_ACL_TABLE_TYPE | ingress
  | | Ethernet8 | |
  | | Ethernet12...

### Create A Duplicate ACL Table

**Json Patch**:
- Identical to previous test

**Expected result**
- Operation Success

**Additional checks**
- None

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
                "IN_PORTS": "Ethernet4"
            }
        }
    ]

**Expected result**
- Operation Success

**Additional checks:**
+ Check that result of “show acl rule | grep RULE_3” matches the following output:
  + DYNAMIC_ACL_TABLE | RULE_3 | 9997  | DROP  | IN_PORTS: “Ethernet4”

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
