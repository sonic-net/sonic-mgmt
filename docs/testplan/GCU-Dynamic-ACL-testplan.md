# Dynamic ACL Update via GCU Test Plan 

**Table of Contents**


## Overview

This test plan will certify that Generic Config Updater (GCU) is able to properly add, remove, and update ACL Table Types, ACL Tables, and ACL Rules. 

## Testbed 

The test will run on T0 testbeds. 

## Setup Configuration 

No setup pre-configuration is required, the test will configure and return the testbed to its original state. 

## Testing Plan 

To test the capability of GCU to dynamically update ACLs, we will: 

- Create a new ACL table type 

- Create an ACL table from this ACL table type 

- Create a duplicate ACL table 

- Create various forwarding rules 

- Create a drop rule 

- Remove the drop rule 

- Confirm that updating a non-existent rule causes an error 

- Update a rules content 

- Remove all rules 

- Confirm that removing a non-existent ACL table causes an error 

- Remove ACL table 

- Remove ACL table type 

## JSON Patch Files and Expected Results

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




