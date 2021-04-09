# **LAG on Distributed VOQ Architecture Test Plan**

 - [Introduction](#introduction)
 - [Scope](#scope)
 - [Assumptions](#assumptions)
 - [Debuggability](#debuggability)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)
     
# Introduction 

This is the test plan for LAG on SONIC Distributed VOQ System, as described in the [VOQ LAG HLD](https://github.com/Azure/SONiC/blob/2e05c6b8ac570fd237484a18e732a58eec004b9c/doc/voq/lag_hld.md)

The PR covered in this test plan is [Distributed VOQ LAG HLD PR 697](https://github.com/Azure/SONiC/pull/697/files#diff-77ea0c16b4ae9885fa0e388e81f6343c6bda0f24b999f93e64fcee8467df63fc)

## Scope

The scope of this test plan is as follows:
* Check for unique SYSTEM_LAG_ID per LAG in a chassis with multiple line cards
* Check if LAG is learned by local and remote ASIC

This test plan does not cover functioning of LAG as an IP/Layer3 endpoint as that is outside the scope of the code PR.

## Assumptions

The current SW design for LAG assumes that configuration changes are always saved prior to any system events or platform events like card insertion/removal or reboots.
All configuration changes mentioned in this document are done using SONiC CLI commands.

## Debuggability

The following are useful commands for validating the testcases that follow, in lieu of show commands.

1. To get SYSTEM_LAG_TABLE from CHASSIS_DB

	`redis-dump -H 10.0.0.16 -p 6380 -d 12 -y -k "*SYSTEM_LAG_TABLE*"`

2. To check in ASIC_DB on local and remote ASIC

	`redis-dump -d 1 -y -k "*LAG:*" `

3. To check APPL_DB on local

	`redis-dump -d 0 -y -k "*LAG*"`


# Test Setup

These test cases will be run in the proposed [T2 topology](https://github.com/Azure/sonic-mgmt/blob/master/ansible/vars/topo_t2.yml). It is assumed that such a configuration is deployed on the chassis.

The pretest checks (prerequisite) will ensure that the LAGs and members are in configured correctly in the CHASSIS_DB, APPL_DB and ASIC_DB on each line card.

# Test Cases

## Test Case 1. Dynamic addition of LAG via CLI

### Test Objective
Verify that when a LAG is dynamically added via CLI on an ASIC, it is populated in remote ASIC_DB.

### Test Steps
* On any ASIC, add a new LAG
* Delete the added LAG

### Pass/Fail Criteria
*  Verify on ANY line cards, that the value of the LAG_ID is unique for that LAG in CHASSIS_DB in SYSTEM_LAG_TABLE
*  Verify on THE line card, that the LAG is populated in local ASIC_DB and APPL_DB.
*  Verify on ALL line cards, that the LAG is populated in ASIC_DB.

### Sample output
To verify SYSTEM_LAG_ID from SYSTEM_LAG_ID_TABLE on CHASSIS_DB
```
admin@Linecard8:/$redis-dump -H 10.0.0.16 -p 6380 -d 12 -y -k "*SYSTEM_LAG_TABLE*"
	  "SYSTEM_LAG_ID_TABLE": {
	    "expireat": 1554651948.54161, 
	    "ttl": -0.001, 
	    "type": "hash", 
	    "value": {
	      "Linecard8|Asic0|PortChannel0001": "1", 
	      "Linecard8|Asic0|PortChannel0002": "2"
	    }
	  }
```
  To verify LAG is populated in local APPL_DB
  ```
  admin@Linecard8:/$ redis-dump -d 0 -y -k "*LAG_TABLE*"
	  "LAG_TABLE:PortChannel0001": {
	    "expireat": 1554687165.581525, 
	    "ttl": -0.001, 
	    "type": "hash", 
	    "value": {
	      "admin_status": "up", 
	      "mtu": "9100", 
	      "oper_status": "up"
	    }
	  }, 
	  "LAG_TABLE:PortChannel0002": {
	    "expireat": 1554687165.5814252, 
	    "ttl": -0.001, 
	    "type": "hash", 
	    "value": {
	      "admin_status": "up", 
	      "mtu": "9100", 
	      "oper_status": "up"
	    }
	  }
```

To verify that the LAG is synchronized to local/remote ASIC_DB:
```
on an asic 
1. Get lag id for a lag from chassis db 

2. admin@ixr-vdk-board4:~$ redis-cli -n 1 keys "*LAG:*"
 	1) "ASIC_STATE:SAI_OBJECT_TYPE_LAG:oid:0x20000000013fd"

3. admin@ixr-vdk-board4:~$ redis-cli -n 1 hgetall "ASIC_STATE:SAI_OBJECT_TYPE_LAG:oid:0x20000000013fd" 
	1) "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID"
	2) "19"

lag id should exist in ASIC DB, repeat the same step on all ASIC on other host.
```

## Test Case 2. Dynamic deletion of LAG via CLI
### Test Objective

Verify that when a LAG is dynamically deleted via CLI on an ASIC, it is removed in remote ASIC_DB.
### Test Steps
* Delete an existing LAG from any ASIC
* Add back the deleted LAG

### Pass/Fail Criteria
*  Verify on THE line card that the  LAG is deleted from LAG in local ASIC_DB and APPL_DB
*  Verify on ANY line card the LAG is removed from SYSTEM_LAG_TABLE in CHASSIS_APP_DB
*  Verify on ALL line cards that the LAG is deleted from the ASIC_DB

## Test Case 3. Dynamic addition of a LAG MEMBER via CLI

### Test Objective
Verify that when a LAG MEMBER is dynamically added via CLI on an ASIC, new member is populated in remote ASIC_DB.

### Test Steps
* On any ASIC, add a LAG and LAG_MEMBERS (We can use existing portchannel members to add in new LAG)
* Restore the config

### Pass/Fail Criteria
*  Verify on THE line card that the new member info is added to LAG in local ASIC_DB and APPL_DB
*  Verify on ANY line card the SYSTEM_LAG_MEMBER_TABLE is synced in CHASSIS_APP_DB
*  Verify on ALL line cards that the new member info is added to LAG in ASIC_DB

### Sample output
```
admin@Linecard1:/etc/sonic$ redis-cli -n 0 keys "LAG_MEMBER_TABLE:*"  
1) "LAG_MEMBER_TABLE:PortChannel0001:Ethernet2"
2) "LAG_MEMBER_TABLE:PortChannel0002:Ethernet11"
```

## Test Case 4. Dynamic deletion of a LAG MEMBER via CLI

### Test Objective
Verify that when a LAG MEMBER is dynamically deleted via CLI on an ASIC from an existing LAG, the entry is deleted from the remote ASIC_DB.

### Test Steps
* Delete a LAG Member from existing LAG
* Restore the config

### Pass/Fail Criteria
*  Verify on THE line card that the MEMBER is deleted from LAG in local ASIC_DB and APPL_DB
*  Verify on ANY line card the LAG MEMBER is removed from SYSTEM_LAG_MEMBER_TABLE in CHASSIS_APP_DB
*  Verify on ALL line cards that the MEMBER is deleted from LAG in ASIC_DB




