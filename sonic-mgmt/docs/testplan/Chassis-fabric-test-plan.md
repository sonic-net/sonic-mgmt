# **VOQ Chassis Fabric Test Plan**

 - [Introduction](#introduction)
 - [Scope](#scope)
 - [Assumptions](#assumptions)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)
     
# Introduction 

This is the test plan for Fabric link testing on SONIC Distributed VOQ System, as described in the [VOQ Fabric HLD](https://github.com/Azure/SONiC/blob/master/doc/voq/fabric.md)

## Scope

The scope of this test plan is as follows:
* Check if all the expected fabric links are up.
* Check if the fabric counters work correctly when there is data traffic.
* Check if the fabric devices can reach all of the forwarding ASICs of the chassis (reachability)

## Assumptions

The current SW design for fabric does not cover events like card insertion/removal or reboots. This test plan depends on fabric counter cli support (work in progress).

# Test Setup

These test cases will be run in the proposed [T2 topology](https://github.com/Azure/sonic-mgmt/blob/master/ansible/vars/topo_t2.yml). It is assumed that such a configuration is deployed on the chassis.

tbinfo will be populated with the number of fabric links per forwarding ASIC that are expected to be up.

# Test Cases

## Test Case 1. Test Fabric connectivity

### Test Objective
Verify that when the chassis is up and running, the fabric links that are expected to be up are up.

### Test Steps
* For each ASIC in the chassis (across different duts), run `show fabric counters port -n <asic_name>` 

### Pass/Fail Criteria
* Verify for each ASIC, the number of links that are up matches the number of links per ASIC defined in the inventory. This is expected to be stored in the host_var attribute.

## Test Case 2. Test fabric reachability

### Test Objective
Verify that from each fabric ASIC, all forwarding ASICs are reachable.

### Test Steps
* Run `show fabric reachability -n asicN` for each fabric ASIC

### Pass/Fail Criteria
* Verify for each fabric ASIC, all the forwarding ASICs in the chassis are reachable and the switch ID matches the expected switch ID.

## Test Case 3. Test fabric counters under traffic

### Test Objective
Verify that under data traffic, all fabric links from an ASIC are utilized. The assumption is that the chassis architecture supports distributing data traffic across all fabric links. 

Note that there may be some internal communication such as intra-chassis BGP, which means that the validation cannot strictly confirm exact match between ingress and egress traffic counts.
Instead, we will validate that the RX counts on the ASIC receiving traffic from the fabric are greater than or equal to the TX counts on the ASIC sending into the fabric.

### Test Steps
* Send a fixed number of packets traversing two ASICs
* Run `show fabric counters port -n asicN` for the ingress and egress ASIC. 

Repeat the above test for the following packet sizes (bytes): 64, 256, 1512, 9000

### Pass/Fail Criteria
* Verify on the ingress ASIC that all fabric links have non-zero value for TX fabric data unit counter.
* Verify on the egress ASIC that all fabric links have non-zero value for RX fabric data unit counters.
* Verify that the RX fabric data unit counters are not less than the TX counters. 
* Verify that there are no increments in error counters.

