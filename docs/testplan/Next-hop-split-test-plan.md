# **Next Hop Split Test Plan**

 - [Introduction](#introduction)
 - [Scope](#scope)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)

# Introduction

This is the test plan for the next hop group split enhancement

The PR covered in this test plan is [Next hop group split HLD PR 712](https://github.com/sonic-net/SONiC/pull/712)

## Scope

This test plan covers a new method of programming routes into APP_DB, where the next hop information is included in a separate NEXT_HOP_GROUP_TABLE referenced by the ROUTE_TABLE and LABEL_ROUTE_TABLE.

There is no support in the BGP container/fpmsyncd for this feature, so routes and next hop groups are all programmed directly into APP_DB by the test scripts.

# Test Setup

These test cases will be run in the T0 topology.

# Test Cases

The methods used to support these test cases will be very similar to the methods in test_static_route.py (for adding IP addresses and routes and for checking traffic).

## Test Case 1. IPv4 routes

### Test Objective
Verify that IPv4 routes and next hop groups can be programmed and cause the correct data plane behaviour.

### Test Steps
* Create an IPv4 next hop group with a single next hop
* Create an IPv4 prefix route referencing the next hop
* Create an IPv4 next hop group with multiple next hops
* Update the route to reference the new next hop group

### Pass/Fail Criteria
*  After the route is created verify that traffic for the prefix is routed via the next hop
*  After the route is updated verify that traffic for the prefix is routed via a next hop in the group

## Test Case 2. IPv6 routes

### Test Objective
Verify that IPv6 routes and next hop groups can be programmed and cause the correct data plane behaviour.

### Test Steps
* Create an IPv6 next hop group with a single next hop
* Create an IPv6 prefix route referencing the next hop
* Create an IPv6 next hop group with multiple next hops
* Update the route to reference the new next hop group

### Pass/Fail Criteria
*  After the route is created verify that traffic for the prefix is routed via the next hop
*  After the route is updated verify that traffic for the prefix is routed via a next hop in the group

## Test Case 3. MPLS routes

### Test Objective
Verify that MPLS routes and next hop groups can be programmed and cause the correct data plane behaviour.

### Test Steps
* Create an IPv4 next hop group with a single labeled next hop
* Create a label route referencing the next hop
* Create an IPv4 next hop group with multiple labeled next hops
* Update the label route to reference the new next hop group

### Pass/Fail Criteria
*  After the route is created verify that traffic for the prefix is routed via the next hop
*  After the route is updated verify that traffic for the prefix is routed via a next hop in the group
