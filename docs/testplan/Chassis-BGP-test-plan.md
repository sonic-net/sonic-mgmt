# **BGP on Distributed VOQ System Test Plan**

 - [Introduction](#introduction)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)

# Introduction

This is the test plan for BGP on distributed VOQ system, as described in the
[Distributed VOQ HLD](https://github.com/Azure/SONiC/blob/master/doc/voq/voq_hld.md)
and [BGP VOQ HLD](https://github.com/Azure/SONiC/blob/master/doc/voq/bgp_voq_chassis.md).

# Test Setup

The test cases proposed in the test plan will be run in [T2 topology](https://github.com/Azure/sonic-mgmt/blob/master/ansible/vars/topo_t2.yml).

# Test Cases

## Test Case #1: Test route propagation/withdrawal through BGP.

### Test Objective
Verify routing updates via eBGP session is propagated throughout the chassis.

### Test Steps
* Select one linecard for injecting routes.
* Inject routes into the selected linecard from the adjacent VM.
* Verify the route is learned on the selected linecard using eBGP.
* Verify the route is learned on the other linecards using iBGP over inband interface.
* Withdraw the route from the adjacent VM of the selected linecard.
* Verify the route is withdrawn from all the linecards in the chassis.
* Repeat with IPv4, IPv6, dual-stack.

## Test Case #2: Test ECMP groups with eBGP and iBGP paths.

### Test Objective
Verify that ECMP groups can be formed with routes having both eBGP and iBGP paths.

### Test Steps
* Select two linecard for injecting routes.
* Inject same route into the selected linecards from the adjacent VMs.
* On all the selected linecards verify route is learned as ECMP route with
one eBGP path and other iBGP path. Verify the rib has both direct eBGP nexthop
and the nexthop that learned over iBGP and resolved recursively.
* Withdraw route from one of VM peers and verify that the ECMP roue is made
as a regular route.
* Repeat with IPv4, IPv6, dual-stack.

## Test Case #3: Test eBGP ECMP groups are propagated.

### Test Objective
Verify that eBGP ECMP group is propagated to all linecards.

### Test Steps
* Select one linecard for injecting routes.
* Inject same route into the selected linecard from two different adjacent VMs so that a eBGP
ECMP group is formed.
* Verify the route is learned on the selected linecard using eBGP.
* Verify the route with both the nexthops is learned on the other linecards using iBGP over
inband interfaces.
* Withdraw the route from the adjacent VM of the selected linecard.
* Verify the route is withdrawn from all the linecards in the chassis.
* Repeat with IPv4, IPv6, dual-stack.

## Test Case #4: eBGP convergence on Link flap.

### Test Objective
Verify eBGP session is reestablished and routes relearnt on a link flap.

### Test Steps
* Select one linecard for injecting routes.
* Inject routes into the selected linecard from the adjacent VM.
* Verify the route is learned on the selected linecard using eBGP.
* Verify the route is learned on the other linecards using iBGP over inband interface.
* Shutdown the front panel port connecting the linecard to the adjacent VM and verify
that the routes learnt via eBGP session is withdrawn from all the other linecards
in the chassis.
* Enable the front panel back and verify the eBGP session comes back up and all
the linecards relearn the routes.
* Repeat with IPv4, IPv6, dual-stack.

## Test Case #5: Disruptive events.

### Test Objective
Verify that eBGP session and all routes reconverge after disruptive events.

### Test Steps
* Setup the chasis with the following routes.
   * Normal routes learnt via eBGP.
   * ECMP groups with eBGP and iBGP paths.
   * eBGP ecmp groups that propagates through the chassis.

* With this setup perform, chassis power cycle and supervisor reboot and verify,
all the eBGP session reconverge on all the linecards and all the routes in the
previous steps are relearnt.
* Repeat with IPv4, IPv6, dual-stack.
