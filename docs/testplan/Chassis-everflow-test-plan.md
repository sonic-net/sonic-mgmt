# **Everflow on Distributed VOQ System Test Plan**

 - [Introduction](#introduction)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)

# Introduction

This is the test plan for Everflow on distributed VOQ system, as described in the [VOQ Everflow HLD](https://github.com/sonic-net/SONiC/blob/master/doc/voq/everflow.md).

# Test Setup

The test cases proposed in the test plan will be run in [T2 topology](https://github.com/sonic-net/sonic-mgmt/blob/aster/ansible/vars/topo_t2.yml).

# Test Cases

All test cases in the test plan will cover both IPv4 and IPv6 mirror destination.

## Test Case #1: Mirrorring packets to local destination port.

### Test Objective
Verify mirror session programming for local destination port.

### Test Steps
* Select one linecard for injecting packets.
* Configure mirror session with destination IP that is resolved through a route pointing to local neighbor.
* Inject packets.
* Verify that packets are mirrored to the desired destination port.
* Verify that headers of mirrored packets are correct.
* Verify that mirrored packet payload is equal to sent packets.

## Test Case #2: Mirrorring packets to remote destination port.

### Test Objective
Verify mirror session programming for remote destination port.

### Test Steps
* Select one linecard for injecting packets.
* Configure mirror session with destination IP that is resolved through a route pointing to remote neighbor.
* Inject packets.
* Verify that packets are mirrored to the desired port in remote linecard.
* Verify that headers of mirrored packets are correct.
* Verify that mirrored packet payload is equal to sent packets.

## Test Case #3: Neighbor MAC change.

### Test Objective
Verify mirror session programming when neighbor MAC changes.

### Test Steps
* Select one linecard for injecting packets.
* Configure mirror session with destination IP that is resolved through a route pointing to remote neighbor.
* Inject packets.
* Verify that packets are mirrored to the desired port in remote linecard.
* Verify that headers of mirrored packets are correct.
* Change neighbor MAC address.
* Inject packets and verify that DST MAC address in mirrored packet header is changed accordingly.

## Test Case #4: Mirror destination resolution change.

### Test Objective
Verify that mirror session programming is updated when mirror destination resolution changes.

### Test Steps
* Select one linecard for injecting packets.
* Add a route with unresolved local next hop.
* Configure mirror session with destination IP that is resolved through the route.
* Inject packets and verify that no packets are mirrored.
* Resolve route next hop.
* Inject packets and verify that packets are mirrored to local destination port.
* Add a longer prefix route with resolved remote next hop.
* Inject packets and verify that packets are mirrored to remote destination port.
* Remove the longer prefix route.
* Inject packets verify that packet are mirrored to local destination port.

## Test Case #5: Add and remove next hops to resolving route.

### Test Objective
Verify that mirror session programming is correct when adding or removing next hops from resolution route.

### Test Steps
* Select one linecard for injecting packets.
* Add a route with 1 resolved next hop from local linecard and 2 unresolved next hops from the other two linecards.
* Inject packets and verify that packets are mirrored to local destination port.
* Resolve one of the unresolved next hop.
* Inject packets and verify that packets are mirrored to ANY of resolved next hops.
* Resolve another unresolved next hop.
* Inject packets and verify that packets are mirrored to ANY of resolved next hops.
* Unresolve local next hop.
* Inject packets and verify that packets are mirrored to ANY of the remote next hops.
