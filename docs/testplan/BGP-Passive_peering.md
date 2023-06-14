- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Passive Peering

## Overview

The goal of this test is to verify that BGP sessions stay established when passive peering is enabled.
It also tests various password matches and mismatches to ensure proper state is maintained.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for BGP expected behavior with passive peering and passwords.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show run bgp | Display the current BGP configuration |
| show ip bgp summary | Dispaly current session status, can be done with ipv6 too |

### Related DUT configuration files

N/A

### Related SAI APIs

N/A

## Test structure
### Setup configuration

This test requires BGP neighbors to be configured and established.

### Configuration scripts

N/A

## Test cases
### Test case #1 - Passive Peering for IPv4

#### Test objective

Enable passive peering to a neighbor and change passwords for IPv4 neighbor.
1. Configure passive peering on neighbor link and ensure session stays established
2. Configure password on DUT and ensure the adjacency is not established
3. Configure password on Neighbor and ensure the adjacency is established
4. Configure mismatch password on DUT and ensure the adjacency is not established

### Test case #2 - Passive Peering for IPv6

#### Test objective

Enable passive peering to a neighbor and change passwords for IPv6 neighbor.
1. Configure passive peering on neighbor link and ensure session stays established
2. Configure password on DUT and ensure the adjacency is not established
3. Configure password on Neighbor and ensure the adjacency is established
4. Configure mismatch password on DUT and ensure the adjacency is not established
