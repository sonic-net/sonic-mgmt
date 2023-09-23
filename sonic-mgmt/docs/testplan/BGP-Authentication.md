- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Authentication

## Overview

The goal of this test is to verify that the BGP authentication feature works as expected.  It tests both peer group and individual neighbor configurations.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BGP Authentication feature, which includes peer group and individual neighbor implementation.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| router bgp <ASN> | Enter BGP config mode |
| neighbor <peer group or neighbor IP> password <pass> | Set the password for peer group or neighbor |
|Show commands|
| show run bgp | Display the current running BGP configuration |
| show ip bgp summary | Dispaly current neighbor relationships, can be done with ipv6 too |

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
### Test case #1 - Peer Group

#### Test objective

Configure peer group passwords for IPv4 and IPv6 for specified neighbor and ensure relationship is established.
1. Configure peer group passwords for both IPv4 and IPv6 on DUT
2. Verify neighbor is not up
3. Configure password on neighbor
4. Verify neighbor is up
5. Set a mismatched password on DUT
6. Verify neighbor is not up
7. Turn off passwords on DUT and neighbor

### Test case #2 - Individual Neighbor

#### Test objective
Configure individual passwords for IPv4 and IPv6 for specified neighbor and ensure relationship is established.
1. Configure neighbor passwords for IPv4 and IPv6 on DUT
2. Verify neighbor is not up
3. Configure password on neighbor
4. Verify neighbor is up
5. Set a mismatched password on DUT
6. Verify neighbor is not up
7. Turn off passwords on DUT and neighbor
