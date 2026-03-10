- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

IPv6 NLRI over IPv4

## Overview

The goal of this test is to verify that the IPv6 NLRI over IPv4 feature operates as intended.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test the IPv6 NLRI over IPv4 feature.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show ip bgp summary | Dispaly current memory statistics, can be done with ipv6 too |
| show ipv6 bgp neighbor <neighbor> received-routes | Neighbor is the intended testing neighbor |
| show run bgp | Display the current BGP running configuration |
| show ipv6 route <route> | Display information on specific BGP route |

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
### Test case IPv6 NLRI Over IPv4

#### Test objective

Have a single neighbor disable and enable BGP to flap the session with DUT.
1. Gather base BGP and route information from DUT and neighbor
2. Remove the IPv4 and IPv6 BGP neighbor config, and reconfigure only the IPv4 neighbor
3. Verify no routes are shared between devices
4. Configure NLRI
5. Verify IPv6 routes are shared with no IPv6 neighbors configured
