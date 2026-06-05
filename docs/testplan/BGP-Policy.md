- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Policy

## Overview

The goal of this test is to verify that the BGP policy feature works as expected in different configurations.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BGP Policy feature.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| router bgp <ASN> | Enter BGP config mode |
| neighbor <neighor IP> route-map <RM> out | Set the route map for neighbor |
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
### Test case #1

#### Test objective

Configure loopback interfaces to advertise.
1. Configure and verify policy to permit only Default Route
2. Configure and verify policy to permit only the first two prefixes
3. Configure and verify policy with AS-path prepend
4. Configure and verify AS-path access list using Regexp (matching)
5. Configure and verify AS-path access list using Regexp (non-matching)
6. Configure and verify Community-list policy to permit only first two routes
7. Configure and verify Community-list policy to permit remaining Routes
8. Configure and verify Community-list policy to permit only first two routes using regexp
9. Configure and verify Community-list policy to permit remaining Routes using regexp
