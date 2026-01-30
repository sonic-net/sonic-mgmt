- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

4byte to 2byte BGP Policy

## Overview

The goal of this test is to verify that the applied 4byte (DUT) to 2byte (neighbor)
policies manipulate traffic as expected for the configured routes.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test 4byte to 2byte BGP Policy.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show ip bgp summary | Dispaly current memory statistics, can be done with ipv6 too |

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
### Test case #1 - 4-byte to 2-byte BGP Policies

#### Test objective

1. Configure DUT with 4-Byte ASN and update neighbor configuration with DUT's 4-Byte ASN
2. Verify BGP session between DUT(4-Byte) and neighbor(2-Byte) is established
3. Configure loopback interfaces to advertise.
4. Configure and verify policy to permit only Default Route
5. Configure and verify policy to permit only the first two prefixes
6. Configure and verify policy with AS-path prepend
7. Configure and verify AS-path access list using Regexp (matching)
8. Configure and verify AS-path access list using Regexp (non-matching)
9. Configure and verify Community-list policy to permit only first two routes
10. Configure and verify Community-list policy to permit remaining Routes
11. Configure and verify Community-list policy to permit only first two routes using regexp
12. Configure and verify Community-list policy to permit remaining Routes using regexp
