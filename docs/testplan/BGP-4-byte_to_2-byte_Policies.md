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
### Test case #1 - 4-byte AS Translation

#### Test objective

Step 1: Configure DUT with 4-Byte ASN and update neighbor configuration with DUT's 4-Byte ASN
Step 2: Verify BGP session between DUT(4-Byte) and neighbor(2-Byte) is established
Step 3: Configure loopback interfaces to advertise.
Step 4: Configure and verify policy to permit only Default Route
Step 5: Configure and verify policy to permit only the first two prefixes
Step 6: Configure and verify policy with AS-path prepend
Step 7: Configure and verify AS-path access list using Regexp (matching)
Step 8: Configure and verify AS-path access list using Regexp (non-matching)
Step 9: Configure and verify Community-list policy to permit only first two routes
Step 10: Configure and verify Community-list policy to permit remaining Routes
Step 11: Configure and verify Community-list policy to permit only first two routes using regexp
Step 12: Configure and verify Community-list policy to permit remaining Routes using regexp
