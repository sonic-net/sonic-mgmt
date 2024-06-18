- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Session Flaps

## Overview

The goal of this test is to verify that the CPU and memory do not spike during cycles of BGP sessions flapping.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for 4-Byte AS translation.

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

Have a single neighbor configured with 4-byte ASN.
Step 1: Configure DUT and neighbor with 4-Byte ASN
Step 2: Verify 4-byte BGP session between DUT and neighbor is established
Step 3: Verify BGP is established for 4-byte neighbor and down for 2-byte neighbors
Step 3: Configure DUT to use 2-byte local-ASN for 2-byte neighbors
Step 4: Verify BGP is now established for 4-byte neighbor AND 2-byte neighbors
Step 5: Verify 2-byte neighbors receive routes from upstream 4-byte routers
