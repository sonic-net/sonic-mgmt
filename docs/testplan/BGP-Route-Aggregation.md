[Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Route Aggregation

## Overview

The goal of this test is to verify that summary-only, as-set summary-only, and suppress map route aggregation
operates as expected.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test route aggregation.

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
### Test case #1 - Route Aggregation

#### Test objective

Step 1: Configure DUT to use summary-only route aggregation
Step 2: Verify expected number of routes are shared to neighbor
Step 3: Configure DUT to use as-set summary-only route aggregation
Step 4: Verify expected number of routes are shared to neighbor
Step 5: Configure prefix list and route map and use sto aggregate routes
Step 6: Verify expected number of routes are shared to neighbor
