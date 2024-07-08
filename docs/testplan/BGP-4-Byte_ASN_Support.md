- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

4Byte ASN Support

## Overview

The goal of this test is to verify bgp supports 4byte ASN and session can be established.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test 4byte ASN Support.

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

Step 1: Configure DUT and neighbor with 4-Byte ASN
Step 2: Verify 4-byte BGP session between DUT and neighbor is established
