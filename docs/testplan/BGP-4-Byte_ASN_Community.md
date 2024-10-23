- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP 4-Byte ASN Community

## Overview

The goal of this test is to verify that BGP can be configured with a 4-byte ASN community.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for compatability with 4-Byte ASN community.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show ip bgp summary | Display current BGP statistics, can be done with ipv6 too |

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
### Test case #1 - Set 4-Byte ASN Community

#### Test objective

Configure 4-Byte ASN Community and ensure neighbor relationships become established
1. Configure DUT and neighbor with 4Byte ASN
2. Verify 4-byte BGP session between DUT and neighbor is established and using the correct ASN
