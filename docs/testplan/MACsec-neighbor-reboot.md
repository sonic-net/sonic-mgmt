- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Neighbor Reboot

## Overview

The goal of this test is to verify that the macsec neighbor relationship is established after the neighbor is rebooted.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to verify
the behavior of a pair of Macsec peers when a neighbor reboots while Macsec is Active and ensure the peer session
returns to functioning state.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| reboot | Reboot Sonic device |

### Related DUT configuration files

N/A

### Related SAI APIs

N/A

## Test structure
### Setup configuration

This test requires MACsec neighbors to be configured and established.

### Configuration scripts

N/A

## Test cases
### Test case #1 - Individual Neighbor Reboot

#### Test objective

Have a single neighbor reboot and verify MACsec link re-establishes with DUT.
1: Configure Macsec between neighbor and DUT
2: Save config on neighbor and reboot
3: Verify macsec connection is re-established after reboot
