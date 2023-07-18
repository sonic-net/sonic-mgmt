- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Single Switch Reboot

## Overview

The goal of this test is to verify that dut is operational post reboot.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to verify operation after SONiC dut is rebooted.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show ip bgp summary |

### Related DUT configuration files

N/A

### Related SAI APIs

N/A

## Test structure
### Setup configuration

N/A

### Configuration scripts

N/A

## Test cases
### Test case #1 - Individual Neighbor Flapping

#### Test objective

Reboot DUT and ensure DUT is operational post reboot.
1. Gather base total bgp routes
2. Reboot neighbor and wait for critial processes
3. Wait for critial processes
4. Check interface status are up on all ports
5. Verify base and post reboot total bgp route count are equal
