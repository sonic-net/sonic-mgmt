- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Double Switch Reboot

## Overview

The goal of this test is to verify that dut is operational and macsec is up post reboot of both dut and neighbor.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to verify operation after SONiC dut and it's
neighbor are rebooted.

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

Reboot DUT and neighbor and ensure DUT is operational post reboot.
1. Gather base total bgp routes
2. Reboot dut and neighbor
3. Wait for critial processes
4. Check interface status are up on all ports
5. Check appl_db
6. Verify base and post reboot total bgp route count are equal
