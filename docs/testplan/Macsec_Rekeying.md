- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Rekeying

## Overview

Verify rekey occurs after reconfiguring the rekey period.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to verify macsec rekey occurs after
re-configuring the rekey period.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| N/A |

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

Reconfigure the macsec rekey period and wait for rekey to occur.
1. Disable the macsec port.
2. Reconfigure the macsec rekey period.
3. Reconfigure the macsec port.
4. Wait for macsec rekey to occur.
5. Verify rekey occurs on both dut and neighbor.
