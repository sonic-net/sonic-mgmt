- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Protocol Shutdown

## Overview

Verify macsec sessions are up after disabling and enabling macsec
with macsec already configured.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to verify macsec sessions are up post flaping of the
macsec protocol globally.

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

While macsec is up
1. Check MKA sessions and ensure sessions are protected.
2. Disable the macsec feature.
3. Enable macsec feature.
4. Check MKA sessions and ensure sessions are restored and protected.
