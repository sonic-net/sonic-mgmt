- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Modify Policy While in Use

## Overview

Verify that attempting to modify a macsec policy while in use behaves as intended.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to that attempting to modify a macsec policy while in use
behaves as intended.

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

Modify macsec poilicy while in use.
1. Modify macsec poilicy while in use
2. Ensure error produced stating poilicy already in use
