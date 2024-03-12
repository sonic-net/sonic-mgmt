- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Docker Restart

## Overview

Verify macsec becomes active after restart macsec docker conatiner.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to verify macsec operation after macsec docker container is restarted.

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

Restart macsec docker container while macsec is configured/active.
1. Restart the Macsec Docker container
2. Check appl_db
