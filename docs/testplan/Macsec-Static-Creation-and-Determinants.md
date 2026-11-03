- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec Protocol Shutdown

## Overview

Verify macsec session is not configured with invalid cipher, cak, ckn, policy and priority.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is to determine the restrictions on Static Keys.

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

Test Case #1 - Configure macsec with invalid cipher suite
Test Case #2 - Configure macsec with invalid policy
Test Case #3 - Configure macsec with invalid CAK
Test Case #4 - Configure macsec with invalid CKN
Test Case #5 - Configure macsec with invalid priority

#### Test objective

Attempt to configure macsec with invalid cipher-suite, policy, CAK, CKN, and priority and ensure error is produced.
