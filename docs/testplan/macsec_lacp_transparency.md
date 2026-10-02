- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

Macsec LACP Transparency

## Overview

The goal of this test is to verify that macsec sessions are secured even when LACP goes down.

### Scope

The test is targeting a running SONIC system with fully functioning configuration.

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

This test requires at least 2 portchannels with two members each and macsec.

### Configuration scripts

N/A

## Test cases
### Test case #1 - LACP Transparency

#### Test objective

1. Configure 2 portchannels on DUT with two members each.
2. First ensure portchannels are up and macsec sessions are secured.
3. Mismatch interfaces on both portchannels. LACP should go down while macsec
sessions should stay secured.
