- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Docker Container Restart

## Overview

The goal of this test is to verify that BGP connectivity is restored after the docker container is restarted.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for resilance with BGP docker container.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| docker restart bgp{asic ID} | Restart docker container for the specified asic ID |
| docker ps | list currently running docker containers |

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
### Test case #1 - Restart docker container

#### Test objective

Verify BGP neighbors are same before and after BGP docker container is reset
1. Configure DUT and neighbor to use BGP
2. Restart BGP docker container
3. Verify neighbors are the same from before and after restart
