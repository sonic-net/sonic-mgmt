- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Test name

BGP Session Flaps

## Overview

The goal of this test is to verify that the CPU and memory do not spike during cycles of BGP sessions flapping.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test for CPU and memory spikes during BGP session flaps.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| N/A |  |
|Show commands|
| show processes cpu | Display the current CPU statistics |
| show ip bgp summary | Dispaly current memory statistics, can be done with ipv6 too |

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
### Test case #1 - Individual Neighbor Flapping

#### Test objective

Have a single neighbor disable and enable BGP to flap the session with DUT.
1. Gather base CPU and memory statistics from DUT
2. Start neighbor BGP session flapping
3. Verify no CPU or memory spikes on DUT by running show process cpu/memory
    and ensuring the output is noticibly higher, either 10% more cpu or 30%
    more memory from baseline

### Test case #2 - Multiple Neighbors Flapping

#### Test objective
Have all neighbors disable and enable BGP to flap their sessions with DUT.
1. Gather base CPU and memory statistics from DUT
2. Start all neighbor BGP sessions flapping
3. Verify no CPU or memory spikes on DUT by running show process cpu/memory
    and ensuring the output is noticibly higher, either 10% more cpu or 30%
    more memory from baseline
