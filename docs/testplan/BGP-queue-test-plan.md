# BGP-queue test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
* [Test cases](#Test%20cases)

## Overview
The purpose is to make sure that BGP control packets use unicast queue 7 by default on all SONiC platforms.
The test expects that basic BGP configuration for the test is pre-configured on SONiC device before test run.

### Scope
The test is targeting a running SONiC system with fully functioning configuration. The purpose of the test is to verify BGP control packets use egress queue 7 on SONiC platforms.

### Testbed
The test could run on any testbed.

## Setup configuration
This test requires BGP neighbors to be configured and established before the test run.

## Test
The test will verify that all BGP packets use unicast queue 7 by default. It is to be noted that if BGP sessions are established over PortChannels, LACP packets will also use the same unicast queue 7, but that does not impact the test functionality.

## Test cases
### Test case test_bgp_queue
#### Test steps
* Clear all queue counters using "sonic-clear counters" command
* Generate a mapping of neighbors to the corresponding interfaces/ports using ARP/NDP entries
* For all "established" BGP sessions, run "show queue counters" on the corresponding port
* Verify that unicast queue 7 counters are non-zero and that unicast queue 0 counters are zero
