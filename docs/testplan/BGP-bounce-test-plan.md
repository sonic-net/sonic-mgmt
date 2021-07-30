# BGP-bounce test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
* [Test cases](#Test%20cases)

## Overview
The purpose is to test the functionality of no-export BGP community feature on the SONIC switch DUT. The tests expecting that all necessary configuration for no-export community are pre-configured on SONiC switch before test run

### Scope
The test is targeting a running SONiC system with fully functioning configuration. Purpose of the test is to verify a SONiC switch system correctly performs no-export BGP community implementation based on configured rules.

### Testbed
The test will run on the following testbeds:
* t1

## Setup configuration
This test requires to change default BGP configuration. We need to enable or disable sending learned routes to the peers of outside AS.

## Test
On BGP container of DUT would be applied no-export BGP community configuration. After that ToR VM gets no export routes.

## Test cases
### Test case test_bgp_bounce
#### Test steps
* Generate BGP plain config
* Generate BGP no export config
* Apply BGP plain config
* Get no export routes on one of the ToR VM
* Apply BGP no export config
* Get no export routes on one of the ToR VM
* Apply default BGP config