- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose is to test how fast FRR propogates updates received from a neighbor to other neighbors. [BGP RFC 4721](https://tools.ietf.org/html/rfc4271#section-9.2.1.1) defines MinRouteAdvertisementIntervalTimer which set the minimum amount of time that must elapse between an advertisement and/or withdrawal of routes to a particular destination by a BGP speaker to a peer. Quagga 0.99.24.1 has an optimization to send BGP updates as fast as possible, but wait MinRouteAdvertisementIntervalTimer for withdraw messages. FRR has optimization for both updates and withdraws. The test should check this.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of BGP implementation on SONIC system.

### Testbed
The test could run on on any testbed.

## Setup configuration
IPv4 BGP neighborship will be configured between DUT and two exabgps. First exabgp will send updates and withdraws of IPv4 routes to the second exabgp.

## Test
On PTF host two exabgp instances would be configured. After that the first exabgp will be used to generate bgp events, and the other exabgp will be used to register time, when the event have been propogated from the first exabgp.

## Test cases
### Test case # 1 - Measure the propogation time for both update and withdraw messages
* Start two exabgp instances on ptf host
* Start capturing bgp packets on both ptf hosts
* Check that the DUT sees both exabgp sessions as 'Established'
* Send updates from the first exabgp, capture the bgp packets on the second exabgp
* Send withdraws from the first exabgp, capture the bgp packets on the second exabpp
* Repeat previous two lines for 5 times
* Extract maximum propagation times for bgp events from the first exabgp to the second
