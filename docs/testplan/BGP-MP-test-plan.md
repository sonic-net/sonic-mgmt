# BGP-MP test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
   * [Ansible scripts to setup and run test](#Ansible%20scripts%20to%20setup%20and%20run%20test)
     * [bgp_mp.yml](#bgp_mp.yml)
   * [Setup of DUT switch](#Setup%20of%20DUT%20switch)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to test functionality of BGP-MP on the SONIC switch DUT, closely resembling production environment. The test assumes all necessary configurations are already pre-configured on the SONIC switch before test runs.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of BGP-MP on SONIC system.

### Testbed
The test will run on the following testbeds:
* t0

## Setup configuration
IPv4 BGP neighborship will be configured between DUT and exabgp and each neighbor will redistribute IPv6 routes to each other.
### Ansible scripts to setup and run test
#### bgp_mp.yml
bgp_mp.yml when run with tag “bgp_mp” will do the following:
1. Generate and apply exabgp configuration.
2. Run test.
3. Clean up dynamic and temporary exabgp configuration.

## Test
On PTF host, exabgp tool will be used to configure bgp peer and redistribute IPv6 routes via IPv4 BGP session.

## Test cases
### Test case # 1 – BGP-MP IPv6 routes over IPv4 session
#### Test objective
Verify that IPv6 routes are correctly redistributed over IPv4 BGP session.
#### Test steps
* Generate IPv4 BGP peer configuration for exabgp instance.
* Generate IPv6 routes, to be announced via IPv4 session, for exabgp instance.
* Run exabgp instance.
* Verify that IPv4 BGP neighborship is established.
* Redistribute IPv6 routes using exabgp.
* Verify that IPv6 routes are correctly redistributed to the DUT.
* Redistribute IPv6 routes from the DUT to exabgp.
* Verify that IPv6 routes are correctly redistributed to the exabgp.
* Set default configuration.

## TODO

## Open questions
* Should be some traffic test cases performed as part of this test?