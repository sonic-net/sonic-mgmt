- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose is to test that BGPSentinel (BGPS) host will setup an IBGP connection to FRR. BGPSentinel (BGPS) will advertise and withdraw routes to FRR. As BGPSentinel session is IBGP and not directly connected to the DUT, this feature relies on V4 and V6 nht resolve via default configuration in FRR.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of BGPSentinel configuration on SONIC system.

### Testbed
The test will run on the following testbeds:
* t1-lag (vs)

## Setup configuration
This test doesn't require any configuration in ansible deployment. IBGP session between BGPSentinel (BGPS) host and DUT are created in set up phase of this case and are cleaned in tear down phase of this case. BGPSentinel (BGPS) host is simulated by exabgp in PTF.

## Test
The test will configure BGPSentinel session and then check that IBGP session would be setup between BGPSentinel (BGPS) host and DUT. After session set up, BGPSentinel (BGPS) will advertise routes with higher local-preference and no-export community. These routes will act as best-path in DUT, which would suppress routes received from t0. The test will cover both V4 and V6 BGPSentinel session.

## Test cases
### Test case # 1 - BGPSentinel to DUT over IBGP V4 session

#### Test Objective
Test BGPSentinel V4 session would be used to advertise and withdraw V4/V6 routes

#### Test Steps
1. Setup IBGP V4 session from BGPSentinel (BGPS) host to DUT (Simulated from ptf using exabgp to DUT).
2. Find V4 and V6 routes advertised from T0.
3. Check these routes are advertised to EBGP peers.
4. In ptf, advertise the same routes with higher local-preference and no-export community to DUT.
5. Check these routes are suppressed and not advertised to EBGP peers.
6. In ptf, withdraw these routes to DUT.
7. Check these routes are advertised to EBGP peers.

### Test case # 2 - BGPSentinel to DUT over IBGP V6 session
Add BGPSentinel to DUT and check IBGP V6 session would set up and advertise V4/V6 routes

#### Test Objective
Test BGPSentinel V6 session would be used to advertise and withdraw V4/V6 routes

#### Test Steps
1. Setup IBGP V6 session from BGPSentinel (BGPS) host to DUT (Simulated from ptf using exabgp to DUT).
2. Find V4 and V6 routes advertised from T0.
3. Check these routes are advertised to EBGP peers.
4. In ptf, advertise the same routes with higher local-preference and no-export community to DUT.
5. Check these routes are suppressed and not advertised to EBGP peers.
6. In ptf, withdraw these routes to DUT.
7. Check these routes are advertised to EBGP peers.
