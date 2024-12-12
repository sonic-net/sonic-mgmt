# SRv6 uSID Tests #

## Outline

- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose of this test is to verify that FRR programs SRv6 SIDs and policies correctly into the SONiC dataplane.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test SRv6 uSID functionality.

### Testbed
The test will run on t0 testbed.

## Setup configuration
The test requires to configure BGP neighborship between DUT and one neighbor.

## Test cases
### Test case # 1 - Verify SRv6 uSID BGP L3VPN services
* Configure a BGP session between DUT and one neighbor.
* Setup an SRv6 uSID L3VPN between the DUT and the neighbor.
* Verify that the DUT programs a SID list in the SONiC data plane.
* Verify that the DUT programs a route to steer VPN traffic over the SID list.
* Verify that the DUT programs an SRv6 uDT6 SID to decapsulate and forward the VPN traffic received from the neighbor.
