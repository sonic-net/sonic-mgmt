- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose of this test is to validate communication between a 2 byte ASN device and a 4 byte ASN device.
### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of BGP configuration on SONIC system.

### Testbed
The test is developed and tested with Sonic t0 testbed setup and CEOS neighbors.

## Setup configuration
This test doesn't required any configurations from outside. But intenally it will modify the ASN of BGPVac and BGPSLBPassive groups in which the new neighboars are being created dynamically. Ensure the "bgp_speaker_route_4bASN.j2" file is available under sonic-mgmt/tests/bgp/templates.

## Test
Configure testbed to emulate production.
Configure IXIA/Spirent with a 4-byte ASN and peer with DUT.
Establish sessions across IPv4 and IPv6 using asplain on the DUT.
Advertise routes from the IXIA/Spirent to DUT.
Ensure prefixes are propagated within Customer VRF 
and that the IXIA/Spirent 4-byte ASN displays properly within the AS_PATH on the DUT.


Expectation:
•DUT should support 4-byte ASN with no problems using both asplain.    
•DUT should propagate prefixes with a 4-byte ASN in their AS_PATH.
## Test cases # 1 - Establish exabgp session from 4 byte ASN neighbors to 2 byte DUT in asplain notation.
1. Assign 4 byte ASN to dynamic bgp neihbors
2. Generate exabgp configurations for 3 bgp neighbors
3. Listen the expected BGP TCP packet to the exabgp neighbors on all ports. 
4. Neighbors with 4 byte ASN should establish exabgp with 2 byte ASN DUT.

### Test case # 2 - Announce route and test traffic with ipv4 prefix
1. Announce route with predefined ipv4 prefix 
2. Test traffic through the prefix using ptf_runner
3. Also, validate prefix is propagated with 4 byte ASN.

### Test case # 3 - Announce route and test traffic with ipv6 prefix
1. Announce route with predefined ipv6 prefix
2. Test traffic through the prefix using ptf_runner
3. Also, validate prefix is propagated with 4 byte ASN.

### Revert the configuration to normal at the end
