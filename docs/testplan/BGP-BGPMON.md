- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose is to test that FRR will setup a connection to BGPMON (BGPL) host. Prevouosly we had difficulty with that because of [nexthop tracking feature](http://docs.frrouting.org/projects/dev-guide/en/latest/next-hop-tracking.html) in FRR. This feature checks that each prefix has a reachable nexthop. The FRR feature considered the BGPMON nexthop unreachable, because BGPMON session is IBGP and not directly connected to the DUT. That was fixed in SONiC by next hop tracking default configuration. This test checks that the configuration works properly.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of BGP configuration on SONIC system.

### Testbed
The test could run on on any testbed.

## Setup configuration
This test doesn't require any configuration.

## Test
The test will configure BGPMON session and then check that FRR sends TCP SYN packet to the configured BGPMON by capturing bgp packets

## Test cases
### Test case # 1 - Add BGPMON to DUT and check that DUT sends TCP SYN packets to the configured BGPMON
1. Generate BGPMON configuration and apply it to the DUT
2. Listen the expected BGP TCP SYN packet to the BGPMON on all ports. Listen for 121 seconds to make sure that BGP will retry its attempt to connect

### Test case # 2 - Remove configuration which fixed the BGPMON issue and check that now BGP doesn't send update TCP SYN packets to BGPMON
1. Remove "ip nht resolve-via-default" from DUT FRR
2. Generate BGPMON configuration and apply it to the DUT
3. Listen the expected BGP TCP SYN packet to the BGPMON on all ports. No packets are expected for 121 seconds
4. Restore "ip nht resolve-via-default" back to the DUT

