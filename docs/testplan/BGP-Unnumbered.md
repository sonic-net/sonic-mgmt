# BGP Unnumbered Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)


## Overview

The goal of this test is to verify that the BGP Unnumbered feature works as expected.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BGP Unnumbered feature, which includes individual neighbor implementation.

### Testbed
Applicable to T0, T1, and T2 topologies.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| router bgp <ASN> | Enter BGP config mode |
| neighbor <interface_name> interface remote-as <remote_as>| neighbor level |
|Show commands|
| show run bgp | Display the current running BGP configuration |
| show ip bgp summary | Dispaly current neighbor relationships, can be done with ipv6 too |

### Sample DUT configuration files
BGP Unnumbered configs:

  router bgp 65100
   bgp router-id 10.1.0.1
   no bgp ebgp-requires-policy

   neighbor Ethernet48 interface remote-as 65200
   neighbor Ethernet48 description SONiC_Ethernet48_UNNUMBERED
   neighbor Ethernet48 capability extended-nexthop

   address-family ipv4 unicast
    neighbor Ethernet48 activate
   exit-address-family

   address-family ipv6 unicast
    neighbor Ethernet48 activate
   exit-address-family
  

## Setup configuration

This test requires configuring BGP unnumbered on both DUT and peer devices. Interfaces must be enabled for IPv6 link-local addressing, as BGP unnumbered relies on IPv6 link-local addresses. Ensure neighbor relationships are established using interface-based configuration.

### Interface configuration

Enable IPv6 link-local-only on each interface that participates in BGP unnumbered peering (no explicit IPv4/IPv6 address is assigned to the interface):

```
sudo config interface ipv6 enable use-link-local-only <intf name>
```

Example:
```
sudo config interface ipv6 enable use-link-local-only Ethernet48
```

Verify the interface has an IPv6 link-local address and is up:
```
show ipv6 interfaces
```

Apply the same interface configuration on the peer device before establishing the BGP unnumbered session.

## Test cases
### Test case #1 - BGP Unnumbered 

#### Test objective

Verify that a BGP Unnumbered session forms successfully between DUT and peer

Steps:
1. Configure BGP Unnumbered on DUT and peer using interface-based neighbors
2. Enable required address-family (IPv4/IPv6)
3. Check BGP session state

Expected Result:
1. Session state is Established
2. Neighbor uses IPv6 link-local address


### Test case #2 - Route Advertisement and Learning

#### Test objective

Verify routes are exchanged over BGP Unnumbered session

Steps:
1. Configure BGP Unnumbered on DUT and peer using interface-based neighbors
2. Enable required address-family (IPv4/IPv6)
3. Check BGP session state
4. Advertise routes (e.g., loopback prefixes) from DUT
5. Advertise routes from peer

Expected Result:
1. Routes are learned from peer and installed in routing table

### Test case #3 - Traffic Forwarding 

#### Test objective

Verify data-plane traffic using learned routes

Steps:
1. Establish BGP session and exchange routes
2. Send traffic between DUT and peer loopbacks

Expected Result:
1. Traffic successfully reaches destination
2. No packet loss after convergence

### Test case #4 - Link Flap Recovery 

#### Test objective

Verify BGP session resiliency to interface flaps

Steps:
1. Establish BGP session
2. Shutdown DUT interface
3. Bring interface back up

Expected Result:
1. Session transitions: Established → Idle → Established
2. Routes withdrawn and reinstalled correctly

### Test case #5 - BGP container Restart

#### Test objective

Verify BGP session resiliency when the BGP container (bgp docker) is restarted

Steps:
1. Establish BGP session
2. Restart BGP container on DUT
   * `sudo systemctl restart bgp`
4. Monitor BGP session state
5. Verify route table before and after restart

Expected Result:
1. Session transitions: Established → Idle/Active → Established
2. Routes are withdrawn during restart
3. Routes are reinstalled after session re-establishment
4. No stale routes remain in FIB
5. Convergence time is within acceptable threshold

### Test case #6 - Authentication

#### Test objective

Verify BGP unnumbered session stability with authentication enabled.

Steps:
1. Configure BGP unnumbered on DUT and peer
2. Enable password on both sides
3. Verify BGP session establishes successfully
4. Change password on DUT only
5. Observe session behavior
6. Reconfigure correct password

Expected Result:
1. Session establishes successfully with correct authentication
2. On password mismatch:
   * Session transitions to Idle
3. After correcting password:
   * Session returns to Established
4. Routes are withdrawn and reinstalled appropriately

### Test case #7 - BGP Unnumbered in VRF

#### Test objective

Verify BGP unnumbered functionality inside a VRF instance

Steps:
1. Create VRF on DUT
2. Assign interface to VRF
3. Configure BGP unnumbered under VRF context
4. Establish BGP session with peer in same VRF
5. Advertise routes within VRF
6. Perform interface flap (optional resilience check)

Expected Result:
1. BGP session establishes within VRF context
2. Routes are learned and installed in correct VRF routing table
3. No leakage into default VRF
4. After flap:
   * Session recovers correctly
   * Routes are reinstalled in VRF

### Test case #8 - BGP Unnumbered on PortChannel

#### Test objective

Verify BGP unnumbered over PortChannel (LAG) interfaces.

Steps:
1. Configure PortChannel between DUT and peer
2. Add member interfaces
3. Enable BGP unnumbered on PortChannel interface
4. Establish BGP session
5. Remove one member link
6. Restore member link
7. (Optional) Shut entire PortChannel and bring back up

Expected Result:
1. Session establishes over PortChannel interface
2. On single member failure:
   * Session remains Established (if LAG still operational)
3. On full PortChannel down:
   * Session transitions to Idle
4. After recovery:
   * Session returns to Established
5. Routes remain consistent and correctly reinstalled

### Test case #9 - ECMP Validation

#### Test objective

Verify Equal-Cost Multi-Path (ECMP) behavior with BGP unnumbered peers

Topology:
DUT connected to multiple peers over different interfaces (or PortChannels), all advertising the same prefix

Steps:
1. Configure BGP unnumbered on DUT with 2+ peers
2. Ensure all peers advertise identical prefix (e.g., same next-hop reachability)
3. Enable ECMP (if not default)
4. Verify BGP sessions reach Established
5. Check routing table for multiple next-hops
6. Verify FIB programming
7. Perform the following disruptions:
   * Shut one interface
   * Restore interface

Expected Result:
1. Multiple next-hops installed for same prefix (ECMP active)
2. Traffic is load-balanced across paths
3. On single path failure:
   * Only affected next-hop is removed
   * Remaining paths continue forwarding
4. On recovery:
   * Path is reinstalled into ECMP group
5. No duplicate or stale next-hops in FIB
6. Convergence is fast and consistent

### Test case #10 - BGP Unnumbered with BFD – Session Failure Detection

#### Test objective

Verify that Bidirectional Forwarding Detection (BFD) provides fast failure detection for BGP unnumbered sessions

Steps:
1. Configure BGP unnumbered between DUT and peer
2. Enable BFD on the BGP neighbor
3. Verify:
   * BGP session is Established
   * BFD session is Up
4. Shutdown DUT interface
5. Measure time for BFD session to go down
6. Observe BGP session state

Expected Result:
1. BFD session detects failure within configured interval
2. BGP session transitions quickly: Established → Idle
3. Route withdrawal is faster than standard BGP timers
4. No stale routes remain in FIB
5. After interface recovery:
   * BFD session comes Up
   * BGP session re-establishes
   * Routes are reinstalled

### Test case #11 - BFD Session Flap

#### Test objective

Verify BGP stability when BFD session flaps independently of link state.

Steps:
1. Establish BGP unnumbered session with BFD enabled
2. Verify both BGP and BFD are Up
3. Introduce BFD flap without bringing link down:
   * Drop BFD packets via ACL / control-plane filter
4. Restore BFD traffic

Expected Result:
1. On BFD failure:
   * BFD session → Down
   * BGP session → Idle
2. Routes are withdrawn immediately
3. On recovery:
   * BFD → Up
   * BGP → Established
4. Routes are reinstalled

### Test case #12 - Link-Local Reachability Loss

#### Test objective

Verify BGP when IPv6 link-local reachability is lost

Steps:
1. Establish BGP session
2. Block IPv6 link-local traffic (ACL or control-plane filter)
3. Monitor session

Expected Result:
1. BGP session times out → transitions to Idle
2. Routes withdrawn
3. After restoring reachability:
   * Session re-establishes
   * Routes reinstalled

### Test case #13 - Cold Reboot

#### Test objective

Verify BGP Unnumbered behavior during cold reboot

Steps:
1. Establish BGP session and traffic flow
2. Perform a cold reboot on the DUT
3. Monitor BGP session state and traffic during reboot and recovery

Expected Result:
1. BGP session is re-established automatically after reboot
2. Minimal traffic disruption
3. Routes preserved or quickly relearned

### Test case #14 - Warm Reboot

#### Test objective

Verify BGP Unnumbered behavior during warm reboot

Steps:
1. Establish BGP session and confirm stable traffic flow
2. Perform a warm reboot on the DUT
3. Monitor BGP session state and traffic during reboot and recovery

Expected Result:
1. BGP session is preserved or quickly re-established
2. Minimal or no traffic disruption
3. Routes preserved or quickly relearned

### Test case #15 - Fast Reboot

#### Test objective

Verify BGP Unnumbered behavior during fast reboot

Steps:
1. Establish BGP session and confirm stable traffic flow
2. Perform a fast reboot on the DUT
3. Monitor BGP session state and traffic during reboot and recovery

Expected Result:
1. BGP session is preserved or rapidly re-established.
2. Minimal traffic disruption
3. Routes preserved or quickly relearned

