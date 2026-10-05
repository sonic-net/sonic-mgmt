# Table of Contents
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)
  - [Test case #1 — Verification of PortChannel Subinterfaces, BGP Sessions, Route-Maps, Community-Lists, and Prefix-Lists](#test-case-1--verification-of-portchannel-subinterfaces-bgp-sessions-route-maps-community-lists-and-prefix-lists)
  - [Test case #2 — Traffic Verification for Specific IPv4 and IPv6 Subnets with Route-Map Filtering in Default and Vrf_Test10 VRFs](#test-case-2--traffic-verification-for-specific-ipv4-and-ipv6-subnets-with-route-map-filtering-in-default-and-Vrf_Test10-vrfs)

---

## Overview
In a data center connected to both a WAN device and a DDoS mitigation device, a filter leaf router is primarily responsible for filtering inbound and outbound traffic, applying security policies, and ensuring that legitimate traffic can flow efficiently while mitigating potential DDoS attacks. It acts as the first line of defense against unwanted traffic and works in conjunction with the DDoS mitigation device to protect the data center's infrastructure from malicious traffic.

### Scope
The test is targeting a running SONiC system with fully functioning configuration. The scope includes validating the integration and operational effectiveness of the filter leaf router working in conjunction with the DDoS mitigation device to protect the data center infrastructure from malicious traffic.

### Testbed
The test will run on the following testbeds:
`t1-filterleaf-lag`

## Setup configuration
Filter-leaf testbed with eight sub-interfaces (two sub-interfaces on each parent interface).
One sub-interface on the default VRF and one sub-interface in a non-default VRF.
BGP IPv4 and IPv6 sessions are running on both default VRF and non-default VRF.

## Test cases

### Test case #1 — Verification of PortChannel Subinterfaces, BGP Sessions, Route-Maps, Community-Lists, and Prefix-Lists

**Test objective:**
Verify that all `PortChannelX.Y` subinterfaces are operational with correct IP and VRF bindings, BGP sessions are established with all IPv4 and IPv6 neighbors in both default and `Vrf_Test10` VRFs, routes are exchanged correctly, route-maps and community-lists are properly applied, and prefix-lists filter the intended subnets.

**Test steps:**
1. Verify all PortChannelX.Y subinterfaces are up and have the correct IP addresses and VRF bindings configured.
2. Confirm BGP sessions are established with all IPv4 neighbors in both the default VRF and Vrf_Test10.
3. Confirm BGP sessions are established with all IPv6 neighbors in both the default VRF and Vrf_Test10.
4. Verify that routes are exchanged via BGP for both IPv4 and IPv6 in the default and Vrf_Test10 VRFs.
5. Confirm that all route-maps with names starting with FROM_* and TO_* are correctly attached to each BGP neighbor.
6. Verify that advertised routes match the configured prefix-lists such as SPECIFIC and DEFAULT.
7. Check that FROM_* route-maps block unwanted prefixes as defined in the policy.
8. Confirm all community-lists are present and applied correctly to the relevant BGP neighbors or policies.
9. Test that the prefix-list correctly filters the subnet 17.17.30.0/24 as intended.

---

### Test case #2 — Traffic Verification for Specific IPv4 and IPv6 Subnets with Route-Map Filtering in Default and `Vrf_Test10` VRFs

**Test objective:**
Verify that specific IPv4 and IPv6 subnets are advertised from T2 to T0 neighbor via BGP in both default and `Vrf_Test10` VRFs, route-maps on the Device Under Test (DUT) allow only specified subnets, and traffic is correctly received or blocked as per the subnet filtering policies.

**Test steps:**
1. Advertise specific IPv4 subnets 17.17.10.0/24, 17.17.20.0/24, and 17.17.30.0/24 from T2 to T0 neighbor via BGP in both default and Vrf_Test10 VRFs.
2. Advertise specific IPv6 subnets '2000:db8:16:10::/64', '2000:db8:16:20::/64', and '2000:db8:16:30::/64' from T2 to T0 neighbor via BGP in both default and Vrf_Test10 VRFs.
3. Apply route-maps on the DUT to allow only the specific IPv4 subnets 17.17.10.0/24 and 17.17.20.0/24 from the device to the T0 neighbor.
4. Apply route-maps on the DUT to allow only the specific IPv6 subnets '2000:db8:16:10::/64' and '2000:db8:16:20::/64' from the device to the T0 neighbor.
5. From the PTF docker, send traffic from the T0 neighbor to the T2 neighbor for the IPv4 subnets 17.17.10.0/24 and 17.17.20.0/24, and confirm that traffic is received on the T2 neighbor.
6. From the PTF docker, send traffic from the T0 neighbor to the T2 neighbor for the IPv6 subnets '2000:db8:16:10::/64' and '2000:db8:16:20::/64', and confirm that traffic is received on the T2 neighbor.
7. From the PTF docker, send traffic from the T0 neighbor to the T2 neighbor for the IPv4 subnet 17.17.30.0/24, and confirm that traffic is not received on the T2 neighbor.
8. From the PTF docker, send traffic from the T0 neighbor to the T2 neighbor for the IPv6 subnet '2000:db8:16:30::/64', and confirm that traffic is not received on the T2 neighbor.
