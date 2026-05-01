# AzD Solution Test Plan

## Overview

This document describes AzD Solution-Test validation for VNETs, PortChannel subinterfaces, BGP, static VXLAN,
VNET_ROUTE_TUNNEL (including ECMP and DMAC rewrite), MAC rewrite ACLs, MacSec,
resilience triggers, scale, longevity, and coexistence with Everflow, Data-ACL, and IP-in-IP.


---

## Topology

                          +---------------------------+
                          |          Spine0           |
                          |   Lo0: 10.10.10.100       |
                          |                           |
                          |                           |
                          |  Ethernet-P   Ethernet-Q  |
                          +--------+---------+--------+
                                   |         |
                                   |         |
                    +--------------+         +--------------+
                    |                                       |
                    |                                       |
        +-----------+---------------+              +--------+------------------+
        |     Ethernet-A            |              |      Ethernet-X           |
        |                           |              |                           |
        |           Leaf0           |              |           Leaf1           |
        |   Lo0: 10.10.11.200       |              |   Lo0: 10.10.10.200       |
        |                           |              |                           |
        |                           |              |                           |
        |  Po100.xyz   Po101.xyz    |              |  Po100.xyz   Po101.xyz    |
        +------+++-+----+++-+-------+              +------+++-+----+++-+-------+
               |||.|    |||.|                             |||.|    |||.|
               |||.|    |||.|                             |||.|    |||.|
               BGP      BGP                               BGP      BGP
               |||.|    |||.|                             |||.|    |||.|
               |||.|    |||.|                             |||.|    |||.|
        +------+++-+----+++-+-------+              +------+++-+----+++-+-------+
        |  Lag1.xyz   Lag2.xyz      |              |  Lag3.xyz   Lag4.xyz      |
        |                           |              |                           |
        |                           |              |                           |
        |          Ixia-A           |              |          Ixia-X           |
        |                           |              |                           |
        +---------------------------+              +---------------------------+


### BGP and traffic (from reference)

-	BGPv4 running between Ixia-A and Leaf0 are advertising routes, say A.x.y.z/32
-	BGPv4 running between Ixia-X and Leaf1 are advertising routes, say X.x.y.z/32
-	Traffic running between A.x.y.z/32 <---->  X.x.y.z/32 


---

## Test Cases — AzD

---

### TC-AZD-1 – Verify that PortChannel-subinterface can be created and can be assigned IP

**Objective:**

Verify that PortChannel-subinterface can be created and can be assigned IP

**Test Steps:**

1. Create 128 Vnets on both leaf. Assign one Loopback interface on each Leaf and spine.
2. Create two portchannels PO100, PO101 with one interface in each lag on both Encap and Decap Leaf.
3. we are using single-port POs. We will use port-breakout and cover multi-port PO case in setups where we have breakout-support on remote-end (which is Ixia)
4. Create 128 PO-subinterface and assign them IP.
5. Using Vnet number same as VLAN number in PO-subinterface
6. Associate each PO-subinterface to a Vnet
7. This will be 1:1 mapping between VLAN and Vnet
8. Save the config (Will be run as part of setup())

**Pass Criteria:**

- Verify that all the CLI are successful
- Verify that ARP is resolved from Ixia when corresponding sub-interfaces are created on Ixia

---

### TC-AZD-2 – Verify ability to associate Po-Subinterface to different VNETs

**Objective:**

Verify ability to associate Po-Subinterface to different VNETs

**Test Steps:**

1. Create 128 Vnets on both leaf. Assign one Loopback interface on each Leaf and spine.
2. Create two portchannels PO100, PO101 with one interface in each lag on both Encap and Decap Leaf.
3. Since we have limited Ixia interface, we are using single-port POs.
4. Create 128 PO-subinterface and assign them IP.
5. Using Vnet number same as VLAN number in PO-subinterface
6. Associate each PO-subinterface to a Vnet
7. This will be 1:1 mapping between VLAN and Vnet
8. Save the config (Will be run as part of setup())

**Pass Criteria:**

- Verify that all the CLI are successful
- Verify that ARP is resolved from Ixia when corresponding sub-interfaces are created on Ixia

---

### TC-AZD-3 – Verify that BGP session can be configured on each PO-subinterfaces separately.

**Objective:**

Verify that BGP session can be configured on each PO-subinterfaces separately.

**Test Steps:**

1. Configure BGP session on all this interfaces created on these PO-subinterface.
2. Configure BGP on Ixia-side as well for both leaf.
3. Add route-ranges on decap leaf to be advertized as NLRI
4. This route-ranges points to host-routes for easy verifcation in later testcases.
5. Save the config (Will be run as part of setup())

**Pass Criteria:**

- Verify that BGP comes up between ixia and both the leaf
- Verify that routes are installed in Vrf associated with Vnet for all the route-ranges

---

### TC-AZD-4 – Verify that VXLAN-tunnel can be created statically over underlay which is running BGP.

**Objective:**

Verify that VXLAN-tunnel can be created statically over underlay which is running BGP.

**Test Steps:**

1. Create underlay using a spine-node.
2. Each leaf has one connected-interface towards spine, and running EBGP on that connection.
3. Advertize Loopback over the BGP as BGP-Network
4. Add vxlan tunnel on both leaf, and only specify source address.
5. Source address of the vxlan tunnel is local loopback IP
6. Save the config (Will be run as part of setup())

**Pass Criteria:**

- Verify that underlay BGP is up.
- Remote Loopback route is learnt via BGP installed on both the Leaf.
- Check show vxlan tunnel is able to show the configured info

---

### TC-AZD-5 – Verify static VNET-route creation for remote IP-networks.

**Objective:**

Verify static VNET-route creation for remote IP-networks.

**Test Steps:**

1. Create route in VNET_ROUTE_TUNNEL for each remote-PO-subinterface with appropriate VNETs.
2. Also create route on encap leaf for BGP-route-ranges learnt from Ixia on decap-leaf.
3. Use remote loopback-ip as nexthop endpoint in above routes.
4. Save the config (Will be run as part of setup())

**Pass Criteria:**

- Verify that routes are properly installed on both leaf. Check for entries in show vnet route tunnel output

---

### TC-AZD-6 – Verify ACL creation for Source-MAC rewrite.

**Objective:**

Verify ACL creation for Source-MAC rewrite.

**Test Steps:**

1. Creates Source MAC Rewrite ACL Configuration on both the Leaf with rewrite action and counter creation.
2. Create Vnet specific ACL Rules which specifies mac to be used for given IP.
3. Associate the ACL to interface connecting to underlay in egress direction.
4. Save the config.(Will be run as part of setup())

**Pass Criteria:**

- Verify ACL creation in show acl rule.
- Later, traffic from the any IP in the ACL-rule should see mapped inner-src-mac.

---

### TC-AZD-7 – Verify Traffic over static VXLAN tunnel. Check that traffic is encapsulated as per route in VNET_ROUTE_TUNNEL.
Also check that traffic is decapsulated and forwarded as per local VNET_ROUTEs

**Objective:**

Verify Traffic over static VXLAN tunnel. 
Check that traffic is encapsulated as per route in VNET_ROUTE_TUNNEL. 
Also check that traffic is decapsulated and forwarded as per local VNET-routes

**Test Steps:**

1. Create & Start the following traffic streams from Ixia:
2. Traffic from Ixia port-channel subinterface IP connected to the Encap Leaf to the corresponding port-channel subinterface IP connected to the Decap Leaf.
3. Traffic from Ixia port-channel subinterface IP connected to the Encap Leaf to the corresponding route ranges advertised by the Ixia connected to Decap Leaf.
4. In this context, “corresponding” refers to traffic mapped to the same VNET / VNI / VLAN.
5. Once BGP sessions are established and ARP resolution is completed, traffic should successfully flow end-to-end between the Encap and Decap Leafs.

**Pass Criteria:**

- Verify that all Ixia interfaces have successfully resolved ARP entries toward the Leaf interfaces.
- Confirm that traffic loss is 0% across all traffic streams.
- Since there is default VNI used here, decap is verified here and traffic is delivered and verified at Ixia after vxlan-decap at Leaf-1
- For high-scale scenarios, BGP route installation on the Leaf may take additional time.
- If packet loss is observed initially, allow some time (tolerance) for route programming and retry traffic verification until loss converges to 0%. Note down this delay in script/log.

---

### TC-AZD-8 – Enable MacSec and verify that traffic (BGP/Data) is encrypted.

**Objective:**

Enable MacSec and verify that traffic (BGP/Data) is encrypted.

**Test Steps:**

1. Enable macsec on both the leaf.
2. Configure a profile with cipher-suite, CAK, CKN, priority, and SCI info
3. Associate the profile to member interfaces of Po100, Po101 on both leaf.
4. Do corresponding config on Ixia-interfaces connected to Leaf.
5. Verify the above with AzD configs (we have requested AzD folks to share the config).
6. Verify LLDP over MACsec
7. Verify disable/enable macsec on DUT.
8. Verify disable/enable macsec on Remote-end (which is Ixia in this case).

**Pass Criteria:**

- Verify that MacSec sessions are up on all the enabled interfaces.
- Verify that IPs are resolved on Po-subinterfaces.
- Verify that BGP is up and running
- Verify that end-to-end Ixia traffic able to flow.

---

### TC-AZD-9 – Verify that VNET_ROUTE_TUNNEL supports routes with multiple endpoints and that traffic is ECMP-balanced across those endpoints.
(ECMP is only verified in one direction, that is Leaf0 to specified-endpoints, reverse traffic is not handled in this case)

**Objective:**

Verify VNET_ROUTE_TUNNEL can have routes with multiple endpoints and traffic is ECMPed to these endpoints. ECMP is only verified in one direction, that is Leaf0 to specified-endpoints, reverse traffic is not handled in this case

**Test Steps:**

1. Base configuration is applied — VNETs, PO-subinterfaces, BGP sessions, VXLAN tunnel, and underlay routing are operational.
2. Configure VNET_ROUTE_TUNNEL entries on Encap Leaf with multiple endpoint IPs (510) per tunnel route.
3. Each route entry contains a comma-separated list of endpoints, with a corresponding per-endpoint inner DMAC and per-endpoint VNI.
4. The multiple endpoints enable ECMP forwarding — the Encap Leaf distributes traffic across all configured tunnel endpoints.
5. Add a static route and BGP aggregate-address so all endpoint IPs are reachable via the underlay.
6. Apply the configuration to the DUT and perform a config save.
7. Initiate traffic from Ixia PO-subinterface endpoints on the Encap Leaf towards the corresponding destination prefixes on the Decap Leaf.
8. Encap Leaf should VXLAN-encapsulate the traffic and ECMP-hash it across the 510 configured tunnel endpoints.
9. Capture VXLAN-encapsulated packets at the Spine to inspect the outer destination IP, inner DMAC, and VNI.
10. Validate that traffic is distributed across all 510 endpoints — each endpoint should appear in the captured packets.
11. Validate that the inner destination MAC and VNI in each packet match the per-endpoint values specified in the VNET_ROUTE_TUNNEL entry.
12. Modify the endpoints, DMAC, and VNI in the VNET_ROUTE_TUNNEL entries and re-apply the configuration to the DUT.
13. This validates support for in-place modification of ECMP endpoints without requiring route deletion and re-creation.
14. Restart traffic and perform a second packet capture on the Spine.
15. Confirm that the outer destination IPs, inner DMACs, and VNIs now reflect the updated values.

**Pass Criteria:**

- All tunnel routes are programmed and visible in show vnet route tunnel with the expected 510 endpoints, mac_address, and vni attributes per route.
- Outer destination IP in VXLAN packets is distributed across all 510 configured endpoints, confirming ECMP hashing is functional.
- Inner destination MAC in each VXLAN packet matches the per-endpoint mac_address.
- VNI in each VXLAN header matches the per-endpoint vni.
- After modification, previous endpoint IPs, MAC prefix, and VNI values are no longer present in route entries, and all routes reflect the updated values.
- Packet captures on the Spine confirm all ECMP endpoints, DMACs, and VNIs are updated in the encapsulated traffic post-modification.

---

### TC-AZD-10 – Verify VNET_ROUTE_TUNNEL can have routes with modified inner DMAC

**Objective:**

Verify VNET_ROUTE_TUNNEL can have routes with modified inner DMAC

**Test Steps:**

1. Base configuration is applied — VNETs, PO-subinterfaces, BGP sessions, VXLAN tunnel, and underlay routing are operational.
2. Configure VNET_ROUTE_TUNNEL entries on Encap Leaf with the mac_address attribute set for each tunnel route.
3. The mac_address field specifies the inner destination MAC to be used in the VXLAN-encapsulated packet, overriding the default ARP-resolved DMAC.
4. Assign a unique DMAC per route using a configurable MAC prefix.
5. Set the endpoint to the remote VTEP loopback IP.
6. VNI override is not configured in this test — only DMAC rewrite behavior is under validation.
7. Apply the configuration to the DUT and perform a config save.
8. Initiate traffic from Ixia PO-subinterface endpoints on the Encap Leaf towards the corresponding destination prefixes on the Decap Leaf.
9. Encap Leaf should VXLAN-encapsulate the traffic and use the configured inner DMAC in the encapsulated packet.
10. Capture VXLAN-encapsulated packets at the Spine to inspect the inner Ethernet frame.
11. Validate that the inner destination MAC matches the mac_address specified in the VNET_ROUTE_TUNNEL entry.
12. Modify the DMAC by updating the MAC prefix in the VNET_ROUTE_TUNNEL entries and re-apply the configuration to the DUT.
13. This validates support for in-place DMAC modification without requiring route deletion and re-creation.
14. Restart traffic and perform a second packet capture on the Spine.
15. Confirm that the inner DMAC now reflects the updated MAC prefix.

**Pass Criteria:**

- All tunnel routes are programmed and visible in show vnet route tunnel with the expected mac_address attribute.
- Inner destination MAC in VXLAN-encapsulated packets on the Spine matches the configured mac_address, confirming DMAC rewrite is functional.
- After modification, the previous MAC prefix is no longer present in route entries, and all routes reflect the new MAC prefix.
- Packet captures on the Spine confirm the updated inner DMAC is applied to encapsulated traffic post-modification.

---

### TC-AZD-11 – Verify VNET_ROUTE_TUNNEL can have routes with modified VNI

**Objective:**

Verify VNET_ROUTE_TUNNEL can have routes with modified VNI

**Test Steps:**

1. Base configuration is applied — VNETs, PO-subinterfaces, BGP sessions, VXLAN tunnel, and underlay routing are operational.
2. Configure VNET_ROUTE_TUNNEL entries on Encap Leaf with the vni attribute set for each tunnel route.
3. The vni field specifies a custom VNI to be used in the VXLAN header, overriding the default VNI derived from the VNET-to-VNI mapping.
4. Assign a unique VNI per route using a configurable VNI base.
5. Set the endpoint to the remote VTEP loopback IP.
6. DMAC rewrite is not configured in this test — only VNI override behavior is under validation.
7. Apply the configuration to the DUT and perform a config save.
8. Initiate traffic from Ixia PO-subinterface endpoints on the Encap Leaf towards the corresponding destination prefixes on the Decap Leaf.
9. Encap Leaf should VXLAN-encapsulate the traffic using the per-route VNI specified in the VNET_ROUTE_TUNNEL entry, rather than the default VNET VNI.
10. Capture VXLAN-encapsulated packets at the Spine to inspect the VXLAN header.
11. Validate that the VNI in the VXLAN header matches the vni specified in the VNET_ROUTE_TUNNEL entry, not the default VNET-assigned VNI.
12. Modify the VNI by updating the VNI base in the VNET_ROUTE_TUNNEL entries and re-apply the configuration to the DUT.
13. This validates support for in-place VNI modification without requiring route deletion and re-creation.
14. Restart traffic and perform a second packet capture on the Spine.
15. Confirm that the VXLAN header VNI now reflects the updated VNI base.

**Pass Criteria:**

- All tunnel routes are programmed and visible in show vnet route tunnel with the expected vni attribute.
- VNI in VXLAN-encapsulated packets on the Spine matches the per-route vni configured in VNET_ROUTE_TUNNEL, confirming VNI override is functional.
- After modification, the previous VNI values are no longer present in route entries, and all routes reflect the new VNI base.
- Packet captures on the Spine confirm the updated VNI is applied in the VXLAN header post-modification.

---

### TC-AZD-12 – Verify EP-DMAC-VNI rewrite combinations.

**Objective:**

Verify EP-DMAC-VNI rewrite combinations.

**Test Steps:**

1. Base configuration is applied — VNETs, PO-subinterfaces, BGP sessions, VXLAN tunnel, and underlay routing are operational.
2. Configure VNET_ROUTE_TUNNEL entries on Encap Leaf with all three rewrite attributes — endpoint, mac_address, and vni — set for each route.
3. Each route specifies a custom endpoint (remote VTEP IP), a custom inner DMAC via mac_address, and a custom VNI overriding the default VNET-assigned VNI.
4. Assign unique DMAC per route using a configurable MAC prefix, and unique VNI per route using a configurable VNI base.
5. Apply the configuration to the DUT and perform a config save.
6. Initiate traffic from Ixia PO-subinterface endpoints on the Encap Leaf towards the corresponding destination prefixes on the Decap Leaf.
7. Encap Leaf should VXLAN-encapsulate the traffic using the configured per-route VNI in the VXLAN header and the configured DMAC as the inner destination MAC.
8. Capture VXLAN-encapsulated packets at the Spine and inspect both the VXLAN header and the inner Ethernet frame.
9. Validate that the VNI in the VXLAN header matches the per-route vni from VNET_ROUTE_TUNNEL.
10. Validate that the inner destination MAC matches the per-route mac_address from VNET_ROUTE_TUNNEL.
11. Validate that the outer destination IP matches the configured endpoint.
12. Modify all three attributes — update the endpoint to a new remote VTEP IP, change the MAC prefix, and update the VNI base — and re-apply the configuration to the DUT.
13. This validates that in-place modification of all rewrite attributes simultaneously is supported without requiring route deletion and re-creation.
14. Restart traffic and perform a second packet capture on the Spine.
15. Confirm that the outer destination IP, inner DMAC, and VXLAN VNI all reflect the updated values.
16. In order to verify decap, modify Vnet-VNI mapping on Leaf1/Decap-Leaf same as in the vnet-route-tunnel in leaf0/encap-leaf with nexthop-endpoint set to Leaf1's loopback-ip.
17. Traffic will not be stopped during modify, once the above modification is complete and we will keep running the traffic and ensure loss-less traffic flow.

**Pass Criteria:**

- All tunnel routes are programmed and visible in show vnet route tunnel with the expected endpoint, mac_address, and vni attributes.
- Outer destination IP in VXLAN packets matches the configured endpoint.
- Inner destination MAC in VXLAN packets matches the configured mac_address.
- VNI in the VXLAN header matches the configured vni.
- After modification, previous endpoint, MAC prefix, and VNI values are no longer present in route entries, and all routes reflect the updated values.
- Packet captures on the Spine confirm all three rewrite attributes are updated in the encapsulated traffic post-modification.
- In addition to verify encapsulation values on the spine, we will modify Vnet-VNI mapping on Leaf1/Decap-Leaf to verify the data is delivered to Ixia after vxlan-decap.

---

### TC-AZD-12A – Verify same route with same nexthop can be shared across VNETs

**Objective:**

Verify same route with same nexthop can be shared across VNETs

**Test Steps:**

Basic Nexthop Sharing
- Create a route to Host-A in Vnet-1 with VNI-A, EP-A, DMAC-A
    * Verify a new nexthop entry is created
- Add the same route in Vnet-2
    * Verify encapsulation for both VNETs
    * Confirm another nexthop for this vnet added or nexthop reference count increments
- Add the same route in Vnet-3
    * Verify encapsulation across all three VNETs
    * Confirm another nexthop for this vnet added or nexthop reference count increments
- Delete the route from Vnet-2 and Vnet-3
    * Verify encapsulation for Vnet-1
    * Confirm another nexthop for these vnet deleted or nexthop reference count decrements by 2
- Attempt to delete the route again from Vnet-2 (negative test)
    * Operation should fail or be ignored
    * Verify no change of nexthop, and reference count remains unchanged
- Delete the route from Vnet-1
    * Verify nexthop entry is removed
    * Confirm nexthop count decreases by 1

Scale and Persistence
- Repeat the above scenarios with multiple routes (e.g., 128 routes)
- Repeat across all VNETs on the SONiC device
- Perform config save + config reload and verify behavior
- Perform config save + reboot and verify behavior

Route Modification Scenarios
- Create a route to Host-A in Vnet-1, Vnet-2, and Vnet-3 using VNI-A, EP-A, DMAC-A (NEXTHOP-1)
    * Verify nexthop count increases by 1
    * Verify reference count = 3
- Modify the route in Vnet-2 to VNI-B, EP-B, DMAC-B (NEXTHOP-2)
    * Verify nexthop count increases to 2 (relative to initial)
    * Verify ref-count: NEXTHOP-1 = 2, NEXTHOP-2 = 1
- Modify the route in Vnet-3 to NEXTHOP-2
    * Verify ref-count: NEXTHOP-1 = 1, NEXTHOP-2 = 2
- Modify the route in Vnet-1 to NEXTHOP-2
    * Verify NEXTHOP-1 is removed
    * Confirm nexthop count reduces to 1 (relative to initial)
    * Verify ref-count: NEXTHOP-2 = 3

Other VNET Peering Scenarios
- Configure peering between:
    * Vnet-1 & Vnet-2
    * Vnet-3 & Vnet-4
- Create:
    * Route to Host-A in Vnet-1 and Vnet-2 using NEXTHOP-1
    * Route to Host-B in Vnet-3 and Vnet-4 using NEXTHOP-2
- Modify:
    * Route for Host-A in Vnet-3 to use NEXTHOP-1
        * Verify encapsulation and reference count
    * Route for Host-B in Vnet-1 to use NEXTHOP-2
        * Verify encapsulation and reference count

**Pass Criteria:**

- Verify encapsulation for as per the configured VNETs
- Verify nexthop entries are created/deleted for every shared vnet
- Eiether reference count is per nexthop increment or a new nexthop is created

---

### TC-AZD-12B – Verify same route with same ECMP-nexthop-endpoints can be shared across VNETs

**Objective:**

Verify same route with same ECMP-nexthop-endpoints can be shared across VNETs

**Test Steps:**

Basic Nexthop Sharing

- Create a ecmp route and verify ecmp+encap for this route:
    ```
    ""VNET_ROUTE_TUNNEL"": {
        ""Vnet100|240.0.0.1/32"": {
            ""endpoint"": ""10.0.1.31,10.0.1.32,10.0.1.33,10.0.1.34"",
            ""mac_address"": ""00:22:f0:31:00:01,00:22:f0:32:00:01,00:22:f0:33:00:01,00:22:f0:34:00:01"",
            ""vni"": ""310031,310032,310033,310034""
        }
    }
    ```
   * Verify a 4 nexthop entries is created, 1 multipath-group and 4 multi path-group-member are created
   
- Add the same route in Vnet-2
    ```
    ""VNET_ROUTE_TUNNEL"": {
        ""Vnet101|240.0.0.1/32"": {
            ""endpoint"": ""10.0.1.31,10.0.1.32,10.0.1.33,10.0.1.34"",
            ""mac_address"": ""00:22:f0:31:00:01,00:22:f0:32:00:01,00:22:f0:33:00:01,00:22:f0:34:00:01"",
            ""vni"": ""310031,310032,310033,310034""
        }
    }
    ```
   * Verify encapsulation for both VNETs
   * Verify additional 4 nexthop entries, 1 multipath-group and 4 multi path-group-member are created

- Add the same route in Vnet-3
    ```
    ""VNET_ROUTE_TUNNEL"": {
        ""Vnet102|240.0.0.1/32"": {
            ""endpoint"": ""10.0.1.31,10.0.1.32,10.0.1.33,10.0.1.34"",
            ""mac_address"": ""00:22:f0:31:00:01,00:22:f0:32:00:01,00:22:f0:33:00:01,00:22:f0:34:00:01"",
            ""vni"": ""310031,310032,310033,310034""
        }
    }
    ```
   * Verify encapsulation across all three VNETs
   * Verify additional 4 nexthop entries, 1 multipath-group and 4 multi path-group-member are created

- Delete the endpoint 10.0.1.31 and corresponding dmac&vni for route in Vnet-2
   * Verify encapsulation for Vnet-1, Vnet-3 is unchanged
   * Verify updated ecmp+encap for Vnet-2 route
   * Verify a 1 nexthop entry is deleted, 1 multi path-group-member is deleted

- Do the same for Vnet-1 and Vnet-3, and do similar verification

- Repeat the 2 above steps (however change the order, Vnet-1, then Vnet-2 and Vnet-3) for endpoint 10.0.1.32, and verify same as above

- Add a endpoint 10.0.1.35 and dmac-1 & vni-1 for route in Vnet-2
    * Verify encapsulation for Vnet-1, Vnet-3 is unchanged
    * Verify updated ecmp+encap for Vnet-2 route
    * Verify a 1 nexthop entry is added, 1 multi path-group-member is also added
- Add endpoint 10.0.1.35 but different dmac-2 & vni-2 for route in Vnet-1
    * Verify encapsulation for all the 3 routes
    * Ensure updated ecmp+encap for Vnet-1 route
    * Verify a 1 nexthop entry is added, 1 multi path-group-member is also added
- Add endpoint 10.0.1.36 but different dmac-1 & vni-1 for route in Vnet-3
    * Verify encapsulation for all the 3 routes
    * Ensure updated ecmp+encap for Vnet-3 route
    * Verify a 1 nexthop entry is added, 1 multi path-group-member is also added

Scale and trigger:

- Repeat the above scenarios with multiple routes (e.g., 4 routes with 511-endpoint)
- Perform config save + config reload and verify behavior
- Perform config save + reboot and verify behavior

Route Modification Scenarios

- Create a ecmp-route to Host-A in Vnet-1, Vnet-2, and Vnet-3 using VNI-A1,A2,A3, EP-A1,A2,A3, DMAC-A1,A2,A3 (Nexthop-A)
   	*Verify encapsulation for Host-A in All Vnets
	*Verify nexthop entries, Multipath-group, multipath-group-member 
        *Verify nexthop-count : NEXTHOP-A = 9

- Modify the route in Vnet-2 to VNI-B1,B2,B3,B4, EP-B1,B2,B3,B4, DMAC-B1,B2,B3,B4
   * Verify encapsulation for Host-A in All Vnets
   * Verify nexthop entries, Multipath-group, multipath-group-member 
   * Verify next hop-count : NEXTHOP-A = 6, NEXTHOP-B = 4

- Modify the route in Vnet-3 to NEXTHOP-B
   * Verify encapsulation for Host-A in All Vnets
   * Verify nexthop entries, Multipath-group, multipath-group-member  
   * Verify next hop-count : NEXTHOP-B = 8, NEXTHOP-A = 3

- Modify the route in Vnet-1 to NEXTHOP-B
   * Verify encapsulation for Host-A in All Vnets
   * Verify nexthop entries, Multipath-group, multipath-group-member 
   * Verify next hop-count : NEXTHOP-B = 12, NEXTHOP-A = 0

- Delete the route in Vnet-1 
   * Verify encapsulation for Host-A in All Vnets, Should use default-VNI for Host-A in Vnet-1, if any other route to host-A exist
   * Verify nexthop entries, Multipath-group, multipath-group-member 
   * Verify next hop-count : NEXTHOP-B = 8, NEXTHOP-A = 0

- Delete the route in Vnet-2 
   * Verify encapsulation for Host-A in All Vnets, Should use default-VNI for Host-A in Vnet-1, Vnet-2, if any other route to host-A exist
   * Verify nexthop entries, Multipath-group, multipath-group-member
   * Verify next hop-count : NEXTHOP-B = 4, NEXTHOP-A = 0

- Delete the route in Vnet-3 
   * Verify encapsulation for Host-A in All Vnets, Should use default-VNI for Host-A in Vnet-1, Vnet-2, Vnet-3, if any other  route to host-A exist
   * Verify nexthop entries, Multipath-group, multipath-group-member
   * Verify next hop-count : NEXTHOP-B = 0, NEXTHOP-A = 0

**Pass Criteria:**

- Verify encapsulation for as per the configured VNETs
- Verify nexthop entries are created/deleted for every shared vnet
- Eiether reference count is per nexthop increment or a new nexthop is created

---


### TC-AZD-13 – Verify the ability to modify VXLAN source-port

**Objective:**

Verify the ability to modify VXLAN source-port

**Test Steps:**

1. Configure Vxlan Source-port as 64128-64255 on encap-Leaf
2. Change the src-port to some other range, and see if the change takes effect.
3. Change to src-port value to default, and see if the change takes effect.
4. Revert back to Vxlan dst-port as 64128-64255 on both the Leaf

**Pass Criteria:**

- Verify Vxlan src port in all the packets are as per the config.
- Verify the packet contents, if possible, on spine.
- Packet on Spine can only be sniffed in tcpdump if its getting dropped at spine.
- Check the load distribution, traffic should be distributed to each src-port equally.

---

### TC-AZD-14 – Verify the ability to modify VXLAN destination-port

**Objective:**

Verify the ability to modify VXLAN destination-port

**Test Steps:**

1. Configure Vxlan dst-port as 61111 on both the Leaf
2. Change the dst-port to some other value, and see if the change takes effect.
3. Change to value to value to default: 4789, and see if the change takes effect.
4. Revert back to Vxlan dst-port as 61111 on both the Leaf

**Pass Criteria:**

- Verify Vxlan dst port in all the packets are as per the config.
- Verify the packet content, if possible, on spine.
- Packet on Spine can only be sniffed in tcpdump if its getting dropped at spine.

---

### TC-AZD-15 – Verify that Consistent Hashing can be achieved when remote endpoint is reachable over multiple path.

**Objective:**

Verify that Consistent Hashing can be achieved when remote endpoint is reachable over multiple path.

**Test Steps:**

1. A Fine-Grained ECMP group can be configured.
2. Specific prefixes use FG-ECMP behavior.
3. Modify bucket size and verify the updated FGNHG config.
4. Modify the end points and verify the updated FGNHG config.
5. Check the scale limit for bucket size. Current expected limit 512 buckets.
6. Check the scale limit for number of next hops. current expect limit, one less than bucket size.
7. Traffic is consistently hashed.
8. Only impacted flows are redistributed when a next-hop changes.
9. Any nexthop-endpoint delete/failure will move the buckets assigned to it to other endpoints. Existing endpoint and bucket association should not change.

**Pass Criteria:**

- Verify the ECMP group is created.
- verify the FGNHG group is created with different prefix.
- verify if traffic is consistent hashing.
- verify if end-point withdrawal and addition is handeled consistently.
- verify triggers with link flap, config reload and switch reboot.

---
### TC-AZD-16 – 1K VNETS on Q200, 4K VNETs on P200

**Objective:**

1K VNETS on Q200, 4K VNETs on P200 platform

**Test Steps:**

1. Increase number of vnets on both leaf to 1K

**Pass Criteria:**

- Verify all the vnets are configured and usable
- Note the time to configure

---

### TC-AZD-17 – 2-Portchannel each with 1K subnets (one each in 1K VNETs)

**Objective:**

2-Portchannel each with 1K subnets (one each in 1K VNETs)

**Test Steps:**

1. Create 1K portchannel-subinterface in each VNET.

**Pass Criteria:**

- Verify all the subinterfaces are created, and resolved with the ixia
- Note the time to configure

---

### TC-AZD-18 – BGP session on each Po-sub-interface (2K BGP session on whole dut, IPv4 only)

**Objective:**

BGP session on each Po-sub-interface (2K BGP session on whole dut, IPv4 only)

**Test Steps:**

1. Create 1 BGP session over all the portchannel-subinterfaces

**Pass Criteria:**

- Verify all the BGP session are configured and UP and NLRI exchanged.
- Note the time to configure and session UP

---

### TC-AZD-19 – 128K host VNET-routes on Q200, 1M on P200

**Objective:**

128K host VNET-routes on Q200, 1M on P200

**Test Steps:**

1. Configure 128K static host-routes in VNET_ROUTE_TUNNEL table

**Pass Criteria:**

- Verify all the host routes are configured.
- Check that host routes are used to forward the data
- Note the time to configure.

---

### TC-AZD-19a1 – Scaled number of rewrite-entries in VNET_ROUTE_TUNNEL table. - 32K for Q200, - 128K for P200

**Objective:**

Scaled number of rewrite-entries in VNET_ROUTE_TUNNEL table.
- 32K for Q200, - 128K for P200

**Test Steps:**

1. Base config operational with traffic at 0% loss.
2. Configure DMAC-rewrite routes at target scale (32K or 128K based on platform). Apply, save, log programming time.
3. Verify traffic, capture on Spine — validate inner DMAC and endpoint. Sample routes for correctness.
4. Modify DMAC prefix and endpoint in-place. Verify updated values, old values gone, route count unchanged.
5. Run triggers (config reload, SWSS restart, reboot) — verify routes restore, traffic resumes, modified values persist.
6. Delete all scaled routes. Verify cleanup, ASIC DB back to baseline.
7. Health checks throughout — no cores, no errors, stable CPU/memory, all services up.

**Pass Criteria:**

- All tunnel routes programmed and visible in show vnet route tunnel at target scale (32K/128K) with expected mac_address and endpoint.
- Outer destination IP and inner DMAC in VXLAN packets match per-route configuration.
- After modification, old values absent, all routes reflect updated DMAC prefix and endpoint.
- Route count unchanged during in-place modification. Spine packet captures confirm updated rewrite attributes post-modification.
- Traffic at 0% loss after programming, modification, and each trigger (config reload, SWSS restart, reboot).
- Modified values persist across all triggers.
- No cores, no syslog errors, stable CPU/memory, no ASIC DB resource leak after deletion.

---

### TC-AZD-20 – 9000 Src-mac rewrite ACL scale

**Objective:**

9000 Src-mac rewrite ACL scale

**Test Steps:**

1. Create 9000 Src-mac rewrite ACLs

**Pass Criteria:**

- Verify that all the ACLs are configured, and are able to change src-mac to configured one, as per IP-MAC mapping.
- Verify that ACL-hit is marked.

---

### TC-AZD-21 – Access Network flap: As good as portchannel flap, this will re-initiate LAG, ARP, BGP, and traffic

**Objective:**

Access Network flap: As good as portchannel flap, this will re-initiate LAG, ARP, BGP, and traffic

**Test Steps:**

1. Flap PO-member interafce from Leaf side.
2. Flap PO-member interafce from Ixia side.

**Pass Criteria:**

- MacSec session should come-up.
- BGP comes up, routes get learnt over all PO-subinterfaces.
- Traffic resume after flap.
- Check for core, any docker-restart

---

### TC-AZD-22 – Container restart SWSS/Orch-agent

**Objective:**

Container restart SWSS/Orch-agent

**Test Steps:**

1. Do docker Restart

**Pass Criteria:**

- Confirm service restarts successfully.
- Confirm configuration is replayed.
- Confirm traffic resumes.
- Confirm no errors in logs.
- Confirm docker restarts
- MacSec session should come-up.
- BGP comes up, routes get learnt over all PO-subinterfaces.
- Check for core, any docker-restart

---

### TC-AZD-23 – Container restart Teamd,

**Objective:**

Container restart Teamd,

**Test Steps:**

1. Do docker Restart

**Pass Criteria:**

- Same as TC-AZD-22 Pass Criteria

---

### TC-AZD-24 – Container restart BGP,

**Objective:**

Container restart BGP,

**Test Steps:**

1. Do docker Restart

**Pass Criteria:**

- Same as TC-AZD-22 Pass Criteria

---

### TC-AZD-25 – Container restart syncd,

**Objective:**

Container restart syncd,

**Test Steps:**

1. Do docker Restart

**Pass Criteria:**

- Same as TC-AZD-22 Pass Criteria

---

### TC-AZD-26 – Container restart Orchagent"

**Objective:**

Container restart Orchagent"

**Test Steps:**

1. Do docker Restart

**Pass Criteria:**

- Same as TC-AZD-22 Pass Criteria

---

### TC-AZD-27 – Config reload

**Objective:**

Config reload

**Test Steps:**

1. Save a copy of config_db.json
2. Run config reload CLI

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria
- Check if config is same as before the trigger.
- Check convergence time.
- Use crm commands to check for resource-leaks.

---

### TC-AZD-28 – Config reload with scaled config, Ensure convergence time within limits. Look for traffic, BGP, VNET-Routes convergence. Monitor top stability and docker bringup.

**Objective:**

Config reload with scaled config, Ensure convergence time within limits.
Look for traffic, BGP, VNET-Routes convergence. Monitor top stability and docker bringup.

**Test Steps:**

1. Add scales config (1k vnet, 2K PO subinterface, 2K BGP-session, 9K src-mac ACL, scaled rewrite-VNI-DMAC-entries)
2. Save a copy of config_db.json
3. Run config reload CLI

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria
- Check if config is same as before the trigger.
- Check convergence time.
- Use crm commands to check for resource-leaks.

---

### TC-AZD-29 – Try config save (Try adding config for 100 New VNETs, PO-subinterface, BGP, VNET_ROUTE) as well, config_db.json should be already significantly big here with scaled config,

**Objective:**

Try config save (Try adding config for 100 New VNETs, PO-subinterface, BGP, VNET_ROUTE) as well, config_db.json should be already significantly big here with scaled config,

**Test Steps:**

1. Save a copy of config_db.json
2. Delete 10% odd scale entries.
3. Verify the change.
4. Add back the deleted entries.
5. Verify the change.D30

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria
- Check if config is same as before the trigger.
- Check convergence time.
- Use crm commands to check for resource-leaks.

---

### TC-AZD-30 – Underlay flap, Remote VTEP unreachable. BGP session between leaf flaps, connectivity to remote neighbor is brought down and restored.

**Objective:**

Underlay flap, Remote VTEP unreachable.
BGP session between leaf flaps, connectivity to remote neighbor is brought down and restored.

**Test Steps:**

1. Flap interface towards spine on encap leaf and verify
2. Flap interface towards spine on decap leaf and verify
3. Restart BGP on spine.

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria
- Check convergence time.
- Use crm commands to check for resource-leaks.

---

### TC-AZD-31 – Device reboot

**Objective:**

Device reboot

**Test Steps:**

1. Save a copy of config_db.json
2. Run reboot CLI

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria
- Check if config is same as before the trigger.
- Check convergence time.
- Use crm commands to check for resource-leaks.

---

### TC-AZD-32 – Add / delete additional VNET/VNI/VLAN mappings

**Objective:**

Add / delete additional VNET/VNI/VLAN mappings

**Test Steps:**

1. Add additional VNET and other corresponding config (PO, BGP, VNET_ROUTEs), and verify other VNETs has no impact.
2. Delete a VNET and other corresponding config (PO, BGP, VNET_ROUTEs), and verify other VNETs has no impact.

**Pass Criteria:**

- Do verifiation same as TC-AZD-22 Pass Criteria

---

### TC-AZD-33 – Longevity of >48 hrs with scaled config

**Objective:**

Longevity of >48 hrs with scaled config

**Test Steps:**

1. Let the config run for > 48 hours

**Pass Criteria:**

- Do the common verifications from the above TCs

---

### TC-AZD-34 – Verify Everflow Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Objective:**

Verify Everflow Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Test Steps:**

1. Verify Everflow  can co-exist and function with AZD-setup. Apply ACL rule with mirror session, and capture mirrored traffic. Host-A → Leaf0 → VXLAN → Leaf1 → Host-B ↘ Analyzer (Everflow mirror)

**Pass Criteria:**

- Verify basic functionality of AZD (end-to-end packet flow as per rewrite-entries) and mirrored traffic should  contain correct original payload.

---

### TC-AZD-35 – Verify Data-ACL Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Objective:**

Verify Data-ACL Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Test Steps:**

1. Verify Data-ACL  can co-exist and function with AZD-setup. Verify that Data-plane ACLs correctly match, permit, and deny traffic in a VNET/VXLAN (AZD) environment

**Pass Criteria:**

- Verify basic functionality of AZD and Data-ACL matching traffic is denied/permitted at ingress/delivered as per ACL-action.

---

### TC-AZD-36 – Verify IP-in-IP Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Objective:**

Verify IP-in-IP Coexists and Functions with VNET/VXLAN Setup (priority P2)

**Test Steps:**

1. Verify IP-in-IP feature can co-exist and function with AZD-setup. Host-A ---- Leaf0 ---- Underlay ---- Leaf1 ---- Host-B | +---- IP-in-IP tunnel ---- Leaf1 ---- Host-C Send traffic from Host-A to Host-B over the VNET/VXLAN path. Send traffic from Host-A to Host-C using the route that resolves over the IP-in-IP tunnel. Capture packets at Spine0:
2. Verify that packet to HostB has outer protocol is UDP, destination port is 4789, VXLAN header is present, VNI matches expected VNET, inner packet matches original overlay traffic.
3. Verify that packet to HostC has outer IP protocol is 4, no UDP/VXLAN header is present, inner IP packet is encapsulated directly inside outer IP, source and destination outer IPs match configured IP-in-IP tunnel endpoints

**Pass Criteria:**

Verify basic functionality of AZD and verify that packet captures show correct encapsulation type:
- VXLAN traffic uses UDP/4789 with VXLAN header
- IP-in-IP traffic uses IP protocol 4 without VXLAN header

---

### TC-AZD-37 – Verify VXLAN Preserves Inner IP TTL and Uses Underlay TTL on Outer Header  (priority P1)

**Objective:**

Verify VXLAN Preserves Inner IP TTL and Uses Underlay TTL on Outer Header  (priority P1)

**Test Steps:**

1. Send a packet with TTL 64 / 32 from Ixia connected to Leaf0/Encap-Leaf.
2. Check the inner and outer header TTL values at Spine0.
3. Check the TTL value at Ixia connected to Leaf1/Decap-Leaf.

**Pass Criteria:**

Verify that:
- inner TTL before encapsulation equals inner TTL after decapsulation
- inner TTL does not change while packet is transported through VXLAN
- outer TTL is present only on the encapsulated packet
- outer TTL decreases across underlay routed hops

---

### TC-AZD-38 – Verify VXLAN TOS/DSCP Handling Across Tunnel without any QoS policy (priority P1)

**Objective:**

Verify VXLAN TOS/DSCP Handling Across Tunnel with QoS policy (priority P1)

**Test Steps:**

1. Send traffic  with a known DSCP value., say: DSCP = 46 (EF), TOS = 0xB8.
2. Sniff the packet on Spine0 and check for:
3. Inner DSCP = 46 (unchanged)
4. Outer DSCP = 46 (copied from inner)
5. Verify that end-packet is received with DSCP 46 on destination.

**Pass Criteria:**

Verify that in this deployment:
- the inner IP TOS/DSCP value is preserved end-to-end
- the outer IP TOS/DSCP is derived correctly (copied from inner by default)

---

### TC-AZD-39 – Verify VXLAN TOS/DSCP Handling Across Tunnel with QoS policy (priority P1)

**Objective:**

Verify VXLAN TOS/DSCP Handling Across Tunnel with QoS policy (priority P1)

**Test Steps:**

1. Send traffic  with a known DSCP value., say: DSCP = 46 (EF), TOS = 0xB8.
2. Configure QoS policy to rewrite DSCP: map 46 -> 10
3. Sniff the packet on Spine0 and check for:
4. Inner DSCP = 46 (unchanged)
5. Outer DSCP = 10 (asp per DSCP-map)
6. Verify that end-packet is received with DSCP 46 on destination.

**Pass Criteria:**

Verify that in this deployment:
- the inner IP TOS/DSCP value is preserved end-to-end
- the outer IP TOS/DSCP is derived correctly from QoS policy

---
