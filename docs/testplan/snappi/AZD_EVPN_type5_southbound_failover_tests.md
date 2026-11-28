# EVPN Type-5 Southbound Failover Test Plan

## Overview

This document describes EVPN Type-5 (IP prefix route) validation for VNET overlay redirect
at **16-VNET scale**. Vnet100 through Vnet115 are all in the run. Every VNET on Leaf0
and Leaf0A has `decap_tunnel_list` pointing at `tunnel_uni`.

When Leaf0 southbound PortChannels are fully down, tenant traffic arriving
from Leaf1 via the spine is encapsulated using EVPN-learned VNET_ROUTE_TUNNEL entries and
forwarded to Leaf0A. Leaf0A decapsulates the traffic and delivers it on its southbound
interfaces.

When only a subset of Leaf0 southbound Po-subinterfaces is shut, only those VNETs lose
the local path and redirect to Leaf0A. Remaining VNETs continue to be delivered on
Leaf0 southbound.

Configuration under test is applied on Leaf0 and Leaf0A as follows:

- CONFIG_DB: Loopback8 as VTEP, VXLAN tunnel with source IP set to that loopback, and all
  16 VNETs (`Vnet100`–`Vnet115`) with `decap_tunnel_list` pointing at that tunnel
- BGP (vtysh): per-VRF L2VPN EVPN address-family with `advertise ipv4 unicast`, RD/RT,
  eBGP EVPN neighbor between Loopback8 addresses (multihop via Spine0), `advertise-all-vni`,
  and outbound next-hop rewrite of Type-5 routes to the local Loopback8

This plan covers loopback VTEP, VXLAN tunnel, per-VRF EVPN address-family, Type-5
advertisement, VNET route programming, baseline forwarding, full southbound failover,
partial southbound failover, restore, EVPN session flap, and triggers (config reload and
reboot of one node at a time; remove and add `decap_tunnel_list` on an existing VNET on
both Leaf0 and Leaf0A). After each trigger, a **partial** Leaf0 southbound shutdown is
the dataplane check: shut the Po-subinterfaces of a few VNETs so those prefixes redirect
to Leaf0A, while the remaining VNETs continue via Leaf0.

Spine0 prefers Leaf0 over Leaf0A for downstream / southbound tenant prefixes.
Traffic from Leaf1 toward those prefixes is forwarded to Leaf0 (Ixia-A) while Leaf0
is reachable. Leaf0A is used only when Leaf0 is down, Leaf0 southbound is fully down,
or the southbound Po-subinterfaces of that VNET are down (Type-5 redirect).

All leaves (Leaf1, Leaf0, Leaf0A) attach to Spine0. Leaf0 and Leaf0A have no direct
leaf-to-leaf link; EVPN and VXLAN between them use Loopback8 reachability through the spine.


---

## Topology
```
  +-----------------------------------------------------+         +---------------------------+
  |                       Spine0                        |         |           Leaf1           |
  |                  Lo0: 10.10.10.100                  +--Eth-P--+     Lo0: 10.10.10.200     |
  |                                                     |         |        Ethernet-A         |
  |       Ethernet-Q                  Ethernet-R        |         |  Po100.xyz   Po101.xyz    |
  +------------+---------------------------+------------+         +------+++-+----+++-+-------+
               |                           |                             |||.|    |||.|
               |                           |                             BGP      BGP
  +-------------------------+ +-------------------------+         +------+++-+----+++-+-------+
  |       Ethernet-X        | |       Ethernet-Y        |         |  Lag3.xyz   Lag4.xyz      |
  |                         | |                         |         |          Ixia-X           |
  |          Leaf0          | |         Leaf0A          |         +---------------------------+
  |    Lo0: 10.10.11.200    | |    Lo0: 10.10.11.200    |
  |    Lo8: 10.10.11.201    | |    Lo8: 10.10.12.201    |
  |                         | |                         |
  | Po100.xyz               | |            Po101.xyz    |
  +-----+++-+---------------+ +--------------+++-+------+
        |||.|                                |||.|
        BGP                                  BGP
  +-----+++-+---------------+ +--------------+++-+------+
  | Lag1.xyz                | |           Lag2.xyz      |
  |         Ixia-A          | |         Ixia-B          |
  +-------------------------+ +-------------------------+
```
EVPN Type-5 and VXLAN between Leaf0 and Leaf0A use Loopback8 (10.10.11.201 <-> 10.10.12.201)
over the spine underlay. There is no direct leaf-to-leaf link.


### VNET scale and southbound mapping

- Max scale for this plan: **16 VNETs** — Vnet100 through Vnet115
- Every VNET has `decap_tunnel_list` = `tunnel_uni` on Leaf0 and on Leaf0A
- VLAN ID equals VNET ID (Vnet100 ↔ VLAN 100 ↔ Po100.100 as mapped in the setup)
- Full southbound failover (TC-6, TC-8, TC-9, TC-10): shut Leaf0 Po100
- Partial southbound trigger: shut only the Leaf0 Po-subinterfaces of a **few** VNETs
  (example: Vnet100–Vnet103). If a VNET is mapped on Po100, shut both of
  that VNET's subinterfaces so the local path is gone. Leave Vnet104–Vnet115 up.
  Affected VNETs redirect to Leaf0A / Ixia-B. Remaining VNETs continue via Leaf0 / Ixia-A.


### BGP and traffic (from reference)

-	All leaves (Leaf1, Leaf0, Leaf0A) are connected to Spine0 over underlay EBGP
-	BGPv4 running between Ixia-X and Leaf1 are advertising routes, say X.x.y.z/32
-	BGPv4 running between Ixia-A and Leaf0 are advertising routes, say A.x.y.z/32
-	BGPv4 running between Ixia-B and Leaf0A are advertising routes, say B.x.y.z/32
-	Underlay EBGP between each leaf and Spine0 advertises Loopback0 and Loopback8
-	L2VPN EVPN EBGP between Leaf0 Lo8 (10.10.11.201) and Leaf0A Lo8 (10.10.12.201) is multihop via Spine0
-	Traffic from Ixia-X / Leaf1 toward tenant prefixes that Leaf0 would normally deliver southbound
-	Spine0 prefers Leaf0 over Leaf0A for those downstream prefixes while Leaf0 is up
-	With Leaf0 Po100 down, that traffic is EVPN Type-5 encapsulated to Leaf0A (outer DIP 10.10.12.201) via Spine0 and delivered to Ixia-B
-	With only a few Leaf0 southbound Po-subinterfaces down, only those VNETs are EVPN Type-5 encapsulated to Leaf0A / Ixia-B; remaining VNETs continue on Leaf0 / Ixia-A
-	If Leaf0 itself is unreachable (reload/reboot), Spine0 sends the same prefixes to Leaf0A until Leaf0 is preferred again


---

## Test Cases — VNET and EVPN Type-5

---

### TC-VNET-AND-EVPN-TYPE5-1 – Verify Loopback8 VTEP and uni-directional VXLAN tunnel can be created

**Objective:**

Verify Loopback8 VTEP and uni-directional VXLAN tunnel can be created

**Test Steps:**

1. On Leaf0 and Leaf0A, create Loopback8 and assign the VTEP /32 (10.10.11.201/32 on Leaf0, 10.10.12.201/32 on Leaf0A).
2. Create a VXLAN tunnel with source IP set to the local Loopback8 on each leaf.
3. Associate all 16 VNETs (Vnet100–Vnet115) with `decap_tunnel_list` pointing at that tunnel. Do not leave any VNET without `decap_tunnel_list`.
4. Advertise Loopback8 into underlay BGP toward Spine0 so the peer VTEP is reachable via the spine.
5. Save the config.

**Pass Criteria:**

- Verify that all the CLI are successful
- Verify Loopback8 IP is present on each leaf
- Verify `show vxlan tunnel` / `show vxlan interface` shows `tunnel_uni` with the expected source IP
- Verify VNET objects include `decap_tunnel_list` pointing to `tunnel_uni`

---

### TC-VNET-AND-EVPN-TYPE5-2 – Verify per-VRF L2VPN EVPN address-family can advertise IPv4 unicast as Type-5

**Objective:**

Verify per-VRF L2VPN EVPN address-family can advertise IPv4 unicast as Type-5

**Test Steps:**

1. Under `router bgp <ASN> vrf Vnet<id>` configure `address-family l2vpn evpn` on Leaf0 and Leaf0A.
2. Enable `advertise ipv4 unicast` for Vnet100 through Vnet115.
3. Configure RD as `<local-asn>:<vni>` and route-target import/export `65000:<vni>`.
4. Repeat for all VNETs used in the setup.
5. Save the config.

**Pass Criteria:**

- Verify that all the CLI are successful
- Verify running-config has `advertise ipv4 unicast`, RD, and RT for each VNET
- Verify BGP VRF instances are present for Vnet100–Vnet115

---

### TC-VNET-AND-EVPN-TYPE5-3 – Verify EVPN BGP session can be established between Leaf0 and Leaf0A over Loopback8

**Objective:**

Verify EVPN BGP session can be established between Leaf0 and Leaf0A over Loopback8

**Test Steps:**

1. Advertise Loopback8 /32 into underlay BGP toward Spine0 (`network 10.10.11.201/32` on Leaf0, `network 10.10.12.201/32` on Leaf0A).
2. Configure eBGP neighbor to the peer Loopback8 with ebgp-multihop and update-source Loopback8 (session is established via Spine0).
3. Activate the neighbor under `address-family l2vpn evpn`.
4. Enable `advertise-all-vni`.
5. Apply outbound route-map `EVPN_NH` matching EVPN route-type prefix and setting next-hop to local Loopback8.
6. Save the config.

**Pass Criteria:**

- Verify underlay BGP is up and remote Loopback8 is installed on both leaves
- Verify ping between Loopback8 addresses succeeds in both directions
- Verify L2VPN EVPN neighbor is Established
- Verify `show bgp l2vpn evpn summary` shows prefixes sent and received

---

### TC-VNET-AND-EVPN-TYPE5-4 – Verify EVPN Type-5 routes are advertised and installed in VNET_ROUTE_TUNNEL

**Objective:**

Verify EVPN Type-5 routes are advertised and installed in VNET_ROUTE_TUNNEL

**Test Steps:**

1. Base configuration is applied — VNETs, PO-subinterfaces, southboung BGP, underlay BGP, Loopback8, and EVPN session are operational.
2. Confirm Type-5 prefix routes in `show bgp l2vpn evpn route type prefix`.
3. Confirm advertised-routes toward the EVPN peer use local Loopback8 as next-hop.
4. Confirm received Type-5 routes are imported into the corresponding BGP VRF.
5. Confirm `show vnet routes all` / `show vnet route tunnel` shows endpoint, mac address, and vni for remote prefixes.

**Pass Criteria:**

- Verify Type-5 routes are present for tenant prefixes in each VNET
- Verify advertised next-hop is the local Loopback8 VTEP
- Verify `show vnet routes all` has endpoint = peer Loopback8, mac address = peer router MAC, vni = VNET VNI
- Verify imported prefixes are visible in `show bgp vrf Vnet<id> ipv4`

---

### TC-VNET-AND-EVPN-TYPE5-5 – Verify baseline tenant traffic from Leaf1 is forwarded on Leaf0 southbound when Po100 are up

**Objective:**

Verify baseline tenant traffic from Leaf1 is forwarded on Leaf0 southbound when Po100 are up

**Test Steps:**

1. Create & Start traffic streams from Ixia-X connected to Leaf1 toward tenant prefixes that Leaf0 delivers locally (same VNET / VNI / VLAN mapping).
2. Leaf0 Po100 is up. BGP and ARP toward Ixia-A are up.
3. Traffic from Leaf1 arrives on Leaf0 via Spine0 underlay.
4. Leaf0 should forward this traffic out Po100 toward Ixia-A.
5. EVPN path to Leaf0A may exist as backup and should not be used while southbound is up.

**Pass Criteria:**

- Verify that all Ixia interfaces have successfully resolved ARP entries toward the Leaf interfaces
- Confirm that traffic loss is 0% across all traffic streams
- Confirm Leaf0 egress is southbound Po100, not VXLAN toward Leaf0A
- For high-scale scenarios, BGP route installation on the Leaf may take additional time
- If packet loss is observed initially, allow some time (tolerance) for route programming and retry traffic verification until loss converges to 0%. Note down this delay in script/log.

---

### TC-VNET-AND-EVPN-TYPE5-6 – Verify that when Leaf0 Po100 is down, traffic from Leaf1 is EVPN Type-5 encapsulated to Leaf0A and delivered southbound

**Objective:**

Verify that when Leaf0 Po100 is down, traffic from Leaf1 is EVPN Type-5 encapsulated to Leaf0A and delivered southbound

**Test Steps:**

1. Base configuration is applied and baseline traffic from T5 is running (or ready to start).
2. Shutdown PortChannel100 on Leaf0 only. Leave Leaf0A southbound up.
3. Confirm Leaf0 LAGs are operationally down.
4. Confirm VRF RIB for tenant prefixes now points to Leaf0A Loopback8 via the VNET bridge (onlink).
5. Confirm `show vnet routes all` is populated with endpoint 10.10.12.201, peer MAC, and VNI, status active.
6. Confirm ASIC_DB ROUTE_ENTRY exists for the tenant prefix in the VNET VR.
7. Continue or start traffic from Ixia-X / Leaf1 toward those tenant prefixes.
8. Leaf0 should VXLAN-encapsulate the packets. Outer destination IP is Leaf0A Loopback8. VNI matches the VNET.
9. Capture VXLAN-encapsulated packets at Spine0 to inspect outer DIP, inner DMAC, and VNI.
10. Leaf0A should decapsulate and forward to Ixia-B on the corresponding Po-subinterface.

**Pass Criteria:**

- Verify Leaf0 Po100 is down
- Verify Type-5 / VNET_ROUTE_TUNNEL entries are active with endpoint = Leaf0A Loopback8
- Verify hardware route is programmed (ASIC_DB ROUTE_ENTRY for the prefix)
- Verify Spine capture shows VXLAN UDP/4789, outer DIP = 10.10.12.201, VNI matches VNET, inner DMAC matches VNET mac address
- Confirm that traffic is received on Ixia-B with 0% loss after convergence (allow programming tolerance as in T5)
- Confirm Leaf0A southbound delivers the decapsulated tenant packets

---

### TC-VNET-AND-EVPN-TYPE5-7 – Verify partial southbound failure redirects only the affected VNET prefixes over EVPN

**Objective:**

Verify that shutting Leaf0 southbound Po-subinterfaces for a few VNETs redirects only those VNETs to Leaf0A, while remaining VNETs continue via Leaf0. All 16 VNETs keep `decap_tunnel_list`.

**Test Steps:**

1. Restore Po100 on Leaf0. Confirm all 16 VNETs (Vnet100–Vnet115) have `decap_tunnel_list` pointing at `tunnel_uni` on Leaf0 and Leaf0A.  Spine0 prefers Leaf0. Traffic for all 16 VNETs is delivered on Ixia-A.
2. On Leaf0 only, shut the southbound Po-subinterfaces of a few VNETs (example: Vnet100–Vnet103). If a VNET is mapped on Po100, shut that VNET's subinterfaces so the local path is gone. Leave Vnet104–Vnet115 southbound up. Do not shut Leaf0A southbound.
3. Send traffic from Ixia-X / Leaf1 for the down-VNET prefixes and for the remaining-VNET prefixes.
4. Confirm down-VNET prefixes are installed in VNET_ROUTE_TUNNEL toward Leaf0A (endpoint 10.10.12.201, peer MAC, matching VNI).
5. Confirm remaining-VNET prefixes continue to use local Leaf0 southbound forwarding (not VXLAN toward Leaf0A).
6. Capture at Spine0 for the down-VNET streams and confirm outer DIP is Leaf0A Loopback8 and VNI matches the source VNET.

**Pass Criteria:**

- Verify only the intended few VNETs have southbound Po-subinterfaces down on Leaf0
- Verify all 16 VNETs still have `decap_tunnel_list` pointing at `tunnel_uni`
- Verify down-VNET tenant traffic is VXLAN-encapsulated to Leaf0A and delivered to Ixia-B
- Verify remaining-VNET tenant traffic continues to egress Leaf0 southbound toward Ixia-A
- Verify no cross-VNET leakage
- Confirm that traffic loss is 0% on both stream groups after convergence

---

### TC-VNET-AND-EVPN-TYPE5-8 – Verify traffic returns to Leaf0 southbound after Po100 is restored

**Objective:**

Verify traffic returns to Leaf0 southbound after Po100 is restored

**Test Steps:**

1. From T6 state (both Leaf0 POs down, EVPN redirect in use), startup PortChannel100 on Leaf0.
2. Wait for LAG, ARP, and southbound BGP to recover toward Ixia-A.
3. Restart or continue traffic from Ixia-X / Leaf1 toward the same tenant prefixes.
4. Confirm VRF best-path is again the local southbound path.
5. Confirm VXLAN encapsulation toward Leaf0A stops for those prefixes.

**Pass Criteria:**

- Verify Po100 is up and southbound BGP/ARP recovered
- Verify traffic is delivered on Ixia-A with 0% loss after convergence
- Verify Leaf0 no longer encapsulates this traffic to Leaf0A
- Check for core, any unexpected docker-restart

---

### TC-VNET-AND-EVPN-TYPE5-9 – Verify EVPN neighbor flap while southbound is down reinstalls Type-5 and resumes traffic

**Objective:**

Verify EVPN neighbor flap while southbound is down reinstalls Type-5 and resumes traffic

**Test Steps:**

1. Shutdown Po100 on Leaf0 so EVPN redirect is in use.
2. Flap the L2VPN EVPN BGP neighbor between Leaf0 and Leaf0A.
3. Wait for the EVPN session to return to Established.
4. Confirm Type-5 routes, VNET_ROUTE_TUNNEL entries, and ASIC routes are reinstalled.
5. Confirm traffic from Leaf1 is again delivered via Leaf0A.

**Pass Criteria:**

- Verify EVPN neighbor returns to Established
- Verify Type-5 and `show vnet routes all` entries are reinstalled with expected endpoint/MAC/VNI
- Confirm that traffic resumes with 0% loss after convergence
- Check for core, any unexpected docker-restart

---

### TC-VNET-AND-EVPN-TYPE5-10 – Verify Type-5 redirect works across all 16 VNETs

**Objective:**

Verify Type-5 redirect works across all 16 VNETs (Vnet100–Vnet115), each with `decap_tunnel_list`

**Test Steps:**

1. Base configuration includes all 16 VNETs (Vnet100 through Vnet115), each with `decap_tunnel_list` pointing at `tunnel_uni`.
2. Shutdown Po100 on Leaf0.
3. Send per-VNET traffic streams from Leaf1 / Ixia-X toward prefixes in all 16 VNETs.
4. Confirm each VNET has its own VNI and peer MAC in `show vnet routes all`.
5. Capture at Spine0 and confirm outer DIP is Leaf0A Loopback8 and VNI matches the source VNET.
6. Confirm Leaf0A delivers each stream on the corresponding VNET Po-subinterface to Ixia-B.

**Pass Criteria:**

- Verify VNET_ROUTE_TUNNEL entries exist for all 16 VNETs with the correct vni
- Verify no cross-VNET leakage (stream for VnetX is not delivered on VnetY)
- Confirm that traffic loss is 0% across all 16 VNET streams after convergence

---

## Trigger Cases — VNET and EVPN Type-5

Spine0 prefers Leaf0 over Leaf0A for downstream / southbound prefixes. Config reload
and reboot are run on **one node at a time**. Do not reload or reboot Leaf0 and Leaf0A
in the same case. Remove and add of `decap_tunnel_list` on an existing VNET are done
on **both Leaf0 and Leaf0A**. All other cases keep `decap_tunnel_list` on all 16 VNETs.

After each trigger has completed and Spine0 prefers Leaf0 again, apply the **partial
southbound trigger** on Leaf0: shut the Po-subinterfaces of a few VNETs only (example:
Vnet100–Vnet103). Leave the remaining VNETs (Vnet104–Vnet115) southbound up. Confirm
the affected VNETs redirect to Leaf0A / Ixia-B and the remaining VNETs continue via
Leaf0 / Ixia-A. Then restore those subinterfaces and confirm all streams return to
Ixia-A.

---

### TC-VNET-AND-EVPN-TYPE5-11 – Verify config reload of Leaf0 only

**Objective:**

Verify config reload of Leaf0 only

**Test Steps:**

1. Base configuration is applied. Leaf0 Po100 is up. Spine0 prefers Leaf0 for downstream prefixes. Traffic from Ixia-X / Leaf1 is delivered on Ixia-A.
2. Save a copy of running config on Leaf0. Do not reload Leaf0A.
3. Run `config reload` on Leaf0 only.
4. While Leaf0 is down, confirm Spine0 no longer prefers Leaf0 and southbound traffic is forwarded to Leaf0A / Ixia-B.
5. Wait for Leaf0 dockers, underlay BGP, Loopback8, L2VPN EVPN neighbor, Type-5, and VNET_ROUTE_TUNNEL to recover. Leaf0A stays up throughout.
6. Confirm Spine0 prefers Leaf0 again and traffic from Leaf1 returns to Ixia-A. Confirm all 16 VNETs still have `decap_tunnel_list`.
7. After the trigger is complete, shut Leaf0 southbound Po-subinterfaces for a few VNETs only (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up. If a VNET is mapped on Po100, shut that VNET's subinterfaces.
8. Confirm Type-5 / `show vnet routes all` entries are still present with expected endpoint/MAC/VNI for the affected VNETs.
9. Confirm affected-VNET traffic is VXLAN-encapsulated to Leaf0A and delivered on Ixia-B. Confirm remaining-VNET traffic continues via Leaf0 to Ixia-A.
10. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm all 16 VNET streams return to Ixia-A.

**Pass Criteria:**

- Verify only Leaf0 is reloaded
- Verify config after reload matches the saved config on Leaf0
- Verify traffic moves to Leaf0A / Ixia-B while Leaf0 is down, then back to Leaf0 / Ixia-A after convergence
- Verify Loopback8, `tunnel_uni`, all 16 VNET `decap_tunnel_list` entries, and EVPN neighbor are restored on Leaf0
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after reload
- Confirm after reload, partial southbound shut redirects only the affected VNETs to Leaf0A / Ixia-B; remaining VNETs stay on Leaf0 / Ixia-A with 0% loss after convergence
- Confirm that traffic loss is 0% after Leaf0 is preferred again (note convergence time)
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-12 – Verify config reload of Leaf0A only

**Objective:**

Verify config reload of Leaf0A only

**Test Steps:**

1. Base configuration is applied. Leaf0 Po100 is up. Spine0 prefers Leaf0. Traffic from Ixia-X / Leaf1 is delivered on Ixia-A.
2. Save a copy of running config on Leaf0A. Do not reload Leaf0.
3. Run `config reload` on Leaf0A only.
4. While Leaf0A is down, confirm Spine0 still prefers Leaf0 and traffic continues to Ixia-A.
5. Wait for Leaf0A dockers, underlay BGP, Loopback8, L2VPN EVPN neighbor, and Type-5 import to recover. Leaf0 stays up throughout.
6. Confirm Spine0 still prefers Leaf0 and traffic remains on Ixia-A. Confirm all 16 VNETs still have `decap_tunnel_list`.
7. After the trigger is complete, shut Leaf0 southbound Po-subinterfaces for a few VNETs only (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up. If a VNET is mapped on Po100, shut that VNET's subinterfaces.
8. Confirm Type-5 / `show vnet routes all` entries are still present with expected endpoint/MAC/VNI (Leaf0 advertise and Leaf0A import/decap) for the affected VNETs.
9. Confirm affected-VNET traffic is VXLAN-encapsulated to Leaf0A and delivered on Ixia-B. Confirm remaining-VNET traffic continues via Leaf0 to Ixia-A.
10. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm all 16 VNET streams return to Ixia-A.

**Pass Criteria:**

- Verify only Leaf0A is reloaded
- Verify config after reload matches the saved config on Leaf0A
- Verify southbound traffic stays on Leaf0 / Ixia-A during and after Leaf0A reload (Leaf0 remains preferred)
- Verify Loopback8, `tunnel_uni`, all 16 VNET `decap_tunnel_list` entries, and EVPN neighbor are restored on Leaf0A
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after Leaf0A reload
- Confirm after Leaf0A reload, partial southbound shut redirects only the affected VNETs to Leaf0A / Ixia-B; remaining VNETs stay on Leaf0 / Ixia-A with 0% loss after convergence
- Confirm that traffic loss is 0% on Ixia-A after convergence (note convergence time)
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-13 – Verify device reboot of Leaf0 only

**Objective:**

Verify device reboot of Leaf0 only

**Test Steps:**

1. Base configuration is applied. Leaf0 Po100 is up. Spine0 prefers Leaf0 for downstream prefixes. Traffic from Ixia-X / Leaf1 is delivered on Ixia-A.
2. Save a copy of running config on Leaf0. Do not reboot Leaf0A.
3. Run reboot on Leaf0 only.
4. While Leaf0 is down, confirm Spine0 no longer prefers Leaf0 and southbound traffic is forwarded to Leaf0A / Ixia-B.
5. After Leaf0 is back, wait for dockers, underlay BGP, Loopback8, L2VPN EVPN neighbor, Type-5, and VNET_ROUTE_TUNNEL to recover. Leaf0A stays up throughout.
6. Confirm Spine0 prefers Leaf0 again and traffic from Leaf1 returns to Ixia-A. Confirm all 16 VNETs still have `decap_tunnel_list`.
7. After the trigger is complete, shut Leaf0 southbound Po-subinterfaces for a few VNETs only (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up.
8. Confirm Type-5 / `show vnet routes all` entries are still present with expected endpoint/MAC/VNI for the affected VNETs.
9. Confirm affected-VNET traffic is VXLAN-encapsulated to Leaf0A and delivered on Ixia-B. Confirm remaining-VNET traffic continues via Leaf0 to Ixia-A.
10. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm all 16 VNET streams return to Ixia-A.

**Pass Criteria:**

- Verify only Leaf0 is rebooted
- Verify config after reboot matches the saved config on Leaf0
- Verify traffic moves to Leaf0A / Ixia-B while Leaf0 is down, then back to Leaf0 / Ixia-A after convergence
- Verify Loopback8, `tunnel_uni`, all 16 VNET `decap_tunnel_list` entries, and EVPN neighbor are restored on Leaf0
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after reboot
- Confirm after reboot, partial southbound shut redirects only the affected VNETs to Leaf0A / Ixia-B; remaining VNETs stay on Leaf0 / Ixia-A with 0% loss after convergence
- Confirm that traffic loss is 0% after Leaf0 is preferred again (note convergence time)
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-14 – Verify device reboot of Leaf0A only

**Objective:**

Verify device reboot of Leaf0A only

**Test Steps:**

1. Base configuration is applied. Leaf0 Po100 is up. Spine0 prefers Leaf0. Traffic from Ixia-X / Leaf1 is delivered on Ixia-A.
2. Save a copy of running config on Leaf0A. Do not reboot Leaf0.
3. Run reboot on Leaf0A only.
4. While Leaf0A is down, confirm Spine0 still prefers Leaf0 and traffic continues to Ixia-A.
5. After Leaf0A is back, wait for underlay BGP, Loopback8, L2VPN EVPN neighbor, and Type-5 import to recover. Leaf0 stays up throughout.
6. Confirm Spine0 still prefers Leaf0 and traffic remains on Ixia-A. Confirm all 16 VNETs still have `decap_tunnel_list`.
7. After the trigger is complete, shut Leaf0 southbound Po-subinterfaces for a few VNETs only (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up.
8. Confirm Type-5 / `show vnet routes all` entries are still present with expected endpoint/MAC/VNI (Leaf0 advertise and Leaf0A import/decap) for the affected VNETs.
9. Confirm affected-VNET traffic is VXLAN-encapsulated to Leaf0A and delivered on Ixia-B. Confirm remaining-VNET traffic continues via Leaf0 to Ixia-A.
10. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm all 16 VNET streams return to Ixia-A.

**Pass Criteria:**

- Verify only Leaf0A is rebooted
- Verify config after reboot matches the saved config on Leaf0A
- Verify southbound traffic stays on Leaf0 / Ixia-A during and after Leaf0A reboot (Leaf0 remains preferred)
- Verify Loopback8, `tunnel_uni`, all 16 VNET `decap_tunnel_list` entries, and EVPN neighbor are restored on Leaf0A
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after Leaf0A reboot
- Confirm after Leaf0A reboot, partial southbound shut redirects only the affected VNETs to Leaf0A / Ixia-B; remaining VNETs stay on Leaf0 / Ixia-A with 0% loss after convergence
- Confirm that traffic loss is 0% on Ixia-A after convergence (note convergence time)
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-15 – Verify remove decap_tunnel_list from an existing VNET on Leaf0 and Leaf0A

**Objective:**

Verify remove `decap_tunnel_list` from an existing VNET on Leaf0 and Leaf0A

**Test Steps:**

1. Base configuration is applied at 16-VNET scale. Vnet100–Vnet115 all have `decap_tunnel_list` pointing at `tunnel_uni`. Spine0 prefers Leaf0. Traffic from Ixia-X / Leaf1 for all 16 VNETs is delivered on Ixia-A.
2. On Leaf0, remove `decap_tunnel_list` (or remove `tunnel_uni` from the list) from existing Vnet100. Leave Vnet101–Vnet115 unchanged.
3. Confirm Vnet100 on Leaf0 no longer includes `tunnel_uni` in `decap_tunnel_list`. Confirm Vnet101–Vnet115 on Leaf0 still have `decap_tunnel_list`. Confirm Type-5 / `show vnet routes all` entries are still present. Confirm traffic remains on Ixia-A.
4. On Leaf0A, remove `decap_tunnel_list` (or remove `tunnel_uni` from the list) from existing Vnet100. Leave Vnet101–Vnet115 unchanged.
5. Confirm Vnet100 on Leaf0A no longer includes `tunnel_uni` in `decap_tunnel_list`. Confirm Vnet101–Vnet115 on Leaf0A still have `decap_tunnel_list`. Confirm traffic remains on Ixia-A.
6. After the trigger is complete on both Leaf0s, shut Leaf0 southbound Po-subinterfaces for a few VNETs including Vnet100 (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up.
7. Confirm Type-5 / `show vnet routes all` entries are still present for the affected VNETs.
8. Confirm Vnet100 is not delivered on Ixia-B (Leaf0A cannot decap Vnet100). Confirm Vnet101–Vnet103 EVPN routes are still usable and are delivered on Ixia-B. Confirm Vnet104–Vnet115 continue via Leaf0 to Ixia-A.
9. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm Spine0 prefers Leaf0 again and all streams return to Ixia-A.

**Pass Criteria:**

- Verify Vnet100 `decap_tunnel_list` is removed on both Leaf0 and Leaf0A
- Verify Vnet101–Vnet115 still have `decap_tunnel_list` on both Leaf0s
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after the remove
- Verify after partial southbound shut, Vnet101–Vnet103 redirect to Ixia-B; Vnet100 does not; Vnet104–Vnet115 stay on Ixia-A
- Confirm that traffic loss is 0% on Ixia-A for all VNET streams while Leaf0 is preferred
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-16 – Verify add decap_tunnel_list to an existing VNET on Leaf0 and Leaf0A

**Objective:**

Verify add `decap_tunnel_list` to an existing VNET on Leaf0 and Leaf0A

**Test Steps:**

1. Base configuration is applied at 16-VNET scale. Existing Vnet100 on Leaf0 and on Leaf0A does **not** have `tunnel_uni` in `decap_tunnel_list` (from TC-VNET-AND-EVPN-TYPE5-15, or remove it first on both Leaf0s). Vnet101–Vnet115 still have `decap_tunnel_list` on both. Spine0 prefers Leaf0.
2. Send traffic for all 16 VNETs from Ixia-X / Leaf1. Confirm all streams are delivered on Ixia-A.
3. On Leaf0, add `tunnel_uni` to `decap_tunnel_list` on existing Vnet100. Confirm Vnet100 on Leaf0 includes `tunnel_uni`. Confirm Vnet101–Vnet115 are unchanged. Confirm traffic remains on Ixia-A.
4. On Leaf0A, add `tunnel_uni` to `decap_tunnel_list` on existing Vnet100. Confirm Vnet100 on Leaf0A includes `tunnel_uni`. Confirm Vnet101–Vnet115 are unchanged. Confirm traffic remains on Ixia-A. All 16 VNETs now have `decap_tunnel_list` again.
5. After the trigger is complete on both Leaf0s, shut Leaf0 southbound Po-subinterfaces for a few VNETs only (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up.
6. Confirm Type-5 / `show vnet routes all` entries are still present with expected endpoint/MAC/VNI.
7. Confirm Vnet100 is now decapped and delivered on Ixia-B. Confirm Vnet101–Vnet103 remain delivered on Ixia-B. Confirm Vnet104–Vnet115 continue via Leaf0 to Ixia-A.
8. Restore the shut Leaf0 southbound Po-subinterfaces. Confirm Spine0 prefers Leaf0 again and all 16 VNET streams return to Ixia-A.

**Pass Criteria:**

- Verify Vnet100 `decap_tunnel_list` is added on both Leaf0 and Leaf0A
- Verify add restores decap for that existing VNET only; Vnet101–Vnet115 are unaffected on both Leaf0s
- Verify EVPN Type-5 / VNET_ROUTE_TUNNEL entries remain after the add
- Confirm after the add, partial southbound shut redirects Vnet100–Vnet103 to Leaf0A / Ixia-B; remaining VNETs stay on Leaf0 / Ixia-A with 0% loss after convergence
- Confirm traffic returns to Ixia-A with 0% loss after Leaf0 southbound subinterfaces are restored
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---

### TC-VNET-AND-EVPN-TYPE5-17 – Verify partial Leaf0 southbound shut redirects a few VNETs to Leaf0A while remaining VNETs stay on Leaf0

**Objective:**

Verify the partial southbound trigger at 16-VNET scale: all VNETs have `decap_tunnel_list`; shutting a few Leaf0 southbound Po-subinterfaces moves only those VNETs to Leaf0A; remaining traffic continues via Leaf0.

**Test Steps:**

1. Base configuration is applied at 16-VNET scale. Vnet100–Vnet115 all have `decap_tunnel_list` pointing at `tunnel_uni` on Leaf0 and Leaf0A. Leaf0 Po100 is up. Spine0 prefers Leaf0. Traffic from Ixia-X / Leaf1 for all 16 VNETs is delivered on Ixia-A.
2. On Leaf0 only, shut the southbound Po-subinterfaces of a few VNETs (example: Vnet100–Vnet103). Leave Vnet104–Vnet115 southbound up. Do not shut Leaf0A southbound.
3. Confirm the intended Leaf0 Po-subinterfaces are operationally down and the remaining VNET subinterfaces are up.
4. Confirm down-VNET prefixes are installed in VNET_ROUTE_TUNNEL toward Leaf0A (endpoint 10.10.12.201, peer MAC, matching VNI). Confirm remaining-VNET prefixes still use local Leaf0 southbound.
5. Confirm traffic for Vnet100–Vnet103 is VXLAN-encapsulated to Leaf0A and delivered on Ixia-B. Confirm traffic for Vnet104–Vnet115 continues via Leaf0 to Ixia-A.
6. Capture at Spine0 for a down-VNET stream and confirm outer DIP is Leaf0A Loopback8 and VNI matches the source VNET. Confirm remaining-VNET streams are not VXLAN-encapsulated toward Leaf0A.
7. Restore the shut Leaf0 southbound Po-subinterfaces. Wait for LAG, ARP, and southbound BGP to recover toward Ixia-A.
8. Confirm all 16 VNET streams return to Ixia-A and Leaf0 no longer encapsulates the previously redirected VNETs to Leaf0A.

**Pass Criteria:**

- Verify all 16 VNETs have `decap_tunnel_list` throughout this case
- Verify only the intended few VNETs lose Leaf0 southbound; remaining VNETs stay up on Leaf0
- Verify down-VNET traffic is delivered on Ixia-B with 0% loss after convergence
- Verify remaining-VNET traffic is delivered on Ixia-A with 0% loss after convergence
- Verify no cross-VNET leakage
- Confirm all 16 VNET streams return to Ixia-A with 0% loss after the subinterfaces are restored
- Check for core, any unexpected docker-restart
- Use crm commands to check for resource-leaks

---
