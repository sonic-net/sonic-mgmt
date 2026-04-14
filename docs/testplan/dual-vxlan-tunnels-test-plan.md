# Dual VXLAN tunnel test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
This test plan verifies support for creating two VXLAN tunnels on the same DUT:
- one VXLAN tunnel with outer IPv4
- one VXLAN tunnel with outer IPv6

The validation targets SPC3 platforms in the Compute T1 role.

Target branches:
- master
- 202511
- 202505

### Test purpose
Validate that one DUT can run an IPv4-outer and an IPv6-outer VXLAN tunnel together: tunnel creation succeeds, state stays correct, and dataplane behavior remains correct as tunnels are added and after both exist, independent of creation order.

### Scope
The test covers:
- dual VXLAN tunnel creation on the same DUT (IPv4 outer + IPv6 outer)
- both creation orders (IPv4 then IPv6, IPv6 then IPv4)
- per-tunnel state and basic traffic validation
- regression on tunnel 1 after tunnel 2 is added
- explicit validation that the second tunnel creation does not fail

For the current phase, basic traffic validation focuses on the encapsulation direction only. The following are not in scope:
- scale, performance, or long stress runs
- persistence across reboot or reload
- platforms other than SPC3
- roles other than Compute T1

### Testbed
The test will run on SPC3 platforms in the Compute T1 role.

Platforms in scope:
- SN4600C
- SN4700
- SN4280

### Setup configuration
Per scenario, start from a clean baseline.

For each tunnel, configure VXLAN and the route/VNET/forwarding needed so traffic can use that tunnel once it exists. Prepare two traffic paths:
- one path mapped uniquely to the IPv4 outer tunnel
- one path mapped uniquely to the IPv6 outer tunnel

Dataplane validation reuses the existing T1 VXLAN encapsulation checks (see `sonic-mgmt/tests/vxlan/test_vnet_bgp_route_precedence.py`): traffic entering the DUT should egress via the expected VXLAN tunnel and be observed correctly on the upstream side.

Cleanup:
- remove both tunnels and related forwarding
- restore the agreed baseline

## Test cases

### Test case 1 — Scenario A: IPv4 outer first, then IPv6 outer
#### Purpose
Prove dual-tunnel behavior when IPv4 outer is created before IPv6 outer, including that tunnel 1 still works after tunnel 2 exists.

#### Test steps

| Step | Action | Check |
|------|--------|--------|
| 1 | Create tunnel 1 (IPv4 outer). | Tunnel 1 present; agreed state check passes. |
| 2 | Run encapsulation traffic validation for tunnel 1. | Traffic direction: T0 -> T2, using the IPv4 outer tunnel path; validation passes. |
| 3 | Create tunnel 2 (IPv6 outer). | Tunnel 2 is created successfully; no swss/orchagent crash or tunnel creation failure is observed; tunnel 1 state is still valid. |
| 4 | Run encapsulation traffic validation for tunnel 2. | Traffic direction: T0 -> T2, using the IPv6 outer tunnel path; validation passes. |
| 5 | Re-check tunnel 1 state. | Same as step 1. |
| 6 | Re-run encapsulation traffic validation for tunnel 1. | Same as step 2; tunnel 2 does not break tunnel 1. |

---

### Test case 2 — Scenario B: IPv6 outer first, then IPv4 outer
#### Purpose
Same checks as test case 1 with reversed creation order to catch order-dependent bugs.

#### Test steps

| Step | Action | Check |
|------|--------|--------|
| 1 | Create tunnel 1 (IPv6 outer). | Tunnel 1 present; agreed state check passes. |
| 2 | Run encapsulation traffic validation for tunnel 1. | Traffic direction: T0 -> T2, using the IPv6 outer tunnel path; validation passes. |
| 3 | Create tunnel 2 (IPv4 outer). | Tunnel 2 is created successfully; no swss/orchagent crash or tunnel creation failure is observed; tunnel 1 state is still valid. |
| 4 | Run encapsulation traffic validation for tunnel 2. | Traffic direction: T0 -> T2, using the IPv4 outer tunnel path; validation passes. |
| 5 | Re-check tunnel 1 state. | Same as step 1. |
| 6 | Re-run encapsulation traffic validation for tunnel 1. | Same as step 2; no regression is observed. |

## TODO
- Define the agreed primary state check source for tunnel presence and health.
- Define the port mapping used for traffic validation.

## Open questions
- Is the current encapsulation-only traffic validation sufficient for the initial phase?
- For the initial phase, ECMP validation is not required. A follow-up phase may add a minimal T1 overlay ECMP sanity test based on the existing `test_vxlan_ecmp.py` coverage.