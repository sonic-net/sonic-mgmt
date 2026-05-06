# VXLAN VPP Failure Investigation

## Scope

This report summarizes the failures listed in `docs/vxlan_vpp_failures.md` after enabling additional VXLAN tests on the SONiC VPP virtual testbed.

Referenced runs:

| Elastictest plan | SONiC image | Topology | ASIC type | Notes |
| --- | --- | --- | --- | --- |
| [`69fbca2e39aa410dfe77faed`](https://elastictest.org/scheduler/testplan/69fbca2e39aa410dfe77faed) | `SONiC.master.1106708-d8f083638` | `t1-lag-vpp` | `vpp` | Ran `test_vxlan_ecmp.py`, `test_vxlan_multiple_tunnels.py`, `test_vnet_bgp_route_precedence.py`; `--include_long_tests=True` for `test_vxlan_ecmp.py`. |
| [`69fae4d990b147b195e54672`](https://elastictest.org/scheduler/testplan/69fae4d990b147b195e54672) | `SONiC.master.1105738-3e1af2a30` | `t1-lag-vpp` | `vpp` | Ran underlay ECMP, VNET decap, BFD TSA, multi-tunnel, route advertisement, and route precedence modules. |

The platform references are:

- `~/workspace/sonic-platform-vpp`: SONiC VPP image, container, HLDs, and VM validation playbooks.
- `~/workspace/sonic-sairedis`: VPP SAI implementation under `vslib/vpp`, including VXLAN, route, next-hop-group, and BFD handling.

## Executive summary

The failures fall into four groups:

| Group | Tests | Summary |
| --- | --- | --- |
| VXLAN tunnel forwarding after route churn | `Test_VxLAN_ecmp_random_hash`, `Test_VxLAN_entropy` | `random_hash` failed because no VXLAN packet was returned for an existing single-endpoint route. `entropy` did not run because pytest stopped at the previous failure. |
| Underlay ECMP over T2 PortChannels | `Test_VxLAN_underlay_ecmp` | VXLAN encapsulation worked, but all observed packets for endpoint `100.0.1.10` exited one PTF port instead of spreading across the expected T2 egress interfaces. |
| Decap and re-encap behavior | `test_vxlan_multiple_tunnels.py`, `test_vnet_decap.py` | The expected VXLAN packet was not observed. `multiple_tunnels` likely conflicts with the VPP bridge-domain/BVI decap model, while `vnet_decap` depends on IP-in-IP decap support that is not implemented in the checked VPP SAI backend. |
| Test/platform gating | `test_vxlan_bfd_tsa.py` | The fixture explicitly rejects `asic_type == "vpp"`, so this is a test enablement gap before any BFD/TSA dataplane behavior is exercised. |

Recommended enablement order:

1. Re-enable `test_vxlan_bfd_tsa.py` only after adding and validating VPP-specific fixture support.
2. Keep `test_vnet_decap.py` skipped until IP-in-IP tunnel termination is implemented and validated in the VPP SAI backend.
3. Keep `test_vxlan_multiple_tunnels.py` skipped or make it VPP-aware until the expected inner Ethernet behavior is aligned with the VPP BVI design.
4. Keep `test_vxlan_underlay_ecmp.py`, `Test_VxLAN_ecmp_random_hash`, and `Test_VxLAN_entropy` skipped until VPP underlay ECMP and VXLAN route lifecycle behavior are fixed or the tests are adapted to the supported VPP behavior.

## Relevant implementation facts

### Test expectations

- `test_vxlan_ecmp.py` now includes `vpp` in the supported ASIC list and uses strict overlay tolerance `0.03` plus underlay tolerance `0.25` for VPP (`tests/vxlan/test_vxlan_ecmp.py:187-193`).
- `dump_self_info_and_run_ptf()` records `show vxlan tunnel`, `show vnet route all`, BGP summaries, and optionally BFD summary before running the PTF VXLAN traffic test (`tests/vxlan/test_vxlan_ecmp.py:476-516`).
- Underlay ECMP validation uses `show ip route <endpoint>` or `show ipv6 route <endpoint>` to build the expected egress interface list, then requires packet distribution across those interfaces within tolerance (`tests/vxlan/test_vxlan_ecmp.py:147-162`, `tests/ptftests/py3/vxlan_traffic.py:352-413`).
- The PTF VXLAN script fails with "Didnot get any reply" when it receives no VXLAN packet for an active endpoint (`tests/ptftests/py3/vxlan_traffic.py:633-638`).
- `test_vxlan_multiple_tunnels.py` sends a VXLAN packet to one DUT tunnel source IP and expects the DUT to decapsulate it, route the inner packet, and emit a new VXLAN packet toward the VNET route endpoint (`tests/vxlan/test_vxlan_multiple_tunnels.py:400-443`).
- `test_vnet_decap.py` sends an IP-in-IP packet to the DUT loopback and expects the DUT to decapsulate the outer IP header, route the inner packet through a VNET route, and re-encapsulate it as VXLAN (`tests/vxlan/test_vnet_decap.py:130-136`, `tests/vxlan/test_vnet_decap.py:236-262`).
- `test_vxlan_bfd_tsa.py` rejects any ASIC type outside `["cisco-8000", "mellanox", "vs"]` during setup, which excludes VPP (`tests/vxlan/test_vxlan_bfd_tsa.py:108-113`).

### VPP VXLAN and tunnel support

- The VPP VXLAN/VNET HLD describes baremetal-to-VM forwarding as VXLAN encap through a dummy neighbor and route via the VXLAN tunnel (`~/workspace/sonic-platform-vpp/docs/HLD/vxlan-vnet.md:133-146`).
- The same HLD describes VM-to-baremetal VXLAN decap through a bridge domain and BVI. It explicitly states that after VXLAN decapsulation, the inner DMAC must match the BVI MAC before VPP forwards the inner IP packet in the VNET table (`~/workspace/sonic-platform-vpp/docs/HLD/vxlan-vnet.md:151-170`).
- The VPP SAI backend creates a VXLAN tunnel when a tunnel-encap next-hop is created, then creates both VPP VXLAN encap and decap state for each VR-to-VNI tunnel map entry (`~/workspace/sonic-sairedis/vslib/vpp/TunnelManager.cpp:57-91`, `~/workspace/sonic-sairedis/vslib/vpp/TunnelManager.cpp:131-213`).
- VXLAN encap creates the VPP VXLAN tunnel and a dummy neighbor with the VXLAN router MAC, using `no_fib_entry` to avoid disturbing underlay forwarding (`~/workspace/sonic-sairedis/vslib/vpp/TunnelManager.cpp:244-280`).
- VXLAN decap creates a dynamic bridge domain, BVI, VRF binding, BVI IPs, and attaches the VXLAN tunnel interface to that bridge domain (`~/workspace/sonic-sairedis/vslib/vpp/TunnelManager.cpp:319-400`).
- VPP route programming handles next-hop groups by setting `is_multipath` when there is more than one member (`~/workspace/sonic-sairedis/vslib/vpp/SwitchVppRoute.cpp:187-207`), and the backend advertises unordered ECMP only (`~/workspace/sonic-sairedis/vslib/vpp/SwitchVpp.cpp:2169-2173`).
- The VPP backend creates default ECMP and LAG hash objects with IP protocol, source/destination IP, and L4 source/destination ports (`~/workspace/sonic-sairedis/vslib/vpp/SwitchVpp.cpp:2038-2075`).
- The code contains an explicit comment about "possible issues with vxlan and lag" in bridge port list refresh (`~/workspace/sonic-sairedis/vslib/vpp/SwitchVpp.cpp:468-475`).
- IP-in-IP support is documented as planned/required in `~/workspace/sonic-platform-vpp/docs/HLD/vpp-ipiptunnel.md`, where decap is triggered by `SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY` (`~/workspace/sonic-platform-vpp/docs/HLD/vpp-ipiptunnel.md:38-47`, `~/workspace/sonic-platform-vpp/docs/HLD/vpp-ipiptunnel.md:125-143`). In the checked VPP SAI backend, `vslib/vpp` has no IP-in-IP tunnel handler; search only finds the object relationship in `SaiObjectDB.cpp`.
- `~/workspace/sonic-platform-vpp/TODO.md` still lists tunnel map, tunnel, tunnel term table entry, tunnel map entry, and BFD session as Phase-2 SAI APIs (`~/workspace/sonic-platform-vpp/TODO.md:55-72`). Some VXLAN and BFD code exists in `sonic-sairedis`, so the TODO may be stale, but it is still a warning that these areas were not part of the original basic validation scope.
- The platform VM VXLAN validation is basic ping coverage with one VNET route per VM. It does not cover multi-tunnel decap, IP-in-IP decap, VXLAN overlay ECMP, underlay ECMP distribution, or TSA/BFD (`~/workspace/sonic-platform-vpp/tests/sonic-vpp-vm-vxlan-bring-up.yaml:247-408`).

## Per-failure analysis

### 1. `vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash`

**Observed failure**

The PTF VXLAN script sent traffic to destination `150.0.3.1` and received zero VXLAN packets:

```text
Sending 1000 packets from port 25 to 150.0.3.1
Vxlan packets received:0
RuntimeError: Didnot get any reply for this destination:150.0.3.1 Its active endpoints:['100.0.1.10']
```

The pytest module summary shows `16 passed, 1 failed`, and the module stopped at:

```text
FAILED vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash::test_vxlan_random_hash[v4_in_v4]
```

**What the test expected**

The test adds a new route with three tunnel endpoints, then calls the shared PTF traffic checker for the whole `dest_to_nh_map` (`tests/vxlan/test_vxlan_ecmp.py:1454-1503`). The failure destination, `150.0.3.1`, is not the newly created `tc11_new_dest` shown in the pytest locals (`150.0.36.1`). It is one of the pre-existing setup routes. That means the failure is not only "3-way random-hash ECMP failed"; it is also "an existing single active VNET endpoint stopped forwarding by the time the random-hash test ran."

**Likely cause**

This looks like a VPP VXLAN tunnel route lifecycle or underlay route state issue exposed after the preceding VXLAN ECMP route modification tests. The baseline VNET route to endpoint `100.0.1.10` was still considered active by the PTF input, but VPP did not emit any VXLAN packet for it.

The VPP backend does support tunnel-encap next-hops and route programming through VPP VXLAN tunnels, but this area has complex interactions between tunnel next-hop creation, dummy neighbors, VNET routes, BFD endpoint health, and underlay ECMP. There is no platform validation that covers repeated VNET route churn followed by a full random-hash sweep across all configured destinations.

**Recommended follow-up**

Create a reduced VPP repro that runs the first 16 passing test operations, then sends one packet to `150.0.3.1` and captures:

- `show vxlan tunnel`
- `show vnet route all`
- `show ip route 100.0.1.10`
- VPP FIB and VXLAN tunnel state
- ASIC DB route, next-hop, and next-hop-group objects for `150.0.3.1`

This should determine whether the stale state is in SONiC orchestration, SAI object translation, or VPP dataplane programming.

### 2. `vxlan/test_vxlan_ecmp.py::Test_VxLAN_entropy`

**Observed failure**

This did not independently fail. The summary entry says:

```text
Test terminated before this test due to the error in vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash
```

The `69fbca2e39aa410dfe77faed` run used `--maxfail=1`, and pytest stopped after `Test_VxLAN_ecmp_random_hash`.

**What the test expected**

The entropy class creates additional endpoints and varies L4 source port, L4 destination port, and source IP fields, then expects VXLAN encapsulation and endpoint distribution to remain within tolerance (`tests/vxlan/test_vxlan_ecmp.py:1510-1611`).

**Likely cause**

No separate entropy conclusion can be drawn from this run. It should remain tied to the `random_hash` skip until the baseline VNET route forwarding issue is understood.

### 3. `vxlan/test_vxlan_underlay_ecmp.py::Test_VxLAN_underlay_ecmp`

**Observed failure**

The PTF run did receive VXLAN traffic, but all packets for endpoint `100.0.1.10` were observed on one PTF port:

```text
Vxlan packets received:9977
received = {'100.0.1.10': 9977}
VNET endpoint to port index to count mapping: {'100.0.1.10': {12: 9977}}
RuntimeError: Underlay ECMP distribution among egress interfaces failed for endpoint 100.0.1.10. Interface PortChannel105 received 0 packet(s), expected between 1068.9642857142858 and 1781.6071428571427.
```

**What the test expected**

The test manipulates T2-facing interfaces, sends 10,000 packets to a VNET route, and enables `check_underlay_ecmp=True` (`tests/vxlan/test_vxlan_underlay_ecmp.py:21-99`). The PTF script computes the expected egress interface list from `show ip route <endpoint>` and verifies distribution across those interfaces and within LAG members (`tests/vxlan/test_vxlan_ecmp.py:436-456`, `tests/ptftests/py3/vxlan_traffic.py:352-413`).

**Likely cause**

The VXLAN encap path is functional for this case, but VPP is not spreading VXLAN-underlay traffic across the expected T2 PortChannels. This points to an underlay ECMP or LAG integration gap in VPP, or to a mismatch between SONiC `show ip route`'s expected egress set and the egress set actually programmed in VPP.

Relevant implementation evidence:

- VPP route programming sets `is_multipath` only from next-hop-group member count (`SwitchVppRoute.cpp:187-207`).
- VPP advertises unordered ECMP only (`SwitchVpp.cpp:2169-2173`).
- The backend creates default ECMP and LAG hash objects (`SwitchVpp.cpp:2038-2075`), but the observed dataplane behavior still used one port.
- The code has an explicit "possible issues with vxlan and lag" comment (`SwitchVpp.cpp:468-475`).

**Recommended follow-up**

Before enabling this test, validate VPP underlay ECMP independently from VXLAN:

1. Confirm VPP FIB has all T2 next-hop paths for endpoint `100.0.1.10`.
2. Confirm PortChannel/LAG membership in SONiC maps to the expected VPP interfaces.
3. Confirm VPP hashing uses inner or outer fields as expected for VXLAN-underlay traffic.
4. Add a platform-level VPP test that sends VXLAN-underlay traffic and checks distribution across T2 PortChannels.

### 4. `vxlan/test_vxlan_multiple_tunnels.py`

**Observed failure**

The first parameter set failed:

```text
FAILED vxlan/test_vxlan_multiple_tunnels.py::test_vxlan_multiple_tunnels[route_loopback_v4-outer_loopback_v4-inner_ipv4]
AssertionError: Did not receive expected packet on any of ports [...]
```

The expected packet was a VXLAN packet from `10.1.0.32` to endpoint `100.0.0.10`, VNI `8000`. The dataplane did not return any matching packet.

**What the test expected**

The test configures multiple VXLAN tunnels and VNETs, sends a VXLAN packet to one tunnel source IP, and expects the DUT to decapsulate the packet, route the inner packet by VNET route, then emit a new VXLAN packet using the tunnel associated with the matching VNET route (`tests/vxlan/test_vxlan_multiple_tunnels.py:120-165`, `tests/vxlan/test_vxlan_multiple_tunnels.py:400-443`).

**Likely cause**

The test's decap expectation does not appear to match the current VPP VXLAN decap model. The VPP HLD says VXLAN decap is implemented with a bridge domain and BVI, and the inner DMAC after decapsulation must match the BVI MAC before VPP strips the inner Ethernet header and routes the inner IP packet (`~/workspace/sonic-platform-vpp/docs/HLD/vxlan-vnet.md:151-170`). The failing test sends an inner Ethernet frame created by `simple_udp_packet()` with a default destination MAC, not the VPP BVI/router MAC (`tests/vxlan/test_vxlan_multiple_tunnels.py:281-291`). The expected output mask ignores the returned inner destination MAC, but the input packet still may not be routable through VPP's BVI path.

There is also limited platform validation for multiple VXLAN tunnels. The HLD says multiple tunnels in the same VNET require one bridge domain and BVI per tunnel (`~/workspace/sonic-platform-vpp/docs/HLD/vxlan-vnet.md:169-170`), but the VM validation playbook only checks a simple one-tunnel VNET ping path.

**Recommended follow-up**

Decide the intended VPP behavior:

- If VPP's BVI model is the contract, make the test VPP-aware by using the router/VXLAN MAC as the inner DMAC for packets that should be routed after decap.
- If VPP should match hardware behavior and route VXLAN-decapped packets regardless of arbitrary inner DMAC, update the VPP decap dataplane to support that behavior.

Until one of those is done, keep this test skipped for VPP.

### 5. `vxlan/test_vnet_decap.py`

**Observed failure**

The test sent an IP-in-IP packet to the DUT and expected VXLAN re-encapsulation, but no matching packet was received:

```text
FAILED vxlan/test_vnet_decap.py::test_vnet_decap[inner_ipv4-outer_ipv4]
AssertionError: Did not receive expected packet on any of ports [...]
```

The received packets shown in the failure were unrelated control traffic, not the expected VXLAN packet.

**What the test expected**

The test creates a VXLAN tunnel, a VNET, and one VNET route, then sends an IP-in-IP packet whose outer destination is the DUT loopback and whose inner destination matches the VNET route. It expects the DUT to decapsulate the outer IP header and send a VXLAN packet to the VNET endpoint (`tests/vxlan/test_vnet_decap.py:59-100`, `tests/vxlan/test_vnet_decap.py:130-136`, `tests/vxlan/test_vnet_decap.py:236-262`).

**Likely cause**

This requires IP-in-IP tunnel termination. The checked VPP SAI backend does not implement IP-in-IP tunnel term handling under `vslib/vpp`; it only has the generic SAI object relationship for `SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY` (`~/workspace/sonic-sairedis/vslib/vpp/SaiObjectDB.cpp:30`). The platform HLD for IP-in-IP support says decap should be triggered by `SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY` (`~/workspace/sonic-platform-vpp/docs/HLD/vpp-ipiptunnel.md:38-47`, `~/workspace/sonic-platform-vpp/docs/HLD/vpp-ipiptunnel.md:125-143`), and `TODO.md` still lists tunnel term table entry as Phase-2 work (`~/workspace/sonic-platform-vpp/TODO.md:67-71`).

The observed failure is therefore consistent with a missing VPP IP-in-IP decap dataplane path, not a VXLAN re-encap packet-format issue.

**Recommended follow-up**

Keep this test skipped until the VPP backend implements and validates:

- `SAI_TUNNEL_TYPE_IPINIP`
- `SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY`
- P2MP and P2P IP-in-IP decap into the overlay/VNET FIB
- Re-encap from the overlay route to a VXLAN tunnel endpoint

### 6. `vxlan/test_vxlan_bfd_tsa.py`

**Observed failure**

The test failed during fixture setup:

```text
asic_type = 'vpp'
RuntimeError: Pls update this script for your platform.
```

**What the test expected**

The test expects TSA/TSB to transition system mode, clear or restore VXLAN BFD sessions, and preserve route behavior across config reload (`tests/vxlan/test_vxlan_bfd_tsa.py:478-694`). However, setup rejects VPP before any TSA or BFD behavior is tested (`tests/vxlan/test_vxlan_bfd_tsa.py:108-113`).

**Likely cause**

This is a test gating issue. VPP was not added to the BFD TSA fixture's supported ASIC list. There is some VPP BFD implementation in `SwitchVppBfd.cpp`, and the VPP image installs a TSA script under `/usr/bin/TSA` (`~/workspace/sonic-platform-vpp/docker-sonic-vpp/frr/TSA:1-41`), but that does not prove the VXLAN BFD TSA test flow is supported.

**Recommended follow-up**

Do not simply add `vpp` to the fixture list without validating the full flow. First confirm:

- `show bfd summary` reports VXLAN endpoint BFD sessions as the test expects.
- PTF `bfd_responder` monitor-file updates drive the expected VPP BFD state transitions.
- `/usr/bin/TSA` and `/usr/bin/TSB` update the BGP route maps correctly in the VPP image.
- `is_vnet_route_active()` and route convergence checks work on VPP.

After that, add `vpp` to the fixture gate and set any VPP-specific tolerance or skip conditions that are actually required.

## Cross-cutting conclusions

1. **The basic VXLAN VNET path exists, but the newly enabled tests exercise behavior beyond the platform validation suite.** The platform playbook validates simple VNET VXLAN ping, not repeated route churn, multiple VXLAN tunnel decap and re-encap, underlay ECMP distribution, or IP-in-IP decap.
2. **The ECMP failures are dataplane or route-programming issues, not simple test collection issues.** One ECMP case emitted no VXLAN packet for an active route; the underlay ECMP case emitted VXLAN packets but sent them all through one observed egress port.
3. **`test_vnet_decap.py` should remain disabled until IP-in-IP tunnel termination is implemented.** The test is not purely VXLAN; it depends on IP-in-IP decap followed by VXLAN encap.
4. **`test_vxlan_multiple_tunnels.py` needs an explicit VPP behavior decision.** VPP's documented BVI model requires the inner DMAC to match the BVI/router MAC. The test uses a default inner destination MAC, which can prevent VPP from routing the decapped packet.
5. **`test_vxlan_bfd_tsa.py` is blocked by test support first.** It never reaches dataplane validation because the fixture excludes VPP.

## Suggested tracking items

| Priority | Item | Owner area |
| --- | --- | --- |
| P0 | Add a minimal repro for `random_hash` failure that isolates route churn from random hashing. | `sonic-mgmt` test + VPP SAI debug |
| P0 | Validate VPP FIB and LAG/PortChannel programming for VXLAN-underlay ECMP to T2 neighbors. | `sonic-sairedis/vslib/vpp`, VPP dataplane |
| P1 | Decide whether `test_vxlan_multiple_tunnels.py` should send inner packets with router MAC for VPP or VPP should route arbitrary inner DMAC after VXLAN decap. | `sonic-mgmt` + VPP VXLAN design |
| P1 | Implement or confirm IP-in-IP tunnel term support before enabling `test_vnet_decap.py`. | `sonic-sairedis/vslib/vpp`, `sonic-platform-vpp` |
| P1 | Add VPP support to `test_vxlan_bfd_tsa.py` only after validating BFD monitor and TSA/TSB behavior. | `sonic-mgmt` + VPP image |
| P2 | Extend `sonic-platform-vpp` validation to cover multi-tunnel VXLAN, IP-in-IP decap, VXLAN underlay ECMP, and VXLAN BFD/TSA. | `sonic-platform-vpp` |
