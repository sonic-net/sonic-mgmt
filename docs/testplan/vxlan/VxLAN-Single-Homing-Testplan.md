# SONiC EVPN VXLAN Single Homing Test Plan HLD

## Table of Contents

- [Overview](#overview)
- [Scope](#scope)
- [Introduction](#introduction)
- [Features Under Test](#features-under-test)
- [Abbreviations](#abbreviations)
- [Testbed](#testbed)
- [Experimental Setup Configuration](#experimental-setup-configuration)
- [Automation Mapping](#automation-mapping)
- [Test Cases](#test-cases)
  - [TestVxlanBasic — Control Plane and Traffic](#testvxlanbasic--control-plane-and-traffic)
  - [TestVxlanBasicTriggers — Interface and Control-Plane Resilience](#testvxlanbasictriggers--interface-and-control-plane-resilience)
  - [TestVxlanSagTriggers — SAG and VLAN Configuration Resilience](#testvxlansagtriggers--sag-and-vlan-configuration-resilience)
  - [TestVxlanReloadTriggers — Persistence and Reboot](#testvxlanreloadtriggers--persistence-and-reboot)

## Overview

This high-level design (HLD) document describes functional and resilience testing of **EVPN VXLAN single-homed** deployments on SONiC leaf switches. The suite validates:

- BGP EVPN overlay control-plane state (remote VTEPs, VLAN/VRF VNI mappings)
- L2/L3 IPv4 and IPv6 inter-leaf traffic forwarding
- Broadcast, unknown unicast, and multicast (BUM) replication
- Static Anycast Gateway (SAG) configuration resilience
- Recovery after interface flaps, BGP/FDB clears, VLAN changes, config reload, and reboot

The test plan is aligned with the Spytest automation module `spytest/tests/vxlan/test_vxlan.py` and the input YAML files under the same directory. The automation module and its supporting templates are not yet part of this repository; they will be contributed in a follow-up pull request.

## Scope

The scope of this test plan includes:

- Single-homed EVPN VXLAN on leaf switches (no EVPN multihoming / ESI)
- L2 VNI and L3 VNI with per-VLAN SVI and static-anycast-gateway (SAG)
- eBGP unnumbered underlay between spine and leaf switches
- eBGP EVPN overlay between leaf loopback VTEPs
- Remote VTEP discovery based on shared VLAN overlap between leaves
- Ixia or Spirent traffic generator for host simulation (two TGen ports per leaf)

## Introduction

EVPN VXLAN provides L2 and L3 network virtualization over an IP underlay. In the single-homing model validated here, each leaf acts as an independent VTEP. Hosts attach to leaf access ports; inter-leaf forwarding uses EVPN Type-2 (MAC/IP), Type-3 (IMET), and Type-5 (IP prefix) routes learned over BGP EVPN.

## Features Under Test

| Feature | Description |
| ------- | ----------- |
| VXLAN NVO | `VXLAN` tunnel interface with source VTEP on leaf loopback |
| L2 VNI | VLAN-to-VNI mapping and EVPN Type-2/Type-3 propagation |
| L3 VNI | VRF-to-VNI mapping and EVPN Type-5 propagation |
| BGP underlay | eBGP unnumbered on spine–leaf uplinks (`TRANSIT` peer-group) |
| BGP overlay | eBGP EVPN between leaf loopbacks (`OVERLAY` peer-group) |
| SAG | Static anycast gateway MAC and per-VLAN SVI IPv4/IPv6 |
| Remote VTEP | EVPN-derived remote VTEP list per leaf (`show vxlan remotevtep`) |
| BUM handling | Broadcast, unknown unicast, and multicast replication to remote leaves |

## Abbreviations

| Term | Meaning |
| ---- | ------- |
| BUM | Broadcast, Unknown unicast, Multicast |
| EVPN | Ethernet VPN |
| L2 VNI | Layer-2 Virtual Network Identifier |
| L3 VNI | Layer-3 Virtual Network Identifier |
| NVO | Network Virtualization Overlay |
| SAG | Static Anycast Gateway |
| SVI | Switched Virtual Interface |
| VNI | Virtual Network Identifier |
| VRF | Virtual Routing and Forwarding |
| VTEP | VXLAN Tunnel End Point |

## Testbed

These test cases run on Spytest testbeds with DUTs named `leaf0`, `leaf1`, … and `spine0`, `spine1`, … as required by the selected topology. Each leaf connects to **two TGen ports** for host traffic generation.

### Supported Topologies

| `topo` env | DUTs | Devices |
| ---------- | ---- | ------- |
| `4s4l` (default) | 8 | spine0–3, leaf0–3 |
| `2s2l` | 4 | spine0–1, leaf0–1 |
| `2l` | 2 | leaf0, leaf1 |

Set VTEP IP version with environment variable **`vtep`** (`v4` or `v6`).

#### 2-Leaf (`2l`)

```
  TGen ─── leaf0 ───────── leaf1 ─── TGen
         (T1D5Px)              (T1D6Px)
```

#### 2-Spine 2-Leaf (`2s2l`)

```
                    ┌── leaf0 ─── TGen (T1D5Px)
           spine0 ──┤
                    └── leaf1 ─── TGen (T1D6Px)
           spine1 ──┘
```

#### 4-Spine 4-Leaf (`4s4l`)

```
  spine0 ──┬── leaf0 ─── TGen (T1D5Px)
  spine1 ──┼── leaf1 ─── TGen (T1D6Px)   ← VLANs 2–5 only
  spine2 ──┼── leaf2 ─── TGen (T1D7Px)   ← VLANs 6–9 only
  spine3 ──┴── leaf3 ─── TGen (T1D8Px)
```

Each leaf connects to all spines via eBGP unnumbered uplinks. EVPN overlay runs on leaves only.

### Testbed Prerequisites

| Requirement | Details |
| ----------- | ------- |
| Traffic generator | Ixia or Spirent via Spytest TGen APIs |
| DUT software | SONiC with EVPN VXLAN, BGP, and SAG support |
| Templates | `show_vxlan_remotevtep.tmpl`, `show_vxlan_vlanvnimap.tmpl`, `show_vxlan_vrfvnimap.tmpl` under `spytest/templates/` |
| Helper on DUT | `spytest-helper.py` under `/etc/spytest/remote/` |

## Experimental Setup Configuration

### Addressing Plan

#### Loopback / VTEP

| Role | IPv4 | IPv6 |
| ---- | ---- | ---- |
| spine0 … spine3 | 100.0.0.1 – 100.0.0.4 | 1000:1::1 – 1000:1::4 |
| leaf0 … leaf3 (VTEP) | 200.0.0.1 – 200.0.0.4 | 2000:1::1 – 2000:1::4 |

#### BGP

| Role | AS numbers | Router-ID |
| ---- | ---------- | --------- |
| Spines | 65100, 65101, … | 10.200.200.100+ |
| Leaves | 65200, 65201, … | 10.200.200.200+ |

- **Underlay:** eBGP unnumbered (`TRANSIT` peer-group)
- **Overlay:** eBGP EVPN between leaf loopbacks (`OVERLAY` peer-group, `update-source Loopback0`)

#### VNI Mapping

**Formula:** `VNI = VLAN_ID + 5000`

| Type | VLAN range (default) | VNI range |
| ---- | -------------------- | --------- |
| L2 VNI | 2–9 | 5002–5009 |
| L3 VNI | 101–104 | 5101–5104 |

#### L3 VRF Bindings (auto-generated)

| VRF | Bound L2 VLANs |
| --- | -------------- |
| Vrf101 | 2, 3 |
| Vrf102 | 4, 5 |
| Vrf103 | 6, 7 |
| Vrf104 | 8, 9 |

#### 4S4L Per-Leaf VLAN Allocation

| Leaf | L2 VLANs | L3 VRF VLANs |
| ---- | -------- | ------------ |
| leaf0, leaf3 | 2–9 (8) | 101–104 (4) |
| leaf1 | 2–5 (4) | 101–102 (2) |
| leaf2 | 6–9 (4) | 103–104 (2) |

Remote VTEPs are derived from **shared VLAN IDs** between leaves. For example, leaf1 and leaf2 do not expect each other as remote VTEPs because they share no L2 VLANs.

#### SVI and Host Addressing

| Purpose | IPv4 | IPv6 |
| ------- | ---- | ---- |
| L2 SVI gateway | `80.{vlan}.0.1/24` | `8000:{vlan}::1/64` |
| Host IP | `80.{vlan}.0.{host_id}` | Derived from SVI subnet |

### Module Setup Flow

Before any test case executes, the automation performs:

1. Select input YAML based on `topo` environment variable
2. Deploy `spytest-helper.py` to all DUTs
3. Configure SONiC underlay (loopback, unnumbered, BGP underlay)
4. Configure BGP EVPN overlay on leaves
5. Configure L2/L3 VNI, SAG MAC, SAG IPv4/IPv6, and BGP L3 VNI
6. Create TGen device groups and L2/L3/BUM traffic streams

Each test function runs a pre-check: remote VTEPs must be `oper_up` on all leaves; otherwise the test is skipped.

## Automation Mapping

| Test plan ID | Spytest class | Spytest function |
| :----------: | ------------- | ---------------- |
| TC-01 | TestVxlanBasic | `test_vtep_state` |
| TC-02 | TestVxlanBasic | `test_vlanvnimap_state` |
| TC-03 | TestVxlanBasic | `test_vrfvnimap_state` |
| TC-04 | TestVxlanBasic | `test_all_traffic` |
| TC-05 | TestVxlanBasic | `test_bum_traffic` |
| TC-06 | TestVxlanBasicTriggers | `test_upstream_int_flap` |
| TC-07 | TestVxlanBasicTriggers | `test_host_int_flap` |
| TC-08 | TestVxlanBasicTriggers | `test_bgp_clear` |
| TC-09 | TestVxlanBasicTriggers | `test_clear_fdb` |
| TC-10 | TestVxlanSagTriggers | `test_del_add_new_sag_mac` |
| TC-11 | TestVxlanSagTriggers | `test_del_add_sag_configs` |
| TC-12 | TestVxlanSagTriggers | `test_del_add_sag_svi_ip` |
| TC-13 | TestVxlanSagTriggers | `test_del_local_mac` |
| TC-14 | TestVxlanSagTriggers | `test_remove_add_vlan_member` |
| TC-15 | TestVxlanSagTriggers | `test_remove_add_vlan` |
| TC-16 | TestVxlanSagTriggers | `test_del_add_vlan_vni` |
| TC-17 | TestVxlanReloadTriggers | `test_config_reload` |
| TC-18 | TestVxlanReloadTriggers | `test_reboot` |

## Test Cases

### TestVxlanBasic — Control Plane and Traffic

The following test cases verify baseline EVPN VXLAN overlay state and data-plane forwarding after module configuration.

---

#### Test Case # 1 (TC-01): Verify remote VTEP state on all leaves

**Objective:** Confirm that all expected remote VTEPs are discovered via EVPN and are in `oper_up` state on every leaf.

- Test steps

  1. On each leaf, execute `show vxlan remotevtep`.
  2. Parse output and compare against expected remote VTEP list derived from shared VLAN overlap and loopback addressing.
  3. Verify each entry has `tun_src = EVPN` and `tun_status = oper_up`.
  4. Verify local VTEP (`src_vtep`) matches the leaf loopback address.

- Pass/Fail Criteria

  - Test passes if all expected remote VTEPs are present and `oper_up` on every leaf.
  - Test fails if any expected remote VTEP is missing, unexpected VTEPs appear, or tunnel status is not `oper_up`.

**Automation:** `TestVxlanBasic::test_vtep_state`

---

#### Test Case # 2 (TC-02): Verify VLAN-to-VNI mappings on all leaves

**Objective:** Confirm L2 VLAN-to-VNI mappings match the topology YAML configuration.

- Test steps

  1. On each leaf, execute `show vxlan vlanvnimap`.
  2. Compare parsed VLAN/VNI pairs against expected mappings from input YAML (`VNI = VLAN + 5000`).

- Pass/Fail Criteria

  - Test passes if all expected VLAN/VNI pairs are present on every leaf with no missing or extra mappings.
  - Test fails if mapping count or values do not match expected data.

**Automation:** `TestVxlanBasic::test_vlanvnimap_state`

---

#### Test Case # 3 (TC-03): Verify VRF-to-VNI mappings on all leaves

**Objective:** Confirm L3 VRF-to-VNI mappings match the topology YAML configuration.

- Test steps

  1. On each leaf, execute `show vxlan vrfvnimap`.
  2. Compare parsed VRF/VNI pairs against expected mappings from input YAML.

- Pass/Fail Criteria

  - Test passes if all expected VRF/VNI pairs are present on every leaf.
  - Test fails if mapping count or values do not match expected data.

**Automation:** `TestVxlanBasic::test_vrfvnimap_state`

---

#### Test Case # 4 (TC-04): Verify L2 and L3 IPv4/IPv6 inter-leaf traffic

**Objective:** Confirm end-to-end L2 and L3 forwarding between hosts on different leaves for both IPv4 and IPv6.

- Test steps

  1. Start TGen protocols.
  2. Enable L2 IPv4, L3 IPv4, L2 IPv6, and L3 IPv6 traffic streams between TGen device groups on different leaves.
  3. Run each stream and collect TX/RX statistics.
  4. Verify the received packet count matches the transmitted packet count for each stream, within the loss tolerance configured in the automation.

- Pass/Fail Criteria

  - Test passes if all four traffic types (L2 v4, L3 v4, L2 v6, L3 v6) forward successfully between leaves.
  - Test fails if any stream shows packet loss beyond the configured tolerance.

**Automation:** `TestVxlanBasic::test_all_traffic`

---

#### Test Case # 5 (TC-05): Verify BUM traffic replication

**Objective:** Confirm broadcast, unknown unicast, and multicast frames are replicated to all expected remote TGen ports.

- Test steps

  1. From a reference leaf TGen port, inject BUM traffic (broadcast, unknown unicast, multicast MAC) on one VLAN per VRF.
  2. Stop/start TGen protocols and run BUM streams in single-burst mode.
  3. Verify RX packet count on remote ports equals `expected_endpoints × TX packets`, where the expected endpoint count is derived from VLAN membership across the leaves.

- Pass/Fail Criteria

  - Test passes if all BUM stream types replicate to the expected number of remote ports.
  - Test fails if replication count does not match expected endpoint count for any BUM type.

**Automation:** `TestVxlanBasic::test_bum_traffic`

---

### TestVxlanBasicTriggers — Interface and Control-Plane Resilience

The following test cases verify that L2/L3 traffic recovers after common operational triggers.

---

#### Test Case # 6 (TC-06): Verify traffic after underlay uplink flap

**Objective:** Confirm VXLAN overlay and traffic recover after shutting and unshutting all spine-facing uplinks on every leaf.

- Test steps

  1. Verify baseline traffic passes.
  2. Shut down all underlay uplink interfaces on all leaf switches.
  3. Wait for the interfaces to go down.
  4. No-shut all underlay uplink interfaces on all leaf switches.
  5. Wait for reconvergence.
  6. Re-run L2/L3 IPv4 and IPv6 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after uplink flap.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanBasicTriggers::test_upstream_int_flap`

---

#### Test Case # 7 (TC-07): Verify traffic after host port flap

**Objective:** Confirm traffic recovers after shutting and unshutting all host-facing (L2 VNI) ports on every leaf.

- Test steps

  1. Verify baseline traffic passes.
  2. Shut down all host-facing ports on all leaf switches.
  3. Wait for the ports to go down.
  4. No-shut all host-facing ports on all leaf switches.
  5. Wait for reconvergence.
  6. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after host port flap.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanBasicTriggers::test_host_int_flap`

---

#### Test Case # 8 (TC-08): Verify traffic after BGP clear on all leaves

**Objective:** Confirm traffic recovers after clearing all BGP sessions on every leaf.

- Test steps

  1. Verify baseline traffic passes.
  2. On each leaf, execute `clear bgp *` in vtysh.
  3. Wait for BGP and EVPN reconvergence.
  4. Clear counters on all leaves.
  5. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after BGP clear.
  - Test fails if any traffic stream does not recover or BGP sessions do not re-establish.

**Automation:** `TestVxlanBasicTriggers::test_bgp_clear`

---

#### Test Case # 9 (TC-09): Verify traffic after FDB clear on all leaves

**Objective:** Confirm traffic recovers after clearing the MAC/FDB table on every leaf.

- Test steps

  1. Verify baseline traffic passes.
  2. Clear the MAC/FDB table on each leaf switch (`sonic-clear fdb all`).
  3. Re-run L2/L3 traffic verification (MACs are re-learned via EVPN and local learning).

- Pass/Fail Criteria

  - Test passes if FDB clear succeeds on all leaves and all L2/L3 traffic streams recover.
  - Test fails if FDB clear fails or traffic does not recover.

**Automation:** `TestVxlanBasicTriggers::test_clear_fdb`

---

### TestVxlanSagTriggers — SAG and VLAN Configuration Resilience

The following test cases verify overlay stability when SAG, SVI, VLAN membership, or VNI mappings are changed.

---

#### Test Case # 10 (TC-10): Verify traffic after SAG MAC change

**Objective:** Confirm L2/L3 traffic continues after deleting and adding a new static-anycast-gateway MAC on all leaves.

- Test steps

  1. Verify baseline traffic passes.
  2. On each leaf, delete the current SAG MAC and add a new MAC (`00:55:44:33:22:11`).
  3. Wait for the new SAG MAC to take effect.
  4. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams pass after SAG MAC change.
  - Test fails if any traffic stream fails.

**Automation:** `TestVxlanSagTriggers::test_del_add_new_sag_mac`

---

#### Test Case # 11 (TC-11): Verify traffic after SAG config remove and re-apply

**Objective:** Confirm traffic recovers after fully removing and re-applying SAG IPv4, IPv6, and MAC configuration on all leaves.

- Test steps

  1. Verify baseline traffic passes.
  2. Remove SAG IPv4, SAG IPv6, and SAG MAC configuration on all leaves.
  3. Wait for the configuration removal to take effect.
  4. Re-apply SAG MAC, SAG IPv4, and SAG IPv6 configuration on all leaves.
  5. Wait for reconvergence.
  6. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after SAG config remove/re-apply.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanSagTriggers::test_del_add_sag_configs`

---

#### Test Case # 12 (TC-12): Verify traffic after SVI IP remove and re-add

**Objective:** Confirm traffic recovers after removing and re-adding SVI IPv4 and IPv6 addresses on all leaves.

- Test steps

  1. Verify baseline traffic passes.
  2. Remove SVI IPv4 and IPv6 addresses from all VLAN SVIs on all leaves.
  3. Wait for the address removal to take effect.
  4. Re-add SVI IPv4 and IPv6 addresses on all leaves.
  5. Wait for reconvergence.
  6. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after SVI IP remove/re-add.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanSagTriggers::test_del_add_sag_svi_ip`

---

#### Test Case # 13 (TC-13): Verify remote MAC removal when local MAC is cleared on leaf0

**Objective:** Confirm remote leaves remove MAC entries that were learned from leaf0 when leaf0's FDB is cleared.

- Test steps

  1. Capture dynamic MAC addresses learned on leaf0.
  2. Clear FDB on leaf0 (`sonic-clear fdb all`).
  3. On all other leaves, execute `show vxlan remotemac all`.
  4. Verify previously captured MACs from leaf0 are no longer present in remote MAC tables.

- Pass/Fail Criteria

  - Test passes if none of the reference MACs from leaf0 remain in remote VTEP MAC tables after leaf0 FDB clear.
  - Test fails if any reference MAC is still present on a remote leaf.

**Automation:** `TestVxlanSagTriggers::test_del_local_mac`

---

#### Test Case # 14 (TC-14): Verify traffic after VLAN member remove and re-add

**Objective:** Confirm L2/L3 and BUM traffic recover after removing and re-adding VLAN members on host ports.

- Test steps

  1. Verify baseline traffic passes.
  2. Select reference VLAN (leaf0 `vlan_start_range`) present on all applicable leaves.
  3. Remove VLAN members from host ports on selected leaves.
  4. Wait for the VLAN member removal to take effect.
  5. Re-add VLAN members on host ports.
  6. Re-run L2/L3 and BUM traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 and BUM traffic streams recover after VLAN member flap.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanSagTriggers::test_remove_add_vlan_member`

---

#### Test Case # 15 (TC-15): Verify traffic after full VLAN delete and re-create with SAG

**Objective:** Confirm L2/L3 and BUM traffic recover after fully deleting and re-creating a VLAN including VXLAN mapping, VRF binding, and SAG.

- Test steps

  1. Verify baseline traffic passes.
  2. Select reference VLAN on leaves where it exists.
  3. Delete VLAN members, VXLAN mapping, VRF binding, and VLAN on selected leaves.
  4. Wait for the VLAN deletion to take effect.
  5. Re-create VLAN, members, VXLAN mapping, VRF binding, SVI IPs, and enable SAG on selected leaves.
  6. Re-run L2/L3 and BUM traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 and BUM traffic streams recover after VLAN delete/re-create.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanSagTriggers::test_remove_add_vlan`

---

#### Test Case # 16 (TC-16): Verify traffic after VLAN-to-VNI mapping flap

**Objective:** Confirm L2/L3 traffic recovers after deleting and re-adding all VLAN-to-VNI VXLAN mappings on all leaves.

- Test steps

  1. Verify baseline traffic passes.
  2. Delete all VLAN-to-VNI mappings on all leaves.
  3. Wait for the mapping removal to take effect.
  4. Re-add all VLAN-to-VNI mappings on all leaves.
  5. Wait for reconvergence.
  6. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if all L2/L3 traffic streams recover after VNI mapping flap.
  - Test fails if any traffic stream does not recover.

**Automation:** `TestVxlanSagTriggers::test_del_add_vlan_vni`

---

### TestVxlanReloadTriggers — Persistence and Reboot

The following test cases verify overlay persistence after configuration reload and system reboot.

---

#### Test Case # 17 (TC-17): Verify VTEPs and traffic after config reload

**Objective:** Confirm remote VTEPs and L2/L3 traffic are restored after `config reload` on a leaf switch.

- Test steps

  1. Verify baseline traffic passes.
  2. Select leaf0 (first leaf in topology).
  3. Save SONiC and FRR configuration on selected leaf.
  4. Record docker count on selected leaf.
  5. Execute `config reload` on selected leaf.
  6. Verify all docker containers recover.
  7. Wait for overlay convergence.
  8. Verify remote VTEPs are `oper_up` on all leaves.
  9. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if config reload succeeds, all dockers recover, remote VTEPs are restored, and all L2/L3 traffic passes.
  - Test fails if reload fails, dockers do not recover, VTEPs are missing, or traffic fails.

**Automation:** `TestVxlanReloadTriggers::test_config_reload`

---

#### Test Case # 18 (TC-18): Verify VTEPs and traffic after save and reboot

**Objective:** Confirm remote VTEPs and L2/L3 traffic are restored after save and reboot of a leaf switch.

- Test steps

  1. Verify baseline traffic passes.
  2. Select leaf0 (first leaf in topology).
  3. Save FRR configuration and reboot selected leaf (`config save` + reboot).
  4. Verify all docker containers recover.
  5. Wait for full system and overlay convergence.
  6. Verify remote VTEPs are `oper_up` on all leaves.
  7. Re-run L2/L3 traffic verification.

- Pass/Fail Criteria

  - Test passes if reboot succeeds, all dockers recover, remote VTEPs are restored, and all L2/L3 traffic passes.
  - Test fails if reboot fails, dockers do not recover, VTEPs are missing, or traffic fails.

**Automation:** `TestVxlanReloadTriggers::test_reboot`

---

## How to Run (Spytest)

```bash
cd spytest
export topo=2s2l    # or 2l, 4s4l
export vtep=v6      # or v4

./bin/spytest --testbed <testbed.yaml> \
    tests/vxlan/test_vxlan.py \
    --logs-path /tmp/vxlan-logs
```

## Verification Commands

Useful CLI commands during debug:

```bash
show vxlan remotevtep
show vxlan vlanvnimap
show vxlan vrfvnimap
show vxlan remotemac all
show vxlan tunnel
show vxlan interface
vtysh -c "show bgp summary"
vtysh -c "show bgp l2vpn evpn summary"
```
