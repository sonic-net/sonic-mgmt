# Scale-Up ESUN Test Plan for sonic-mgmt

## Revision

| Rev | Date       | Author                              | Org       | Change Description |
|-----|------------|-------------------------------------|-----------|-------------------|
| 0.1 | 2026-09-10 | Arvindsrinivasan Lakshmi Narasimhan | UpscaleAI | Initial proposal  |

## Table of Contents

- [Scope](#scope)
- [Definitions and Abbreviations](#definitions-and-abbreviations)
- [Background](#background)
  - [Why a new test suite for Scale-Up?](#why-a-new-test-suite-for-scale-up)
  - [Alibaba Ranking Test Framework](#alibaba-ranking-test-framework)
- [Device Role](#device-role)
- [Testbed Topology](#testbed-topology)
  - [PTF Topology (functional tests)](#ptf-topology-functional-tests)
  - [How frames travel through the topology](#how-frames-travel-through-the-topology)
  - [Why the standard fanout works for ESUN](#why-the-standard-fanout-works-for-esun)
  - [Port mapping on the PTF host](#port-mapping-on-the-ptf-host)
  - [TGEN Topology (line-rate and congestion tests)](#tgen-topology-line-rate-and-congestion-tests)
- [Test Setup](#test-setup)
  - [Control Plane](#control-plane)
  - [Data Plane](#data-plane)
  - [Test Organization](#test-organization)
- [Test Plan](#test-plan)
  - [Summary](#summary)
  - [E1. ESUN Header Processing and Efficiency](#e1-esun-header-processing-and-efficiency)
  - [E2. Static L2 Forwarding](#e2-static-l2-forwarding)
  - [E3. EH-CoS Differentiation](#e3-eh-cos-differentiation)
  - [E4. Flow Label and F-bit](#e4-flow-label-and-f-bit)
  - [E5. TTL and Loop Prevention](#e5-ttl-and-loop-prevention)
  - [E6. ECN Fabric Feedback](#e6-ecn-fabric-feedback)
- [References](#references)

## Scope

This document describes the test plan for adding SAI-level functional and scale tests for Ethernet for Scale-Up Networking (ESUN) devices in the sonic-mgmt test framework. Scale-Up switches are a new class of device used in AI/ML clusters where the network fabric sits inside the compute domain rather than the traditional data center spine-leaf topology. These devices have unique forwarding behavior — they rely on ESUN (Ethernet Header) encapsulation instead of standard Ethernet L3 routing, and they need their own test coverage.

The tests proposed here follow the Ranking Test design from [sonic-net/SONiC PR #2351](https://github.com/sonic-net/SONiC/pull/2351). They use the SAI Thrift API so the ASIC can be validated with or without SONiC running on the device. 

- **`esun_saitests/`** — Tests covering ESUN-specific features: EH processing, static L2 forwarding, CoS differentiation, flow label hashing, TTL, ECN, PFC/CBFC, LLR, endpoint requirements, hierarchical topology, and error handling.

Test suites live under `sonic-mgmt/tests/ranking/`. A new device role — **`scaleup`** — is introduced in sonic-mgmt to identify ESUN devices and gate which tests apply to them.

## Definitions and Abbreviations

| Term   | Description |
|--------|-------------|
| SAI    | Switch Abstraction Interface — vendor-neutral API for programming switching ASICs |
| ESUN   | Ethernet for Scale-Up Networking — Scale-Up link-layer encapsulation |
| EH     | ESUN Header — the 4-byte header carrying ECN, CoS, Flow Label, TTL, UD, and Rev fields |
| EH-ET  | ESUN EtherType — identifies ESUN frames (value pending assignment by IEEE) |
| PTF    | Packet Test Framework — Python-based framework for crafting and verifying packets |
| DUT    | Device Under Test |
| TGEN   | Traffic Generator (e.g., Keysight IXIA) |
| ECMP   | Equal-Cost Multi-Path routing |
| PFC    | Priority-based Flow Control |
| CBFC   | Credit-Based Flow Control |
| CoS    | Class of Service |
| TC     | Traffic Class |

## Background

### Why a new test suite for Scale-Up?

Traditional SONiC testing assumes devices running in a data center spine-leaf topology with standard Ethernet/IP forwarding. Scale-Up switches are different:

- They sit inside an AI/ML training cluster, connecting GPUs and accelerators over a high-bandwidth, low-latency fabric.
- Forwarding is based on L2 destination addresses with the ESUN Ethernet Header (EH) instead of IP routing.
- Features like EH-CoS traffic differentiation, EH-ECN fabric feedback, Flow Label hashing, EH-TTL loop prevention, and CBFC/LLR lossless transport have no equivalent in traditional SONiC tests.
- The devices need to be validated at the SAI level early in silicon bring-up, before the full SONiC stack is available.

### Alibaba Ranking Test Framework

Alibaba proposed a Ranking Test framework ([PR #2351](https://github.com/sonic-net/SONiC/pull/2351)) that evaluates switching ASICs through SAI directly, without depending on the SONiC control plane. The key ideas:

- **SAI Thrift API** — tests talk to the ASIC through auto-generated Thrift bindings of the SAI headers. This means the DUT can run with or without SONiC.
- **Two data-plane modes:**
  - **PTF** for functional and sanity tests — the test script crafts packets, injects them, and checks what comes out.
  - **IXIA / TGEN** for performance, congestion, and line-rate tests — a hardware traffic generator drives real traffic through the DUT.
- **saiserver** as the control plane — it provides the same call stack as syncd, so the full path from Thrift RPC down to the SDK is exercised.

This test plan builds on that design. We propose contributing the Scale-Up ESUN SAI tests into the sonic-mgmt repo.

## Device Role

We introduce a new sonic-mgmt role: **`scaleup`**.

```
# In the testbed definition (e.g., testbed.yaml)
- role: scaleup
  hwsku: sonic-ScaleUp
  platform: x86_64-sonic_scaleup-r0
```

**What the role controls:**

- Tests under `saitests/` (standard SAI functional areas) run on `scaleup` devices the same way they run on other roles (T0, T1), with minor topology adjustments.
- Tests under `esun_saitests/` (ESUN-specific features) are gated on `role == scaleup` — they only run on devices that support the ESUN Ethernet Header.
- Pytest markers (e.g., `@pytest.mark.scaleup`) will be used to include or skip tests based on the DUT's role.

**Why a separate role instead of a platform flag:**

Scale-Up devices differ from leaf/spine/T0/T1 devices not just in hardware but in forwarding model. A role captures this cleanly — topology files, default configs, and test selection all key off the role, and it avoids overloading existing roles with conditions that do not apply to them.

## Testbed Topology

Every test has two planes: a **control plane** where the test script programs the ASIC via SAI Thrift RPC, and a **data plane** where packets flow through the DUT's ports so the test can verify forwarding behavior.

This test plan is for validating ESUN switches. Since these tests exercise real ASIC behavior through the vendor SAI library, the DUT must be a physical Scale-Up ESUN switch running saiserver.

Per the OCP ESUN Base Specification (Rev 1.0), ESUN frames use **standard Ethernet framing** — 48-bit DMAC, 48-bit SMAC, followed by the ESUN EtherType (EH-ET) and the 4-byte ESUN Header (EH). The IP header is removed for efficiency, but the Ethernet L2 header is unchanged:

```
┌────────┬────────┬──────────┬──────────┬─────────┬─────┐
│ DMAC   │ SMAC   │ EH-ET    │ EH (4B)  │ Payload │ FCS │
│ (6B)   │ (6B)   │ (2B)     │ ECN,CoS, │         │     │
│        │        │          │ F,FlowLbl│         │     │
│        │        │          │ TTL,UD,  │         │     │
│        │        │          │ Rev      │         │     │
└────────┴────────┴──────────┴──────────┴─────────┴─────┘
```

Because ESUN keeps standard Ethernet L2 framing, the testbed uses the **standard sonic-mgmt fanout topology** — a regular Ethernet switch with port-based VLAN trunking. No special infrastructure (OCS, custom TPID, or direct cabling) is needed. The fanout handles ESUN frames the same as any other Ethernet frame — the DMAC and SMAC are real 48-bit addresses, only the EtherType is different.

### PTF Topology (functional tests)
We are defining a new testbed topology for these tests.
The DUT front-panel ports are connected to the fanout switch. The fanout switch is connected to the PTF host, which hosts the test runner and the PTF container to send and receive traffic.
For this purpose a new topology file `topo_scaleup.yml` will be introduced.

```
  ┌──────────────┐
  │  PTF Host    │
  │  (server,    │
  │  test runner │        ┌──────────────┐
  │  + Thrift    │ trunk  │ Fanout       │
  │  client,     ├────────┤ (Ethernet    │
  │  1 NIC)      │        │  switch,     │
  └──────┬───────┘        │  VLAN-per-   │
         │                │  port)       │
         │mgmt            └──────┬───────┘
         │                       │ one cable per DUT port
         │                       │
  ┌──────┴───────────────────────┴───────┐
  │         DUT (scaleup ESUN HW)        │
  │         saiserver running             │
  └──────────────────────────────────────┘
```

**How it works:**

- The **fanout** has one port connected to each DUT port under test, and a trunk link back to the PTF host. Each DUT port is mapped to a VLAN. When PTF sends a packet tagged with VLAN 5, the fanout strips the tag and forwards it out the port cabled to DUT port 5. Packets returning from the DUT are tagged the same way, so PTF knows which port they came from.
- The **PTF host** programs the ASIC via Thrift RPC over the management link, and sends/receives test packets through the fanout.
- The fanout is passive infrastructure — any managed Ethernet switch that supports port-based VLAN trunking works.

### How frames travel through the topology

**PTF → DUT** (test sends an ESUN packet to DUT Ethernet0):

```
PTF: send_packet(self, 1, esun_pkt)
  │
  │  eth1 is VLAN sub-interface eth0.5
  │  Linux kernel adds 802.1Q tag: VLAN 5
  ▼
Fanout: receives on trunk, sees VLAN 5
  │  strips tag, forwards to access port 5
  ▼
DUT Ethernet0: receives the raw ESUN frame (no VLAN tag)
```

**DUT → PTF** (DUT forwards a packet out Ethernet4):

```
DUT Ethernet4: sends ESUN frame out
  │
  ▼
Fanout: receives on access port 6 (VLAN 6)
  │  adds 802.1Q tag: VLAN 6, sends on trunk
  ▼
PTF: Linux kernel strips VLAN 6 tag, delivers to eth0.6 (= eth2)
  │  AF_PACKET raw socket on eth2 receives the frame
  ▼
Test: verify_packet(self, expected_pkt, port_id=2)  ✓
```

### Why the standard fanout works for ESUN

- **ESUN uses real 48-bit DMAC/SMAC.** The fanout parses, learns, and forwards based on them normally — standard L2 bridging.
- **Only the EtherType is non-standard (EH-ET).** The fanout checks bytes 12–13 for 0x8100 (VLAN tag). Since EH-ET is not 0x8100, it treats the frame as untagged and assigns the port-default VLAN. The ESUN EtherType and everything after it passes through untouched.
- **VLAN tag insertion/stripping is symmetric.** The fanout inserts 802.1Q between SMAC and EH-ET on the trunk side; PTF's VLAN sub-interface strips it on receive. The original ESUN frame is preserved byte-for-byte.
- **PTF uses AF_PACKET raw sockets in promiscuous mode**, which receive all frames regardless of EtherType.

### Port mapping on the PTF host

VLAN sub-interfaces are created on the PTF host during testbed setup (via Ansible), mapping each DUT port to a numbered PTF interface:

```
eth0            ← physical trunk NIC to fanout
├── eth0.5      ← VLAN 5
├── eth0.6      ← VLAN 6
├── eth0.7      ← VLAN 7
└── eth0.8      ← VLAN 8

PTF interface mapping:
  eth1 → eth0.5 → fanout VLAN 5 → DUT Ethernet0
  eth2 → eth0.6 → fanout VLAN 6 → DUT Ethernet4
  eth3 → eth0.7 → fanout VLAN 7 → DUT Ethernet8
  eth4 → eth0.8 → fanout VLAN 8 → DUT Ethernet12
```

The test script never deals with VLANs or fanout configuration. It just calls `send_packet(self, port_id, pkt)` and the infrastructure handles the rest. The connection graph CSV files (`sonic_*_links.csv`) define the mapping, and the `conn_graph_facts` Ansible module resolves it at runtime.

### TGEN Topology (line-rate and congestion tests)

Most tests work with PTF alone. A subset require a **hardware traffic generator** (e.g., Keysight IXIA) for line-rate traffic, precise timing, or real congestion:

| Category | TGEN-required tests | Why TGEN is needed |
|----------|--------------------|--------------------|
| Port and Link | Port bandwidth rate verification, port rate traffic tests | Verifying Kbps/Pps shaping at line rate |
| PFC and Lossless | PFC generation under traffic, PFC watchdog, buffer/PG watermarks, PFC duration tests | PFC triggers need real back-pressure from sustained line-rate flows |
| QoS, Buffers, ECN | Watermark accuracy, egress queue scaling factor, ECN threshold tests | Accurate buffer fill requires controlled line-rate injection |
| Mirror / sFlow | sFlow under line-rate traffic | Verifying sFlow sampling does not drop under congestion |
| PFC and CBFC | CBFC credit-based flow control, combined PFC+CBFC | Lossless transport validation at line rate |

These TGEN tests are outside the scope of this test plan and will be introduced in a subsequent test plan. When a TGEN is needed, it replaces the PTF host as the traffic source/sink, connecting to the DUT through the same fanout. The topology is shown here for reference:
```
  ┌──────────────┐
  │  TGEN        │
  │  (Keysight   │        ┌──────────────┐
  │  IXIA /      │ trunk  │ Fanout       │
  │  Snappi)     ├────────┤ (Ethernet    │
  │              │        │  switch,     │
  └──────────────┘        │  VLAN-per-   │
                          │  port)       │
  ┌──────────────┐        └──────┬───────┘
  │  PTF Host    │               │ one cable per DUT port
  │  (Thrift     ├── mgmt ──┐   │
  │  client +    │           │   │
  │  RestPy)     │           │   │
  └──────────────┘           │   │
  ┌──────────────────────────┴───┴───────┐
  │         DUT (scaleup ESUN HW)        │
  │         saiserver running             │
  └──────────────────────────────────────┘
```

- The **TGEN** connects to the fanout trunk and drives line-rate traffic through the same VLAN-per-port mapping.
- The **PTF host** programs the ASIC via Thrift RPC and controls the TGEN via RestPy over the management network. It does not send data-plane traffic in this mode.

## Test Setup

### Control Plane

The DUT runs **saiserver** inside a Docker container. The saiserver binary provides the same SAI call path as syncd, with a Thrift RPC server on top. Test scripts connect to it as a Thrift client.

```python
# Example: initialize the switch via SAI Thrift
from sai_thrift.sai_headers import *

self.switch_id = sai_thrift_create_switch(
    self.client,
    init_switch=True,
    src_mac_address=ROUTER_MAC)
assert self.status() == SAI_STATUS_SUCCESS
```

The saiserver Docker image is built with `SAITHRIFT_V2=y` and integrates into the SONiC build system.

### Data Plane

- **PTF mode:** Test scripts use `ptf.testutils` to send crafted packets into front-panel ports and verify expected packets on egress ports. This covers all functional and most scale tests.
- **IXIA mode:** For line-rate and congestion tests, the IXIA tester is controlled via RestPy from the PTF host. The test script sets up SAI state, then tells IXIA to push traffic and collects stats.

### Test Organization

Tests live under `sonic-mgmt/tests/ranking/`:

```
tests/ranking/
├── conftest.py                        # shared fixtures: sai client, topology, role
│
├── esun_saitests/                      # Scale-Up-specific tests (scaleup role only)
│   ├── conftest.py
│   │
│   │   # ESUN Ethernet Header tests (E1–E6)
│   ├── test_eh_processing.py              # E1: EH header processing and efficiency
│   ├── test_static_l2_fwd.py              # E2: Static L2 forwarding
│   ├── test_eh_cos.py                     # E3: EH-CoS differentiation
│   ├── test_flow_label.py                 # E4: Flow Label and F-bit
│   ├── test_ttl.py                        # E5: TTL and loop prevention
│   ├── test_ecn.py                        # E6: ECN fabric feedback
│
└
```

- **`esun_saitests/`** contains tests specific to ESUN devices. They validate the ESUN Ethernet Header semantics — header processing, static L2 forwarding, CoS differentiation, flow label hashing, TTL, and ECN. All tests are gated on `role == scaleup`.


## Test Plan

### Summary

**Scale-Up ESUN SAI Tests (`esun_saitests/`):**

*ESUN Ethernet Header tests:*

| # | Test Area | Test Count | What Is Validated |
|---|-----------|-----------|-------------------|
| E1 | ESUN Header Processing and Efficiency | 10 | EH identification, 4-byte header, revision, ECN, CoS, Flow Label, TTL, UD and FCS |
| E2 | Static L2 Forwarding | 3 | Static 48-bit DA forwarding, no MAC learning and BUM handling |
| E3 | EH-CoS Differentiation | 4 | Traffic-class mapping and precedence over VLAN PCP and CBFC traffic class |
| E4 | Flow Label and F-bit | 4 | Flow Label hashing, deterministic forwarding, F-bit behavior and entropy |
| E5 | TTL and Loop Prevention | 2 | Per-hop decrement and expiry |
| E6 | ECN Fabric Feedback | 3 | EH-ECN encoding, congestion marking and FCS update |



### E1. ESUN Header Processing and Efficiency

**Goal:** Verify that the ASIC correctly identifies and parses the ESUN Ethernet Header — the 4-byte EH with its revision field, ECN bits, CoS, Flow Label, TTL, UD (User-Defined) field, and that FCS is recomputed correctly after any header modification.

**10 tests** covering:
- EH identification — the ASIC recognizes ESUN frames by EtherType and processes the EH
- 4-byte header parsing — all fields at the correct bit offsets
- Revision field handling — current revision accepted, future revisions handled gracefully
- ECN bits read and preserved through the pipeline
- CoS field extraction for QoS classification
- Flow Label extraction for hashing
- TTL field read for loop prevention
- UD (User-Defined) field pass-through
- FCS recomputation after EH field modification (e.g., TTL decrement, ECN marking)
- End-to-end header integrity — frame enters with known EH values, exits with expected values

---

### E2. Static L2 Forwarding

**Goal:** Verify that ESUN frames are forwarded based on a static 48-bit destination address lookup in the FDB, that there is no dynamic MAC learning, and that BUM (Broadcast, Unknown unicast, Multicast) traffic is handled correctly (dropped or forwarded per policy).

**3 tests** covering:
- Static 48-bit DA forwarding — programmed FDB entry resolves to the correct egress port
- No MAC learning — the switch does not learn source addresses from ESUN frames
- BUM handling — unknown destination, broadcast, and multicast frames are handled per the configured policy (drop or flood)

---

### E3. EH-CoS Differentiation

**Goal:** Verify that the EH-CoS field in the ESUN header is used for traffic-class mapping, and that it takes precedence over VLAN PCP and CBFC traffic class when all are present.

**4 tests** covering:
- EH-CoS to traffic-class mapping — each CoS value maps to the expected TC/queue
- Precedence over VLAN PCP — when both EH-CoS and VLAN PCP are present, EH-CoS wins
- Precedence over CBFC traffic class — EH-CoS takes priority for scheduling decisions
- All CoS values exercised — verify the full range of CoS values maps correctly

---

### E4. Flow Label and F-bit

**Goal:** Verify that the Flow Label field in the ESUN header is used for ECMP/LAG hashing, that it provides deterministic forwarding for flows with the same label, and that the F-bit controls whether the label contributes entropy.

**4 tests** covering:
- Flow Label hashing — packets with different Flow Labels are distributed across ECMP paths
- Deterministic forwarding — packets with the same Flow Label always take the same path
- F-bit behavior — when the F-bit is set, the Flow Label is used for hashing; when cleared, it is ignored
- Entropy — Flow Labels provide sufficient entropy for even load distribution across paths

---

### E5. TTL and Loop Prevention

**Goal:** Verify that the TTL field in the ESUN header is decremented at each hop and that frames with expired TTL are dropped.

**2 tests** covering:
- Per-hop TTL decrement — TTL decreases by 1 at each forwarding hop
- TTL expiry — frame with TTL=0 or TTL=1 is dropped (not forwarded)

---

### E6. ECN Fabric Feedback

**Goal:** Verify that the ECN bits in the ESUN header are used to signal congestion within the fabric — the switch marks frames when congestion is detected, and FCS is updated after ECN modification.

**3 tests** covering:
- EH-ECN encoding — the 2-bit ECN field in the EH is parsed and forwarded correctly
- Congestion marking — when the switch detects congestion (queue depth exceeds threshold), it sets the ECN bits in the EH
- FCS update — after the switch modifies the ECN bits, the FCS is recomputed so the frame is valid on egress

---



## References

1. **OCP ESUN Base Specification** — "OCP ESUN - Network Operator Requirements - Base Specification Rev 1.0", Manoj Wadekar (Meta), Rajesh Sankaran (Microsoft), February 9, 2026. Defines the ESUN Ethernet Header (EH), frame format, EH-ECN, EH-CoS, Flow Label, TTL, and requirements for endpoints and switches.
2. **Alibaba Ranking Test HLD** — "Tier 1 - Ranking Test HLD", Yubin Lee, [sonic-net/SONiC PR #2351](https://github.com/sonic-net/SONiC/pull/2351). Proposes the SAI Thrift-based test framework for vendor-neutral ASIC evaluation using PTF and IXIA.
3. **SAI (Switch Abstraction Interface)** — [https://github.com/opencomputeproject/SAI](https://github.com/opencomputeproject/SAI). The vendor-neutral API used by all tests to program the ASIC.
4. **sonic-mgmt Test Framework** — [https://github.com/sonic-net/sonic-mgmt](https://github.com/sonic-net/sonic-mgmt). The SONiC test infrastructure where these tests will be contributed, including the fanout, connection graph, and PTF framework.
5. **UEC Transport Specification** — Ultra Ethernet Consortium Specification v1.0.2. Referenced by the ESUN spec for CBFC (Credit-Based Flow Control) and LLR (Link-Level Retry) definitions.
6. **IEEE 802.1Q-2018** — IEEE Standard for Local and Metropolitan Area Networks — Bridges and Bridged Networks. Referenced for VLAN tagging and 802.1p CoS definitions.
7. **IEEE 802.3-2022** — IEEE Standard for Ethernet.
