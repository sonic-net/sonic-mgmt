# Scale-Up ESUN Test Plan for sonic-mgmt

## Revision

| Rev | Date       | Author                              | Org       | Change Description |
|-----|------------|-------------------------------------|-----------|-------------------|
| 0.1 | 2026-09-10 | Arvindsrinivasan Lakshmi Narasimhan | UpscaleAI | Initial proposal  |
| 0.2 | 2026-11-13 | Arvindsrinivasan Lakshmi Narasimhan | UpscaleAI | Added per-case tables (ID, preconditions, steps, expected result, pass/fail) for E1–E6 |

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
  - [Test Case Conventions](#test-case-conventions)
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

### Test Case Conventions

Each test area below has a table with one row per test case. The columns are:

- **Case ID** — `ESUN-E<area>-<nn>`. The same ID is used as the pytest test ID in `esun_saitests/`.
- **Preconditions** — state that must exist before step 1, in addition to the common baseline below.
- **Test Steps** — the ordered actions the test performs.
- **Expected Result** — what the DUT must do.
- **Pass/Fail Criterion** — the measurable check that decides the verdict.

The SAI objects and attributes used by each case are intentionally not listed in this revision. The SAI specification for ESUN is still under discussion, so the cases describe configuration in functional terms (for example, "program a static FDB entry"). A "SAI APIs / attributes" column will be added to every table once the SAI ESUN proposal is finalized.

**Common baseline (`BASE`).** Unless a case says otherwise, every test starts from this state and restores it on teardown:

- The switch is initialized through saiserver and all ports under test are operationally up.
- Four DUT ports `P1`–`P4` are used, all in the same L2 forwarding domain. `P1` is the ingress port; `P2`–`P4` are egress ports. Each is reachable from the PTF host as described in [Port mapping on the PTF host](#port-mapping-on-the-ptf-host).
- Four station addresses `MAC_1`–`MAC_4` are defined, with a static FDB entry `MAC_n → Pn` for each.
- ESUN processing is enabled on `P1`–`P4` with the EH-ET value under test. Because EH-ET is pending IEEE assignment, it is a test parameter and is never hard-coded.
- No ECN marking profile, shaper, or non-default CoS map is applied.
- Port, queue, and drop counters on `P1`–`P4` are cleared at the start of each case.

**Default ESUN frame.** Unless a step overrides a field, test frames are built as follows:

| Field | Default value |
|-------|---------------|
| DMAC | `MAC_2` |
| SMAC | `MAC_1` |
| EtherType | EH-ET |
| EH-ECN | `00` (Not-ECT) |
| EH-CoS | 0 |
| F | 0 |
| Flow Label | `0x0000` |
| TTL | 8 |
| UD | `00` |
| Rev | `00` |
| Payload | 64-byte incrementing pattern |

Frames are built with a scapy layer for the EH that will be added to the test library, so every EH field can be set and compared independently.

**Common verification rules.**

- "Forwarded" means the frame is received on the expected PTF port, and on no other PTF port, within the PTF default timeout.
- "Dropped" means the frame is not received on any PTF port and the DUT drop counter for the ingress port increases by the number of frames sent.
- Unless a case says otherwise, a forwarded frame must match the sent frame byte-for-byte except for TTL, which is decremented by one.
- Unless a case says otherwise, each step sends 10 frames, and all 10 must meet the criterion.
- FCS is not visible to PTF because the NIC strips it. FCS correctness is checked indirectly: the fanout discards frames with a bad FCS, so the frame must arrive at PTF, and the FCS/CRC error counters on the DUT egress port and on the fanout port facing it must not increase.

---

### E1. ESUN Header Processing and Efficiency

**Goal:** Verify that the ASIC correctly identifies and parses the ESUN Ethernet Header — the 4-byte EH with its revision field, ECN bits, CoS, Flow Label, TTL, UD (User-Defined) field, and that FCS is recomputed correctly after any header modification.

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E1-01** | EH identification by EtherType | `BASE` | 1. Send the default ESUN frame on `P1`.<br>2. Capture on `P2`–`P4`.<br>3. Send a non-ESUN Ethernet frame (EtherType `0x0800`, IPv4 payload) with the same DMAC/SMAC on `P1`.<br>4. Capture on `P2`–`P4`. | The ESUN frame is recognized by EH-ET, processed as ESUN, and forwarded to `P2` with TTL decremented. The non-ESUN frame is not treated as ESUN: the four bytes after its EtherType are not modified. | Step 2: frame received only on `P2` with TTL = 7 and all other bytes unchanged.<br>Step 4: if the frame is forwarded, it is byte-for-byte identical to the sent frame; no frame is received with bytes 14–17 modified. |
| **ESUN-E1-02** | All EH fields are parsed at the correct bit offsets | `BASE` | 1. For each EH field in turn (ECN, CoS, F, Flow Label, UD), send a frame with that field set to all ones and every other field at its default.<br>2. Repeat with a walking-one pattern across the 16-bit Flow Label.<br>3. Capture on `P2` after each frame. | Each field is carried through unchanged and no neighbouring field is disturbed. Only TTL changes. | For every frame, the received EH equals the sent EH with TTL decremented by one. Any other bit difference in the 4-byte EH is a failure. |
| **ESUN-E1-03** | Revision field handling | `BASE`. The platform declares its behaviour for unsupported revisions (drop or forward unmodified). | 1. Send a frame with Rev = `00`.<br>2. Send frames with Rev = `01`, `10`, and `11`.<br>3. Send a frame with Rev = `00` again.<br>4. Read drop counters on `P1`. | Rev = `00` is accepted and forwarded. Non-zero revisions follow the declared behaviour and do not affect later traffic. | Steps 1 and 3: frame forwarded to `P2` with Rev = `00`.<br>Step 2: every frame follows the declared behaviour — either dropped with the drop counter increased, or forwarded with the Rev field unchanged. Mixed behaviour across the three values is a failure. |
| **ESUN-E1-04** | ECN bits are read and preserved when there is no congestion | `BASE` | 1. Send frames with EH-ECN = `00`, `01`, `10`, and `11`.<br>2. Capture on `P2` after each value. | All four codepoints are forwarded unchanged. | For each codepoint, the received EH-ECN equals the sent EH-ECN. |
| **ESUN-E1-05** | CoS field is extracted and preserved | `BASE` | 1. Send frames with EH-CoS = 0, 3, and 7.<br>2. Capture on `P2` after each value.<br>3. Read the per-queue counters on `P2`. | EH-CoS is carried unchanged on egress and is the field used for classification. | The received EH-CoS equals the sent value for all three, and the frames for the three CoS values are counted on three different egress queues. |
| **ESUN-E1-06** | Flow Label is extracted and preserved | `BASE` | 1. With F = 1, send frames with Flow Label = `0x0000`, `0xFFFF`, `0xAAAA`, `0x5555`, and `0x0001`.<br>2. Repeat with F = 0.<br>3. Capture on `P2` after each frame. | The F bit and the Flow Label are carried unchanged on egress. | For all ten combinations, the received F bit and Flow Label equal the sent values. |
| **ESUN-E1-07** | TTL field is read and updated without disturbing adjacent fields | `BASE` | 1. Send a frame with TTL = 15, UD = `11`, Flow Label = `0xFFFF`.<br>2. Send a frame with TTL = 2, UD = `00`, Flow Label = `0x0000`.<br>3. Capture on `P2` after each frame. | TTL is decremented by exactly one and the 4-bit decrement does not borrow from or carry into neighbouring fields. | Step 1: received TTL = 14, UD = `11`, Flow Label = `0xFFFF`.<br>Step 2: received TTL = 1, UD = `00`, Flow Label = `0x0000`. |
| **ESUN-E1-08** | UD field pass-through | `BASE` | 1. Send frames with UD = `00`, `01`, `10`, and `11`.<br>2. Capture on `P2` after each value. | UD is end-to-end information and is never interpreted or modified by the switch. | For each value, the received UD equals the sent UD, and forwarding port and egress queue are the same for all four values. |
| **ESUN-E1-09** | FCS is recomputed after an EH modification | `BASE` | 1. Record FCS/CRC error counters on DUT `P2` and on the fanout port facing `P2`.<br>2. Send 1000 frames with TTL = 8 on `P1`.<br>3. Capture on `P2`.<br>4. Read the counters again. | The DUT rewrites TTL and transmits each frame with a valid FCS. | All 1000 frames are received on PTF with TTL = 7, and neither error counter has increased. |
| **ESUN-E1-10** | End-to-end header and payload integrity | `BASE` | 1. Build a frame with every EH field non-default: ECN = `10`, CoS = 5, F = 1, Flow Label = `0xBEEF`, TTL = 12, UD = `01`, Rev = `00`.<br>2. Send it at frame sizes 64, 128, 512, 1518, and the port MTU.<br>3. Capture on `P2` after each size. | Frames of every size are forwarded with the EH intact apart from TTL, and the payload is untouched. | For every size, the received frame is byte-for-byte identical to the sent frame except TTL = 11, and the received length equals the sent length. |

---

### E2. Static L2 Forwarding

**Goal:** Verify that ESUN frames are forwarded based on a static 48-bit destination address lookup in the FDB, that there is no dynamic MAC learning, and that BUM (Broadcast, Unknown unicast, Multicast) traffic is handled correctly (dropped or forwarded per policy).

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E2-01** | Static 48-bit DA forwarding | `BASE` | 1. From `P1`, send frames to `MAC_2`, `MAC_3`, and `MAC_4`.<br>2. Capture on `P2`–`P4`.<br>3. Change the FDB entry for `MAC_2` to point to `P3`.<br>4. Send a frame to `MAC_2` and capture.<br>5. Remove the FDB entry for `MAC_2`.<br>6. Send a frame to `MAC_2` and capture.<br>7. Send a frame to a DMAC that differs from `MAC_3` only in the last bit. | Each frame leaves on the port in its FDB entry. An entry update takes effect immediately. A removed entry no longer forwards. The lookup uses all 48 bits. | Step 2: each frame is received only on the port that matches its FDB entry.<br>Step 4: frame received only on `P3`.<br>Steps 6 and 7: frame is not received on any port. |
| **ESUN-E2-02** | No MAC learning or aging on ESUN frames | `BASE`. `MAC_X` is an address with no FDB entry. | 1. From `P1`, send 100 frames with SMAC = `MAC_X` to `MAC_2`.<br>2. Read the FDB.<br>3. From `P3`, send a frame with DMAC = `MAC_X` and capture on all ports.<br>4. From `P3`, send 100 frames with SMAC = `MAC_2` (a station move against the static entry) to `MAC_4`.<br>5. From `P1`, send a frame to `MAC_2` and capture.<br>6. Wait longer than the default FDB aging time, then send a frame from `P1` to `MAC_2` and capture. | The switch does not learn `MAC_X`, does not move the static `MAC_2` entry, and does not age static entries out. | Step 2: the FDB holds exactly the four static entries from `BASE`.<br>Step 3: frame is not received on `P1` or any other port.<br>Steps 5 and 6: frame received only on `P2`. |
| **ESUN-E2-03** | BUM handling | `BASE`. `MAC_X` is an address with no FDB entry. | 1. From `P1`, send an ESUN frame with DMAC = `MAC_X` (unknown unicast).<br>2. From `P1`, send an ESUN frame with DMAC = `ff:ff:ff:ff:ff:ff` (broadcast).<br>3. From `P1`, send an ESUN frame with a multicast DMAC (`01:00:5e:00:00:01`).<br>4. Capture on `P1`–`P4` after each frame and read the drop counter on `P1`.<br>5. Where the platform supports a flood policy for broadcast/multicast, enable it and repeat steps 2–4. | Unknown unicast ESUN frames are never flooded. Broadcast and multicast frames follow the configured policy, which is drop by default. | Step 1: no frame on any port and the drop counter increases by the number sent.<br>Steps 2–3 with the default policy: no frame on any port and the drop counter increases.<br>Step 5: each frame is received exactly once on each of `P2`–`P4` and never on `P1`. |

---

### E3. EH-CoS Differentiation

**Goal:** Verify that the EH-CoS field in the ESUN header is used for traffic-class mapping, and that it takes precedence over VLAN PCP and CBFC traffic class when all are present.

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E3-01** | EH-CoS to traffic-class mapping | `BASE` plus an identity map: EH-CoS `c` → TC `c` → egress queue `c`, for `c` = 0–7. | 1. For each `c` in 0–7, clear the queue counters on `P2`.<br>2. Send 100 frames with EH-CoS = `c` from `P1` to `MAC_2`.<br>3. Read the per-queue counters on `P2`.<br>4. Capture on `P2`. | Frames with EH-CoS `c` are enqueued on queue `c` and the EH-CoS field is not rewritten. | For each `c`: queue `c` on `P2` counts 100 frames, every other queue counts 0, and all 100 frames are received with EH-CoS = `c`. |
| **ESUN-E3-02** | EH-CoS takes precedence over VLAN PCP | `BASE` plus the identity EH-CoS map from E3-01, and a PCP → TC map that is also identity. The DUT accepts 802.1Q-tagged ESUN frames on `P1` and the fanout passes the inner tag transparently. Skipped on platforms that do not support tagged ESUN frames. | 1. Send 100 frames carrying an 802.1Q tag with PCP = 1 followed by an EH with EH-CoS = 6.<br>2. Read the per-queue counters on `P2`.<br>3. Repeat with PCP = 6 and EH-CoS = 1.<br>4. Repeat for every pair where PCP = 7 − EH-CoS. | The traffic class is taken from EH-CoS. PCP is ignored for classification. | For every pair, all 100 frames are counted on the queue mapped from EH-CoS and the queue mapped from PCP counts 0. |
| **ESUN-E3-03** | EH-CoS takes precedence over CBFC traffic class | `BASE` plus the identity EH-CoS map from E3-01, and CBFC enabled on `P1` with a traffic-class assignment that differs from the EH-CoS value used in the test. Skipped on platforms where CBFC cannot be enabled in the PTF topology. | 1. Send 100 frames whose CBFC traffic class is 2 and whose EH-CoS = 5.<br>2. Read the per-queue counters on `P2`.<br>3. Repeat with CBFC traffic class 5 and EH-CoS = 2. | Scheduling and queue selection follow EH-CoS, not the CBFC traffic class. | In both runs, all 100 frames are counted on the queue mapped from EH-CoS and the queue mapped from the CBFC traffic class counts 0. |
| **ESUN-E3-04** | Full CoS range with a non-default map | `BASE` plus a reversed map: EH-CoS `c` → queue `7 − c`. | 1. Send an interleaved stream of 800 frames, 100 for each EH-CoS value 0–7, from `P1` to `MAC_2`.<br>2. Read the per-queue counters on `P2`.<br>3. Change the map back to identity while no traffic is running.<br>4. Repeat steps 1–2. | Every CoS value is classified independently according to the map in force, and a map change takes effect without a switch restart. | Step 2: queue `7 − c` counts exactly 100 frames for each `c`.<br>Step 4: queue `c` counts exactly 100 frames for each `c`.<br>All 800 frames are received on `P2` in both runs. |

---

### E4. Flow Label and F-bit

**Goal:** Verify that the Flow Label field in the ESUN header is used for ECMP/LAG hashing, that it provides deterministic forwarding for flows with the same label, and that the F-bit controls whether the label contributes entropy.

These cases need one ingress port and a multipath group with at least two member ports (four recommended). `MAC_G` is a station address with a static FDB entry that points to the group. `N` is the number of group members.

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E4-01** | Flow Label is used for load-balancing hash | `BASE` plus a group `G` with members `P2`–`P4`, a static FDB entry `MAC_G → G`, and Flow Label included in the hash. | 1. Send 1000 frames from `P1` to `MAC_G` with F = 1, fixed DMAC and SMAC, and Flow Label incrementing from 1 to 1000.<br>2. Count the frames received on each member port. | With DMAC and SMAC fixed, changing the Flow Label alone moves traffic across members. | All 1000 frames are received, each on exactly one member, and every member receives at least one frame. |
| **ESUN-E4-02** | Deterministic forwarding for a given Flow Label | Same as E4-01. | 1. Pick 16 Flow Label values.<br>2. For each value, send 100 frames with F = 1 and record the member port.<br>3. Repeat step 2 three times, interleaving the 16 labels in a different order each time.<br>4. Flap a port that is not in `G` and repeat step 2. | Every frame of a flow takes the same member port, regardless of ordering, repetition, or unrelated port events. | For each of the 16 labels, all frames across all repetitions are received on one and the same member port. |
| **ESUN-E4-03** | F-bit controls use of the Flow Label | Same as E4-01. | 1. Send 1000 frames with F = 0, fixed DMAC and SMAC, and Flow Label incrementing from 1 to 1000.<br>2. Count frames per member.<br>3. Send the same 1000 frames with F = 1.<br>4. Count frames per member. | With F = 0 the Flow Label does not contribute to the hash, so all frames follow one path. With F = 1 the Flow Label contributes and the frames spread. | Step 2: all 1000 frames are received on a single member.<br>Step 4: frames are received on more than one member.<br>The F bit and Flow Label are unchanged on egress in both runs. |
| **ESUN-E4-04** | Flow Label entropy gives even distribution | Same as E4-01. | 1. Send 10,000 frames with F = 1, fixed DMAC and SMAC, and Flow Label drawn at random without repetition from the 16-bit range.<br>2. Count frames per member.<br>3. Repeat with sequential Flow Labels starting at `0x0000`.<br>4. Repeat with Flow Labels that differ only in the upper byte. | Load is spread evenly across the members for random, sequential, and sparse label patterns. | In each run all 10,000 frames are received, and every member receives within ±25% of 10,000 / `N` frames. |

---

### E5. TTL and Loop Prevention

**Goal:** Verify that the TTL field in the ESUN header is decremented at each hop and that frames with expired TTL are dropped.

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E5-01** | Per-hop TTL decrement | `BASE` | 1. For each TTL value `t` from 2 to 15, send a frame from `P1` to `MAC_2`.<br>2. Capture on `P2`.<br>3. Take the frame captured for `t` = 15 and re-inject it unmodified on `P1`; repeat with each captured frame until no frame is received, to emulate successive hops. | TTL is decremented by exactly one on each pass through the switch and no other field changes. | Step 2: for every `t`, the received TTL is `t − 1`.<br>Step 3: the frame is forwarded exactly 14 times, with TTL going from 15 down to 1, and is not forwarded on the 15th injection. |
| **ESUN-E5-02** | TTL expiry | `BASE` | 1. Send 100 frames with TTL = 1 from `P1` to `MAC_2`.<br>2. Send 100 frames with TTL = 0.<br>3. Capture on `P1`–`P4` and read the drop counter on `P1`.<br>4. Send 100 frames with TTL = 2. | Frames whose TTL would reach 0, or is already 0, are discarded and counted. The TTL field never wraps. Valid traffic is unaffected. | Steps 1–3: no frame is received on any port, no frame with TTL = 15 or TTL = 0 is seen on egress, and the drop counter increases by 200.<br>Step 4: all 100 frames are received on `P2` with TTL = 1. |

---

### E6. ECN Fabric Feedback

**Goal:** Verify that the ECN bits in the ESUN header are used to signal congestion within the fabric — the switch marks frames when congestion is detected, and FCS is updated after ECN modification.

Congestion is created in the PTF topology the same way as in the existing sonic-mgmt QoS SAI tests: transmission on the egress port is held, frames are sent to fill the egress queue to a known depth, and transmission is then released so the queued frames can be captured. EH-ECN uses the same codepoints as the IP ECN field: `00` Not-ECT, `01` ECT(1), `10` ECT(0), `11` CE.

| Case ID | Objective | Preconditions | Test Steps | Expected Result | Pass/Fail Criterion |
|:--------|:----------|:--------------|:-----------|:----------------|:--------------------|
| **ESUN-E6-01** | EH-ECN encoding with marking enabled and no congestion | `BASE` plus the identity EH-CoS map from E3-01, and an ECN marking profile attached to every egress queue of `P2`. | 1. For each EH-CoS value 0–7 and each EH-ECN codepoint, send 10 frames from `P1` to `MAC_2` with transmission on `P2` running normally.<br>2. Capture on `P2`. | With the queue empty, no frame is marked. All four codepoints are forwarded unchanged on every queue. | For all 32 combinations, the received EH-ECN equals the sent EH-ECN. |
| **ESUN-E6-02** | Congestion marking | `BASE` plus an ECN marking profile on the `P2` queue used by EH-CoS 3, with minimum threshold = maximum threshold = `T` and mark probability 100%. `K` is the number of test frames that fill the queue to `T`. | 1. Hold transmission on `P2`.<br>2. Send `2 × K` frames with EH-CoS = 3 and EH-ECN = `10` from `P1` to `MAC_2`.<br>3. Release transmission on `P2` and capture.<br>4. Repeat steps 1–3 with EH-ECN = `01`, then with `11`.<br>5. Repeat steps 1–3 with EH-ECN = `00`.<br>6. Repeat steps 1–3 sending only `K / 2` frames with EH-ECN = `10`.<br>7. Repeat steps 1–3 with EH-CoS = 4, whose queue has no marking profile. | ECN-capable frames queued beyond the threshold leave with EH-ECN = `11`. Frames already marked CE stay CE. Not-ECT frames are never changed to CE. Below the threshold, and on a queue without a profile, nothing is marked. | Step 3 and step 4 (`01`): the number of frames received with EH-ECN = `11` is greater than 0 and within the platform-declared tolerance of `K`; the remaining frames keep the sent codepoint.<br>Step 4 (`11`): every received frame has EH-ECN = `11`.<br>Step 5: no received frame has EH-ECN = `11`.<br>Steps 6 and 7: every received frame has the sent codepoint. |
| **ESUN-E6-03** | FCS is updated after ECN marking | Same as E6-02. | 1. Record FCS/CRC error counters on DUT `P2` and on the fanout port facing `P2`.<br>2. Run steps 1–3 of E6-02 with TTL = 8.<br>3. Read the counters again. | Frames that have both EH-ECN and TTL rewritten are transmitted with a valid FCS. | Every frame the DUT counts as transmitted on `P2` is received on PTF, the marked frames carry EH-ECN = `11` and TTL = 7, and neither error counter has increased. |

---

## References

1. **OCP ESUN Base Specification** — "OCP ESUN - Network Operator Requirements - Base Specification Rev 1.0", Manoj Wadekar (Meta), Rajesh Sankaran (Microsoft), February 9, 2026. Defines the ESUN Ethernet Header (EH), frame format, EH-ECN, EH-CoS, Flow Label, TTL, and requirements for endpoints and switches.
2. **Alibaba Ranking Test HLD** — "Tier 1 - Ranking Test HLD", Yubin Lee, [sonic-net/SONiC PR #2351](https://github.com/sonic-net/SONiC/pull/2351). Proposes the SAI Thrift-based test framework for vendor-neutral ASIC evaluation using PTF and IXIA.
3. **SAI (Switch Abstraction Interface)** — [https://github.com/opencomputeproject/SAI](https://github.com/opencomputeproject/SAI). The vendor-neutral API used by all tests to program the ASIC.
4. **sonic-mgmt Test Framework** — [https://github.com/sonic-net/sonic-mgmt](https://github.com/sonic-net/sonic-mgmt). The SONiC test infrastructure where these tests will be contributed, including the fanout, connection graph, and PTF framework.
5. **UEC Transport Specification** — Ultra Ethernet Consortium Specification v1.0.2. Referenced by the ESUN spec for CBFC (Credit-Based Flow Control) and LLR (Link-Level Retry) definitions.
6. **IEEE 802.1Q-2018** — IEEE Standard for Local and Metropolitan Area Networks — Bridges and Bridged Networks. Referenced for VLAN tagging and 802.1p CoS definitions.
7. **IEEE 802.3-2022** — IEEE Standard for Ethernet.
