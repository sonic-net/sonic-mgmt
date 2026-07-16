# PFC Lossy Test Plan

> Test Plan for verifying **lossy** priority behavior under PFC on SONiC switches.

- [PFC Lossy Test Plan](#pfc-lossy-test-plan)
  - [1. Test Objective](#1-test-objective)
  - [2. Background \& Theory](#2-background--theory)
    - [2.1 PFC Frame Structure](#21-pfc-frame-structure)
    - [2.2 Quanta and Pause Duration](#22-quanta-and-pause-duration)
    - [2.3 Lossless vs. Lossy Priorities](#23-lossless-vs-lossy-priorities)
  - [3. Topology](#3-topology)
  - [4. Scope \& Limitations](#4-scope--limitations)
  - [5. Prerequisites](#5-prerequisites)
  - [6. Test Setup](#6-test-setup)
  - [7. Test Cases](#7-test-cases)
    - [Test Case Matrix](#test-case-matrix)
    - [Y01: Lossy Traffic Unaffected During PFC Storm](#y01-lossy-traffic-unaffected-during-pfc-storm)
    - [Y02: Malformed PFC Frame Handling](#y02-malformed-pfc-frame-handling)
    - [Y03: Global PAUSE (802.3x) - DUT Ignores](#y03-global-pause-8023x--dut-ignores)
    - [Y04: Lossy Queue Congestion - No PFC Generated](#y04-lossy-queue-congestion--no-pfc-generated)
  - [8. Teardown](#8-teardown)
  - [9. Metrics \& Reporting](#9-metrics--reporting)
  - [10. Known Limitations \& Future Work](#10-known-limitations--future-work)
  - [11. References](#11-references)

## 1. Test Objective

Verify that SONiC switch ports correctly **isolate lossy** priority queues from PFC —
lossy traffic continues at full throughput during a PFC storm on lossless priorities,
the DUT ignores PFC and global-pause frames aimed at lossy priorities, and the DUT
never generates PFC for lossy traffic — so best-effort and management traffic in an AI
fabric is neither paused nor able to interfere with RDMA flow control.

## 2. Background & Theory

### 2.1 PFC Frame Structure

PFC is defined by IEEE 802.1Qbb. A PFC frame is a MAC Control frame that carries a
per-priority pause request:

```
+--------------------+------------------------------------------------+
| Field              | Value / Meaning                                |
+--------------------+------------------------------------------------+
| Destination MAC    | 01-80-C2-00-00-01  (reserved multicast;        |
|                    | NOT forwarded by 802.1D-compliant bridges)     |
| Ethertype          | 0x8808  (MAC Control)                          |
| Opcode             | 0x0101  (PFC / Priority-based Flow Control)    |
| Class-Enable Vector| 16 bits: low 8 bits = 1 bit per priority.      |
|                    | bit P = 1 -> priority P is paused              |
|                    | bit P = 0 -> priority P is unaffected          |
| Time[0..7]         | 8 x 16-bit pause durations (quanta),           |
|                    | one per priority. 0 = resume (un-pause).       |
+--------------------+------------------------------------------------+
```

Key consequence of the reserved destination MAC: PFC frames are **link-local**. They
are consumed by the first switch and never bridged onward. This drives the topology
constraints in Section 3.

### 2.2 Quanta and Pause Duration

One **quantum** is the time to transmit 512 bits at the current link speed. The pause
duration a PFC frame requests is speed-dependent:

```
pause_duration_seconds = (quanta_value * 512) / link_speed_bps
```

Worked example at 100 Gbps with the maximum quanta value (65535):

```
pause_duration = (65535 * 512) / 100,000,000,000 = 335.54 microseconds
```

### 2.3 Lossless vs. Lossy Priorities

| Property              | Lossless Queues (default 3, 4)   | Lossy Queues (0,1,2,5,6,7) |
|-----------------------|----------------------------------|----------------------------|
| Reacts to PFC         | YES - stops transmitting         | NO - ignores PFC frames    |
| Generates PFC         | YES - when ingress buffers fill  | NO - drops packets instead |
| Has headroom buffer   | YES                              | NO                         |
| WRED profile          | `AZURE_LOSSLESS`                 | None                       |

This plan focuses on the **lossy** column — proving those queues stay unaffected by,
and never generate, PFC.

## 3. Topology

```
Supported Topologies

[PREFERRED] Single-Tier (DUT can be T0/T1):
+-------------------+         +-------------------+         +-------------------+
| Snappi Tx Port    | ------> |    SONiC DUT      | <------ | Snappi Rx Port    |
| (Data flows)      |         | (Port under test) |         | (PFC storm + Rx)  |
+-------------------+         +-------------------+         +-------------------+

[ALTERNATIVE] Two-Tier (T0 proxy):
+-------------------+         +---------+         +---------+
| Snappi Tx Port    | ------> | T0 DUT  | ------> | T1 DUT  |
+-------------------+         +---------+         +---------+
                                   ^
                                   |
                              Snappi PFC (reaches T0 only)

NOTE: PFC frames (dst MAC 01-80-C2-00-00-01) are NOT forwarded by 802.1D bridges.
      Testing a T1 DUT therefore requires a T0 switch as a port stand-in, or the
      generator connected directly to the T1 (which makes it a single-tier test).
      Every port under test requires a dedicated traffic-generator port.
```

## 4. Scope & Limitations

**In scope:** lossy isolation during lossless PFC storms, malformed-frame robustness,
ignoring PFC/global-pause on lossy priorities, and confirming no PFC is generated for
lossy congestion.

**Out of scope:** lossless pause/resume behavior, standalone PFC Watchdog tests (see
`tests/pfcwd/`), MACSEC, port-channel PFC, buffer tuning, performance benchmarking,
and SAI-level tests.

**Topology limitation:** PFC pause-frame tests are valid only on **single-tier**
testbeds (traffic generator directly attached to the DUT), or on the **T0 tier** of a
two-tier testbed used as a proxy. PFC cannot be validated on a T1 DUT reached *through*
a T0 because the storm is consumed at the T0 bridge.

## 5. Prerequisites

- DUT with `pfc_enable` configured in `PORT_QOS_MAP` (default `"3,4"`); lossy
  priorities are the complement (0,1,2,5,6,7).
- Snappi traffic generator with at least 2 ports connected to the DUT.
- PFC Watchdog DISABLED for these cases unless stated.

## 6. Test Setup

1. Read `config_DB` to derive lossless and lossy priority lists (do not hardcode).
2. Build data flows per priority (DSCP-matched) Tx -> DUT -> Rx.
3. Build PFC / global-pause flows per case (Rx -> DUT).
4. Disable PFC Watchdog and packet aging unless the case states otherwise.
5. Clear PFC counters (`sonic-clear pfccounters`) to establish a baseline.

All cases are parametrized over link speed, buffer model, and ASIC count. Derive
`buffer_model` at runtime from `DEVICE_METADATA|localhost.buffer_model` in `config_DB`:

```python
@pytest.mark.parametrize("speed", ["100G", "400G", "800G"])
# static = per-port partitioned buffer; dynamic = shared pool (dynamic_th alpha)
@pytest.mark.parametrize("buffer_model", ["static", "dynamic"])
# single-ASIC vs multi-ASIC (chassis) platforms
@pytest.mark.parametrize("asic_count", ["single", "multi"])
```

## 7. Test Cases

### Test Case Matrix

| ID  | Test Case                                  | Priority | Description |
|-----|--------------------------------------------|----------|-------------|
| Y01 | Lossy traffic unaffected during PFC storm  | P0 | Full PFC storm on lossless priorities; all lossy flows keep full throughput. |
| Y02 | Malformed PFC frame handling               | P2 | Invalid class-enable vectors, wrong opcodes, truncated frames; DUT ignores all. |
| Y03 | Global PAUSE (802.3x) - DUT ignores        | P1 | IEEE 802.3x global pause; SONiC neither pauses nor forwards. |
| Y04 | Lossy queue congestion - no PFC generated  | P1 | Oversubscribe a lossy queue; DUT generates no PFC for lossy priorities. |

---

### Y01: Lossy Traffic Unaffected During PFC Storm

#### Objective
Verify that a full PFC storm on the lossless priorities (3, 4) leaves all lossy
priority flows (0,1,2,5,6,7) at full throughput with zero loss.

#### Test Configuration
- PFC storm targeting lossless priorities {3, 4}.
- Data flows on all lossy priorities, each at line_rate / number_of_lossy_priorities.
- PFC Watchdog DISABLED.

#### Test Steps
1. Read `config_DB` to confirm lossy priorities.
2. Configure data flows on all lossy priorities (Tx -> DUT -> Rx).
3. Configure a PFC storm targeting priorities 3 and 4.
4. Start the storm; wait 1 second.
5. Start lossy data flows; run 10 seconds.
6. Collect per-flow Rx statistics.

#### Pass / Fail Criteria
| Flow Priority         | Expected Rx Rate          | Tolerance |
|-----------------------|---------------------------|-----------|
| 0, 1, 2, 5, 6, 7      | configured per-flow rate  | +/-2%     |

- Packet loss for every lossy priority: MUST be 0%.
- `RxPfc` on lossy priorities: MUST be 0 (storm only targets 3, 4).
- Record `pfc.lossy.status` and `pfc.lossy.packet_loss_pct`.

#### Teardown
Per Section 8.

---

### Y02: Malformed PFC Frame Handling

#### Objective
Verify the DUT robustly ignores malformed PFC frames (invalid class-enable vectors,
wrong opcodes, truncated frames) without affecting any traffic class or destabilizing.

#### Test Configuration
- Data flows on all priorities at line rate.
- Inject malformed control frames toward the DUT:
  - PFC frame with reserved/invalid opcode.
  - PFC frame with an all-ones class-enable vector including reserved bits.
  - Truncated PFC frame (short length).

#### Test Steps
1. Start data flows on all priorities.
2. Inject each malformed-frame variant in turn.
3. Monitor all flows and DUT stability/counters throughout.

#### Pass / Fail Criteria
- No priority (lossless or lossy) is paused by any malformed frame.
- 0% loss on lossy priorities; lossless priorities flow normally (no spurious pause).
- DUT control plane stays responsive; no crash, no counter corruption.
- Malformed frames are dropped, not forwarded.

#### Teardown
Per Section 8.

---

### Y03: Global PAUSE (802.3x) - DUT Ignores

#### Objective
Verify that SONiC ignores IEEE 802.3x global PAUSE frames - it neither pauses any
traffic nor forwards the frames.

#### Test Configuration
- Data flows on all priorities at line rate.
- Inject IEEE 802.3x global PAUSE frames (dst MAC `01-80-C2-00-00-01`, opcode 0x0001)
  toward the DUT.

#### Test Steps
1. Start data flows on all priorities.
2. Inject a continuous stream of 802.3x global PAUSE frames.
3. Measure all flows during the global-pause injection.

#### Pass / Fail Criteria
- No priority is paused (all flows maintain expected rate, +/-2%).
- 0% loss on lossy priorities.
- Global PAUSE frames are NOT forwarded by the DUT.

#### Teardown
Per Section 8.

---

### Y04: Lossy Queue Congestion - No PFC Generated

#### Objective
Verify that congesting (oversubscribing) a lossy queue causes the DUT to **drop**
excess traffic rather than **generate** PFC frames for the lossy priority.

#### Test Configuration
- Oversubscribe a lossy priority into the DUT (ingress rate exceeds egress capacity).
- Monitor DUT Tx PFC frames for the lossy priority.

#### Test Steps
1. Configure an oversubscribing data flow on a lossy priority.
2. Capture DUT Tx PFC frames and per-queue drop counters.

#### Pass / Fail Criteria
- DUT `TxPfc` for the lossy priority: MUST be 0 (no PFC generated).
- Excess traffic is dropped (drop counters increase), as expected for lossy queues.
- Record `pfc.counter.tx_pfc` for the lossy priority (expected 0).

#### Teardown
Per Section 8.

## 8. Teardown

Every test **MUST** clean up unconditionally — even when it fails part-way through. A
failed test that leaves PFC watchdog stopped, packet aging disabled, or generator
streams configured will silently corrupt subsequent tests. Use a `yield` fixture with
`autouse=True` (or an equivalent `try/finally`):

**Teardown contract (all six MUST hold after every case, pass or fail):**

1. All traffic-generator flows stopped and cleared.
2. PFC Watchdog returned to its pre-test state.
3. Packet aging re-enabled.
4. Buffer profiles restored to defaults.
5. All ports administratively and operationally up.
6. PFC counters cleared.

## 9. Metrics & Reporting

Each case records at minimum:

- `pfc.lossy.status` (PASS/FAIL) labeled with device id, port id, queue priority,
  traffic type, and link speed.
- `pfc.lossy.packet_loss_pct` and, where relevant, `pfc.counter.tx_pfc`.

Every case asserts pass/fail with a detailed, context-rich failure message — the metric
is recorded in addition to, not instead of, the hard assertion:


## 10. Known Limitations & Future Work

- Malformed-frame variants (Y02) depend on generator support for crafting raw control
  frames; skip cleanly where unsupported.
- This document specifies **what** to verify; the pytest implementation follows in a
  separate code change building on `tests/snappi_tests/pfc/`.

## 11. References

- Legacy plan: [PFC-test-plan.md](PFC-test-plan.md) (2020, frame diagrams, Keysight config)
- [PFC_Snappi_Additional_Testcases.md](PFC_Snappi_Additional_Testcases.md) (multi-ASIC, MACSEC, ECN, PFCWD, port-channel)
- IEEE 802.1Qbb — Priority-based Flow Control
- IEEE 802.3x — Link-level Flow Control (global PAUSE)
- RFC 8782 / RoCEv2 — RDMA over Converged Ethernet
