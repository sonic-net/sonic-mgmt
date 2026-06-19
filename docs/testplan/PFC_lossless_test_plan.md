# PFC Lossless Priority Test Plan

> Companion to [PFC_common.md](PFC_common.md) and [PFC_lossy_test_plan.md](PFC_lossy_test_plan.md).
> This plan covers **lossless** priority behavior. For lossy isolation, see the lossy plan.

- [PFC Lossless Priority Test Plan](#pfc-lossless-priority-test-plan)
  - [1. Test Objective](#1-test-objective)
  - [2. Scope \& Limitations](#2-scope--limitations)
  - [3. References](#3-references)
  - [4. Prerequisites](#4-prerequisites)
  - [5. Test Setup](#5-test-setup)
  - [6. Test Cases](#6-test-cases)
    - [Test Case Matrix](#test-case-matrix)
    - [L01: Single Lossless Priority Pause](#l01-single-lossless-priority-pause)
    - [L02: Multiple Lossless Priorities Pause](#l02-multiple-lossless-priorities-pause)
    - [L03: PFC Resume (duration = 0)](#l03-pfc-resume-duration--0)
    - [L04: Pause Duration Accuracy](#l04-pause-duration-accuracy)
    - [L05: All Ports Simultaneous PFC Storm](#l05-all-ports-simultaneous-pfc-storm)
    - [L06: Varying Packet Sizes](#l06-varying-packet-sizes)
    - [L07: IMIX Traffic Profile](#l07-imix-traffic-profile)
    - [L08: Headroom Buffer Exhaustion](#l08-headroom-buffer-exhaustion)
    - [L09: PFC + ECN Interaction](#l09-pfc--ecn-interaction)
    - [L10: PFC Deadlock Detection](#l10-pfc-deadlock-detection)
    - [L11: PFC During Link Flap](#l11-pfc-during-link-flap)
    - [L12: PFC with Watchdog Enabled (Normal Pause)](#l12-pfc-with-watchdog-enabled-normal-pause)
    - [L13: PFC Storm Exceeds Watchdog Threshold](#l13-pfc-storm-exceeds-watchdog-threshold)
    - [L14: Multi-ASIC PFC Forwarding](#l14-multi-asic-pfc-forwarding)
    - [L15: PFC Counter Verification](#l15-pfc-counter-verification)
  - [7. Teardown](#7-teardown)
  - [8. Metrics \& Reporting](#8-metrics--reporting)
  - [9. Known Limitations \& Future Work](#9-known-limitations--future-work)

## 1. Test Objective

Verify that SONiC switch ports correctly honor PFC pause frames on **lossless**
priority queues — fully halting the targeted priority while leaving all other
priorities untouched, and correctly resuming when the pause is released — so that
RoCEv2 RDMA traffic in AI/ML GPU fabrics remains lossless under congestion.

## 2. Scope & Limitations

**In scope:** PFC pause/resume on lossless priorities, pause-duration accuracy,
per-port and all-port storms, packet-size and IMIX sensitivity, headroom-buffer
generation of PFC, PFC/ECN coexistence, PFC/Watchdog interaction, multi-ASIC
forwarding, and PFC counter verification.

**Out of scope (see [PFC_common.md §9](PFC_common.md#9-scope-boundaries)):** standalone
PFC Watchdog tests, MACSEC, port-channel PFC, buffer tuning, performance benchmarking,
SAI-level tests.

**Topology limitation:** Valid only on **single-tier** testbeds, or the **T0 tier** of
a two-tier testbed used as proxy. PFC frames (dst MAC `01-80-C2-00-00-01`) are not
forwarded by 802.1D bridges. See [PFC_common.md §3](PFC_common.md#3-topology-reference).

**Platform limitation:** Deadlock (L10) and link-flap (L11) require generator/platform
support and are skipped where unsupported. Multi-ASIC (L14) applies only to chassis
platforms.

## 3. References

- Shared theory, topology, utilities, teardown, metrics: [PFC_common.md](PFC_common.md)
- Lossy isolation companion: [PFC_lossy_test_plan.md](PFC_lossy_test_plan.md)
- Legacy plan: [PFC-test-plan.md](PFC-test-plan.md)
- IEEE 802.1Qbb (PFC)

## 4. Prerequisites

- DUT with `pfc_enable` configured in `PORT_QOS_MAP` (default `"3,4"`).
- Snappi traffic generator with at least 2 ports connected to the DUT (Tx + Rx/PFC).
- For per-port and all-port cases, one generator port per DUT port under test.
- PFC Watchdog state controlled per test case (disabled for L01-L11, L14-L15;
  enabled for L12-L13).
- Fixtures from [PFC_common.md §5](PFC_common.md#5-common-utilities-reference):
  `prio_dscp_map`, `all_prio_list`, `lossless_prio_list`.

## 5. Test Setup

1. Read `config_DB` (`PORT_QOS_MAP`, `TC_TO_QUEUE_MAP`, `QUEUE`) to derive the
   lossless priority list (do not hardcode).
2. Determine negotiated link speed per port; compute PFC storm rate dynamically per
   [PFC_common.md §4](PFC_common.md#4-platform--speed-parametrization).
3. Build data flows (one per priority, DSCP-matched via `prio_dscp_map`) from the Tx
   port to the Rx port through the DUT.
4. Build PFC storm flow(s) from the Rx port toward the DUT, with the class-enable
   vector aligned to the lossless priority/priorities under test
   (`pfc_class_enable_vector`).
5. Disable PFC Watchdog and packet aging unless the case states otherwise.
6. Clear PFC counters (`sonic-clear pfccounters`) to establish a baseline.

All cases are parametrized:

```python
@pytest.mark.parametrize("speed", ["100G", "400G", "800G"])
@pytest.mark.parametrize("platform_type", ["memory", "shared_memory"])
@pytest.mark.parametrize("asic_count", ["single", "multi"])
```

## 6. Test Cases

### Test Case Matrix

| ID  | Test Case                                | Priority | Description |
|-----|------------------------------------------|----------|-------------|
| L01 | Single lossless priority pause           | P0 | PFC storm for priority 3 only; queue 3 stops, others unaffected. |
| L02 | Multiple lossless priorities pause       | P0 | PFC storm for priorities 3 AND 4; both pause. |
| L03 | PFC resume (duration=0)                  | P0 | After pausing, send duration=0; traffic resumes within expected latency. |
| L04 | Pause duration accuracy                  | P1 | Send known quanta; measured pause vs expected within +/-5%. |
| L05 | All ports simultaneous PFC storm         | P0 | PFC storm on ALL ports; each port's lossless queues pause independently. |
| L06 | Varying packet sizes (64/512/1518/9216)  | P1 | Repeat L01 per frame size; behavior is size-independent. |
| L07 | IMIX traffic profile                     | P1 | Realistic size mix; PFC still holds. |
| L08 | Headroom buffer exhaustion               | P1 | Burst fills headroom; DUT generates PFC upstream before drop. |
| L09 | PFC + ECN interaction                    | P1 | ECN marks at lower threshold BEFORE PFC triggers; both coexist. |
| L10 | PFC deadlock detection                   | P2 | Circular PFC dependency; DUT detects/breaks deadlock. |
| L11 | PFC during link flap                     | P2 | Flap link during storm; DUT recovers after link up. |
| L12 | PFC with Watchdog enabled (normal pause) | P1 | WD ON, storm below threshold; WD does not trigger; normal pause works. |
| L13 | PFC storm exceeds Watchdog threshold     | P1 | Persistent storm beyond detection_time; WD DROP/FORWARD action fires. |
| L14 | Multi-ASIC PFC forwarding                | P1 | Chassis platforms; PFC honored across ASIC boundaries. |
| L15 | PFC counter verification                 | P0 | `show pfc counters` matches expected Rx/Tx per priority per port. |

---

### L01: Single Lossless Priority Pause

#### Objective
Verify that a PFC storm targeting a single lossless priority (e.g., 3) completely
stops traffic egress for that priority while all other priorities remain unaffected.

#### AI Workload Relevance
RDMA traffic typically uses priority 3 (or 4). A single congested downstream port
must pause only the RDMA class, allowing management and monitoring traffic to keep
flowing.

#### Prerequisites
- DUT with `pfc_enable: "3,4"` in `PORT_QOS_MAP`.
- Snappi generator with at least 2 ports connected to the DUT.
- PFC Watchdog DISABLED (`stop_pfcwd(duthost)`).

#### Test Configuration
- Lossless priority under test: P = 3.
- Data traffic: 8 flows (one per priority 0-7), each at line_rate / 8.
- PFC storm: continuous frames with class-enable bit P=1, duration = 65535 quanta.
- PFC rate: computed per [PFC_common.md §4](PFC_common.md#4-platform--speed-parametrization).
- Link speed: {100G, 400G, 800G} (parametrized).

#### Test Steps
1. Read `config_DB` to confirm lossless priorities.
2. Configure 8 data flows (Tx -> DUT -> Rx), one per priority.
3. Configure PFC storm flow (Rx -> DUT) targeting priority 3 only.
4. Start the PFC storm.
5. Wait 1 second for PFC to take effect.
6. Start all 8 data flows at line rate.
7. Run for 10 seconds.
8. Collect per-flow Rx statistics on the Rx port.

#### Pass / Fail Criteria
| Flow Priority         | Expected Rx Rate | Tolerance     |
|-----------------------|------------------|---------------|
| 0, 1, 2, 4, 5, 6, 7   | line_rate / 8    | +/-2%         |
| 3 (under PFC)         | 0 bps            | exactly 0     |

- Packet loss for priorities != 3: MUST be 0%.
- PFC counter `RxPfc` for priority 3: MUST be > 0.
- PFC counter `RxPfc` for priorities != 3: MUST be 0.
- Fail with the detailed assertion in [PFC_common.md §7.2](PFC_common.md#72-assertion-pattern).

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L02: Multiple Lossless Priorities Pause

#### Objective
Verify that a PFC storm targeting all lossless priorities (3 AND 4) simultaneously
pauses both queues, while lossy priorities remain unaffected.

#### AI Workload Relevance
Some fabrics carry two lossless classes (e.g., RoCEv2 data on 3, congestion-control
or storage on 4). Both must pause independently under combined congestion.

#### Test Configuration
- Priorities under test: {3, 4}; class-enable vector has bits 3 and 4 set.
- Data traffic: 8 flows, one per priority, each line_rate / 8.
- PFC Watchdog DISABLED.

#### Test Steps
1-2. As L01.
3. Configure PFC storm targeting priorities 3 and 4 (`pfc_class_enable_vector([3,4])`).
4-8. As L01.

#### Pass / Fail Criteria
| Flow Priority     | Expected Rx Rate | Tolerance |
|-------------------|------------------|-----------|
| 0, 1, 2, 5, 6, 7  | line_rate / 8    | +/-2%     |
| 3 and 4           | 0 bps            | exactly 0 |

- `RxPfc` for priorities 3 and 4: MUST be > 0; for others MUST be 0.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L03: PFC Resume (duration = 0)

#### Objective
Verify that after a queue has been paused, sending a PFC frame with duration = 0 for
that priority causes traffic to resume promptly.

#### AI Workload Relevance
Congestion is transient. When a downstream buffer drains, the resume signal must
restart RDMA traffic quickly so GPUs do not idle longer than necessary.

#### Test Configuration
- Priority under test: 3.
- Phase A: PFC storm pausing priority 3 for 3 seconds.
- Phase B: send a single PFC frame with duration = 0 for priority 3 (resume).

#### Test Steps
1-6. Establish pause as in L01 (confirm priority 3 Rx == 0).
7. Send PFC frame with duration = 0 for priority 3.
8. Timestamp the first received priority-3 packet; continue 5 seconds.

#### Pass / Fail Criteria
- During Phase A: priority 3 Rx rate == 0.
- After resume: priority 3 Rx rate recovers to line_rate / 8 (+/-2%).
- `pfc.resume_latency_us` recorded; MUST be below the platform threshold
  (default target: < 1000 us, document the value used).

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L04: Pause Duration Accuracy

#### Objective
Verify that the actual pause duration the DUT honors matches the quanta value carried
in the PFC frame.

#### AI Workload Relevance
Over-pausing wastes link time; under-pausing risks loss. Accurate honoring of the
requested quanta keeps the fabric efficient and lossless.

#### Test Configuration
- Priority under test: 3.
- Send a single PFC frame with a known quanta value (e.g., 65535) and do NOT refresh.
- Expected pause = quanta * 512 / link_speed_bps (see [PFC_common.md §2.2](PFC_common.md#22-quanta-and-pause-duration)).

#### Test Steps
1-2. As L01 with priority-3 data flowing at line_rate / 8.
3. Send one PFC frame (priority 3, known quanta), no refresh.
4. Measure the gap in received priority-3 traffic (pause start to resume).

#### Pass / Fail Criteria
- Measured pause duration vs computed expected: within +/-5%.
- Record `pfc.resume_latency_us` and measured pause for telemetry.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L05: All Ports Simultaneous PFC Storm

#### Objective
Verify that a PFC storm applied to ALL DUT ports simultaneously pauses each port's
lossless queues independently, with no cross-port leakage and no DUT instability.

#### AI Workload Relevance
In a GPU fabric every port carries RDMA. A correct switch must handle PFC on all
ports at once — a single-port test is insufficient evidence for fleet deployment.

#### Test Configuration
- Every DUT port under test has a paired generator port.
- Data flows on all ports (per-priority); PFC storm on all ports targeting lossless
  priorities.
- PFC Watchdog DISABLED.

#### Test Steps
1. Configure data + PFC storm flows on every port pair.
2. Start all PFC storms; wait 1 second.
3. Start all data flows; run 10 seconds.
4. Collect per-port, per-priority Rx statistics.

#### Pass / Fail Criteria
- For every port: lossless-priority Rx == 0; lossy-priority loss == 0%.
- DUT remains stable (control plane responsive; no port flaps).
- Per-port `pfc.lossless.status` recorded.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L06: Varying Packet Sizes

#### Objective
Verify PFC pause behavior is independent of data packet size.

#### AI Workload Relevance
RDMA and storage traffic span small control messages to large payloads. PFC must hold
regardless of frame size.

#### Test Configuration
- Repeat L01 with data frame sizes parametrized: 64, 512, 1518, 9216 (jumbo) bytes.

#### Test Steps
As L01, parametrized over `packet_size`.

#### Pass / Fail Criteria
- For every packet size: priority 3 Rx == 0; other priorities unaffected (+/-2%).
- Record `test.packet_size` label with each metric.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L07: IMIX Traffic Profile

#### Objective
Verify PFC holds under a realistic IMIX (mixed packet-size) traffic profile.

#### AI Workload Relevance
Production traffic is never single-size. IMIX approximates real fabric load.

#### Test Configuration
- Data flows use a standard IMIX size distribution; PFC storm on priority 3.

#### Test Steps
As L01 with the data flow configured for IMIX.

#### Pass / Fail Criteria
- Priority 3 Rx == 0 throughout the storm.
- Lossy priorities maintain expected aggregate throughput (+/-2%).

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L08: Headroom Buffer Exhaustion

#### Objective
Verify that when ingress lossless buffers approach exhaustion, the DUT **generates**
PFC pause frames upstream **before** dropping any packet.

#### AI Workload Relevance
This is the DUT acting as a PFC source — the upstream-facing half of lossless
behavior. If the DUT drops instead of pausing, RDMA breaks.

#### Test Configuration
- Oversubscribe a lossless priority into the DUT (ingress burst exceeding drain rate).
- Monitor DUT-generated (Tx) PFC frames toward the source and headroom utilization.

#### Test Steps
1. Configure a burst data flow on priority 3 that fills the headroom buffer.
2. Capture DUT Tx PFC frames and `pfc.headroom.utilization_pct`.
3. Verify no priority-3 packet loss occurs.

#### Pass / Fail Criteria
- DUT `TxPfc` for priority 3: MUST be > 0 (DUT generated PFC).
- Priority-3 packet loss: MUST be 0%.
- Headroom utilization recorded.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L09: PFC + ECN Interaction

#### Objective
Verify that ECN marking engages at a **lower** congestion threshold than PFC, so the
DUT marks ECN before it ever asserts PFC, and the two mechanisms coexist correctly.

#### AI Workload Relevance
ECN is the first line of congestion control for RoCEv2; PFC is the last resort. If
PFC triggers before ECN, the fabric loses the chance for graceful end-to-end slowdown.

#### Test Configuration
- Gradually ramp priority-3 congestion from below ECN threshold up toward PFC
  threshold.
- Monitor ECN-marked (CE) packet count and DUT PFC generation.

#### Test Steps
1. Ramp priority-3 load; capture ECN CE marks and Tx PFC over time.
2. Confirm ECN marks appear at lower load than the first PFC frame.

#### Pass / Fail Criteria
- ECN CE marks observed at a load below where PFC first generates.
- No priority-3 loss at any point.
- Both ECN-mark count and PFC count recorded.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L10: PFC Deadlock Detection

#### Objective
Verify that the DUT detects (and where supported, breaks) a circular PFC dependency
(Port A pauses Port B, which pauses Port A).

#### AI Workload Relevance
PFC deadlock is the single most feared operational hazard in large AI fabrics — it can
freeze an entire pod. The switch must detect and recover.

#### Test Configuration
- Construct a topology/flow pattern that induces a circular pause dependency on a
  lossless priority. Requires platform/generator support.

#### Test Steps
1. Establish the circular PFC dependency.
2. Observe whether the DUT's deadlock-detection mechanism fires and recovers traffic.

#### Pass / Fail Criteria
- Deadlock is detected within the platform's configured detection window.
- Traffic recovers after mitigation (no permanent freeze).
- Skip with a clear reason on platforms without deadlock-detection support.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L11: PFC During Link Flap

#### Objective
Verify the DUT recovers cleanly when a link flaps while a PFC storm is active.

#### AI Workload Relevance
Optics and cables fail in real fabrics. A flap during congestion must not leave a
queue permanently stuck paused.

#### Test Configuration
- Active PFC storm on priority 3; administratively flap a participating link mid-test.

#### Test Steps
1. Establish pause as in L01.
2. Flap the link (down, then up).
3. After link up, send resume / let the storm lapse; observe traffic recovery.

#### Pass / Fail Criteria
- After link recovery, priority-3 traffic resumes to expected rate (+/-2%).
- No queue remains stuck paused; DUT control plane stable.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L12: PFC with Watchdog Enabled (Normal Pause)

#### Objective
With PFC Watchdog ENABLED, verify that PFC storms **below** the watchdog detection
threshold are honored as normal pauses and the watchdog does NOT trigger.

#### AI Workload Relevance
Production runs with PFC Watchdog ON. Normal, healthy pauses must not be mistaken for
a stuck queue and dropped.

#### Test Configuration
- PFC Watchdog ENABLED (`start_pfcwd(duthost)` / default).
- PFC storm tuned below the watchdog detection_time (intermittent pause).

#### Test Steps
1. Ensure watchdog is enabled with default thresholds.
2. Apply an intermittent PFC pattern on priority 3 below the detection window.
3. Verify normal pause behavior and that the watchdog does not fire.

#### Pass / Fail Criteria
- Priority-3 traffic pauses/resumes normally.
- PFC Watchdog does NOT enter the storm/drop state (`show pfcwd stats` shows no
  detection).

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).
Restore watchdog to its pre-test state.

---

### L13: PFC Storm Exceeds Watchdog Threshold

#### Objective
With PFC Watchdog ENABLED, verify that a persistent PFC storm exceeding the watchdog
detection_time triggers the configured DROP/FORWARD action.

#### AI Workload Relevance
A stuck/abusive PFC storm must be contained so one bad neighbor cannot freeze the
fabric — the watchdog is the safety valve.

#### Test Configuration
- PFC Watchdog ENABLED with known detection/restoration thresholds.
- Sustained PFC storm on priority 3 exceeding detection_time.

#### Test Steps
1. Enable watchdog with known thresholds.
2. Apply a continuous priority-3 PFC storm beyond detection_time.
3. Observe the watchdog action (DROP or FORWARD) and counters.

#### Pass / Fail Criteria
- Watchdog detects the storm within the configured detection_time.
- The configured action (DROP/FORWARD) is applied; `show pfcwd stats` reflects it.
- On storm removal, the queue is restored within restoration_time.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).
Restore watchdog to its pre-test state.

---

### L14: Multi-ASIC PFC Forwarding

#### Objective
On multi-ASIC (chassis) platforms, verify lossless traffic crossing ASIC boundaries
still honors PFC.

#### AI Workload Relevance
Chassis and modular switches are common in large fabrics; PFC must work across the
internal fabric, not just within one ASIC.

#### Test Configuration
- Select an ingress port and an egress port on **different** ASICs.
- Data flow traverses the ASIC boundary; PFC storm on the egress-facing lossless
  priority.

#### Test Steps
1. Configure a cross-ASIC data flow on priority 3.
2. Apply a PFC storm targeting priority 3 at the egress side.
3. Verify the priority-3 flow pauses and lossy priorities are unaffected.

#### Pass / Fail Criteria
- Priority-3 Rx == 0 during the storm despite the ASIC crossing.
- Lossy priorities: 0% loss.
- Skip with a clear reason on single-ASIC platforms.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### L15: PFC Counter Verification

#### Objective
Verify that DUT PFC counters (`show pfc counters`) accurately reflect the Rx/Tx PFC
frames per priority per port for the preceding test activity.

#### AI Workload Relevance
Operators rely on PFC counters for fabric health monitoring and incident triage.
Inaccurate counters mask real problems.

#### Test Configuration
- Run a controlled PFC exchange (e.g., the L01 storm) with a known frame count.

#### Test Steps
1. Clear PFC counters (`sonic-clear pfccounters`).
2. Send a known number of PFC frames on priority 3.
3. Read `show pfc counters` and compare against the generator's sent/received counts.

#### Pass / Fail Criteria
- `RxPfc` for priority 3 matches the generator's transmitted PFC count
  (within a documented small tolerance for in-flight frames).
- Counters for non-targeted priorities remain 0.
- Per-priority `pfc.counter.rx_pfc` / `pfc.counter.tx_pfc` recorded.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

## 7. Teardown

All cases use the unconditional teardown contract defined in
[PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template). Teardown MUST run even
when a case fails mid-execution:

1. Stop and clear all generator flows.
2. Restore PFC Watchdog to its pre-test state.
3. Re-enable packet aging.
4. Restore buffer profiles.
5. Confirm all ports up.
6. Clear PFC counters.

## 8. Metrics & Reporting

Use the telemetry framework and assertion pattern from
[PFC_common.md §7](PFC_common.md#7-metrics--reporting-specification). Each case records
at minimum:

- `pfc.lossless.status` (PASS/FAIL) labeled with device id, port id, queue priority,
  traffic type, link speed, and packet size.
- `pfc.lossless.rx_rate_bps`, `pfc.counter.rx_pfc`, `pfc.counter.tx_pfc`.
- `pfc.resume_latency_us` (L03, L04) and `pfc.headroom.utilization_pct` (L08).

Every case asserts pass/fail with a detailed, context-rich failure message — the
metric is recorded in addition to, not instead of, the hard assertion.

## 9. Known Limitations & Future Work

- L10 (deadlock) and L11 (link flap) depend on platform/generator capabilities and
  are P2; they skip cleanly where unsupported.
- L14 applies only to multi-ASIC chassis platforms.
- Absolute 0-bps / 0% thresholds may require a small, explicitly documented tolerance
  on specific hardware; any tolerance must be justified in the test code.
- This document specifies **what** to verify; the pytest implementation follows in a
  separate code change building on `tests/snappi_tests/pfc/`.
