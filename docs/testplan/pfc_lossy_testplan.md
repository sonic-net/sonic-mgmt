# PFC Lossy Test Plan

> Companion to [PFC_common.md](PFC_common.md) and [PFC_lossless_test_plan.md](PFC_lossless_test_plan.md).
> This plan covers **lossy** test case.

- [PFC Lossy Priority Test Plan](#pfc-lossy-priority-test-plan)
  - [1. Test Objective](#1-test-objective)
  - [2. Scope \& Limitations](#2-scope--limitations)
  - [3. References](#3-references)
  - [4. Prerequisites](#4-prerequisites)
  - [5. Test Setup](#5-test-setup)
  - [6. Test Cases](#6-test-cases)
    - [Test Case Matrix](#test-case-matrix)
    - [Y01: Lossy Traffic Unaffected During PFC Storm](#y01-lossy-traffic-unaffected-during-pfc-storm)
    - [Y02: Malformed PFC Frame Handling](#y02-malformed-pfc-frame-handling)
    - [Y03: PFC Targeting Lossy Priority - DUT Ignores](#y03-pfc-targeting-lossy-priority--dut-ignores)
    - [Y04: Global PAUSE (802.3x) - DUT Ignores](#y04-global-pause-8023x--dut-ignores)
    - [Y05: Head-of-Line Blocking Measurement](#y05-head-of-line-blocking-measurement)
    - [Y06: Lossy Queue Congestion - No PFC Generated](#y06-lossy-queue-congestion--no-pfc-generated)
  - [7. Teardown](#7-teardown)
  - [8. Metrics \& Reporting](#8-metrics--reporting)
  - [9. Known Limitations \& Future Work](#9-known-limitations--future-work)

## 1. Test Objective

Verify that SONiC switch ports correctly **isolate lossy** priority queues from PFC -
lossy traffic continues at full throughput during a PFC storm on lossless priorities,
the DUT ignores PFC and global-pause frames aimed at lossy priorities, and the DUT
never generates PFC for lossy traffic - so best-effort and management traffic in an
 fabric is neither paused nor able to interfere with RDMA flow control.

## 2. Scope & Limitations

**In scope:** lossy isolation during lossless PFC storms, malformed-frame
robustness, ignoring PFC/global-pause on lossy priorities, head-of-line blocking
measurement, and confirming no PFC is generated for lossy congestion.

**Topology limitation:** Valid only on **single-tier** testbeds, or the **T0 tier** of
a two-tier testbed used as proxy. See [PFC_common.md §3](PFC_common.md#3-topology-reference).

## 3. References

- Shared theory, topology, utilities, teardown, metrics: [PFC_common.md](PFC_common.md)
- Lossless companion: [PFC_lossless_test_plan.md](PFC_lossless_test_plan.md)
- Legacy plan: [PFC-test-plan.md](PFC-test-plan.md)
- IEEE 802.1Qbb (PFC), IEEE 802.3x (global PAUSE)

## 4. Prerequisites

- DUT with `pfc_enable` configured in `PORT_QOS_MAP` (default `"3,4"`); lossy
  priorities are the complement (0,1,2,5,6,7).
- Snappi traffic generator with at least 2 ports connected to the DUT.
- PFC Watchdog DISABLED for these cases unless stated.
- Fixtures from [PFC_common.md §5](PFC_common.md#5-common-utilities-reference):
  `prio_dscp_map`, `all_prio_list`, `lossless_prio_list`, `lossy_prio_list`.

## 5. Test Setup

1. Read `config_DB` to derive lossless and lossy priority lists.
2. Compute PFC storm rate dynamically per
   [PFC_common.md §4](PFC_common.md#4-platform--speed-parametrization).
3. Build data flows per priority (DSCP-matched) Tx -> DUT -> Rx.
4. Build PFC / global-pause flows per case (Rx -> DUT).
5. Disable PFC Watchdog and packet aging unless the case states otherwise.
6. Clear PFC counters to establish a baseline.

All cases are parametrized:

```python
@pytest.mark.parametrize("speed", ["100G", "400G", "800G"])
# A check to be put to see what the DUT supports
@pytest.mark.parametrize("buffer_model", ["static", "dynamic"])
# A check to be put to see what the DUT supports
@pytest.mark.parametrize("asic_count", ["single", "multi"])
```

## 6. Test Cases

### Test Case Matrix

| ID  | Test Case                                  | Priority | Description |
|-----|--------------------------------------------|----------|-------------|
| Y01 | Lossy traffic unaffected during PFC storm  | P0 | Full PFC storm on lossless priorities; all lossy flows keep full throughput. |
| Y02 | Malformed PFC frame handling               | P1 | Invalid class-enable vectors, wrong opcodes, truncated frames; DUT ignores all. |
| Y03 | PFC targeting lossy priority - DUT ignores | P0 | PFC with class-enable bit set for a lossy priority; DUT does NOT pause it. |
| Y04 | Global PAUSE (802.3x) - DUT ignores        | P1 | IEEE 802.3x global pause; SONiC neither pauses nor forwards. |
| Y05 | Head-of-line blocking measurement          | P0 | Heavy PFC storm on lossless queues; lossy queue latency stays below threshold. |
| Y06 | Lossy queue congestion - no PFC generated  | P1 | Oversubscribe a lossy queue; DUT generates no PFC for lossy priorities. |

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
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

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
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### Y03: PFC Targeting Lossy Priority - DUT Ignores

#### Objective
Verify that a well-formed PFC frame whose class-enable vector sets a **lossy** priority
bit (e.g., 0) does NOT pause that lossy queue.

#### Test Configuration
- Data flow on a lossy priority (e.g., 0) at line rate.
- PFC storm with the class-enable bit set for that lossy priority only.

#### Test Steps
1. Start the lossy-priority data flow.
2. Send a PFC storm targeting that lossy priority.
3. Measure the lossy flow's Rx rate during the storm.

#### Pass / Fail Criteria
- Lossy-priority Rx rate is unchanged (full throughput, +/-2%); NOT paused.
- 0% loss on the lossy priority.
- Record `pfc.lossy.status`.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### Y04: Global PAUSE (802.3x) - DUT Ignores

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
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### Y05: Head-of-Line Blocking Measurement

#### Objective
Under a heavy PFC storm on lossless queues, verify that lossy-queue latency does not
rise above a defined threshold - i.e., paused lossless traffic does not head-of-line
block lossy traffic.

#### Test Configuration
- Heavy PFC storm pausing lossless priorities {3, 4}.
- Latency-measured data flows on lossy priorities at moderate load.
- Define and document a maximum acceptable added latency threshold.

#### Test Steps
1. Start lossy data flows with latency measurement enabled.
2. Apply the lossless PFC storm.
3. Compare lossy-queue latency during the storm vs a no-storm baseline.

#### Pass / Fail Criteria
- Added lossy-queue latency during the storm stays below the documented threshold.
- 0% loss on lossy priorities.
- Record lossy latency (baseline and under-storm) for telemetry.

#### Teardown
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

---

### Y06: Lossy Queue Congestion - No PFC Generated

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
Per [PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template).

## 7. Teardown

All cases use the unconditional teardown contract from
[PFC_common.md §6](PFC_common.md#6-mandatory-teardown-template), executed even on
mid-test failure:

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

- `pfc.lossy.status` (PASS/FAIL) labeled with device id, port id, queue priority,
  traffic type, and link speed.
- `pfc.lossy.packet_loss_pct` and, where relevant, `pfc.counter.tx_pfc`.
- Lossy-queue latency (Y05).

Every case asserts pass/fail with a detailed, context-rich failure message - the
metric is recorded in addition to, not instead of, the hard assertion.

## 9. Known Limitations & Future Work

- Y05 head-of-line latency thresholds are platform-dependent and must be documented
  per platform rather than assumed universal.
- Malformed-frame variants (Y02) depend on generator support for crafting raw control
  frames; skip cleanly where unsupported.
