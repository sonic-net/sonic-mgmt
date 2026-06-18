# PFC Test Plan — Common Reference

- [PFC Test Plan — Common Reference](#pfc-test-plan--common-reference)
  - [1. Purpose](#1-purpose)
  - [2. Background Theory](#2-background-theory)
    - [2.1 PFC Frame Structure](#21-pfc-frame-structure)
    - [2.2 Quanta and Pause Duration](#22-quanta-and-pause-duration)
    - [2.3 Required PFC Storm Rate](#23-required-pfc-storm-rate)
    - [2.4 Lossless vs. Lossy Priorities](#24-lossless-vs-lossy-priorities)
    - [2.5 SONiC Default QoS Configuration](#25-sonic-default-qos-configuration)
  - [3. Topology Reference](#3-topology-reference)
  - [4. Platform \& Speed Parametrization](#4-platform--speed-parametrization)
  - [5. Common Utilities Reference](#5-common-utilities-reference)
  - [6. Mandatory Teardown Template](#6-mandatory-teardown-template)
  - [7. Metrics \& Reporting Specification](#7-metrics--reporting-specification)
    - [7.1 Telemetry Framework Integration](#71-telemetry-framework-integration)
    - [7.2 Assertion Pattern](#72-assertion-pattern)
  - [8. Key Engineering Decisions](#8-key-engineering-decisions)
  - [9. Scope Boundaries](#9-scope-boundaries)
  - [10. Known Limitations \& Future Work](#10-known-limitations--future-work)
  - [11. References](#11-references)

## 1. Purpose

This document is the **shared reference** for the SONiC PFC (Priority Flow Control)
test plans. It centralizes the background theory, topology constraints, reusable
utilities, the mandatory teardown contract, and the metrics/reporting specification
that are common to both companion documents:

- [PFC_lossless_test_plan.md](PFC_lossless_test_plan.md) — verifies lossless priority pause/resume behavior (15 cases)
- [PFC_lossy_test_plan.md](PFC_lossy_test_plan.md) — verifies lossy priority isolation (6 cases)

Together, these three documents supersede the legacy
[PFC-test-plan.md](PFC-test-plan.md) (2020, Keysight) for new test development.
The legacy plan remains valuable for its frame-format diagrams and Keysight-specific
configuration and is retained for reference.

**Why PFC matters for AI workloads:** AI/ML training clusters move terabytes of
gradient data between GPUs using RDMA over Converged Ethernet v2 (RoCEv2). RoCEv2
requires a **lossless** Ethernet fabric — a single dropped RDMA packet forces a
retransmission that stalls the GPU. At 400G/800G, that idle time directly wastes
expensive compute. PFC is the mechanism that guarantees zero packet loss on the
designated lossless priority queues. A switch that mishandles PFC (ignores it,
over-applies it, or deadlocks) breaks the entire collective-communication fabric.

## 2. Background Theory

### 2.1 PFC Frame Structure

PFC is defined by IEEE 802.1Qbb. A PFC frame is a MAC Control frame that carries a
per-priority pause request:

```
+--------------------+------------------------------------------------+
| Field              | Value / Meaning                                |
+--------------------+------------------------------------------------+
| Destination MAC    | 01-80-C2-00-00-01  (reserved multicast;        |
|                    | NOT forwarded by 802.1D-compliant bridges)     |
| Source MAC         | Sending station MAC                            |
| Ethertype          | 0x8808  (MAC Control)                          |
| Opcode             | 0x0101  (PFC / Priority-based Flow Control)    |
| Class-Enable Vector| 16 bits: low 8 bits = 1 bit per priority.      |
|                    | bit P = 1 -> priority P is paused              |
|                    | bit P = 0 -> priority P is unaffected          |
| Time[0..7]         | 8 x 16-bit pause durations (quanta),           |
|                    | one per priority. 0 = resume (un-pause).       |
| Pad / FCS          | Frame padding and checksum                     |
+--------------------+------------------------------------------------+
```

Key consequence of the reserved destination MAC: PFC frames are **link-local**. They
are consumed by the first switch and never bridged onward. This drives the topology
constraints in Section 3.

### 2.2 Quanta and Pause Duration

One **quantum** is the time required to transmit 512 bits at the current link speed.
The pause duration requested by a PFC frame is therefore speed-dependent (plain-text
formula, no LaTeX):

```
pause_duration_seconds = (quanta_value * 512) / link_speed_bps
```

Worked example at 100 Gbps with the maximum quanta value (65535):

```
pause_duration = (65535 * 512) / 100,000,000,000
               = 33,553,920 / 100,000,000,000
               = 0.00033554 seconds
               = 335.54 microseconds
```

### 2.3 Required PFC Storm Rate

To hold a queue paused continuously, PFC frames must be re-sent before each pause
window expires. The minimum sustained storm rate is:

```
frames_per_second = 1,000,000 / pause_duration_microseconds
```

The achievable wire rate is bounded by frame size. For minimum-size (64-byte) PFC
frames at 100 Gbps with max quanta:

```
frames_per_second = 1,000,000 / 335.54 = ~2,980 fps   (to refresh the pause window)
```

In practice test implementations send PFC at a rate high enough to guarantee the
queue never un-pauses; a common conservative target derived from frame-size headroom
is approximately:

```
storm_rate_fps = (1,000,000 / pause_duration_us) * frame_size_bytes
```

which at 100 Gbps / 64 B yields ~190,738 fps. The exact rate is **computed
dynamically per link speed** (see Section 4) rather than hardcoded.

### 2.4 Lossless vs. Lossy Priorities

| Property              | Lossless Queues (default 3, 4)   | Lossy Queues (0,1,2,5,6,7) |
|-----------------------|----------------------------------|----------------------------|
| Reacts to PFC         | YES — stops transmitting         | NO — ignores PFC frames    |
| Generates PFC         | YES — when ingress buffers fill  | NO — drops packets instead |
| Typical use           | RDMA / RoCEv2, AI training        | Best-effort, management    |
| Has headroom buffer   | YES                              | NO                         |
| WRED profile          | `AZURE_LOSSLESS`                 | None                       |

### 2.5 SONiC Default QoS Configuration

Read from `config_DB` at test setup time — never hardcode the priority list:

```json
"PORT_QOS_MAP": {
    "Ethernet0": {
        "dscp_to_tc_map": "AZURE",
        "pfc_enable": "3,4",
        "pfcwd_sw_enable": "3,4",
        "tc_to_pg_map": "AZURE",
        "tc_to_queue_map": "AZURE"
    }
}
```

- Lossless priorities are derived from `pfc_enable` (here, `3,4`).
- Queues 3 and 4 use `scheduler.1` + `wred_profile: AZURE_LOSSLESS` + a headroom buffer.
- All other queues use `scheduler.0` with no WRED and are therefore lossy.

## 3. Topology Reference

```
Supported Topologies

[PREFERRED] Single-Tier:
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
                              Snappi PFC storm (reaches T0 only)

NOTE: PFC frames (dst MAC 01-80-C2-00-00-01) are NOT forwarded by 802.1D bridges.
      Testing a T1 DUT therefore requires a T0 switch as a port stand-in.
      The T0 proxy MUST match the DUT model and software build.
      Every port under test requires a dedicated traffic-generator port.
```

**Scope constraint (document in every plan):** PFC pause-frame tests are valid only
on **single-tier testbeds** (traffic generator directly attached to the DUT), or on
the **T0 tier of a two-tier testbed** used as a proxy. PFC cannot be validated on a
T1 DUT directly because the storm is consumed at the T0 bridge.

## 4. Platform & Speed Parametrization

All test cases are parametrized across link speed, buffer model, and ASIC count:

```python
@pytest.mark.parametrize("speed", ["100G", "400G", "800G"])
@pytest.mark.parametrize("platform_type", ["memory", "shared_memory"])
@pytest.mark.parametrize("asic_count", ["single", "multi"])
```

Speed-dependent reference values (max quanta = 65535, 64-byte PFC frames):

| Speed     | Max Quanta Duration | Required PFC Rate (64B frames) |
|-----------|---------------------|--------------------------------|
| 100 Gbps  | 335.54 us           | ~190,738 fps                   |
| 400 Gbps  | 83.89 us            | ~763,000 fps                   |
| 800 Gbps  | 41.94 us            | ~1,526,000 fps                 |

Dynamic calculation (plain text):

```
pause_duration_us = (quanta * 512 / speed_bps) * 1e6
pfc_rate_fps      = (1,000,000 / pause_duration_us) * frame_size_bytes
```

The test must compute these at runtime from the negotiated link speed so the same
test body covers 100G/400G/800G without hardcoded constants.

## 5. Common Utilities Reference

The following helpers and fixtures already exist in sonic-mgmt and SHOULD be reused.
Import paths reflect the current repository layout:

```python
# QoS / priority fixtures
from tests.common.snappi_tests.qos_fixtures import (
    prio_dscp_map,        # Priority -> DSCP mapping (from config_DB)
    all_prio_list,        # [0, 1, 2, 3, 4, 5, 6, 7]
    lossless_prio_list,   # e.g. [3, 4], derived from pfc_enable
    lossy_prio_list,      # complement of lossless_prio_list
)

# PFC / PFC-watchdog / packet-aging helpers
from tests.common.snappi_tests.common_helpers import (
    pfc_class_enable_vector,   # build class-enable vector from priority list
    start_pfcwd,               # restore PFC watchdog
    stop_pfcwd,                # disable PFC watchdog for the test window
    disable_packet_aging,      # Mellanox: hold paused packets in buffer
    enable_packet_aging,       # restore packet aging on teardown
    sec_to_nanosec,
)

# Snappi traffic-generation helpers and PFC test driver
from tests.common.snappi_tests.traffic_generation import (
    setup_base_traffic_config, generate_test_flows, generate_pause_flows,
)
from tests.snappi_tests.pfc.files.helper import run_pfc_test

# Assertions
from tests.common.helpers.assertions import pytest_assert

# Telemetry (current framework — preferred over legacy test_reporting/)
from tests.common.telemetry import (
    GaugeMetric,
    METRIC_LABEL_DEVICE_ID,
    METRIC_LABEL_DEVICE_PORT_ID,
    METRIC_LABEL_DEVICE_QUEUE_ID,
)
from tests.common.telemetry.reporters import DBReporter, TSReporter
```

> Note: `stop_pfcwd`, `disable_packet_aging`, and `pfc_class_enable_vector` live in
> `tests/common/snappi_tests/common_helpers.py` (not in the pfc `files/helper.py`).
> Confirm symbol availability against the target branch before implementation.

## 6. Mandatory Teardown Template

Every PFC test **MUST** clean up unconditionally — even when the test fails part-way
through. A failed test that leaves PFC watchdog stopped, packet aging disabled, or
traffic-generator streams configured will silently corrupt subsequent tests. Use a
`yield` fixture with `autouse=True` (or an equivalent `try/finally`):

```python
@pytest.fixture(autouse=True)
def pfc_test_cleanup(duthost, snappi_api):
    """Unconditional teardown for PFC tests. Runs even on failure."""
    # --- SETUP (before yield): snapshot state to restore ---
    original_pfcwd_state = get_pfcwd_state(duthost)

    yield  # <-- test body runs here

    # --- TEARDOWN (always runs) ---
    # 1. Stop all traffic-generator streams
    snappi_api.stop_all_flows()

    # 2. Restore PFC Watchdog to its original state
    if original_pfcwd_state == "enabled":
        start_pfcwd(duthost)

    # 3. Re-enable packet aging (Mellanox/Nvidia platforms)
    enable_packet_aging(duthost)

    # 4. Restore any modified buffer profiles
    #    restore_buffer_alpha(duthost, orig_dynamic_th)

    # 5. Verify all DUT ports are back up
    assert_all_ports_up(duthost)

    # 6. Clear PFC counters for a clean next-test baseline
    duthost.shell("sonic-clear pfccounters")
```

**Teardown contract (assert in every plan's Teardown section):**

1. All traffic-generator flows stopped and cleared.
2. PFC Watchdog returned to its pre-test state.
3. Packet aging re-enabled.
4. Buffer profiles restored to defaults.
5. All ports administratively and operationally up.
6. PFC counters cleared.

## 7. Metrics & Reporting Specification

### 7.1 Telemetry Framework Integration

Use the current `tests/common/telemetry/` framework (preferred over the legacy
`test_reporting/telemetry/`). It supports both time-series (OTLP) and DB export.

```python
PFC_METRICS = {
    "pfc.lossless.status":          "PASS/FAIL for lossless pause verification",
    "pfc.lossy.status":             "PASS/FAIL for lossy isolation verification",
    "pfc.lossless.rx_rate_bps":     "Measured Rx rate for a paused priority (should be 0)",
    "pfc.lossy.packet_loss_pct":    "Packet loss % for lossy traffic (should be 0)",
    "pfc.resume_latency_us":        "Microseconds from un-pause to first packet received",
    "pfc.counter.rx_pfc":           "DUT Rx PFC frame count per priority",
    "pfc.counter.tx_pfc":           "DUT Tx PFC frame count per priority",
    "pfc.headroom.utilization_pct": "Headroom buffer utilization %",
}

PFC_LABELS = {
    METRIC_LABEL_DEVICE_ID:       "DUT hostname",
    METRIC_LABEL_DEVICE_PORT_ID:  "Ethernet port name",
    METRIC_LABEL_DEVICE_QUEUE_ID: "Priority queue number (0-7)",
    "test.traffic_type":          "lossless | lossy",
    "test.link_speed":            "100G | 400G | 800G",
    "test.packet_size":           "64 | 512 | 1518 | 9216 | imix",
}
```

Example of recording a per-port status metric:

```python
reporter = DBReporter(...)
status = GaugeMetric(
    name="pfc.lossless.status",
    description="Lossless pause verification result",
    unit="bool",
    reporter=reporter,
)
status.record(
    labels={
        METRIC_LABEL_DEVICE_ID: duthost.hostname,
        METRIC_LABEL_DEVICE_PORT_ID: port,
        METRIC_LABEL_DEVICE_QUEUE_ID: priority,
        "test.traffic_type": "lossless",
        "test.link_speed": speed,
    },
    value=1 if passed else 0,
)
```

### 7.2 Assertion Pattern

Per reviewer mandate, every test fails with **detailed, actionable logs** — not just
a silent metric. The metric is recorded *in addition to* a hard assertion:

```python
def assert_pfc_lossless_paused(port, priority, rx_rate, pfc_counters, config):
    """Assert lossless traffic is fully paused. Fail with full context."""
    pytest_assert(rx_rate == 0, (
        f"\n{'='*60}\n"
        f"PFC LOSSLESS TEST FAILED\n"
        f"{'='*60}\n"
        f"Port:              {port}\n"
        f"Priority:          {priority}\n"
        f"Expected Rx:       0 bps\n"
        f"Actual Rx:         {rx_rate} bps\n"
        f"PFC Rx Count:      {pfc_counters['rx']}\n"
        f"PFC Tx Count:      {pfc_counters['tx']}\n"
        f"Config pfc_enable: {config['pfc_enable']}\n"
        f"Link Speed:        {config['speed']}\n"
        f"PFC Storm Rate:    {config['pfc_rate']} fps\n"
        f"{'='*60}"
    ))
```

## 8. Key Engineering Decisions

| Decision              | Choice                                       | Rationale                                          |
|-----------------------|----------------------------------------------|----------------------------------------------------|
| Traffic generator     | Snappi                                       | Open-source, CI-friendly, actively maintained      |
| Test framework        | pytest + Snappi fixtures                      | Existing sonic-mgmt standard                       |
| Telemetry             | `tests/common/telemetry/`                    | Newer; supports OTLP + DB export                   |
| PFC rate calculation  | Dynamic per link speed                       | Supports 100G/400G/800G without hardcoding         |
| Port iteration        | Parametrized over all ports                  | AI clusters use every port; one-port tests are insufficient |
| Teardown              | `yield` fixture, `autouse=True`              | Guarantees cleanup even on assertion failure       |
| Pass/fail threshold   | Lossy: exactly 0% loss; Lossless: exactly 0 bps Rx | Zero-tolerance for AI workloads              |
| PFC Watchdog          | Test both states                             | Production runs with WD ON; interaction must be verified |
| Document split        | 3 files (common + lossless + lossy)          | Reviewer mandate; easier to maintain               |
| Math rendering        | Plain text formulas                          | LaTeX `$$` does not render on GitHub               |

## 9. Scope Boundaries

To keep these plans focused, the following are **explicitly out of scope** and live
elsewhere:

- PFC Watchdog standalone tests — see `tests/pfcwd/`. Here we only test PFC/WD
  **interaction**.
- MACSEC + PFC — see [PFC_Snappi_Additional_Testcases.md](PFC_Snappi_Additional_Testcases.md).
- Port-channel PFC behavior — separate concern, separate plan.
- Buffer tuning/optimization — a configuration guide, not a test plan.
- Performance benchmarking beyond pass/fail — separate perf suite.
- SAI-level PFC tests — see `tests/saitests/`.

## 10. Known Limitations & Future Work

- PFC pause-frame validation requires single-tier (or T0-proxy) topology; pure T1
  validation is not possible due to the reserved destination MAC.
- Deadlock (L10) and link-flap (L11) cases depend on generator and platform
  capabilities; they are marked P2 and may be skipped on unsupported platforms.
- Absolute 0% thresholds may need a small, explicitly-documented tolerance on some
  hardware; any tolerance must be justified in the test, not silently widened.
- These plans describe **what to verify**. The corresponding pytest implementation
  is delivered in a follow-up code change.

## 11. References

- [PFC_lossless_test_plan.md](PFC_lossless_test_plan.md)
- [PFC_lossy_test_plan.md](PFC_lossy_test_plan.md)
- [PFC-test-plan.md](PFC-test-plan.md) (legacy 2020 plan; frame diagrams, Keysight config)
- [PFC_Snappi_Additional_Testcases.md](PFC_Snappi_Additional_Testcases.md) (multi-ASIC, MACSEC, ECN, PFCWD, port-channel)
- IEEE 802.1Qbb — Priority-based Flow Control
- IEEE 802.3x — Link-level Flow Control (global PAUSE)
- RFC 8782 / RoCEv2 — RDMA over Converged Ethernet
