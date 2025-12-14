# Test Plan for High Frequency Telemetry 

- [Overview](#overview)
  - [Scope](#scope)
  - [Supported Counters](#supported-counters)
- [Setup Configuration](#setup-configuration)
  - [Prerequisites](#prerequisites)
  - [Platform Support](#platform-support)
- [Test Cases](#test-cases)
  - [Basic Functionality Tests](#basic-functionality-tests)
    - [Test HFT Port Counters](#test-hft-port-counters)
    - [Test HFT Queue Counters](#test-hft-queue-counters)
    - [Test HFT Full Port Counters](#test-hft-full-port-counters)
  - [State Transition Tests](#state-transition-tests)
    - [Test HFT Disabled Stream](#test-hft-disabled-stream)
    - [Test HFT Config Deletion Stream](#test-hft-config-deletion-stream)
    - [Test HFT Poll Interval Validation](#test-hft-poll-interval-validation)
    - [Test HFT Port Shutdown Stream](#test-case-test-hft-port-shutdown-stream)
    
---

## Overview

This test plan outlines the approach for validating the [High Frequency Telemetry (HFT)](https://github.com/sonic-net/SONiC/blob/master/doc/high-frequency-telemetry/high-frequency-telemetry-hld.md) feature in SONiC. 

The tests verify that the system can accurately collect, transmit, and process real-time telemetry data. HFT enables microsecond-level polling and streaming of network statistics, supporting advanced monitoring and analytics.

---

### Scope

The test suite covers:
- Validation of new test fixtures, utilities, and test cases relating to HFT.
- Verification that dummy HFT config generation is functioning for platforms that support it.
- Ensuring proper setup and cleanup for HFT test environments.
- Validation of skip conditions for unsupported hardware platforms.

---

### Supported counters

**Phase 1**: Implement core HFT functionality. Support key AI DC stats: PORT, QUEUE, INGRESS_PRIORITY_GROUP, BUFFER_POOL

- SAI_PORT_STAT_IF_IN_OCTETS
- SAI_PORT_STAT_IF_IN_UCAST_PKTS
- SAI_PORT_STAT_IF_IN_DISCARDS
- SAI_PORT_STAT_IF_IN_ERRORS
- SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES
- SAI_PORT_STAT_IF_OUT_OCTETS
- SAI_PORT_STAT_IF_OUT_DISCARDS
- SAI_PORT_STAT_IF_OUT_ERRORS
- SAI_PORT_STAT_IF_OUT_UCAST_PKTS
- SAI_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES
- SAI_PORT_STAT_TRIM_PACKETS
- SAI_QUEUE_STAT_PACKETS
- SAI_QUEUE_STAT_BYTES
- SAI_QUEUE_STAT_DROPPED_PACKETS
- SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES
- SAI_QUEUE_STAT_WATERMARK_BYTES
- SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS
- SAI_QUEUE_STAT_TRIM_PACKETS
- SAI_BUFFER_POOL_STAT_DROPPED_PACKETS
- SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES
- SAI_BUFFER_POOL_STAT_WATERMARK_BYTES
- SAI_BUFFER_POOL_STAT_XOFF_ROOM_WATERMARK_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS
- SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES
- SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS

---

## Setup Configuration
### Prerequisites
- Validate that HFT dummy tables are added to config DB for supported platforms by running golden config DB generation and inspecting contents.
- Confirm SWSS container readiness and stability before each test by exercising the `ensure_swss_ready` fixture.
- Confirm that all relevant cleanup is performed prior to executing each test via the `cleanup_high_frequency_telemetry` fixture, ensuring no stale HFT data exists.

### Platform Support
- **Primary Platform**: Mellanox SN5600 (`nvidia_sn5600`)
- **Minimum Ports**: 1 active port required

---

## Test cases
### Basic Functionality Tests
#### Test Case: Test HFT Port Counters
**Objective**

Checks the basic functionality of high-frequency telemetry on port counters.

**Test Steps**

1. Set up an HFT profile for ports and enable the streaming.
2. Assign monitor targets (ports), and specific counters (e.g., `IF_IN_OCTETS`).
3. Run the counter sync daemon and capture output.
4. Validate that the counter values are being reported and are increasing as expected.
5. Cleanup of test profiles/groups afterwards.

**Validation**

All monitored counters report values > 0 and message rates match expectations.

#### Test Case: Test HFT Queue Counters *Currently Skipped*
**Objective**

Validate HFT for queue counters. This test demonstrates a different configuration with queue objects.

**Skip Reason**

Queue-based HFT not yet supported.

**Test Steps**
1. Get available ports from topology (try for 2 ports, min 1 required).
2. Set up a HFT profile with different poll intervals.
3. Configure queue group with format `{port}|{queue_index}`.
4. Monitor `QUEUE_STAT_PACKETS` counter.
5. Run countersyncd for 120 seconds to capture telemetry data.
6. Parse and validate queue counter output.

#### Test Case: Test HFT Full Port Counters *Currently Skipped*
**Objective**

Validate HFT when monitoring all available port counters on all avilable ports.

**Skip Reason**

Some PORT stats not yet supported.

**Test Steps**:

1. Set up an HFT profile with all available counters.
2. Validate correct application and functioning by verifying at least one counter per port is being reported and that coverage is close to expectations.

### State Transition Tests
#### Test Case: Test HFT Disabled Stream
**Objective**

Check dynamic enabling/disabling of HFT stream and how it affects message rate output (`Msg/s`).

**Test Phases** (60s each):

1. Set up a continuous countersyncd process.
2. Dynamically change stream state (enabled → disabled → enabled).
3. Validate that message rate drops to `0` when disabled, then resumes.

**Validation** 

Asserts message rate is nonzero when enabled, zero when disabled.

#### Test Case: Test HFT Config Deletion Stream 
**Objective**

Validate HFT configuration lifecycle (create → delete → recreate) and verify countersyncd correctly responds to dynamic CONFIG_DB changes without requiring process restart.

**Test Phases** (60s each):

1. Create profile/group and monitor counters (`Msg/s` > 0).
2. Delete config and verify telemetry output halts (`Msg/s` = 0).
3. Recreate config and validate resumption of telemetry output.

**Validation** 

Phased transition and output as expected.

#### Test Case: Test HFT Poll Interval Validation
**Objective**

Ensure correct mapping between configured polling interval (in microseconds) and message rate, across a range of values.

**Test Steps**:

1. For each interval (1ms, 10ms, 100ms, 1s, 10s, etc.), configure HFT.
2. Validate the measured message rate is within tolerance of theoretical expectation.

**Validation** 

Uses tolerance bands (`±20%`, `±30%`, `±50%` based on message rate) to account for system variation.

#### Test Case: Test HFT Port Shutdown Stream
**Objective**

Verifies correct HFT counter behavior as monitored port is shut down and restarted while test traffic is running via PTF.

**Test Steps**:

1. Configure HFT for a test port.
2. Phase 1: Port up, traffic injected, counters should increase.
3. Phase 2: Port down, traffic continues, counters should be flat/stable.
4. Phase 3: Port up again, counters should resume increasing.

**Validation** 

For each phase, checks the expected trend (increasing or stable) of counters.

---

## Skipped Tests

Some tests are decorated with `@pytest.mark.skip` due to lack of feature support or partial DUT/platform support:

- **`test_hft_queue_counters`**: Queue-based HFT not yet supported.
- **`test_hft_full_port_counters`**: Not all port stats/counters supported on all platforms.
- **`test_hft_poll_interval_validation`**: Some DUTs may not support shorter intervals.

Remove/comment out the `@pytest.mark.skip` annotation to enable once support is confirmed.

---
