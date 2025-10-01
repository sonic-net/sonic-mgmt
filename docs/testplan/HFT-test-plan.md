# Test Plan for High Frequency Telemetry 

- [Overview](#overview)
  - [Scope](#scope)
- [Setup configuration](#setup-configuration)
  - [Prerequisites](#prerequisites)
  - [Platform Support](#platform-support)
- [Test Cases](#test-cases)
  - [Basic Functionality Tests](#basic-functionality-tests)
	- [Test HFT Port Counters](Test-hft-port-counters)

## Overview

This test plan outlines the approach for validating the [High Frequency Telemetry (HFT)](https://github.com/sonic-net/SONiC/blob/master/doc/high-frequency-telemetry/high-frequency-telemetry-hld.md) feature in SONiC. 

The tests verify that the system can accurately collect, transmit, and process real-time telemetry data. HFT enables microsecond-level polling and streaming of network statistics, supporting advanced monitoring and analytics.

### Scope

The test suite covers:
- Port counter telemetry with configurable poll intervals
- Stream state transitions (enabled/disabled)
- Configuration lifecycle management (create/delete)
- Port state transitions during telemetry collection
- Poll interval validation at different frequencies
- Counter accuracy and data consistency

## Setup configuration
### Prerequisites
- Flex counters must be disabled during HFT tests to avoid conflicts
- SWSS container must be running and stable (uptime ≥ 10 seconds)
- CONFIG_DB must be accessible for HFT configuration

### Platform Support
- **Primary Platform**: Mellanox SN5600 (`nvidia_sn5600`)
- **Minimum Ports**: 1 active port required

## Test cases
### Basic Functionality Tests
#### Test Case: Test HFT Port Counters
**Objective**

Validate basic HFT functionality for port counters.

**Test Steps**
1. Get available ports from topology (try for 2 ports, min 1 required).
2. Set up a HFT profile with 10ms poll interval (10000 μs).
3. Configure port group with test ports monitoring `IF_IN_OCTETS`.
4. Run countersyncd for 120 seconds to capture telemetry data.
5. Parse and validate port counter output.

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

Validate HFT with all available port counters.

**Skip Reason**

Some PORT stats not yet supported.

**Monitored Counters**:
- `IF_IN_OCTETS`
- `IF_IN_UCAST_PKTS`
- `IF_IN_DISCARDS`
- `IF_IN_ERRORS`
- `IN_CURR_OCCUPANCY_BYTES`
- `IF_OUT_OCTETS`
- `IF_OUT_DISCARDS`
- `IF_OUT_ERRORS`
- `IF_OUT_UCAST_PKTS`
- `OUT_CURR_OCCUPANCY_BYTES`
- `TRIM_PACKETS`

### State Transition Tests
#### Test Case: Test HFT Disabled Stream
**Objective**

Validate HFT with disabled stream state transitions (enabled → disabled → enabled).

**Test Phases**:
1. **Phase 1** (60s): Stream enabled, active telemetry stream
   - Expected: Msg/s > 0, counters reporting
2. **Phase 2** (60s): Stream disabled
   - Expected: Msg/s = 0, no new data, silent stream
3. **Phase 3** (60s): Stream re-enabled, stream recovery with active data flow
   - Expected: Msg/s > 0, counters resume

