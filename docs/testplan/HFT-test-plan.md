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
1. Set up a HFT profile with 10ms poll interval (10000 μs).
2. Configures specific ports and counters to monitor.
3. Run countersyncd for 120 seconds to capture telemetry data.
4. Validate telemetry output.

