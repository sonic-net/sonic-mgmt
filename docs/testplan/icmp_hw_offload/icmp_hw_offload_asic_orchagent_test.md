# ICMP Hardware Offload Orchestrator Test Plan

## Table of Contents

- [Revision History](#revision-history)
- [Test Plan Overview](#test-plan-overview)
  - [Objective](#objective)
  - [Scope](#scope)
  - [Background](#background)
- [Test Topology](#test-topology)
  - [SNAPPI Testbed Setup](#snappi-testbed-setup)
  - [Physical Topology](#physical-topology)
  - [Logical Architecture](#logical-architecture)
  - [Topology Requirements](#topology-requirements)
- [System Architecture](#system-architecture)
  - [Data Flow Overview](#data-flow-overview)
  - [Session Types](#session-types)
  - [Session Configuration](#session-configuration)
  - [ICMP Payload Structure](#icmp-payload-structure)
- [Test Cases](#test-cases)
  - [Test Case 1: Session Creation and State Detection](#test-case-1-session-creation-and-state-detection)
  - [Test Case 2: TX Interval Validation](#test-case-2-tx-interval-validation)
  - [Test Case 3: RX Interval with Variable FPS](#test-case-3-rx-interval-with-variable-fps)
- [Test Execution](#test-execution)
  - [Prerequisites](#prerequisites)
  - [Running the Tests](#running-the-tests)
  - [Test Fixtures](#test-fixtures)
- [Debugging and Troubleshooting](#debugging-and-troubleshooting)
  - [Common Issues](#common-issues)
  - [Log Collection](#log-collection)
- [Related Documentation](#related-documentation)
- [Appendix](#appendix)
  - [A. Test Script Organization](#a-test-script-organization)
  - [B. APP_DB Schema](#b-app_db-schema)
  - [C. STATE_DB Schema](#c-state_db-schema)
  - [D. ICMP Packet Format](#d-icmp-packet-format)
  - [E. Test Coverage Matrix](#e-test-coverage-matrix)
  - [F. Performance Expectations](#f-performance-expectations)
- [Summary](#summary)

---

## Revision History

| Rev | Date | Author | Change Description |
|-----|------|--------|-------------------|
| 0.1 | Jan 2026 | Harjot Singh| Initial version |

## Test Plan Overview

### Objective

This test plan validates the **ICMP Hardware Offload Orchestrator** functionality in SONiC by verifying:
1. ICMP session creation and configuration in APP_DB
2. ASIC programming by the orchestrator (orchagent)
3. Session state tracking and updates in STATE_DB
4. Timeout detection and state transitions based on received ICMP packets

### Scope

#### In Scope

- ICMP session creation and deletion via APP_DB
- NORMAL session type (active probing)
- RX session type (passive monitoring)
- Session state transitions (Up/Down) based on ICMP traffic
- Timeout detection with various `tx_interval` and `rx_interval` values
- ICMP payload structure validation (session GUID embedding)
- Hardware offload verification using traffic generator (IXIA/Snappi)

#### Out of Scope

- Software-based ICMP ping functionality
- ICMP packet routing and forwarding (handled by BGP/routing tests)
- Performance benchmarking
- Multi-ASIC or distributed system configurations

### Background

The ICMP Hardware Offload feature enables SONiC switches to handle ICMP-based link probing directly in hardware (ASIC) rather than software, providing:
- **Lower latency** for link state detection (sub-millisecond)
- **Reduced CPU overhead** on the switch control plane
- **More reliable heartbeat monitoring** for dual-ToR (Top-of-Rack) high-availability deployments

The ICMP orchestrator (`icmporch`) acts as the control plane component that:
1. Reads ICMP session configurations from **APP_DB** (created by applications or tests)
2. Programs the **ASIC** via SAI API to handle ICMP packets in hardware
3. Monitors received ICMP packets matched to sessions
4. Updates **STATE_DB** with real-time session state (Up/Down)
5. Detects timeouts when expected ICMP packets stop arriving

---

## Test Topology

### SNAPPI Testbed Setup 

Please use folllowing link to properly setup snappi testbed 
https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Keysight.md

### Physical Topology

The test requires a **T0 topology** with at least one DUT interface connected to an IXIA traffic generator:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                          Test Server                            │
│                                                                 │
│  ┌──────────────────┐         ┌──────────────────────┐          │
│  │  Ansible/pytest  │         │  IXIA API Server     │          │
│  │   (sonic-mgmt)   │         │   (Snappi backend)   │          │
│  └────────┬─────────┘         └───────────┬──────────┘          │
│           │ SSH/API                       │ API                 │
└───────────┼───────────────────────────────┼─────────────────────┘
            │                               │
            │                               │
            ├───────────────────────────────┤
            │                               │
            ▼                               ▼
  ┌─────────────────────┐         ┌──────────────────────┐
  │                     │         │                      │
  │    SONiC DUT        │◄───────►│  IXIA Chassis/VM     │
  │  (Device Under Test)│         │  (Traffic Generator) │
  │                     │         │                      │
  └─────────────────────┘         └──────────────────────┘
           │                               │
           │  Ethernet16                   │  Port1
           │  (192.16.2.1/24)              │  (192.16.2.100/24)
           │                               │
           └───────────────────────────────┘
              Physical or Virtual Link
```

### Logical Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ SONiC DUT                                                        │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌─────────────────┐   │
│  │   APP_DB     │────►│  ORCHAGENT   │────►│   STATE_DB      │   │
│  │  (ICMP       │     │  (Programs   │     │  (Session State:│   │
│  │   Session    │     │   ASIC via   │     │   Up/Down)      │   │
│  │   Config)    │     │   SAI API)   │     │                 │   │
│  └──────▲───────┘     └───────┬──────┘     └─────────────────┘   │
│         │                     │                                  │
│         │                     │                                  │
│    ┌────┴────────┐     ┌──────▼─────────────────────┐            │
│    │ icmporch_   │     │        ASIC/SAI            │            │
│    │   util.py   │     │   (Hardware Offload)       │            │
│    │ (Test Tool) │     │  - ICMP packet matching    │            │
│    └─────────────┘     │  - Session GUID detection  │            │
│                        │  - State tracking          │            │
│                        └───────┬────────────────────┘            │
│                                │                                 │
└────────────────────────────────┼─────────────────────────────────┘
                                 │
                  Ethernet16 (192.16.2.1/24)
                                 │
                                 │ ICMP Echo Request/Reply
                                 │ (Carries session GUID in payload)
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│ IXIA Traffic Generator (192.16.2.100/24)                         │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  IXIA Host Device (Emulated Network Host)                   │ │
│  │  - Responds to ARP requests                                 │ │
│  │  - Automatically responds to ICMP Echo Requests from DUT    │ │
│  │  - Used for NORMAL session testing                          │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  RX Stream (Continuous ICMP Echo Reply)                     │ │
│  │  - Sends unsolicited ICMP Echo Replies to DUT               │ │
│  │  - 20 PPS (1 packet every 50ms)                             │ │
│  │  - Embeds unique session GUID in payload                    │ │
│  │  - Used for RX session testing                              │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Topology Requirements

| Component | Requirement | Details |
|-----------|-------------|---------|
| **Topology Type** | T0 | Standard leaf switch topology |
| **DUT Interfaces** | Minimum 1 | At least one interface connected to IXIA |
| **IXIA Ports** | Minimum 1 | Traffic generator port for ICMP streams |
| **Network** | IPv4 subnet | e.g., 192.16.2.0/24 |
| **DUT Software** | ICMP orchestrator support | orchagent with icmporch compiled |
| **Snappi Version** | ≥ 1.42.1 | snappi and snappi_ixnetwork packages |

---

## System Architecture

### Data Flow Overview

```
   Test Script                  SONiC DUT                    IXIA
      (pytest)                   (orchagent)              (Traffic Gen)
         │                           │                         │
    ┌────▼──────────────┐            │                         │
    │1. Create Session  │            │                         │
    │   in APP_DB       │────────────┼────────────────────────►│
    │ (icmporch_util.py)│            │                         │
    └────┬──────────────┘            │                         │
         │                    ┌──────▼───────┐                 │
         │                    │2. icmporch   │                 │
         │                    │   reads      │                 │
         │                    │   APP_DB     │                 │
         │                    └──────┬───────┘                 │
         │                           │                         │
         │                    ┌──────▼───────────┐             │
         │                    │3. Programs ASIC  │             │
         │                    │   with session   │             │
         │                    │   config via SAI │             │
         │                    └──────────────────┘             │
         │                           │                         │
    ┌────▼──────────────┐            │                         │
    │4. Start ICMP      │            │                         │
    │   traffic on IXIA │────────────┼────────────────────────►│
    └───────────────────┘            │                         │
         │                           │                ┌────────▼────────┐
         │                           │                │5a. IXIA Host    │
         │                           │                │    responds to  │
         │                           │◄───────────────┤    DUT ICMP Req │
         │                           │   ICMP Reply   └─────────────────┘
         │                           │                         │
         │                           │                ┌────────▼────────┐
         │                           │◄───────────────┤5b. RX Stream    │
         │                           │  ICMP Reply    │    sends        │
         │                           │  (unsolicited) │    continuous   │
         │                    ┌──────▼───────┐        │    replies      │
         │                    │6. ASIC matches│       └─────────────────┘
         │                    │   packet to   │                │
         │                    │   session GUID│                │
         │                    └──────┬───────┘                 │
         │                           │                         │
         │                    ┌──────▼───────────┐             │
         │                    │7. Updates        │             │
         │                    │   STATE_DB       │             │
         │                    │   (Session: Up)  │             │
         │                    └──────────────────┘             │
         │                           │                         │
    ┌────▼──────────────┐            │                         │
    │8. Query STATE_DB  │            │                         │
    │   and verify      │◄───────────┤                         │
    │   session state   │            │                         │
    └───────────────────┘            │                         │
```

### Session Types

The orchestrator supports two types of ICMP sessions:

| Session Type | Direction | Behavior | Use Case |
|--------------|-----------|----------|----------|
| **NORMAL** | Bidirectional | DUT sends ICMP Echo Requests at configured interval (`tx_interval`), expects replies within timeout (`rx_interval`) | Active link probing, heartbeat monitoring |
| **RX** | Unidirectional | DUT only receives ICMP Echo Replies, expects packets within timeout (`rx_interval`), does not send requests | Passive monitoring of peer heartbeats |

### Session Configuration

Sessions are stored in APP_DB with the following key format:
```
ICMP_ECHO_SESSION_TABLE:{vrf}:{interface}:{session_guid}:{type}
```

**Example Keys:**
```
ICMP_ECHO_SESSION_TABLE:default:Ethernet16:0x55555556:NORMAL
ICMP_ECHO_SESSION_TABLE:default:Ethernet16:0x55555557:RX
```

**Configuration Fields:**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `tx_interval` | Integer (ms) | Interval for sending ICMP requests (0 for RX sessions) | `300` (300ms) |
| `rx_interval` | Integer (ms) | Timeout for receiving replies | `1500` (1.5s) |
| `session_cookie` | Hex String | Device-level ICMP offload identifier | `0x58767e7a` |
| `src_ip` | IPv4 Address | Source IP address for ICMP packets | `192.16.2.1` |
| `dst_ip` | IPv4 Address | Destination IP address | `192.16.2.100` |
| `src_mac` | MAC Address | Source MAC address | `40:14:82:f7:55:90` |
| `dst_mac` | MAC Address | Destination MAC address | `02:42:f0:00:00:02` |

### ICMP Payload Structure

ICMP Echo Request/Reply packets contain a structured payload matching the **LinkProberHw specification**:

```
Byte Offset    Field Name        Size      Value           Description
───────────────────────────────────────────────────────────────────────
0-3            Cookie            4 bytes   0x58767e7a      Device-level config ID
4-7            Version           4 bytes   0x00000000      Protocol version
8-11           GUID MSB          4 bytes   varies          Session ID (upper 32 bits)
12-15          GUID LSB          4 bytes   varies          Session ID (lower 32 bits)
16-23          Sequence          8 bytes   0x0000000000    Packet sequence (set to 0)
24             TLV Type          1 byte    0xFF            Sentinel marker
25-26          TLV Length        2 bytes   0x0000          TLV length field
27-39          Padding           13 bytes  0x00...         Pad to 40 bytes minimum
```

**GUID (Session Identifier):**
- 64-bit unique identifier for the session
- Embedded in every ICMP packet for session matching
- The ASIC uses this to associate received packets with configured sessions
- Critical for state tracking in STATE_DB

---

## Test Cases

### Test Case 1: Session Creation and State Detection

**Test Function:** `test_icmp_orchestrator_session_creation_and_state_detection`

**Objective:** Validates the complete end-to-end ICMP orchestrator functionality including session creation, ASIC programming, state tracking, and timeout detection.

**Test Topology:**
```
      DUT (192.16.2.1)                IXIA (192.16.2.100)
         │                                 │
         │  ┌──────────────────────────┐   │
         │  │ NORMAL Session           │   │
         ├──┤ - DUT sends ICMP Request ├──►│ IXIA Host
         │◄─┤ - IXIA responds          │◄──┤ (auto-responds)
         │  │ - tx_interval: 300ms     │   │
         │  │ - rx_interval: 1500ms    │   │
         │  └──────────────────────────┘   │
         │                                 │
         │  ┌──────────────────────────┐   │
         │  │ RX Session               │   │
         │◄─┤ - IXIA sends unsolicited ├───┤ RX Stream
         │  │   ICMP Replies (20 PPS)  │   │ (continuous)
         │  │ - rx_interval: 1500ms    │   │
         │  └──────────────────────────┘   │
```

**Prerequisites:**
- T0 topology with DUT connected to IXIA
- Snappi packages ≥ 1.42.1
- DUT interface configured with IP address

**Test Steps:**

1. **Setup Phase**
   - Initialize ICMP session manager
   - Discover DUT interface connected to IXIA
   - Configure IP addresses on DUT interface (e.g., 192.16.2.1/24)
   - Create NORMAL and RX sessions in APP_DB

2. **Traffic Configuration**
   - Configure IXIA host to respond to DUT ICMP requests (for NORMAL session)
   - Create RX stream sending continuous ICMP Echo Replies (20 PPS)
   - Apply configuration and wait for ARP resolution

3. **State Transition Testing - Sessions UP**
   - Start IXIA traffic streams
   - Wait 5 seconds for sessions to stabilize
   - Query STATE_DB for both sessions
   - **Verify:** NORMAL session state = `Up`
   - **Verify:** RX session state = `Up`
   - Let traffic run for 5 more seconds to verify stability

4. **State Transition Testing - RX Session DOWN**
   - Stop all IXIA traffic streams
   - Wait 5 seconds for timeout detection
   - Query STATE_DB for RX session
   - **Verify:** RX session state = `Down`

5. **Cleanup**
   - Remove test sessions from APP_DB
   - Remove IP configuration from DUT interface

**Expected Results:**

| Test Step | Assertion | Expected Value |
|-----------|-----------|----------------|
| After traffic starts | Normal session state | `Up` |
| After traffic starts | RX session state | `Up` |
| After traffic stops | RX session state | `Down` |

**Pass Criteria:**
- All three assertions pass
- No errors in orchagent logs during session creation/deletion
- STATE_DB updates occur within expected timeframes

**What This Proves:**
1. Orchestrator correctly reads session config from APP_DB
2. Orchestrator programs ASIC with session parameters
3. ASIC correctly matches received ICMP packets to sessions via GUID
4. Orchestrator correctly updates STATE_DB based on packet reception
5. Timeout detection works correctly when packets stop

---

### Test Case 2: TX Interval Validation

**Test Function:** `test_icmp_orchestrator_tx_interval_values`

**Objective:** Validates that NORMAL sessions work correctly with different probing intervals (`tx_interval`).

**Test Matrix:**

| Test | tx_interval | Packet Rate | Expected State | Rationale |
|------|-------------|-------------|----------------|-----------|
| Fast | 3ms | ~333 PPS | Up | Very fast probing |
| Slow | 1200ms | ~0.83 PPS | Up | Slow probing |

**Test Flow:**

```
For each tx_interval value:
   │
   ├─► 1. Create NORMAL session with specified tx_interval
   │
   ├─► 2. Configure IXIA host to respond to DUT requests
   │
   ├─► 3. Start traffic and wait 5 seconds
   │
   ├─► 4. Verify session state = Up
   │
   ├─► 5. Wait 5 more seconds
   │
   ├─► 6. Verify session still Up (stable)
   │
   ├─► 7. Stop traffic and cleanup session
   │
   └─► Repeat for next tx_interval
```

**Prerequisites:**
- Same as Test Case 1

**Expected Results:**

| tx_interval | Expected State | Stability Check |
|-------------|----------------|-----------------|
| 3ms | Up | Remains Up after 5s |
| 1200ms | Up | Remains Up after 5s |

**Pass Criteria:**
- Sessions come UP regardless of tx_interval value
- Sessions remain stable (don't flap)
- No packet loss or timeout errors

**What This Proves:**
1. Orchestrator handles various probing rates correctly
2. No timing issues with fast intervals (3ms)
3. No timeout issues with slow intervals (1200ms)
4. ASIC can process ICMP at different rates

---

### Test Case 3: RX Interval with Variable FPS

**Test Function:** `test_icmp_orchestrator_rx_interval_with_fps`

**Objective:** Validates RX session timeout detection based on the relationship between `rx_interval` and incoming packet rate (fps).

**Test Matrix:**

| Test | rx_interval | FPS | Packet Interval | Expected State | Logic |
|------|-------------|-----|-----------------|----------------|-------|
| 1 | 9ms | 111 | ~9ms | Up | Packets arrive within timeout |
| 2 | 500ms | 2 | 500ms | Up | Packets arrive just within timeout |

**Traffic Pattern Visualization:**

```
Test 1: rx_interval=9ms, FPS=111 (~9ms interval)
Packets:  ↓    ↓    ↓    ↓    ↓    ↓    ↓    ↓
Time:    0ms  9ms  18ms 27ms 36ms 45ms 54ms 63ms
Result:  Packets arrive within 9ms window → Session UP

Test 2: rx_interval=500ms, FPS=2 (500ms interval)
Packets:  ↓          ↓          ↓          ↓
Time:    0ms       500ms      1000ms     1500ms
Result:  Packets arrive at 500ms boundary → Session UP

After traffic stops:
Packets:  ↓          X (no more packets)
Time:    0ms       500ms+     (timeout)
Result:  No packets received within rx_interval → Session DOWN
```

**Test Flow:**

```
For each test case:
   │
   ├─► 1. Create RX session with specified rx_interval
   │
   ├─► 2. Create RX stream with specified FPS
   │
   ├─► 3. Start traffic and wait 5 seconds
   │
   ├─► 4. Verify session state matches expected (Up)
   │
   ├─► 5. Stop traffic
   │
   ├─► 6. Wait for timeout (5 seconds)
   │
   ├─► 7. Verify session goes Down
   │
   ├─► 8. Cleanup session
   │
   └─► Repeat for next test case
```

**Prerequisites:**
- Same as Test Case 1

**Expected Results:**

| rx_interval | FPS | During Traffic | After Stop |
|-------------|-----|----------------|------------|
| 9ms | 111 | Up | Down |
| 500ms | 2 | Up | Down |

**Pass Criteria:**
- Sessions come UP when packets arrive within rx_interval
- Sessions go DOWN after traffic stops and timeout expires
- State transitions occur within expected timeframes

**What This Proves:**
1. Orchestrator correctly tracks packet arrival timing
2. Timeout detection works for various rx_interval values
3. Fast timeout detection (9ms) works correctly
4. Slow timeout detection (500ms) works correctly
5. Session goes DOWN reliably when packets stop

---

## Test Execution

### Prerequisites

#### Software Requirements

| Component | Version | Installation |
|-----------|---------|--------------|
| snappi | ≥ 1.42.1 | `pip install snappi>=1.42.1` |
| snappi_ixnetwork | ≥ 1.42.1 | `pip install snappi_ixnetwork>=1.42.1` |
| netaddr | Latest | `pip install netaddr` |
| pytest | Latest | Included in sonic-mgmt |

#### Hardware/Topology Requirements

| Component | Requirement |
|-----------|-------------|
| Topology | T0 |
| DUT Ports | Minimum 1 connected to IXIA |
| IXIA Ports | Minimum 1 |
| DUT Software | SONiC image with ICMP orchestrator support |

#### DUT Requirements

- ICMP orchestrator (`icmporch`) compiled and running in orchagent
- At least one interface available for testing
- Interface must support IP configuration
- SSH access from test server

### Running the Tests

#### Run All Tests

```bash
cd sonic-mgmt/tests
pytest snappi_tests/test_orchagent_icmp_hw_offload.py -v
```

#### Run Specific Test

```bash
# Test 1: Session creation and state detection
pytest snappi_tests/test_orchagent_icmp_hw_offload.py::test_icmp_orchestrator_session_creation_and_state_detection -v

# Test 2: TX interval validation
pytest snappi_tests/test_orchagent_icmp_hw_offload.py::test_icmp_orchestrator_tx_interval_values -v

# Test 3: RX interval with FPS
pytest snappi_tests/test_orchagent_icmp_hw_offload.py::test_icmp_orchestrator_rx_interval_with_fps -v
```

#### Run with Custom Options

```bash
# Run with detailed logging
pytest snappi_tests/test_orchagent_icmp_hw_offload.py -v -s --log-cli-level=INFO

# Run with specific DUT
pytest snappi_tests/test_orchagent_icmp_hw_offload.py --inventory=inventory.yml --host-pattern=dut1 -v
```

### Test Fixtures

The test uses the following pytest fixtures:

| Fixture | Scope | Purpose |
|---------|-------|---------|
| `duthost` | Function | DUT host connection |
| `snappi_api` | Function | Snappi API instance |
| `snappi_testbed_config` | Function | IXIA testbed configuration |
| `conn_graph_facts` | Function | Connection graph information |
| `fanout_graph_facts` | Function | Fanout connection details |
| `setup_icmp_sessions` | Function | ICMPSessionManager instance with cleanup |
| `create_test_sessions` | Function | Pre-configured test sessions |
| `apply_mock_dual_tor_tables` | Function | Dual-ToR mock tables |
| `apply_mock_dual_tor_kernel_configs` | Function | Dual-ToR kernel configs |

---

## Debugging and Troubleshooting

### Common Issues

#### Issue 1: Snappi Version Too Old

**Symptom:**
```
SKIPPED [1] test_orchagent_icmp_hw_offload.py: snappi version X.Y.Z is older than required minimum version 1.42.1
```

**Solution:**
```bash
pip install --upgrade snappi>=1.42.1 snappi_ixnetwork>=1.42.1
```

#### Issue 2: Session State Not Updating

**Symptom:** Session remains in initial state, doesn't transition to Up

**Debug Steps:**
1. Check if icmporch is running:
   ```bash
   docker exec -it swss bash
   ps aux | grep icmporch
   ```

2. Check APP_DB session configuration:
   ```bash
   redis-cli -n 0 KEYS "ICMP_ECHO_SESSION_TABLE:*"
   redis-cli -n 0 HGETALL "ICMP_ECHO_SESSION_TABLE:default:Ethernet16:0x55555556:NORMAL"
   ```

3. Check STATE_DB for session state:
   ```bash
   redis-cli -n 6 KEYS "ICMP_ECHO_SESSION_STATE_TABLE:*"
   redis-cli -n 6 HGETALL "ICMP_ECHO_SESSION_STATE_TABLE:default:Ethernet16:0x55555556:NORMAL"
   ```

4. Check orchagent logs:
   ```bash
   docker exec -it swss tail -f /var/log/swss/sairedis.rec
   docker logs swss 2>&1 | grep -i icmp
   ```

#### Issue 3: IXIA Host Not Responding

**Symptom:** NORMAL session doesn't come UP, no ICMP replies from IXIA

**Debug Steps:**
1. Verify ARP resolution:
   ```bash
   show arp
   ```

2. Check IXIA configuration:
   - Verify IXIA host IP configuration
   - Verify gateway IP points to DUT
   - Check IXIA port link status

3. Capture packets on DUT:
   ```bash
   sudo tcpdump -i Ethernet16 -vvv icmp
   ```

### Log Collection

Collect the following logs for troubleshooting:

```bash
# DUT logs
show logging
docker logs swss
docker logs syncd

# Redis databases
redis-cli -n 0 KEYS "*ICMP*"  # APP_DB
redis-cli -n 6 KEYS "*ICMP*"  # STATE_DB

# Test execution logs
pytest snappi_tests/test_orchagent_icmp_hw_offload.py -v -s --log-cli-level=DEBUG > test_output.log 2>&1
```

---

## Related Documentation

- [SONiC ICMP Hardware Offload Feature HLD](https://wwwin-github.cisco.com/harjosin/DOCS/blob/master/icmp_hwoffload_test.md)
- [Snappi API Documentation](https://github.com/open-traffic-generator/snappi)
- [SONiC Test Framework Guide](../../docs/tests/README.md)
- [Pytest Best Practices](../../docs/tests/guidelines.md)

---

## Appendix

### A. Test Script Organization

```
sonic-mgmt/tests/snappi_tests/
├── test_orchagent_icmp_hw_offload.py    # Main test script
├── ICMP_HW_OFFLOAD_TEST_DOCUMENTATION.md # This document
└── files/
    └── icmporch_util.py                  # Redis utility script
```

### B. APP_DB Schema

**Table:** `ICMP_ECHO_SESSION_TABLE`

**Key Format:** `{vrf}:{interface}:{session_guid}:{type}`

**Fields:**
```json
{
  "tx_interval": "<milliseconds>",
  "rx_interval": "<milliseconds>",
  "session_cookie": "<hex_string>",
  "src_ip": "<ipv4_address>",
  "dst_ip": "<ipv4_address>",
  "src_mac": "<mac_address>",
  "dst_mac": "<mac_address>"
}
```

### C. STATE_DB Schema

**Table:** `ICMP_ECHO_SESSION_STATE_TABLE`

**Key Format:** `{vrf}|{interface}|{session_guid}|{type}`

**Fields:**
```json
{
  "state": "Up|Down",
  "last_update": "<timestamp>"
}
```

### D. ICMP Packet Format

```
Ethernet Header (14 bytes)
├── Destination MAC: <dut_interface_mac>
├── Source MAC: <remote_mac>
└── EtherType: 0x0800 (IPv4)

IPv4 Header (20 bytes)
├── Source IP: <remote_ip>
├── Destination IP: <dut_ip>
├── Protocol: 1 (ICMP)
└── TTL: 64

ICMP Header (8 bytes)
├── Type: 0 (Echo Reply) or 8 (Echo Request)
├── Code: 0
├── Checksum: <calculated>
├── Identifier: 0
└── Sequence: 0

ICMP Payload (40+ bytes)
├── Cookie: 0x58767e7a (4 bytes)
├── Version: 0x00000000 (4 bytes)
├── GUID MSB: <session_id_upper> (4 bytes)
├── GUID LSB: <session_id_lower> (4 bytes)
├── Sequence: 0x0000000000000000 (8 bytes)
├── TLV Type: 0xFF (1 byte)
├── TLV Length: 0x0000 (2 bytes)
└── Padding: 0x00... (13+ bytes)
```

### E. Test Coverage Matrix

| Feature | Test Case 1 | Test Case 2 | Test Case 3 |
|---------|-------------|-------------|-------------|
| Session creation | ✓ | ✓ | ✓ |
| Session deletion | ✓ | ✓ | ✓ |
| NORMAL session | ✓ | ✓ | - |
| RX session | ✓ | - | ✓ |
| State tracking (Up) | ✓ | ✓ | ✓ |
| State tracking (Down) | ✓ | - | ✓ |
| tx_interval variations | - | ✓ | - |
| rx_interval variations | - | - | ✓ |
| Timeout detection | ✓ | - | ✓ |
| GUID payload | ✓ | - | ✓ |
| Traffic generation | ✓ | ✓ | ✓ |

### F. Performance Expectations

| Metric | Expected Value | Notes |
|--------|----------------|-------|
| Session creation time | < 1 second | Time from APP_DB write to STATE_DB appearance |
| State transition time | < 100ms | Time from packet arrival to STATE_DB update |
| Timeout detection | rx_interval + 100ms | Time from last packet to DOWN state |
| Minimum tx_interval | 3ms | Fastest probing rate tested |
| Maximum tx_interval | 1200ms | Slowest probing rate tested |
| Minimum rx_interval | 9ms | Fastest timeout tested |
| Maximum rx_interval | 1500ms | Slowest timeout tested |

---

## Summary

This test plan validates the ICMP Hardware Offload Orchestrator by:

1. **Creating ICMP sessions** in APP_DB with various configurations (NORMAL and RX types)
2. **Generating ICMP traffic** via IXIA to simulate network conditions and peer responses
3. **Monitoring STATE_DB** to verify orchestrator correctly tracks session state changes
4. **Testing edge cases** with different timing parameters (tx_interval, rx_interval, fps)
5. **Verifying timeout detection** when packets stop arriving

The tests ensure the orchestrator correctly:
- ✓ Programs ASIC with session configurations via SAI API
- ✓ Detects incoming ICMP packets and matches them to sessions via GUID payload
- ✓ Updates session state based on packet reception timing
- ✓ Handles various probing rates (3ms to 1200ms intervals)
- ✓ Handles various timeout windows (9ms to 1500ms)
- ✓ Detects timeouts reliably when packets stop arriving
- ✓ Cleans up sessions properly on deletion

**Test Coverage:** 3 test cases covering 10+ scenarios with comprehensive validation of session lifecycle, state tracking, and timeout detection.
