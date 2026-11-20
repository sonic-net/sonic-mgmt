# Link Event Damping Test Suite - README

## Overview

This document provides comprehensive documentation for the Link Event Damping test suite implemented in SONiC. The test suite validates the correctness, robustness, and compliance of the Link Event Damping feature with the High-Level Design (HLD).

**Test Suite Location**: `tests/link_event_damping/`

**Files**:
- `test_link_event_damping.py` - Main test file with 53 test cases
- `link_event_damping_utils.py` - Utility functions and helpers
- `conftest.py` - Pytest fixtures and configuration

**Topologies Supported**: T0, T1

---

## Prerequisites

### Hardware Requirements
- SONiC-supported switch with multiple Ethernet ports
- Fanout switch(es) for generating deterministic link flaps
- Access to front-facing interfaces (at least 2 for basic tests, 5+ for comprehensive tests)

### Software Requirements
- SONiC image with Link Event Damping support
- Access to:
  - SONiC CLI (config and show commands)
  - Redis databases (CONFIG_DB, APP_DB, STATE_DB)
  - Docker CLI for container restart tests
  - System logs

### Test Environment Setup
```bash
# Install sonic-mgmt test dependencies
pip install -r requirements.txt

# Verify test environment
pytest --version
python3 -m py_compile tests/link_event_damping/test_link_event_damping.py
```

---

## Quick Start

### Running All Tests
```bash
# Run all link event damping tests
pytest tests/link_event_damping/test_link_event_damping.py -v

# Run with detailed logging
pytest tests/link_event_damping/test_link_event_damping.py -v -s

# Run specific test class
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingBasics -v
```

### Running Specific Test Cases
```bash
# TC01.1 - Normal Link Flap Event Propagation
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingBasics::test_tc01_1_normal_link_flap_event_propagation -v

# TC02.1 - Basic Link Damping Configuration
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingConfiguration::test_tc02_1_basic_link_damping_configuration -v

# All TC03 (Unsupported Configuration) tests
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingUnsupported -v
```

### Test Execution with Topology
```bash
# Run tests on specific topology
pytest tests/link_event_damping/test_link_event_damping.py -v -k "topology"
```

---

## Test Cases Documentation

### Test Configuration Parameters

**Standard Damping Configuration (DAMPING_CONFIG_PARAMS)**:
```
suppress_threshold: 1600      # Penalty threshold to enter suppressed state
reuse_threshold: 1200         # Penalty threshold to exit suppressed state
decay_half_life: 15 seconds   # Time for penalty to decay by half
max_suppress_time: 30 seconds # Maximum suppression duration
flap_penalty: 500             # Penalty per link down event
```

---

## TC01: Normal Link Flap Event Propagation

**Objective**: Verify that link up/down events propagate normally when damping is inactive.

### TC01.1 - Normal Link Flap Event Propagation

**Procedure**:
1. Get a test interface from the DUT
2. Ensure damping is **disabled** on the interface
3. Record initial interface physical state
4. Generate 5 link flaps via fanout switch with 1 second interval
5. Monitor interface operational state
6. Retrieve pre-damping link transition counters
7. Verify operational state matches physical state

**Expected Results**:
- ✓ Damping is successfully disabled
- ✓ All physical link changes are propagated
- ✓ Pre-damping link transitions counter > 0
- ✓ Operational state matches physical state
- ✓ No events are suppressed

**Duration**: ~10 seconds

---

### TC01.2 - Multiple Sequential Flaps

**Procedure**:
1. Get a test interface
2. Disable damping on the interface
3. Clear all link damping statistics
4. Generate 10 sequential flaps with 0.5 second interval between flaps
5. Retrieve counters: pre-damping DOWN events and pre-damping UP events
6. Verify counter values

**Expected Results**:
- ✓ DOWN events counter ≥ (10/2) = 5
- ✓ UP events counter ≥ (10/2) = 5
- ✓ All flaps are recorded in statistics
- ✓ Counters reflect actual number of events

**Duration**: ~10 seconds

---

### TC01.3 - Simultaneous Flaps on Multiple Ports

**Procedure**:
1. Get 3 test interfaces from the DUT
2. Disable damping on all 3 interfaces
3. Clear statistics
4. Generate 3 link flaps with 0.5 second interval on all interfaces simultaneously
5. Verify each interface has recorded events independently

**Expected Results**:
- ✓ All 3 interfaces report pre-damping transitions > 0
- ✓ Each interface's counters are independent
- ✓ No counter cross-talk between interfaces
- ✓ Concurrent flaps handled correctly

**Duration**: ~5 seconds per interface

---

## TC02: Valid Damping Configuration

**Objective**: Verify that all damping parameters are configurable and persistent.

### TC02.1 - Basic Link Damping Configuration

**Procedure**:
1. Select a test interface
2. Configure damping with all parameters:
   - suppress_threshold: 1600
   - reuse_threshold: 1200
   - decay_half_life: 15 seconds
   - max_suppress_time: 30 seconds
   - flap_penalty: 500
3. Verify configuration was applied

**Expected Results**:
- ✓ Configuration command accepted
- ✓ No error messages in output
- ✓ Configuration parameters appear in CONFIG_DB
- ✓ Interface damping is now active

**Duration**: ~2 seconds

---

### TC02.2 - CONFIG_DB Persistence

**Procedure**:
1. Configure damping on a test interface with standard parameters
2. Query CONFIG_DB via `redis-cli -n 4 HGETALL 'LINK_DAMPING|<interface>'`
3. Verify all configuration parameters are present
4. Verify values match configured parameters

**Expected Results**:
- ✓ CONFIG_DB entry exists for interface
- ✓ All parameters are queryable
- ✓ Values match configuration
- ✓ persist flag is set (if applicable)

**Duration**: ~2 seconds

---

### TC02.3 - Redis Persistence

**Procedure**:
1. Configure damping on test interface
2. Query multiple Redis databases:
   - CONFIG_DB (index 4)
   - APP_DB (index 0)
   - STATE_DB (index 1)
3. Verify entries exist in appropriate databases
4. Validate configuration consistency across databases

**Expected Results**:
- ✓ CONFIG_DB has configuration entry
- ✓ APP_DB has operational entry (if applicable)
- ✓ STATE_DB has state entry (if applicable)
- ✓ Data is consistent across all databases

**Duration**: ~2 seconds

---

### TC02.4 - Multiple Configuration Profiles

**Procedure**:
1. Get 2 test interfaces
2. Apply different configurations to each:
   - Interface 1: suppress_threshold=1600, max_suppress_time=30
   - Interface 2: suppress_threshold=800, max_suppress_time=20
3. Query CONFIG_DB for both interfaces
4. Verify configurations are independent

**Expected Results**:
- ✓ Interface 1 has configuration with threshold=1600
- ✓ Interface 2 has configuration with threshold=800
- ✓ No cross-interference between configurations
- ✓ Both interfaces function independently

**Duration**: ~3 seconds

---

### TC02.5 - Individual Parameter Validation

**Procedure**:
1. Select a test interface
2. Configure each parameter individually:
   - suppress_threshold: 2000
   - reuse_threshold: 1500
   - decay_half_life: 20
   - max_suppress_time: 45
   - flap_penalty: 600
3. After each parameter, verify in CONFIG_DB
4. Repeat for each parameter

**Expected Results**:
- ✓ Each parameter is individually configurable
- ✓ Parameter changes don't affect others
- ✓ Values persist in CONFIG_DB
- ✓ No validation errors

**Duration**: ~5 seconds

---

### TC02.6 - Configuration Synchronization

**Procedure**:
1. Configure damping on test interface
2. Verify in CONFIG_DB (redis-cli -n 4)
3. Verify in APP_DB (redis-cli -n 0)
4. Verify in operational state (show commands if available)
5. Check all layers have synchronized data

**Expected Results**:
- ✓ CONFIG_DB has configuration
- ✓ APP_DB has synchronized copy
- ✓ Operational state reflects configuration
- ✓ All layers in sync within 1 second

**Duration**: ~2 seconds

---

## TC03: Unsupported Configuration Handling

**Objective**: Ensure unsupported damping configurations are handled safely.

### TC03.1 - Decay Exceeds Max Suppress Time

**Procedure**:
1. Select test interface
2. Configure with unsupported parameters:
   - decay_half_life: 45 seconds (> max_suppress_time of 30)
   - max_suppress_time: 30 seconds
3. Generate 5 link flaps with 0.5 second interval
4. Retrieve statistics:
   - pre_damping_link_transitions
   - post_damping_propagated_transitions
5. Compare event counts

**Expected Results**:
- ✓ Configuration is accepted (or gracefully rejected)
- ✓ Damping is **disabled** (unsupported config)
- ✓ All events are propagated
- ✓ post_damping_propagated ≈ pre_damping_link_transitions
- ✓ No suppression occurs

**Duration**: ~5 seconds

---

### TC03.2 - Zero Flap Penalty

**Procedure**:
1. Configure with flap_penalty: 0
2. Generate 5 link flaps
3. Verify configuration is accepted
4. Check if damping is disabled (penalty accumulation impossible)

**Expected Results**:
- ✓ Configuration is accepted
- ✓ No validation errors
- ✓ Damping functionality degrades gracefully (if applicable)

**Duration**: ~2 seconds

---

### TC03.3 - Suppress Less Than Reuse

**Procedure**:
1. Configure with invalid parameters:
   - suppress_threshold: 800 (less than reuse)
   - reuse_threshold: 1000
2. Attempt to apply configuration
3. Check for validation errors

**Expected Results**:
- ✓ Configuration either rejected OR handled gracefully
- ✓ Error message logged (if rejected)
- ✓ System remains stable

**Duration**: ~2 seconds

---

### TC03.4 - Zero Reuse Threshold

**Procedure**:
1. Configure with reuse_threshold: 0
2. Generate link flaps
3. Verify configuration is accepted
4. Check suppression behavior

**Expected Results**:
- ✓ Configuration is accepted
- ✓ System handles gracefully
- ✓ No crashes or errors

**Duration**: ~2 seconds

---

### TC03.6 - Zero Max Suppress Time

**Procedure**:
1. Configure with max_suppress_time: 0
2. Generate flaps to trigger suppression
3. Monitor suppression duration
4. Check system behavior

**Expected Results**:
- ✓ Configuration handled gracefully
- ✓ No infinite suppression
- ✓ System remains stable

**Duration**: ~2 seconds

---

### TC03.9 - Error Logging

**Procedure**:
1. Apply invalid configuration
2. Check system logs:
   - `/var/log/syslog`
   - `/var/log/swss.log`
   - `/var/log/syncd.log`
3. Verify appropriate error messages are logged

**Expected Results**:
- ✓ Error messages logged for invalid configs
- ✓ Messages are clear and actionable
- ✓ No spurious warnings for valid configs

**Duration**: ~2 seconds

---

## TC04: Multiple Ports with Mixed Damping Configuration

**Objective**: Verify independent behavior across multiple interfaces.

### TC04.1 - Basic Mixed Configuration

**Procedure**:
1. Get 2 test interfaces
2. Enable damping on interface 1 with standard parameters
3. Disable damping on interface 2
4. Verify both configurations independently

**Expected Results**:
- ✓ Interface 1 has damping enabled (CONFIG_DB verified)
- ✓ Interface 2 has damping disabled
- ✓ No cross-interference
- ✓ Independent operation confirmed

**Duration**: ~3 seconds

---

### TC04.2 - Simultaneous Flaps (Damped vs Undamped)

**Procedure**:
1. Get 2 interfaces (damped and undamped)
2. Configure as per TC04.1
3. Clear statistics on both
4. Generate 10 identical flaps simultaneously on both
5. Retrieve post-damping propagated transition counters

**Expected Results**:
- ✓ Undamped interface propagated_transitions ≈ 10
- ✓ Damped interface propagated_transitions < 10 (if suppression triggered)
- ✓ Undamped >= damped propagated events
- ✓ Independent damping verified

**Duration**: ~8 seconds

---

### TC04.3 - Different Damping Profiles

**Procedure**:
1. Get 2 interfaces
2. Apply Profile A to interface 1:
   - suppress_threshold: 1600
   - max_suppress_time: 30
3. Apply Profile B to interface 2:
   - suppress_threshold: 800
   - max_suppress_time: 20
4. Verify configurations in CONFIG_DB

**Expected Results**:
- ✓ Interface 1 has suppress_threshold=1600
- ✓ Interface 2 has suppress_threshold=800
- ✓ max_suppress_time values differ
- ✓ Different suppression behaviors expected

**Duration**: ~2 seconds

---

### TC04.4 - Port Independence

**Procedure**:
1. Get 3 interfaces
2. Enable damping on interface 1
3. Generate 10 flaps on interface 1 (may trigger suppression)
4. Check operational states of interfaces 2 and 3
5. Verify interfaces 2 and 3 are unaffected

**Expected Results**:
- ✓ Interface 2 and 3 operational states normal
- ✓ No flap-induced transitions on interfaces 2 and 3
- ✓ Complete port independence
- ✓ No crosstalk

**Duration**: ~8 seconds

---

### TC04.6 - Flap Pattern Comparison

**Procedure**:
1. Get 2 interfaces (damped and undamped)
2. Clear statistics
3. Generate flap pattern A: 5 rapid flaps (0.3s interval) + 5s pause + 2 sparse flaps
4. Observe event propagation on both interfaces
5. Compare propagated events

**Expected Results**:
- ✓ Damped interface suppresses more events (if pattern triggers threshold)
- ✓ Undamped interface propagates all events
- ✓ Counters show clear difference

**Duration**: ~20 seconds

---

### TC04.7 - Large-Scale Mixed Configuration

**Procedure**:
1. Get 10 interfaces
2. Alternately enable/disable damping:
   - Interfaces 1, 3, 5, 7, 9: damping enabled
   - Interfaces 2, 4, 6, 8, 10: damping disabled
3. Verify all 10 configurations independently
4. Verify CONFIG_DB has 10 entries (or subset per topology)

**Expected Results**:
- ✓ All 10 interfaces configured correctly
- ✓ Alternating pattern verified
- ✓ All configurations persisted
- ✓ No configuration errors
- ✓ System handles 10+ configurations

**Duration**: ~5 seconds

---

## TC05: Post-Damping Operational State Accuracy

**Objective**: Ensure operational state reflects physical state after damping ends.

### TC05.1 - Operational State Frozen During Suppression

**Procedure**:
1. Configure damping on test interface with standard parameters
2. Generate 5 rapid flaps (0.5s interval) to trigger suppression
3. **While suppression is active**:
   - Record operational state
   - Record physical state
4. Compare states during suppression
5. Verify physical and operational states diverge

**Expected Results**:
- ✓ Suppression is confirmed active
- ✓ Operational state ≠ Physical state (one is frozen)
- ✓ Operational state matches last propagated event
- ✓ Physical state reflects actual link condition
- ✓ Divergence confirmed during suppression

**Duration**: ~8 seconds

---

### TC05.2 - Operational State Updates After Suppression Ends

**Procedure**:
1. Configure damping and trigger suppression (as TC05.1)
2. Wait for suppression to end:
   - max_suppress_time = 30 seconds
   - Wait: 30 + 10 = 40 seconds (buffer for decay)
3. Verify suppression is no longer active
4. Record operational state
5. Record physical state
6. Compare states

**Expected Results**:
- ✓ Suppression is no longer active
- ✓ Operational state == Physical state
- ✓ State update occurred
- ✓ States are synchronized

**Duration**: ~50 seconds

---

### TC05.3 - Physical vs Operational State Divergence During Suppression

**Procedure**:
1. Enable damping on test interface
2. Record initial states
3. Generate 10 rapid flaps (0.3s interval) to trigger suppression
4. **During suppression period**:
   - Monitor physical state (from fanout perspective)
   - Monitor operational state (from DUT perspective)
   - Record at t=2s, t=5s, t=10s, t=20s, t=30s
5. Create divergence timeline

**Expected Results**:
- ✓ Divergence detected during suppression
- ✓ Physical state changes with link
- ✓ Operational state remains frozen
- ✓ Clear timeline of divergence/convergence
- ✓ States match again after suppression ends

**Duration**: ~35 seconds

---

### TC05.4 - Penalty Decay and State Recovery

**Procedure**:
1. Enable damping and trigger suppression
2. Record initial penalty: P₀
3. Wait 5 seconds, record penalty: P₅
4. Wait another 5 seconds (t=10), record penalty: P₁₀
5. Calculate decay rate
6. Compare with expected decay (half-life based)

**Expected Results**:
- ✓ P₀ > P₅ > P₁₀ (monotonic decay)
- ✓ Decay rate approximately follows half-life formula
- ✓ Penalty eventually drops below reuse threshold
- ✓ State recovery occurs when penalty < reuse_threshold

**Duration**: ~15 seconds

---

### TC05.5 - Multiple Suppression Cycles

**Procedure**:
1. Enable damping on test interface
2. **Cycle 1**:
   - Generate 5 flaps to trigger suppression
   - Wait 35 seconds for suppression to end
3. **Cycle 2**:
   - Generate 5 flaps again
   - Wait 35 seconds
4. Verify operational state recovery both cycles

**Expected Results**:
- ✓ Cycle 1: Suppression starts, runs, ends correctly
- ✓ Cycle 2: Second suppression cycle behaves identically
- ✓ State recovery occurs both cycles
- ✓ No hanging state between cycles
- ✓ System can handle multiple suppression cycles

**Duration**: ~80 seconds

---

## TC06: Frequent vs Infrequent Flaps

**Objective**: Verify proportional suppression based on flap frequency.

### TC06.1 - Frequent Flaps Longer Suppression

**Procedure**:
1. Enable damping on test interface
2. Generate 10 flaps with 0.5s interval (frequent, rapid)
3. Record suppression start time
4. Monitor suppression status every 2 seconds
5. Record suppression end time
6. Calculate total suppression duration: T_supp

**Expected Results**:
- ✓ Suppression is triggered (penalty reaches threshold)
- ✓ T_supp > 10 seconds (significant suppression)
- ✓ T_supp ≤ max_suppress_time (30 seconds)
- ✓ Longer suppression for frequent flaps (higher penalty accumulation)

**Duration**: ~40 seconds

---

### TC06.2 - Infrequent Flaps Shorter Suppression

**Procedure**:
1. Enable damping on test interface
2. Generate 2 flaps with 5 second interval (sparse, infrequent)
3. Record suppression start time (if triggered)
4. Monitor suppression status
5. Record suppression end time
6. Calculate suppression duration: T_supp

**Expected Results**:
- ✓ Suppression may be triggered (lower penalty)
- ✓ If triggered, T_supp < suppression from TC06.1
- ✓ Shorter suppression for sparse flaps (lower penalty)
- ✓ Suppression ends sooner

**Duration**: ~25 seconds

---

### TC06.3 - Penalty Accumulation Difference

**Procedure**:
1. Get 2 interfaces (Interface A and B)
2. Enable damping on both with same parameters
3. **Interface A**: Generate 10 flaps with 0.3s interval (frequent)
4. **Interface B**: Generate 2 flaps with 5s interval (sparse)
5. Record penalty on both interfaces immediately after flaps
6. Compare penalty values: P_A vs P_B

**Expected Results**:
- ✓ P_A > P_B (frequent flaps accumulate more penalty)
- ✓ Significant difference in penalty values
- ✓ Demonstrates penalty accumulation difference

**Duration**: ~12 seconds

---

### TC06.4 - Decay Rate Same for Both

**Procedure**:
1. Two interfaces with same configuration
2. Trigger suppression on both (different flap patterns)
3. Record penalties at t=0, t=5, t=10, t=15
4. Interface A penalties: P_A0, P_A5, P_A10, P_A15
5. Interface B penalties: P_B0, P_B5, P_B10, P_B15
6. Calculate decay rates (ratio of penalties over time)

**Expected Results**:
- ✓ Decay rate (P_t / P_0) is same for both interfaces
- ✓ Decay follows same mathematical formula (exponential)
- ✓ At t=decay_half_life (15s): P_t ≈ P_0 / 2 for both
- ✓ Decay rate independent of initial penalty

**Duration**: ~20 seconds

---

### TC06.5 - Recovery Time Proportional to Frequency

**Procedure**:
1. Two interfaces with same parameters
2. Interface A: Frequent flaps (10 with 0.3s interval)
3. Interface B: Sparse flaps (2 with 5s interval)
4. Measure recovery time for each:
   - From suppression start to end (when penalty < reuse_threshold)
5. Compare recovery times: T_A vs T_B

**Expected Results**:
- ✓ T_A > T_B (frequent flaps take longer to recover)
- ✓ Recovery time proportional to peak penalty
- ✓ Higher penalty = longer recovery
- ✓ Clear correlation between frequency and recovery time

**Duration**: ~50 seconds

---

### TC06.6 - Mixed Pattern Suppression

**Procedure**:
1. Enable damping on test interface
2. Generate mixed pattern:
   - Phase 1: 5 rapid flaps (0.3s interval) - **frequent**
   - Pause 5 seconds
   - Phase 2: 2 sparse flaps (5s interval apart) - **sparse**
3. Monitor penalties during all phases
4. Track suppression status

**Expected Results**:
- ✓ Phase 1 triggers suppression (high penalty)
- ✓ Phase 2 occurs while penalty is still decaying
- ✓ Penalty may spike during Phase 2
- ✓ Suppression duration reflects combined pattern
- ✓ System handles pattern transitions correctly

**Duration**: ~30 seconds

---

### TC06.7 - Threshold Crossing Different Timing

**Procedure**:
1. Two interfaces with different configurations:
   - Interface A: suppress_threshold = 1600 (standard)
   - Interface B: suppress_threshold = 3200 (conservative, higher threshold)
2. Both interfaces: Generate 10 flaps with 0.5s interval
3. Record time to reach suppress_threshold for each
4. Compare threshold crossing times

**Expected Results**:
- ✓ Interface A crosses threshold sooner (lower threshold)
- ✓ Interface B takes longer (higher threshold)
- ✓ Clear timing difference in suppression start
- ✓ Demonstrates threshold impact on suppression timing

**Duration**: ~12 seconds

---

## TC07: Stats Verification

**Objective**: Validate accuracy of link damping counters.

### TC07.1 - Pre-Damping Link Transitions Counter

**Procedure**:
1. Enable damping on test interface
2. Clear all statistics
3. Generate 5 link flaps
4. Retrieve counter: `pre_damping_link_transitions`
5. Verify counter value

**Expected Results**:
- ✓ Counter incremented for each transition
- ✓ pre_damping_link_transitions ≥ 5 (minimum 5 transitions from 5 flaps)
- ✓ Counter is accurate

**Duration**: ~5 seconds

---

### TC07.2 - Post-Damping Propagated Transitions Counter

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 10 flaps with 0.5s interval
4. Retrieve counter: `post_damping_propagated_transitions`
5. Verify counter value

**Expected Results**:
- ✓ Counter incremented only for non-suppressed events
- ✓ post_damping_propagated_transitions ≤ pre_damping_link_transitions
- ✓ Counter reflects only advertised events

**Duration**: ~8 seconds

---

### TC07.3 - Pre-Damping UP Events Counter

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 5 flaps (each flap = 1 DOWN + 1 UP event)
4. Retrieve counter: `pre_damping_up_events`
5. Verify counter value

**Expected Results**:
- ✓ pre_damping_up_events ≥ 5 (one UP per flap)
- ✓ Counter reflects actual UP transitions
- ✓ Accurate UP event count

**Duration**: ~5 seconds

---

### TC07.4 - Pre-Damping DOWN Events Counter

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 5 flaps (each flap = 1 DOWN event initially)
4. Retrieve counter: `pre_damping_down_events`
5. Verify counter value

**Expected Results**:
- ✓ pre_damping_down_events ≥ 5 (one DOWN per flap)
- ✓ Counter reflects actual DOWN transitions
- ✓ Accurate DOWN event count

**Duration**: ~5 seconds

---

### TC07.5 - Post-Damping UP Advertised Counter

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 10 flaps with 0.5s interval
4. Retrieve counter: `post_damping_up_advertised`
5. Verify counter value reflects only advertised UPs

**Expected Results**:
- ✓ post_damping_up_advertised ≤ pre_damping_up_events
- ✓ Only non-suppressed UP events counted
- ✓ Counter is accurate

**Duration**: ~8 seconds

---

### TC07.6 - Post-Damping DOWN Advertised Counter

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 10 flaps with 0.5s interval
4. Retrieve counter: `post_damping_down_advertised`
5. Verify counter value reflects only advertised DOWNs

**Expected Results**:
- ✓ post_damping_down_advertised ≤ pre_damping_down_events
- ✓ Only non-suppressed DOWN events counted
- ✓ Counter is accurate

**Duration**: ~8 seconds

---

### TC07.7 - Counter Consistency Across Cycles

**Procedure**:
1. Enable damping
2. Clear statistics
3. **Cycle 1**: Generate 5 flaps, record counters: C1
4. **Cycle 2**: Generate 3 more flaps, record counters: C2
5. Compare: C2 should be C1 + new increments

**Expected Results**:
- ✓ Counters increment monotonically
- ✓ C2_transitions = C1_transitions + new_transitions
- ✓ No counter resets between cycles
- ✓ Counters remain consistent

**Duration**: ~10 seconds

---

### TC07.8 - Counter Increments Proportional to Events

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 10 flaps with 0.5s interval
4. Retrieve counter: `pre_damping_link_transitions`
5. Verify counter proportional to number of flaps

**Expected Results**:
- ✓ pre_damping_link_transitions ≥ 10 (or ≥ expected count)
- ✓ Counter increments with each event
- ✓ Linear relationship: more flaps = higher counter
- ✓ Counter accuracy maintained

**Duration**: ~8 seconds

---

### TC07.9 - Suppressed Events Not in Post-Damping

**Procedure**:
1. Enable damping
2. Clear statistics
3. Generate 20 flaps with 0.3s interval (sufficient to trigger suppression)
4. Retrieve both counters:
   - pre_damping_link_transitions
   - post_damping_propagated_transitions
5. Calculate difference

**Expected Results**:
- ✓ pre_damping > post_damping (some events suppressed)
- ✓ Difference = number of suppressed events
- ✓ Suppressed events NOT counted in post-damping
- ✓ Clear evidence of suppression

**Duration**: ~8 seconds

---

### TC07.10 - Counter Reset and Recovery

**Procedure**:
1. Enable damping
2. Generate 5 flaps
3. Retrieve counters: initial_count
4. Clear statistics (reset counters to 0)
5. Retrieve counters: should be ~0
6. Generate 3 more flaps
7. Retrieve counters: should equal 3 (or proportional count)

**Expected Results**:
- ✓ Counters reset successfully
- ✓ After reset: counters ≈ 0
- ✓ New events counted from 0
- ✓ Counter recovery works correctly
- ✓ No stale data from previous count

**Duration**: ~10 seconds

---

## TC09: Timeline Validation

**Objective**: Validate link damping algorithm using deterministic event sequence per HLD.

**Note**: This comprehensive test validates the core damping algorithm against the HLD timeline specification.

### TC09.1 - Timeline Event Sequence Execution

**Configuration**:
```
suppress_threshold: 1600
reuse_threshold: 1200
decay_half_life: 15 seconds
max_suppress_time: 30 seconds
flap_penalty: 500
```

**Procedure**:
1. Enable damping with above configuration
2. Clear statistics
3. Execute deterministic timeline of events (starting at t=0):

| Time | Event | Expected Propagated |
|------|-------|------------------|
| 3s   | DOWN  | Yes (pre-threshold) |
| 7s   | UP    | Yes (pre-threshold) |
| 10s  | DOWN  | Yes (accumulated penalty=500) |
| 14s  | UP    | No (penalty=1000, < threshold) |
| 17s  | DOWN  | No (suppression active) |
| 20s  | UP    | No (suppression active) |
| 31s  | -     | Yes (penalty < reuse, suppression ends) |
| 40s  | DOWN  | Yes (new cycle) |
| 44s  | UP    | No (suppression active) |
| 46s  | DOWN  | No (suppression active) |
| 61s  | -     | No (suppression ending) |
| 70s  | UP    | Yes (suppression ended) |
| 100s | DOWN  | Yes (no suppression) |
| 102s | UP    | Yes (no suppression) |
| 105s | DOWN  | Yes (suppression starts) |
| 124s | UP    | No (suppression active) |
| 152s | -     | Yes (suppression ends) |

**Expected Results**:
- ✓ All events execute at correct times (within 1 second tolerance)
- ✓ Suppression starts at correct thresholds
- ✓ Events are suppressed/propagated per timeline
- ✓ Suppression ends at correct times
- ✓ Multiple suppression cycles work correctly
- ✓ Algorithm matches HLD specification

**Duration**: ~160 seconds


---

## TC10: Persistence and Restart Resilience

**Objective**: Verify damping configuration and functionality persists across reboots and docker restarts.

### TC10.1 - Damping Config Persists After Reboot

**Procedure**:
1. Select test interface
2. Configure damping with standard parameters
3. Verify configuration in CONFIG_DB
4. Reboot DUT: `sudo reboot`
5. Wait for DUT to come up (~3-5 minutes)
6. Query CONFIG_DB again
7. Compare pre/post reboot configurations

**Expected Results**:
- ✓ Configuration exists before reboot
- ✓ Reboot completes successfully
- ✓ Configuration persists in CONFIG_DB after reboot
- ✓ All parameters match pre-reboot values
- ✓ No configuration loss

**Duration**: ~5-10 minutes

---

### TC10.2 - Damping Functionality After Reboot

**Procedure**:
1. Configure damping (as TC10.1)
2. Reboot DUT
3. Wait for DUT to be fully up
4. Clear statistics
5. Generate 10 flaps with 0.5s interval
6. Retrieve counters:
   - pre_damping_link_transitions
   - post_damping_propagated_transitions
7. Verify suppression is working (post < pre)

**Expected Results**:
- ✓ Configuration persists
- ✓ Damping is fully operational after reboot
- ✓ Suppression works correctly
- ✓ Counters are accurate
- ✓ No functional degradation

**Duration**: ~5-10 minutes + 8 seconds

---

### TC10.3 - Counters Preserved After Reboot

**Procedure**:
1. Configure damping and trigger events
2. Generate 5 flaps
3. Retrieve counters: C_before
4. Reboot DUT
5. Wait for DUT to come up
6. Retrieve counters: C_after
7. Compare counter values

**Expected Results**:
- ✓ Counters before reboot: C_before > 0
- ✓ Counters after reboot: C_after (may or may not persist - depends on implementation)
- ✓ If persisted: C_after ≥ C_before
- ✓ No counter corruption

**Duration**: ~5-10 minutes

---

### TC10.4 - Multiple Reboot Cycles

**Procedure**:
1. Configure damping on test interface
2. **Reboot Cycle 1**:
   - Verify configuration exists
   - Reboot DUT
   - Verify configuration persists
   - Verify functionality works
3. **Reboot Cycle 2**:
   - Repeat cycle 1 steps

**Expected Results**:
- ✓ Cycle 1: Configuration survives reboot
- ✓ Cycle 2: Configuration survives second reboot
- ✓ Multiple reboots handled correctly
- ✓ No progressive degradation
- ✓ System is stable

**Duration**: ~10-20 minutes

---

### TC10.5 - Concurrent Damping Multiple Ports After Reboot

**Procedure**:
1. Configure damping on 5 interfaces with different parameters:
   - Interface 1-3: standard config
   - Interface 4-5: conservative config (higher thresholds)
2. Reboot DUT
3. Wait for recovery
4. Verify all 5 configurations persisted
5. Generate flaps on each interface
6. Verify independent suppression on each

**Expected Results**:
- ✓ All 5 configurations survive reboot
- ✓ Configurations are independent
- ✓ Suppression works correctly on each
- ✓ No cross-interference
- ✓ System handles concurrent damping post-reboot

**Duration**: ~5-10 minutes

---

### TC10.6 - Reboot During Suppression

**Procedure**:
1. Configure damping on test interface
2. Generate flaps to trigger suppression
3. Verify suppression is active
4. Immediately reboot DUT (while suppressed)
5. Wait for DUT to come up
6. Verify configuration persisted
7. Verify system stability

**Expected Results**:
- ✓ Reboot is graceful (no hang)
- ✓ Configuration persists
- ✓ DUT comes up fully
- ✓ Suppression state is reset (clean state)
- ✓ Functionality works after recovery
- ✓ No state corruption

**Duration**: ~5-10 minutes

---

### TC10.7 - BGP Docker Restart

**Procedure**:
1. Configure damping on test interface
2. Verify configuration in CONFIG_DB
3. Restart BGP container: `docker restart bgp`
4. Wait for BGP to fully restart (~10-30 seconds)
5. Verify configuration persists
6. Generate flaps and verify suppression works

**Expected Results**:
- ✓ BGP restart completes successfully
- ✓ Configuration persists in CONFIG_DB
- ✓ Damping functionality unaffected
- ✓ No ASIC state issues
- ✓ System continues operating

**Duration**: ~1-2 minutes

---

### TC10.8 - SWSS Docker Restart

**Procedure**:
1. Configure damping on test interface
2. Verify configuration in CONFIG_DB and APP_DB
3. Restart SWSS container: `docker restart swss`
4. Wait for SWSS to fully restart and reconcile (~30-60 seconds)
5. Verify configuration persists in both databases
6. Generate flaps and verify suppression works
7. Check for any ASIC inconsistencies

**Expected Results**:
- ✓ SWSS restart completes successfully
- ✓ Configuration persists in CONFIG_DB
- ✓ Configuration reconciled in APP_DB
- ✓ Damping fully operational post-restart
- ✓ No ASIC inconsistency
- ✓ All counters reset (fresh state)

**Duration**: ~2-3 minutes

---

### TC10.9 - Syncd Docker Restart

**Procedure**:
1. Configure damping on test interface
2. Verify configuration and ASIC state
3. Restart Syncd container: `docker restart syncd`
4. Wait for Syncd to fully reconnect to ASIC (~20-60 seconds)
5. Verify configuration persists
6. Verify ASIC state remains consistent
7. Generate flaps and verify suppression works
8. Check ASIC counters/state

**Expected Results**:
- ✓ Syncd restart completes successfully
- ✓ ASIC reconnection successful
- ✓ Configuration persists
- ✓ ASIC state consistent (no mismatch)
- ✓ Damping functionality intact
- ✓ No counter corruption
- ✓ Link states correct after restart

**Duration**: ~2-3 minutes

---

## Test Execution Summary

### Quick Reference: Test Count and Duration

| Test Class | Test Count | Total Duration |
|-----------|-----------|-----------------|
| TC01 - Basics | 3 | ~15 seconds |
| TC02 - Configuration | 6 | ~12 seconds |
| TC03 - Unsupported | 6 | ~25 seconds |
| TC04 - Mixed Config | 6 | ~35 seconds |
| TC05 - Operational State | 5 | ~150 seconds |
| TC06 - Frequency Effects | 7 | ~150 seconds |
| TC07 - Counters | 10 | ~80 seconds |
| TC09 - Timeline | 1 | ~160 seconds |
| TC10 - Persistence | 9 | ~45-60 minutes |
| **TOTAL** | **53** | **~46-62 minutes** |

**Note**: Most of TC10 tests require device reboot (5-10 min each), which is why the total time is significant.

---

## Running Tests Efficiently

### For Quick Validation (excluding reboots)
```bash
# Run all tests except TC10 (persistence)
pytest tests/link_event_damping/test_link_event_damping.py -v -k "not tc10"

# Estimated time: ~10-15 minutes
```

### For Overnight Testing
```bash
# Run all tests including persistence/reboots
pytest tests/link_event_damping/test_link_event_damping.py -v

# Estimated time: ~60-80 minutes (depending on DUT boot time)
```

### For Specific Feature Testing
```bash
# Test suppression logic
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingOperationalState -v

# Test configuration validation
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingConfiguration -v

# Test counters
pytest tests/link_event_damping/test_link_event_damping.py::TestLinkEventDampingCounters -v
```

### Parallel Execution (if supported by test infrastructure)
```bash
# Run on multiple DUTs
pytest tests/link_event_damping/test_link_event_damping.py -v -n 4

# Note: Adjust based on available resources
```

---

## Expected Pass Criteria

### Comprehensive Success
- ✓ All 53 test cases pass
- ✓ No critical errors in logs
- ✓ Configuration persists correctly
- ✓ Counters are accurate
- ✓ Suppression algorithm matches HLD
- ✓ System stable before/after all tests

### Partial Success (acceptable for feature development)
- ✓ TC01-TC07 pass (basic functionality)
- ✓ TC09 passes (algorithm validation)
- ✗ TC10 may have issues if restart feature not complete

### Known Limitations
- Some TC10 tests may timeout if DUT boot time > 5 minutes
- Fanout-based flaps require proper topology; fallback to admin commands works
- Counter persistence across reboot depends on implementation

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Test Timeout
**Symptom**: Test hangs waiting for suppression to end
**Cause**: Decay half-life calculation issue
**Solution**:
```bash
# Check penalty decay:
redis-cli -n 1 HGET 'LINK_DAMPING_STATUS:Ethernet0' current_penalty
# Wait and check again
```

#### 2. Configuration Not Applied
**Symptom**: CONFIG_DB shows no entries
**Cause**: Configuration command syntax error
**Solution**:
```bash
# Verify supported syntax:
config interface link-damping --help
# Check SWSS logs:
docker exec -it swss tail -100 /var/log/swss.log
```

#### 3. Counters Not Incrementing
**Symptom**: All counters remain 0
**Cause**: Link events not being generated properly
**Solution**:
```bash
# Verify link flap is working:
show interfaces status <interface>
# Check if events are in syslog:
grep -i "link\|flap" /var/log/syslog | tail -20
```

#### 4. Fanout Connection Issues
**Symptom**: Flap generation fails
**Cause**: Fanout switch not accessible
**Solution**:
```bash
# Test will fall back to DUT admin commands
# Verify manual flap:
config interface shutdown Ethernet0
config interface startup Ethernet0
```

---

## Validation Checklist

Before declaring Link Event Damping feature complete:

- [ ] All 53 tests pass
- [ ] Configuration persists correctly
- [ ] Suppression algorithm validates against HLD timeline
- [ ] Counters are accurate and consistent
- [ ] Reboot resilience verified (TC10.1-TC10.6)
- [ ] Docker restart resilience verified (TC10.7-TC10.9)
- [ ] Multi-port concurrent damping works
- [ ] No memory leaks or hangs
- [ ] Performance acceptable (suppression/recovery times match HLD)
- [ ] No unexpected errors in system logs

---

## References

- SONiC Link Event Damping HLD: `/home/hp_test/tsiva/Link_event_damping.md`
- Test Suite: `tests/link_event_damping/test_link_event_damping.py`
- Utilities: `tests/link_event_damping/link_event_damping_utils.py`
- Configuration: `tests/link_event_damping/conftest.py`

---

## Contact & Support

For test execution issues or clarifications:
1. Check test logs: `pytest ... -v -s` (verbose + show output)
2. Check system logs: `/var/log/syslog`, `/var/log/swss.log`
3. Check Redis databases: `redis-cli -n <index> KEYS '*DAMPING*'`
4. Review HLD specification for algorithm details
