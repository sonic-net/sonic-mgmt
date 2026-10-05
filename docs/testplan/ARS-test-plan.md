# Test Plan for ARS

## Overview

This test plan validates ARS (Adaptive routing and switching) load balancing functionality in SONiC network devices by verifying packet distribution based on ARS configurations.

## Test Objectives

- Verify that the Adaptive Routing and Switching (ARS) mechanism dynamically optimizes forwarding paths in response to network conditions such as congestion, link failures etc,
 ensuring improved performance and traffic distribution.
- Validate ARS ECMP functionality with assign-mode configured as per-flowlet and per-packet under different ARS modes — Global, Interface, and Nexthop.
- Ensure co-existence of ARS ECMP and non-ARS ECMP routes without impact to traffic forwarding or convergence behavior.
- Verify nexthop add/remove operations in ARS-enabled ECMP groups

## Test Scope

### Current Scope

- ARS for ECMP
    - Validates IPv4 and IPv6 traffic based on 5-tuple hashing such as Source IP, Destination IP, Source Port, Destination Port, and IP Protocol.
    - Validates Static ARS Selector mode for controlled and predictable next-hop selection modes such as - Global, Interface, and Nexthop.

### Future Scope

- ARS support to LAG
- Statistics for ARS-LAG and ARS-NHG to monitor flow distribution.

## Test Cases

### Test Case 1: Test ARS ECMP When NHG Mode is Global

**Test Function:** `test_ars_global`

**Objective:**  
Verify ARS ECMP functionality under Global NHG mode in per-packet and per-flowlet assign modes with different traffic patterns
for ensuring all ECMP groups with ARS and correct next-hop selection, balanced load distribution.

#### Test Steps

1. Initialize the test environment and collect topology information.  
2. Clear all interface and port statistics.  
3. Configure ARS profile.  
4. Create ARS object with assign mode set to per-packet quality.  
5. Associate the configured ARS object as the default_ars_object in ARS_PROFILE.  
6. Configure BGP to learn routes with ECMP paths.  
7. Verify route installation in the routing table.  
8. Generate two distinct 5-tuple traffic patterns.  
9. Send 1000 packets per variation and monitor forwarding behavior.  
10. Verify packet forwarding accuracy and ensure packet counts match expectations.  
11. Save test results to a JSON file.  

#### Repeat Test for Flowlet Mode

12. Modify ARS object assign mode to per-flowlet quality.  
13. Reapply configuration (steps 6–11).  
14. Validate consistent forwarding and traffic distribution under flowlet-based ARS mode.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic is evenly distributed across ECMP paths based on ARS configuration.  
- In per-packet mode: balanced distribution across all next hops.  
- In per-flowlet mode: consistent path per flowlet with overall balanced distribution.  

#### Pass Criteria

- All sent packets are received and properly routed.  
- Traffic distribution aligns with the expected ARS assign mode behavior (per-packet or per-flowlet).  

---

### Test Case 2: Test ARS ECMP When NHG Mode is Interface

**Test Function:** `test_ars_interface`

**Objective:**  
Verify ARS ECMP functionality under Interface NHG mode in per-packet and per-flowlet assign modes with different traffic patterns
for ensuring all ECMP groups with ARS and correct next-hop selection, balanced load distribution.

#### Test Steps

1. Initialize the test environment and collect topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile.  
4. Create an ARS object with assign mode initially set to per-packet quality.  
5. Configure an ARS interface.  
6. Associate the ARS object with the ARS intefaces.  
7. Configure BGP to ensure ECMP paths exist on the ARS enabled interface.  
8. Verify route installation and ECMP path setup in the routing table.  
9. Generate two distinct 5-tuple traffic patterns.  
10. Send 1000 packets per traffic pattern and monitor forwarding behavior.  
11. Verify packet forwarding accuracy and ensure counters/statistics match expectations.  
12. Save test results to a JSON file.  

#### Repeat Test for Flowlet Mode

13. Modify the ARS object assign mode to per-flowlet quality.  
14. Reapply configuration steps (steps 7–12).  
15. Validate consistent forwarding per flowlet and overall balanced distribution across ECMP paths.

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic distribution adheres to the ARS assign mode:  
  - Per-packet mode: balanced across all next-hop interfaces.  
  - Per-flowlet mode: each flowlet follows a consistent path while maintaining overall balance.  

#### Pass Criteria

- All sent packets are received at the destination and properly routed.  
- Traffic distribution aligns with the configured ARS assign mode (per-packet or per-flowlet) for interface-based NHG mode.

---

### Test Case 3: Test ARS ECMP When NHG Mode is Nexthop

**Test Function:** `test_ars_nexthop`

**Objective:**  
Verify ARS ECMP functionality under Nexthop NHG mode in per-packet and per-flowlet assign modes with different traffic patterns
for ensuring all ECMP groups with ARS and correct next-hop selection, balanced load distribution.

#### Test Steps

1. Initialize the test environment and collect topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile.  
4. Create an ARS object with assign mode initially set to per-packet quality.  
5. Configure ARS interfaces.  
6. Configure ARS nexthops.  
7. Associate the ARS object with the ARS nexthops.  
8. Configure BGP to ensure ECMP paths exist with the configured nexthops.  
9. Verify route installation and ECMP path setup in the routing table.  
10. Generate two distinct 5-tuple traffic patterns.  
11. Send 1000 packets per traffic pattern and monitor forwarding behavior.  
12. Verify packet forwarding accuracy and ensure counters/statistics match expectations.  
13. Save test results to a JSON file.  

#### Repeat Test for Flowlet Mode

14. Modify the ARS object assign mode to per-flowlet quality.  
15. Reapply configuration steps (steps 8–13).  
16. Validate consistent forwarding per flowlet and overall balanced distribution across ECMP nexthops.

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic distribution adheres to the ARS assign mode:  
  - Per-packet mode: balanced across all next-hop paths.  
  - Per-flowlet mode: each flowlet follows a consistent path while maintaining overall balance.  

#### Pass Criteria

- All sent packets are received at the destination and properly routed.  
- Traffic distribution aligns with the configured ARS assign mode (per-packet or per-flowlet) for nexthop-based NHG mode.

---

### Test Case 4: Test ACL Disable ARS Forwarding Action When ARS is Configured

**Test Function:** `test_ars_acl_action`

**Objective:**  
Verify that ACL can disable ARS forwarding action for specific traffic and that the traffic uses non-ARS path selection in per-packet mode.

#### Test Steps

1. Initialize the test environment and gather topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile, ARS object, and route with ECMP paths.  
4. Set ARS assign mode to per-packet quality.  
5. Apply ACL to disable ARS forwarding for a particular traffic pattern.  
6. Generate two distinct 5-tuple traffic patterns.  
7. Send 1000 packets per traffic pattern and monitor forwarding behavior.  
8. Verify that packet forwarding follows non-ARS selection and packet counts match expectations.  
9. Save test results to a JSON file.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic follows non-ARS paths when ACL disables ARS forwarding.  

#### Pass Criteria

- All sent packets are received and properly routed.  
- Traffic forwarding aligns with ACL configuration, bypassing ARS paths as expected.

---

### Test Case 5: Test ECMP When NHG Mode is Interface and Underlying Ports Are Not ARS-Enabled

**Test Function:** `test_ars_nonars_ports`

**Objective:**  
Verify that ECMP paths are correctly formed and traffic is properly forwarded when the interfaces are not ARS-enabled.

#### Test Steps

1. Initialize the test environment and gather topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile, ARS object, ARS interface, and route with ECMP paths.  
4. Ensure that the underlying interfaces are not ARS-enabled.  
5. Generate two distinct 5-tuple traffic patterns.  
6. Send 1000 packets per traffic pattern and monitor forwarding behavior.  
7. Verify that packet forwarding occurs correctly and that packet counts match expectations.  
8. Save test results to a JSON file.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic is distributed based on non-ARS ECMP, respecting the interface-based ECMP paths.

#### Pass Criteria

- All sent packets are received and properly routed.  
- Traffic forwarding aligns with ECMP behavior on non-ARS interfaces.

---

### Test Case 6: Test ECMP When NHG Mode is Nexthop and Nexthops Are Not ARS-Enabled

**Test Function:** `test_ars_nonars_nexthop`

**Objective:**  
Verify that ECMP paths are correctly formed and traffic is properly forwarded when the nexthops are not ARS-enabled.

#### Test Steps

1. Initialize the test environment and gather topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile, ARS object, ARS interface, ARS nexthop, and route with ECMP paths.  
4. Ensure that the nexthops are **not ARS-enabled**.  
5. Configure BGP to ensure ECMP paths exist with the configured nexthops.  
6. Generate two distinct 5-tuple traffic patterns.  
7. Send 1000 packets per traffic pattern and monitor forwarding behavior.  
8. Verify that packet forwarding occurs correctly and that packet counts match expectations.  
9. Save test results to a JSON file.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern).  
- Traffic is distributed based on **non-ARS ECMP**, respecting the nexthop-based ECMP paths.

#### Pass Criteria

- All sent packets are received and properly routed.  
- Traffic forwarding aligns with ECMP behavior on non-ARS nexthops.

---

### Test Case 7: Test ARS with Reboot, Warm-Reboot, and Fast-Reboot

**Test Function:** `test_ars_reboot`

**Objective:**  
Verify that ARS ECMP functionality works correctly after reboot, warm-reboot, and fast-reboot, ensuring traffic continues to be forwarded based on ARS configuration.

#### Test Steps

1. Initialize the test environment and gather topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile, ARS object, ARS interfaces, ARS nexthops, and route with ECMP paths.  
4. Configure BGP to ensure ECMP paths exist with the configured nexthops.  
5. Set ARS assign mode to per-packet quality.  
6. Generate two distinct 5-tuple traffic patterns.  
7. Send 1000 packets per traffic pattern and verify forwarding behavior and counters.  
8. Perform a reboot, warm-reboot, and fast-reboot sequentially.  
9. After each reboot type, verify:  
   - ARS configuration is still applied.  
   - ECMP routes are installed via BGP.  
   - Packet forwarding occurs correctly and counters/statistics match expectations.  
10. Save test results to a JSON file.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern) before and after each type of reboot.  
- Traffic continues to be distributed based on ARS ECMP configuration after reboot, warm-reboot, and fast-reboot.  
- ARS configuration persists across all reboot types.

#### Pass Criteria

- All sent packets are received and properly routed before and after reboot, warm-reboot, and fast-reboot.  
- Traffic distribution aligns with the per-packet ARS assign mode across all tests.

---

### Test Case 8: Test ARS with Multiple Port Flap and Scaling Factor Changes

**Test Function:** `test_ars_stress`

**Objective:**  
Verify that ARS ECMP functionality works correctly under multiple port flaps and changes in per-port scaling factor, ensuring traffic continues to be forwarded based on ARS configuration.

#### Test Steps

1. Initialize the test environment and gather topology information.  
2. Clear all interface and port statistics.  
3. Configure an ARS profile, ARS object, ARS interfaces, ARS nexthops, and routes with ECMP paths.  
4. Configure BGP to ensure ECMP paths exist with the configured nexthops.  
5. Set ARS assign mode to per-packet quality.  
6. Generate two distinct 5-tuple traffic patterns.  
7. Send 1000 packets per traffic pattern and verify forwarding behavior and counters.  
8. Perform multiple port flap operations on the ARS-enabled interfaces.  
9. After each port flap, verify:  
   - ARS configuration persists.  
   - Packet forwarding occurs correctly.  
   - Counters/statistics match expectations.  
10. Change the scaling factor on one or more ARS interfaces.  
11. Verify that:  
   - Packet forwarding occurs correctly after scaling factor changes.  
   - Traffic distribution aligns with updated per-port scaling factors.  
12. Save test results to a JSON file.  

#### Expected Results

- All packets are forwarded correctly (≥1000 packets per traffic pattern) before, during, and after port flaps or scaling factor changes.  
- Traffic continues to be distributed based on ARS ECMP configuration and respects updated scaling factors.

#### Pass Criteria

- All sent packets are received and properly routed.  
- Traffic forwarding aligns with per-packet ARS assign mode and updated scaling factors across all operations.

---

## Test Data and Parameters

### Traffic Parameters

- **Packet Count per Test:** 10000  
- **Variations per Pattern:** 10  
- **Packet Types:** IPv4, IPv6  
- **L4 Header:** TCP  
- **5-Tuple Fields for Traffic Generation:**  
  - Source IP  
  - Destination IP  
  - Source Port  
  - Destination Port  
  - Protocol (TCP)

### Network Parameters

- T0 Topology 

### Validation Criteria

1. **Packet Forwarding Accuracy**
   - All transmitted packets must be successfully received.
   - Packet format must remain correct after routing.
   - Time-To-Live (TTL) or hop limit must decrement appropriately at each hop.

2. **Load Balancing Distribution**
   - Traffic should be distributed across the Next Hop Group (NHG) according to ARS and non-ARS configurations.
   - Identical flows must consistently follow the same path to ensure deterministic forwarding behavior.

3. **ARS Load Balancing Behavior**

#### Per-Packet Mode

1. **Single flow of traffic** – Traffic should be evenly distributed across all next hops (NHs) within the ARS ECMP group.  
2. **Multiple flows of traffic** – Aggregate traffic should be evenly balanced across all NHs within the ARS ECMP group.  
3. **Link failure event** – Upon link down, the system should dynamically reselect paths and continue to distribute traffic evenly across remaining NHs without packet loss.  

#### Per-Flowlet Mode

1. **Single flow of traffic** – Packets within a given flowlet must follow a consistent path; subsequent flowlets should be able to select new paths to achieve balanced traffic distribution.  
2. **Multiple flows of traffic** – Traffic should remain evenly distributed across NHs while ensuring each flow maintains a consistent path.  
3. **Link failure event** – Upon link down, the system should immediately update path selection and maintain even traffic distribution across the remaining NHs with no packet loss.  

---

## Test Reporting

### Test Results Storage

- JSON files with detailed results.  
- Formatted results organized by interface  
- Separate files for baseline and ECMP offset tests

### Key Metrics

- Packet transmission success rate  
- Interface distribution patterns  
- Test execution time

### Test Limitation

- **Hardware Compatibility:** Limited to specific chipset supporting ARS.

---

## Test Matrix

| Test Case               | NHG Mode     | Assign Mode            | Expected Outcome                                                          |
|-------------------------|--------------|------------------------|---------------------------------------------------------------------------|
| test_ars_global         | Global       | Per-packet quality     | Traffic balanced across ARS ECMP paths                                    |
| test_ars_global         | Global       | Per-flowlet quality    | Traffic balanced across ARS ECMP paths                                    |
| test_ars_interface      | Interface    | Per-packet quality     | Traffic balanced across ARS ECMP paths                                    |
| test_ars_interface      | Interface    | Per-flowlet quality    | Traffic balanced across ARS ECMP paths                                    |
| test_ars_nexthop        | Nexthop      | Per-packet quality     | Traffic balanced across ARS ECMP paths                                    |
| test_ars_nexthop        | Nexthop      | Per-flowlet quality    | Traffic balanced across ARS ECMP paths                                    |
| test_ars_acl_action     | Global       | Per-packet quality     | Traffic bypasses ARS ECMP per ACL rules                                   |
| test_ars_nonars_ports   | Interface    | N/A                    | Traffic balanced across non-ARS ECMP paths                                |
| test_ars_nonars_nexthop | Nexthop      | N/A                    | Traffic balanced across non-ARS ECMP paths                                |
| test_ars_reboot         | Interface    | Per-packet quality     | Traffic balanced across ARS ECMP paths before/after reboot                |
| test_ars_stress         | Interface    | Per-packet quality     | Traffic balanced across ARS ECMP paths during port flap and scaling change|

---

## Future Enhancements

- Support ARS LAG testing  
- Support for ARS NHG and ARS LAG statistics
