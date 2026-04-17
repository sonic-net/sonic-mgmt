
QoS Spytest Validation Summary (FX3)

This PR validates DSCP mapping, Scheduler (DWRR/SP), and WRED behavior on FX3
under realistic traffic conditions using SpyTest + IXIA.

Scheduler (DWRR / SP) Validation
DWRR weight distribution validated across queues (Q0–Q5)
Observed TX share aligns with configured weights within ±20% tolerance
All queues passed share validation (6/6 PASS)
Strict Priority queues (Q6–Q7) verified:
No packet drops observed
Behavior consistent with SP expectations

✅  Result: Scheduler behavior validated (DWRR + SP)

WRED Validation (Linearity & Threshold Behavior)
Traffic oversubscription used to trigger WRED (100% → ~105.5%)
Queue depth observed to increase from ~1.1MB → ~3.0MB
WRED drop probability increases linearly with queue depth
Measured drop rate closely matches expected probability

Key Observations:
WRED operates in linear region (Zone B) as expected
Drop behavior matches configured min/max thresholds
No unexpected drop anomalies observed

✅  Result: WRED linearity and threshold behavior validated

Test Coverage
The following test scenarios are covered:

Scheduler
test_scheduler_dwrr_validation_ipv4
test_scheduler_dwrr_validation_ipv6

WRED
test_wred_active_zone_ipv4/ipv6
test_wred_below_min_ipv4/ipv6
test_wred_linearity_ipv4/ipv6
test_wred_tail_drop_ipv4/ipv6

✅  Environment
Platform: FX3
ASIC: Tahoe (Sundown1)
SDK: Nexus SDK
SAI Version: 1.16.4
Testbed: IXIA-based (2×100G ingress → 1×100G egress)
Conclusion
Scheduler (DWRR/SP) behavior is validated and stable
WRED operates correctly across threshold regions with expected linearity
End-to-end validation confirms correct integration across SONiC → SAI → DCHAL → ASIC
Description of PR
Summary:

✅  Test Result Examples
Scheduler CLI:
cd /data/sonic-mgmt/spytest && bin/spytest \
  --testbed testbeds/fx3/fx3_qos_testbed_2022.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --logs-path run_logs/ \
  cisco/fx3/qos/test_fx3_qos_integration.py -k 'test_scheduler_dwrr_validation'

========================================================================
  DWRR TX-SHARE VALIDATION  —  DWRR validation
  Tolerance  : 20%  (±20% of expected share)
  Total weight: 170  (Q0=20  Q1=20  Q2=20  Q3=40  Q4=40  Q5=30)
========================================================================
  Queue    Weight      Before (pkts)     After (pkts)       Tx Delta     Drop Delta
  ------------------------------------------------------------------------
  Q0       20                      0       84,387,397     84,387,397     86,065,657
  Q1       20                      0       84,387,385     84,387,385     86,065,669
  Q2       20                      0       84,387,389     84,387,389     86,065,665
  Q3       40                      0      170,453,054    170,453,054              0
  Q4       40                      0      170,453,054    170,453,054              0
  Q5       30                      0      130,370,050    130,370,050     40,083,004
  ------------------------------------------------------------------------
  Total Tx delta: 724,438,329 pkts

  Queue    Weight       Expected %       Actual %     Acceptable Range Result
  ------------------------------------------------------------------------
  Q0       20                11.8%          11.6%  [9.4% .. 14.1%]   PASS
  Q1       20                11.8%          11.6%  [9.4% .. 14.1%]   PASS
  Q2       20                11.8%          11.6%  [9.4% .. 14.1%]   PASS
  Q3       40                23.5%          23.5%  [18.8% .. 28.2%]   PASS
  Q4       40                23.5%          23.5%  [18.8% .. 28.2%]   PASS
  Q5       30                17.6%          18.0%  [14.1% .. 21.2%]   PASS
  ------------------------------------------------------------------------
  DWRR share result : 6 passed,  0 failed

  Strict-Priority Queues (zero drops expected):
  ------------------------------------------------------------------------
  Queue         Before (drop)     After (drop)     Drop Delta Result
  ------------------------------------------------------------------------
  Q6                        0                0              0 PASS
  Q7                        0                0              0 PASS
  ------------------------------------------------------------------------
========================================================================



WRED CLI:
cd /data/sonic-mgmt/spytest && bin/spytest \
  --testbed testbeds/fx3/fx3_qos_testbed_2022.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --logs-path run_logs/ \
  cisco/fx3/qos/test_fx3_qos_integration.py -k 'test_wred_linearity'

 ==========================================================================================
   WRED LINEARITY SUMMARY (egress 100000M)
 ==========================================================================================
     Margin    Port A    Port B     Rate% Avg Depth  Est. Prob  WRED Drop   Zone   Status
   ----------------------------------------------------------------------------------------
       250M   50.125%   50.125%  100.250%    1.12MB      0.30%      0.25%      B       OK
       500M   50.250%   50.250%  100.500%    1.20MB      0.51%      0.50%      B       OK
      1000M   50.500%   50.500%  101.000%    1.43MB      1.06%      0.99%      B       OK
      2000M   51.000%   51.000%  102.000%    1.80MB      2.00%      1.96%      B       OK
      3000M   51.500%   51.500%  103.000%    2.18MB      2.94%      2.91%      B       OK
      4000M   52.000%   52.000%  104.000%    2.59MB      3.98%      3.85%      B       OK
      5000M   52.500%   52.500%  105.000%    2.90MB      4.74%      4.76%      B       OK
      5250M   52.625%   52.625%  105.250%    2.98MB      4.95%      4.99%      B       OK
      5500M   52.750%   52.750%  105.500%    3.00MB      5.00%      5.29%      B       OK
 ==========================================================================================

Approach
What is the motivation for this PR?
To validate FX3 Tortuga QoS DSCP, Scheduler, WRED behavior on FX3 under realistic traffic conditions
and ensure correct implementation across SAI, DCHAL, and ASIC layers, especially for threshold-based drop behavior.

How did you do it?
Added Scheduler validation helper functions in fx3_qos_helpers.py
Added WRED validation helper functions in fx3_qos_helpers.py
Implemented SpyTest-based WRED test cases
Generated congestion using IXIA traffic to trigger WRED behavior
Verified queue mapping and WRED profile application via SAI and DCHAL

How did you verify/test it?
Ran SAI regression tests (PASS)
Validated min/max thresholds and drop behavior
Monitored queue depth and drop counters via ASIC/DCHAL CLI
Repeated traffic runs (multiple iterations) to confirm consistency

Any platform specific information?
Platform: FX3
ASIC: Tahoe (Sundown1)
SDK: Nexus SDK
SAI Version: 1.16.4

Supported testbed topology if it's a new test case?
test_scheduler_dwrr_validation_ipv4
test_scheduler_dwrr_validation_ipv6
test_wred_active_zone_ipv4
test_wred_active_zone_ipv6
test_wred_below_min_ipv4
test_wred_below_min_ipv6
test_wred_linearity_ipv4
test_wred_linearity_ipv6
test_wred_tail_drop_ipv4
test_wred_tail_drop_ipv6

Documentation
https://wwwin-github.cisco.com/whitebox/cisco-nx-sai/pull/333
https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/967479575/Testbed+Setup
