# High Availability Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [KeysightTestbed](#keysight-testbed)
- [Topology](#topology)
    - [Configuration for HATesting](#configuration-for-HA-testing)
- [Setup configuration](#setup-configuration)
- [Test Methodology](#test-methodology)
- [Test cases](#test-cases)
    - [Common Steps](#test-common-steps)
    - [Test Metrics](#test-metrics)
     - [Test case # 1 – CPS Without HA Enabled](#test-case1-cps-without-ha-enabled)
       - [Test objective 1](#test-objective-1)
       - [Test steps 1](#steps-for-test-case-1)
    - [Test case # 2 –  Planned Switchover Between HA Sets](#test-case2-planned-switchover-between-ha-sets)
      - [Test objective 2](#test-objective-2)
      - [Test steps 2](#steps-for-test-case-2)
    - [Test case # 3 –  Planned Switchover Perfect Sync Between HA Sets](#test-case3-planned-switchover-perfect-sync-between-ha-sets)
      - [Test objective 3](#test-objective-3)
      - [Test steps 3](#steps-for-test-case-3)
    - [Test case # 4 -  Link Failures Active NPU to DPU Probe Drop Active](#test-case4-link-failures-active-npu-to-dpu-probe-drop-active)
      - [Test objective 4](#test-objective-4)
      - [Steps for Test Case 4](#steps-for-test-case-4)
    - [Test case # 5 -  Link Failures Active NPU to DPU Probe Drop Standby](#test-case5-link-failures-active-npu-to-dpu-probe-drop-standby-)
      - [Test objective 5](#test-objective-5)
      - [Steps for Test Case 5](#steps-for-test-case-5)
    - [Test case # 6 -  Link Failures Standby NPU to DPU Probe Drop Active](#test-case6-link-failures-standby-npu-to-dpu-probe-drop-active)
      - [Test objective 6](#test-objective-6)
      - [Steps for Test Case 6](#steps-for-test-case-6)
    - [Test case # 7 -  Link Failures Standby NPU to DPU Probe Drop Standby](#test-case7-link-failures-standby-npu-to-dpu-probe-drop-standby)
      - [Test objective 7](#test-objective-7)
      - [Steps for Test Case 7](#steps-for-test-case-7)
    - [Test case # 8 -  Link Failures Active T1-T0 Link Drop Active](#test-case8-link-failures-active-t1-t0-link-drop-active)
      - [Test objective 8](#test-objective-8)
      - [Steps for Test Case 8](#steps-for-test-case-8)
    - [Test case # 9 -  Link Failures Active T1-T0 Link Drop Standby](#test-case9-link-failures-active-t1-t0-link-drop-standby-)
      - [Test objective 9](#test-objective-9)
      - [Steps for Test Case 9](#steps-for-test-case-9)
    - [Test case # 10 -  Link Failures Standby T1-T0 Link Drop Active](#test-case10-link-failures-standby-t1-t0-link-drop-active)
      - [Test objective 10](#test-objective-10)
      - [Steps for Test Case 10](#steps-for-test-case-10)
    - [Test case # 11 -  Link Failures Standby T1-T0 Link Drop Standby](#test-case11-link-failures-standby-t1-t0-link-drop-standby-)
      - [Test objective 11](#test-objective-11)
      - [Steps for Test Case 11](#steps-for-test-case-11)
    - [Test case # 12 – DPU Loss HA Set](#test-case12-dpuloss-ha-set)
      - [Test objective 12](#test-objective-12)
      - [Test steps 12](#steps-for-test-case-12)

## Overview
The purpose of these tests is to evaluate various High Availability (HA)
scenarios associated with testing planned and unplanned events in the
SmartSwitch system.

### Scope
These tests are targeted on a fully functioning SmartSwitch system. We will
be measuring the system as a whole while evaluating HA scenarios such as 100%
link loss, DPU, and Grey failover.

### Keysight Testbed
Tests will run on the following testbeds.

![HA TestBed](images/ha_testbed.svg)

Model expanded to show Keysight chassis, SONiC Capable Switch, and
SmartSwitch.  The SONiC Switch and SmartSwitchs can be used to configure
various test case scenarios and network configurations.  For example,
simulating DPUs within the same or separate SmartSwitch or pairing distant
DPUs to form HA sets.  The SONiC Switch shall additionally be used with
Stateful traffic for VxLan encapsulation and decapsulation.

![HA SmartSwitch Topology](images/smartswitch_ha_topology.svg)

## Topology
### Configuration for HA testing
The topic presented is an interim for SmartSwitch HA testing.  The primary
goal is to illustrate a vision for simulating multiple HA scenarios using
a SmartSwitch mock-up to test DPU SmartSwitch behavior.   This document is
based on testing now before full Sonic integration.  We are working on
aligning test cases and setup with the HA test plan.

![HA topology](images/ha_test_topology.svg)

## Setup Configuration
There are three main test configurations used for exercising the various
test configurations. All three use a traffic generator.  Traffic is sent
through a SONiC capable switch and then to a SmartSwitch(s) which hosts a DPU
to be tested.

Configuration1.  In cases of a single DPU, the test will run under one
Smartswitch.  This objective is to baseline performance of the network
traffic with HA enabled.

Configuration2.  A second test configuration will use two DPUs from different
SmartSwitches.  In this case, HA will be enabled.  For example, dpu0 in
SmartSwitch0 will be the Active node and dpu0 in SmartSwitch1 shall be set to
Standby.  Both DPUs will share same network configurations.

## Test Methodology
Following test methodology will be used for measuring HA switchover and
performance.
* Traffic generator will be used to configure ENI peering between DPU ports.
* Data traffic will be sent from  server to server via SmartSwitch, server
to SmartSwitch and SmartSwitch to server.
* Depending on the test case, switchovers/failovers will be generated and
measured.
* Switchover between DPUs will be measured by noting down the precise time of
the switchover/failover event.  Traffic generator will create those
timestamps and provide us with the recovery statistics.


## Test cases

### Common Steps
Configuration1: Single SmartSwitch with Single DPU.
* Configure 1 DPUs networked within a SmartSwitch with HA not enable.
* The SmartSwitch configuration will consist of 1 DPU.
* The SONiC Switch will be configured to route traffic to SmartSwitch0 hosting
DPU.
* There will be a physical link between front panel ports of SONiC switch and
SmartSwitch0.
* Verify links are up and start all protocols and verify traffic is
established.
* Enable csv logging and check the state of the DPU through the API.
* Apply and start traffic stateful and stateless.

Configuration2: Two Smart Switches with Two DPUs.
![HA Perfect Sync Between HA Sets](images/ha_linkloss_test.svg)
* Configure 2 DPUs networked across two SmartSwitches forming an HA set.
* The SmartSwitch configuration will consist of 2 DPUs sharing the same
network configurations such as: IPs, MACs, VLan/VxLan, ENIs.
* The SONiC Switch will be configured to split traffic into two separate
entities.
* There will be a physical link between front panel ports of both
SmartSwitch0 and SmartSwitch1 and SONiC switch.
* For traffic from server (simulating T2), it will be using 1 link to
SmartSwitch NPU.
* For traffic from SmartSwitch NPU to the other NPU, we will use 2 links as
ECMP groups to simulate multi-T0 bounce-back routing.
* Verify links are up and start all protocols and verify traffic is
established.
* Enable csv logging and check the state of the DPUs through the API.
* Apply and start traffic stateful and stateless.

### Test Metrics
Each test case will use the following metrics to measure performance of the HA
failover/switchover for all test cases.

The following metrics shall be collected Before and After switchover is
initiated.

| Performance Metric                  | Achieved |
|:------------------------------------|:--------:|
| Concurrent Connections              |         |
| CPS                                 |         |
| PPS                                 |         |
| TCP Connection Breaks               |         |

As soon as failover/switchover is initiated a timer will be initiated to
measure DPU pair switchover.

| Failover/Switchover<br/>Type |                   Event                    | Convergence (s) |
|:------------------------|:------------------------------------------:| :---: |
|                         | Switchover time from <br/>Active-to-Standby DPU | 0  |

* TODO: Add flow comparison, dump all flows from both DPUs and compare them using
Dash FLow API.

### Test case1 CPS Without HA Enabled
#### Test Objective 1
* Baseline performance of the SmartSwitch system before HA sets are
established.
* Test metrics will be collected on a single DPU within a SmartSwitch

![HA CPS Without HA Enabled](images/ha_test_cps_ha_not_enabled.svg)
#### Steps for Test Case 1
* Refer to the section Common Steps Configuration1.
* Using traffic generator tools to verify metrics associated with number of
Concurrent
Connections, Connection rate, and TCP/UDP failures collect data before, after
completion of test.


### Test case2 Planned Switchover Between HA Sets
#### Test Objective 2
* Reference HA-SmartSwitch-test_plan Module 1 Normal OP and Planned Events.
Reference the following test cases:
    * Normal Op - Active
    * Normal Op - Standby
    * Planned Switchover - Active
    * Planned Switchover - Backup

![HA Perfect Sync Between HA Sets](images/ha_linkloss_test.svg)
#### Steps for Test Case 2
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss.
* Verify normal operation.  Active DPU and Standby DPU states remain the same.
* Through mgmt switch send commands to set Active DPU to Standby. A switchover
shall be triggered.
* The Backup should become Active immediately.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after switchover.

### Test case3 Planned Switchover Perfect Sync Between HA Sets
#### Test Objective 3
* Reference HA-SmartSwitch-test_plan Module 1 Normal OP and Planned Events.
  Reference the following test cases:
    * Normal Op - Active
    * Normal Op - Standby
    * Planned Switchover - Active
    * Planned Switchover - Backup

![HA Perfect Sync Between HA Sets](images/ha_linkloss_test.svg)
#### Steps for Test Case 3
* Refer to the section Common Steps Configuration1.
* Verify traffic is flowing without any loss.
* Add a second SmartSwitch with DPU set to Standby.
* Verify normal operation.  Active DPU and Standby DPU states remain the same.
* Through mgmt switch send commands to sync the Standby DPU to the Active.
the second DPU shall join the HA set.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after switchover.

### Test case4 Link Failures Active NPU to DPU Probe Drop Active
#### Test Objective 4
Verify packet flow when Active NPU to DPU link starts dropping probe packets.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 4
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Active side.
* Through mgmt remove link connection between Active DPU and NPU to drop packets.
* Add ACL to block traffic the state should not change.
* Mark start time at beginning of test as link connection is removed.
* Role of the DPUs will not change.
* Standby DPU will start to receive traffic will be verified by rx/tx counters.
* DPU of SmartSwitch0 stays active.
* DPU of SmartSwitch1 remains standby.
* Measure convergence time from start of the link removal between
SmartSwitch0 and SmartSwitch1 switchover.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after unplanned event.

### Test case5 Link Failures Active NPU to DPU Probe Drop Standby
#### Test Objective 5
Verify packet flow when Active NPU to DPU link starts dropping probe packets.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 5
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Standby side.
* Through mgmt remove link connection between Active DPU and NPU to drop packets.
* Add ACL on DPU side to completely block the data port to simulate the DPU
  link failure.
* Mark start time at beginning of test as link connection is removed.
* Role of the DPUs will not change.
* Standby DPU will start to receive traffic will be verified by rx/tx counters.
* DPU of SmartSwitch0 stays active.
* DPU of SmartSwitch1 remains standby.
* Measure convergence time from start of the link removal between
  SmartSwitch0 and SmartSwitch1 switchover.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case6 Link Failures Standby NPU to DPU Probe Drop Active
#### Test Objective 6
Verify packet flow when Standby NPU to DPU link starts dropping probe packets.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 6
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Active side.
* Through mgmt remove link connection between Standby DPU and NPU to drop packets.
* Add ACL on DPU side to completely block the data port to simulate the DPU
  link failure.
* Mark start time at beginning of test as link connection is removed.
* DPU of SmartSwitch0 becomes standalone.
* DPU of SmartSwitch1 shall become anything but active.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case7 Link Failures Standby NPU to DPU Probe Drop Standby
#### Test Objective 7
Verify packet flow when Standby NPU to DPU link starts dropping probe packets.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 7
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Standby side.
* Through mgmt remove link connection between Standby DPU and NPU to drop packets.
* Add ACL on DPU side to completely block the data port to simulate the DPU
  link failure.
* Mark start time at beginning of test as link connection is removed.
* DPU of SmartSwitch0 becomes standalone.
* DPU of SmartSwitch1 shall become anything but active.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case8 Link Failures Active T1-T0 Link Drop Active
#### Test Objective 8
Verify packet flow when T1-T0 link drop.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 8
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Active side.
* Enable link from the BBR ECMP group and remove other link. Nothing should fail.
* Then remove the other link from the BBR ECMP group.  DPU to DPU probe will fail
and HA role will change to standalone.
* Mark start time at beginning of test as link connection is removed.
* DPU of SmartSwitch0 becomes non-active.
* DPU of SmartSwitch1 becomes standalone.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case9 Link Failures Active T1-T0 Link Drop Standby
#### Test Objective 9
Verify packet flow when T1-T0 link drop.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 9
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Standby side.
* Enable link from the BBR ECMP group and remove other link. Nothing should fail.
* Then remove the other link from the BBR ECMP group.  DPU to DPU probe will fail
  and HA role will change to standalone.
* Mark start time at beginning of test as link connection is removed.
* DPU of SmartSwitch0 becomes non-active.
* DPU of SmartSwitch1 becomes standalone.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case10 Link Failures Standby T1-T0 Link Drop Active
#### Test Objective 10
Verify packet flow when T1-T0 link drop.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 10
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Active side.
* Enable link from the BBR ECMP group and remove other link. Nothing should fail.
* Then remove the other link from the BBR ECMP group.  DPU to DPU probe will fail
  and HA role will change to standalone.
* Mark start time at beginning of test as link connection is removed.
* DPU of SmartSwitch0 becomes standalone.
* DPU of SmartSwitch1 becomes anything but active.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case11 Link Failures Standby T1-T0 Link Drop Standby
#### Test Objective 11
Verify packet flow when T1-T0 link drop.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 11
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss through the Standby side.
* Enable link from the BBR ECMP group and remove other link. Nothing should fail.
* Then remove the other link from the BBR ECMP group.  DPU to DPU probe will fail
  and HA role will change to standalone.
* DPU of SmartSwitch0 becomes standalone.
* DPU of SmartSwitch1 becomes anything but active.
* Measure convergence time from start of the link removal.
* Using traffic generator tools to verify metrics associated with number of
  Concurrent Connections, Connection rate, and TCP/UDP failures collect data
  before, during and after unplanned event.

### Test case12 DPULoss HA Set
#### Test Objective 12
* Reference HA-SmartSwitch-test_plan Module 6 Power down and hardware failure.

![HA DPULoss HA Set](images/ha_dpuloss_test.svg)
#### Steps for Test Case 12
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss.
* Through mgmt port poweroff or reboot Active DPU.
* Mark start time at beginning of test as DPU is removed from topology.
* There should be 100% failure with the Active DPU during switchover.
* DPU0 in SmartSwitch1 shall become the new Active DPU in the HA set.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Measure convergence time from start of the link removal on DPU0 and DPU1
switchover.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after switchover.
