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
    - [Test case # 2 – Perfect Sync Between HA Sets](#test-case2-perfect-sync-between-ha-sets)
       - [Test objective 2](#test-objective-2)
       - [Test steps 2](#steps-for-test-case-2)
    - [Test case # 3 - Link Loss HA Set](#test-case3-link-loss-ha-set-)
        - [Test objective 3](#test-objective-3)
        - [Steps for Test Case 3](#steps-for-test-case-3)
    - [Test case # 4 - Link Loss Multiple HA Sets](#test-case4-link-loss-multiple-ha-sets)
        - [Test objective 4](#test-objective-4)
        - [Test steps 4](#steps-for-test-case-4)
    - [Test case # 5 – DPU Loss HA Set](#test-case5-dpuloss-ha-set)
        - [Test objective 5](#test-objective-5)
        - [Test steps 5](#steps-for-test-case-5)
    - [Test case # 6 – DPU Loss Multiple HA Sets](#test-case6-dpuloss-multiple-ha-sets)
        - [Test objective 6](#test-objective-6)
        - [Test steps 6](#steps-for-test-case-6)

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

Configuration3.  A third test configuration will use four DPUs.  HA sets will
be established between dpu0 of SmartSwitch0 and SmartSwitch1 and dpu1 of
SmartSwitch0 and SmartSwitch1


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
Configuration1
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

Configuration2
* Configure 2 DPUs networked across two SmartSwitches forming an HA set.
* The SmartSwitch configuration will consist of 2 DPUs sharing the same
network configurations such as: IPs, MACs, VLan/VxLan, ENIs.
* The SONiC Switch will be configured to split traffic into two separate
entities.
* There will be a physical link between front panel ports of both
SmartSwitch0 and SmartSwitch1 and SONiC switch.
* Verify links are up and start all protocols and verify traffic is
established.
* Enable csv logging and check the state of the DPUs through the API.
* Apply and start traffic stateful and stateless.

Configuration3
* Configure 4 DPUs networked within separate SmartSwitches forming a HA set
between SmartSwitch0 and SmartSwitch1.
* The SmartSwitch configuration will consist of 4 DPUs sharing the same
network configurations such as: IPs, MACs, VLan/VxLan, ENIs.  SmartSwitch0
will have DPU0 and DPU1 running. SmartSwitch1 also will use DPU0 and DPU1
running.
* The SONiC Switch will be configured to split traffic into two separate
entities going to both SmartSwitches.
* There will be a physical link between front panel ports of SmartSwitch0 and
SmartSwitch1 and SONiC switch.
* The HA set shall be between DPU0s in SmartSwitch0 and 1. Also an HA set
between DPU1s in SmartSwitch0 and SmartSwitch1.
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
| TCP Client Failures Resets Sent     |         |
| TCP Client Failures Resets Recieved |         |
| TCP Client Failures Resets Retries  |         |
| TCP Server Failures Resets Sent     |         |
| TCP Server Failures Resets Recieved |         |
| TCP Server Failures Resets Retries  |         |

As soon as failover/switchover is initiated a timer will be initiated to
measure DPU pair switchover.

| Failover/Switchover<br/>Type |                   Event                    | Convergence (s) |
|:------------------------|:------------------------------------------:| :---: |
|                         | Switchover time from <br/>Active-to-Standby DPU | 0  |

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



### Test case2 Perfect Sync Between HA Sets
#### Test Objective 2
* Reference HA-SmartSwitch-test_plan Module 1 Normal OP and Planned Events.
Reference the following test cases:
    * Active, Normal OP - Standby
    * Planned Switchover - Active
    * Planned Switchover - Backup

![HA Perfect Sync Between HA Sets](images/ha_test_perfect_sync.svg)
#### Steps for Test Case 2
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss.
* Through mgmt switch traffic from the Active to Standby node.
* Mark start time at beginning of test as DPU is removed from topology.
* The Backup should become Active immediately.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Perform perfect sync between DPUs, flow tables shall sync, verify success
by observing state
sync state.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after switchover.

### Test case3 Link Loss HA Set
#### Test Objective 3
In this scenario we will test the unplanned event link loss between an
Active DPU to it's paired Standby DPU.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss](images/ha_linkloss_test.svg)
#### Steps for Test Case 3
* Refer to the section Common Steps Configuration2.
* Verify traffic is flowing without any loss.
* Through mgmt port remove link connection between DPU0 of SmartSwitch0.
* Mark start time at beginning of test as link connection is removed.
* There should be 100% link failure with the Active DPU during unplanned
event.
* DPU1 shall become the new Active DPU in the HA set.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Measure convergence time from start of the link removal between
SmartSwitch0 and SmartSwitch1 switchover.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after unplanned event.

### Test case4 Link Loss Multiple HA Sets
#### Test Objective 4
In this scenario we will test the unplanned event link loss between an Active
DPUs to it's paired DPUs, here multiple HA sets have been established before
event.
* Reference HA-SmartSwitch-test_plan Module 4 Link Failures.

![HA LinkLoss Multiple HA Sets](images/ha_linkloss_multiple_ha_sets.svg)
#### Steps for Test Case 4
* Refer to the section Common Steps Configuration3.
* Verify traffic is flowing without any loss.
* Through mgmt port remove link connection between SmartSwitch0 and DPU0.
Additional remove link on DPU1 in SmartSwitch1.
* Mark start time at beginning of test as link connection is removed.
* There should be 100% link failure with the Active DPU during unplanned
event.
* Standby nodes shall become the new Active in the HA set.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Measure convergence time from start of the link removal on switchover.
* Using traffic generator tools to verify metrics associated with number of
Concurrent
Connections, Connection rate, and TCP/UDP failures collect data before,
during and after switchover.


### Test case5 DPULoss HA Set
#### Test Objective 5
* Reference HA-SmartSwitch-test_plan Module 6 Power down and hardware failure.

![HA DPULoss HA Set](images/ha_dpuloss_test.svg)
#### Steps for Test Case 5
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


### Test case6 DPULoss Multiple HA Sets
#### Test Objective 6
* Reference HA-SmartSwitch-test_plan Module 6 Power down and hardware failure.

![HA DPULoss Multple HA Sets](images/ha_dpuloss_multiple_ha_sets.svg)

#### Steps for Test Case 6
* Refer to the section Common Steps Configuration3.
* Verify traffic is flowing without any loss.
* Through mgmt port poweroff or reboot Active DPU.
* Mark start time at beginning of test as DPU is removed from topology.
* There should be 100% failure with the Active DPU during switchover.
* DPU3 shall become the new Active DPU in the HA set.
* Mark time when the Standby DPU becomes Active and fully running traffic.
* Measure convergence time from start of the link removal between HA sets and
switchover.
* Using traffic generator tools to verify metrics associated with number of
Concurrent Connections, Connection rate, and TCP/UDP failures collect data
before, during and after switchover.
