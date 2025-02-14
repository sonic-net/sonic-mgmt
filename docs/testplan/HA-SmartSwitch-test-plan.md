# Smart Switch HA – SONiC MGMT Test Plan

## Revision History

| Date       | Author        | Description                      |
|------------|---------------|----------------------------------|
| 2024-02-06 | Jing Zhang   | Initial draft                    |

## Table of Contents

<!-- TOC orderedlist:false -->

- [Smart Switch HA – SONiC MGMT Test Plan](#smart-switch-ha--sonic-mgmt-test-plan)
    - [Revision History](#revision-history)
    - [Table of Contents](#table-of-contents)
    - [Scope](#scope)
    - [Topology](#topology)
    - [Test Methodology](#test-methodology)
    - [Test Plan](#test-plan)
        - [Downstream T2->T0 Traffic Verification](#downstream-t2-t0-traffic-verification)
            - [Module 1 Normal OP](#module-1-normal-op)
            - [Module 2 Planned Events](#module-2-planned-events)
            - [Module 3 	BFD state pinned](#module-3-%09bfd-state-pinned)
            - [Module 4 	HA state pinned by upstream service](#module-4-%09ha-state-pinned-by-upstream-service)
            - [Module 5 	Link Failures](#module-5-%09link-failures)
            - [Module 6 	Critical Process Crash](#module-6-%09critical-process-crash)
            - [Module 7 	Power down and hardware failure](#module-7-%09power-down-and-hardware-failure)
            - [Module 8 	Operations](#module-8-%09operations)
        - [Upstream T0->T2 Traffic Verification](#upstream-t0-t2-traffic-verification)
            - [Module 1 Normal OP](#module-1-normal-op)
    - [Test Utilities](#test-utilities)

<!-- /TOC -->

## Scope 
This document proposes solutions for Smart Switch High-Availability test plans. The document will cover smart switch test scenarios.

The goal of this test plan is to verify HA state machine behavior in normal operation scenarios and network failure scenarios with [t1-smartswitch-ha](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/vars/topo_t1-smartswitch-ha.yml) topology. Both control plane and data plane will need to be verified in the test cases. 

## Topology

Tests will run on a sonic-mgmt testbed. The key components will be:
1. Test server
1. Fanout switches
    * root fanout switch
    * leaf fanout switch
1. SONiC DUTs -- the two smartswitches.


Key aspects of the physical connection:
1. Every DUT port is connected to the leaf fanout switch.
1. Every leaf fanout switch has unique VLAN tag for every DUT port.
1. Root fanout switch connects leaf fanout switches and test servers using 802.1Q trunks. 

For HA testbeds, the 2 smartswitch DUTs will be connected to the same leaf fanout, to eliminate factors that are irrelevant to the test scenarios. 

Any test server can access any DUT port by sending a packet with the port VLAN tag. In test servers, a set of dockers can be created for running cEOS to simulate neighbors of the SONiC DUT. A PTF container (based on the PTF test framework) for injecting/sniffing packets will be created. The PTF docker, the cEOS dockers and VLAN interfaces in test server can be interconnected by open vSwitch bridges. 

For HA testbeds, the 2 smartswitch DUTs will share the same set of cEOS dockers as the neighbors, and same PTF docker for packets injecting and sniffing. 

![physical-connection](./Img/topo_smartswitch_ha.png)

Please refer to [sonic-mgmt testbed overview](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Overview.md) for more about testbed setup and diagrams, also [HA Topology](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/high-availability/smart-switch-ha-hld.md#4-network-physical-topology) for HA Network Physical Design. 


## Test Methodology

1. Open flow rules are configured on OVS Bridges to control the traffic flow:
    * All packets sent out from Neighbor are only forwarded to DUT
    * All packets sent out from DUT are forwarded to Neighbor and PTF
    * All packets sent out from PTF are only forwarded to DUT
1. Traffic will be sent from PTF docker, and sniffed on PTF docker by sonic-mgmt test scripts.
1. Depending on the test cases, switchovers will be triggered and verified. 
1. Control plane status, DPU counters, metering data will be measured for the tests.

## Test Plan
Assuming there is a pair of DPUs in the system, and at the step of test setup, we have DPU-1 as active, DPU-2 as standby. 


### Downstream (T2->T0) Traffic Verification 

For some of the cases in downstream traffic verification, you will see two versions, one is traffic sending through DPU1, and the other one is traffic sending through DPU2. The purpose of  it is to verify:
* Traffic shouldn’t be disrupted when failures happen on standby side.
* Traffic should be tunneled if landing on standby side. 

The name convention of a test case will be “\<Test Scenario\>-[Active|Standby]”, indicating the traffic is sent through the initial active or standby side. 

#### Module 1 Normal OP 
| Case                      | Goal                                       | Test Steps                                                                                 | Expected Control Plane Behavior                               | Expected Data Plane Behavior                      |
|---------------------------|--------------------------------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------|
| Normal OP – Active        | Verify normal operation in healthy state  | • Start downstream I/O through Active side                                                 | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption.          |
| Normal OP – Standby       | Verify normal operation in healthy state  | • Start downstream I/O through Standby side                                                | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption from the active side.          |

#### Module 2 Planned Events
| Case                      | Goal                                       | Test Steps                                                                                 | Expected Control Plane Behavior                               | Expected Data Plane Behavior                      |
|---------------------------|--------------------------------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------|
| Planned Switchover - Active | Verify zero traffic loss in planned maintenance | • Start downstream I/O through active side<br>• Issue switchover following planned maintenance procedure | DPU-1 becomes standby, DPU-2 becomes active.                | T0 receives packets without disruption.          |
| Planned Switchover – Standby | Verify zero traffic loss in planned maintenance | • Start downstream I/O through standby side<br>• Issue switchover following planned maintenance procedure | DPU-1 becomes standby, DPU-2 becomes active.              | T0 receives packets without disruption.          |
| Planned shutdown          | Verify zero traffic loss in planned shutdown | • Start downstream I/O <br>• Issue shutdown on standby side                                 | DPU-1 becomes standalone, DPU-2 is dead.                    | T0 receives packets without disruption.          |


####  Module 3 	BFD state pinned
Here the BFD pin down refers to a upstream service provided state, which does not essentially indicate a link failure hence does not trigger an actual switchover.

| Case                                    | Goal                                                | Test Steps                                                                                     | Expected Control Plane Behavior                               | Expected Data Plane Behavior                      |
|-----------------------------------------|-----------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------|
| BFD state UP pinned as DOWN – Active    | Verify traffic flow honored the pinned state.       | • Start downstream I/O through active side<br>• Pin DPU1 BFD probe state as DOWN.             | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption.          |
| BFD state UP pinned as DOWN – Standby   | Verify traffic flow honored the pinned state.       | • Start downstream I/O through standby side<br>• Pin DPU1 BFD probe state as DOWN.            | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption.          |
| Both side pinned as DOWN – Active       | Verify traffic flow honored the pinned state.       | • Start downstream I/O through active side<br>• Pin DPU1 and DPU2 BFD probe state as DOWN.   | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption.          |
| Both side pinned as DOWN – Standby      | Verify traffic flow honored the pinned state.       | • Start downstream I/O through standby side<br>• Pin DPU1 and DPU2 BFD probe state as DOWN.  | DPU1 remains active, DPU2 remains standby.                   | T0 receives packets without disruption.          |


####  Module 4 	HA state pinned by upstream service

| Case                           | Goal                                           | Test Steps                                                                                                            | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|--------------------------------|------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| HA state pinned – Active       | Verify control plane honors the pinned state. | • Start downstream I/O through DPU1.<br>• Pin DPU2 as standalone.<br>• Remove Pin.                                    | DPU1 becomes standby, DPU2 becomes active.        | T0 receives packets without disruption.          |
| HA state pinned – Standby      | Verify control plane honors the pinned state. | • Start downstream I/O through DPU2.<br>• Pin DPU2 as standalone.<br>• Remove Pin.                                    | DPU1 becomes standby, DPU2 becomes active.        | T0 receives packets without disruption.          |


####  Module 5 	Link Failures 

| Case                                    | Goal                                                           | Test Steps                                                                                                     | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|-----------------------------------------|----------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| Active NPU-to-DPU probe drop -Active    | Verify packet flow when NPU1 to DPU1 link starts dropping probe packets. | • Start downstream I/O through active side.<br>• Configure the NPU1-to-DPU1 link to drop packets.         | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets with 1 allowed disruption.  |
| Active NPU-to-DPU probe drop -Standby   | Verify packet flow when NPU1 to DPU1 link starts dropping probe packets. | • Start downstream I/O through standby side.<br>• Configure the NPU1-to-DPU1 link to drop packets.        | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets with 1 allowed disruption.  |
| Standby NPU-to-DPU probe drop – Active  | Verify packet flow when NPU2 to DPU2 link starts dropping probe packets. | • Start downstream I/O through active side.<br>• Configure the NPU2-to-DPU2 link to drop packets.         | DPU1 becomes standalone, DPU2 is anything but active. | T0 receives packets without disruption.          |
| Standby NPU-to-DPU probe drop – Standby | Verify packet flow when NPU2 to DPU2 link starts dropping probe packets. | • Start downstream I/O through standby side.<br>• Configure the NPU2-to-DPU2 link to drop packets.       | DPU1 becomes standalone, DPU2 is anything but active. | T0 receives packets without disruption.          |
| Active T1-T0 link drop – Active         | Verify packet flow when T1-T0 link drop.                      | • Start downstream I/O through active side.<br>• Configure DPU1 side T1-T0 link drop.                       | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets with 1 allowed disruption.  |
| Active T1-T0 link drop – Standby        | Verify packet flow when T1-T0 link drop.                      | • Start downstream I/O through standby side.<br>• Configure DPU1 side T1-T0 link drop.                      | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets with 1 allowed disruption.  |
| Standby T1-T0 link drop – Active        | Verify packet flow when T1-T0 link drop.                      | • Start downstream I/O through active side.<br>• Configure DPU2 side T1-T0 link drop.                       | DPU1 becomes standalone, DPU2 is anything but active. | T0 receives packets without disruption.          |
| Standby T1-T0 link drop - Standby      | Verify packet flow when T1-T0 link drop.                      | • Start downstream I/O through standby side.<br>• Configure DPU2 side T1-T0 link drop.                      | DPU1 becomes standalone, DPU2 is anything but active. | T0 receives packets without disruption.          |

#### Module 6 	Critical Process Crash 
For all process crash cases, we will have 4 variations, it’s 
1.	Process crash on DPU1, traffic landing on DPU2
2.	Process crash on DPU2, traffic landing on DPU1
3.	Process crash on DPU1, traffic landing on DPU1
4.	Process crash on DPU2, traffic landing on DPU2
The expected behavior is same, that HA state remains unchanged. No data plane disruption is expected. 

| Case            | Goal                                     | Test Steps                                            | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|-----------------|------------------------------------------|-------------------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| syncd on DPU    | Verify when syncd crash on DPU.         | • Start downstream I/O<br>• Kill syncd on DPU       | DPU1 remains active, DPU2 remains standby.        | T0 receives packets without disruption.          |
| hamgrd on NPU   | Verify when hamgrd crash on NPU.        | • Start downstream I/O<br>• Kill hamgrd on NPU      | DPU1 remains active, DPU2 remains standby.        | T0 receives packets without disruption.          |
| pmon on NPU     | Verify when pmon crash on NPU.          | • Start downstream I/O<br>• Kill pmon on NPU        | DPU1 remains active, DPU2 remains standby.        | T0 receives packets without disruption.          |
| bgpd on NPU     | Verify when bgpd crash on NPU.          | • Start downstream I/O<br>• Kill bgpd on NPU        | DPU1 remains active, DPU2 remains standby.        | T0 receives packets without disruption.          |

####  Module 7 	Power down and hardware failure
For each case in this module, there are 2 variations:
1.	Failure happens on DPU1, traffic landing on DPU2
2.	Failure happens on DPU2, traffic landing on DPU1

| Case                   | Goal                                             | Test Steps                                           | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|------------------------|--------------------------------------------------|------------------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| DPU hardware failure   | Verify traffic flow when DPU hardware fails     | • Start downstream I/O<br>• Force DPU reset (ChassisStateDB DPU_STATE) | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets without disruption.          |
| T1 unplanned reboot    | Verify traffic when T1 ungracefully reboots     | • Start downstream I/O<br>• Reboot T1               | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets without disruption.          |
| T1 power down          | Verify traffic when T1 power down               | • Start downstream I/O<br>• Toggle T1 PDU link     | DPU1 becomes non-active, DPU2 becomes standalone. | T0 receives packets without disruption.          |


#### Module 8 	Operations
For each case in this module, there are 2 variations:
1.	Failure happens on DPU1, traffic landing on DPU2
2.	Failure happens on DPU2, traffic landing on DPU1

| Case                                   | Goal                                                    | Test Steps                                                                   | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|----------------------------------------|---------------------------------------------------------|------------------------------------------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| Shutdown/Startup BGP sessions from NPU | Verify traffic when shutdown and startup sessions from NOS | • Start downstream I/O<br>• Shutdown all BGP sessions on NPU<br>• Startup all BGP sessions on NPU | Impacted side become non-active, the peer side become standalone. | T0 receives packets without disruption.          |
| TSA on T1                              | Verify traffic when TSA on T1                            | • Start downstream I/O<br>• TSA on T1<br>• TSB on T1                        | Impacted side become non-active, the peer side become standalone. | T0 receives packets without disruption.          |
| Config reload on T1                    | Verify traffic when config reload on T1                  | • Start downstream I/O<br>• Config reload on T1                              | Impacted side become non-active, the peer side become standalone. | T0 receives packets without disruption.          |

### Upstream (T0->T2) Traffic Verification
Upstream traffic verification can be trivial due to the nature of this test topology. We will add a case in the normal operation module.

#### Module 1 Normal OP

| Case       | Goal                                   | Test Steps                               | Expected Control Plane Behavior                   | Expected Data Plane Behavior                      |
|------------|----------------------------------------|------------------------------------------|--------------------------------------------------|---------------------------------------------------|
| Normal OP  | Verify normal operation in healthy state | • Start upstream I/O through            | DPU1 remains active, DPU2 remains standby.       | T2 receives packets without disruption.          |

## Test Utilities 
There are some test utilities we need to implement to cover all test scenarios, including but not limited to:
1.	Utilities to simulator gnmi requests from upstream service.
2.	Utilities to config link drops (add ACL rules to drop probe packets),  kill critical process etc. 
3.	Utilities to “fake” a failure signature in DB. 

