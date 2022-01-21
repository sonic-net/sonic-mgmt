# Scaling of BGP EVPN VxLAN

- [Scaling of BGP EVPN VxLAN](#scaling-of-bgp-evpn-vxlan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Keysight Testbed](#keysight-testbed)
  - [Topology](#topology)
    - [SONiC switch as Leaf](#sonic-switch-as-leaf)
  - [Setup configuration](#setup-configuration)
  - [Bgp Evpn VxLan HLD](#bgp-evpn-vxlan-hld)
  - [Scalability Requirements](#scalability-requirements)
  - [Test cases](#test-cases)
    - [Test case # 1 - Validating maximum remote VTEPs (VXLAN destination tunnels) supported on switch - 512](#test-case--1---validating-maximum-remote-vteps-vxlan-destination-tunnels-supported-on-switch---512)
      - [Test objective](#test-objective)
      - [Test steps](#test-steps)
      - [Test results](#test-results)
  - [Test cases](#test-cases-1)
    - [Test case # 2 – Validating total L2 VNI supported per switch - 4K.](#test-case--2--validating-total-l2-vni-supported-per-switch---4k)
      - [Test objective](#test-objective-1)
      - [Test steps](#test-steps-1)
      - [Test results](#test-results-1)
  - [Test cases](#test-cases-2)
    - [Test case # 3 – Validating total L2 VNI supported per tunnel - 4K.](#test-case--3--validating-total-l2-vni-supported-per-tunnel---4k)
      - [Test objective](#test-objective-2)
      - [Test steps](#test-steps-2)
      - [Test results](#test-results-2)
  - [Test cases](#test-cases-3)
    - [Test case # 4 – Validating total EVPN participating VRF per switch - 512.](#test-case--4--validating-total-evpn-participating-vrf-per-switch---512)
      - [Test objective](#test-objective-3)
      - [Test steps](#test-steps-3)
      - [Test results](#test-results-3)
  - [Test cases](#test-cases-4)
    - [Test case # 5 – Host mac mobility from one VTEP to other.](#test-case--5--host-mac-mobility-from-one-vtep-to-other)
      - [Test objective](#test-objective-4)
      - [Test steps](#test-steps-4)
      - [Test results](#test-results-4)

## Overview
The purpose of these tests is to perform the scalability tests on BGP EVPN VxLAN and verify the performance of the SONiC system, closely resembling production environment.

### Scope
These tests are targeted on fully functioning SONiC system. Will cover functional and scalability testing of VxLAN using BGP EVPN as control plane to learn remote hosts.

### Keysight Testbed
The tests will use Single DUT Topology defined under Keysight Testbed section in testbed overview.

[Keysight Testbed](https://github.com/Azure/sonic-mgmt/blob/master/docs/testbed/README.testbed.Overview.md)

![Single DUT Topology ](Img/Single_DUT_Topology.png)

## Topology
### SONiC switch as Leaf

![SONiC DUT as Leaf ](Img/BGP_EVPN_Topology.png)

## Setup configuration
IPv4 EBGP/IBGP neighborship will be established for underlay and BGP EVPN will be used as the control plane protocol for overlay network. 

## Bgp Evpn VxLan HLD

[HLD](https://github.com/Azure/SONiC/blob/eeebbf6f8a32e5d989595b0816849e8ef0d15141/doc/vxlan/EVPN/EVPN_VXLAN_HLD.md)

## Scalability Requirements
* Total Remote VTEPs (VXLAN destination tunnels) - 512.
* Total L2 VNI per switch - 4K. 
* Total VNI per tunnel - 4K.
* Total EVPN participating VRF per switch - 512. 
  
## Test cases
### Test case # 1 - Validating maximum remote VTEPs (VXLAN destination tunnels) supported on switch - 512
#### Test objective
Verify that switch supports 512 remote VTEPs.

<p float="left">
  <img src="Img/Max_VTEP.png"  width="750"  hspace="50"/>
</p>


#### Test steps
* Conifgure Maximum number of vteps supported and divide across n number of spines. In this test case we are are using sample as 3 spines.
* Configure EBGP/IBGP as underlay protocol.
* Configure IBGP as overlay protocol for remote mac learning.
* Start all protocols.
* Verify that switch is able to learn all remote VTEPs and measure the CPU utilization and memory usage.
* Verify that different route types are learned and shown in database.
* Send traffic from local host to remote hosts configured behind these VTEPs.
* Enable egress tracking on vlan and see packets mapped between VNI and Vlan's.
* Traffic should flow without any loss at line rate.

#### Test results
* It supports only upto 128 VTEPs. 
* If we go beyond 128, VxLAN tunnel's are not coming up.
* Vxlan tunnel destination IP's are not seen in community images.


## Test cases
### Test case # 2 – Validating total L2 VNI supported per switch - 4K.
#### Test objective
  Verify that switch supports total 4K L2 VNI's.

<p float="left">
  <img src="Img/Max_L2VNI_Per_Switch.png" width="600"  hspace="50"/>
</p>


#### Test steps
* Configure maximum supported L2VNI per switch. In this case, we are distributing the max supported L2VNI across 10 vteps for each spine.
* Configure 133 MAC-VRFs per vtep.
* Configure EBGP/IBGP as underlay protocol.
* Configure IBGP as overlay protocol for remote mac learning.
* Start all protocols.
* Verify that switch is able to learn all remote VTEPs and measure the CPU utilization and memory usage.
* Verify that different route types are learned and shown in database.
* Send traffic from local host to remote hosts configured behind these VTEPs.
* Enable egress tracking on vlan and see packets mapped between VNI and Vlan's.
* Traffic should flow without any loss at line rate.

#### Test results


## Test cases
### Test case # 3 – Validating total L2 VNI supported per tunnel - 4K.
#### Test objective
Verify that switch supports total 4K L2 VNI's per tunnel.

<p float="left">
  <img src="Img/Max_L2VNI_Per_Tunnel.png" width="600"  hspace="50"/>
</p>


#### Test steps
* Configure 4K L2VNI per tunnel. Configure 4K MAC-VRF behind vtep. Simulate same vtep behind all spines.
* Configure EBGP/IBGP as underlay protocol.
* Configure IBGP as overlay protocol for remote mac learning.
* Start all protocols.
* Verify that switch is able to learn all remote VTEPs and measure the CPU utilization and memory usage.
* Verify that different route types are learned and shown in database.
* Send traffic from local host to remote hosts configured behind these VTEPs.
* Enable egress tracking on vlan and see packets mapped between VNI and Vlan's.
* Traffic should flow without any loss at line rate

#### Test results


## Test cases
### Test case # 4 – Validating total EVPN participating VRF per switch - 512.
#### Test objective
Verify that swich supports upto 512 VRF instances.

<p float="left">
  <img src="Img/Max_VRF.png" width="600"  hspace="50"/>
</p>


#### Test steps
* Configure 512 VTEPs on each spine having 1 L3VNI(VRF). Advertise same 512 VTEPs behind each spine. So, overall 512 VRF per switch.
* Configure EBGP/IBGP as underlay protocol.
* Configure IBGP as overlay protocol for remote mac learning.
* Start all protocols.
* Verify that switch is able to learn all remote VTEPs and measure the CPU utilization and memory usage.
* Verify that different route types are learned and shown in database.
* Send traffic from local host to remote hosts configured behind these VTEPs.
* Enable egress tracking on vlan and see packets mapped between VNI and Vlan's.
* Traffic should flow without any loss at line rate.

#### Test results


## Test cases
### Test case # 5 – Host mac mobility from one VTEP to other.
#### Test objective
Verify that swich supports host mobility and learns the informtion through new VTEP.

<p float="left">
  <img src="Img/Host_Mobility.png" width="600"  hspace="50"/>
</p>


#### Test steps
* Configure one VTEP behind each spine. 
* onfigure EBGP/IBGP as underlay protocol.
* Configure IBGP as overlay protocol for remote mac learning.
* Start all protocols.
* Move host from one VTEP1 to VTEP2 and see that it learns the new information that it has been moved.
* Verify that switch is able to learn all remote VTEPs and measure the CPU utilization and memory usage.
* Verify that different route types are learned and shown in database.
* Send traffic from local host to remote hosts configured behind these VTEPs.
* Enable egress tracking on vlan and see packets mapped between VNI and Vlan's.
* Traffic should flow without any loss at line rate.

#### Test results
