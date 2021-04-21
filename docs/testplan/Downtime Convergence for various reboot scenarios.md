# Downtime convergence for various reboot scenarios

- [Downtime convergence for various reboot scenarios](#downtime-convergence-for-various-reboot-scenarios)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Keysight Testbed](#keysight-testbed)
  - [Topology](#topology)
    - [SONiC switch as ToR](#sonic-switch-as-tor)
  - [Setup configuration](#setup-configuration)
  - [Test Methodology](#test-methodology)
  - [Test cases](#test-cases)
    - [Test case # 1 - Downtime convergence measurement for warm-reboot while sending traffic](#test-case--1--downtime-convergence-measurement-for-warm-reboot-while-sending-traffic)
      - [Test objective](#test-objective)
      - [Test steps](#test-steps)
      - [Test results](#test-results)
  - [Test cases](#test-cases-1)
    - [Test case # 2 – Downtime Convergence measurement for fast-reboot while sending traffic.](#test-case-2-downtime-convergence-measurement-for-fast-reboot-while-sending-traffic)
      - [Test objective](#test-objective-1)
      - [Test steps](#test-steps-1)
      - [Test results](#test-results-1)
  - [Test cases](#test-cases-2)
    - [Test case # 3 – Downtime Convergence measurement for cold-reboot while sending traffic.](#test-case-3-downtime-convergence-measurement-for-cold-reboot-while-sending-traffic)
      - [Test objective](#test-objective-2)
      - [Test steps](#test-steps-2)
      - [Test results](#test-results-2)
  - [Test cases](#test-cases-3)
    - [Test case # 4 – Downtime Convergence measurement for soft-reboot while sending traffic.](#test-case-4-downtime-convergence-measurement-for-soft-reboot-while-sending-traffic)
      - [Test objective](#test-objective-3)
      - [Test steps](#test-steps-3)
      - [Test results](#test-results-3)
    - [Call for action](#call-for-action)

## Overview
The purpose of these tests is to measure the downtime convergence of the system or the service by evaluating various reboot scenarios in the SONiC system, closely resembling production environment.

### Scope
These tests are targeted on fully functioning SONiC system. We will be measuring the downtime convergence of a particular system or a system as a whole while evaluating reboot scenarios such as warm-reboot, fast-reboot, cold-reboot and soft-reboot.

### Keysight Testbed
The tests will run on following testbeds:
* t0, t1

![Single DUT Topology ](Img/Single_DUT_Topology.png)

## Topology
### SONiC switch as ToR

![SONiC DUT as ToR ](Img/Server-T1-Topology.png)

## Setup configuration
IPv4 EBGP neighborship will be established on a LAG between SONiC DUT and directly connected test ports. Test ports inturn will simulate the ToR's and Leafs by advertising IPv4/IPv6, dual-stack routes.

## Test Methodology
Following test methodology will be used for measuring downtime convergence. 
* Traffic generator will be used to configure ebgp peering between chassis ports and SONiC DUT on top of LAG by advertising IPv4/IPv6, dual-stack routes. 
* Data traffic will be sent from  server to server, server to T1 and T1 to server. 
* Depending on the test case, the reboots will be generated and downtime convergence will be measured.
* Downtime convergence will be measured by noting down the precise time of the data plane below threshold timestamp and the data plane above threshold timestamp. Traffic generator will create those timestmaps and provide us with the data plane downtime convergence statistics.
* In order to measure the control plane downtime convergence, we will be pinging the DUT loopback interface to measure how long it takes to respond back to the ping once it comes back online.
* Similarly for measuring protocol downtime convergence can be neasured for concerned protocol, in this case it is BGP by polling the state of the protocol. 
  
## Test cases
### Test case # 1 - Downtime convergence measurement for warm-reboot while sending traffic
#### Test objective
Measure the downtime convergence time when warm-reboot is issued while traffic is running.

<p float="left">
  <img src="Img/Downtime-Convergence-Topology.png" width="280"  hspace="100"/>
  <img src="Img/Downtime-convergence-graph.png" width="400" /> 
</p>


#### Test steps
* Configure a IPv4 EBGP session between test port and the SONiC switch on top of a LAG.
* Advertise 4000 IPv4 and 3000 IPv6 routes through BGP.
* Configure 2000 vlan hosts per server.
* Start all protocols and verify that IPv4 BGP neighborship is established.
* Create server-server, server-T1 and T1-server data traffics and enable tracking by "Destination Endpoint" and by "Destination session description".
* Set the desired threshold value for receiving traffic. By default it will be set to 90% of expected receiving rate.
* Apply and start the data traffic.
* Verify that traffic is flowing without any loss.
* Enable csv logging or check the state of bgp protocol through API.
* Control plane convergence time is measured by pinging the loopback interface of switch. 
* Now do warm-reboot by issuing the command "sudo warm-reboot".
* Verify that there is no traffic loss after the switch is back up. 
* Drill down by "Destination Endpoint" under traffic statistics to get the data plance convergence time.
* In general the convergence value will fall in certain range. In order to achieve proper results, run the test multiple times and average out the test results. 
* Set it back to default configuration.
#### Test results
| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 0  |
|   | Server-T1 Traffic  | 315  |
| Warm-reboot  | T1-Server Traffic  | 0  |
|   | Control plane (Loopback ping)  | 23  |
|   | BGP Control plane  | 149  |

For above test case, below are the test results when BGP is running on routed interface without LAG.

| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 0  |
|   | Server-T1 Traffic  | 255  |
| Warm-reboot  | T1-Server Traffic  | 0  |
|   | Control plane (Loopback ping)  | 23  |
|   | BGP Control plane  | 91  |

## Test cases
### Test case # 2 – Downtime Convergence measurement for fast-reboot while sending traffic.
#### Test objective
Measure the downtime convergence time when fast-reboot is issued while traffic is running.

<p float="left">
  <img src="Img/Downtime-Convergence-Topology.png" width="280"  hspace="100"/>
  <img src="Img/Downtime-convergence-graph.png" width="400" /> 
</p>


#### Test steps
* Configure a IPv4 EBGP session between test port and the SONiC switch on top of a LAG.
* Advertise 4000 IPv4 and 3000 IPv6 routes through BGP.
* Configure 2000 vlan hosts per server.
* Start all protocols and verify that IPv4 BGP neighborship is established.
* Create server-server, server-T1 and T1-server data traffics and enable tracking by "Destination Endpoint" and by "Destination session description".
* Set the desired threshold value for receiving traffic. By default it will be set to 90% of expected receiving rate.
* Apply and start the data traffic.
* Verify that traffic is flowing without any loss.
* Enable csv logging or check the state of bgp protocol through API.
* Control plane convergence time is measured by pinging the loopback interface of switch. 
* Now do warm-reboot by issuing the command "sudo fast-reboot".
* Verify that there is no traffic loss after the switch is back up. 
* Drill down by "Destination Endpoint" under traffic statistics to get the data plance convergence time.
* In general the convergence value will fall in certain range. In order to achieve proper results, run the test multiple times and average out the test results. 
* Set it back to default configuration.
#### Test results
| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 318  |
|   | Server-T1 Traffic  | 339  |
| Fast-reboot  | T1-Server Traffic  | 321  |
|   | Control plane (Loopback ping)  | 148  |
|   | BGP Control plane  | 411  |

For above test case, below are the test results when BGP is running on routed interface without LAG.

| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 14  |
|   | Server-T1 Traffic  | 391  |
| Fast-reboot  | T1-Server Traffic  | 16  |
|   | Control plane (Loopback ping)  | 33  |
|   | BGP Control plane  | 109  |

## Test cases
### Test case # 3 – Downtime Convergence measurement for cold-reboot while sending traffic.
#### Test objective
Measure the downtime convergence time when cold-reboot is issued while traffic is running.

<p float="left">
  <img src="Img/Downtime-Convergence-Topology.png" width="280"  hspace="100"/>
  <img src="Img/Downtime-convergence-graph.png" width="400" /> 
</p>


#### Test steps
* Configure a IPv4 EBGP session between test port and the SONiC switch on top of a LAG.
* Advertise 4000 IPv4 and 3000 IPv6 routes through BGP.
* Configure 2000 vlan hosts per server.
* Start all protocols and verify that IPv4 BGP neighborship is established.
* Create server-server, server-T1 and T1-server data traffics and enable tracking by "Destination Endpoint" and by "Destination session description".
* Set the desired threshold value for receiving traffic. By default it will be set to 90% of expected receiving rate.
* Apply and start the data traffic.
* Verify that traffic is flowing without any loss.
* Enable csv logging or check the state of bgp protocol through API.
* Control plane convergence time is measured by pinging the loopback interface of switch. 
* Now do warm-reboot by issuing the command "sudo coldreboot".
* Verify that there is no traffic loss after the switch is back up. 
* Drill down by "Destination Endpoint" under traffic statistics to get the data plance convergence time.
* In general the convergence value will fall in certain range. In order to achieve proper results, run the test multiple times and average out the test results. 
* Set it back to default configuration.
#### Test results
| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 66  |
|   | Server-T1 Traffic  | 463  |
| Cold-reboot  | T1-Server Traffic  | 97  |
|   | Control plane (Loopback ping)  | 31  |
|   | BGP Control plane  | 99  |

For above test case, below are the test results when BGP is running on routed interface without LAG.

| Reboot Type         | Event | Convergence (s) |
| :---         |     :---:      | :---: |
|   | Server-Server Traffic  | 67  |
|   | Server-T1 Traffic  | 441  |
| Cold-reboot  | T1-Server Traffic  | 71  |
|   | Control plane (Loopback ping)  | 32  |
|   | BGP Control plane  | 107  |


## Test cases
### Test case # 4 – Downtime Convergence measurement for soft-reboot while sending traffic.
#### Test objective
Measure the downtime convergence time when cold-reboot is issued while traffic is running.

<p float="left">
  <img src="Img/Downtime-Convergence-Topology.png" width="280"  hspace="100"/>
  <img src="Img/Downtime-convergence-graph.png" width="400" /> 
</p>


#### Test steps
* Configure a IPv4 EBGP session between test port and the SONiC switch on top of a LAG.
* Advertise 4000 IPv4 and 3000 IPv6 routes through BGP.
* Configure 2000 vlan hosts per server.
* Start all protocols and verify that IPv4 BGP neighborship is established.
* Create server-server, server-T1 and T1-server data traffics and enable tracking by "Destination Endpoint" and by "Destination session description".
* Set the desired threshold value for receiving traffic. By default it will be set to 90% of expected receiving rate.
* Apply and start the data traffic.
* Verify that traffic is flowing without any loss.
* Enable csv logging or check the state of bgp protocol through API.
* Control plane convergence time is measured by pinging the loopback interface of switch. 
* Now do warm-reboot by issuing the command "sudo soft-reboot".
* Verify that there is no traffic loss after the switch is back up. 
* Drill down by "Destination Endpoint" under traffic statistics to get the data plance convergence time.
* In general the convergence value will fall in certain range. In order to achieve proper results, run the test multiple times and average out the test results. 
* Set it back to default configuration.
#### Test results

### Call for action
* Soft-reboot command is not available in cli. Once it is available will upstream the script.
