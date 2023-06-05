# Pytest-TRex Test HLD

- [Pytest-TRex Test HLD](#pytest-trex-test-hld)
  * [1 Background](#1-background)
  * [2 Scope](#2-scope)
  * [3 Testbed Setup](#3-testbed-setup)
    + [3.1 General Wiring](#31-general-wiring)
    + [3.2 TRex Installation](#32-trex-installation)
    + [3.3 TRex Configuration](#33-trex-configuration)
      - [3.3.1 Configuration File](#331-configuration-file)
      - [3.3.2 DUT Configuration](#332-dut-configuration)
    + [3.4 Traffic Generating](#34-traffic-generating)
  * [4 Test Cases](#4-test-cases)
    + [4.1 RDMA Test](#41-rdma-test)

## 1 Background

This project introduces a tool which is to generate traffic called TRex. This application should be installed on server appliances to provide traffic-generating service. So in some cases or scenarios, TRex can be combined with Pytest Framework to cover the test cases which need traffic of high or full bandwidth. And packets of most protocols can also be sent. This project makes it possible that some test cases could be covered without physical traffic-generating devices.

## 2 Scope

The scope of this test plan is to verify correct end-to-end operation of a Pytest-TRex infrastructure configuration and usage. This includes control plane testing to verify correct state on the device under test (DUT) and data plane testing to verify correct serial data transfer between the TRex and DUT.
Based on Pytest framework, there are not too many hardware level constraints and no SAI dependence either. So the main focus will be software layer adaptive:
- Pytest-TRex Configuration
- Traffic Generating
- Test Cases Running

## 3 Testbed Setup

### 3.1 General Wiring

TRex is installed on Pytest server to provide traffic-generating service through network cards. Server-Fanout-DUT wiring is consistent with the existing Pytest framework.
Below is the example of wiring diagram which is based on T0 topo:
![image](https://github.com/sonic-net/sonic-mgmt/assets/126938317/547cb37c-4a97-468c-9b7a-d7b7cbfbb86f)
One or more network cards are needed, according to how many ports are needed to generate traffic. The bandwidth between TRex and DUT supports 100 Gig locally, and theoretically supports 200 Gig or 400 Gig.
Connection between Pytest and TRex uses SSH, which makes TRex decoupled from pytest so that TRex module gets more stability.

### 3.2 TRex Installation

TRex installation guide: https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation

### 3.3 TRex Configuration

#### 3.3.1 Configuration File

TRex configuration file should be edited before TRex server starts, whose default configuration file is /etc/trex_cfg.yaml.
Below is the TRex configuration file example:
- port_limit      : 2    //Num of ports to generate traffic
  version         : 2
  interfaces    : ["c2:00.1","c2:00.0"]    //ports on Server to generate traffic
  stack: linux_based

  memory:
             mbuf_64     : 86380
             mbuf_128    : 81900
             mbuf_256    : 8190
             mbuf_512    : 8190
             mbuf_1024   : 8190
             mbuf_2048   : 40960
             traffic_mbuf_64     : 86380
             traffic_mbuf_128    : 81900
             traffic_mbuf_256    : 8190
             traffic_mbuf_512    : 8190
             traffic_mbuf_1024   : 8190
             traffic_mbuf_2048   : 40960
             dp_flows    : 1048576
             global_flows : 10240

  port_info       :  # Port IPs. Change to suit your needs. In case of loopback, you can leave as is.
          - ip         :  11.255.255.2    //IP on Server
            default_gw :  11.255.255.1    //IP on DUT
          - ip         :  200.0.0.2
            default_gw :  200.0.0.1

#### 3.3.2 DUT Configuration

**a) IP configuration (consistent with the default_gw in /etc/trex_cfg.yaml)**

config interface ip add Ethernet55 200.0.0.1/30
config interface ip add Ethernet56 11.255.255.1/30

**b) Route configuration**

config route add prefix 16.0.0.0/24 nexthop 11.255.255.0
config route add prefix 48.0.0.0/24 nexthop 200.0.0.2

### 3.4 Traffic Generating

**a) Start TRex server**

cd /opt/trex/v2.87/
./t-rex-64 -i (default cfg file is /etc/trex_cfg.yaml, add "--cfg /etc/trex_cfg_xxx.yaml" to appoint another cfg file)

**b) Get into trex-console mode and learn ARP**

./trex-console
service -p 0 1
arp -p 0 1
service -p 0 1 --off

**c) Start traffic**

start -f stl/rdmaPacketV4V6_Port0.py -m 98gbps -p 0.traffic
Argument explanation: ("start -h" to get usage)
  -f FILE: the python script to generate traffic
  -m MULT: bandwidth
  -p PORT[.PROFILE]: port to generate traffic, [.PROFILE] for several streams on a physical port

## 4 Test Cases

### 4.1 RDMA Test

This contribution started from fixing the test gap: https://github.com/sonic-net/sonic-mgmt/issues/6733
Below is part of RDMA test cases that we adapted on local SONiC version. We plan to adapt the RDMA test cases with community master version first. Then other modules are going to be adapted too.

| Case | Objective | Test Setup | Expected Control Plane | Expected Data Plane |
|-|-|-|-|-|
| Buffer Profile | Verify the port priority of the buffer profile, supporting PFC	| -	| Add 8 buffer profiles and apply them to port priority 0-7	| - |
| Asymmetric PFC mode	| Verify asymmetric PFC mode is supported	| TRex = DUT | Enable PFC asymmetric, enable PFC function for all queues on the port, and respond to all PFC frames	| - |
| Symmetric PFC mode | Verify symmetric PFC mode is supported	| TRex = DUT | Turn off PFC asymmetric, and enable PFC for port queue and PG queue according to the configuration	 | - |
| PFC Frames Statistics	| Verify PFC Frames Statistics is supported	| TRex = DUT | Enable PFC statistics to perform statistics on PFC frames and display them correctly	| - |
| PFC Frame Statistical Period	| Adjust the pfc frame statistical period	| TRex = DUT | Configure period to several value and verify whether it takes effect	| - |
| PFC Statictics Configuration	| Query PFC frame statistics configuration	| TRex = DUT	| Display the statistics to verify whether PFC statistics configuration is correct.	| - |
| PFC Statistics Result | Query	Query PFC frame statistics results	| TRex = DUT	| Execute "show PFC statistics" display PFC frame statistics for all ports	| - |
